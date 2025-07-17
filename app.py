import streamlit as st
import gspread
import pandas as pd
import datetime
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
import json

# --- Page Configuration ---
st.set_page_config(page_title="Multi-Channel YouTube Analytics Dashboard", page_icon="📊", layout="wide")

# --- Google API Configuration ---
# Keep scopes consistent and in the same order
SCOPES = [
    "https://www.googleapis.com/auth/yt-analytics.readonly",
    "https://www.googleapis.com/auth/youtube.readonly",
    "https://www.googleapis.com/auth/youtube.force-ssl",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid"
]

# --- Secrets Management ---
try:
    # Get the Streamlit Cloud URL first
    streamlit_cloud_url = st.secrets["STREAMLIT_CLOUD_URI"]
    
    CLIENT_CONFIG = {
        "web": {
            "client_id": st.secrets["GOOGLE_CLIENT_ID"],
            "project_id": st.secrets.get("GOOGLE_PROJECT_ID", ""),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": st.secrets["GOOGLE_CLIENT_SECRET"],
            "redirect_uris": [streamlit_cloud_url]
        }
    }
    GOOGLE_SHEET_ID = st.secrets["GOOGLE_SHEET_ID"].strip()
    
    # Validate required secrets
    required_secrets = ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "STREAMLIT_CLOUD_URI", "GOOGLE_SHEET_ID"]
    missing_secrets = [secret for secret in required_secrets if not st.secrets.get(secret)]
    
    if missing_secrets:
        st.error(f"🔴 Missing required secrets: {', '.join(missing_secrets)}")
        st.stop()
        
except KeyError as e:
    st.error(f"🔴 Critical Error: Missing secret key - {e}. Please configure your secrets in the Streamlit app settings.")
    st.error("Required secrets: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, STREAMLIT_CLOUD_URI, GOOGLE_SHEET_ID")
    st.stop()

# --- Authentication State ---
if 'credentials' not in st.session_state:
    st.session_state.credentials = None
if 'selected_channels' not in st.session_state:
    st.session_state.selected_channels = []
if 'analytics_data' not in st.session_state:
    st.session_state.analytics_data = {}

# --- Helper Functions ---
def get_credentials_from_session():
    """Retrieves credentials from Streamlit's session state."""
    if st.session_state.credentials:
        return Credentials.from_authorized_user_info(st.session_state.credentials)
    return None

def save_credentials_to_session(credentials):
    """Saves credentials to Streamlit's session state."""
    st.session_state.credentials = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

def get_streamlit_cloud_url():
    """Gets the Streamlit Cloud URL from secrets or environment."""
    return st.secrets["STREAMLIT_CLOUD_URI"]

def create_oauth_flow():
    """Create a consistent OAuth flow with proper state management."""
    redirect_uri = get_streamlit_cloud_url()
    
    # Create flow with minimal configuration to avoid scope issues
    flow = Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=SCOPES,
        redirect_uri=redirect_uri
    )
    
    # Override the authorization URL generation to be more explicit
    flow._scopes = SCOPES  # Set scopes explicitly
    
    return flow

def safe_fetch_token(flow, auth_code):
    """Safely fetch token with better error handling for scope issues."""
    try:
        # Try normal token fetch first
        flow.fetch_token(code=auth_code)
        return flow.credentials, None
    except Exception as e:
        error_msg = str(e)
        
        # If it's a scope mismatch error, try creating a new flow
        if "Scope has changed" in error_msg:
            try:
                # Create a completely fresh flow
                fresh_flow = Flow.from_client_config(
                    CLIENT_CONFIG,
                    scopes=SCOPES,
                    redirect_uri=get_streamlit_cloud_url()
                )
                
                # Try with the fresh flow
                fresh_flow.fetch_token(code=auth_code)
                return fresh_flow.credentials, None
                
            except Exception as fresh_error:
                return None, f"Fresh flow failed: {str(fresh_error)}"
        
        return None, error_msg

def get_all_channels_comprehensive(credentials):
    """
    Comprehensive method to get ALL channels associated with the authenticated account.
    Uses multiple approaches including direct API calls and token-based requests.
    """
    try:
        all_channels = []
        access_token = credentials.token
        
        # Refresh token if needed
        if credentials.expired:
            credentials.refresh(requests.Request())
            access_token = credentials.token
        
        # Method 1: Standard YouTube Data API
        youtube_service = build('youtube', 'v3', credentials=credentials)
        
        # Get personal channel
        try:
            personal_request = youtube_service.channels().list(
                part="snippet,statistics,brandingSettings,contentDetails",
                mine=True
            )
            personal_response = personal_request.execute()
            personal_channels = personal_response.get("items", [])
            
            for channel in personal_channels:
                channel["channel_type"] = "Personal"
                channel["discovery_method"] = "YouTube API - mine=True"
                all_channels.append(channel)
                
        except HttpError as e:
            st.warning(f"Could not fetch personal channel: {e}")
        
        # Method 2: Direct REST API call to get all channels
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
            
            # This endpoint sometimes returns more channels than the SDK
            api_url = "https://www.googleapis.com/youtube/v3/channels"
            params = {
                "part": "snippet,statistics,brandingSettings,contentDetails",
                "mine": "true",
                "maxResults": 50
            }
            
            response = requests.get(api_url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                direct_channels = data.get("items", [])
                
                existing_ids = {ch["id"] for ch in all_channels}
                for channel in direct_channels:
                    if channel["id"] not in existing_ids:
                        channel["channel_type"] = "Direct API"
                        channel["discovery_method"] = "Direct REST API"
                        all_channels.append(channel)
                        
        except Exception as e:
            st.info(f"Direct API method failed: {e}")
        
        # Method 3: Use YouTube Analytics API to discover channels
        try:
            analytics_service = build("youtubeAnalytics", "v2", credentials=credentials)
            
            # Try to get available channels through analytics
            # This often reveals brand channels that aren\'t shown in regular API
            analytics_url = "https://youtubeanalytics.googleapis.com/v2/reports"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
            
            # Get a simple report that will reveal channel IDs
            params = {
                "ids": "channel==MINE",
                "startDate": "2023-01-01",
                "endDate": "2023-01-02",
                "metrics": "views",
                "dimensions": "channel"
            }
            
            response = requests.get(analytics_url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                if "rows" in data:
                    for row in data["rows"]:
                        channel_id = row[0] if row else None
                        if channel_id:
                            # Get full channel details
                            try:
                                channel_request = youtube_service.channels().list(
                                    part="snippet,statistics,brandingSettings",
                                    id=channel_id
                                )
                                channel_response = channel_request.execute()
                                analytics_channels = channel_response.get("items", [])
                                
                                existing_ids = {ch["id"] for ch in all_channels}
                                for channel in analytics_channels:
                                    if channel["id"] not in existing_ids:
                                        channel["channel_type"] = "Analytics Discovery"
                                        channel["discovery_method"] = "YouTube Analytics API"
                                        all_channels.append(channel)
                                        
                            except HttpError:
                                pass
                                
        except Exception as e:
            st.info(f"Analytics discovery method failed: {e}")
        
        # Method 4: Channel enumeration through search
        try:
            # Search for channels owned by the authenticated user
            search_request = youtube_service.search().list(
                part="snippet",
                forMine=True,
                type="channel",
                maxResults=50
            )
            search_response = search_request.execute()
            
            for item in search_response.get("items", []):
                channel_id = item["snippet"]["channelId"]
                
                # Get full channel details
                try:
                    channel_request = youtube_service.channels().list(
                        part="snippet,statistics,brandingSettings",
                        id=channel_id
                    )
                    channel_response = channel_request.execute()
                    search_channels = channel_response.get("items", [])
                    
                    existing_ids = {ch["id"] for ch in all_channels}
                    for channel in search_channels:
                        if channel["id"] not in existing_ids:
                            channel["channel_type"] = "Search Discovery"
                            channel["discovery_method"] = "YouTube Search API"
                            all_channels.append(channel)
                            
                except HttpError:
                    pass
                    
        except HttpError as e:
            st.info(f"Search discovery failed: {e}")
        
        # Method 5: Attempt to list content owners and their associated channels
        try:
            st.info("Attempting to discover channels via content owner API...")
            youtube_owner_service = build("youtube", "v3", credentials=credentials)
            
            # First, try to list content owners associated with the account
            # This requires YouTube Content ID API access, which might not be granted to all users
            try:
                content_owners_request = youtube_owner_service.contentOwners().list(
                    part="snippet"
                )
                content_owners_response = content_owners_request.execute()
                content_owners = content_owners_response.get("items", [])
                
                for owner in content_owners:
                    owner_id = owner["id"]
                    st.info(f"Found Content Owner: {owner["snippet"]["displayName"]} (ID: {owner_id})")
                    
                    # Now list channels for this content owner
                    channels_for_owner_request = youtube_owner_service.channels().list(
                        part="snippet,statistics,brandingSettings",
                         onBehalfOfContentOwner=owner_id,
                        managedByMe=True # This should work with onBehalfOfContentOwner
                    )
                    channels_for_owner_response = channels_for_owner_request.execute()
                    owner_channels = channels_for_owner_response.get("items", [])
                    
                    existing_ids = {ch["id"] for ch in all_channels}
                    for channel in owner_channels:
                        if channel["id"] not in existing_ids:
                            channel["channel_type"] = "Brand (Content Owner)"
                            channel["discovery_method"] = f"YouTube Content Owner API ({owner["snippet"]["displayName"]})"
                            all_channels.append(channel)
                            
            except HttpError as e:
                if e.resp.status == 403:
                    st.warning(f"Content Owner API access denied. This is common if you don't have Content ID access. Error: {e}")
                else:
                    st.info(f"Content Owner API failed: {e}")
        except Exception as e:
            st.info(f"Content Owner API discovery failed: {e}")

        # Display discovery summary
        if all_channels:
            st.success(f"🎉 Found {len(all_channels)} total channels using multiple discovery methods!")
            
            # Group by discovery method
            method_counts = {}
            for channel in all_channels:
                method = channel.get("discovery_method", "Unknown")
                method_counts[method] = method_counts.get(method, 0) + 1
            
            st.write("**Discovery Summary:**")
            for method, count in method_counts.items():
                st.write(f"- {method}: {count} channels")
                
        else:
            st.error("❌ No channels found with comprehensive discovery methods.")
            st.write("**This suggests that:**")
            st.write("1. Your brand channels may not be properly linked to this Google account")
            st.write("2. You may need to use each brand channel\'s specific Google account")
            st.write("3. The brand channels might require separate authentication")
            
            st.write("**Try this approach:**")
            st.write("1. Go to YouTube Studio for each brand channel")
            st.write("2. Note which Google account you use to log in")
            st.write("3. Use that specific account to authenticate with this app")
            st.write("4. Or manually add channel IDs using the method below")
        
        return all_channels
        
    except Exception as e:
        st.error(f"Comprehensive channel discovery failed: {e}")
        return []

def get_all_brand_channels_ultimate(credentials):
    """
    Ultimate method to discover ALL brand channels associated with the authenticated account.
    This uses advanced techniques including direct token verification and alternative APIs.
    """
    try:
        access_token = credentials.token
        
        # Refresh token if needed
        if credentials.expired:
            credentials.refresh(requests.Request())
            access_token = credentials.token
        
        st.info("🚀 Using ultimate brand channel discovery method...")
        
        all_channels = []
        
        # Method 1: Use OAuth2 token info to get associated accounts
        try:
            # Get token info to understand the scope and associated accounts
            token_info_url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={access_token}"
            token_response = requests.get(token_info_url)
            
            if token_response.status_code == 200:
                token_data = token_response.json()
                st.write("**Token Info:**", token_data.get('scope', 'Unknown'))
                
        except Exception as e:
            st.info(f"Token info retrieval failed: {e}")
        
        # Method 2: Brute force channel enumeration using Analytics API
        try:
            st.info("🔍 Attempting channel enumeration through Analytics API...")
            
            # Use YouTube Analytics API to find all accessible channels
            analytics_url = "https://youtubeanalytics.googleapis.com/v2/reports"
            headers = {'Authorization': f'Bearer {access_token}'}
            
            # Try different date ranges to maximize channel discovery
            date_ranges = [
                ('2024-01-01', '2024-01-31'),
                ('2023-01-01', '2023-12-31'),
                ('2022-01-01', '2022-12-31'),
                ('2021-01-01', '2021-12-31')
            ]
            
            discovered_channel_ids = set()
            
            for start_date, end_date in date_ranges:
                try:
                    params = {
                        'ids': 'channel==MINE',
                        'startDate': start_date,
                        'endDate': end_date,
                        'metrics': 'views,subscribersGained',
                        'dimensions': 'channel',
                        'sort': 'channel'
                    }
                    
                    response = requests.get(analytics_url, headers=headers, params=params)
                    if response.status_code == 200:
                        data = response.json()
                        
                        if 'rows' in data:
                            for row in data['rows']:
                                channel_id = row[0] if row and len(row) > 0 else None
                                if channel_id and channel_id.startswith('UC'):
                                    discovered_channel_ids.add(channel_id)
                                    
                except Exception as e:
                    continue
            
            # Get full channel details for all discovered IDs
            if discovered_channel_ids:
                youtube_service = build('youtube', 'v3', credentials=credentials)
                
                # Process in batches (YouTube API allows up to 50 IDs per request)
                channel_ids_list = list(discovered_channel_ids)
                for i in range(0, len(channel_ids_list), 50):
                    batch_ids = channel_ids_list[i:i+50]
                    
                    try:
                        channel_request = youtube_service.channels().list(
                            part="snippet,statistics,brandingSettings,contentDetails",
                            id=','.join(batch_ids)
                        )
                        channel_response = channel_request.execute()
                        batch_channels = channel_response.get("items", [])
                        
                        for channel in batch_channels:
                            channel['channel_type'] = 'Analytics Discovery'
                            channel['discovery_method'] = 'Analytics Channel Enumeration'
                            all_channels.append(channel)
                            
                    except HttpError as e:
                        st.warning(f"Failed to get details for batch: {e}")
                        continue
                
                st.success(f"🎉 Analytics enumeration found {len(all_channels)} channels!")
                
        except Exception as e:
            st.info(f"Analytics enumeration failed: {e}")
        
        return all_channels
        
    except Exception as e:
        st.error(f"Ultimate channel discovery failed: {e}")
        return []

def get_brand_channels_by_email(credentials):
    """
    Alternative approach: Get brand channels by checking all possible channels
    associated with the authenticated email account.
    """
    try:
        access_token = credentials.token
        
        # Refresh token if needed
        if credentials.expired:
            credentials.refresh(requests.Request())
            access_token = credentials.token
        
        st.info("🔍 Attempting alternative brand channel discovery...")
        
        # Try different approaches to discover channels through analytics
        try:
            analytics_service = build('youtubeAnalytics', 'v2', credentials=credentials)
            discovered_channels = []
            
            # Try different date ranges
            test_dates = ['2024-01-01', '2023-01-01', '2022-01-01']
            
            for start_date in test_dates:
                try:
                    # Use a broad analytics query that might reveal channel IDs
                    analytics_url = "https://youtubeanalytics.googleapis.com/v2/reports"
                    headers = {'Authorization': f'Bearer {access_token}'}
                    
                    params = {
                        'ids': 'channel==MINE',
                        'startDate': start_date,
                        'endDate': start_date,
                        'metrics': 'views',
                        'dimensions': 'channel,day'
                    }
                    
                    response = requests.get(analytics_url, headers=headers, params=params)
                    if response.status_code == 200:
                        data = response.json()
                        if 'rows' in data:
                            for row in data['rows']:
                                channel_id = row[0] if row else None
                                if channel_id and channel_id.startswith('UC'):
                                    if channel_id not in discovered_channels:
                                        discovered_channels.append(channel_id)
                                        
                except Exception:
                    continue
            
            # Get full details for discovered channels
            if discovered_channels:
                youtube_service = build('youtube', 'v3', credentials=credentials)
                all_channels = []
                
                for channel_id in discovered_channels:
                    try:
                        channel_request = youtube_service.channels().list(
                            part="snippet,statistics,brandingSettings",
                            id=channel_id
                        )
                        channel_response = channel_request.execute()
                        channels = channel_response.get("items", [])
                        
                        for channel in channels:
                            channel['channel_type'] = 'Analytics Enumeration'
                            channel['discovery_method'] = 'Analytics Channel Enumeration'
                            all_channels.append(channel)
                            
                    except HttpError:
                        pass
                
                return all_channels
                
        except Exception as e:
            st.info(f"Analytics enumeration failed: {e}")
        
        return []
        
    except Exception as e:
        st.error(f"Brand channel discovery failed: {e}")
        return []

def fetch_youtube_data(credentials, channel_id, start_date, end_date):
    """Fetches comprehensive YouTube Analytics data."""
    try:
        youtube_service = build('youtubeAnalytics', 'v2', credentials=credentials)
        
        request = youtube_service.reports().query(
            ids=f"channel=={channel_id}",
            startDate=start_date.strftime("%Y-%m-%d"),
            endDate=end_date.strftime("%Y-%m-%d"),
            metrics="views,redViews,comments,likes,dislikes,shares,estimatedMinutesWatched,averageViewDuration,subscribersGained,subscribersLost",
            dimensions="day",
            sort="day"
        )

        response = request.execute()
        
        if 'rows' in response:
            column_headers = [header['name'] for header in response['columnHeaders']]
            df = pd.DataFrame(response['rows'], columns=column_headers)
            df['day'] = pd.to_datetime(df['day'])
            return df
        else:
            return pd.DataFrame()
    except HttpError as e:
        if e.resp.status == 403:
            st.error(f"🛑 HTTP 403 Forbidden Error: No permission for channel {channel_id}")
        else:
            st.error(f"An error occurred while fetching YouTube data: {e}")
        return None

def write_to_sheet(credentials, sheet_id, channel_name, dataframe):
    """Writes DataFrame to Google Sheet with channel-specific worksheet."""
    try:
        gc = gspread.authorize(credentials)
        spreadsheet = gc.open_by_key(sheet_id)
        
        # Create or get worksheet for this channel
        worksheet_name = f"{channel_name}_analytics"
        try:
            worksheet = spreadsheet.worksheet(worksheet_name)
        except gspread.WorksheetNotFound:
            worksheet = spreadsheet.add_worksheet(title=worksheet_name, rows=1000, cols=20)
        
        # Clear existing data and write new data
        worksheet.clear()
        
        # Prepare data with headers
        headers = dataframe.columns.tolist()
        data = [headers] + dataframe.values.tolist()
        
        worksheet.update(data, value_input_option='USER_ENTERED')
        return True
    except Exception as e:
        st.error(f"An error occurred while writing to Google Sheets: {e}")
        return False

def create_analytics_charts(df, channel_name):
    """Creates interactive charts for analytics data."""
    if df.empty:
        return None
    
    # Create subplots
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('Views Over Time', 'Engagement Metrics', 'Watch Time', 'Subscriber Changes'),
        specs=[[{"secondary_y": False}, {"secondary_y": True}],
               [{"secondary_y": False}, {"secondary_y": True}]]
    )
    
    # Views over time
    fig.add_trace(
        go.Scatter(x=df['day'], y=df['views'], name='Views', line=dict(color='blue')),
        row=1, col=1
    )
    
    # Engagement metrics
    fig.add_trace(
        go.Scatter(x=df['day'], y=df['likes'], name='Likes', line=dict(color='green')),
        row=1, col=2
    )
    fig.add_trace(
        go.Scatter(x=df['day'], y=df['comments'], name='Comments', line=dict(color='orange')),
        row=1, col=2, secondary_y=True
    )
    
    # Watch time
    fig.add_trace(
        go.Scatter(x=df['day'], y=df['estimatedMinutesWatched'], name='Minutes Watched', line=dict(color='purple')),
        row=2, col=1
    )
    
    # Subscriber changes
    fig.add_trace(
        go.Scatter(x=df['day'], y=df['subscribersGained'], name='Gained', line=dict(color='green')),
        row=2, col=2
    )
    fig.add_trace(
        go.Scatter(x=df['day'], y=df['subscribersLost'], name='Lost', line=dict(color='red')),
        row=2, col=2, secondary_y=True
    )
    
    fig.update_layout(
        title=f"{channel_name} - Analytics Dashboard",
        height=600,
        showlegend=True
    )
    
    return fig

def check_alerts(df, channel_name):
    """Check for various alert conditions."""
    alerts = []
    
    if df.empty:
        return alerts
    
    # Calculate recent metrics
    recent_data = df.tail(3)  # Last 3 days
    avg_views = recent_data['views'].mean()
    avg_engagement = (recent_data['likes'] + recent_data['comments']).mean()
    subscriber_net = recent_data['subscribersGained'].sum() - recent_data['subscribersLost'].sum()
    
    # Alert conditions
    if avg_views < 100:  # Customize threshold
        alerts.append(f"⚠️ {channel_name}: Low views (avg {avg_views:.0f} in last 3 days)")
    
    if avg_engagement < 10:  # Customize threshold
        alerts.append(f"⚠️ {channel_name}: Low engagement (avg {avg_engagement:.0f} in last 3 days)")
    
    if subscriber_net < -5:  # Customize threshold
        alerts.append(f"🚨 {channel_name}: Net subscriber loss ({subscriber_net}) in last 3 days")
    
    return alerts

# --- Main Application UI ---
st.title("📊 Multi-Channel YouTube Analytics Dashboard")

# Sidebar for navigation
with st.sidebar:
    st.header("Navigation")
    page = st.radio("Choose a page:", ["🔐 Authentication", "📊 Analytics Dashboard", "🚨 Alerts", "📈 Channel Comparison"])

creds = get_credentials_from_session()

if page == "🔐 Authentication":
    st.header("Authentication")
    
    if creds is None:
        st.write("Click the button below to grant access to your YouTube Analytics and Google Sheets data.")
        
        redirect_uri = get_streamlit_cloud_url()
        
        # Create authorization URL
        try:
            # Always create a fresh flow to avoid scope caching issues
            flow = create_oauth_flow()
            
            # Create auth URL with minimal parameters to avoid scope issues
            auth_url, state = flow.authorization_url(
                prompt='consent',
                access_type='offline'
            )
            
            # Display current configuration
            with st.expander("🔧 App Configuration"):
                st.write(f"**Streamlit Cloud URL:** {redirect_uri}")
                st.write("**Scopes requested:**")
                for scope in SCOPES:
                    st.write(f"  - {scope}")
                st.write("Make sure this URL is added to your Google Cloud Console OAuth settings.")
            
            st.link_button("🔐 Authorize with Google", auth_url, type="primary")
            
            # Check for authorization code in URL
            auth_code = st.query_params.get("code")
            
            if auth_code:
                with st.spinner("Processing authorization..."):
                    credentials, error = safe_fetch_token(flow, auth_code)
                    
                    if credentials:
                        save_credentials_to_session(credentials)
                        st.success("🎉 Authentication successful! Navigate to Analytics Dashboard.")
                        st.balloons()
                        st.query_params.clear()
                        st.rerun()
                    else:
                        st.error(f"❌ Auto-authentication failed: {error}")
                        st.write("Please try the manual method below.")
            
            # Manual authorization code input
            st.write("---")
            st.subheader("📝 Manual Authorization")
            st.write("If the automatic process doesn't work:")
            st.write("1. Click the authorization button above")
            st.write("2. Complete the Google authorization process")
            st.write("3. Copy the **authorization code** from the URL")
            st.write("4. Paste it below and click Submit")
            
            st.code("Look for: ?code=4/0AbUR2VM... \nCopy just: 4/0AbUR2VM...")
            
            manual_auth_code = st.text_input(
                "Paste Authorization Code Here:", 
                placeholder="4/0AbUR2VM...",
                help="Copy just the code parameter value (after 'code=' in the URL)",
                key="manual_auth_input"
            )
            
            if st.button("✅ Submit Authorization Code", type="primary") and manual_auth_code:
                with st.spinner("Processing manual authorization..."):
                    clean_auth_code = manual_auth_code.strip()
                    
                    # Create a completely fresh flow for manual processing
                    manual_flow = create_oauth_flow()
                    credentials, error = safe_fetch_token(manual_flow, clean_auth_code)
                    
                    if credentials:
                        save_credentials_to_session(credentials)
                        st.success("🎉 Manual authentication successful! Navigate to Analytics Dashboard.")
                        st.balloons()
                        st.rerun()
                    else:
                        st.error(f"❌ Manual authentication failed: {error}")
                        
                        # Show different error messages based on error type
                        if "Scope has changed" in error:
                            st.write("**Scope mismatch error - Try this:**")
                            st.write("1. Clear your browser cache and cookies")
                            st.write("2. Try an incognito/private browsing window")
                            st.write("3. Get a fresh authorization code")
                            st.write("4. Make sure to use the same browser session")
                        else:
                            st.write("**Troubleshooting tips:**")
                            st.write("- Make sure you copied the complete authorization code")
                            st.write("- The code should start with '4/0A' or similar")
                            st.write("- Try getting a fresh code by clicking the authorization button again")
                        
                        with st.expander("🔧 Debug Information"):
                            st.write(f"**Error details:** {error}")
                            st.write(f"**Code length:** {len(clean_auth_code) if clean_auth_code else 0}")
                            st.write(f"**Code starts with:** {clean_auth_code[:10] if clean_auth_code else 'N/A'}")
            
            # Alternative: Direct Google OAuth Playground method
            st.write("---")
            st.subheader("🔧 Alternative: Google OAuth Playground")
            st.write("If you continue having scope issues:")
            
            with st.expander("Use Google OAuth Playground"):
                st.write("1. Go to [Google OAuth2 Playground](https://developers.google.com/oauthplayground/)")
                st.write("2. Click the settings gear icon (⚙️)")
                st.write("3. Check 'Use your own OAuth credentials'")
                st.write("4. Enter your Client ID and Client Secret:")
                st.code(f"Client ID: {CLIENT_CONFIG['web']['client_id']}\nClient Secret: {CLIENT_CONFIG['web']['client_secret']}")
                st.write("5. In Step 1, add these scopes:")
                for scope in SCOPES:
                    st.code(scope)
                st.write("6. Click 'Authorize APIs'")
                st.write("7. In Step 2, click 'Exchange authorization code for tokens'")
                st.write("8. Copy the 'Authorization code' from Step 1 and paste here:")
                
                playground_code = st.text_input(
                    "OAuth Playground Authorization Code:",
                    placeholder="4/0AbUR2VM...",
                    key="playground_code"
                )
                
                if st.button("✅ Use Playground Code") and playground_code:
                    with st.spinner("Processing playground authorization..."):
                        playground_flow = create_oauth_flow()
                        credentials, error = safe_fetch_token(playground_flow, playground_code.strip())
                        
                        if credentials:
                            save_credentials_to_session(credentials)
                            st.success("🎉 Playground authentication successful!")
                            st.balloons()
                            st.rerun()
                        else:
                            st.error(f"❌ Playground authentication failed: {error}")
                
        except Exception as e:
            st.error(f"❌ Failed to create OAuth flow: {e}")
            st.write("**This usually means:**")
            st.write("- Your Google Cloud Console credentials are incorrect")
            st.write("- The redirect URI doesn't match your Google Cloud Console settings")
            st.write("- Required APIs are not enabled")
            
            with st.expander("🔧 Debug Information"):
                st.write(f"**Error:** {str(e)}")
                st.write(f"**Redirect URI:** {redirect_uri}")
                st.write("**CLIENT_CONFIG:**")
                st.json({k: v for k, v in CLIENT_CONFIG["web"].items() if k != "client_secret"})
            
            st.write("---")
            st.subheader("🛠️ Setup Checklist")
            
            st.write("**1. Google Cloud Console APIs (Enable these):**")
            st.write("  - YouTube Analytics API")
            st.write("  - YouTube Data API v3") 
            st.write("  - Google Sheets API")
            
            st.write("**2. OAuth 2.0 Client ID Configuration:**")
            st.write(f"  - Authorized redirect URIs: `{redirect_uri}`")
            st.write("  - Application type: Web application")
            
            st.write("**3. OAuth Consent Screen:**")
            st.write("  - Configure consent screen")
            st.write("  - Add your email to test users")
            st.write("  - Add all required scopes")
            
            test_url = f"https://accounts.google.com/o/oauth2/v2/auth?client_id={CLIENT_CONFIG['web']['client_id']}&redirect_uri={redirect_uri}&response_type=code&scope=openid"
            st.write(f"**4. Test basic OAuth:** [Click here]({test_url})")
    else:
        st.success("✅ You are authenticated!")
        
        with st.spinner("Loading your channels..."):
            # Try comprehensive channel discovery first
            channels = get_all_channels_comprehensive(creds)
            
            # If comprehensive method doesn't find enough channels, try ultimate method
            if len(channels) < 7:  # You mentioned you have 7 channels
                st.info("🔄 Trying ultimate discovery method...")
                ultimate_channels = get_all_brand_channels_ultimate(creds)
                
                # Merge with existing channels, avoiding duplicates
                existing_ids = {ch['id'] for ch in channels}
                for channel in ultimate_channels:
                    if channel['id'] not in existing_ids:
                        channels.append(channel)
            
            # Final fallback: try the alternative email method
            if len(channels) < 3:  # Still not enough channels
                st.info("🔄 Trying alternative discovery methods...")
                additional_channels = get_brand_channels_by_email(creds)
                
                # Merge with existing channels, avoiding duplicates
                existing_ids = {ch['id'] for ch in channels}
                for channel in additional_channels:
                    if channel['id'] not in existing_ids:
                        channels.append(channel)
        
        if channels:
            st.write("### Your YouTube Channels:")
            
            # Separate channels by type
            personal_channels = [ch for ch in channels if ch.get('channel_type') == 'Personal']
            brand_channels = [ch for ch in channels if ch.get('channel_type') == 'Brand']
            other_channels = [ch for ch in channels if ch.get('channel_type') not in ['Personal', 'Brand']]
            
            # Display personal channels
            if personal_channels:
                st.write("**Personal Channels:**")
                for channel in personal_channels:
                    col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
                    with col1:
                        st.write(f"🏠 **{channel['snippet']['title']}**")
                    with col2:
                        st.write(f"Subscribers: {channel['statistics'].get('subscriberCount', 'Hidden')}")
                    with col3:
                        st.write(f"Videos: {channel['statistics'].get('videoCount', '0')}")
                    with col4:
                        st.write("Personal")
            
            # Display brand channels
            if brand_channels:
                st.write("**Brand Channels:**")
                for channel in brand_channels:
                    col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
                    with col1:
                        st.write(f"🏢 **{channel['snippet']['title']}**")
                    with col2:
                        st.write(f"Subscribers: {channel['statistics'].get('subscriberCount', 'Hidden')}")
                    with col3:
                        st.write(f"Videos: {channel['statistics'].get('videoCount', '0')}")
                    with col4:
                        st.write("Brand")
            
            # Display other discovered channels
            if other_channels:
                st.write("**Other Discovered Channels:**")
                for channel in other_channels:
                    col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
                    with col1:
                        st.write(f"🔍 **{channel['snippet']['title']}**")
                    with col2:
                        st.write(f"Subscribers: {channel['statistics'].get('subscriberCount', 'Hidden')}")
                    with col3:
                        st.write(f"Videos: {channel['statistics'].get('videoCount', '0')}")
                    with col4:
                        st.write(channel.get('channel_type', 'Unknown'))
            
            # Show channel IDs for debugging
            with st.expander("🔧 Channel IDs (for debugging)"):
                for channel in channels:
                    st.write(f"**{channel['snippet']['title']}**: `{channel['id']}` ({channel.get('channel_type', 'Unknown')})")
                    
        else:
            st.warning("No channels found. Make sure you have:")
            st.write("- Manager access to your brand channels")
            st.write("- Accepted any pending invitations in YouTube Studio")
            st.write("- Proper OAuth permissions")
            
            st.write("**Troubleshooting steps:**")
            st.write("1. Go to [YouTube Studio](https://studio.youtube.com)")
            st.write("2. Check if you can access all your channels there")
            st.write("3. Accept any pending manager invitations")
            st.write("4. Try re-authenticating with this app")
            
            # Manual channel input option
            st.write("---")
            st.subheader("🔧 Manual Channel Setup")
            st.write("As a workaround, you can manually add your channel IDs:")
            
            manual_channels = st.text_area(
                "Enter Channel IDs (one per line)",
                placeholder="UC1234567890abcdefghij\nUC0987654321zyxwvutsrq\nUC...",
                help="Get Channel IDs from YouTube Studio → Settings → Channel → Advanced Settings"
            )
            
            if st.button("Load Manual Channels") and manual_channels:
                manual_channel_ids = [id.strip() for id in manual_channels.split('\n') if id.strip()]
                if manual_channel_ids:
                    try:
                        youtube_service = build('youtube', 'v3', credentials=creds)
                        manual_request = youtube_service.channels().list(
                            part="snippet,statistics,brandingSettings",
                            id=','.join(manual_channel_ids)
                        )
                        manual_response = manual_request.execute()
                        manual_found = manual_response.get("items", [])
                        
                        if manual_found:
                            st.success(f"✅ Found {len(manual_found)} channels!")
                            for channel in manual_found:
                                channel['channel_type'] = 'Manual'
                            
                            # Store in session state
                            st.session_state.manual_channels = manual_found
                            st.rerun()
                        else:
                            st.error("No channels found with the provided IDs")
                            
                    except HttpError as e:
                        st.error(f"Error loading manual channels: {e}")
        
        # Check for manual channels in session state
        if 'manual_channels' in st.session_state and st.session_state.manual_channels:
            st.write("### Manually Added Channels:")
            for channel in st.session_state.manual_channels:
                col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
                with col1:
                    st.write(f"⚙️ **{channel['snippet']['title']}**")
                with col2:
                    st.write(f"Subscribers: {channel['statistics'].get('subscriberCount', 'Hidden')}")
                with col3:
                    st.write(f"Videos: {channel['statistics'].get('videoCount', '0')}")
                with col4:
                    st.write("Manual")
            
            # Combine with auto-discovered channels
            if 'channels' in locals() and channels:
                channels.extend(st.session_state.manual_channels)
            else:
                channels = st.session_state.manual_channels
        
        if st.button("🚪 Logout"):
            st.session_state.credentials = None
            st.rerun()

elif page == "📊 Analytics Dashboard":
    if creds is None:
        st.warning("Please authenticate first!")
        st.stop()
    
    st.header("Analytics Dashboard")
    
    with st.spinner("Loading channels..."):
        # Try comprehensive channel discovery first
        channels = get_all_channels_comprehensive(creds)
        
        # If comprehensive method doesn't find enough channels, try ultimate method
        if len(channels) < 7:  # You mentioned you have 7 channels
            st.info("🔄 Trying ultimate discovery method...")
            ultimate_channels = get_all_brand_channels_ultimate(creds)
            
            # Merge with existing channels, avoiding duplicates
            existing_ids = {ch['id'] for ch in channels}
            for channel in ultimate_channels:
                if channel['id'] not in existing_ids:
                    channels.append(channel)
        
        # Final fallback: try the alternative email method
        if len(channels) < 3:  # Still not enough channels
            st.info("🔄 Trying alternative discovery methods...")
            additional_channels = get_brand_channels_by_email(creds)
            
            # Merge with existing channels, avoiding duplicates
            existing_ids = {ch['id'] for ch in channels}
            for channel in additional_channels:
                if channel['id'] not in existing_ids:
                    channels.append(channel)
        
        # Also check for manual channels
        if 'manual_channels' in st.session_state and st.session_state.manual_channels:
            if channels:
                # Combine auto-discovered and manual channels, avoiding duplicates
                existing_ids = {ch['id'] for ch in channels}
                for manual_ch in st.session_state.manual_channels:
                    if manual_ch['id'] not in existing_ids:
                        channels.append(manual_ch)
            else:
                channels = st.session_state.manual_channels
    
    if channels:
        # Channel selection
        channel_options = {ch['snippet']['title']: ch['id'] for ch in channels}
        selected_channel_names = st.multiselect(
            "Select channels to analyze:",
            options=list(channel_options.keys()),
            default=list(channel_options.keys())[:3] if len(channel_options) <= 3 else list(channel_options.keys())[:3]
        )
        
        if selected_channel_names:
            # Date range selection
            col1, col2 = st.columns(2)
            with col1:
                start_date = st.date_input(
                    "Start date", 
                    datetime.date.today() - datetime.timedelta(days=30)
                )
            with col2:
                end_date = st.date_input(
                    "End date", 
                    datetime.date.today() - datetime.timedelta(days=1)
                )
            
            if st.button("Fetch Analytics Data", type="primary"):
                for channel_name in selected_channel_names:
                    channel_id = channel_options[channel_name]
                    
                    with st.spinner(f"Fetching data for {channel_name}..."):
                        df = fetch_youtube_data(creds, channel_id, start_date, end_date)
                    
                    if df is not None and not df.empty:
                        st.session_state.analytics_data[channel_name] = df
                        
                        # Display charts
                        st.subheader(f"📈 {channel_name}")
                        
                        # Key metrics
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Total Views", f"{df['views'].sum():,}")
                        with col2:
                            st.metric("Total Likes", f"{df['likes'].sum():,}")
                        with col3:
                            st.metric("Total Comments", f"{df['comments'].sum():,}")
                        with col4:
                            net_subscribers = df['subscribersGained'].sum() - df['subscribersLost'].sum()
                            st.metric("Net Subscribers", f"{net_subscribers:+}")
                        
                        # Charts
                        chart = create_analytics_charts(df, channel_name)
                        if chart:
                            st.plotly_chart(chart, use_container_width=True)
                        
                        # Save to sheets
                        with st.spinner(f"Saving {channel_name} data to Google Sheets..."):
                            write_to_sheet(creds, GOOGLE_SHEET_ID, channel_name, df)
                    
                    elif df is not None and df.empty:
                        st.warning(f"No data found for {channel_name} in the selected date range.")
                    else:
                        st.error(f"Failed to fetch data for {channel_name}.")
                
                st.success("Data fetching complete!")
                sheet_url = f"https://docs.google.com/spreadsheets/d/{GOOGLE_SHEET_ID}"
                st.markdown(f"**[View Google Sheet]({sheet_url})**")

elif page == "🚨 Alerts":
    if creds is None:
        st.warning("Please authenticate first!")
        st.stop()
    
    st.header("Custom Alerts")
    
    if st.session_state.analytics_data:
        st.subheader("Alert Settings")
        
        col1, col2 = st.columns(2)
        with col1:
            view_threshold = st.number_input("Low views alert threshold", value=100, min_value=0)
        with col2:
            engagement_threshold = st.number_input("Low engagement alert threshold", value=10, min_value=0)
        
        subscriber_loss_threshold = st.number_input("Subscriber loss alert threshold", value=-5, max_value=0)
        
        if st.button("Check Alerts"):
            all_alerts = []
            
            for channel_name, df in st.session_state.analytics_data.items():
                alerts = check_alerts(df, channel_name)
                all_alerts.extend(alerts)
            
            if all_alerts:
                st.subheader("🚨 Active Alerts")
                for alert in all_alerts:
                    st.error(alert)
            else:
                st.success("✅ No alerts detected. All channels performing well!")
    else:
        st.info("No analytics data available. Please fetch data from the Analytics Dashboard first.")

elif page == "📈 Channel Comparison":
    if creds is None:
        st.warning("Please authenticate first!")
        st.stop()
    
    st.header("Channel Comparison")
    
    if st.session_state.analytics_data and len(st.session_state.analytics_data) > 1:
        # Create comparison charts
        metrics = ['views', 'likes', 'comments', 'subscribersGained']
        
        for metric in metrics:
            fig = go.Figure()
            
            for channel_name, df in st.session_state.analytics_data.items():
                if metric in df.columns:
                    fig.add_trace(go.Scatter(
                        x=df['day'],
                        y=df[metric],
                        name=channel_name,
                        mode='lines+markers'
                    ))
            
            fig.update_layout(
                title=f"{metric.title()} Comparison",
                xaxis_title="Date",
                yaxis_title=metric.title(),
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        # Summary table
        st.subheader("Performance Summary")
        summary_data = []
        
        for channel_name, df in st.session_state.analytics_data.items():
            summary_data.append({
                'Channel': channel_name,
                'Total Views': df['views'].sum(),
                'Total Likes': df['likes'].sum(),
                'Total Comments': df['comments'].sum(),
                'Avg Daily Views': df['views'].mean(),
                'Net Subscribers': df['subscribersGained'].sum() - df['subscribersLost'].sum()
            })
        
        summary_df = pd.DataFrame(summary_data)
        st.dataframe(summary_df, use_container_width=True)
    
    else:
        st.info("Please fetch data for at least 2 channels to enable comparison.")

# Footer
st.markdown("---")
st.markdown("Built with ❤️ using Streamlit | Multi-Channel YouTube Analytics Dashboard")
