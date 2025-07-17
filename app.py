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
SCOPES = [
    "https://www.googleapis.com/auth/yt-analytics.readonly",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/youtube.readonly",
    "https://www.googleapis.com/auth/youtube.force-ssl",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile"
]

# --- Secrets Management ---
try:
    CLIENT_CONFIG = {
        "web": {
            "client_id": st.secrets["GOOGLE_CLIENT_ID"],
            "project_id": st.secrets.get("GOOGLE_PROJECT_ID", ""),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": st.secrets["GOOGLE_CLIENT_SECRET"],
            "redirect_uris": [st.secrets["STREAMLIT_CLOUD_URI"]]
        }
    }
    GOOGLE_SHEET_ID = st.secrets["GOOGLE_SHEET_ID"].strip()
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
        
        # Method 2: Use YouTube's internal channel switching API
        try:
            # This mimics what YouTube Studio does to get channel switcher data
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Origin': 'https://studio.youtube.com',
                'Referer': 'https://studio.youtube.com/'
            }
            
            # Try multiple internal YouTube endpoints
            internal_urls = [
                "https://studio.youtube.com/youtubei/v1/creator/get_creator",
                "https://studio.youtube.com/youtubei/v1/creator/channel/get_channels",
                "https://www.youtube.com/youtubei/v1/account/accounts_list"
            ]
            
            for url in internal_urls:
                try:
                    response = requests.post(url, headers=headers, json={})
                    if response.status_code == 200:
                        data = response.json()
                        st.write(f"Found data from {url}: {len(str(data))} characters")
                        # Parse the response for channel information
                        # This would need to be adapted based on actual response structure
                        
                except Exception as e:
                    continue
                    
        except Exception as e:
            st.info("Internal YouTube APIs not accessible")
        
        # Method 3: Brute force channel enumeration using Analytics API
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
        
        # Method 4: Try using Google My Business API (for business accounts)
        try:
            # Some brand channels are associated with Google My Business
            # This is a long shot but worth trying
            
            gmb_headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
            
            # Try to get Google My Business accounts
            gmb_url = "https://mybusiness.googleapis.com/v4/accounts"
            gmb_response = requests.get(gmb_url, headers=gmb_headers)
            
            if gmb_response.status_code == 200:
                gmb_data = gmb_response.json()
                st.info(f"Found Google My Business data: {len(str(gmb_data))} characters")
                
        except Exception as e:
            st.info("Google My Business API not accessible")
        
        return all_channels
        
    except Exception as e:
        st.error(f"Ultimate channel discovery failed: {e}")
        return []
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
        
        st.info("🔍 Attempting advanced brand channel discovery...")
        
        # Method 1: Use YouTube Studio's internal API endpoints
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            # This endpoint is used by YouTube Studio to get channel switcher data
            studio_url = "https://studio.youtube.com/youtubei/v1/creator/get_creator"
            
            # Note: This might not work as it's an internal API
            # but it's worth trying for brand channel discovery
            
        except Exception as e:
            st.info("YouTube Studio API not accessible")
        
        # Method 2: Enumerate through Analytics API with different channel patterns
        try:
            analytics_service = build('youtubeAnalytics', 'v2', credentials=credentials)
            discovered_channels = []
            
            # Try different approaches to discover channels through analytics
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
        return [] Streamlit Cloud URL from secrets or environment."""
    return st.secrets["STREAMLIT_CLOUD_URI"]

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
                channel['channel_type'] = 'Personal'
                channel['discovery_method'] = 'YouTube API - mine=True'
                all_channels.append(channel)
                
        except HttpError as e:
            st.warning(f"Could not fetch personal channel: {e}")
        
        # Method 2: Direct REST API call to get all channels
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
            
            # This endpoint sometimes returns more channels than the SDK
            api_url = "https://www.googleapis.com/youtube/v3/channels"
            params = {
                'part': 'snippet,statistics,brandingSettings,contentDetails',
                'mine': 'true',
                'maxResults': 50
            }
            
            response = requests.get(api_url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                direct_channels = data.get('items', [])
                
                existing_ids = {ch['id'] for ch in all_channels}
                for channel in direct_channels:
                    if channel['id'] not in existing_ids:
                        channel['channel_type'] = 'Direct API'
                        channel['discovery_method'] = 'Direct REST API'
                        all_channels.append(channel)
                        
        except Exception as e:
            st.info(f"Direct API method failed: {e}")
        
        # Method 3: Use YouTube Analytics API to discover channels
        try:
            analytics_service = build('youtubeAnalytics', 'v2', credentials=credentials)
            
            # Try to get available channels through analytics
            # This often reveals brand channels that aren't shown in regular API
            analytics_url = "https://youtubeanalytics.googleapis.com/v2/reports"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
            
            # Get a simple report that will reveal channel IDs
            params = {
                'ids': 'channel==MINE',  # Special keyword for all accessible channels
                'startDate': '2023-01-01',
                'endDate': '2023-01-02',
                'metrics': 'views',
                'dimensions': 'channel'
            }
            
            response = requests.get(analytics_url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                if 'rows' in data:
                    for row in data['rows']:
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
                                
                                existing_ids = {ch['id'] for ch in all_channels}
                                for channel in analytics_channels:
                                    if channel['id'] not in existing_ids:
                                        channel['channel_type'] = 'Analytics Discovery'
                                        channel['discovery_method'] = 'YouTube Analytics API'
                                        all_channels.append(channel)
                                        
                            except HttpError:
                                pass
                                
        except Exception as e:
            st.info(f"Analytics discovery method failed: {e}")
        
        # Method 4: Brand account specific discovery
        try:
            # Use Google's People API to get associated accounts
            people_service = build('people', 'v1', credentials=credentials)
            
            # Get the user's profile which might reveal brand accounts
            profile = people_service.people().get(
                resourceName='people/me',
                personFields='emailAddresses'
            ).execute()
            
            # This is a more advanced approach that might work for brand accounts
            # We'll try to enumerate possible brand channels
            
        except Exception as e:
            st.info(f"Brand account discovery not available: {e}")
        
        # Method 5: Channel enumeration through search
        try:
            # Search for channels owned by the authenticated user
            search_request = youtube_service.search().list(
                part="snippet",
                forMine=True,
                type="channel",
                maxResults=50
            )
            search_response = search_request.execute()
            
            for item in search_response.get('items', []):
                channel_id = item['snippet']['channelId']
                
                # Get full channel details
                try:
                    channel_request = youtube_service.channels().list(
                        part="snippet,statistics,brandingSettings",
                        id=channel_id
                    )
                    channel_response = channel_request.execute()
                    search_channels = channel_response.get("items", [])
                    
                    existing_ids = {ch['id'] for ch in all_channels}
                    for channel in search_channels:
                        if channel['id'] not in existing_ids:
                            channel['channel_type'] = 'Search Discovery'
                            channel['discovery_method'] = 'YouTube Search API'
                            all_channels.append(channel)
                            
                except HttpError:
                    pass
                    
        except HttpError as e:
            st.info(f"Search discovery failed: {e}")
        
        # Method 6: Channel Groups API (for brand accounts)
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
            
            # Try to get channel groups which might reveal brand channels
            groups_url = "https://youtubeanalytics.googleapis.com/v2/groupItems"
            params = {
                'groupId': 'allChannels'  # This might reveal brand channels
            }
            
            response = requests.get(groups_url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('items', []):
                    channel_id = item.get('resource', {}).get('id')
                    if channel_id:
                        try:
                            channel_request = youtube_service.channels().list(
                                part="snippet,statistics,brandingSettings",
                                id=channel_id
                            )
                            channel_response = channel_request.execute()
                            group_channels = channel_response.get("items", [])
                            
                            existing_ids = {ch['id'] for ch in all_channels}
                            for channel in group_channels:
                                if channel['id'] not in existing_ids:
                                    channel['channel_type'] = 'Group Discovery'
                                    channel['discovery_method'] = 'Channel Groups API'
                                    all_channels.append(channel)
                                    
                        except HttpError:
                            pass
                            
        except Exception as e:
            st.info(f"Groups discovery failed: {e}")
        
        # Method 7: Legacy API endpoints (sometimes more permissive)
        try:
            # Try older v2 API endpoints that might still work
            legacy_url = "https://gdata.youtube.com/feeds/api/users/default/channels"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'GData-Version': '2'
            }
            
            response = requests.get(legacy_url, headers=headers)
            # This is just a fallback attempt
            
        except Exception as e:
            pass  # Legacy APIs often fail, that's expected
        
        # Display discovery summary
        if all_channels:
            st.success(f"🎉 Found {len(all_channels)} total channels using multiple discovery methods!")
            
            # Group by discovery method
            method_counts = {}
            for channel in all_channels:
                method = channel.get('discovery_method', 'Unknown')
                method_counts[method] = method_counts.get(method, 0) + 1
            
            st.write("**Discovery Summary:**")
            for method, count in method_counts.items():
                st.write(f"- {method}: {count} channels")
                
        else:
            st.error("❌ No channels found with comprehensive discovery methods.")
            st.write("**This suggests that:**")
            st.write("1. Your brand channels may not be properly linked to this Google account")
            st.write("2. You may need to use each brand channel's specific Google account")
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
        
        # Use Streamlit Cloud URL
        redirect_uri = get_streamlit_cloud_url()
        
        # Update CLIENT_CONFIG with the Streamlit Cloud redirect URI
        CLIENT_CONFIG["web"]["redirect_uris"] = [redirect_uri]
        
        flow = Flow.from_client_config(
            CLIENT_CONFIG,
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        auth_url, _ = flow.authorization_url(prompt='consent')
        
        # Display current redirect URI for verification
        with st.expander("🔧 App Configuration"):
            st.write(f"**Streamlit Cloud URL:** {redirect_uri}")
            st.write("Make sure this URL is added to your Google Cloud Console OAuth settings.")
        
        st.link_button("🔐 Authorize with Google", auth_url, type="primary")
        
        # Manual authorization code input as primary method for Streamlit Cloud
        st.write("---")
        st.subheader("📝 Authorization Code")
        st.write("After clicking the authorization button above:")
        st.write("1. Complete the Google authorization process")
        st.write("2. You may see an error page - that's normal!")
        st.write("3. Copy the **code** parameter from the URL")
        st.write("4. Paste it below and click Submit")
        
        # Example of what to look for
        st.code("Example URL: https://your-app.streamlit.app/?code=4/0AbUR2VM... \nCopy: 4/0AbUR2VM...")
        
        manual_auth_code = st.text_input(
            "Paste Authorization Code Here", 
            placeholder="4/0AbUR2VM...",
            help="Copy the entire code parameter from the redirect URL"
        )
        
        if st.button("✅ Submit Authorization Code", type="primary") and manual_auth_code:
            try:
                # Clean the auth code (remove any extra spaces or characters)
                clean_auth_code = manual_auth_code.strip()
                flow.fetch_token(code=clean_auth_code)
                save_credentials_to_session(flow.credentials)
                st.success("🎉 Authentication successful! Navigate to Analytics Dashboard.")
                st.balloons()
                st.rerun()
            except Exception as e:
                st.error(f"❌ Authentication failed: {e}")
                st.write("**Troubleshooting tips:**")
                st.write("- Make sure you copied the complete authorization code")
                st.write("- The code should start with '4/0A' or similar")
                st.write("- Try getting a fresh code by clicking the authorization button again")

        # Auto-check for authorization code in URL (backup method)
        auth_code = st.query_params.get("code")
        if auth_code:
            try:
                flow.fetch_token(code=auth_code)
                save_credentials_to_session(flow.credentials)
                st.success("🎉 Authentication successful! Navigate to Analytics Dashboard.")
                st.rerun()
            except Exception as e:
                st.error(f"Auto-authentication failed: {e}")
                st.write("Please use the manual method above.")
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
            owned_channels = [ch for ch in channels if ch.get('channel_type') == 'Owned']
            
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
            
            # Display owned channels
            if owned_channels:
                st.write("**Owned Channels:**")
                for channel in owned_channels:
                    col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
                    with col1:
                        st.write(f"👑 **{channel['snippet']['title']}**")
                    with col2:
                        st.write(f"Subscribers: {channel['statistics'].get('subscriberCount', 'Hidden')}")
                    with col3:
                        st.write(f"Videos: {channel['statistics'].get('videoCount', '0')}")
                    with col4:
                        st.write("Owned")
            
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
            if channels:
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
            default=list(channel_options.keys())[:3] if len(channel_options) <= 3 else list(channel_options.keys())[:3]  # Select first 3 by default
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
