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

# --- Page Configuration ---
st.set_page_config(page_title="Multi-Channel YouTube Analytics Dashboard", page_icon="📊", layout="wide")

# --- Google API Configuration ---
SCOPES = [
    "https://www.googleapis.com/auth/yt-analytics.readonly",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/youtube.readonly"
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

def get_streamlit_cloud_url():
    """Gets the Streamlit Cloud URL from secrets or environment."""
    return st.secrets["STREAMLIT_CLOUD_URI"]

def get_accessible_channels(credentials):
    """Uses the YouTube Data API v3 to list channels accessible by the user."""
    try:
        youtube_service = build('youtube', 'v3', credentials=credentials)
        request = youtube_service.channels().list(
            part="snippet,statistics",
            mine=True,
            maxResults=50
        )
        response = request.execute()
        return response.get("items", [])
    except HttpError as e:
        st.error(f"An error occurred while checking accessible channels: {e}")
        return None

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
            channels = get_accessible_channels(creds)
        
        if channels:
            st.write("### Your YouTube Channels:")
            for channel in channels:
                col1, col2, col3 = st.columns([3, 2, 2])
                with col1:
                    st.write(f"**{channel['snippet']['title']}**")
                with col2:
                    st.write(f"Subscribers: {channel['statistics'].get('subscriberCount', 'Hidden')}")
                with col3:
                    st.write(f"Videos: {channel['statistics'].get('videoCount', '0')}")
        
        if st.button("🚪 Logout"):
            st.session_state.credentials = None
            st.rerun()

elif page == "📊 Analytics Dashboard":
    if creds is None:
        st.warning("Please authenticate first!")
        st.stop()
    
    st.header("Analytics Dashboard")
    
    with st.spinner("Loading channels..."):
        channels = get_accessible_channels(creds)
    
    if channels:
        # Channel selection
        channel_options = {ch['snippet']['title']: ch['id'] for ch in channels}
        selected_channel_names = st.multiselect(
            "Select channels to analyze:",
            options=list(channel_options.keys()),
            default=list(channel_options.keys())[:3]  # Select first 3 by default
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
