from flask import Flask, jsonify, send_from_directory, session, redirect, url_for, request
import os
import json
import time
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
from flask_limiter.errors import RateLimitExceeded

# Load environment variables from .env file
load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
AUTH_BASE_URL = os.getenv("AUTH_BASE_URL")
TOKEN_URL = os.getenv("TOKEN_URL")

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Allow OAuth without HTTPS in development

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = os.urandom(24)

# Setup rate limiter (stores limits in memory by default)
limiter = Limiter(
    get_remote_address,  # Uses IP address for limiting
    app=app,
    default_limits=["10 per minute"]  # Adjust as needed
)

ACTIVITIES_DIR = "activities"

if not os.path.exists(ACTIVITIES_DIR):
    os.makedirs(ACTIVITIES_DIR)

@app.route('/login')
def login():
    """Handle the login process using Strava OAuth"""
    oauth = OAuth2Session(
        CLIENT_ID,
        redirect_uri="http://127.0.0.1:5000/callback",  # Update to match exact local URL
        scope=["activity:read_all"]
    )
    authorization_url, state = oauth.authorization_url(AUTH_BASE_URL)
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    """Handle the OAuth callback from Strava"""
    try:
        oauth = OAuth2Session(
            CLIENT_ID,
            state=session.get('oauth_state'),
            redirect_uri="http://127.0.0.1:5000/callback"  # Update to match exact local URL
        )
        token = oauth.fetch_token(
            TOKEN_URL,
            client_secret=CLIENT_SECRET,
            authorization_response=request.url,
            include_client_id=True
        )
        
        # Store athlete info in session
        athlete = token.get('athlete', {})
        session['athlete_id'] = athlete.get('id')
        session['access_token'] = token['access_token']
        session['refresh_token'] = token['refresh_token']
        session['expires_at'] = token['expires_at']
        
        return redirect('/')
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/logout')
def logout():
    """Clear the session data"""
    session.clear()
    return redirect('/')

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/static/<path:path>')
def serve_static(path):
    """Serve static files from the static directory"""
    return send_from_directory('static', path)

# Remove or comment out this route since it's now covered by the general static route
# @app.route('/static/images/<path:filename>')
# def static_files(filename):
#     return send_from_directory('static/images', filename)

@app.route('/activities/<path:filename>')
def serve_activity(filename):
    """Securely serve activity files only to authorized users"""
    if 'athlete_id' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    # Validate filename format - now includes athlete_id
    if not filename.startswith('response_') or not filename.endswith('.json'):
        return jsonify({"error": "Invalid filename"}), 400
    
    try:
        # Parse athlete_id and activity_id from filename
        parts = filename.replace('response_', '').replace('.json', '').split('_')
        if len(parts) != 2:
            return jsonify({"error": "Invalid filename format"}), 400
        
        file_athlete_id, activity_id = map(int, parts)
        
        # Verify athlete_id matches session
        if file_athlete_id != session['athlete_id']:
            return jsonify({"error": "Unauthorized access"}), 403

        file_path = os.path.join(ACTIVITIES_DIR, filename)
        if not os.path.exists(file_path):
            return jsonify({"error": "Activity not found"}), 404

        return send_from_directory(ACTIVITIES_DIR, filename)
    except Exception as e:
        return jsonify({"error": "Error accessing activity data"}), 500

def save_activity_response(athlete_id, activity_id, data, status_code=200):
    """Save activity data or error response to file"""
    filename = f'response_{athlete_id}_{activity_id}.json'
    with open(os.path.join(ACTIVITIES_DIR, filename), 'w') as outfile:
        json.dump(data, outfile, indent=4)
    return jsonify(data), status_code

@app.route('/fetch_activity/<activity_id>')
@limiter.limit("5 per minute")
def get_activity(activity_id):
    if 'athlete_id' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    filename = f'response_{session["athlete_id"]}_{activity_id}.json'
    json_path = os.path.join(ACTIVITIES_DIR, filename)
    
    try:
        # If file exists, read and return its contents
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                data = json.load(f)
                if 'error' in data:
                    return jsonify(data), data.get('status', 500)
                if data.get('athlete', {}).get('id') == session['athlete_id']:
                    return jsonify(data)
                return jsonify({"error": "Unauthorized access"}), 403

        # Fetch new activity data
        return fetch_activity(activity_id)
            
    except Exception as e:
        print(f"Error processing activity request: {e}")
        return jsonify({"error": "Error processing activity request"}), 500

@app.route("/status")
def status():
    """Check if user is authenticated"""
    try:
        if "access_token" in session:
            # Check if token needs refresh
            if "expires_at" in session and session["expires_at"] < time.time():
                new_token = refresh_access_token(session.get("refresh_token"))
                if new_token:
                    session["access_token"] = new_token["access_token"]
                    session["refresh_token"] = new_token["refresh_token"]
                    session["expires_at"] = new_token["expires_at"]
                else:
                    return jsonify({"authenticated": False, "error": "Token refresh failed"})
            return jsonify({
                "authenticated": True,
                "athlete_id": session.get("athlete_id")  # Include athlete_id in response
            })
        return jsonify({"authenticated": False})
    except Exception as e:
        return jsonify({"authenticated": False, "error": str(e)}), 500

@app.errorhandler(RateLimitExceeded)
def handle_ratelimit_error(e):
    return jsonify({
        "error": "Rate limit exceeded. Please wait before trying again.",
        "status": 429
    }), 429

def refresh_access_token(refresh_token):
    """Refresh the access token if expired"""
    if not refresh_token:
        return None

    try:
        response = requests.post(
            "https://www.strava.com/oauth/token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token
            }
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return None

def fetch_activity(activity_id):
    """Fetch Strava activity data using session access token."""
    if 'access_token' not in session or 'athlete_id' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        response = requests.get(
            f"https://www.strava.com/api/v3/activities/{activity_id}",
            headers={"Authorization": f"Bearer {session['access_token']}"}
        )
        
        # Handle error cases
        if not response.ok:
            error_data = {"error": "Failed to load activity. Activity ID not found"}
            return save_activity_response(session['athlete_id'], activity_id, error_data, response.status_code)
            
        response_json = response.json()
        
        # Verify activity belongs to authenticated user
        if response_json.get('athlete', {}).get('id') != session['athlete_id']:
            return jsonify({"error": "Unauthorized access"}), 403
        
        # Store and return successful activity data
        return save_activity_response(session['athlete_id'], activity_id, response_json)
            
    except requests.exceptions.RequestException as e:
        print(f"Error fetching activity: {e}")
        return jsonify({"error": "Failed to fetch activity data"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
