# FitOverlays - Copyright (c) 2025 Spyros Lontos
# Licensed under AGPL-3.0

from flask import Flask, jsonify, send_from_directory, session, redirect, url_for, request, Response
import os
import json
import time
import requests
import logging
import secrets
from logging.handlers import RotatingFileHandler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
from flask_limiter.errors import RateLimitExceeded
from validators import validate_activity_id, validate_filename
from werkzeug.utils import secure_filename, safe_join

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

# Configure logging
if not os.path.exists('logs'):
    os.makedirs('logs')

logging.basicConfig(
    handlers=[
        RotatingFileHandler(
            'logs/security.log',
            maxBytes=10000000,  # 10MB
            backupCount=5
        ),
        logging.StreamHandler()
    ],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Add CSP configuration function
def add_security_headers(response: Response) -> Response:
    """Add security headers including Content Security Policy"""
    csp = {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'"],  # Required for inline scripts
        'style-src': ["'self'", "'unsafe-inline'"],   # Required for inline styles
        'img-src': ["'self'", "*.strava.com", "data:"],
        'connect-src': ["'self'", "www.strava.com", "strava.com"],
        'frame-ancestors': ["'none'"],
        'form-action': ["'self'"],
        'base-uri': ["'self'"]
    }
    
    csp_string = '; '.join([
        f"{key} {' '.join(value)}" 
        for key, value in csp.items()
    ])
    
    # Add security headers
    response.headers['Content-Security-Policy'] = csp_string
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    return response

# Apply security headers to all responses
app.after_request(add_security_headers)

# Setup rate limiter (stores limits in memory by default)
limiter = Limiter(
    get_remote_address,  # Uses IP address for limiting
    app=app,
    default_limits=["100 per day", "30 per hour"]  # More restrictive default limits
)

ACTIVITIES_DIR = "activities"

if not os.path.exists(ACTIVITIES_DIR):
    os.makedirs(ACTIVITIES_DIR)

def generate_csrf_token():
    """Generate a new CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token():
    """Validate CSRF token from request header against session token"""
    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        token = request.headers.get('X-CSRF-Token')
        if not token or token != session.get('csrf_token'):
            logger.warning(f'CSRF validation failed - IP: {get_remote_address()}')
            return False
    return True

@app.before_request
def csrf_protect():
    """Protect all state-changing requests with CSRF validation"""
    if not validate_csrf_token():
        return jsonify({"error": "Invalid CSRF token"}), 403

@app.route('/login')
@limiter.limit("10 per minute")  # Add rate limit for login to prevent OAuth abuse
def login():
    """Handle the login process using Strava OAuth"""
    try:
        oauth = OAuth2Session(
            CLIENT_ID,
            redirect_uri="http://127.0.0.1:5000/callback",  # Update to match exact local URL
            scope=["activity:read_all"]
        )
        authorization_url, state = oauth.authorization_url(AUTH_BASE_URL)
        session['oauth_state'] = state
        return redirect(authorization_url)
    except Exception as e:
        logger.warning(f'Failed login attempt: {str(e)} - IP: {get_remote_address()}')
        return jsonify({"error": "Authentication failed"}), 401

@app.route('/callback')
@limiter.limit("10 per minute")  # Add rate limit for callback to prevent OAuth abuse
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
        logger.error(f'OAuth callback error details: {str(e)} - IP: {get_remote_address()}')
        return jsonify({"error": "Authentication failed. Please try again."}), 400

@app.route('/logout', methods=['POST'])  # Add POST method
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

@app.route('/activities/<path:filename>')
def serve_activity(filename):
    """Securely serve activity files only to authorized users"""
    if 'athlete_id' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    # Validate filename with athlete_id check
    is_valid, error = validate_filename(filename, session.get('athlete_id'))
    if not is_valid:
        return jsonify({"error": error}), 400
    
    try:
        # Sanitize filename and ensure it's within ACTIVITIES_DIR
        safe_filename = secure_filename(filename)
        if safe_filename != filename:
            return jsonify({"error": "Invalid filename"}), 400
            
        # Use safe_join to prevent directory traversal
        file_path = safe_join(ACTIVITIES_DIR, safe_filename)
        if not file_path:
            return jsonify({"error": "Invalid file path"}), 400

        # Get absolute paths for comparison
        activities_abs_path = os.path.abspath(ACTIVITIES_DIR)
        file_abs_path = os.path.abspath(file_path)
        
        # Additional check: Ensure file path starts with activities directory
        # This prevents symbolic link attacks and ensures we stay within ACTIVITIES_DIR
        if not file_abs_path.startswith(activities_abs_path):
            logger.warning(f'Directory traversal attempt detected - IP: {get_remote_address()} - Path: {filename}')
            return jsonify({"error": "Invalid file path"}), 403

        # Check if file exists after all validations
        if not os.path.exists(file_abs_path):
            return jsonify({"error": "Activity not found"}), 404

        return send_from_directory(ACTIVITIES_DIR, safe_filename)
    except Exception as e:
        logger.error(f'Error serving activity: {str(e)} - IP: {get_remote_address()} - File: {filename}')
        return jsonify({"error": "Error accessing activity data"}), 500

def save_activity_response(athlete_id, activity_id, data, status_code=200):
    """Save activity data or error response to file"""
    filename = f'response_{athlete_id}_{activity_id}.json'
    with open(os.path.join(ACTIVITIES_DIR, filename), 'w') as outfile:
        json.dump(data, outfile, indent=4)
    return jsonify(data), status_code

@app.route('/fetch_activity/<athlete_id>/<activity_id>', methods=['POST'])
@limiter.limit("5 per minute;20 per hour;100 per day")  # Stricter limits for fetch endpoint
def get_activity(athlete_id, activity_id):
    """Fetch activity with input validation for both athlete and activity IDs"""
    if 'athlete_id' not in session:
        logger.warning(f'Unauthenticated access attempt - IP: {get_remote_address()}')
        return jsonify({"error": "Not authenticated"}), 401

    # Verify athlete_id matches session
    try:
        if int(athlete_id) != session['athlete_id']:
            logger.warning(f'Unauthorized athlete access attempt - IP: {get_remote_address()} - ' \
                         f'Requested Athlete: {athlete_id}, Session Athlete: {session["athlete_id"]}')
            return jsonify({"error": "Unauthorized access"}), 403
    except ValueError:
        return jsonify({"error": "Invalid athlete ID"}), 400

    # Validate activity_id
    is_valid, error = validate_activity_id(activity_id)
    if not is_valid:
        return jsonify({"error": error}), 400

    filename = f'response_{athlete_id}_{activity_id}.json'
    
    # Validate generated filename
    is_valid, error = validate_filename(filename, athlete_id)
    if not is_valid:
        return jsonify({"error": error}), 400

    json_path = os.path.join(ACTIVITIES_DIR, filename)
    
    try:
        # If file exists, read and return its contents
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                data = json.load(f)
                if 'error' in data:
                    return jsonify(data), data.get('status', 500)
                # Verify athlete_id in data matches session
                if data.get('athlete', {}).get('id') == session['athlete_id']:
                    return jsonify(data)
                return jsonify({"error": "Unauthorized access"}), 403

        # Fetch new activity data
        return fetch_activity(activity_id)
            
    except Exception as e:
        logger.error(f'Activity fetch error details: {str(e)} - IP: {get_remote_address()} - Activity: {activity_id}')
        return jsonify({"error": "Unable to process request. Please try again later."}), 500

@app.route("/status")
@limiter.limit("30 per minute")  # Add specific limit for status endpoint
def status():
    """Check if user is authenticated and provide CSRF token"""
    try:
        if "access_token" in session:
            # Generate new CSRF token if needed
            csrf_token = generate_csrf_token()
            # Check if token needs refresh
            if "expires_at" in session:
                current_time = time.time()
                # Add 5 minute buffer to token expiry
                if session["expires_at"] - current_time < 300:  # 5 minutes
                    new_token = refresh_access_token(session.get("refresh_token"))
                    if new_token:
                        session["access_token"] = new_token["access_token"]
                        session["refresh_token"] = new_token["refresh_token"]
                        session["expires_at"] = new_token["expires_at"]
                    else:
                        # Clear session if refresh fails
                        session.clear()
                        return jsonify({
                            "authenticated": False,
                            "error": "Session expired. Please log in again.",
                            "require_login": True,
                            "csrf_token": csrf_token
                        })
            return jsonify({
                "authenticated": True,
                "athlete_id": session.get("athlete_id"),
                "expires_at": session.get("expires_at"),
                "csrf_token": csrf_token
            })
        return jsonify({
            "authenticated": False,
            "csrf_token": generate_csrf_token()
        })
    except Exception as e:
        return jsonify({
            "authenticated": False,
            "error": str(e),
            "require_login": True,
            "csrf_token": generate_csrf_token()
        }), 500

@app.errorhandler(RateLimitExceeded)
def handle_ratelimit_error(e):
    logger.warning(f'Rate limit exceeded - IP: {get_remote_address()} - Endpoint: {request.path}')
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
    """Fetch Strava activity data with validation"""
    if 'access_token' not in session or 'athlete_id' not in session:
        logger.warning(f'Unauthenticated activity access attempt - IP: {get_remote_address()} - Activity: {activity_id}')
        return jsonify({"error": "Not authenticated"}), 401

    # Check token expiry before making request
    if "expires_at" in session and time.time() > session["expires_at"]:
        logger.info(f'Session expired - Athlete ID: {session.get("athlete_id")} - IP: {get_remote_address()}')
        session.clear()
        return jsonify({
            "error": "Session expired. Please log in again.",
            "require_login": True
        }), 401

    # Validate activity_id
    is_valid, error = validate_activity_id(activity_id)
    if not is_valid:
        return jsonify({"error": error}), 400

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
            logger.warning(f'Unauthorized activity access attempt - IP: {get_remote_address()} - ' \
                         f'Athlete: {session["athlete_id"]} - Activity: {activity_id}')
            return jsonify({"error": "Unauthorized access"}), 403
        
        # Store and return successful activity data
        return save_activity_response(session['athlete_id'], activity_id, response_json)
            
    except requests.exceptions.RequestException as e:
        logger.error(f'Strava API error details: {str(e)} - IP: {get_remote_address()} - Activity: {activity_id}')
        return jsonify({"error": "Unable to fetch activity data. Please try again later."}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
