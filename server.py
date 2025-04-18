# FitnessOverlays - Copyright (c) 2025 Spyros Lontos
# Licensed under AGPL-3.0

from flask import Flask, jsonify, send_from_directory, session, redirect, url_for, request, Response, send_file
import os
import time
import requests
import logging
import secrets
from logging.handlers import TimedRotatingFileHandler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
from flask_limiter.errors import RateLimitExceeded
from werkzeug.utils import secure_filename, safe_join
import re
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone, timedelta

# Add this log line right at the top
logging.basicConfig(level=logging.INFO) # Basic config if logger not set up yet
logging.info("--- server.py script started execution ---")

# Load environment variables from .env file
load_dotenv()

# --- Environment Variable Validation ---
def check_env_vars():
    required_vars = [
        "CLIENT_ID",
        "CLIENT_SECRET",
        "AUTH_BASE_URL",
        "TOKEN_URL",
        "DATABASE_FILENAME",
        "SECRET_KEY",
        "RATELIMIT_STORAGE_URI",
        "ENVIRONMENT"
    ]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

check_env_vars() # Execute validation immediately
# --- End Validation ---

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
AUTH_BASE_URL = os.getenv("AUTH_BASE_URL")
TOKEN_URL = os.getenv("TOKEN_URL")
DATABASE_FILENAME = os.getenv("DATABASE_FILENAME")
PERSISTENT_DATA_DIR = os.getenv("PERSISTENT_DATA_DIR", None) # Optional for local dev
RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://") # Default to memory if not set

# Environment-based configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "prod").lower()  # Default to prod if not set
if ENVIRONMENT == "dev":
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Allow OAuth without HTTPS in development
    DEBUG_MODE = True
else:
    # In production, we don't set OAUTHLIB_INSECURE_TRANSPORT at all
    # This ensures HTTPS is required
    if 'OAUTHLIB_INSECURE_TRANSPORT' in os.environ:
        del os.environ['OAUTHLIB_INSECURE_TRANSPORT']
    DEBUG_MODE = False

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Use a consistent secret key from environment variables
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    # Optionally, log an error or provide a default for local dev (not recommended for prod)
    # For production, it's better to fail fast if the key is missing.
    raise ValueError("SECRET_KEY environment variable not set. Cannot run application securely.")

# Configure logging
if not os.path.exists('logs'):
    # Use exist_ok=True to prevent errors if the directory already exists
    os.makedirs('logs', exist_ok=True)

# Use TimedRotatingFileHandler for daily logs
log_file = 'logs/app.log' # Base log filename
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Custom namer for log files
def custom_namer(default_name):
    # default_name looks like /path/to/logs/app.log.YYYY-MM-DD
    dir_name, file_name = os.path.split(default_name)
    try:
        # Split assuming the original extension '.log' is present before the date suffix
        base_name, timestamp_suffix = file_name.split('.log.')
        # Construct the new name: logs/app.YYYY-MM-DD.log
        new_name = os.path.join(dir_name, f"{base_name}.{timestamp_suffix}.log")
    except ValueError:
        # Fallback in case the split fails (e.g., initial log file)
        # This shouldn't happen with TimedRotatingFileHandler naming, but good practice
        new_name = default_name + ".rotated" # Or handle differently
        logging.error(f"Could not parse rotated log filename: {default_name}. Using fallback: {new_name}")
    return new_name

# Configure TimedRotatingFileHandler for daily rotation at midnight, keeping 30 days of logs
# Rotated files will have dates appended like app.YYYY-MM-DD -> NOW app.YYYY-MM-DD.log
timed_handler = TimedRotatingFileHandler(
    log_file,
    when='midnight', # Rotate daily at midnight
    interval=1,      # Interval is 1 day
    backupCount=30,  # Keep 30 days of backup logs
    encoding='utf-8',# Use UTF-8 encoding
    delay=False,     # Open file immediately
    utc=False        # Use local time for rotation timestamp
)
timed_handler.namer = custom_namer # Assign the custom namer
timed_handler.setFormatter(formatter)
timed_handler.setLevel(logging.INFO)

# Configure StreamHandler for console output
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
stream_handler.setLevel(logging.INFO) # Or DEBUG if you want more verbose console output

# Get the root logger and remove existing handlers (if any added by default)
root_logger = logging.getLogger()
root_logger.handlers.clear()

# Add the configured handlers
root_logger.addHandler(timed_handler)
root_logger.addHandler(stream_handler)
root_logger.setLevel(logging.INFO) # Set root logger level

# Use the configured logger throughout the app
logger = logging.getLogger(__name__)

# --- Database Path Construction ---
def get_database_uri(filename, persistent_dir):
    db_path = None
    # Production environment with a specified absolute persistent directory
    if ENVIRONMENT == "prod" and persistent_dir and os.path.isabs(persistent_dir):
        try:
            # Ensure the directory exists, create if necessary
            os.makedirs(persistent_dir, exist_ok=True)
            db_path = os.path.join(persistent_dir, filename)
            logger.info(f"Using persistent database path in PROD: {db_path}")
        except OSError as e:
            # Handle potential errors during directory creation (e.g., permissions)
            logger.error(f"Error creating persistent directory {persistent_dir} in PROD: {e}")
            # Fallback or raise error? Raising prevents startup if persistent disk is mandatory/expected.
            raise ValueError(f"Could not create persistent directory: {persistent_dir}") from e
    
    # Fallback for Development environment OR Production without a valid persistent_dir
    if db_path is None:
        instance_path = os.path.join(app.instance_path)
        try:
            # Ensure the instance folder exists
            os.makedirs(instance_path, exist_ok=True)
            db_path = os.path.join(instance_path, filename)
            if ENVIRONMENT == "prod":
                logger.info(f"Using instance folder database path in PROD (PERSISTENT_DATA_DIR not set/absolute): {db_path}")
            else:
                logger.info(f"Using instance folder database path in DEV: {db_path}")
        except OSError as e:
            logger.error(f"Error creating instance directory {instance_path}: {e}")
            raise ValueError(f"Could not create instance directory: {instance_path}") from e
            
    if db_path is None:
        # This should theoretically not be reached if makedirs works or raises
        critical_error = "Failed to determine a valid database path."
        logger.critical(critical_error)
        raise RuntimeError(critical_error)
        
    return f"sqlite:///{db_path}"
# --- End Database Path Construction ---

# Configure SQLAlchemy
# Construct the database URI dynamically
constructed_db_uri = get_database_uri(DATABASE_FILENAME, PERSISTENT_DATA_DIR)
app.config['SQLALCHEMY_DATABASE_URI'] = constructed_db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Recommended setting
app.config['RATELIMIT_STORAGE_URI'] = RATELIMIT_STORAGE_URI
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=1)
)
if ENVIRONMENT != "prod":
    app.config.update(
        SESSION_COOKIE_SECURE=False
    )
db = SQLAlchemy(app)

# Define the ActivityCache model
class ActivityCache(db.Model):
    activity_id = db.Column(db.BigInteger, primary_key=True)
    athlete_id = db.Column(db.BigInteger, index=True, nullable=False)
    data = db.Column(db.JSON, nullable=False)
    fetched_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<ActivityCache {self.athlete_id}:{self.activity_id}>'

# Create database tables if they don't exist
with app.app_context():
    db.create_all()

# Add CSP configuration function
def add_security_headers(response: Response) -> Response:
    """Add security headers including Content Security Policy"""
    csp = {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'", "cdn.tailwindcss.com"],
        'style-src': ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
        'font-src': ["'self'", "fonts.gstatic.com"],
        'img-src': ["'self'", "*.strava.com", "dgalywyr863hv.cloudfront.net", "data:"],
        'connect-src': ["'self'", "www.strava.com", "strava.com"],
        'frame-ancestors': ["'none'"],
        'form-action': ["'self'"],
        'base-uri': ["'self'"],
        'manifest-src': ["'self'"],
        'media-src': ["'self'"],
        'object-src': ["'none'"],
        'worker-src': ["'self'"]
    }
    
    # In production, remove the Tailwind CDN script source
    if ENVIRONMENT == "prod":
        # Ensure the CDN source is removed if present
        if "cdn.tailwindcss.com" in csp['script-src']:
             csp['script-src'].remove("cdn.tailwindcss.com")
        # No need to append '/static/css/tailwind.css' to style-src, 'self' covers it.
    
    csp_string = '; '.join([
        f"{key} {' '.join(value)}" 
        for key, value in csp.items()
    ])
    
    # Add security headers
    response.headers['Content-Security-Policy'] = csp_string
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Permissions-Policy'] = (
        'accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), '
        'encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), '
        'magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), '
        'screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()'
    )
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    # Remove X-Powered-By header if present
    response.headers.pop('X-Powered-By', None)
    response.headers.pop('Server', None)
    return response

def add_cache_control_headers(response):
    """Add cache control headers to prevent caching of sensitive data"""
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Update app.after_request to include cache control
@app.after_request
def after_request(response):
    """Apply security and cache control headers to all responses"""
    response = add_security_headers(response)
    
    # Add cache control headers to sensitive endpoints
    sensitive_endpoints = {'/status', '/fetch_activity', '/activities', '/callback', '/login'}
    if any(request.path.startswith(endpoint) for endpoint in sensitive_endpoints):
        response = add_cache_control_headers(response)
    elif request.path.startswith('/static/'):
        # Allow caching for static assets with 1 hour max age
        response.headers['Cache-Control'] = 'public, max-age=3600'
    else:
        # Default no-cache policy for other endpoints
        response.headers['Cache-Control'] = 'no-store, max-age=0'
    
    return response

# Setup rate limiter (NOW uses the storage URI from config)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "30 per hour"]
)

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
def login():
    """Handle the login process using Strava OAuth"""
    try:
        # Generate the dynamic callback URL
        callback_url = url_for('callback', _external=True)
        logger.info(f"Generated dynamic callback URL: {callback_url}") # Log the generated URL for debugging

        oauth = OAuth2Session(
            CLIENT_ID,
            redirect_uri=callback_url, # Use the dynamic URL
            scope=["activity:read_all"]
        )
        authorization_url, state = oauth.authorization_url(AUTH_BASE_URL)
        session['oauth_state'] = state
        return redirect(authorization_url)
    except Exception as e:
        logger.warning(f'Failed login attempt: {str(e)} - IP: {get_remote_address()}')
        return jsonify({"error": "Authentication failed"}), 401

@app.route('/callback')
def callback():
    """Handle the OAuth callback from Strava"""
    try:
        # Generate the dynamic callback URL consistently
        callback_url = url_for('callback', _external=True)
        logger.info(f"Using dynamic callback URL in callback handler: {callback_url}") # Log for debugging

        oauth = OAuth2Session(
            CLIENT_ID,
            state=session.get('oauth_state'),
            redirect_uri=callback_url # Use the dynamic URL here as well
        )
        token = oauth.fetch_token(
            TOKEN_URL,
            client_secret=CLIENT_SECRET,
            authorization_response=request.url, # Keep using request.url here, it contains the code from Strava
            include_client_id=True
        )
        
        # Store athlete info in session
        athlete = token.get('athlete', {})
        session['athlete_id'] = athlete.get('id')
        session['athlete_username'] = athlete.get('username')
        session['athlete_first_name'] = athlete.get('firstname')
        session['athlete_last_name'] = athlete.get('lastname')
        session['athlete_profile'] = athlete.get('profile_medium')  # Store profile picture URL
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
    # Serve index.html from static/html
    return send_from_directory('static/html', 'index.html')

@app.before_request
def require_authentication():
    """Serve the authentication required page for unauthenticated users."""
    # Allow requests to static files, login, callback, and root path
    if request.path.startswith('/static/') or request.path in ['/login', '/callback', '/']:
        return

    if 'athlete_id' not in session:
        # Serve auth_required.html from static/html
        return send_from_directory('static/html', 'auth_required.html')

ALLOWED_EXTENSIONS = {
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', 
    '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot'
}

@app.route('/static/<path:path>')
def serve_static(path):
    """Serve static files with strict validation"""
    try:
        # Validate file extension
        _, ext = os.path.splitext(path.lower())
        if ext not in ALLOWED_EXTENSIONS:
            logger.warning(f'Attempted to access unauthorized file type: {path} - IP: {get_remote_address()}')
            return jsonify({"error": "File type not allowed"}), 403

        # Use safe_join to prevent directory traversal
        safe_path = safe_join('static', path)
        if not safe_path:
            logger.warning(f'Directory traversal attempt detected - IP: {get_remote_address()} - Path: {path}')
            return jsonify({"error": "Invalid file path"}), 403

        # Get absolute paths for comparison
        static_abs_path = os.path.abspath('static')
        file_abs_path = os.path.abspath(safe_path)
        
        # Ensure file path starts with static directory
        if not file_abs_path.startswith(static_abs_path):
            logger.warning(f'Path traversal attempt detected - IP: {get_remote_address()} - Path: {path}')
            return jsonify({"error": "Invalid file path"}), 403

        # Check if file exists after all validations
        if not os.path.exists(file_abs_path):
            return jsonify({"error": "File not found"}), 404

        return send_from_directory('static', path)
    except Exception as e:
        logger.error(f'Error serving static file: {str(e)} - IP: {get_remote_address()} - Path: {path}')
        return jsonify({"error": "Error accessing file"}), 500

def save_or_update_activity(athlete_id, activity_id, data):
    """Save or update activity data in the database"""
    try:
        existing_activity = db.session.get(ActivityCache, activity_id) # Use db.session.get for primary key lookup
        if existing_activity:
            # Verify athlete ID match before updating
            if existing_activity.athlete_id != athlete_id:
                 logger.warning(f'Attempt to update activity {activity_id} belonging to athlete {existing_activity.athlete_id} by athlete {athlete_id}')
                 return False, jsonify({"error": "Unauthorized access to update activity"}), 403

            existing_activity.data = data
            existing_activity.fetched_at = datetime.now(timezone.utc)
            db.session.commit()
            logger.info(f'Updated activity {activity_id} for athlete {athlete_id} in DB')
            return True, jsonify(data), 200
        else:
            new_activity = ActivityCache(
                athlete_id=athlete_id,
                activity_id=activity_id,
                data=data
            )
            db.session.add(new_activity)
            db.session.commit()
            logger.info(f'Saved new activity {activity_id} for athlete {athlete_id} to DB')
            return True, jsonify(data), 200
    except Exception as e:
        db.session.rollback() # Rollback on error
        logger.error(f"Database error saving/updating activity {activity_id} for athlete {athlete_id}: {str(e)}")
        return False, jsonify({"error": "Database error saving activity data"}), 500

def resolve_strava_link(link):
    """Resolve a Strava deep link to get the actual activity ID"""
    try:
        # Clean the input
        link = link.strip()
        
        # First check if it's already a direct link
        direct_pattern = r'^(?:https?:\/\/)?(?:www\.)?strava\.com\/activities\/(\d+)(?:\/.*)?$'
        direct_match = re.match(direct_pattern, link)
        if direct_match:
            return direct_match.group(1)
        
        # Check if it's a deep link
        deep_link_pattern = r'^(?:https?:\/\/)?strava\.app\.link\/[A-Za-z0-9_-]+$'
        if not re.match(deep_link_pattern, link):
            return None

        # First request with mobile User-Agent to get redirect
        mobile_headers = {
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
            
        response = requests.head(
            link,
            allow_redirects=True,
            timeout=10,
            headers=mobile_headers,
            verify=True
        )
        
        # Get the final URL after redirects
        final_url = response.url
        logger.info(f'Resolved deep link to: {final_url}')
        
        # Try to match activity ID from various URL patterns
        patterns = [
            r'activities/(\d+)',
            r'activity/(\d+)',
            r'workout/(\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, final_url)
            if match:
                activity_id = match.group(1)
                is_valid, error = validate_activity_id(activity_id)
                if is_valid:
                    return activity_id
        
        return None
        
    except requests.RequestException as e:
        logger.error(f'Failed to resolve deep link: {str(e)}')
        return None
    except Exception as e:
        logger.error(f'Unexpected error resolving deep link: {str(e)}')
        return None

@app.route('/fetch_activity/<athlete_id>/<path:activity_input>', methods=['POST'])
@limiter.limit("5 per minute;20 per hour;100 per day")
def get_activity(athlete_id, activity_input):
    """Fetch activity from DB or Strava, with validation"""
    if 'athlete_id' not in session:
        logger.warning(f'Unauthenticated access attempt - URL athlete {athlete_id}, session athlete {session_athlete_id} - IP: {get_remote_address()}')
        return jsonify({"error": "Unauthorized access"}), 403

    try:
        # Validate athlete_id from URL against session
        session_athlete_id = session['athlete_id']
        if int(athlete_id) != session_athlete_id:
            logger.warning(f'Unauthorized athlete access attempt - URL athlete {athlete_id}, session athlete {session_athlete_id} - IP: {get_remote_address()}')
            return jsonify({"error": "Unauthorized access"}), 403
    except (ValueError, KeyError):
        return jsonify({"error": "Invalid athlete ID or session"}), 400

    final_activity_id = None
    is_link = False

    # Resolve link if necessary
    deep_link_pattern = r'^(?:https?:\/\/)?strava\.app\.link\/[A-Za-z0-9_-]+$'
    direct_link_pattern = r'^(?:https?:\/\/)?(?:www\.)?strava\.com\/activities\/\d+'
    if re.match(deep_link_pattern, activity_input) or re.match(direct_link_pattern, activity_input):
        is_link = True
        resolved_id = resolve_strava_link(activity_input)
        if not resolved_id:
            logger.warning(f'Could not resolve Strava link: {activity_input}')
            return jsonify({"error": "Could not resolve Strava link"}), 400
        final_activity_id = resolved_id
        logger.info(f'Resolved link {activity_input} to activity ID: {final_activity_id}')
    else:
        # Assume it's a direct ID
        final_activity_id = activity_input

    # Validate the final activity ID
    is_valid, error = validate_activity_id(final_activity_id)
    if not is_valid:
        return jsonify({"error": error or "Invalid activity ID"}), 400

    try:
        # 1. Check Database Cache
        # Convert final_activity_id to int for DB lookup
        try:
            db_activity_id = int(final_activity_id)
        except (ValueError, TypeError):
             # This should have been caught by validate_activity_id, but belts and braces
            return jsonify({"error": "Invalid activity ID format for lookup"}), 400
            
        cached_activity = db.session.get(ActivityCache, db_activity_id)
        if cached_activity:
            # Verify athlete ID match
            if cached_activity.athlete_id != session_athlete_id:
                logger.warning(f'Unauthorized DB access attempt - Activity {final_activity_id} belongs to {cached_activity.athlete_id}, requested by {session_athlete_id}')
                return jsonify({"error": "Unauthorized access"}), 403
            
            # Optional: Add cache expiry logic here if needed
            # e.g., if datetime.now(timezone.utc) - cached_activity.fetched_at > timedelta(hours=1): fetch new
            
            logger.info(f"Serving activity {final_activity_id} for athlete {session_athlete_id} from DB cache.")
            
            # Check if the cached data indicates 'not found'
            cached_data = cached_activity.data
            if isinstance(cached_data, dict) and cached_data.get('error') == 'not_found':
                logger.info(f"Activity {final_activity_id} previously determined as not found (cached).")
                return jsonify({"error": "Activity not found (cached)"}), 404
                
            return jsonify(cached_data)

        # 2. If not in cache or expired, fetch from Strava
        logger.info(f"Activity {final_activity_id} for athlete {session_athlete_id} not in cache, fetching from Strava.")
        return fetch_activity_from_strava(final_activity_id) # Call the renamed function

    except Exception as e:
        logger.error(f'Activity lookup/fetch error: {str(e)} - IP: {get_remote_address()} - Activity Input: {activity_input}, Resolved ID: {final_activity_id}')
        return jsonify({"error": "Unable to process request. Please try again later."}), 500

def validate_activity_id(activity_id):
    """
    Validate Strava activity ID.
    Returns (is_valid: bool, error_message: str)
    """
    print('INSIDE THE validate_activity_id FUNCTION')
    if not activity_id:
        return False, "Activity ID is required"
    
    print(f'activity_id: {activity_id}')
    try:
        # Convert to integer
        activity_id = int(activity_id)
        
        # Check if positive and within reasonable bounds
        if activity_id <= 0:
            return False, "Activity ID must be positive"
        
        # Add strict regex validation for activity ID format
        if not re.match(r'^[1-9]\d{0,19}$', str(activity_id)):
            return False, "Invalid activity ID format"
            
        return True, None
        
    except (ValueError, TypeError):
        return False, "Activity ID must be a number"

# Rename original fetch_activity to avoid conflict and clarify purpose
def fetch_activity_from_strava(activity_id):
    """Fetch Strava activity data from API and save to DB"""
    if 'access_token' not in session or 'athlete_id' not in session:
        # This check is technically redundant due to get_activity caller, but good for safety
        logger.warning(f'Unauthenticated Strava fetch attempt - IP: {get_remote_address()} - Activity: {activity_id}')
        return jsonify({"error": "Not authenticated"}), 401

    # Session check should happen before this function is called, but double check anyway
    session_athlete_id = session['athlete_id']

    # Check token expiry before making request
    if "expires_at" in session and time.time() > session["expires_at"]:
        logger.info(f'Session expired before Strava fetch - Athlete ID: {session_athlete_id} - IP: {get_remote_address()}')
        session.clear()
        return jsonify({
            "error": "Session expired. Please log in again.",
            "require_login": True
        }), 401

    # Activity ID validation already done by caller (get_activity)

    try:
        response = requests.get(
            f"https://www.strava.com/api/v3/activities/{activity_id}",
            headers={"Authorization": f"Bearer {session['access_token']}"},
            timeout=15 # Added timeout
        )

        # Handle error cases before attempting JSON decode
        if not response.ok:
            error_message = f"Failed to load activity {activity_id}. Status: {response.status_code}"
            # Specific handling for 404 Not Found to cache it
            if response.status_code == 404:
                logger.warning(f"Activity {activity_id} not found on Strava for athlete {session_athlete_id}.")
                not_found_data = {"error": "not_found", "status": 404}
                # Save the 'not found' status to the DB
                save_or_update_activity(session_athlete_id, int(activity_id), not_found_data)
                return jsonify({"error": "Activity not found"}), 404
                
            # Handle other errors (don't cache these specific errors unless desired)
            try:
                # Try to get more specific error from Strava
                strava_error = response.json().get('message', 'Unknown Strava API error')
                error_message += f". Reason: {strava_error}"
            except ValueError: # Handle cases where response is not JSON
                error_message += f". Response: {response.text[:100]}" # Log part of the response
            
            logger.error(error_message)
            # Don't save API errors to DB unless specifically needed. Return error directly.
            status_code = response.status_code if response.status_code in [401, 403, 404] else 500
            return jsonify({"error": f"Failed to load activity from Strava (Status: {response.status_code})."}), status_code

        response_json = response.json()

        # Verify activity belongs to authenticated user *before saving*
        if response_json.get('athlete', {}).get('id') != session_athlete_id:
            logger.warning(f'Unauthorized Strava activity access - IP: {get_remote_address()} - ' \
                         f'Athlete: {session_athlete_id} - Activity: {activity_id}')
            return jsonify({"error": "Unauthorized access to this Strava activity"}), 403

        # Save successful response to DB
        success, result, status = save_or_update_activity(session_athlete_id, int(activity_id), response_json)
        if not success:
             logger.error(f"Failed to save activity {activity_id} to DB after fetching from Strava.")
             # Return the fetched data even if DB save failed, or return the DB error?
             # Returning the fetched data might be better UX for this request.
             return jsonify(response_json), 200 # Return fetched data, maybe log the DB error more prominently
        
        return result, status # Return from save_or_update_activity

    except requests.exceptions.Timeout:
        logger.error(f'Strava API request timed out for activity {activity_id}')
        return jsonify({"error": "Strava API request timed out. Please try again."}), 504
    except requests.exceptions.RequestException as e:
        logger.error(f'Strava API network error: {str(e)} - IP: {get_remote_address()} - Activity: {activity_id}')
        return jsonify({"error": "Unable to connect to Strava API. Please try again later."}), 503
    except Exception as e: # Catch broader exceptions during fetch/save
         logger.error(f'Unexpected error during Strava fetch/DB save for activity {activity_id}: {str(e)}')
         return jsonify({"error": "An unexpected error occurred."}), 500

@app.route("/status")
def status():
    """Check if user is authenticated, provide CSRF token and handle token refresh"""
    logger.info(f"Status endpoint called - Session: {session}")
    try:
        if "access_token" in session:
            csrf_token = generate_csrf_token()
            
            # Check if token needs refresh
            if "expires_at" in session:
                current_time = time.time()
                # Add 5 minute buffer to token expiry
                if session["expires_at"] - current_time < 300:  # 5 minutes
                    new_token = refresh_access_token(session.get("refresh_token"))
                    if new_token:
                        try:
                            # Validate token response
                            required_fields = ['access_token', 'refresh_token', 'expires_at']
                            if not all(field in new_token for field in required_fields):
                                raise ValueError('Invalid token response structure')
                            
                            session["access_token"] = new_token["access_token"]
                            session["refresh_token"] = new_token["refresh_token"]
                            session["expires_at"] = new_token["expires_at"]
                            
                            # Log successful token refresh
                            logger.info(f'Token refreshed successfully for athlete: {session.get("athlete_id")}')
                        except (KeyError, ValueError) as e:
                            logger.error(f'Invalid token response format: {str(e)}')
                            session.clear()
                            return jsonify({
                                "authenticated": False,
                                "error": "Authentication error. Please log in again.",
                                "require_login": True,
                                "csrf_token": csrf_token
                            })
                    else:
                        # Clear session if refresh fails
                        logger.warning(f'Token refresh failed for athlete: {session.get("athlete_id")}')
                        session.clear()
                        return jsonify({
                            "authenticated": False,
                            "error": "Session expired. Please log in again.",
                            "require_login": True,
                            "csrf_token": csrf_token
                        })
                elif session["expires_at"] < current_time:  # Token already expired
                    logger.warning(f'Token expired for athlete: {session.get("athlete_id")}')
                    session.clear()
                    return jsonify({
                        "authenticated": False,
                        "error": "Session expired. Please log in again.",
                        "require_login": True,
                        "csrf_token": csrf_token
                    })
            
            # Return successful status with profile picture
            return jsonify({
                "authenticated": True,
                "athlete_id": session.get("athlete_id"),
                "athlete_username": session.get("athlete_username"),
                "athlete_first_name": session.get("athlete_first_name"),
                "athlete_last_name": session.get("athlete_last_name"),
                "athlete_profile": session.get("athlete_profile"),  # Include profile picture URL
                "expires_at": session.get("expires_at"),
                "csrf_token": csrf_token
            })
            
        return jsonify({
            "authenticated": False,
            "csrf_token": generate_csrf_token()
        })
    except Exception as e:
        logger.error(f'Status check error: {str(e)}')
        session.clear()  # Clear session on unexpected errors
        return jsonify({
            "authenticated": False,
            "error": "Authentication error. Please try again.",
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

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors by serving our custom 404 page"""
    # Serve 404.html from static/html
    return send_from_directory('static/html', '404.html'), 404

def refresh_access_token(refresh_token):
    """Refresh the access token with robust error handling"""
    if not refresh_token:
        logger.warning('Refresh token missing during token refresh attempt')
        return None

    try:
        # Add timeout to prevent hanging
        response = requests.post(
            "https://www.strava.com/oauth/token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token
            },
            timeout=10
        )
        
        # Handle specific error cases
        if response.status_code == 400:
            logger.error('Invalid refresh token detected')
            return None
        elif response.status_code == 401:
            logger.error('Refresh token expired or revoked')
            return None
        elif response.status_code == 429:
            logger.error('Rate limit exceeded during token refresh')
            return None
        elif not response.ok:
            logger.error(f'Token refresh failed with status code: {response.status_code}')
            return None

        try:
            token_data = response.json()
            
            # Validate token response structure
            required_fields = ['access_token', 'refresh_token', 'expires_at']
            if not all(field in token_data for field in required_fields):
                logger.error('Invalid token response structure')
                return None
                
            # Validate token values
            if not all(isinstance(token_data[field], str) for field in ['access_token', 'refresh_token']):
                logger.error('Invalid token format received')
                return None
                
            if not isinstance(token_data['expires_at'], (int, float)):
                logger.error('Invalid expiry timestamp received')
                return None
                
            return token_data
            
        except (ValueError, TypeError, KeyError) as e:
            logger.error(f'Invalid token response format: {str(e)}')
            return None
            
    except requests.exceptions.Timeout:
        logger.error('Token refresh request timed out')
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f'Token refresh network error: {str(e)}')
        return None
    except Exception as e:
        logger.error(f'Unexpected error during token refresh: {str(e)}')
        return None

# Add login_required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'athlete_id' not in session:
            # Redirect to login page if not authenticated
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/input_activity')
@login_required
def input_activity():
    """Serve the page for inputting Strava activity ID/URL"""
    # Serve input_activity.html from static/html
    return send_from_directory('static/html', 'input_activity.html')

@app.route('/generate_overlays')
@login_required
def generate_overlays():
    """Serve the generate overlays page for authenticated users"""
    if not session.get('access_token'):
        return redirect(url_for('login'))
    
    # Serve generate_overlays.html from static/html
    return send_from_directory('static/html', 'generate_overlays.html')

if __name__ == '__main__':
    logging.info("--- Preparing to run Flask app ---") # Add this log line
    logging.info("Starting Flask application...") # Example log at startup
    app.run(debug=DEBUG_MODE, port=5000)
