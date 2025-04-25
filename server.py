# FitnessOverlays - Copyright (c) 2025 Spyros Lontos
# Licensed under AGPL-3.0

from flask import Flask, jsonify, send_from_directory, session, redirect, url_for, request, Response
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
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone, timedelta

# Add this log line right at the top
logging.basicConfig(level=logging.INFO) # Basic config if logger not set up yet
logging.info("--- server.py script started execution ---")

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
    logging.info('All required environment variables are set.')

# Load environment variables from .env file
load_dotenv()

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
    raise ValueError("SECRET_KEY environment variable not set. Cannot run application securely.")

# Validation of environment variables
check_env_vars()

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

# Define the Athletes model
class Athletes(db.Model):
    athlete_id = db.Column(db.BigInteger, primary_key=True)  # Primary key
    access_token = db.Column(db.String(100), nullable=False)
    refresh_token = db.Column(db.String(100), nullable=False)
    expires_at = db.Column(db.BigInteger, nullable=False)  # Epoch timestamp
    athlete_username = db.Column(db.String(100))  # Optional
    athlete_first_name = db.Column(db.String(100))  # Optional
    athlete_last_name = db.Column(db.String(100))  # Optional
    athlete_profile = db.Column(db.String(255))  # Optional - URL to profile picture
    first_authentication = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_authentication = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<Athletes {self.athlete_id}>'

    def update_from_token(self, token_data, athlete_data=None):
        """Update athlete data from token response and athlete info"""
        self.access_token = token_data['access_token']
        self.refresh_token = token_data['refresh_token']
        self.expires_at = token_data['expires_at']
        self.last_authentication = datetime.now(timezone.utc)
        
        if athlete_data:
            self.athlete_username = athlete_data.get('username')
            self.athlete_first_name = athlete_data.get('firstname')
            self.athlete_last_name = athlete_data.get('lastname')
            self.athlete_profile = athlete_data.get('profile')

# Define the Activities model
class Activities(db.Model):
    activity_id = db.Column(db.BigInteger, primary_key=True)
    athlete_id = db.Column(db.BigInteger, db.ForeignKey('athletes.athlete_id'), index=True, nullable=False)
    data = db.Column(db.JSON, nullable=False)
    last_fetched = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    FETCH_COOLDOWN = timedelta(minutes=5)

    def __repr__(self):
        return f'<Activities {self.athlete_id}:{self.activity_id}>'

    def is_fetch_allowed(self):
        """Check if enough time has passed since last fetch"""
        if not self.last_fetched:
            return True
        return datetime.now(timezone.utc) - self.last_fetched > self.FETCH_COOLDOWN

# Define the ActivityLists model
class ActivityLists(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    athlete_id = db.Column(db.BigInteger, db.ForeignKey('athletes.athlete_id'), index=True, nullable=False)
    data = db.Column(db.JSON, nullable=False)
    last_synced = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    page = db.Column(db.Integer, nullable=False, default=1)
    per_page = db.Column(db.Integer, nullable=False, default=30)
    SYNC_COOLDOWN = timedelta(minutes=1)
    ITEMS_PER_PAGE = 30

    @classmethod
    def get_last_sync(cls, athlete_id):
        """Get the most recent sync time for an athlete across all pages"""
        last_sync = cls.query.filter_by(athlete_id=athlete_id).order_by(cls.last_synced.desc()).first()
        if last_sync and last_sync.last_synced:
            # Ensure the datetime is timezone-aware
            if last_sync.last_synced.tzinfo is None:
                return last_sync.last_synced.replace(tzinfo=timezone.utc)
            return last_sync.last_synced
        return None

    def is_sync_allowed(self):
        """Check if enough time has passed since last sync for this athlete"""
        last_sync = self.get_last_sync(self.athlete_id)
        if not last_sync:
            return True
        current_time = datetime.now(timezone.utc)
        time_since_sync = current_time - last_sync
        return time_since_sync > self.SYNC_COOLDOWN

    def get_cooldown_remaining(self):
        """Get remaining cooldown time in seconds"""
        last_sync = self.get_last_sync(self.athlete_id)
        if not last_sync:
            return 0
        current_time = datetime.now(timezone.utc)
        time_since_sync = current_time - last_sync
        if time_since_sync > self.SYNC_COOLDOWN:
            return 0
        return int((self.SYNC_COOLDOWN - time_since_sync).total_seconds())

# Create database tables
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

@app.after_request
def after_request(response):
    """Apply security and cache control headers to all responses"""
    # Apply security headers to all responses
    response = add_security_headers(response)
    
    # Simple and clear caching rules
    if request.path.startswith('/static/'):
        # Cache static assets for 1 hour
        response.headers['Cache-Control'] = 'public, max-age=3600'
    else:
        # No caching for all other routes (API endpoints, dynamic pages)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
    
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
    """Protect state-changing requests with CSRF validation"""
    # Skip CSRF check for certain API endpoints that handle their own authentication
    if request.path == '/api/activities/sync':
        return
        
    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        token = request.headers.get('X-CSRF-Token')
        if not token or token != session.get('csrf_token'):
            logger.warning(f'CSRF validation failed - IP: {get_remote_address()}')
            return jsonify({"error": "Invalid CSRF token"}), 403

@app.route('/login')
def login():
    """Handle the login process using Strava OAuth"""
    try:
        # Generate the dynamic callback URL
        callback_url = url_for('callback', _external=True)
        logger.info(f"Generated dynamic callback URL: {callback_url}")

        oauth = OAuth2Session(
            CLIENT_ID,
            redirect_uri=callback_url,
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
        # Check if user denied authorization
        if 'error' in request.args:
            logger.info(f"User denied Strava authorization - IP: {get_remote_address()}")
            return redirect('/')

        # Generate the dynamic callback URL consistently
        callback_url = url_for('callback', _external=True)
        logger.info(f"Using dynamic callback URL in callback handler: {callback_url}") 

        oauth = OAuth2Session(
            CLIENT_ID,
            state=session.get('oauth_state'),
            redirect_uri=callback_url
        )
        token = oauth.fetch_token(
            TOKEN_URL,
            client_secret=CLIENT_SECRET,
            authorization_response=request.url,
            include_client_id=True
        )
        
        # Get athlete info from token response
        athlete_data = token.get('athlete', {})
        athlete_id = athlete_data.get('id')
        
        if not athlete_id:
            logger.error('No athlete ID in token response')
            return redirect('/')
            
        try:
            # Find existing athlete or create new one
            athlete = db.session.get(Athletes, athlete_id)
            if not athlete:
                athlete = Athletes(athlete_id=athlete_id)
                db.session.add(athlete)
                logger.info(f'Creating new athlete record for ID: {athlete_id}')
            else:
                logger.info(f'Updating existing athlete record for ID: {athlete_id}')
            
            # Update athlete data with new tokens and info
            athlete.update_from_token(token, athlete_data)
            db.session.commit()
            logger.info(f'Successfully updated athlete data in database for ID: {athlete_id}')
            
            # Store athlete info in session
            session['athlete_id'] = athlete_id
            session['athlete_username'] = athlete_data.get('username')
            session['athlete_first_name'] = athlete_data.get('firstname')
            session['athlete_last_name'] = athlete_data.get('lastname')
            session['athlete_profile'] = athlete_data.get('profile_medium')
            session['access_token'] = token['access_token']
            session['refresh_token'] = token['refresh_token']
            session['expires_at'] = token['expires_at']
            
        except Exception as db_error:
            db.session.rollback()
            logger.error(f'Database error during callback: {str(db_error)}')
            return redirect('/')
        
        return redirect('/')
    except Exception as e:
        logger.error(f'OAuth callback error details: {str(e)} - IP: {get_remote_address()}')
        return redirect('/')

@app.route('/logout', methods=['POST'])
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
    """Handle authentication requirements for different types of requests."""
    # Allow requests to static files, login, callback, and root path
    if request.path.startswith('/static/') or request.path in ['/login', '/callback', '/']:
        return

    # For API endpoints, return JSON response when not authenticated
    if request.path.startswith('/api/') or request.path == '/status':
        if 'athlete_id' not in session:
            return jsonify({
                "authenticated": False,
                "require_login": True,
                "error": "Authentication required"
            })
    elif 'athlete_id' not in session:
        return send_from_directory('static/html', 'auth_required.html')

ALLOWED_EXTENSIONS = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico'}

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

@app.route("/status")
def status():
    """Check if user is authenticated and handle token refresh"""
    logger.info(f"Status endpoint called - IP: {get_remote_address()}")
    
    try:
        csrf_token = generate_csrf_token()
        current_time = time.time()
        
        # Not authenticated case
        if "access_token" not in session:
            logger.info("Status: No access token in session")
            return jsonify({
                "authenticated": False,
                "csrf_token": csrf_token
            })

        # Check token expiry
        if "expires_at" not in session:
            logger.warning("Status: Token exists but no expiry time found")
            session.clear()
            return jsonify({
                "authenticated": False,
                "error": "Invalid session state",
                "require_login": True,
                "csrf_token": csrf_token
            })

        token_expires_at = session["expires_at"]
        time_until_expiry = token_expires_at - current_time
        
        logger.info(f"Status: Token expires in {time_until_expiry:.2f} seconds")

        # Token expired
        if time_until_expiry <= 0:
            logger.info("Status: Token has expired, attempting refresh")
            new_token = refresh_access_token(session.get("refresh_token"))
            
            if not new_token:
                logger.warning("Status: Token refresh failed")
                session.clear()
                return jsonify({
                    "authenticated": False,
                    "error": "Session expired. Please log in again.",
                    "require_login": True,
                    "csrf_token": csrf_token
                })
                
            # Update session with new token info
            session["access_token"] = new_token["access_token"]
            session["refresh_token"] = new_token["refresh_token"]
            session["expires_at"] = new_token["expires_at"]
            logger.info("Status: Token successfully refreshed")
            
        # Token about to expire (within 5 minutes)
        elif time_until_expiry < 300:
            logger.info("Status: Token expiring soon, attempting proactive refresh")
            new_token = refresh_access_token(session.get("refresh_token"))
            
            if new_token:
                session["access_token"] = new_token["access_token"]
                session["refresh_token"] = new_token["refresh_token"]
                session["expires_at"] = new_token["expires_at"]
                logger.info("Status: Token proactively refreshed")
            else:
                logger.warning("Status: Proactive token refresh failed, but current token still valid")
                # Continue with current token since it's still valid

        # Return successful authentication response
        logger.info(f"Status: Returning successful auth for athlete {session.get('athlete_id')}")
        return jsonify({
            "authenticated": True,
            "athlete_id": session.get("athlete_id"),
            "athlete_username": session.get("athlete_username"),
            "athlete_first_name": session.get("athlete_first_name"),
            "athlete_last_name": session.get("athlete_last_name"),
            "athlete_profile": session.get("athlete_profile"),
            "expires_at": session.get("expires_at"),
            "csrf_token": csrf_token
        })

    except Exception as e:
        logger.error(f"Status: Unexpected error: {str(e)}")
        session.clear()
        return jsonify({
            "authenticated": False,
            "error": "Authentication error. Please try again.",
            "require_login": True,
            "csrf_token": csrf_token
        }), 500

@app.errorhandler(RateLimitExceeded)
def handle_ratelimit_error(e):
    logger.warning(f'Rate limit exceeded - IP: {get_remote_address()} - Endpoint: {request.path}')
    # Return JSON response only for API endpoints
    if request.path.startswith('/api/'):
        return jsonify({
            "error": "Rate limit exceeded. Please wait before trying again.",
            "status": 429
        }), 429
    # For non-API endpoints, return empty response so user stays on current page
    return "", 429

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
        
    # Get athlete from database using session athlete_id
    athlete_id = session.get('athlete_id')
    if not athlete_id:
        logger.error('No athlete_id in session during token refresh')
        return None

    athlete = db.session.get(Athletes, athlete_id)
    if not athlete:
        logger.error(f'Athlete {athlete_id} not found in database during token refresh')
        return None

    # Verify stored refresh token matches the one provided
    if athlete.refresh_token != refresh_token:
        logger.error('Refresh token mismatch between session and database')
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

            # Update athlete record in database
            try:
                athlete.update_from_token(token_data)
                db.session.commit()
                logger.info(f'Token refreshed and updated in database for athlete {athlete_id}')
            except Exception as e:
                db.session.rollback()
                logger.error(f'Failed to update refreshed token in database: {str(e)}')
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

@app.route('/customize_overlays')
@login_required
def customize_overlays():
    """Serve the generate overlays page for authenticated users"""
    if not session.get('access_token'):
        return redirect(url_for('login'))
    
    # Serve customize_overlays.html from static/html
    return send_from_directory('static/html', 'customize_overlays.html')

@app.route('/activities')
@login_required
def activities():
    """Serve the activities page for authenticated users"""
    if not session.get('access_token'):
        return redirect(url_for('login'))
    
    # Serve activities.html from static/html
    return send_from_directory('static/html', 'activities.html')

def create_sync_response(activities, page, per_page, sync_log, seconds_remaining, warning=None, using_cached=False):
    """Helper function to create a consistent sync response"""
    response = {
        "activities": activities,
        "pagination": {"page": page, "per_page": per_page},
        "cooldown": {
            "active": seconds_remaining > 0,
            "seconds_remaining": seconds_remaining,
            "total_cooldown": ActivityLists.SYNC_COOLDOWN.total_seconds()
        },
        "cached": using_cached
    }
    
    if sync_log and sync_log.last_synced:
        response["last_synced"] = sync_log.last_synced.isoformat()
    elif not sync_log:
        response["last_synced"] = datetime.now(timezone.utc).isoformat()
    
    if warning:
        response["warning"] = warning

    return response

@app.route('/api/activities/sync', methods=['GET', 'POST'])
@login_required
@limiter.limit("30 per minute")
def sync_activities():
    """Unified endpoint to fetch/sync activities from Strava with caching and cooldown"""
    logger.info(f"Activities endpoint called - Method: {request.method} - Session: {session}")
    athlete_id = session.get('athlete_id')
    if not athlete_id:
        return jsonify({"error": "Not authenticated"}), 401

    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(request.args.get('per_page', 30, type=int), ActivityLists.ITEMS_PER_PAGE)

    sync_instance = ActivityLists(athlete_id=athlete_id)
    sync_log = ActivityLists.query.filter_by(
        athlete_id=athlete_id,
        page=page,
        per_page=per_page
    ).first()

    seconds_remaining = sync_instance.get_cooldown_remaining()
    force_sync = request.method == 'POST'

    # Return cached data if available and appropriate
    if not force_sync or not sync_instance.is_sync_allowed():
        if sync_log:
            return jsonify(create_sync_response(sync_log.data, page, per_page, sync_log, seconds_remaining, using_cached=True))
        elif not force_sync:
            return jsonify(create_sync_response([], page, per_page, None, seconds_remaining))

    # Attempt to fetch fresh data from Strava
    try:
        response = requests.get(
            "https://www.strava.com/api/v3/athlete/activities",
            headers={"Authorization": f"Bearer {session['access_token']}"},
            params={"page": page, "per_page": per_page},
            timeout=15
        )

        if not response.ok:
            return jsonify(create_sync_response(
                sync_log.data if sync_log else [],
                page,
                per_page,
                sync_log,
                seconds_remaining,
                warning="Failed to fetch fresh data, showing cached data" if sync_log else None,
                using_cached=True
            )), response.status_code if not sync_log else 200

        activities = response.json()
        current_time = datetime.now(timezone.utc)

        # Update or create sync log
        try:
            if sync_log:
                sync_log.data = activities
                sync_log.last_synced = current_time
            else:
                sync_log = ActivityLists(
                    athlete_id=athlete_id,
                    data=activities,
                    page=page,
                    per_page=per_page,
                    last_synced=current_time
                )
                db.session.add(sync_log)
            db.session.commit()
            return jsonify(create_sync_response(activities, page, per_page, sync_log, seconds_remaining, using_cached=False))
        except Exception as db_error:
            db.session.rollback()
            logger.error(f'Database error: {str(db_error)}')
            raise

    except Exception as e:
        logger.error(f'Error syncing activities: {str(e)}')
        return jsonify(create_sync_response(
            sync_log.data if sync_log else [],
            page,
            per_page,
            sync_log,
            seconds_remaining,
            warning="Failed to sync data, showing cached data" if sync_log else None,
            using_cached=True
        )), 500 if not sync_log else 200

if __name__ == '__main__':
    logging.info("Starting Flask application...")
    app.run(debug=DEBUG_MODE, port=5000)
