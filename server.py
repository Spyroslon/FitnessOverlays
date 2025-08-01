from flask import Flask, render_template, request, redirect, session, url_for, jsonify, send_from_directory, Response, make_response
from flask_cors import CORS
from dotenv import load_dotenv
import os
import requests
import logging
from logging.handlers import TimedRotatingFileHandler
from requests_oauthlib import OAuth2Session
import secrets
import time
from datetime import datetime, timezone, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import safe_join
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import mimetypes
import json

# --- Environment Variable Validation ---
def check_env_vars():
    required_vars = [
        "CLIENT_ID",
        "CLIENT_SECRET",
        "AUTH_BASE_URL",
        "TOKEN_URL",
        "VERIFY_TOKEN",
        "SQLALCHEMY_DATABASE_URI",
        "RATELIMIT_STORAGE_URI",
        "SECRET_KEY",
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
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN")
SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI")
RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI")

# Environment-based configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "prod").lower()
if ENVIRONMENT == "dev":
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Allow OAuth without HTTPS in development
    DEBUG_MODE = True
else:
    # In production, we don't set OAUTHLIB_INSECURE_TRANSPORT at all. This ensures HTTPS is required
    if 'OAUTHLIB_INSECURE_TRANSPORT' in os.environ:
        del os.environ['OAUTHLIB_INSECURE_TRANSPORT']
    DEBUG_MODE = False

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Use a consistent secret key from environment variables
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    raise ValueError("SECRET_KEY environment variable not set. Cannot run application securely.")

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=3)

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

# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Recommended setting

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
    athlete_id = db.Column(db.BigInteger, primary_key=True)
    access_token = db.Column(db.String(100), nullable=False)
    refresh_token = db.Column(db.String(100), nullable=False)
    expires_at = db.Column(db.BigInteger, nullable=False)

    athlete_username = db.Column(db.String(100))
    athlete_first_name = db.Column(db.String(100))
    athlete_last_name = db.Column(db.String(100))
    athlete_profile = db.Column(db.String(255))
    profile_medium = db.Column(db.String(255))

    first_authentication = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_authentication = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    sex = db.Column(db.String(10))
    city = db.Column(db.String(100))
    state = db.Column(db.String(100))
    country = db.Column(db.String(100))

    follower_count = db.Column(db.Integer)
    friend_count = db.Column(db.Integer)

    date_preference = db.Column(db.String(20))
    measurement_preference = db.Column(db.String(20))

    weight = db.Column(db.Float)
    premium = db.Column(db.Boolean)
    athlete_type = db.Column(db.Integer)

    def __repr__(self):
        return f'<Athletes {self.athlete_id}>'

    def update_from_dict(self, data: dict):
        field_map = {
            'athlete_username': 'username',
            'athlete_first_name': 'firstname',
            'athlete_last_name': 'lastname',
            'athlete_profile': 'profile',
            'profile_medium': 'profile_medium',
            'sex': 'sex',
            'city': 'city',
            'state': 'state',
            'country': 'country',
            'follower_count': 'follower_count',
            'friend_count': 'friend_count',
            'date_preference': 'date_preference',
            'measurement_preference': 'measurement_preference',
            'weight': 'weight',
            'premium': 'premium',
            'athlete_type': 'athlete_type',
        }
        for model_field, data_key in field_map.items():
            setattr(self, model_field, data.get(data_key))

    def update_from_token(self, token_data, athlete_data=None):
        """Update athlete data from token response and athlete info"""
        self.access_token = token_data['access_token']
        self.refresh_token = token_data['refresh_token']
        self.expires_at = token_data['expires_at']
        self.last_authentication = datetime.now(timezone.utc)
        if athlete_data:
            self.update_from_dict(athlete_data)

    def update_from_athlete_details(self, details: dict):
        self.update_from_dict(details)

# Define the Activities model
class Activities(db.Model):
    activity_id = db.Column(db.BigInteger, primary_key=True)
    athlete_id = db.Column(db.BigInteger, db.ForeignKey('athletes.athlete_id'), index=True, nullable=False)
    data = db.Column(db.JSON, nullable=False)
    last_synced = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    SYNC_COOLDOWN = timedelta(minutes=5)

    def __repr__(self):
        return f'<Activities {self.athlete_id}:{self.activity_id}>'

    @classmethod
    def get_last_sync(cls, athlete_id, activity_id):
        """Get the most recent sync time for an athlete across all pages"""
        last_sync = cls.query.filter_by(athlete_id=athlete_id, activity_id=activity_id).order_by(cls.last_synced.desc()).first()
        if last_sync and last_sync.last_synced:
            # Ensure the datetime is timezone-aware
            if last_sync.last_synced.tzinfo is None:
                return last_sync.last_synced.replace(tzinfo=timezone.utc)
            return last_sync.last_synced
        return None

    def is_sync_allowed(self):
        """Check if enough time has passed since last sync for this athlete"""
        last_sync = self.get_last_sync(self.athlete_id, self.activity_id)
        if not last_sync:
            return True
        current_time = datetime.now(timezone.utc)
        time_since_sync = current_time - last_sync
        return time_since_sync > self.SYNC_COOLDOWN

    def get_cooldown_remaining(self):
        """Get remaining cooldown time in seconds"""
        last_sync = self.get_last_sync(self.athlete_id, self.activity_id)
        if not last_sync:
            return 0
        current_time = datetime.now(timezone.utc)
        time_since_sync = current_time - last_sync
        if time_since_sync > self.SYNC_COOLDOWN:
            return 0
        return int((self.SYNC_COOLDOWN - time_since_sync).total_seconds())

# Define the ActivityLists model
class ActivityLists(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    athlete_id = db.Column(db.BigInteger, db.ForeignKey('athletes.athlete_id'), index=True, nullable=False)
    data = db.Column(db.JSON, nullable=False)
    last_synced = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    page = db.Column(db.Integer, nullable=False, default=1)
    per_page = db.Column(db.Integer, nullable=False, default=30)
    SYNC_COOLDOWN = timedelta(minutes=2)
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

def fetch_athlete_details(access_token: str) -> dict | None:
    """Fetch athlete details from Strava API."""
    try:
        response = requests.get(
            "https://www.strava.com/api/v3/athlete",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30
        )
        if response.ok:
            return response.json()
        logger.error(f"Failed to fetch athlete details: {response.status_code}")
    except Exception as e:
        logger.error(f"Error fetching athlete details: {e}")
    return None

# Create database tables
with app.app_context():
    db.create_all()

@app.after_request
def after_request(response: Response) -> Response:
    """Apply security headers, CSP, and cache-control strategy to all responses."""

    # --- Content Security Policy ---
    csp = {
        'default-src': ["'self'"],
        'script-src': [
            "'self'",
            "'unsafe-inline'",
            "cdn.tailwindcss.com",
            "www.googletagmanager.com",
            "www.google-analytics.com",
            "static.cloudflareinsights.com",
            "unpkg.com"
        ],
        'style-src': [
            "'self'",
            "'unsafe-inline'",
            "fonts.googleapis.com",
            "cdnjs.cloudflare.com"
        ],
        'font-src': [
            "'self'",
            "fonts.gstatic.com",
            "cdnjs.cloudflare.com"
        ],
        'img-src': [
            "'self'",
            "data:",
            "*.strava.com",
            "dgalywyr863hv.cloudfront.net",
            "www.googletagmanager.com",
            "www.google-analytics.com"
        ],
        'connect-src': [
            "'self'",
            "www.strava.com",
            "strava.com",
            "www.google-analytics.com",
            "region1.google-analytics.com"
        ],
        'frame-ancestors': ["'none'"],
        'form-action': ["'self'"],
        'base-uri': ["'self'"],
        'manifest-src': ["'self'"],
        'media-src': ["'self'"],
        'object-src': ["'none'"],
        'worker-src': ["'self'"]
    }

    if ENVIRONMENT == "prod":
        csp['script-src'] = [src for src in csp['script-src'] if src != "cdn.tailwindcss.com"]

    csp_string = '; '.join(f"{k} {' '.join(v)}" for k, v in csp.items())
    response.headers['Content-Security-Policy'] = csp_string

    # --- Security Headers ---
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Permissions-Policy'] = (
        'accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), '
        'encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), '
        'magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), '
        'publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()'
    )
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # --- Cache-Control Strategy ---
    path = request.path

    is_logged_in = False
    athlete_id = session.get("athlete_id")

    if athlete_id:
        athlete = db.session.get(Athletes, athlete_id)
        if athlete:
            is_logged_in = True
        else:
            session.clear()

    if path.startswith('/static/images/'):
        response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
    elif path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=300'
    elif is_logged_in:
        if path == '/customize':
            response.headers['Cache-Control'] = 'private, max-age=600'
        else:
            response.headers['Cache-Control'] = 'private, no-store'
            response.headers['Pragma'] = 'no-cache'
    else:
        if path == '/':
            response.headers['Cache-Control'] = 'public, max-age=300'
        else:
            response.headers['Cache-Control'] = 'public, max-age=60'

    # --- Header Cleanup ---
    response.headers.pop('X-Powered-By', None)
    response.headers.pop('Server', None)

    return response

ALLOWED_EXTENSIONS = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico'}
STATIC_DIR = 'static'

@app.route('/static/<path:path>')
def serve_static(path):
    """Securely serve static files with Cache-Control headers"""
    client_ip = get_remote_address()
    ext = os.path.splitext(path.lower())[1]

    if ext not in ALLOWED_EXTENSIONS:
        logger.warning(f'Blocked disallowed file type: {path} - IP: {client_ip}')
        return jsonify({"error": "File type not allowed"}), 403

    safe_path = safe_join(STATIC_DIR, path)
    if not safe_path:
        logger.warning(f'Directory traversal attempt: {path} - IP: {client_ip}')
        return jsonify({"error": "Invalid file path"}), 403

    abs_safe_path = os.path.abspath(safe_path)
    abs_static_root = os.path.abspath(STATIC_DIR)

    if not abs_safe_path.startswith(abs_static_root):
        logger.warning(f'Path traversal detected: {path} - IP: {client_ip}')
        return jsonify({"error": "Invalid file path"}), 403

    if not os.path.exists(abs_safe_path):
        return jsonify({"error": "File not found"}), 404

    try:
        mime_type = mimetypes.guess_type(path)[0] or 'application/octet-stream'
        response = make_response(send_from_directory(STATIC_DIR, path, mimetype=mime_type))
        response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        return response
    except Exception as e:
        logger.error(f'Failed to serve file: {path} - IP: {client_ip} - Error: {e}')
        return jsonify({"error": "Error accessing file"}), 500

def generate_csrf_token():
    """Generate a new CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(request):
    """Validate CSRF token."""
    token = request.headers.get('X-CSRF-Token')
    return token and token == session.get('csrf_token')

@app.before_request
def csrf_protect():
    """Protect state-changing requests with CSRF validation."""

    # Exempt webhook and known internal endpoints
    if request.path in ['/webhook', '/api/activities/sync']:
        return

    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        if not validate_csrf_token(request):
            logger.warning(f'CSRF validation failed - IP: {get_remote_address()}')
            return jsonify({"error": "Invalid CSRF token"}), 403

@app.before_request
def enforce_custom_domain():
    host = request.host.split(":")[0]
    path = request.path

    # Allow API calls and webhooks to bypass domain enforcement
    if path.startswith("/api") or path.startswith("/webhook"):
        return

    allowed_exact = {"fitnessoverlays.com", "localhost", "127.0.0.1"}
    allowed_suffixes = (".ngrok.io", ".ngrok-free.app")

    if host not in allowed_exact and not host.endswith(allowed_suffixes):
        logger.warning(f'Redirecting athlete - IP: {get_remote_address()}')
        return redirect(f"https://fitnessoverlays.com{request.full_path}", code=301)

@app.before_request
def rate_limit_unknown_paths():
    allowed_paths = [
        "/favicon.ico",
        "/robots.txt",
        "/llms.txt"
        "/sitemap.xml",
        "/static/",
    ]
    
    if request.endpoint is None and not any(request.path.startswith(p) for p in allowed_paths):
        logger.info(f"Triggered 404: for path {request.path}")
        limiter.check()

def refresh_access_token(refresh_token):
    """Refresh the access token with robust error handling"""
    if not refresh_token:
        logger.warning('Missing refresh token')
        return None

    athlete_id = session.get('athlete_id')
    if not athlete_id:
        logger.error('Missing athlete_id in session')
        return None

    athlete = db.session.get(Athletes, athlete_id)
    if not athlete:
        logger.error(f'Athlete {athlete_id} not found')
        return None

    if athlete.refresh_token != refresh_token:
        logger.error('Refresh token mismatch')
        return None

    try:
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

        if response.status_code in {400, 401, 429}:
            logger.error(f'Token refresh failed with status {response.status_code}')
            return None
        if not response.ok:
            logger.error(f'Unexpected error: {response.status_code}')
            return None

        try:
            token_data = response.json()
        except (ValueError, TypeError) as e:
            logger.error(f'Invalid JSON response: {str(e)}')
            return None

        # Validate required fields
        if not all(k in token_data for k in ('access_token', 'refresh_token', 'expires_at')):
            logger.error('Missing fields in token response')
            return None
        if not isinstance(token_data['access_token'], str) or not isinstance(token_data['refresh_token'], str):
            logger.error('Invalid token format')
            return None
        if not isinstance(token_data['expires_at'], (int, float)):
            logger.error('Invalid expires_at format')
            return None

        # Update DB
        try:
            athlete.update_from_token(token_data)
            # Fetch and update extended athlete details after token refresh
            athlete_details = fetch_athlete_details(token_data['access_token'])
            if athlete_details:
                athlete.update_from_athlete_details(athlete_details)
            db.session.commit()
            logger.info(f'Token refreshed for athlete {athlete_id}')
        except Exception as e:
            db.session.rollback()
            logger.error(f'DB update failed: {str(e)}')
            return None

        return token_data

    except requests.exceptions.Timeout:
        logger.error('Request timed out')
    except requests.exceptions.RequestException as e:
        logger.error(f'Network error: {str(e)}')
    except Exception as e:
        logger.error(f'Unexpected error: {str(e)}')

    return None

@app.route('/logout', methods=['POST'])
def logout():
    """Clear the session data"""
    logger.info(f"Athlete logged out - ID: {session['athlete_id']} - Name: {session['athlete_first_name']} {session['athlete_last_name']} - IP: {get_remote_address()}")
    session.clear()
    return redirect('/')

def ensure_valid_token():
    """Helper function to validate and refresh access token if needed.
    Returns True if token is valid or was successfully refreshed, False otherwise."""
    if 'access_token' not in session or 'expires_at' not in session:
        logger.warning("Missing token data in session")
        session.clear()
        return False

    current_time = time.time()
    token_expires_at = session['expires_at']
    time_until_expiry = token_expires_at - current_time

    if time_until_expiry <= 300:  # 5 minutes buffer
        logger.info(f"Token expiring in {int(time_until_expiry)}s, attempting refresh")
        new_token = refresh_access_token(session.get('refresh_token'))
        
        if not new_token:
            logger.warning("Token refresh failed")
            session.clear()
            return False
            
        session['access_token'] = new_token['access_token']
        session['refresh_token'] = new_token['refresh_token']
        session['expires_at'] = new_token['expires_at']
        logger.info(f"Token refreshed successfully - New expiry: {datetime.fromtimestamp(new_token['expires_at']).isoformat()}")
        return True

    logger.info(f"Token valid – expires in {int(time_until_expiry)}s (at {datetime.fromtimestamp(token_expires_at).isoformat()})")
    return True

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check login status and athlete existence
        if 'athlete_id' not in session:
            return redirect(url_for('login'))
            
        athlete = db.session.get(Athletes, session['athlete_id'])
        if not athlete:
            session.clear()
            return redirect(url_for('login'))

        # Validate and refresh token if needed
        if not ensure_valid_token():
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    logger.info(f"Landing page accessed - IP: {get_remote_address()} | X-Forwarded-For: {request.headers.get("X-Forwarded-For")}")

    try:
        csrf_token = generate_csrf_token()

        if "access_token" not in session:
            logger.info("Index: No access token in session")
            return render_template("index.html", 
                                    authenticated=False, 
                                    csrf_token=csrf_token)

        # Validate and refresh token if needed
        if not ensure_valid_token():
            return render_template("index.html", 
                                    authenticated=False, 
                                    csrf_token=csrf_token)

        # Authenticated, token is valid
        logger.info(f"Index: Authenticated user - Athlete ID: {session.get('athlete_id')} - Athlete Name: {session['athlete_first_name']} {session['athlete_last_name']}")
        return render_template("index.html",
                                authenticated=True,
                                athlete_id=session.get("athlete_id"),
                                athlete_first_name=session.get("athlete_first_name"),
                                athlete_last_name=session.get("athlete_last_name"),
                                athlete_profile=session.get("athlete_profile"),
                                csrf_token=csrf_token)

    except Exception as e:
        logger.error(f"Index: Unexpected error: {str(e)}")
        session.clear()
        return render_template("index.html", 
                                authenticated=False, 
                                csrf_token=generate_csrf_token())

# Configure rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=RATELIMIT_STORAGE_URI,
    default_limits=["200 per day", "50 per hour"],
    default_limits_exempt_when=lambda: request.path.startswith('/static/')
)

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded based on endpoint type"""
    logger.warning(f"Rate limit exceeded - IP: {get_remote_address()} - Path: {request.path}")
    
    # Return JSON for API and webhook endpoints
    if request.path.startswith('/api/') or request.path == '/webhook':
        return jsonify({
            "error": "Rate limit exceeded",
            "message": str(e.description)
        }), 429
    
    # Redirect to index for web pages
    return redirect(url_for('index'))

# Register the rate limit handler
limiter.error_handler = ratelimit_handler

@app.route('/login')
@limiter.limit("5 per minute")
def login():
    """Start OAuth login with Strava."""
    try:
        callback_url = url_for('callback', _external=True)
        logger.info(f"Generated callback URL: {callback_url}")

        oauth = OAuth2Session(
            CLIENT_ID,
            redirect_uri=callback_url,
            scope=["read,activity:read_all,profile:read_all"]
        )
        authorization_url, state = oauth.authorization_url(AUTH_BASE_URL)
        session['oauth_state'] = state

        return redirect(authorization_url)

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"error": "Authentication failed"}), 401

@app.route('/callback')
@limiter.limit("5 per minute")
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

        logger.info(f"Athlete Logged In - ID: {athlete_id} - Name: {athlete_data.get('firstname')} {athlete_data.get('lastname')} - IP: {get_remote_address()}")

        try:
            # Find existing athlete or create new one
            athlete = db.session.get(Athletes, athlete_id)
            if not athlete:
                athlete = Athletes(athlete_id=athlete_id)
                db.session.add(athlete)
                logger.info(f'Creating new athlete record for ID: {athlete_id}')
            else:
                logger.info(f'Updating existing athlete record for ID: {athlete_id}')
            
            # Update athlete data with new tokens and info (all fields)
            athlete.update_from_token(token, athlete_data)

            # Fetch and update extended athlete details
            athlete_details = fetch_athlete_details(token['access_token'])
            if athlete_details:
                athlete.update_from_athlete_details(athlete_details)

            db.session.commit()
            logger.info(f'Successfully updated athlete data in database for ID: {athlete_id}')
            
            # Set session as permanent before setting any session data
            session.permanent = True
            
            # Store athlete info in session
            session['athlete_id'] = athlete_id
            session['athlete_username'] = athlete_data.get('username')
            session['athlete_first_name'] = athlete_data.get('firstname')
            session['athlete_last_name'] = athlete_data.get('lastname')
            session['athlete_profile'] = athlete_data.get('profile_medium')
            session['access_token'] = token['access_token']
            session['refresh_token'] = token['refresh_token']
            session['expires_at'] = token['expires_at']
            session['date_preference'] = athlete_data.get('date_preference')
            session['measurement_preference'] = athlete_data.get('measurement_preference')
            
            # Generate new CSRF token for the session
            session['csrf_token'] = generate_csrf_token()
            
        except Exception as db_error:
            db.session.rollback()
            logger.error(f'Database error during callback: {str(db_error)}')
            return redirect('/')
        
        return redirect('/')
    except Exception as e:
        logger.error(f'OAuth callback error details: {str(e)} - IP: {get_remote_address()}')
        return redirect('/')

@limiter.limit("100 per hour", key_func=lambda: session.get("athlete_id", get_remote_address()))
@app.route('/customize')
@login_required
def customize():
    logger.info(f"Customize overlays endpoint called - Athlete ID: {session['athlete_id']} - Athlete Name: {session['athlete_first_name']} {session['athlete_last_name']}")
    """Serve the generate overlays page for authenticated users"""
    return render_template("customize.html",
                        authenticated=True,
                        athlete_id=session.get("athlete_id"),
                        athlete_first_name=session.get("athlete_first_name"),
                        athlete_last_name=session.get("athlete_last_name"),
                        athlete_profile=session.get("athlete_profile"),
                        csrf_token=session['csrf_token'])

@limiter.limit("100 per hour", key_func=lambda: session.get("athlete_id", get_remote_address()))
@app.route('/activities')
@login_required
def activities():
    """Serve the activities page for authenticated users"""
    return render_template("activities.html",
                        authenticated=True,
                        athlete_id=session.get("athlete_id"),
                        athlete_first_name=session.get("athlete_first_name"),
                        athlete_last_name=session.get("athlete_last_name"),
                        athlete_profile=session.get("athlete_profile"),
                        csrf_token=session['csrf_token'])

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

@limiter.limit("100 per hour", key_func=lambda: session.get("athlete_id", get_remote_address()))
@app.route('/api/activities/sync', methods=['GET'])
@login_required
def sync_activities():
    """Unified endpoint to fetch/sync activities from Strava with caching and cooldown"""
    logger.info(f"Syncing Activities called - Athlete ID: {session['athlete_id']} - Athlete Name: {session['athlete_first_name']} {session['athlete_last_name']}")
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

    # Return cached data if available and appropriate
    if not sync_instance.is_sync_allowed() and sync_log:
        return jsonify(create_sync_response(sync_log.data if sync_log else [], page, per_page, sync_log, seconds_remaining, using_cached=True))

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

@limiter.limit("100 per hour", key_func=lambda: session.get("athlete_id", get_remote_address()))
@app.route('/api/activities/<int:activity_id>', methods=['GET'])
@login_required
def get_activity(activity_id):
    """Fetch specific activity data from Strava with caching and cooldown"""
    athlete_id = session['athlete_id']
    logger.info(f"Fetching Activity {activity_id} - Athlete ID: {athlete_id}")

    # Check cache and cooldown
    activity = Activities.query.filter_by(
        athlete_id=athlete_id,
        activity_id=activity_id
    ).first()

    if activity:
        seconds_remaining = activity.get_cooldown_remaining()
        if seconds_remaining > 0:
            logger.info(f"Returning cached activity {activity_id} - {seconds_remaining}s cooldown remaining")
            return jsonify({
                "activity": activity.data,
                "cooldown": {
                    "active": True,
                    "seconds_remaining": seconds_remaining,
                    "total_cooldown": Activities.SYNC_COOLDOWN.total_seconds()
                },
                "cached": True
            })

    # Fetch fresh data
    try:
        logger.info(f"Fetching fresh data for activity {activity_id} from Strava")
        response = requests.get(
            f"https://www.strava.com/api/v3/activities/{activity_id}",
            headers={"Authorization": f"Bearer {session['access_token']}"},
            timeout=15
        )

        if not response.ok:
            logger.error(f"Strava API error for activity {activity_id}: {response.status_code}")
            if activity:
                seconds_remaining = activity.get_cooldown_remaining()
                return jsonify({
                    "activity": activity.data,
                    "cooldown": {
                        "active": True,
                        "seconds_remaining": seconds_remaining,
                        "total_cooldown": Activities.SYNC_COOLDOWN.total_seconds()
                    },
                    "cached": True,
                    "warning": "Failed to fetch fresh data, showing cached data"
                }), response.status_code
            return jsonify({"error": "Failed to fetch activity data"}), response.status_code

        activity_data = response.json()
        current_time = datetime.now(timezone.utc)

        # Update cache
        try:
            if activity:
                activity.data = activity_data
                activity.last_synced = current_time
            else:
                activity = Activities(
                    activity_id=activity_id,
                    athlete_id=athlete_id,
                    data=activity_data,
                    last_synced=current_time
                )
                db.session.add(activity)
            db.session.commit()
            logger.info(f"Successfully cached activity {activity_id}")
            return jsonify({
                "activity": activity_data,
                "cooldown": {
                    "active": False,
                    "seconds_remaining": 0,
                    "total_cooldown": Activities.SYNC_COOLDOWN.total_seconds()
                },
                "cached": False
            })
        except Exception as db_error:
            db.session.rollback()
            logger.error(f'Database error caching activity {activity_id}: {str(db_error)}')
            raise

    except Exception as e:
        logger.error(f'Error fetching activity {activity_id}: {str(e)}')
        if activity:
            seconds_remaining = activity.get_cooldown_remaining()
            return jsonify({
                "activity": activity.data,
                "cooldown": {
                    "active": True,
                    "seconds_remaining": seconds_remaining,
                    "total_cooldown": Activities.SYNC_COOLDOWN.total_seconds()
                },
                "cached": True,
                "warning": "Failed to fetch fresh data, showing cached data"
            }), 500
        return jsonify({"error": "Failed to fetch activity data"}), 500

def delete_user_data(athlete_id):
    """Delete all user data from the database when they deauthorize"""
    try:
        logger.info(f"Deleting data for athlete {athlete_id}")
        
        # Delete activities
        Activities.query.filter_by(athlete_id=athlete_id).delete()
        
        # Delete activity lists
        ActivityLists.query.filter_by(athlete_id=athlete_id).delete()
        
        # Delete athlete record
        Athletes.query.filter_by(athlete_id=athlete_id).delete()
        
        db.session.commit()
        logger.info(f"Successfully deleted all data for athlete {athlete_id}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user data for athlete {athlete_id}: {str(e)}")
        raise

@app.route("/webhook", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def webhook():
    """Handle Strava webhook verification and events"""
    if request.method == "GET":
        # Strava webhook verification
        if not VERIFY_TOKEN:
            logger.error("STRAVA_VERIFY_TOKEN not configured")
            return jsonify({"error": "Webhook not configured"}), 500
            
        if request.args.get("hub.verify_token") == VERIFY_TOKEN:
            challenge = request.args.get("hub.challenge")
            logger.info(f"Webhook verification successful with challenge: {challenge}")
            return jsonify({
                "hub.challenge": challenge
            })
        logger.warning(f"Invalid webhook verification token from IP: {get_remote_address()}")
        return jsonify({"error": "Invalid verification token"}), 403

    elif request.method == "POST":
        try:
            # Verify request signature if provided by Strava
            signature = request.headers.get('X-Strava-Signature')
            if not signature:
                if ENVIRONMENT == "dev":  # or use a custom flag like app.config["DEBUG"]
                    logger.warning("Skipping signature verification in development mode")
                else:
                    logger.warning(f"Missing Strava signature in webhook request from IP: {get_remote_address()}")
                    return jsonify({"error": "Unauthorized"}), 403

            event = request.json
            logger.info(f"Received webhook event: {event}")

            # Only handle deauthorization events
            if (event.get("object_type") == "athlete" and
                event.get("aspect_type") == "update" and
                event.get("updates", {}).get("authorized") == "false"):

                athlete_id = event.get("owner_id")
                if athlete_id:
                    # Delete user data - this will naturally invalidate their session
                    delete_user_data(athlete_id)
                    logger.info(f"Successfully processed deauthorization for athlete {athlete_id}")
                else:
                    logger.warning("Received deauthorization event without athlete_id")

            return jsonify({"status": "ok"}), 200
            
        except Exception as e:
            logger.error(f"Error processing webhook event: {str(e)}")
            return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(os.path.join("static", "images"), "FitnessOverlaysLogo.ico", mimetype="image/vnd.microsoft.icon")

@app.route('/robots.txt')
def robots_txt():
    return send_from_directory('static', 'robots.txt')

@app.route('/llms.txt')
def llms_txt():
    return send_from_directory('static', 'llms.txt')

@app.route('/faq')
def faq():
    """Serve the FAQ page"""
    return render_template("faq.html",
                        authenticated=bool(session.get("athlete_id")),
                        athlete_id=session.get("athlete_id"),
                        athlete_first_name=session.get("athlete_first_name"),
                        athlete_last_name=session.get("athlete_last_name"),
                        athlete_profile=session.get("athlete_profile"),
                        csrf_token=session.get('csrf_token', generate_csrf_token()))

@limiter.limit("30 per hour")
@app.route('/demo')
def demo():
    """Serve the demo page with sample activity data for unauthenticated users"""
    logger.info(f"Demo page accessed - IP: {get_remote_address()}")

    # Load the demo activity JSON
    with open('static/demo/activity_demo.json', 'r', encoding='utf-8') as f:
        activity = json.load(f)

    # Check if user is authenticated
    is_authenticated = False
    athlete_id = session.get("athlete_id")

    if athlete_id:
        athlete = db.session.get(Athletes, athlete_id)
        if athlete:
            is_authenticated = True
            logger.info(f"Authenticated user accessing demo - Athlete ID: {athlete_id} - Name: {session.get('athlete_first_name')} {session.get('athlete_last_name')} - IP: {get_remote_address()}")

    return render_template(
        'customize.html',
        activity=activity,
        demo_mode=True,
        authenticated=is_authenticated,
        athlete_id=session.get("athlete_id") if is_authenticated else None,
        athlete_first_name=session.get("athlete_first_name") if is_authenticated else None,
        athlete_last_name=session.get("athlete_last_name") if is_authenticated else None,
        athlete_profile=session.get("athlete_profile") if is_authenticated else None,
        csrf_token=session.get('csrf_token') if is_authenticated else generate_csrf_token()
    )

def get_lastmod(filepath):
    """Get last modification date of a file in ISO format with timezone awareness"""
    try:
        timestamp = os.path.getmtime(filepath)
        if filepath.endswith('.html'):
            base_timestamp = os.path.getmtime('templates/base.html')
            timestamp = max(timestamp, base_timestamp)
        dt = datetime.fromtimestamp(timestamp, timezone.utc)
        return dt.date().isoformat()
    except Exception:
        return None

@app.route('/sitemap.xml')
def sitemap_xml():
    """Generate sitemap with actual file modification dates"""
    sitemap = f'''<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url>
            <loc>https://fitnessoverlays.com/</loc>
            {f'<lastmod>{get_lastmod("templates/index.html")}</lastmod>' if get_lastmod("templates/index.html") else ''}
            <changefreq>weekly</changefreq>
            <priority>1.0</priority>
        </url>
        <url>
            <loc>https://fitnessoverlays.com/faq</loc>
            {f'<lastmod>{get_lastmod("templates/faq.html")}</lastmod>' if get_lastmod("templates/faq.html") else ''}
            <changefreq>monthly</changefreq>
            <priority>0.8</priority>
        </url>
        <url>
            <loc>https://fitnessoverlays.com/demo</loc>
            {f'<lastmod>{get_lastmod("templates/customize.html")}</lastmod>' if get_lastmod("templates/customize.html") else ''}
            <changefreq>monthly</changefreq>
            <priority>0.9</priority>
        </url>
    </urlset>'''
    return Response(sitemap, mimetype='application/xml')

if __name__ == '__main__':
    logging.info("Starting Flask application...")
    app.run(debug=DEBUG_MODE, port=5000)
