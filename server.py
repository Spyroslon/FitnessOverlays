from flask import Flask, jsonify, send_from_directory
import os
from simple_authentication import fetch_activity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Setup rate limiter (stores limits in memory by default)
limiter = Limiter(
    get_remote_address,  # Uses IP address for limiting
    app=app,
    default_limits=["10 per minute"]  # Adjust as needed
)

ACTIVITIES_DIR = "activities"

if not os.path.exists(ACTIVITIES_DIR):
    os.makedirs(ACTIVITIES_DIR)

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/activities/<path:filename>')
def serve_activity(filename):
    return send_from_directory(ACTIVITIES_DIR, filename)

@app.route('/fetch_activity/<activity_id>')
@limiter.limit("5 per minute")  # Limit specific route
def get_activity(activity_id):
    json_path = os.path.join(ACTIVITIES_DIR, f'response_{activity_id}.json')
    
    if not os.path.exists(json_path):
        fetch_activity(activity_id)
    
    return send_from_directory(ACTIVITIES_DIR, f'response_{activity_id}.json')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
