from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
import os
import json
import time

# Load environment variables from .env file
load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URL = os.getenv("REDIRECT_URL")
AUTH_BASE_URL = 'https://www.strava.com/oauth/authorize'
TOKEN_URL = 'https://www.strava.com/oauth/token'
TOKENS_FILE = ".tokens.json"
ACTIVITIES_PATH = 'activities'

def save_tokens(tokens):
    """Save tokens to a file for persistence."""
    with open(TOKENS_FILE, "w") as file:
        json.dump(tokens, file, indent=4)


def load_tokens():
    """Load tokens from a file if they exist."""
    if os.path.exists(TOKENS_FILE):
        with open(TOKENS_FILE, "r") as file:
            return json.load(file)
    return None


def authenticate():
    """Authorize the user and obtain initial access tokens."""
    session = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URL, scope=["activity:read_all"])
    authorization_url, state = session.authorization_url(AUTH_BASE_URL)

    print(f"Click Here >>> {authorization_url}")

    redirect_response = input("Paste the full redirect URL here: ")
    tokens = session.fetch_token(
        token_url=TOKEN_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        authorization_response=redirect_response,
        include_client_id=True
    )

    tokens["expires_at"] = time.time() + tokens["expires_in"]  # Save actual expiry timestamp
    save_tokens(tokens)


def refresh_access_token():
    """Refresh the access token if expired."""
    tokens = load_tokens()
    if not tokens:
        print("No stored tokens found. Please authenticate first.")
        return None

    if time.time() < tokens["expires_at"]:
        return tokens["access_token"]  # Token is still valid

    print("Access token expired, refreshing...")

    session = OAuth2Session(CLIENT_ID)
    new_tokens = session.refresh_token(
        TOKEN_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        refresh_token=tokens["refresh_token"],
    )

    new_tokens["expires_at"] = time.time() + new_tokens["expires_in"]
    save_tokens(new_tokens)
    
    return new_tokens["access_token"]


def fetch_activity(activity_id):
    """Fetch Strava activity data using a valid access token."""
    access_token = refresh_access_token()
    if not access_token:
        print("Failed to get access token.")
        return

    session = OAuth2Session(CLIENT_ID, token={"access_token": access_token})
    response = session.get(f"https://www.strava.com/api/v3/activities/{activity_id}")

    print(f"Response Status: {response.status_code}")
    print(f"Response Reason: {response.reason}")
    print(f"Time Elapsed: {response.elapsed}")
    
    response_json = response.json()
    print(f"Response Text: \n{'-'*15}\n{json.dumps(response_json, indent=4)}")

    with open(f"{ACTIVITIES_PATH}/response_{activity_id}.json", "w") as outfile:
        json.dump(response_json, outfile, indent=4)


if __name__ == "__main__":
    if not os.path.exists(TOKENS_FILE):
        authenticate()
    
    activity_id = "13928894108"  # Change this to a valid activity ID
    fetch_activity(activity_id)

