from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
import os
import json

# Load environment variables from .env file
load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
redirect_url = "https://developers.strava.com"

session = OAuth2Session(CLIENT_ID, redirect_uri=redirect_url)

auth_base_url = 'https://www.strava.com/oauth/authorize'
session.scope = ["activity:read_all"]
authorization_url, state = session.authorization_url(auth_base_url)

print(f'Click Here >>> {authorization_url}')

redirect_reponse = input("Paste the full redirect URL here: ")

token_url = 'https://www.strava.com/oauth/token'
session.fetch_token(
    token_url=token_url,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    authorization_response=redirect_reponse,
    include_client_id=True
)

response = session.get('https://www.strava.com/api/v3/activities/13928894108')

print(f'Response Status: {response.status_code}')
print(f'Response Reason: {response.reason}')
print(f'Time Elapsed: {response.elapsed}')
response_json = response.json()
print(f'Response Text: \n{'-'*15}\n{response_json}')

with open("api_response.json", "w") as outfile:
    json.dump(response_json, outfile, indent=4)
