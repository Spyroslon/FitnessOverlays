# FitnessOverlays - Quick Dev Notes

Core information for getting started and common tasks.

## Project Basics

- **Goal:** Authenticate with Strava, choose activity, customize overlay
- **Backend:** Python (Flask), Postgres, Strava API.
- **Frontend:** HTML, Vanilla JS, Tailwind CSS

## Quick Reference Commands

## 1. Setup & Running (Local)

```bash
# Create virtual environment (if not exists)
python -m venv .fitnessoverlays-venv

# Activate virtual environment (Git Bash)
source .fitnessoverlays-venv/Scripts/activate

# Install/Update dependencies
pip install -r requirements.txt

# Copy the example file
cp .env.example .env
# --> EDIT .env with your Strava Client ID/Secret <--

# Run the Flask development server
flask --app server run
# Access at http://127.0.0.1:5000 (or the address shown)
```

## 2. Dependencies

```bash
# Install from requirements.txt
pip install -r requirements.txt

# Save current environment to requirements.txt
pip freeze > requirements-frozen.txt
```

## 3. Docker (App)

```bash
# --- Application (if running via Docker) ---

# Build the app image (after code changes)
docker build -t fitnessoverlays-app .

# Run the app container (using .env file for secrets)
docker run -p 5000:8000 --name fitnessoverlays-web -d --env-file .env fitnessoverlays-app
# Access at http://localhost:5000

# Mounted mode for faster testing
docker run -p 5000:8000 \
  --name fitnessoverlays-web \
  -v "//c/Developments/FitnessOverlays:/app" \
  -d \
  --env-file .env \
  fitnessoverlays-app

# Check running app container
docker ps

# View app container logs
docker logs fitnessoverlays-web

# Follow app container logs
docker logs -f fitnessoverlays-web

# Stop app container
docker stop fitnessoverlays-web

# Remove stopped app container (e.g., before running a new build)
docker rm fitnessoverlays-web
```

## 4. Tailwind CSS (Local Build)

```bash
# --- Tailwind Setup & Build ---
https://tailwindcss.com/docs/installation/tailwind-cli

# Build and watch for changes during development
npx @tailwindcss/cli -i ./static/css/input.css -o ./static/css/tailwind.css --watch

# For production builds (minified)
npx @tailwindcss/cli -i ./static/css/input.css -o ./static/css/tailwind.css --minify
```

## 5. Strava Webhook Management

```bash
# List current webhook subscriptions
curl -X GET "https://www.strava.com/api/v3/push_subscriptions?client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET"

# Delete a webhook subscription
curl -X DELETE "https://www.strava.com/api/v3/push_subscriptions/284758?client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET"

# Create a new webhook subscription
curl -X POST https://www.strava.com/api/v3/push_subscriptions \
  -F client_id=YOUR_CLIENT_ID \
  -F client_secret=YOUR_CLIENT_SECRET \
  -F callback_url=https://fitnessoverlays.com/webhook \
  -F verify_token=your_verify_token
```
