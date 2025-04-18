# FitnessOverlays - Quick Dev Notes

Core information for getting started and common tasks.

## Project Basics

- **Goal:** Authenticate with Strava, input activity, generate overlays.
- **Backend:** Python (Flask), SQLite (`activities.db`), Strava API.
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

# Set up .env (if first time)
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
npm install -D tailwindcss

# Initialize Tailwind (creates tailwind.config.js)
npx tailwindcss init

# Configure './tailwind.config.js' - *IMPORTANT*
# You MUST tell Tailwind where your template files are. Example:
# module.exports = {
#   content: [
#     "./static/html/**/*.html",
#     "./static/js/**/*.js",
#     // Add other paths if needed
#   ],
#   theme: {
#     extend: {},
#   },
#   plugins: [],
# }

# Create your main input CSS file (e.g., ./static/css/input.css)
# Add the Tailwind directives:
# @tailwind base;
# @tailwind components;
# @tailwind utilities;

# Build the output CSS file (run this after changes to templates/config)
npx tailwindcss -i ./static/css/input.css -o ./static/css/tailwind.css

# Build and watch for changes during development
npx tailwindcss -i ./static/css/input.css -o ./static/css/tailwind.css --watch

# For production builds (minified)
npx tailwindcss -i ./static/css/input.css -o ./static/css/tailwind.css --minify
```
