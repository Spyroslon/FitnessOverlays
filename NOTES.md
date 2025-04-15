# FitnessOverlays - Quick Dev Notes

Core information for getting started and common tasks.

## Quick Reference Commands

**1. Setup & Running (Local)**

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

# Start local Redis (Required! See Docker section below)
docker start my-redis-dev

# Run the Flask development server
flask run
# Access at http://127.0.0.1:5000 (or the address shown)
```

**2. Docker (Redis & App)**

```bash
# --- Redis (for local dev rate limiting) ---

# Start Redis container (first time)
docker run --name my-redis-dev -d -p 6379:6379 redis

# Start existing stopped Redis container
docker start my-redis-dev

# Check if Redis container is running
docker ps

# Stop Redis container
docker stop my-redis-dev

# --- Application (if running via Docker) ---

# Build the app image (after code changes)
docker build -t fitnessoverlays-app .

# Run the app container (using .env file for secrets)
docker run -p 5000:8000 --name fitnessoverlays-web -d --env-file .env fitnessoverlays-app
# Access at http://localhost:5000

docker run -p 5000:8000 \
  --name fitnessoverlays-web-dev \
  -v "//c/Developments/FitOverlays:/app" \
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

**3. Dependencies**

```bash
# Install from requirements.txt
pip install -r requirements.txt

# Save current environment to requirements.txt
pip freeze > requirements.txt
```

## Project Basics

- **Goal:** Authenticate with Strava, input activity, generate overlays.
- **Backend:** Python (Flask), SQLite (`activities.db`), Strava API.
- **Frontend:** HTML, Vanilla JS, Tailwind CSS (CDN).
- **Key Files:**
  - `server.py`: Main Flask application logic.
  - `static/html/`: HTML pages (`index.html`, `input_activity.html`, `generate_overlays.html`, `404.html`, `auth_required.html`).
  - `static/js/`: JavaScript files (logic is embedded in HTML for now).
  - `static/images/`: Logos, icons.
  - `activities.db`: Local cache of fetched activities.
  - `.env`: Environment variables (Strava keys, secrets - **DO NOT COMMIT**).
  - `requirements.txt`: Python dependencies.
  - `Dockerfile`: Instructions to build the Docker image.

## Backend Basics (`server.py`)

- **Authentication:**
  - `/login`: Starts Strava OAuth flow.
  - `/callback`: Handles redirect from Strava, saves tokens to session.
  - `/logout`: Clears user session.
- **Core Functionality:**
  - `/status`: Checks if user is logged in, returns profile info, handles token refresh.
  - `/fetch_activity/<...>`: (POST) Gets activity data (checks local DB cache first, then Strava API).
- **Main Pages Served:**
  - `/`: `index.html`
  - `/input_activity`: `input_activity.html` (needs login)
  - `/generate_overlays`: `generate_overlays.html` (needs login)
- **Database:** Uses `ActivityCache` model (in `server.py`) to store activity details in `activities.db` to reduce Strava API calls.

## Frontend Basics (HTML/JS)

- **Authentication:** `checkAuth()` function in JS (on each page load) calls `/status` to see if logged in and updates UI (shows profile pic, correct buttons).
- **Data Flow (Simplified):**
    1. Login via `/login` -> `/callback`.
    2. Go to `/input_activity`, enter link/ID.
    3. JS sends link/ID to `/fetch_activity` endpoint.
    4. If successful, server sends back activity data (JSON).
    5. JS stores this data in `sessionStorage['currentActivity']`.
    6. JS redirects to `/generate_overlays`.
    7. `generate_overlays.html` JS reads data from `sessionStorage`.
    8. User customizes overlay via buttons/options.
    9. JS uses HTML Canvas (`<canvas id="overlayCanvas">`) to draw the overlay based on selected data and options.
    10. "Copy" buttons use `navigator.clipboard` API to copy text or canvas image data.
- **Styling:** Primarily Tailwind CSS via CDN link in HTML `<head>`. Some minor custom CSS in `<style>` tags.

## Docker Troubleshooting Tips

1. **Container Not Running?**
    - Check status: `docker ps` (running) or `docker ps -a` (all, including stopped/error).
2. **App Error (e.g., 500 Internal Server Error)?**
    - Check logs: `docker logs fitnessoverlays-web`.
    - Follow logs: `docker logs -f fitnessoverlays-web`.
3. **Redis Connection Issues?**
    - Ensure Redis container is running: `docker ps` (should show `my-redis-dev`).
    - Start it if stopped: `docker start my-redis-dev`.
    - Check `.env` variable `RATELIMIT_STORAGE_URI`. For local Docker, it should be `redis://localhost:6379/0` when running Flask locally, or potentially `redis://host.docker.internal:6379/0` if the Flask *app itself* is running inside Docker and needs to reach Redis on the host (less common setup here).
4. **Code Changes Not Appearing (When using Docker)?**
    - You **must** rebuild the image: `docker build -t fitnessoverlays-app .`
    - Then stop/remove the old container and run the new image:

        ```bash
        docker stop fitnessoverlays-web
        docker rm fitnessoverlays-web
        docker run -p 5000:8000 --name fitnessoverlays-web -d --env-file .env fitnessoverlays-app
        ```

5. **Port Conflicts?**
    - Ensure nothing else is running on port `5000` (for Flask local dev or Docker host port) or `6379` (for Redis) on your machine.
    - Access the app via the *host* port (e.g., `http://localhost:5000`), not the internal container port (8000).
