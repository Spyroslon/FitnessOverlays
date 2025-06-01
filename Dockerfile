    # 1. Start with an official Python base image
    #    Using a specific version is good practice. 'slim' is smaller.
    FROM python:3.13-slim 
    
    # 2. Set environment variables
    #    Prevents Python from writing pyc files and buffers output
    ENV PYTHONDONTWRITEBYTECODE=1
    ENV PYTHONUNBUFFERED=1
    
    # 3. Set the working directory inside the container
    WORKDIR /app
    
    # 4. Install Node.js, npm, and other system dependencies (if any)
    #    Install Node.js (needed for Tailwind build) and curl (to download NodeSource script)
    RUN apt-get update && \
        apt-get install -y --no-install-recommends curl gnupg && \
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
        apt-get install -y nodejs && \
        # Clean up apt lists to reduce image size
        rm -rf /var/lib/apt/lists/*
    
    # 5. Copy package.json and package-lock.json (if it exists)
    #    Do this before copying the rest of the code for better caching
    COPY package*.json ./
    
    # 6. Install Node.js dependencies (including Tailwind)
    RUN npm install
    
    # 7. Copy only the Python requirements file first
    COPY requirements-frozen.txt .
    
    # 8. Install Python dependencies
    RUN pip install --no-cache-dir -r requirements-frozen.txt
    
    # 9. Copy the rest of your application code into the container
    #    Files listed in .dockerignore will be skipped automatically.
    COPY . .
    
    # 10. Build Tailwind CSS for production
    RUN npx tailwindcss -i ./static/css/input.css -o ./static/css/tailwind_test.css
    
    # 11. Expose the port the app runs on (Gunicorn default is 8000)
    EXPOSE 8000
    
    # 12. Define the command to run your application using Gunicorn
    #     -w 1: Use 1 worker process (suitable for Render free tier)
    #     -b 0.0.0.0:8000: Bind to all network interfaces on the 8000 port
    #     --access-logfile - --error-logfile -: Log to stdout/stderr
    #     server:app: Run the 'app' object from the 'server.py' module
    CMD ["gunicorn", "-w", "1", "--bind", "0.0.0.0:8000", "--access-logfile", "-", "--error-logfile", "-", "server:app"]
