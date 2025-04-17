    # 1. Start with an official Python base image
    #    Using a specific version is good practice. 'slim' is smaller.
    FROM python:3.13-slim 
    
    # 2. Set environment variables
    #    Prevents Python from writing pyc files and buffers output
    ENV PYTHONDONTWRITEBYTECODE=1
    ENV PYTHONUNBUFFERED=1
    
    # 3. Set the working directory inside the container
    WORKDIR /app
    
    # 4. Install system dependencies (if any are needed)
    #    Example: RUN apt-get update && apt-get install -y some-package && rm -rf /var/lib/apt/lists/*
    #    (Add packages here if your Python libraries need them, e.g., for database drivers)
    
    # 5. Copy only the requirements file first
    #    This takes advantage of Docker's layer caching. If requirements.txt doesn't change,
    #    Docker won't re-run the pip install step on subsequent builds.
    COPY requirements-frozen.txt .
    
    # 6. Install Python dependencies
    RUN pip install --no-cache-dir -r requirements-frozen.txt
    
    # 7. Copy the rest of your application code into the container
    #    Files listed in .dockerignore will be skipped automatically.
    COPY . .
    
    # 8. Expose the port the app runs on (Gunicorn default is 8000)
    EXPOSE 8000
    
    # 9. Define the command to run your application using Gunicorn
    #    -w 1: Use 1 worker processes (adjust based on your server CPU cores)
    #    -b 0.0.0.0:8000: Bind to all network interfaces on port 8000
    #    app.server:app: Run the 'app' object from the 'app/server.py' module
    CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:8000", "app.server:app"]
    
    # TEMPORARY change for debugging
    # CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "--log-level", "debug", "--error-logfile", "-", "--access-logfile", "-", "server:app"]
