# FitOverlays Development Notes

## Environment Setup

```bash
# Development setup
python -m venv .fitnessoverlays-venv
source .fitnessoverlays-venv/Scripts/activate  # Git Bash

# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your settings
```

### Dependency Maintenance

```bash
# Check for outdated packages
pip list --outdated

# Check for security vulnerabilities
safety check

# Update all dependencies
pip install -r requirements.txt --upgrade

# Generate requirements with versions
pip freeze > requirements.txt

npx tailwindcss -i ./static/css/input.css -o ./static/css/output.css --minify
```

Important: Always test thoroughly after updates!

## Maintenance Tasks

- Check error logs
- Monitor API usage
- Review API changes
- Check SSL certificates
- Review access attempts
- Purge old activity data

## API Integration

### Strava API

- Monitor rate limits
- Keep OAuth flow secure
