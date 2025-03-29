# FitOverlays - Copyright (c) 2025 Spyros Lontos
# Licensed under AGPL-3.0

import re
import requests

def validate_activity_id(activity_id):
    """
    Validate Strava activity ID.
    Returns (is_valid: bool, error_message: str)
    """
    print('INSIDE THE validate_activity_id FUNCTION')
    if not activity_id:
        return False, "Activity ID is required"
    
    print(f'activity_id: {activity_id}')
    try:
        # Convert to integer
        activity_id = int(activity_id)
        
        # Check if positive and within reasonable bounds
        if activity_id <= 0:
            return False, "Activity ID must be positive"
        
        # Add strict regex validation for activity ID format
        if not re.match(r'^[1-9]\d{0,19}$', str(activity_id)):
            return False, "Invalid activity ID format"
            
        return True, None
        
    except (ValueError, TypeError):
        return False, "Activity ID must be a number"

def validate_strava_link(link):
    """
    Validate and extract activity ID from Strava links.
    Returns (is_valid: bool, activity_id: str|None, error_message: str|None)
    """
    if not isinstance(link, str):
        return False, None, "Invalid link format"

    # Clean input
    link = link.strip()
    
    # Direct activity link pattern
    direct_pattern = r'^(?:https?:\/\/)?(?:www\.)?strava\.com\/activities\/(\d+)(?:\/.*)?$'
    direct_match = re.match(direct_pattern, link)
    if direct_match:
        activity_id = direct_match.group(1)
        is_valid, error = validate_activity_id(activity_id)
        return is_valid, activity_id if is_valid else None, error

    # Strava app deep link pattern
    deep_link_pattern = r'^(?:https?:\/\/)?strava\.app\.link\/[A-Za-z0-9_-]+$'
    if re.match(deep_link_pattern, link):
        try:
            # Follow the redirect with timeout and limited redirects
            response = requests.head(
                link, 
                allow_redirects=True,
                timeout=5,
                headers={'User-Agent': 'FitOverlays/1.0'},
                verify=True
            )
            
            # Get the final URL after redirects
            final_url = response.url
            direct_match = re.match(direct_pattern, final_url)
            
            if direct_match:
                activity_id = direct_match.group(1)
                is_valid, error = validate_activity_id(activity_id)
                return is_valid, activity_id if is_valid else None, error
                
            return False, None, "Invalid Strava deep link destination"
            
        except requests.RequestException:
            return False, None, "Could not resolve Strava deep link"
            
    # If no patterns match
    return False, None, "Invalid Strava link format"

def validate_activity_input(input_str):
    """
    Validate activity input - could be an ID or a Strava link.
    Returns (is_valid: bool, activity_id: str|None, error_message: str|None)
    """
    if not input_str:
        return False, None, "Input is required"
        
    input_str = str(input_str).strip()
    
    # Handle direct activity ID
    if input_str.isdigit():
        is_valid, error = validate_activity_id(input_str)
        return is_valid, input_str if is_valid else None, error

    # Pass through URLs for server-side handling
    direct_pattern = r'^(?:https?:\/\/)?(?:www\.)?strava\.com\/activities\/\d+(?:\/.*)?$'
    deep_link_pattern = r'^(?:https?:\/\/)?strava\.app\.link\/[A-Za-z0-9_-]+$'
    
    if re.match(direct_pattern, input_str) or re.match(deep_link_pattern, input_str):
        return True, input_str, None
    
    return False, None, "Invalid Strava activity URL or ID format"

def validate_activity_data(data):
    """
    Validate stored activity data structure.
    Returns (is_valid: bool, error_message: str)
    """
    if not isinstance(data, dict):
        return False, "Invalid activity data format"
    
    # Check for error flag in stored data
    if 'error' in data:
        return False, data.get('error', 'Invalid activity data')
    
    # Check required fields
    required_fields = ['id', 'name', 'distance', 'moving_time', 'total_elevation_gain']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return False, f"Missing required activity data: {', '.join(missing_fields)}"
        
    return True, None

def validate_filename(filename, athlete_id=None):
    """
    Validate activity filename format and optionally check athlete_id.
    Returns (is_valid: bool, error_message: str)
    """
    if not filename:
        return False, "Filename is required"
    
    # Stricter filename format validation
    if not isinstance(filename, str):
        return False, "Invalid filename type"
        
    # Only allow exact filename pattern with strict regex
    if not re.match(r'^response_\d+_\d+\.json$', filename):
        return False, "Invalid filename format"
        
    # Check for any special characters or directory traversal attempts
    if any(char in filename for char in r'\/:<>"|?*'):
        return False, "Invalid filename characters"
    
    try:
        # Extract IDs from filename (format: response_athlete_activity.json)
        match = re.match(r'^response_(\d+)_(\d+)\.json$', filename)
        if not match:
            return False, "Invalid filename structure"
            
        file_athlete_id = int(match.group(1))
        activity_id = int(match.group(2))
        
        # Validate activity_id
        is_valid, error = validate_activity_id(activity_id)
        if not is_valid:
            return False, error
            
        # If athlete_id provided, verify it matches
        if athlete_id is not None:
            try:
                athlete_id = int(athlete_id)
                if file_athlete_id != athlete_id:
                    return False, "Unauthorized access"
            except (ValueError, TypeError):
                return False, "Invalid athlete ID"
            
        return True, None
        
    except (ValueError, TypeError):
        return False, "Invalid ID format in filename"
