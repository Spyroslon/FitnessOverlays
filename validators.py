import re

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
