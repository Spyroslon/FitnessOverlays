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
        
        # Check length is less than 21 digits
        if len(str(activity_id)) >= 21:
            return False, "Invalid activity ID format"
            
        return True, None
        
    except (ValueError, TypeError):
        return False, "Activity ID must be a number"

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
        
    # Only allow specific filename pattern
    if not filename.startswith('response_') or not filename.endswith('.json'):
        return False, "Invalid filename format"
        
    # Check for any directory traversal attempts
    if '/' in filename or '\\' in filename or '..' in filename:
        return False, "Invalid filename characters"
    
    try:
        # Extract IDs from filename (format: response_athlete_activity.json)
        parts = filename.replace('response_', '').replace('.json', '').split('_')
        if len(parts) != 2:
            return False, "Invalid filename structure"
            
        file_athlete_id, activity_id = map(int, parts)
        
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
