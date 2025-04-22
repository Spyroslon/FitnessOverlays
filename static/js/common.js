let csrfToken = '';
let athleteId = null; // Keep track of athlete ID globally if needed across functions

// Helper function to add CSRF token to fetch options
function addCSRFToken(options = {}) {
    return {
        ...options,
        headers: {
            ...options.headers,
            'X-CSRF-Token': csrfToken
        }
    };
}

// Function to initialize the profile dropdown menu
function initializeProfileDropdown() {
    const profileDropdownContainer = document.getElementById('profile-dropdown-container');
    const profilePictureTrigger = document.getElementById('profile-picture-trigger');
    const profileDropdownMenu = document.getElementById('profile-dropdown-menu');
    const logoutButton = document.getElementById('logout-button');

    if (!profilePictureTrigger || !profileDropdownMenu || !logoutButton || !profileDropdownContainer) {
        // console.warn("Profile dropdown elements not found. Skipping initialization.");
        return; // Don't proceed if elements aren't on the page
    }

    // Toggle dropdown on picture click
    profilePictureTrigger.addEventListener('click', (event) => {
        event.stopPropagation(); // Prevent click from immediately closing the dropdown
        profileDropdownMenu.classList.toggle('hidden');
        profileDropdownMenu.classList.toggle('opacity-0');
        profileDropdownMenu.classList.toggle('opacity-100');
        profileDropdownMenu.classList.toggle('translate-y-1');
        profileDropdownMenu.classList.toggle('translate-y-0');
    });

    // Close dropdown if clicked outside
    document.addEventListener('click', (event) => {
        // Check if the click target is outside the dropdown container
        if (!profileDropdownContainer.contains(event.target) && !profilePictureTrigger.contains(event.target)) {
            profileDropdownMenu.classList.add('hidden', 'opacity-0', 'translate-y-1');
            profileDropdownMenu.classList.remove('opacity-100', 'translate-y-0');
        }
    });

    // Logout button action
    logoutButton.addEventListener('click', async () => {
        console.log("Logout button clicked"); // Debug log
        if (!csrfToken) {
           console.error("CSRF token not available for logout");
           // Optionally show an error message to the user
           return;
       }
       try {
           const response = await fetch('/logout', addCSRFToken({ 
               method: 'POST',
               credentials: 'include' 
           }));
           
           if (response.ok) {
               // Redirect or update UI after successful logout
                console.log("Logout successful, redirecting..."); // Debug log
               window.location.href = '/'; 
           } else {
               console.error('Logout failed:', response.status, await response.text());
                // Optionally show an error message
           }
       } catch (error) {
           console.error('Error during logout:', error);
            // Optionally show an error message
       }
       profileDropdownMenu.classList.add('hidden', 'opacity-0', 'translate-y-1');
       profileDropdownMenu.classList.remove('opacity-100', 'translate-y-0'); // Hide dropdown after action
    });
}

// Function to check authentication status
async function checkAuth() {
    try {
        const response = await fetch("/status", { credentials: "include" });
        
        // --- Handle non-OK responses first --- 
        if (!response.ok) {
            // For expected auth errors (401/403), log minimally and handle redirect/return
            if (response.status === 401 || response.status === 403) {
                console.debug(`Auth check returned status ${response.status}. User likely not authenticated.`);
                const publicPages = ['/', '/404', '/auth_required'];
                if (!publicPages.includes(window.location.pathname)) {
                    window.location.href = "/auth_required";
                }
                return { authenticated: false, require_login: true };
            }

            // For other non-OK statuses, it might be a server error.
            console.warn(`Auth check received unexpected non-OK status: ${response.status}`);
            let errorData = { error: `HTTP error! status: ${response.status}` }; // Default error
            const contentType = response.headers.get("content-type");
            if (contentType && contentType.includes("application/json")) {
                try {
                    errorData = await response.json();
                } catch (e) {
                    console.error("Failed to parse JSON error response:", e);
                }
            } else {
                 console.warn(`Non-OK response (${response.status}) Content-Type is not JSON (${contentType}). Body not parsed.`);
            }
            
             // Check if the parsed error data indicates require_login
             if (errorData?.require_login) {
                 const publicPages = ['/', '/404', '/auth_required'];
                 if (!publicPages.includes(window.location.pathname)) {
                     window.location.href = "/auth_required";
                 }
                 return { authenticated: false, require_login: true };
             }

            // Throw an error based on parsed data or the status code
            throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
        }
        
        // --- Handle OK responses --- 
        const contentType = response.headers.get("content-type");
        if (!contentType || !contentType.includes("application/json")) {
             // This is an error because an OK response *should* be JSON
            //  console.error(`Auth check received OK status but Content-Type is not JSON: ${contentType}`); 
             return { authenticated: false, require_login: false, error: "Invalid response format from server." }; 
        }

        // Only parse if response is OK and Content-Type is JSON
        const data = await response.json();
        csrfToken = data.csrf_token; // Store CSRF token globally
        athleteId = data.athlete_id; // Store athlete ID globally

        // Start token expiry check timer if expiry time is provided
        if (data.expires_at) {
            const nowSeconds = Date.now() / 1000;
            const timeToExpiry = data.expires_at - nowSeconds;
            console.log(`Token expires in ${Math.round(timeToExpiry / 60)} minutes.`);

            if (timeToExpiry > 0) {
                // Check auth status 5 minutes before expiry, but not more frequently than every minute
                const checkInterval = Math.max(60 * 1000, (timeToExpiry - 300) * 1000); 
                // Use setTimeout for a single check before expiry
                setTimeout(checkAuth, checkInterval); 
                console.log(`Scheduled re-check in ${Math.round(checkInterval / 1000 / 60)} minutes.`);
            } else if (timeToExpiry <= 0 && data.authenticated) {
                 // If already expired but backend said authenticated (edge case?), trigger re-auth flow
                 console.warn("Token expired according to client clock, but server reported authenticated. Re-checking.");
                 // We might redirect here, or just let the next action fail & trigger auth
                 // For now, just return the potentially stale 'authenticated' status but log it.
            }
        }

        return { // Return relevant auth details
            authenticated: data.authenticated,
            athlete_profile: data.athlete_profile,
            athleteId: data.athlete_id, // Return athleteId too
            require_login: data.require_login // Pass this through
        };

    } catch (error) {
        console.error("Auth check failed:", error);
        // Return a clearly unauthenticated state on error
        return { authenticated: false, require_login: false, error: error.message }; 
    }
}

// Initialize common elements listeners after the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    initializeProfileDropdown(); 
    // Note: checkAuth() is NOT called here automatically. 
    // Each page should call it explicitly if needed within its own DOMContentLoaded handler.
});