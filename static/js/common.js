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
        const data = await response.json();
        
        // Store CSRF token if provided
        if (data.csrf_token) {
            csrfToken = data.csrf_token;
        }

        // If authenticated, store athlete ID globally
        if (data.authenticated && data.athlete_id) {
            athleteId = data.athlete_id;
        }

        console.log("checkAuth response:", data); // Debug log
        return data;
    } catch (error) {
        console.error('checkAuth: Unexpected error:', error);
        return { 
            authenticated: false, 
            require_login: true 
        };
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initializeProfileDropdown(); 
});