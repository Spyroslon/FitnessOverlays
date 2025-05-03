let csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';

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

document.addEventListener("DOMContentLoaded", () => {
    const trigger = document.getElementById("profile-picture-trigger");
    const dropdown = document.getElementById("profile-dropdown-menu");

    if (trigger && dropdown) {
        trigger.addEventListener("click", () => {
            dropdown.classList.toggle("hidden");
        });

        document.addEventListener("click", (e) => {
            if (!trigger.contains(e.target) && !dropdown.contains(e.target)) {
                dropdown.classList.add("hidden");
            }
        });
    }

    const logoutBtn = document.getElementById("logout-button");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", async () => {
            await fetch("/logout", addCSRFToken({ method: "POST" }));
            window.location.href = "/";
        });
    }
});
