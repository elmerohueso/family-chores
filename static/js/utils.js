/**
 * Family Chores - Utility Functions
 * Shared JavaScript utilities for URL management and user pre-selection
 */
/**
 * Get current user role from localStorage
 * @returns {string|null} 'parent', 'kid', or null if not set
 */
function getRole() {
    return localStorage.getItem('userRole');
}

/**
 * Set current user role in localStorage
 * @param {string} role - 'parent' or 'kid'
 */
function setRole(role) {
    localStorage.setItem('userRole', role);
}

/**
 * Get URL parameter value
 * @param {string} name - Parameter name
 * @returns {string|null} Parameter value or null if not found
 */
function getUrlParameter(name) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(name);
}

/**
 * Clean URL by replacing current state with base URL
 * This removes query parameters from the address bar while preserving page state
 */
function cleanUrl() {
    const baseUrl = '/';
    window.history.replaceState({}, '', baseUrl);
}

/**
 * Pre-select user in dropdown and trigger change event
 * Captures user_id from URL parameter before cleaning URL
 * @param {string} selectId - ID of the select element
 * @returns {string|null} The user_id that was pre-selected, or null
 */
function preSelectUserFromUrl(selectId) {
    const userIdParam = getUrlParameter('user_id');
    if (userIdParam) {
        const userSelect = document.getElementById(selectId);
        if (userSelect) {
            userSelect.value = userIdParam;
            // Trigger change event to update UI (balance display, etc.)
            const changeEvent = new Event('change');
            userSelect.dispatchEvent(changeEvent);
        }
        // Clean URL after pre-selecting
        cleanUrl();
        return userIdParam;
    }
    return null;
}

/**
 * Preserve user filter for history page
 * Captures user_id from URL and returns it without cleaning URL immediately
 * URL is cleaned after filter is applied
 * @returns {number|null} The user_id filter value, or null
 */
function getUserFilterFromUrl() {
    const userIdParam = getUrlParameter('user_id');
    if (userIdParam) {
        return parseInt(userIdParam);
    }
    return null;
}

/**
 * Fetch kid permissions from server settings
 * Populates a global or caller-managed object with kid permissions.
 * Returns the permissions object for convenience.
 */
async function getPermissions() {
    try {
        const settings = await getSettings();
        const perms = {
            record_chore: settings.kid_allowed_record_chore || false,
            redeem_points: settings.kid_allowed_redeem_points || false,
            withdraw_cash: settings.kid_allowed_withdraw_cash || false,
            view_history: settings.kid_allowed_view_history || false
        };
        return perms;
    } catch (error) {
        console.error('Error loading kid permissions:', error);
        return {
            record_chore: false,
            redeem_points: false,
            withdraw_cash: false,
            view_history: false
        };
    }
}

/**
 * Fetch and return all settings from the backend.
 * @returns {Promise<Object>} Settings object as returned by /api/settings
 */
async function getSettings() {
    try {
        const response = await fetch('/api/settings');
        if (!response.ok) {
            throw new Error(`Failed to load settings: ${response.status}`);
        }
        const settings = await response.json();
        return settings;
    } catch (error) {
        console.error('Error fetching settings:', error);
        return {};
    }
}

/**
 * Logout the current user (clears role and reloads page)
 */
async function logout() {
    // Clear the role from localStorage
    localStorage.removeItem('userRole');
    // Clear role from session on server
    try {
        await fetch('/api/set-role', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ role: '' })
        });
    } catch (error) {
        console.error('Error clearing role:', error);
    }
    // Reload the page to show role selection again
    window.location.reload();
}
