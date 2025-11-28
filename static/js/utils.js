/**
 * Family Chores - Utility Functions
 * Shared JavaScript utilities for URL management and user pre-selection
 */

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
