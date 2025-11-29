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
function setLocalRole(role) {
    localStorage.setItem('userRole', role);
}

/**
 * Set role in session on server
 * @param {string} role - 'parent', 'kid', or '' to clear
 * @returns {Promise<boolean>} True if successful, false otherwise
 */
async function setServerRole(role) {
    try {
        const response = await fetch('/api/set-role', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ role: role })
        });
        return response.ok;
    } catch (error) {
        console.error('Error setting role on server:', error);
        return false;
    }
}

/**
 * Validate parent PIN
 * @param {string} pin - PIN to validate
 * @returns {Promise<{valid: boolean, error?: string}>} Validation result
 */
async function validatePin(pin) {
    try {
        const response = await fetch('/api/validate-pin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pin: pin })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            return result;
        } else {
            return { valid: false, error: result.error || 'Invalid PIN' };
        }
    } catch (error) {
        console.error('Error validating PIN:', error);
        return { valid: false, error: 'Network error. Please try again.' };
    }
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
 * Fetch and return all users.
 * @returns {Promise<Array>} Array of user objects from /api/users
 */
async function getUsers() {
    try {
        const response = await fetch('/api/users');
        if (!response.ok) {
            throw new Error(`Failed to load users: ${response.status}`);
        }
        const users = await response.json();
        return users;
    } catch (error) {
        console.error('Error fetching users:', error);
        return [];
    }
}

/**
 * Fetch and return all chores.
 * @returns {Promise<Array>} Array of chore objects from /api/chores
 */
async function getChores() {
    try {
        const response = await fetch('/api/chores');
        if (!response.ok) {
            throw new Error(`Failed to load chores: ${response.status}`);
        }
        const chores = await response.json();
        return chores;
    } catch (error) {
        console.error('Error fetching chores:', error);
        return [];
    }
}

async function setServerRole(role) {
    // Set role in session on server
    try {
        const response = await fetch('/api/set-role', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ role: role })
        });

        if (response.ok) {
            setLocalRole(role);
            // Reload permissions in case settings changed
            permissions = await getPermissions();
                const roleOverlay = document.getElementById('roleSelectionOverlay');
                roleOverlay.classList.remove('show');
                roleOverlay.classList.add('hidden');
            applyRoleRestrictions();
            // Load users after role is set to apply restrictions
            loadUsers();
        } else {
            console.error('Failed to set role on server');
        }
    } catch (error) {
        console.error('Error setting role:', error);
    }
}

/**
 * Logout the current user (clears role and reloads page)
 */
async function logout() {
    // Clear role from session on server
    await setServerRole('');
    // Reload the page to show role selection again
    window.location.reload();
}

/**
 * Safely escape text for HTML insertion
 * @param {string} text - Raw text to escape
 * @returns {string} Escaped HTML string
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Sync system time with server and return time components.
 * Does not touch the DOM; caller can update UI.
 * @returns {Promise<{hours:number, minutes:number, seconds:number, nowMs:number}|null>}
 */
async function syncServerTime() {
    try {
        const response = await fetch('/api/system-time');
        const data = await response.json();

        const timestamp = data.timestamp; // ISO string
        const match = timestamp.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/);
        if (match) {
            const hours = parseInt(match[4]);
            const minutes = parseInt(match[5]);
            const seconds = parseInt(match[6]);
            return { hours, minutes, seconds, nowMs: Date.now() };
        }
        return null;
    } catch (error) {
        console.error('Error syncing server time:', error);
        return null;
    }
}

/**
 * Load app footer details (version + GitHub link) and apply role-based visibility.
 * Updates elements with ids `appVersion` and `appGithub`.
 */
async function loadAppFooter() {
    try {
        const response = await fetch('/api/version');
        const data = await response.json();

        const versionEl = document.getElementById('appVersion');
        const githubEl = document.getElementById('appGithub');

        if (versionEl) {
            versionEl.textContent = `v${data.version}`;
        }

        if (githubEl) {
            githubEl.href = data.github_url;
            // Show GitHub icon only for parents (use local role)
            if (getRole() === 'parent') {
                githubEl.classList.add('visible');
            } else {
                githubEl.classList.remove('visible');
            }
        }
    } catch (error) {
        console.error('Error loading app footer:', error);
    }
}

async function uploadAvatar(user_id, selectedAvatarFile) {

        const formData = new FormData();
        formData.append('avatar', selectedAvatarFile);

        try {
            const response = await fetch(`/api/users/${user_id}/avatar`, {
                method: 'POST',
                body: formData
            });

            return response;
        } catch (error) {
            console.error('Error:', error);
        }
    }

/**
 * Show a page-level message in a target element.
 * Defaults to element with id `message` and auto-hides after 5s.
 * @param {string} text - Message text
 * @param {boolean} [isError=false] - Whether to show error styling
 * @param {string} [elementId='message'] - Target element id
 */
function showMessage(text, isError = false, elementId = 'message') {
    const messageDiv = document.getElementById(elementId);
    if (!messageDiv) return;
    messageDiv.textContent = text;
    messageDiv.className = 'message ' + (isError ? 'error' : 'success');
    messageDiv.style.display = 'block';
    window.scrollTo({ top: 0, behavior: 'smooth' });
    setTimeout(() => { messageDiv.style.display = 'none'; }, 5000);
}

/**
 * Show a transient toast notification at top-center.
 * @param {string} text - Message text
 * @param {boolean} [isError=false] - Error styling when true, success otherwise
 */
function showToast(text, isError = false) {
    const existingToast = document.querySelector('.toast');
    if (existingToast) {
        try { existingToast.remove(); } catch (e) {}
    }
    const toast = document.createElement('div');
    toast.className = `toast ${isError ? 'error' : 'success'}`;
    toast.textContent = text;
    document.body.appendChild(toast);
    setTimeout(() => { toast.classList.add('show'); }, 10);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => { try { toast.remove(); } catch (e) {} }, 300);
    }, 3000);
}

/**
 * Create a new user
 * @param {Object} userData - User data object
 * @param {string} userData.name - User's name
 * @param {number} userData.balance - Initial point balance
 * @param {number} userData.cash_balance - Initial cash balance
 * @returns {Promise<Response>} Fetch response object
 */
async function createUser(userData) {
    try {
        const response = await fetch('/api/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData)
        });
        return response;
    } catch (error) {
        console.error('Error creating user:', error);
        throw error;
    }
}

/**
 * Create a new chore
 * @param {Object} choreData - Chore data object
 * @param {string} choreData.description - Chore description
 * @param {number} choreData.points - Point value
 * @param {string} choreData.repeat - Repeat frequency (daily/weekly/monthly/as_needed)
 * @returns {Promise<Response>} Fetch response object
 */
async function createChore(choreData) {
    try {
        const response = await fetch('/api/chores', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(choreData)
        });
        return response;
    } catch (error) {
        console.error('Error creating chore:', error);
        throw error;
    }
}

/**
 * Import chores from JSON data
 * @param {Array} choresData - Array of chore objects to import
 * @returns {Promise<Response>} Fetch response object
 */
async function importChores(choresData) {
    try {
        const response = await fetch('/api/chores/import', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ chores: choresData })
        });
        return response;
    } catch (error) {
        console.error('Error importing chores:', error);
        throw error;
    }
}

/**
 * Preview avatar image with file validation
 * @param {Event} event - File input change event
 * @param {Object} config - Configuration object
 * @param {string} config.previewElementId - ID of preview image element
 * @param {string} config.fileInputId - ID of file input element
 * @param {Function} config.onSuccess - Callback(file) when file is valid
 * @param {Function} config.onError - Callback(message) when file is invalid
 * @param {Function} [config.onUploadBtnChange] - Optional callback(disabled) to update upload button
 */
function previewAvatar(event, config) {
    const file = event.target.files[0];
    const {
        previewElementId,
        fileInputId,
        onSuccess,
        onError,
        onUploadBtnChange
    } = config;

    if (file) {
        // Check file size (5MB limit)
        if (file.size > 5 * 1024 * 1024) {
            onError('File too large. Maximum size is 5MB');
            event.target.value = '';
            const preview = document.getElementById(previewElementId);
            if (preview) {
                preview.classList.remove('show');
                preview.src = '';
            }
            if (onUploadBtnChange) onUploadBtnChange(true);
            return;
        }

        // Check file type
        const allowedTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp'];
        if (!allowedTypes.includes(file.type)) {
            onError('Invalid file type. Please use PNG, JPG, JPEG, GIF, or WEBP');
            event.target.value = '';
            const preview = document.getElementById(previewElementId);
            if (preview) {
                preview.classList.remove('show');
                preview.src = '';
            }
            if (onUploadBtnChange) onUploadBtnChange(true);
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            const preview = document.getElementById(previewElementId);
            if (preview) {
                preview.src = e.target.result;
                preview.classList.add('show');
            }
            if (onUploadBtnChange) onUploadBtnChange(false);
            onSuccess(file);
        };
        reader.readAsDataURL(file);
    }
}