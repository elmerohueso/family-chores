/**
 * Family Chores - Utility Functions
 * Shared JavaScript utilities for URL management and user pre-selection
 */
/**
 * In-memory current user role.
 * We intentionally do NOT persist the role to localStorage for security
 * and freshness — the server session is authoritative.
 * Possible values: 'parent', 'kid', or null.
 */
// Initialize from server-injected role when available. The templates inject
// `window.__serverRole` before this script is loaded so we can synchronously
// pick it up here. Do not persist to localStorage — server session is
// authoritative.
let currentUserRole = (typeof window !== 'undefined' && window.__serverRole && (window.__serverRole === 'kid' || window.__serverRole === 'parent')) ? window.__serverRole : null;

/**
 * Get current user role (from memory).
 * Synchronous so templates and inline scripts can call `getRole()`.
 * @returns {string|null}
 */
function getRole() {
    return currentUserRole;
}

/**
 * Set current user role in memory only (do NOT persist to localStorage).
 * @param {string|null} role - 'parent', 'kid', or null to clear
 */
function setLocalRole(role) {
    if (role === 'kid' || role === 'parent') {
        currentUserRole = role;
    } else {
        currentUserRole = null;
    }
}

/**
 * Check server session role on page load and redirect if unauthorized.
 * Uses only the server response and updates the in-memory role.
 */
async function checkRoleOnLoad() {
    try {
        const resp = await fetch('/api/get-role');
        if (!resp.ok) {
            console.warn('Failed to fetch role:', resp.status);
            return;
        }

        const data = await resp.json();
        const role = data && data.role ? data.role : null;

        // Keep server-authoritative role in memory only
        if (role === 'kid' || role === 'parent') {
            setLocalRole(role);
            return;
        }

        // Server reports no role — clear in-memory role and redirect off protected pages
        setLocalRole(null);
        const pathname = window.location.pathname || '/';
        if (pathname !== '/dashboard' && pathname !== '/') {
            window.location.replace('/dashboard');
        }
    } catch (err) {
        console.error('Error checking role on load:', err);
    }
}

// Run role check after DOM is ready
if (document && document.addEventListener) {
    document.addEventListener('DOMContentLoaded', () => {
        checkRoleOnLoad();
    });
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
        const resp = await fetch('/api/kid-permissions');
        if (!resp.ok) {
            throw new Error(`Failed to load kid permissions: ${resp.status}`);
        }
        const settings = await resp.json();
        const perms = {
            record_chore: !!settings.kid_allowed_record_chore,
            redeem_points: !!settings.kid_allowed_redeem_points,
            withdraw_cash: !!settings.kid_allowed_withdraw_cash,
            view_history: !!settings.kid_allowed_view_history
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
 * Update settings on the server
 * @param {Object} settingsData - Settings data object
 * @returns {Promise<Response>} Fetch response object
 */
async function updateSettings(settingsData) {
    try {
        // If settingsData contains kid permission keys, send them to the
        // dedicated endpoint first (parent-only). Remove them from the
        // payload sent to /api/settings to avoid duplication.
        const permKeys = ['kid_allowed_record_chore', 'kid_allowed_redeem_points', 'kid_allowed_withdraw_cash', 'kid_allowed_view_history'];
        const permPayload = {};
        const settingsPayload = Object.assign({}, settingsData);

        for (const k of permKeys) {
            if (k in settingsPayload) {
                permPayload[k] = settingsPayload[k];
                delete settingsPayload[k];
            }
        }

        // If there are permission changes, call the kid-permissions endpoint
        if (Object.keys(permPayload).length > 0) {
            const permResp = await fetch('/api/kid-permissions', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(permPayload)
            });

            if (!permResp.ok) {
                // Return a Response-like error so callers can handle uniformly
                const errText = await permResp.text().catch(() => 'Failed to update kid permissions');
                return new Response(JSON.stringify({ error: errText }), { status: permResp.status || 500, headers: { 'Content-Type': 'application/json' } });
            }
        }

        // Send remaining settings to the main settings endpoint
        const response = await fetch('/api/settings', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(settingsPayload)
        });
        return response;
    } catch (error) {
        console.error('Error updating settings:', error);
        throw error;
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
 * Delete a user by ID
 * @param {number} userId - The user ID to delete
 * @returns {Promise<Response>} Fetch response object
 */
async function deleteUser(userId) {
    try {
        const response = await fetch(`/api/users/${userId}`, {
            method: 'DELETE'
        });
        return response;
    } catch (error) {
        console.error('Error deleting user:', error);
        throw error;
    }
}

/**
 * Delete a chore by ID
 * @param {number} choreId - The chore ID to delete
 * @returns {Promise<Response>} Fetch response object
 */
async function deleteChore(choreId) {
    try {
        const response = await fetch(`/api/chores/${choreId}`, {
            method: 'DELETE'
        });
        return response;
    } catch (error) {
        console.error('Error deleting chore:', error);
        throw error;
    }
}

/**
 * Reset all user point balances to 0
 * @returns {Promise<Response>} Fetch response object
 */
async function resetPoints() {
    try {
        const response = await fetch('/api/reset-points', {
            method: 'POST'
        });
        return response;
    } catch (error) {
        console.error('Error resetting points:', error);
        throw error;
    }
}

/**
 * Reset all user cash balances to $0.00
 * @returns {Promise<Response>} Fetch response object
 */
async function resetCash() {
    try {
        const response = await fetch('/api/reset-cash', {
            method: 'POST'
        });
        return response;
    } catch (error) {
        console.error('Error resetting cash:', error);
        throw error;
    }
}

/**
 * Reset all transaction history
 * @returns {Promise<Response>} Fetch response object
 */
async function resetTransactions() {
    try {
        const response = await fetch('/api/reset-transactions', {
            method: 'POST'
        });
        return response;
    } catch (error) {
        console.error('Error resetting transactions:', error);
        throw error;
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

/**
 * Fetch and return all transactions.
 * @returns {Promise<Array>} Array of transaction objects from /api/transactions
 */
async function getTransactions() {
    try {
        const response = await fetch('/api/transactions');
        if (!response.ok) {
            throw new Error(`Failed to load transactions: ${response.status}`);
        }
        const transactions = await response.json();
        return transactions;
    } catch (error) {
        console.error('Error fetching transactions:', error);
        return [];
    }
}

/**
 * Record a chore completion (permission-protected endpoint).
 * @param {Object} data - { user_id, chore_id, value }
 * @returns {Promise<Response>} Fetch response
 */
async function recordChore(data) {
    try {
        const payload = {
            user_id: data.user_id,
            chore_id: data.chore_id ?? null,
            points: data.value ?? data.points ?? 0
        };

        const response = await fetch('/api/record-chore', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return response;
    } catch (error) {
        console.error('Error recording chore:', error);
        throw error;
    }
}

/**
 * Redeem points (permission-protected endpoint).
 * @param {Object} data - { user_id, points, redemption_type? }
 * @returns {Promise<Response>} Fetch response
 */
async function redeemPoints(data) {
    try {
        const payload = {
            user_id: data.user_id,
            points: data.points ?? Math.abs(data.value ?? 0)
        };
        if (data.redemption_type) payload.redemption_type = data.redemption_type;

        const response = await fetch('/api/redeem-points', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return response;
    } catch (error) {
        console.error('Error redeeming points:', error);
        throw error;
    }
}

/**
 * Withdraw cash from user's cash balance
 * @param {number} userId - User ID
 * @param {number} amount - Amount to withdraw
 * @returns {Promise<Response>} Fetch response object
 */
async function withdrawCash(userId, amount) {
    try {
        const response = await fetch('/api/withdraw-cash', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                user_id: userId,
                amount: amount
            })
        });
        return response;
    } catch (error) {
        console.error('Error withdrawing cash:', error);
        throw error;
    }
}

/**
 * Trigger manual daily cash-out operation
 * @returns {Promise<Response>} Fetch response object
 */
async function triggerDailyCashOut() {
    try {
        const response = await fetch('/api/daily-cash-out', {
            method: 'POST'
        });
        return response;
    } catch (error) {
        console.error('Error triggering daily cash out:', error);
        throw error;
    }
}

/**
 * Send test email to configured parent addresses
 * @param {Array<string>|null} emailAddresses - Email addresses to send test to, or null for all configured
 * @returns {Promise<Response>} Fetch response object
 */
async function sendTestEmail(emailAddresses = null) {
    try {
        const response = await fetch('/api/send-test-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                parent_email_addresses: emailAddresses
            })
        });
        return response;
    } catch (error) {
        console.error('Error sending test email:', error);
        throw error;
    }
}

/**
 * Send daily digest email
 * @returns {Promise<Response>} Fetch response object
 */
async function sendDailyDigest() {
    try {
        const response = await fetch('/api/send-daily-digest', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        return response;
    } catch (error) {
        console.error('Error sending daily digest:', error);
        throw error;
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

        return response
    } catch (error) {
        console.error('Error setting role:', error);
    }
}

/**
 * roleLogout: clear the current session role and reload the page
 * Clears role on server (best-effort), clears the client in-memory role,
 * then reloads the page so the role selection overlay is shown.
 */
async function roleLogout() {
    try {
        // Clear role on server (ignore response outcome for now)
        await setServerRole('');
    } catch (e) {
        console.error('Server role clear failed (continuing logout):', e);
    }
    // Clear local stored role so page load shows selection overlay
    setLocalRole('');
    // Navigate to the requested dashboard path so the role selection UI is shown
    // Use replace to avoid adding an extra history entry
    window.location.replace('/dashboard');
}

/**
 * Tenant logout: clears tenant session on server and redirects to the index/login page.
 * Calls `/api/auth/logout` (server will clear refresh cookie) and then clears any
 * client-side stored tenant tokens before redirecting to `/`.
 */
async function tenantLogout() {
    // Immediately clear any locally stored tokens and in-memory role so UI updates
    try {
        localStorage.removeItem('access_token');
        localStorage.removeItem('tenant_name');
        localStorage.removeItem('userRole');
        // Also clear legacy/login token used by the tenant UI
        localStorage.removeItem('fc_token');
    } catch (e) {}

    try {
        // Clear in-memory role used by client UI
        if (typeof setLocalRole === 'function') setLocalRole('');
    } catch (e) {}

    // Tell the server to revoke the refresh token and clear tenant cookie
    try {
        await fetch('/api/auth/logout', { method: 'POST' });
    } catch (err) {
        console.error('Error calling tenant logout endpoint:', err);
    }

    // Also clear the server-side session role to keep UI and server in sync
    try {
        await setServerRole('');
    } catch (err) {
        console.error('Error clearing server role via /api/set-role:', err);
    }

    // Redirect to the root (tenant/login) page
    window.location.href = '/';
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
 * Update an existing chore
 * @param {number} choreId - The chore ID to update
 * @param {Object} choreData - Chore data object
 * @param {string} choreData.chore - Chore name/description
 * @param {number} choreData.point_value - Point value
 * @param {string} choreData.repeat - Repeat frequency (daily/weekly/monthly/as_needed)
 * @param {boolean} choreData.requires_approval - Whether chore requires approval
 * @returns {Promise<Response>} Fetch response object
 */
async function updateChore(choreId, choreData) {
    try {
        const response = await fetch(`/api/chores/${choreId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(choreData)
        });
        return response;
    } catch (error) {
        console.error('Error updating chore:', error);
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

/**
 * Format repeat frequency with proper casing
 * @param {string} repeat - Repeat frequency value
 * @returns {string} Formatted repeat string
 */
function formatRepeat(repeat) {
    if (!repeat) return 'None';
    const repeatLower = repeat.toLowerCase();
    if (repeatLower === 'as_needed') return 'As Needed';
    return repeat.charAt(0).toUpperCase() + repeat.slice(1);
}

/**
 * Get badge CSS class for repeat frequency
 * @param {string} repeat - Repeat frequency value
 * @returns {string} Badge class name
 */
function getRepeatBadgeClass(repeat) {
    if (!repeat) return 'badge-none';
    const repeatLower = repeat.toLowerCase();
    if (repeatLower === 'daily') return 'badge-daily';
    if (repeatLower === 'weekly') return 'badge-weekly';
    if (repeatLower === 'monthly') return 'badge-monthly';
    if (repeatLower === 'as_needed') return 'badge-as-needed';
    return 'badge-none';
}

/**
 * Format timestamp to readable date/time string
 * @param {string} timestamp - ISO timestamp string
 * @returns {string} Formatted date/time
 */
function formatTimestamp(timestamp) {
    if (!timestamp) return 'Never';
    // Parse timestamp string directly without timezone conversion
    // The timestamp is already in the server's local timezone (set via TZ)
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    
    let year, month, day, hour, minute;
    
    if (typeof timestamp === 'string') {
        // Parse ISO format string directly (e.g., "2024-01-15T12:30:00" or "2024-01-15T12:30:00-07:00")
        const match = timestamp.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/);
        if (match) {
            year = parseInt(match[1]);
            month = parseInt(match[2]) - 1; // 0-indexed
            day = parseInt(match[3]);
            hour = parseInt(match[4]);
            minute = parseInt(match[5]);
        } else {
            // Fallback: try to parse as Date (may apply timezone conversion)
            const date = new Date(timestamp);
            year = date.getFullYear();
            month = date.getMonth();
            day = date.getDate();
            hour = date.getHours();
            minute = date.getMinutes();
        }
    } else {
        return 'Never';
    }
    
    // Format the date/time components
    const hour12 = hour % 12 || 12;
    const ampm = hour < 12 ? 'AM' : 'PM';
    const minuteStr = minute.toString().padStart(2, '0');
    
    return `${months[month]} ${day}, ${year} ${hour12}:${minuteStr} ${ampm}`;
}

/**
 * Update scrollbar width for synchronized horizontal scrolling
 * @param {string} tableId - ID of the table element
 * @param {string} scrollTopInnerId - ID of the top scroll inner element
 */
function updateScrollbarWidth(tableId, scrollTopInnerId) {
    const table = document.getElementById(tableId);
    const topScroll = document.getElementById(scrollTopInnerId);
    if (table && topScroll) {
        topScroll.style.width = table.scrollWidth + 'px';
    }
}

/**
 * Synchronize scroll position between top and bottom scrollbars
 * @param {string} source - Source scrollbar ('top' or 'bottom')
 * @param {string} topScrollId - ID of top scroll element
 * @param {string} bottomScrollId - ID of bottom scroll element
 */
function syncScroll(source, topScrollId, bottomScrollId) {
    const top = document.getElementById(topScrollId);
    const bottom = document.getElementById(bottomScrollId);
    if (source === 'top') {
        bottom.scrollLeft = top.scrollLeft;
    } else {
        top.scrollLeft = bottom.scrollLeft;
    }
}

/**
 * Change the authenticated tenant password.
 * @param {string} currentPassword - Current password
 * @param {string} newPassword - New password
 * @returns {Promise<Response>} Fetch response object
 */
async function resetTenantPassword(currentPassword, newPassword) {
    try {
        const response = await fetch('/api/tenant/password', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
        });
        return response;
    } catch (error) {
        console.error('Error resetting tenant password:', error);
        throw error;
    }
}


/**
 * Fetch server timezone information from `/api/tz-info`.
 * Returns an object { tz_offset_min, tz_name, timestamp } or null on error.
 * @returns {Promise<{tz_offset_min:number,tz_name:string,timestamp:string}|null>}
 */
async function getServerTzInfo() {
    try {
        const resp = await fetch('/api/tz-info', { credentials: 'same-origin' });
        if (!resp.ok) {
            console.warn('getServerTzInfo failed:', resp.status);
            return null;
        }
        const data = await resp.json();
        return data;
    } catch (err) {
        console.error('Error fetching tz info:', err);
        return null;
    }
}