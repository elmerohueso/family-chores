from flask import Flask, jsonify, request, render_template, send_from_directory, session, redirect, url_for, has_request_context, g
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import csv
import io
from datetime import datetime, timezone, timedelta
import uuid
import threading
import time as time_module
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from cryptography.fernet import Fernet
import base64
import logging
from logging.handlers import RotatingFileHandler
import jwt
import secrets
import hashlib
from argon2 import PasswordHasher, exceptions as argon2_exceptions

# Argon2 hasher instance (raise if argon2-cffi missing so failures are visible)
ph = PasswordHasher()

# Configure logging with rotation
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
LOG_DIR = '/data/syslogs'
os.makedirs(LOG_DIR, exist_ok=True)

# Create log file with rotation: 20MB max size, keep last 10 files
log_filename = os.path.join(LOG_DIR, 'app.log')
log_format = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Set up root logger
root_logger = logging.getLogger()
root_logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# Add rotating file handler (20MB max, keep 10 backups)
file_handler = RotatingFileHandler(
    log_filename,
    maxBytes=20 * 1024 * 1024,  # 20MB
    backupCount=10
)
file_handler.setFormatter(log_format)
root_logger.addHandler(file_handler)

# Add console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_format)
root_logger.addHandler(console_handler)

logger = logging.getLogger(__name__)

logger.info("Application starting")

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Application version

__version__ = '2.3.1'

# Github repo URL
GITHUB_REPO_URL = 'https://github.com/elmerohueso/FamilyChores'

# Database connection configuration from environment variables
POSTGRES_HOST = os.environ.get('POSTGRES_HOST', 'localhost')
POSTGRES_DATABASE = os.environ.get('POSTGRES_DATABASE', 'family_chores')
POSTGRES_USER = os.environ.get('POSTGRES_USER', 'family_chores')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'family_chores')
POSTGRES_PORT = os.environ.get('POSTGRES_PORT', '5432')

# Construct database connection string
DATABASE_URL = f'postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DATABASE}'

# Avatar storage directory
AVATAR_DIR = '/data/avatars'
os.makedirs(AVATAR_DIR, exist_ok=True)

# Parent PIN from environment variable
PARENT_PIN = os.environ.get('PARENT_PIN', '1234')

# Email password encryption key (derived from app secret key)
def get_encryption_key():
    """Get or generate encryption key for email password."""
    secret_key = app.secret_key.encode('utf-8')
    # Derive a 32-byte key from the secret key using SHA256
    from hashlib import sha256
    key = sha256(secret_key).digest()
    # Convert to base64 for Fernet
    return base64.urlsafe_b64encode(key)

# Initialize Fernet with encryption key
try:
    encryption_key = get_encryption_key()
    fernet = Fernet(encryption_key)
except Exception as e:
    # Fallback to a default key if there's an error (not secure but better than crashing)
    encryption_key = Fernet.generate_key()
    fernet = Fernet(encryption_key)

def encrypt_password(password):
    """Encrypt a password for storage."""
    if not password:
        return ''
    try:
        return fernet.encrypt(password.encode('utf-8')).decode('utf-8')
    except Exception:
        return ''

def decrypt_password(encrypted_password):
    """Decrypt a password from storage."""
    if not encrypted_password:
        return ''
    try:
        return fernet.decrypt(encrypted_password.encode('utf-8')).decode('utf-8')
    except Exception:
        # If decryption fails, return empty string (might be unencrypted legacy data)
        logger.error("Failed to decrypt password, returning empty string.")
        return ''

# Allowed avatar file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_AVATAR_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    """Get a database connection with dictionary cursor."""
    conn = psycopg2.connect(DATABASE_URL)
    return conn


# --- JWT / Refresh token helpers ---
JWT_ALGORITHM = 'HS256'
# Access token lifetime in seconds (short-lived)
ACCESS_TOKEN_EXPIRES = int(os.environ.get('ACCESS_TOKEN_EXPIRES', 900))  # 15 minutes default
# Refresh token lifetime in seconds (long-lived)
REFRESH_TOKEN_EXPIRES = int(os.environ.get('REFRESH_TOKEN_EXPIRES', 60 * 60 * 24 * 30))  # 30 days

def create_access_token(tenant_id: str):
    now = datetime.utcnow()
    payload = {
        'sub': str(tenant_id),
        'iat': now,
        'exp': now + timedelta(seconds=ACCESS_TOKEN_EXPIRES)
    }
    token = jwt.encode(payload, app.secret_key, algorithm=JWT_ALGORITHM)
    return token

def create_refresh_token_record(conn, tenant_id, user_agent=None, ip_address=None):
    # Create a cryptographically random token, store its sha256 hash in DB
    token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    issued_at = datetime.utcnow()
    expires_at = issued_at + timedelta(seconds=REFRESH_TOKEN_EXPIRES)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO refresh_tokens (tenant_id, token_hash, issued_at, expires_at, user_agent, ip_address) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
        (tenant_id, token_hash, issued_at, expires_at, user_agent, ip_address)
    )
    conn.commit()
    cur.close()
    return token, expires_at

# Argon2 password hasher instance
try:
    ph = PasswordHasher()
except Exception:
    ph = None

def revoke_refresh_token(conn, token):
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    cur = conn.cursor()
    cur.execute('UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = %s', (token_hash,))
    conn.commit()
    cur.close()

def validate_refresh_token(conn, token):
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    cur = conn.cursor()
    cur.execute('SELECT id, tenant_id, issued_at, expires_at, revoked FROM refresh_tokens WHERE token_hash = %s', (token_hash,))
    row = cur.fetchone()
    cur.close()
    if not row:
        return None
    id_, tenant_id, issued_at, expires_at, revoked = row
    now = datetime.utcnow()
    if revoked or expires_at < now:
        return None
    return {'id': id_, 'tenant_id': tenant_id}

def log_system_event(log_type, message, details=None, status='success'):
    """Log a system event using the logging module.
    
    Args:
        log_type: Type of event (e.g., 'settings_saved', 'email_sent', 'cash_out_run', 'error')
        message: Brief message describing the event
        details: Optional detailed information (JSON string or dict)
        status: 'success' or 'error'
    """
    try:
        # Format details if provided
        details_str = ''
        if details:
            if isinstance(details, dict):
                import json
                details_str = f" | Details: {json.dumps(details)}"
            else:
                details_str = f" | Details: {details}"
        
        # Determine log level based on status and log_type
        if status == 'error' or 'error' in log_type.lower() or 'failed' in message.lower():
            log_level = logging.ERROR
        elif 'warning' in log_type.lower() or 'warning' in message.lower():
            log_level = logging.WARNING
        elif log_type in ['cash_out_check', 'login', 'logout']:
            # Routine checks and auth events are DEBUG level
            log_level = logging.DEBUG
        else:
            # Most other events are INFO level
            log_level = logging.INFO
        
        # Log the message
        full_message = f"[{log_type}] {message}{details_str}"
        logger.log(log_level, full_message)
    except Exception as e:
        # Fallback to error logging if formatting fails
        logger.error(f"System event formatting error: {log_type} - {message} (Error: {e})")

def get_local_timezone():
    """Get the local system timezone."""
    # Get local timezone by converting UTC to local
    return datetime.now(timezone.utc).astimezone().tzinfo

def get_system_timestamp():
    """Get current timestamp in system timezone as ISO format string."""
    # Get current time in UTC first, then convert to system's local timezone
    # This ensures we have a timezone-aware datetime
    now_utc = datetime.now(timezone.utc)
    # Convert to system's local timezone
    now_local = now_utc.astimezone()
    # Return as ISO format string with timezone offset
    return now_local.isoformat()

def make_timezone_aware(dt):
    """Convert a naive datetime to timezone-aware datetime in local system timezone.
    
    Args:
        dt: datetime object (naive or timezone-aware)
    
    Returns:
        timezone-aware datetime in local system timezone
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        # Naive datetime - assume it's in local system time
        local_tz = get_local_timezone()
        return dt.replace(tzinfo=local_tz)
    else:
        # Already timezone-aware, convert to local timezone
        return dt.astimezone()

def parent_required(f):
    """Decorator to require parent role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_role = session.get('user_role')
        if user_role != 'parent':
            # Redirect to index (login) if not parent
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def kid_or_parent_required(f):
    """Decorator to require kid or parent role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_role = session.get('user_role')
        if user_role not in ['kid', 'parent']:
            # Redirect to index (login) if no role set
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def kid_permission_required(permission_key):
    """Decorator factory to check kid permission settings.
    Usage: @kid_permission_required('kid_allowed_record_chore')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_role = session.get('user_role')
            
            # Parents always have access
            if user_role == 'parent':
                return f(*args, **kwargs)
            
            # Kids need permission check
            if user_role == 'kid':
                # Map legacy permission_key to roles table column
                perm_map = {
                    'kid_allowed_record_chore': 'can_record_chore',
                    'kid_allowed_redeem_points': 'can_redeem_points',
                    'kid_allowed_withdraw_cash': 'can_withdraw_cash',
                    'kid_allowed_view_history': 'can_view_history'
                }
                col = perm_map.get(permission_key)
                if not col:
                    # Unknown permission key - deny access by default
                    return redirect(url_for('index'))

                conn = get_db_connection()
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                try:
                    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
                    if not tenant_id:
                        # No tenant context -> deny
                        cursor.close()
                        conn.close()
                        return redirect(url_for('index'))
                    cursor.execute(f'SELECT {col} FROM tenant_roles WHERE tenant_id = %s AND role_name = %s', (tenant_id, 'kid'))
                    row = cursor.fetchone()
                finally:
                    cursor.close()
                    conn.close()

                if row and row.get(col):
                    return f(*args, **kwargs)
                else:
                    # Permission not allowed - redirect to index (login)
                    return redirect(url_for('index'))
            
            # No role set - redirect to index (login)
            return redirect(url_for('index'))
        return decorated_function
    return decorator



@app.route('/')
def index():
    """Home page."""
    # Show the public landing / login page at the root so tenants
    # who are not logged in (no token) are directed to `index.html`.
    return render_template('index.html')


@app.route('/create-tenant')
def create_tenant_page():
    """Page to create a new tenant with an invite token."""
    return render_template('create_tenant.html')


# Global auth enforcement: require authentication for all routes except a small whitelist
@app.before_request
def require_auth_for_everything():
    # Allow Flask internal endpoints and OPTIONS preflight
    if request.method == 'OPTIONS' or request.endpoint == 'static':
        return None

    path = request.path or ''
    # Whitelist: index page and the auth endpoints the login page uses
    whitelist = set([
        '/',
        '/create-tenant',
        '/api/auth/login',
        '/api/auth-check',
        '/api/tenant-login',
        '/api/auth/refresh',
        '/api/auth/logout',
        '/api/tenants',
        '/api/tenants/invites',  # Allow invite creation with management key (no auth required)
        # Allow a few read-only endpoints used by head/includes and utils
        '/api/version',
        '/api/system-time',
        '/api/tz-info',
        '/api/get-role',
    ])

    # Allow static assets and avatar serving without auth (so login page can load)
    if path.endswith('favicon.ico'):
        return None

    if path in whitelist:
        return None

    # Perform authentication: accept Bearer JWT or valid refresh token cookie
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        token = auth.split(None, 1)[1]
        try:
            payload = jwt.decode(token, app.secret_key, algorithms=[JWT_ALGORITHM])
            g.tenant_id = payload.get('sub')
            return None
        except Exception:
            pass

    refresh = request.cookies.get('refresh_token')
    if refresh:
        conn = None
        try:
            conn = get_db_connection()
            valid = validate_refresh_token(conn, refresh)
            if valid:
                g.tenant_id = valid['tenant_id']
                return None
        finally:
            if conn:
                conn.close()

    # Not authenticated: API -> 401 JSON, pages -> redirect to index
    if path.startswith('/api/'):
        return jsonify({'error': 'Not authenticated'}), 401
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard_page():
    """Dashboard route serving the main application UI."""
    return render_template('dashboard.html')

@app.route('/api/validate-pin', methods=['POST'])
def validate_pin():
    """Validate parent PIN."""
    data = request.get_json()
    pin = data.get('pin', '')
    # Prefer parent PIN stored in the settings table when available.
    db_pin = None
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        # Try tenant-scoped parent PIN first
        if tenant_id:
            try:
                cur.execute("SELECT setting_value FROM tenant_settings WHERE tenant_id = %s AND setting_key = %s", (tenant_id, 'parent_pin'))
                row = cur.fetchone()
                if row and row.get('setting_value') is not None:
                    raw_val = str(row.get('setting_value'))
                    try_decrypted = decrypt_password(raw_val)
                    if try_decrypted and try_decrypted.isdigit():
                        db_pin = try_decrypted
                    elif raw_val.isdigit():
                        db_pin = raw_val
            except Exception:
                # Continue to fallback to global setting or env var
                db_pin = None

        # Do not fall back to global settings; tenant-scoped only
        if db_pin is None:
            db_pin = None
    except Exception:
        # Don't fail validation if DB read fails; fall back to env var below
        db_pin = None
    finally:
        try:
            cur.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

    effective_pin = db_pin if db_pin else PARENT_PIN

    if pin == effective_pin:
        session['user_role'] = 'parent'
        
        # Log successful parent login
        try:
            log_system_event('login', 'Parent logged in successfully', {'role': 'parent'}, 'success')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'valid': True, 'message': 'PIN validated successfully'}), 200
    else:
        # Log failed parent login attempt
        try:
            log_system_event('login_failed', 'Failed parent login attempt', {'role': 'parent', 'reason': 'Invalid PIN'}, 'error')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'valid': False, 'error': 'Invalid PIN'}), 401

@app.route('/api/set-role', methods=['POST'])
def set_role():
    """Set user role (for kid login)."""
    data = request.get_json()
    role = data.get('role', '')
    
    if role == '':
        # Clear role (for logout)
        old_role = session.get('user_role')
        session.pop('user_role', None)
        
        # Log logout event
        try:
            log_system_event('logout', 'User logged out', {'role': old_role if old_role else 'unknown'}, 'success')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'success': True, 'message': 'Role cleared'}), 200
    elif role in ['kid', 'parent']:
        session['user_role'] = role
        
        # Log successful login
        try:
            log_system_event('login', f'{role.capitalize()} logged in successfully', {'role': role}, 'success')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'success': True, 'message': f'Role set to {role}'}), 200
    else:
        # Log failed login attempt (invalid role)
        try:
            log_system_event('login_failed', 'Failed login attempt', {'role': role, 'reason': 'Invalid role'}, 'error')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'error': 'Invalid role'}), 400

@app.route('/api/get-role', methods=['GET'])
def get_role():
    """Get current user role."""
    user_role = session.get('user_role')
    return jsonify({'role': user_role}), 200


@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    data = request.get_json(force=True)
    tenant_name = data.get('tenant_name')
    password = data.get('password')
    if not tenant_name or not password:
        return jsonify({'error': 'Missing tenant_name or password'}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch stored password hash for tenant and verify using Argon2 only.
    # Perform case-insensitive tenant lookup so usernames are not case-sensitive
    cur.execute("SELECT tenant_id, tenant_password FROM tenants WHERE LOWER(tenant_name) = LOWER(%s)", (tenant_name,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    tenant_id, stored = row[0], row[1]

    # Only accept Argon2-formatted hashes (argon2-cffi). Reject other formats.
    if not (isinstance(stored, str) and stored.startswith('$argon2')):
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    try:
        ph.verify(stored, password)
        # Rehash transparently if parameters changed
        try:
            if ph.check_needs_rehash(stored):
                new_hash = ph.hash(password)
                cur.execute('UPDATE tenants SET tenant_password = %s WHERE tenant_id = %s', (new_hash, tenant_id))
                conn.commit()
        except Exception:
            pass
    except argon2_exceptions.VerifyMismatchError:
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception:
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    # Successful authentication - issue tokens
    access_token = create_access_token(tenant_id)
    refresh_token, refresh_expires = create_refresh_token_record(conn, tenant_id, request.headers.get('User-Agent'), request.remote_addr)

    # Set refresh token as HttpOnly cookie (note: Secure cookie requires HTTPS in browsers)
    resp = jsonify({'access_token': access_token, 'expires_in': ACCESS_TOKEN_EXPIRES})
    resp.set_cookie('refresh_token', refresh_token, httponly=True, secure=False, samesite='Strict', expires=refresh_expires)

    try:
        log_system_event('login', 'Tenant login success', {'tenant_id': tenant_id}, 'success')
    except Exception:
        pass

    cur.close()
    conn.close()
    return resp, 200


@app.route('/api/auth/refresh', methods=['POST'])
def api_auth_refresh():
    # Read refresh token from cookie or JSON body
    token = request.cookies.get('refresh_token') or (request.get_json(silent=True) or {}).get('refresh_token')
    if not token:
        return jsonify({'error': 'Missing refresh token'}), 400

    conn = get_db_connection()
    valid = validate_refresh_token(conn, token)
    if not valid:
        conn.close()
        return jsonify({'error': 'Invalid or expired refresh token'}), 401

    tenant_id = valid['tenant_id']

    # Rotate refresh token: revoke current and issue a new one
    revoke_refresh_token(conn, token)
    new_token, new_expires = create_refresh_token_record(conn, tenant_id, request.headers.get('User-Agent'), request.remote_addr)

    access_token = create_access_token(tenant_id)
    resp = jsonify({'access_token': access_token, 'expires_in': ACCESS_TOKEN_EXPIRES})
    resp.set_cookie('refresh_token', new_token, httponly=True, secure=False, samesite='Strict', expires=new_expires)

    conn.close()
    return resp, 200


@app.route('/api/auth/logout', methods=['POST'])
def api_auth_logout():
    token = request.cookies.get('refresh_token') or (request.get_json(silent=True) or {}).get('refresh_token')
    if token:
        conn = get_db_connection()
        revoke_refresh_token(conn, token)
        conn.close()

    resp = jsonify({'success': True})
    # Clear cookie
    # Clear refresh token and tenant association cookies
    resp.set_cookie('refresh_token', '', expires=0)
    resp.set_cookie('tenant_id', '', expires=0)

    # Also clear UI session role (kid/parent) so frontend role gating resets
    try:
        session.pop('user_role', None)
    except Exception:
        pass
    try:
        log_system_event('logout', 'Tenant logged out', None, 'success')
    except Exception:
        pass
    return resp, 200


@app.route('/api/tenant-login', methods=['POST'])
def api_tenant_login():
    """Tenant login endpoint used by the tenant sign-in page.

    Expects JSON: { tenant: <tenant_name>, username: <optional>, password: <password> }
    On success:
      - sets HttpOnly cookie `tenant_id` (so JS cannot read it)
      - sets HttpOnly cookie `refresh_token` (rotation/refresh flow)
      - returns JSON { token: <access_token>, expires_in: <seconds> }
    """
    data = request.get_json(force=True) or {}
    tenant = data.get('tenant') or data.get('tenant_name')
    password = data.get('password')

    if not tenant or not password:
        return jsonify({'error': 'Missing tenant or password'}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    # Look up tenant credentials
    # Perform case-insensitive tenant lookup so usernames are not case-sensitive
    cur.execute("SELECT tenant_id, tenant_password FROM tenants WHERE LOWER(tenant_name) = LOWER(%s)", (tenant,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    tenant_id, stored = row[0], row[1]

    # Only accept Argon2-formatted hashes
    if not (isinstance(stored, str) and stored.startswith('$argon2')):
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    try:
        ph.verify(stored, password)
        # Rehash transparently if parameters changed
        try:
            if ph.check_needs_rehash(stored):
                new_hash = ph.hash(password)
                cur.execute('UPDATE tenants SET tenant_password = %s WHERE tenant_id = %s', (new_hash, tenant_id))
                conn.commit()
        except Exception:
            pass
    except argon2_exceptions.VerifyMismatchError:
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception:
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    # Issue tokens
    access_token = create_access_token(tenant_id)
    refresh_token, refresh_expires = create_refresh_token_record(conn, tenant_id, request.headers.get('User-Agent'), request.remote_addr)

    # Set cookies: refresh_token and tenant_id (HttpOnly)
    resp = jsonify({'token': access_token, 'expires_in': ACCESS_TOKEN_EXPIRES})
    # refresh_token cookie (long-lived)
    resp.set_cookie('refresh_token', refresh_token, httponly=True, secure=False, samesite='Strict', expires=refresh_expires)
    # tenant_id cookie (HttpOnly so JS cannot access it)
    # set expiry similar to refresh token so tenant association persists
    resp.set_cookie('tenant_id', str(tenant_id), httponly=True, secure=False, samesite='Strict', expires=refresh_expires)

    try:
        log_system_event('tenant_login', 'Tenant login success', {'tenant_id': tenant_id}, 'success')
    except Exception:
        pass

    cur.close()
    conn.close()
    return resp, 200


@app.route('/api/tenants', methods=['POST'])
def api_create_tenant():
    """Create a new tenant via invite token (invite-only).

    Requires a valid invite token in the JSON body.
    Expects JSON: { "tenant_name": "...", "password": "...", "parent_pin": "<4-digit>", "invite_token": "..." }
    Returns: { "tenant_id": "<uuid>" }
    """
    # Parse JSON body early
    if not request.is_json:
        return jsonify({'error': 'Expected JSON body'}), 400
    data = request.get_json(force=True) or {}
    tenant_name = (data.get('tenant_name') or '').strip()
    password = data.get('password') or ''
    parent_pin = (data.get('parent_pin') or '').strip()
    invite_token = (data.get('invite_token') or '').strip()

    # Require invite token (no management key fallback)
    if not invite_token:
        try:
            log_system_event('tenant_create_forbidden', 'Attempt to create tenant without invite token', None, 'error')
        except Exception:
            pass
        return jsonify({'error': 'Invite token required'}), 403

    invite_row = None
    conn = None
    cur = None
    # Validate invite token
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('''
            SELECT invite_id, expires_at, max_uses, uses, allowed_email
            FROM tenant_invites WHERE token = %s
        ''', (invite_token,))
        row = cur.fetchone()
        if not row:
            try:
                log_system_event('tenant_create_invalid_invite', 'Invalid invite token used', None, 'error')
            except Exception:
                pass
            cur.close()
            conn.close()
            return jsonify({'error': 'Invalid invite token'}), 403

        invite_id, expires_at, max_uses, uses, allowed_email = row
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        if expires_at and expires_at < now:
            cur.close()
            conn.close()
            return jsonify({'error': 'Invite token expired'}), 403
        if max_uses is not None and uses is not None and uses >= max_uses:
            cur.close()
            conn.close()
            return jsonify({'error': 'Invite token already used'}), 403

        # Optionally enforce allowed_email here (not implemented; placeholder)
        invite_row = {
            'invite_id': invite_id,
            'token': invite_token,
            'expires_at': expires_at,
            'max_uses': max_uses,
            'uses': uses,
            'allowed_email': allowed_email
        }
    except Exception as e:
        try:
            log_system_event('tenant_create_error', f'Error validating invite token: {e}', None, 'error')
        except Exception:
            pass
        cur.close()
        conn.close()
        return jsonify({'error': 'Error validating invite token'}), 500

    # Disallow whitespace in tenant name (prevent spaces, tabs, etc.)
    if any(ch.isspace() for ch in tenant_name):
        return jsonify({'error': 'tenant_name must not contain spaces or whitespace characters'}), 400

    if not tenant_name or not password or not parent_pin:
        return jsonify({'error': 'tenant_name, password and parent_pin are required'}), 400

    # parent_pin is required and must be exactly 4 digits
    if not (len(parent_pin) == 4 and parent_pin.isdigit()):
        return jsonify({'error': 'parent_pin must be exactly 4 digits'}), 400

    # Ensure Argon2 hasher is available
    if ph is None:
        return jsonify({'error': 'Server misconfigured: password hasher unavailable'}), 500

    # Use existing DB connection if invite validation already opened one, else create a new connection
    if conn is None:
        conn = get_db_connection()
        cur = conn.cursor()
    try:
        # Prevent duplicate tenant names (case-insensitive)
        cur.execute("SELECT tenant_id FROM tenants WHERE LOWER(tenant_name) = LOWER(%s)", (tenant_name,))
        if cur.fetchone():
            return jsonify({'error': 'Tenant with that name already exists'}), 400

        # Hash password with Argon2
        hashed = ph.hash(password)

        cur.execute(
            "INSERT INTO tenants (tenant_name, tenant_password) VALUES (%s, %s) RETURNING tenant_id",
            (tenant_name, hashed)
        )
        tenant_id = cur.fetchone()[0]

        # Encrypt and store the required parent PIN in the tenant-scoped settings table
        try:
            encrypted_pin = encrypt_password(parent_pin)
            cur.execute('''
                INSERT INTO tenant_settings (tenant_id, setting_key, setting_value)
                VALUES (%s, %s, %s)
                ON CONFLICT (tenant_id, setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
            ''', (tenant_id, 'parent_pin', encrypted_pin))
        except Exception:
            # If storing the PIN fails, rollback and return an error
            conn.rollback()
            try:
                log_system_event('tenant_create_error', 'Failed to store parent PIN during tenant creation', None, 'error')
            except Exception:
                pass
            return jsonify({'error': 'Failed to store parent PIN'}), 500

        # Seed tenant_roles for the new tenant: create a 'kid' role (defaults False)
        # and a 'parent' role (all permissions True). This is idempotent.
        try:
            cur.execute('''
                INSERT INTO tenant_roles (tenant_id, role_name, can_record_chore, can_redeem_points, can_withdraw_cash, can_view_history)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, role_name) DO UPDATE
                SET can_record_chore = EXCLUDED.can_record_chore,
                    can_redeem_points = EXCLUDED.can_redeem_points,
                    can_withdraw_cash = EXCLUDED.can_withdraw_cash,
                    can_view_history = EXCLUDED.can_view_history
            ''', (tenant_id, 'kid', False, False, False, False))
        except Exception:
            # Non-fatal; continue even if seeding fails
            pass

        try:
            cur.execute('''
                INSERT INTO tenant_roles (tenant_id, role_name, can_record_chore, can_redeem_points, can_withdraw_cash, can_view_history)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, role_name) DO UPDATE
                SET can_record_chore = TRUE,
                    can_redeem_points = TRUE,
                    can_withdraw_cash = TRUE,
                    can_view_history = TRUE
            ''', (tenant_id, 'parent', True, True, True, True))
        except Exception:
            # Non-fatal; continue even if seeding fails
            pass

        conn.commit()

        try:
            log_system_event('tenant_created', f'Tenant created: {tenant_name}', {'tenant_id': str(tenant_id)}, 'success')
        except Exception:
            pass

        # If invite-based creation, increment invite uses (mark as used)
        try:
            if invite_row and cur is not None:
                cur.execute('UPDATE tenant_invites SET uses = uses + 1 WHERE invite_id = %s', (invite_row['invite_id'],))
                conn.commit()
        except Exception:
            try:
                log_system_event('tenant_create_warn', 'Failed to update invite usage count', {'tenant_id': str(tenant_id)}, 'error')
            except Exception:
                pass

        return jsonify({'tenant_id': str(tenant_id)}), 201
    except Exception as e:
        error_msg = str(e)
        conn.rollback()
        try:
            log_system_event('tenant_create_error', f'Error creating tenant: {error_msg}', None, 'error')
        except Exception:
            pass
        return jsonify({'error': f'Error creating tenant: {error_msg}'}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/api/tenant/password', methods=['POST'])
def api_change_tenant_password():
    """Change the authenticated tenant's password.

    Expects JSON: { current_password: <str>, new_password: <str> }
    Requires authentication (JWT or valid refresh token) so `g.tenant_id` is set.
    """
    tenant_id = getattr(g, 'tenant_id', None)
    if not tenant_id:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json(silent=True) or {}
    current = data.get('current_password', '')
    new_password = data.get('new_password', '')

    if not new_password:
        return jsonify({'error': 'new_password is required'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('SELECT tenant_password FROM tenants WHERE tenant_id = %s', (tenant_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'Tenant not found'}), 404

        stored = row[0]
        # Only accept Argon2-formatted hashes
        if not (isinstance(stored, str) and stored.startswith('$argon2')):
            return jsonify({'error': 'Invalid credential format'}), 500

        try:
            # Verify current password
            ph.verify(stored, current)
        except Exception:
            return jsonify({'error': 'Current password is incorrect'}), 401

        # Hash and store new password, revoke all refresh tokens for this tenant
        hashed = ph.hash(new_password)
        cur.execute('UPDATE tenants SET tenant_password = %s WHERE tenant_id = %s', (hashed, tenant_id))
        # Revoke any existing refresh tokens so existing sessions must re-auth
        cur.execute('UPDATE refresh_tokens SET revoked = TRUE WHERE tenant_id = %s', (tenant_id,))
        conn.commit()

        try:
            log_system_event('tenant_password_changed', f'Tenant password changed and tokens revoked', {'tenant_id': str(tenant_id)}, 'success')
        except Exception:
            pass

        # Return response that also clears the refresh cookie and tenant_id cookie (forces client to re-login)
        resp = jsonify({'message': 'Password updated'})
        resp.set_cookie('refresh_token', '', expires=0)
        resp.set_cookie('tenant_id', '', expires=0)
        return resp, 200

    except Exception as e:
        conn.rollback()
        try:
            log_system_event('tenant_password_change_error', f'Error changing tenant password: {e}', None, 'error')
        except Exception:
            pass
        return jsonify({'error': 'Error changing password'}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/api/tenants/invites', methods=['POST'])
def api_create_invite():
        """Create a new invite token (requires management key).

        Expects JSON or header: management key can be provided as X-Tenant-Creation-Key header or management_key in JSON body.
        Expects JSON: { expires_at: ISO8601 (optional), max_uses: int (optional), allowed_email: str (optional), notes: str (optional), created_by: str (optional) }
        Returns: { invite_id, token, expires_at, max_uses }
        """
        # Get management key from environment
        mgmt_key = os.environ.get('INVITE_CREATION_KEY')
        if not mgmt_key:
            return jsonify({'error': 'Invite creation is disabled'}), 403

        # Accept management key from either header or JSON body
        provided_key = request.headers.get('X-Invite-Creation-Key') or ''
        if not provided_key and request.is_json:
            data = request.get_json(force=True) or {}
            provided_key = data.get('management_key', '').strip()

        if not provided_key or provided_key != mgmt_key:
            try:
                log_system_event('invite_create_forbidden', 'Attempt to create invite without valid management key', None, 'error')
            except Exception:
                pass
            return jsonify({'error': 'Invalid or missing management key'}), 403

        # Parse JSON body for invite parameters
        if not request.is_json:
            return jsonify({'error': 'Expected JSON body'}), 400
        data = request.get_json(force=True) or {}

        # Extract invite creation parameters
        expires_at = data.get('expires_at')
        allowed_email = data.get('allowed_email')
        notes = data.get('notes')
        created_by = data.get('created_by')
        
        # All invites are single-use only
        max_uses = 1

        # Generate a secure token
        token = secrets.token_urlsafe(48)

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute('''
                INSERT INTO tenant_invites (token, created_by, expires_at, max_uses, uses, allowed_email, notes)
                VALUES (%s, %s, %s, %s, 0, %s, %s) RETURNING invite_id, created_at
            ''', (token, created_by, expires_at, max_uses, allowed_email, notes))
            row = cur.fetchone()
            conn.commit()
            invite_id, created_at = row
            try:
                log_system_event('invite_created', 'Tenant invite created', {'invite_id': str(invite_id), 'created_by': created_by}, 'success')
            except Exception:
                pass
            return jsonify({'invite_id': str(invite_id), 'token': token, 'expires_at': created_at.isoformat() if created_at else None, 'max_uses': max_uses}), 201
        except Exception as e:
            conn.rollback()
            try:
                log_system_event('invite_create_error', f'Error creating invite: {e}', None, 'error')
            except Exception:
                pass
            return jsonify({'error': f'Error creating invite: {e}'}), 500
        finally:
            cur.close()
            conn.close()


@app.route('/api/tenants/invites', methods=['GET'])
def api_list_invites():
        """List all invite tokens (requires admin invite token)."""
        if not request.is_json:
            return jsonify({'error': 'Expected JSON body'}), 400
        data = request.get_json(force=True) or {}
        admin_invite_token = data.get('admin_invite_token', '').strip()

        if not admin_invite_token:
            return jsonify({'error': 'admin_invite_token required'}), 403

        # Validate admin token exists
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute('SELECT 1 FROM tenant_invites WHERE token = %s LIMIT 1', (admin_invite_token,))
            if not cur.fetchone():
                cur.close()
                conn.close()
                return jsonify({'error': 'Invalid admin token'}), 403

            cur.execute('SELECT invite_id, token, created_by, created_at, expires_at, max_uses, uses, allowed_email, notes FROM tenant_invites ORDER BY created_at DESC')
            rows = cur.fetchall()
            invites = []
            for r in rows:
                invite_id, token, created_by, created_at, expires_at, max_uses, uses, allowed_email, notes = r
                invites.append({
                    'invite_id': str(invite_id),
                    'token': token,
                    'created_by': created_by,
                    'created_at': created_at.isoformat() if created_at else None,
                    'expires_at': expires_at.isoformat() if expires_at else None,
                    'max_uses': max_uses,
                    'uses': uses,
                    'allowed_email': allowed_email,
                    'notes': notes
                })
            cur.close()
            conn.close()
            return jsonify(invites), 200
        except Exception as e:
            try:
                log_system_event('invite_list_error', f'Error listing invites: {e}', None, 'error')
            except Exception:
                pass
            cur.close()
            conn.close()
            return jsonify({'error': 'Error listing invites'}), 500


@app.route('/api/tenants/invites/<invite_id>', methods=['DELETE'])
def api_delete_invite(invite_id):
        """Delete an invite token (requires admin invite token)."""
        if not request.is_json:
            return jsonify({'error': 'Expected JSON body'}), 400
        data = request.get_json(force=True) or {}
        admin_invite_token = data.get('admin_invite_token', '').strip()

        if not admin_invite_token:
            return jsonify({'error': 'admin_invite_token required'}), 403

        # Validate admin token exists
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute('SELECT 1 FROM tenant_invites WHERE token = %s LIMIT 1', (admin_invite_token,))
            if not cur.fetchone():
                cur.close()
                conn.close()
                return jsonify({'error': 'Invalid admin token'}), 403

            cur.execute('DELETE FROM tenant_invites WHERE invite_id = %s RETURNING invite_id', (invite_id,))
            row = cur.fetchone()
            if not row:
                cur.close()
                conn.close()
                return jsonify({'error': 'Invite not found'}), 404
            conn.commit()
            try:
                log_system_event('invite_deleted', f'Invite deleted: {invite_id}', None, 'success')
            except Exception:
                pass
            cur.close()
            conn.close()
            return jsonify({'deleted': str(row[0])}), 200
        except Exception as e:
            conn.rollback()
            try:
                log_system_event('invite_delete_error', f'Error deleting invite: {e}', None, 'error')
            except Exception:
                pass
            cur.close()
            conn.close()
            return jsonify({'error': 'Error deleting invite'}), 500
@app.route('/api/auth-check', methods=['GET'])
def api_auth_check():
    """Validate current authentication state.

    Checks Authorization: Bearer <token> header or refresh_token cookie. If valid,
    returns 200 and ensures HttpOnly `tenant_id` cookie is set.
    """
    # 1) Try Authorization header (Bearer)
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        token = auth.split(None, 1)[1]
        try:
            payload = jwt.decode(token, app.secret_key, algorithms=[JWT_ALGORITHM])
            tenant_id = payload.get('sub')
            # Ensure tenant_id cookie exists and matches; set if missing
            resp = jsonify({'tenant_id': tenant_id})
            if not request.cookies.get('tenant_id') or request.cookies.get('tenant_id') != str(tenant_id):
                expires = datetime.utcnow() + timedelta(seconds=REFRESH_TOKEN_EXPIRES)
                resp.set_cookie('tenant_id', str(tenant_id), httponly=True, secure=False, samesite='Strict', expires=expires)
            return resp, 200
        except Exception:
            # fall through to check refresh token
            pass

    # 2) Try refresh token cookie
    refresh = request.cookies.get('refresh_token')
    if refresh:
        conn = get_db_connection()
        valid = validate_refresh_token(conn, refresh)
        if valid:
            tenant_id = valid['tenant_id']
            # Optionally rotate refresh token here, but keep simple: validate only
            resp = jsonify({'tenant_id': tenant_id})
            expires = datetime.utcnow() + timedelta(seconds=REFRESH_TOKEN_EXPIRES)
            resp.set_cookie('tenant_id', str(tenant_id), httponly=True, secure=False, samesite='Strict', expires=expires)
            conn.close()
            return resp, 200
        conn.close()

    return jsonify({'error': 'Not authenticated'}), 401

@app.route('/api/version', methods=['GET'])
def get_version():
    """Get application version and GitHub repo URL."""
    return jsonify({
        'version': __version__,
        'github_url': GITHUB_REPO_URL
    }), 200

@app.route('/api/system-time', methods=['GET'])
def get_system_time():
    """Get current server time in server's local timezone (set via TZ)."""
    # Get current time in server's local timezone
    now = datetime.now()
    # Convert to timezone-aware and get ISO format with timezone
    now_aware = make_timezone_aware(now)
    iso_timestamp = now_aware.isoformat()
    
    return jsonify({
        'time': now.strftime('%H:%M:%S'),
        'hour': now.hour,
        'minute': now.minute,
        'second': now.second,
        'timestamp': iso_timestamp,
        'unix_ms': int(now_aware.timestamp() * 1000)  # Unix timestamp in milliseconds
    }), 200


@app.route('/api/tz-info', methods=['GET'])
def get_tz_info():
    """Return server timezone info.

    JSON fields:
      - tz_offset_min: integer minutes east of UTC (negative = west)
      - tz_name: timezone name as returned by datetime.tzname()
      - timestamp: ISO 8601 timestamp in server local timezone
    """
    # Current local time (naive), convert to timezone-aware local
    now = datetime.now()
    now_aware = make_timezone_aware(now)

    # Compute offset in minutes (utcoffset returns timedelta or None)
    offset = now_aware.utcoffset()
    if offset is None:
        tz_offset_min = 0
    else:
        tz_offset_min = int(offset.total_seconds() / 60)

    tz_name = now_aware.tzname() or ''
    iso_timestamp = now_aware.isoformat()

    return jsonify({
        'tz_offset_min': tz_offset_min,
        'tz_name': tz_name,
        'timestamp': iso_timestamp
    }), 200

@app.route('/add-user')
@parent_required
def add_user_page():
    """Page to add a new user."""
    return render_template('add_user.html')

@app.route('/add-chore')
@parent_required
def add_chore_page():
    """Page to add new chores."""
    return render_template('add_chore.html')

@app.route('/users')
def users_page():
    """Page to view all users."""
    return render_template('users.html')

@app.route('/chores')
@kid_or_parent_required
def chores_page():
    """Page to view all chores."""
    return render_template('chores.html')

@app.route('/record-chore')
@kid_permission_required('kid_allowed_record_chore')
def record_chore_page():
    """Page to record a completed chore."""
    return render_template('record_chore.html')

@app.route('/redeem-points')
@kid_permission_required('kid_allowed_redeem_points')
def redeem_points_page():
    """Page to redeem points for rewards."""
    return render_template('redeem_points.html')

@app.route('/withdraw-cash')
@kid_permission_required('kid_allowed_withdraw_cash')
def withdraw_cash_page():
    """Page to withdraw cash from user's cash balance."""
    return render_template('withdraw_cash.html')

# Chores endpoints
@app.route('/api/chores', methods=['GET'])
@kid_or_parent_required
def get_chores():
    """Get all chores. All chores are visible, but those with requires_approval=True are greyed out for kids."""
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        return jsonify({'error': 'tenant context required'}), 401

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    # Return tenant-scoped chores ordered by point value, and treats leading underscores as spaces for sorting by chore name
    cursor.execute(
        'SELECT * FROM tenant_chores WHERE tenant_id = %s ORDER BY point_value, REPLACE(chore, \'_\', \' \') ASC',
        (tenant_id,)
    )
    chores = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([dict(chore) for chore in chores])

@app.route('/api/chores/<int:chore_id>', methods=['DELETE'])
@parent_required
def delete_chore(chore_id):
    """Delete a chore without affecting existing transactions."""
    conn = get_db_connection()
    cursor = conn.cursor()
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        return jsonify({'error': 'tenant context required'}), 401
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        return jsonify({'error': 'tenant context required'}), 401
    
    try:
        # First, check if chore exists and get chore name for logging
        tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
        if not tenant_id:
            return jsonify({'error': 'tenant context required'}), 401

        cursor.execute('SELECT chore FROM tenant_chores WHERE chore_id = %s AND tenant_id = %s', (chore_id, tenant_id))
        chore_result = cursor.fetchone()
        if not chore_result:
            cursor.close()
            conn.close()
            # Log error
            try:
                log_system_event('chore_deleted', f'Failed to delete chore: Chore not found', 
                                {'chore_id': chore_id}, 'error')
            except Exception:
                pass
            return jsonify({'error': 'Chore not found'}), 404
        
        chore_name = chore_result[0]  # Get chore name from result
        
        # Delete the chore (transactions keep their original description)
        cursor.execute('DELETE FROM tenant_chores WHERE chore_id = %s AND tenant_id = %s', (chore_id, tenant_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Log successful deletion
        try:
            log_system_event('chore_deleted', f'Chore deleted: {chore_name}', 
                            {'chore_id': chore_id, 'chore': chore_name}, 'success')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'message': 'Chore deleted successfully'}), 200
    except Exception as e:
        error_msg = str(e)
        conn.rollback()
        cursor.close()
        conn.close()
        
        # Log deletion error
        try:
            log_system_event('chore_deleted', f'Error deleting chore: {error_msg}', 
                            {'chore_id': chore_id, 'error': error_msg}, 'error')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'error': f'Error deleting chore: {error_msg}'}), 500

@app.route('/api/chores/<int:chore_id>', methods=['PUT'])
@parent_required
def update_chore(chore_id):
    """Update an existing chore."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Validate required fields if provided
    if 'point_value' in data:
        try:
            point_value = int(data['point_value'])
        except (ValueError, TypeError):
            return jsonify({'error': 'point_value must be a number'}), 400
    else:
        point_value = None
    
    # Handle repeat value
    repeat_value = None
    if 'repeat' in data:
        repeat_value = data.get('repeat')
        if repeat_value == '':
            repeat_value = 'as_needed'
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # Require tenant context and get current chore values for comparison
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        return jsonify({'error': 'tenant context required'}), 401

    cursor.execute('SELECT chore, point_value, "repeat", requires_approval FROM tenant_chores WHERE chore_id = %s AND tenant_id = %s', (chore_id, tenant_id))
    chore_result = cursor.fetchone()
    if not chore_result:
        cursor.close()
        conn.close()
        # Log error
        try:
            log_system_event('chore_edited', f'Failed to update chore: Chore not found', 
                            {'chore_id': chore_id}, 'error')
        except Exception:
            pass
        return jsonify({'error': 'Chore not found'}), 404
    
    old_chore_name = chore_result['chore']
    old_point_value = chore_result.get('point_value')
    old_repeat = chore_result.get('repeat')
    old_requires_approval = chore_result.get('requires_approval', False)
    
    # Track changed fields for logging (with old and new values)
    changed_fields = {}
    
    cursor.close()
    
    # Switch to regular cursor for updates
    cursor = conn.cursor()
    
    try:
        # Build update query dynamically based on provided fields
        updates = []
        params = []
        
        if 'chore' in data:
            new_chore_name = data['chore']
            if new_chore_name != old_chore_name:
                changed_fields['chore'] = {'old': old_chore_name, 'new': new_chore_name}
            updates.append('chore = %s')
            params.append(new_chore_name)
        
        if point_value is not None:
            if point_value != old_point_value:
                changed_fields['point_value'] = {'old': old_point_value, 'new': point_value}
            updates.append('point_value = %s')
            params.append(point_value)
        
        if 'repeat' in data:
            # Normalize repeat value for comparison
            old_repeat_normalized = old_repeat if old_repeat else 'as_needed'
            if repeat_value != old_repeat_normalized:
                changed_fields['repeat'] = {'old': old_repeat_normalized, 'new': repeat_value}
            updates.append('"repeat" = %s')
            params.append(repeat_value)
        
        if 'requires_approval' in data:
            requires_approval = data.get('requires_approval', False)
            if isinstance(requires_approval, str):
                requires_approval = requires_approval.lower() in ('true', '1', 'yes')
            if requires_approval != old_requires_approval:
                changed_fields['requires_approval'] = {'old': old_requires_approval, 'new': requires_approval}
            updates.append('requires_approval = %s')
            params.append(requires_approval)
        
        if not updates:
            cursor.close()
            conn.close()
            return jsonify({'error': 'No fields to update'}), 400
        
        params.append(chore_id)
        params.append(tenant_id)

        cursor.execute(
            f'UPDATE tenant_chores SET {", ".join(updates)} WHERE chore_id = %s AND tenant_id = %s',
            params
        )
        
        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            # Log error
            try:
                log_system_event('chore_edited', f'Failed to update chore: Chore not found after update attempt', 
                                {'chore_id': chore_id}, 'error')
            except Exception:
                pass
            return jsonify({'error': 'Chore not found'}), 404
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Log chore update - only include chore name and changed fields
        try:
            # Get the final chore name (could have changed)
            final_chore_name = data.get('chore', old_chore_name)
            log_details = {'chore': final_chore_name}
            
            # Only include changed fields in details
            if changed_fields:
                log_details.update(changed_fields)
            
            log_system_event('chore_edited', f'Chore updated: {final_chore_name}', 
                            log_details, 'success')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'message': 'Chore updated successfully'}), 200
    except Exception as e:
        error_msg = str(e)
        conn.rollback()
        cursor.close()
        conn.close()
        
        # Log update error
        try:
            log_system_event('chore_edited', f'Error updating chore: {error_msg}', 
                            {'chore_id': chore_id, 'error': error_msg}, 'error')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'error': f'Error updating chore: {error_msg}'}), 500

@app.route('/api/chores', methods=['POST'])
@parent_required
def create_chore():
    """Create a new chore."""
    # Handle both JSON and form data
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()
        if 'point_value' in data:
            try:
                data['point_value'] = int(data['point_value'])
            except (ValueError, TypeError):
                return jsonify({'error': 'point_value must be a number'}), 400
    
    if not data.get('chore'):
        return jsonify({'error': 'chore is required'}), 400
    if not data.get('point_value'):
        return jsonify({'error': 'point_value is required'}), 400
    
    try:
        point_value = int(data['point_value'])
    except (ValueError, TypeError):
        return jsonify({'error': 'point_value must be a number'}), 400
    
    # Default repeat to 'as_needed' if not provided or is empty string, but allow explicit null
    # Check if 'repeat' key exists in the data
    if 'repeat' in data:
        repeat_value = data.get('repeat')
        # If explicitly set to None/null, use None
        # If empty string, default to 'as_needed'
        if repeat_value == '':
            repeat_value = 'as_needed'
        # If None, keep as None (explicit null)
    else:
        # Key not provided, default to 'as_needed'
        repeat_value = 'as_needed'
    
    # Handle requires_approval field (default to False if not provided)
    requires_approval = data.get('requires_approval', False)
    if isinstance(requires_approval, str):
        requires_approval = requires_approval.lower() in ('true', '1', 'yes')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
        if not tenant_id:
            return jsonify({'error': 'tenant context required'}), 401

        cursor.execute(
            'INSERT INTO tenant_chores (tenant_id, chore, point_value, "repeat", requires_approval) VALUES (%s, %s, %s, %s, %s) RETURNING chore_id',
            (tenant_id, data['chore'], point_value, repeat_value, requires_approval)
        )
        chore_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
        conn.close()
        
        # Log chore creation
        try:
            log_system_event('chore_added', f'Chore created: {data["chore"]}', 
                            {'chore_id': chore_id, 'chore': data['chore'], 'point_value': point_value, 'repeat': repeat_value}, 'success')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'chore_id': chore_id, 'message': 'Chore created successfully'}), 201
    except Exception as e:
        error_msg = str(e)
        conn.rollback()
        cursor.close()
        conn.close()
        
        # Log creation error
        try:
            log_system_event('chore_added', f'Error creating chore: {error_msg}', 
                            {'chore': data.get('chore', ''), 'error': error_msg}, 'error')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'error': f'Error creating chore: {error_msg}'}), 500

@app.route('/api/chores/import', methods=['POST'])
@parent_required
def import_chores():
    """Import multiple chores from CSV data."""
    data = request.get_json()
    
    if not data or 'chores' not in data:
        return jsonify({'error': 'chores array is required'}), 400
    
    chores = data['chores']
    if not isinstance(chores, list):
        return jsonify({'error': 'chores must be an array'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        return jsonify({'error': 'tenant context required'}), 401

    imported = 0
    errors = 0
    
    for chore_data in chores:
        try:
            chore = chore_data.get('chore', '').strip()
            point_value = chore_data.get('point_value', '')
            repeat = chore_data.get('repeat', '')
            if repeat:
                repeat = repeat.strip().lower()
            else:
                repeat = ''
            
            # Default to 'as_needed' if not provided or is empty, but allow explicit null
            # If explicitly set to "null" or "none" (case-insensitive), use None
            if repeat in ['null', 'none']:
                repeat = None
            elif repeat == '':
                repeat = 'as_needed'
            
            if not chore:
                errors += 1
                continue
            
            try:
                point_value = int(point_value)
            except (ValueError, TypeError):
                errors += 1
                continue
            
            cursor.execute(
                'INSERT INTO tenant_chores (tenant_id, chore, point_value, "repeat") VALUES (%s, %s, %s, %s)',
                (tenant_id, chore, point_value, repeat)
            )
            imported += 1
        except Exception as e:
            errors += 1
            logger.error(f"Error importing chore: {e}")
    
    try:
        conn.commit()
        cursor.close()
        conn.close()
        
        # Log chore import
        try:
            status = 'success' if errors == 0 else 'error' if imported == 0 else 'success'
            log_system_event('chore_imported', f'Chores imported: {imported} successful, {errors} errors', 
                            {'imported': imported, 'errors': errors, 'total': len(chores)}, status)
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({
            'imported': imported,
            'errors': errors,
            'message': f'Imported {imported} chore(s)'
        }), 201
    except Exception as e:
        error_msg = str(e)
        conn.rollback()
        cursor.close()
        conn.close()
        
        # Log import error
        try:
            log_system_event('chore_imported', f'Error during chore import: {error_msg}', 
                            {'imported': imported, 'errors': errors, 'total': len(chores), 'error': error_msg}, 'error')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'error': f'Error importing chores: {error_msg}'}), 500

# User endpoints
@app.route('/api/users', methods=['GET'])
@kid_or_parent_required
def get_users():
    """Get all users with their cash balances."""
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        return jsonify({'error': 'tenant context required'}), 401

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('''
        SELECT 
            u.user_id,
            u.full_name,
            u.points_balance,
            u.avatar_path,
            u.cash_balance
        FROM tenant_users u
        WHERE u.tenant_id = %s
        ORDER BY u.user_id
    ''', (tenant_id,))
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([dict(user) for user in users])

@app.route('/api/users/<int:user_id>/avatar', methods=['POST'])
@kid_or_parent_required
def upload_avatar(user_id):
    """Upload avatar for a user."""
    if 'avatar' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Allowed: png, jpg, jpeg, gif, webp'}), 400
    
    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size > MAX_AVATAR_SIZE:
        return jsonify({'error': 'File too large. Maximum size is 5MB'}), 400
    
    # Verify user exists (tenant-scoped)
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        return jsonify({'error': 'tenant context required'}), 401

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT user_id FROM tenant_users WHERE user_id = %s AND tenant_id = %s', (user_id, tenant_id))
    user = cursor.fetchone()
    if not user:
        cursor.close()
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    
    # Generate unique filename
    file_ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f'{user_id}_{uuid.uuid4().hex}.{file_ext}'
    filepath = os.path.join(AVATAR_DIR, filename)
    
    # Save file
    file.save(filepath)
    
    # Delete old avatar if exists (tenant-scoped)
    cursor.execute('SELECT avatar_path FROM tenant_users WHERE user_id = %s AND tenant_id = %s', (user_id, tenant_id))
    old_avatar = cursor.fetchone()
    if old_avatar and old_avatar.get('avatar_path'):
        old_path = os.path.join(AVATAR_DIR, os.path.basename(old_avatar['avatar_path']))
        if os.path.exists(old_path):
            try:
                os.remove(old_path)
            except:
                pass  # Ignore errors deleting old file
    
    # Get user name for logging (tenant-scoped)
    cursor.execute('SELECT full_name FROM tenant_users WHERE user_id = %s AND tenant_id = %s', (user_id, tenant_id))
    user_result = cursor.fetchone()
    user_name = user_result.get('full_name') if user_result else f'User {user_id}'

    # Update database
    relative_path = os.path.join('avatars', filename)
    cursor.execute('UPDATE tenant_users SET avatar_path = %s WHERE user_id = %s AND tenant_id = %s', (relative_path, user_id, tenant_id))
    conn.commit()
    cursor.close()
    conn.close()
    
    # Log avatar upload
    try:
        log_system_event('avatar_uploaded', f'Avatar uploaded for {user_name}', 
                        {'user_id': user_id, 'user_name': user_name, 'filename': filename}, 'success')
    except Exception:
        pass  # Don't fail if logging fails
    
    return jsonify({
        'avatar_path': relative_path,
        'message': 'Avatar uploaded successfully'
    }), 200

@app.route('/avatars/<path:filename>')
def serve_avatar(filename):
    """Serve avatar images."""
    return send_from_directory(AVATAR_DIR, filename)

@app.route('/api/users', methods=['POST'])
@parent_required
def create_user():
    """Create a new user."""
    # Handle both JSON and form data
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()
        if 'points_balance' in data:
            try:
                data['points_balance'] = int(data['points_balance'])
            except (ValueError, TypeError):
                data['points_balance'] = 0
    
    if not data.get('full_name'):
        return jsonify({'error': 'full_name is required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
        if not tenant_id:
            return jsonify({'error': 'tenant context required'}), 401

        cursor.execute(
            'INSERT INTO tenant_users (tenant_id, full_name, points_balance) VALUES (%s, %s, %s) RETURNING user_id',
            (tenant_id, data['full_name'], data.get('points_balance', 0))
        )
        user_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
        conn.close()
        
        # Log user creation
        try:
            log_system_event('user_added', f'User created: {data["full_name"]}', 
                            {'user_id': user_id, 'full_name': data['full_name'], 'points_balance': data.get('points_balance', 0)}, 'success')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'user_id': user_id, 'message': 'User created successfully'}), 201
    except Exception as e:
        error_msg = str(e)
        conn.rollback()
        cursor.close()
        conn.close()
        
        # Log creation error
        try:
            log_system_event('user_added', f'Error creating user: {error_msg}', 
                            {'full_name': data.get('full_name', ''), 'error': error_msg}, 'error')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'error': f'Error creating user: {error_msg}'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@parent_required
def delete_user(user_id):
    """Delete a user and all associated data."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        return jsonify({'error': 'tenant context required'}), 401

    # Check if user exists and get user name for logging (tenant-scoped)
    cursor.execute('SELECT full_name, avatar_path FROM tenant_users WHERE user_id = %s AND tenant_id = %s', (user_id, tenant_id))
    user = cursor.fetchone()
    if not user:
        cursor.close()
        conn.close()
        # Log error
        try:
            log_system_event('user_deleted', f'Failed to delete user: User not found', 
                            {'user_id': user_id, 'tenant_id': tenant_id}, 'error')
        except Exception:
            pass
        return jsonify({'error': 'User not found'}), 404

    user_name = user['full_name']
    
    # Delete avatar file if exists
    if user.get('avatar_path'):
        avatar_path = os.path.join(AVATAR_DIR, os.path.basename(user['avatar_path']))
        if os.path.exists(avatar_path):
            try:
                os.remove(avatar_path)
            except:
                pass  # Ignore errors deleting file
    
    # Delete related data (cascading deletes should handle this, but being explicit)
    # Note: Transactions are kept for historical purposes - they reference user_id
    # which will become orphaned. The user record is deleted but transactions remain.
    # If you want to delete transactions too, uncomment the line below:
    # Delete transactions first to avoid foreign key issues, then balances.
    try:
        cursor.execute('DELETE FROM tenant_transactions WHERE user_id = %s AND tenant_id = %s', (user_id, tenant_id))
        deleted_tx = cursor.rowcount
    except Exception:
        # If transactions table or FK constraints behave differently, ignore and continue
        deleted_tx = None
    
    # Delete user (tenant-scoped) - cash_balance is now a column in tenant_users
    cursor.execute('DELETE FROM tenant_users WHERE user_id = %s AND tenant_id = %s', (user_id, tenant_id))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    # Log successful deletion
    try:
        log_system_event('user_deleted', f'User deleted: {user_name}', 
                        {'user_id': user_id, 'full_name': user_name}, 'success')
    except Exception:
        pass  # Don't fail if logging fails
    
    return jsonify({'message': 'User deleted successfully'}), 200

# Transactions endpoints
@app.route('/api/transactions', methods=['GET'])
@kid_or_parent_required
def get_transactions():
    """Get all transactions with user and chore names."""
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        return jsonify({'error': 'tenant context required'}), 401

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    # Join with tenant_users to get user name, description is now directly in tenant_transactions table
    cursor.execute('''
        SELECT 
            t.transaction_id,
            t.user_id,
            t.description,
            t.value,
            t.transaction_type,
            t.timestamp,
            u.full_name as user_name
        FROM tenant_transactions t
        LEFT JOIN tenant_users u ON t.user_id = u.user_id AND t.tenant_id = u.tenant_id
        WHERE t.tenant_id = %s
        ORDER BY t.timestamp DESC
    ''', (tenant_id,))
    transactions = cursor.fetchall()
    cursor.close()
    conn.close()
    
    # Convert timestamps to ISO format with timezone info
    transactions_list = []
    for transaction in transactions:
        transaction_dict = dict(transaction)
        timestamp = transaction_dict.get('timestamp')
        if timestamp:
            # Timestamps are stored as naive datetimes in local system time
            # Convert to timezone-aware and then to ISO format string
            timestamp_aware = make_timezone_aware(timestamp)
            transaction_dict['timestamp'] = timestamp_aware.isoformat()
        transactions_list.append(transaction_dict)
    
    return jsonify(transactions_list)

@app.route('/history')
@kid_permission_required('kid_allowed_view_history')
def history_page():
    """Page to view transaction history."""
    return render_template('history.html')

def get_email_notification_setting(setting_key):
    """Get email notification setting from database."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    # Prefer tenant-scoped setting when tenant context is available
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    result = None
    try:
        if tenant_id:
            cursor.execute('SELECT setting_value FROM tenant_settings WHERE tenant_id = %s AND setting_key = %s', (tenant_id, setting_key))
            result = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if result and result.get('setting_value') is not None:
        return result.get('setting_value') == '1'
    return False

def send_notification_email(notification_type, user_name, description, value=None, user_id=None):
    """Send email notification based on transaction type.
    
    Args:
        notification_type: 'chore_completed', 'points_redeemed', or 'cash_withdrawn'
        user_name: Name of the user who performed the action
        description: Description of the transaction
        value: Optional value (points or cash amount)
        user_id: Optional user ID to fetch current balances
    """
    # Check if notification is enabled for this type
    setting_key = f'email_notify_{notification_type}'
    if not get_email_notification_setting(setting_key):
        return
    
    # Get parent email addresses and all email settings to send notification to
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    # Tenant-scoped email settings only
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        cursor.close()
        conn.close()
        return
    cursor.execute('SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = %s AND setting_key LIKE %s', (tenant_id, 'email_%'))
    results = cursor.fetchall()
    
    # Get user's current balances if user_id is provided (tenant-scoped)
    point_balance = None
    cash_balance = None
    if user_id:
        cursor.execute('SELECT points_balance, cash_balance FROM tenant_users WHERE user_id = %s AND tenant_id = %s', (user_id, tenant_id))
        user_result = cursor.fetchone()
        if user_result:
            point_balance = user_result.get('points_balance') or 0
            cash_balance = user_result.get('cash_balance') or 0
        else:
            point_balance = 0
            cash_balance = 0
    
    cursor.close()
    conn.close()
    
    settings_dict = {row['setting_key']: row['setting_value'] for row in results}
    
    # Determine recipient emails - prefer parent_email_addresses, fallback to email_username
    parent_emails_str = settings_dict.get('parent_email_addresses', '').strip()
    username = settings_dict.get('email_username', '').strip()
    
    if parent_emails_str:
        email_list = [e.strip() for e in parent_emails_str.split(',') if e.strip()]
    elif username:
        email_list = [username]
    else:
        return  # No email configured
    
    if not email_list:
        return
    
    # Format balance information for email
    balance_info_html = ""
    balance_info_text = ""
    if point_balance is not None and cash_balance is not None:
        balance_info_html = f"""
            <p>Current point balance: <strong>{point_balance}</strong></p>
            <p>Current cash balance: <strong>${cash_balance:.2f}</strong></p>
        """
        balance_info_text = f"""Current point balance: {point_balance}
Current cash balance: ${cash_balance:.2f}

"""
    
    # Format email subject and body based on notification type
    if notification_type == 'chore_completed':
        subject = f"{user_name} completed a chore: {description}"
        body_html = f"""
        <html>
          <head></head>
          <body>
            <h2>Chore Completed</h2>
            <p><strong>{user_name}</strong> completed: <strong>{description}</strong></p>
            <p>Points earned: <strong>{value if value else 'N/A'}</strong></p>
            {balance_info_html}
            <hr>
            <p style="color: #666; font-size: 12px;">Sent from Family Chores application</p>
          </body>
        </html>
        """
        body_text = f"""Chore Completed

{user_name} completed: {description}
Points earned: {value if value else 'N/A'}
{balance_info_text}Sent from Family Chores application
        """
    elif notification_type == 'points_redeemed':
        subject = f"{user_name} {description.lower()}"
        body_html = f"""
        <html>
          <head></head>
          <body>
            <h2>Points Redeemed</h2>
            <p><strong>{user_name}</strong> redeemed points.</p>
            <p>Details: <strong>{description}</strong></p>
            <p>Points redeemed: <strong>{abs(value) if value else 'N/A'}</strong></p>
            {balance_info_html}
            <hr>
            <p style="color: #666; font-size: 12px;">Sent from Family Chores application</p>
          </body>
        </html>
        """
        body_text = f"""Points Redeemed

{user_name} redeemed points.
Details: {description}
Points redeemed: {abs(value) if value else 'N/A'}
{balance_info_text}Sent from Family Chores application
        """
    elif notification_type == 'cash_withdrawn':
        subject = f"{user_name} withdrew ${abs(value) if value else 'N/A'}"
        body_html = f"""
        <html>
          <head></head>
          <body>
            <h2>Cash Withdrawn</h2>
            <p><strong>{user_name}</strong> withdrew cash.</p>
            <p>Amount: <strong>${abs(value) if value else 'N/A'}</strong></p>
            {balance_info_html}
            <hr>
            <p style="color: #666; font-size: 12px;">Sent from Family Chores application</p>
          </body>
        </html>
        """
        body_text = f"""Cash Withdrawn

{user_name} withdrew cash.
Amount: ${abs(value) if value else 'N/A'}
{balance_info_text}Sent from Family Chores application
        """
    else:
        return
    
    # Send email to all parent addresses (ignore errors - don't fail transaction if email fails)
    try:
        for email in email_list:
            try:
                send_email(email, subject, body_html, body_text, settings_dict=settings_dict)
            except Exception:
                pass  # Silently ignore individual email errors
    except Exception:
        pass  # Silently ignore email errors



# Settings endpoints
@app.route('/settings')
@parent_required
def settings_page():
    """Page to view and edit settings."""
    return render_template('settings.html')

@app.route('/api/settings', methods=['GET'])
@parent_required
def get_settings():
    """Get all settings."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        cursor.close()
        conn.close()
        return jsonify({}), 200
    cursor.execute('SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = %s', (tenant_id,))
    settings = cursor.fetchall()
    cursor.close()
    conn.close()
    
    settings_dict = {row['setting_key']: row['setting_value'] for row in settings}
    
    # Convert string values to appropriate types
    # Fetch kid role permissions from roles table if available (roles table now authoritative)
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    # Tenant-scoped roles lookup
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if tenant_id:
        cursor.execute("SELECT can_record_chore, can_redeem_points, can_withdraw_cash, can_view_history FROM tenant_roles WHERE tenant_id = %s AND role_name = %s", (tenant_id, 'kid'))
        kid_role = cursor.fetchone()
    else:
        kid_role = None
    cursor.close()
    conn.close()

    result = {
        'automatic_daily_cash_out': settings_dict.get('automatic_daily_cash_out', '1') == '1',
        'max_rollover_points': int(settings_dict.get('max_rollover_points', '4')),
        'daily_cooldown_hours': int(settings_dict.get('daily_cooldown_hours', '12')),
        'weekly_cooldown_days': int(settings_dict.get('weekly_cooldown_days', '4')),
        'monthly_cooldown_days': int(settings_dict.get('monthly_cooldown_days', '14')),
        'kid_allowed_record_chore': (kid_role and kid_role.get('can_record_chore')) if kid_role is not None else (settings_dict.get('kid_allowed_record_chore', '0') == '1'),
        'kid_allowed_redeem_points': (kid_role and kid_role.get('can_redeem_points')) if kid_role is not None else (settings_dict.get('kid_allowed_redeem_points', '0') == '1'),
        'kid_allowed_withdraw_cash': (kid_role and kid_role.get('can_withdraw_cash')) if kid_role is not None else (settings_dict.get('kid_allowed_withdraw_cash', '0') == '1'),
        'kid_allowed_view_history': (kid_role and kid_role.get('can_view_history')) if kid_role is not None else (settings_dict.get('kid_allowed_view_history', '0') == '1'),
        'email_smtp_server': settings_dict.get('email_smtp_server', ''),
        'email_smtp_port': settings_dict.get('email_smtp_port', '587'),
        'email_username': settings_dict.get('email_username', ''),
        'email_password': '',  # Never return password in API
        'email_sender_name': settings_dict.get('email_sender_name', 'Family Chores'),
        'email_notify_chore_completed': settings_dict.get('email_notify_chore_completed', '0') == '1',
        'email_notify_points_redeemed': settings_dict.get('email_notify_points_redeemed', '0') == '1',
        'email_notify_cash_withdrawn': settings_dict.get('email_notify_cash_withdrawn', '0') == '1',
        'email_notify_daily_digest': settings_dict.get('email_notify_daily_digest', '0') == '1',
        'parent_email_addresses': settings_dict.get('parent_email_addresses', ''),
        # For security, never return the actual parent PIN. Frontend will leave field blank to keep existing.
        'parent_pin': ''
    }
    
    return jsonify(result)

@app.route('/api/settings', methods=['PUT'])
@parent_required
def update_settings():
    """Update settings."""
    data = request.get_json()
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # Get current tenant-scoped settings to compare for logging
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        cursor.close()
        conn.close()
        return jsonify({'error': 'Tenant context required'}), 400
    cursor.execute('SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = %s', (tenant_id,))
    current_settings = {row['setting_key']: row['setting_value'] for row in cursor.fetchall()}
    cursor.close()
    
    # Track changed settings for logging
    changed_settings = {}
    
    # Helper function to update a boolean setting
    def update_bool_setting(key, default='0'):
        if key in data:
            value = '1' if data[key] else '0'
            old_value = current_settings.get(key, default)
            if str(value) != str(old_value):
                changed_settings[key] = {'old': old_value == '1', 'new': data[key]}
            cursor.execute('''
                INSERT INTO tenant_settings (tenant_id, setting_key, setting_value)
                VALUES (%s, %s, %s)
                ON CONFLICT (tenant_id, setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
            ''', (tenant_id, key, value))
    
    # Helper function to update an integer setting with validation
    def update_int_setting(key, default, min_value=0, error_msg=None):
        if key in data:
            try:
                int_value = int(data[key])
                if int_value < min_value:
                    cursor.close()
                    conn.close()
                    msg = error_msg or f'{key} must be non-negative'
                    return jsonify({'error': msg}), 400
                old_value = current_settings.get(key, str(default))
                if str(int_value) != str(old_value):
                    changed_settings[key] = {'old': int(old_value), 'new': int_value}
                cursor.execute('''
                    INSERT INTO tenant_settings (tenant_id, setting_key, setting_value)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (tenant_id, setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
                ''', (tenant_id, key, str(int_value)))
            except (ValueError, TypeError):
                cursor.close()
                conn.close()
                msg = error_msg or f'{key} must be a number'
                return jsonify({'error': msg}), 400
        return None
    
    # Helper function to update a string setting
    def update_string_setting(key, default=''):
        if key in data:
            new_value = data[key] or default
            old_value = current_settings.get(key, default)
            if new_value != old_value:
                changed_settings[key] = {'old': old_value, 'new': new_value}
            cursor.execute('''
                INSERT INTO tenant_settings (tenant_id, setting_key, setting_value)
                VALUES (%s, %s, %s)
                ON CONFLICT (tenant_id, setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
            ''', (tenant_id, key, new_value))
    
    # Switch to regular cursor for updates
    cursor = conn.cursor()
    
    # Fetch current kid role permissions from roles table for comparison and updates
    try:
        cursor.execute("SELECT can_record_chore, can_redeem_points, can_withdraw_cash, can_view_history FROM tenant_roles WHERE tenant_id = %s AND role_name = %s", (tenant_id, 'kid'))
        current_role_perms = cursor.fetchone()
    except Exception:
        current_role_perms = None
    
    # Update boolean settings
    update_bool_setting('automatic_daily_cash_out', '1')
    
    # Update integer settings with validation
    result = update_int_setting('max_rollover_points', 4, 0, 'Max rollover points must be non-negative')
    if result:
        return result
    
    result = update_int_setting('daily_cooldown_hours', 12, 0, 'Daily cooldown hours must be non-negative')
    if result:
        return result
    
    result = update_int_setting('weekly_cooldown_days', 4, 0, 'Weekly cooldown days must be non-negative')
    if result:
        return result
    
    result = update_int_setting('monthly_cooldown_days', 14, 0, 'Monthly cooldown days must be non-negative')
    if result:
        return result
    
    # Helper function to update kid permission settings
    def update_kid_permission(key, db_column, perm_index):
        if key in data:
            new_bool = bool(data[key])
            old_bool = False
            if current_role_perms:
                try:
                    old_bool = bool(current_role_perms[perm_index])
                except Exception:
                    old_bool = False
            if new_bool != old_bool:
                changed_settings[key] = {'old': old_bool, 'new': new_bool}
            cursor.execute(f'''
                UPDATE tenant_roles SET {db_column} = %s WHERE role_name = 'kid' AND tenant_id = %s
            ''', (new_bool, tenant_id))
    
    # Update kid permission settings
    update_kid_permission('kid_allowed_record_chore', 'can_record_chore', 0)
    update_kid_permission('kid_allowed_redeem_points', 'can_redeem_points', 1)
    update_kid_permission('kid_allowed_withdraw_cash', 'can_withdraw_cash', 2)
    update_kid_permission('kid_allowed_view_history', 'can_view_history', 3)
    
    # Handle email settings
    update_string_setting('email_smtp_server', '')
    update_string_setting('email_username', '')
    update_string_setting('email_sender_name', 'Family Chores')
    update_string_setting('parent_email_addresses', '')
    
    # Handle SMTP port with validation
    if 'email_smtp_port' in data:
        try:
            smtp_port = str(data['email_smtp_port']).strip()
            if smtp_port and not smtp_port.isdigit():
                cursor.close()
                conn.close()
                return jsonify({'error': 'SMTP port must be a number'}), 400
            new_value = smtp_port or '587'
            old_value = current_settings.get('email_smtp_port', '587')
            if new_value != old_value:
                changed_settings['email_smtp_port'] = {'old': old_value, 'new': new_value}
            cursor.execute('''
                INSERT INTO tenant_settings (tenant_id, setting_key, setting_value)
                VALUES (%s, 'email_smtp_port', %s)
                ON CONFLICT (tenant_id, setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
            ''', (tenant_id, new_value))
        except (ValueError, TypeError):
            cursor.close()
            conn.close()
            return jsonify({'error': 'SMTP port must be a number'}), 400
    
    if 'email_password' in data:
        # Only update password if provided (not empty)
        if data['email_password']:
            # If password is provided, treat it as changed (can't compare encrypted values)
            # But don't show the actual value in logs - show old value if exists
            old_password_exists = bool(current_settings.get('email_password', ''))
            changed_settings['email_password'] = {'old': '<set>' if old_password_exists else '<not set>', 'new': '<changed>'}
            # Encrypt the password before storing
            encrypted_password = encrypt_password(data['email_password'])
            cursor.execute('''
                INSERT INTO tenant_settings (tenant_id, setting_key, setting_value)
                VALUES (%s, 'email_password', %s)
                ON CONFLICT (tenant_id, setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
            ''', (tenant_id, encrypted_password))
    
    # Handle email notification toggles
    update_bool_setting('email_notify_chore_completed', '0')
    update_bool_setting('email_notify_points_redeemed', '0')
    update_bool_setting('email_notify_cash_withdrawn', '0')
    update_bool_setting('email_notify_daily_digest', '0')

    # Handle parent PIN: only update if provided (non-empty). Accept only exactly 4 digits.
    if 'parent_pin' in data:
        try:
            pin_value = str(data['parent_pin'] or '').strip()
        except Exception:
            pin_value = ''

        # If empty, user chose to keep existing PIN; do nothing
        if pin_value:
            # Validate exactly 4 digits
            if not (len(pin_value) == 4 and pin_value.isdigit()):
                cursor.close()
                conn.close()
                return jsonify({'error': 'Parent PIN must be exactly 4 digits or left empty to keep existing'}), 400

            # Determine tenant context. Parent PIN is tenant-scoped.
            tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
            if not tenant_id:
                cursor.close()
                conn.close()
                return jsonify({'error': 'Tenant context required to set parent PIN'}), 400

            # Log that PIN was changed (don't report old/new values for security)
            changed_settings['parent_pin'] = 'changed'

            # Encrypt the PIN before storing for security
            encrypted_pin = encrypt_password(pin_value)
            cursor.execute('''
                INSERT INTO tenant_settings (tenant_id, setting_key, setting_value)
                VALUES (%s, %s, %s)
                ON CONFLICT (tenant_id, setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
            ''', (tenant_id, 'parent_pin', encrypted_pin))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    # Log settings save with only changed settings
    try:
        if changed_settings:
            log_system_event('settings_saved', 'Settings updated successfully', changed_settings, 'success')
        else:
            # No actual changes (all values were the same)
            log_system_event('settings_saved', 'Settings saved (no changes)', {}, 'success')
    except Exception:
        pass  # Don't fail if logging fails
    
    return jsonify({'message': 'Settings updated successfully'}), 200


# Kid permissions endpoints
@app.route('/api/kid-permissions', methods=['GET'])
@kid_or_parent_required
def get_kid_permissions():
    """Return kid role permissions.

    Prefers values from the `roles` table if present, otherwise falls back
    to legacy settings keys in the `settings` table.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
        if not tenant_id:
            cursor.close()
            conn.close()
            return jsonify({
                'kid_allowed_record_chore': False,
                'kid_allowed_redeem_points': False,
                'kid_allowed_withdraw_cash': False,
                'kid_allowed_view_history': False,
            })

        # Check tenant-scoped roles first
        cursor.execute("SELECT can_record_chore, can_redeem_points, can_withdraw_cash, can_view_history FROM tenant_roles WHERE tenant_id = %s AND role_name = %s", (tenant_id, 'kid'))
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if row:
            return jsonify({
                'kid_allowed_record_chore': bool(row.get('can_record_chore')),
                'kid_allowed_redeem_points': bool(row.get('can_redeem_points')),
                'kid_allowed_withdraw_cash': bool(row.get('can_withdraw_cash')),
                'kid_allowed_view_history': bool(row.get('can_view_history')),
            })

        # Fallback to tenant-scoped settings if roles row not present
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
        if not tenant_id:
            cursor.close()
            conn.close()
            return jsonify({
                'kid_allowed_record_chore': False,
                'kid_allowed_redeem_points': False,
                'kid_allowed_withdraw_cash': False,
                'kid_allowed_view_history': False,
            })
        cursor.execute('SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = %s AND setting_key IN (%s, %s, %s, %s)', (
            tenant_id, 'kid_allowed_record_chore', 'kid_allowed_redeem_points', 'kid_allowed_withdraw_cash', 'kid_allowed_view_history'))
        settings = {r['setting_key']: r['setting_value'] for r in cursor.fetchall()}
        cursor.close()
        conn.close()

        return jsonify({
            'kid_allowed_record_chore': settings.get('kid_allowed_record_chore', '0') == '1',
            'kid_allowed_redeem_points': settings.get('kid_allowed_redeem_points', '0') == '1',
            'kid_allowed_withdraw_cash': settings.get('kid_allowed_withdraw_cash', '0') == '1',
            'kid_allowed_view_history': settings.get('kid_allowed_view_history', '0') == '1',
        })
    except Exception as e:
        error_msg = str(e)
        try:
            log_system_event('kid_permissions_error', f'Error fetching kid permissions: {error_msg}', {'error': error_msg}, 'error')
        except Exception:
            pass
        return jsonify({'error': f'Error fetching kid permissions: {error_msg}'}), 500


def _coerce_bool(val):
    """Coerce a variety of input types to boolean sensibly."""
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    if isinstance(val, (int, float)):
        return bool(val)
    s = str(val).strip().lower()
    return s in ('1', 'true', 'yes', 'y', 'on')


@app.route('/api/kid-permissions', methods=['PUT'])
@parent_required
def set_kid_permissions():
    """Set kid role permissions (parent-only).

    Accepts JSON with any of the following boolean keys:
      - kid_allowed_record_chore
      - kid_allowed_redeem_points
      - kid_allowed_withdraw_cash
      - kid_allowed_view_history

    Performs an upsert into the `roles` table and logs changes.
    """
    data = request.get_json() or {}
    allowed_keys = {
        'kid_allowed_record_chore': 'can_record_chore',
        'kid_allowed_redeem_points': 'can_redeem_points',
        'kid_allowed_withdraw_cash': 'can_withdraw_cash',
        'kid_allowed_view_history': 'can_view_history',
    }

    # Build column updates from provided keys
    updates = {}
    for k, col in allowed_keys.items():
        if k in data:
            updates[col] = _coerce_bool(data[k])

    if not updates:
        return jsonify({'message': 'No permission keys provided'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        # Fetch current values to compute changes
        # Tenant-scoped roles lookup
        tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
        if not tenant_id:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Tenant context required'}), 400
        cursor.execute("SELECT can_record_chore, can_redeem_points, can_withdraw_cash, can_view_history FROM tenant_roles WHERE tenant_id = %s AND role_name = %s", (tenant_id, 'kid'))
        current = cursor.fetchone()

        # Prepare upsert: insert if not exists, otherwise update
        # Use ON CONFLICT to update existing row (assumes role_name is unique/PK)
        # Ensure all columns are provided for insert; use current or defaults if missing
        insert_vals = {
            'can_record_chore': updates.get('can_record_chore', current.get('can_record_chore') if current else False),
            'can_redeem_points': updates.get('can_redeem_points', current.get('can_redeem_points') if current else False),
            'can_withdraw_cash': updates.get('can_withdraw_cash', current.get('can_withdraw_cash') if current else False),
            'can_view_history': updates.get('can_view_history', current.get('can_view_history') if current else False),
        }

        cursor.execute('''
            INSERT INTO tenant_roles (tenant_id, role_name, can_record_chore, can_redeem_points, can_withdraw_cash, can_view_history)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, role_name) DO UPDATE SET
                can_record_chore = EXCLUDED.can_record_chore,
                can_redeem_points = EXCLUDED.can_redeem_points,
                can_withdraw_cash = EXCLUDED.can_withdraw_cash,
                can_view_history = EXCLUDED.can_view_history
        ''', (
            tenant_id, 'kid', insert_vals['can_record_chore'], insert_vals['can_redeem_points'], insert_vals['can_withdraw_cash'], insert_vals['can_view_history']
        ))

        # Determine which settings changed for logging
        changed = {}
        for col, new_val in insert_vals.items():
            old_val = None
            if current:
                old_val = bool(current.get(col))
            else:
                old_val = False
            if bool(old_val) != bool(new_val):
                # map back to external key name for readability
                external_key = next((k for k, v in allowed_keys.items() if v == col), col)
                changed[external_key] = {'old': old_val, 'new': bool(new_val)}

        conn.commit()
        cursor.close()
        conn.close()

        try:
            if changed:
                log_system_event('kid_permissions_updated', 'Kid permissions updated', changed, 'success')
            else:
                log_system_event('kid_permissions_updated', 'Kid permissions saved (no changes)', {}, 'success')
        except Exception:
            pass

        return jsonify({'message': 'Kid permissions updated successfully', 'changed': changed}), 200
    except Exception as e:
        error_msg = str(e)
        try:
            log_system_event('kid_permissions_error', f'Error updating kid permissions: {error_msg}', {'error': error_msg}, 'error')
        except Exception:
            pass
        return jsonify({'error': f'Error updating kid permissions: {error_msg}'}), 500

@app.route('/api/daily-cash-out', methods=['POST'])
@parent_required
def manual_daily_cash_out():
    """Manually trigger daily cash out process."""
    try:
        # Log manual trigger (process_daily_cash_out will also log with trigger_type)
        try:
            log_system_event('cash_out_manual', 'Manual daily cash out triggered', {}, 'success')
        except Exception:
            pass  # Don't fail if logging fails
        
        process_daily_cash_out(triggered_manually=True)
        return jsonify({'message': 'Daily cash out processed successfully'}), 200
    except Exception as e:
        error_msg = str(e)
        
        # Log manual trigger error
        try:
            log_system_event('cash_out_manual', f'Error during manual daily cash out: {error_msg}', 
                            {'error': error_msg}, 'error')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'error': f'Error processing daily cash out: {error_msg}'}), 500

@app.route('/api/reset-points', methods=['POST'])
@parent_required
def reset_points():
    """Reset all users' points balances to 0."""
    try:
        tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
        if not tenant_id:
            return jsonify({'error': 'tenant context required'}), 401

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE tenant_users SET points_balance = 0 WHERE tenant_id = %s', (tenant_id,))
        affected_users = cursor.rowcount
        conn.commit()
        cursor.close()
        conn.close()
        
        # Log points reset
        try:
            log_system_event('points_reset', f'All points balances reset to 0 for {affected_users} user(s)', 
                            {'affected_users': affected_users}, 'success')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'message': 'All points balances have been reset to 0'}), 200
    except Exception as e:
        error_msg = str(e)
        
        # Log reset error
        try:
            log_system_event('points_reset', f'Error resetting points balances: {error_msg}', 
                            {'error': error_msg}, 'error')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'error': f'Error resetting points balances: {error_msg}'}), 500

@app.route('/api/reset-cash', methods=['POST'])
@parent_required
def reset_cash():
    """Reset all users' cash balances to 0."""
    try:
        tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
        if not tenant_id:
            return jsonify({'error': 'tenant context required'}), 401

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE tenant_users SET cash_balance = 0.0 WHERE tenant_id = %s', (tenant_id,))
        affected_users = cursor.rowcount
        conn.commit()
        cursor.close()
        conn.close()
        
        # Log cash reset
        try:
            log_system_event('cash_reset', f'All cash balances reset to $0.00 for {affected_users} user(s)', 
                            {'affected_users': affected_users}, 'success')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'message': 'All cash balances have been reset to $0.00'}), 200
    except Exception as e:
        error_msg = str(e)
        
        # Log reset error
        try:
            log_system_event('cash_reset', f'Error resetting cash balances: {error_msg}', 
                            {'error': error_msg}, 'error')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'error': f'Error resetting cash balances: {error_msg}'}), 500

@app.route('/api/reset-transactions', methods=['POST'])
@parent_required
def reset_transactions():
    """Delete all transactions from the database."""
    try:
        tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
        if not tenant_id:
            return jsonify({'error': 'tenant context required'}), 401

        conn = get_db_connection()
        cursor = conn.cursor()
        # Get count before deletion for logging
        cursor.execute('SELECT COUNT(*) as total FROM tenant_transactions WHERE tenant_id = %s', (tenant_id,))
        count_result = cursor.fetchone()
        total_transactions = count_result[0] if count_result else 0

        cursor.execute('DELETE FROM tenant_transactions WHERE tenant_id = %s', (tenant_id,))
        conn.commit()
        cursor.close()
        conn.close()
        
        # Log transactions reset
        try:
            log_system_event('transactions_reset', f'All transactions deleted ({total_transactions} transaction(s))', 
                            {'deleted_count': total_transactions}, 'success')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'message': 'All transactions have been deleted'}), 200
    except Exception as e:
        error_msg = str(e)
        
        # Log reset error
        try:
            log_system_event('transactions_reset', f'Error deleting transactions: {error_msg}', 
                            {'error': error_msg}, 'error')
        except Exception:
            pass  # Don't fail if logging fails
        
        return jsonify({'error': f'Error deleting transactions: {error_msg}'}), 500

def send_email(to_email, subject, body_html, body_text=None, settings_dict=None):
    """Send an email using SMTP settings from the database or provided settings.
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        body_html: HTML body content
        body_text: Plain text body content (optional)
        settings_dict: Optional pre-fetched settings dict. If not provided, fetches from database using tenant context.
    
    Returns:
        tuple: (success: bool, message: str) - success indicates if email was sent, message contains status or error
    """
    try:
        # If settings not provided, fetch from database using tenant context
        if settings_dict is None:
            # Get tenant-scoped email settings from database
            conn = get_db_connection()
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
            if not tenant_id:
                cursor.close()
                conn.close()
                return False, 'Tenant context required'
            cursor.execute('SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = %s AND setting_key LIKE %s', (tenant_id, 'email_%'))
            settings = cursor.fetchall()
            cursor.close()
            conn.close()
            
            settings_dict = {row['setting_key']: row['setting_value'] for row in settings}
        
        smtp_server = settings_dict.get('email_smtp_server', '').strip()
        smtp_port = settings_dict.get('email_smtp_port', '587').strip()
        username = settings_dict.get('email_username', '').strip()
        encrypted_password = settings_dict.get('email_password', '').strip()
        # Decrypt the password
        password = decrypt_password(encrypted_password)
        sender_name = settings_dict.get('email_sender_name', 'Family Chores').strip()
        # Validate required settings
        if not password:
            return False, "Please update the email Password in Settings."
        elif not smtp_server or not smtp_port or not username:
            return False, "Email settings are not configured. Please configure SMTP settings in Settings."
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = formataddr((sender_name, username))
        msg['To'] = to_email
        
        # Add text and HTML parts
        if body_text:
            text_part = MIMEText(body_text, 'plain')
            msg.attach(text_part)
        
        html_part = MIMEText(body_html, 'html')
        msg.attach(html_part)
        
        # Connect to SMTP server and send
        try:
            smtp_port_int = int(smtp_port)
            server = smtplib.SMTP(smtp_server, smtp_port_int, timeout=10)
            server.starttls()  # Enable encryption
            server.login(username, password)
            server.send_message(msg)
            server.quit()
            
            # Log successful email send
            try:
                log_system_event('email_sent', f'Email sent to {to_email}', {'to': to_email, 'subject': subject}, 'success')
            except Exception:
                pass  # Don't fail if logging fails
            
            return True, "Email sent successfully"
        except smtplib.SMTPAuthenticationError:
            return False, "SMTP authentication failed. Please check your username and password."
        except smtplib.SMTPConnectError:
            return False, f"Could not connect to SMTP server {smtp_server}:{smtp_port}. Please check your SMTP settings."
        except smtplib.SMTPException as e:
            error_msg = f"SMTP error: {str(e)}"
            # Log email error
            try:
                log_system_event('email_error', f'Failed to send email to {to_email}', {'to': to_email, 'subject': subject, 'error': error_msg}, 'error')
            except Exception:
                pass
            return False, error_msg
        except Exception as e:
            error_msg = f"Error sending email: {str(e)}"
            # Log email error
            try:
                log_system_event('email_error', f'Failed to send email to {to_email}', {'to': to_email, 'subject': subject, 'error': error_msg}, 'error')
            except Exception:
                pass
            return False, error_msg
    
    except Exception as e:
        error_msg = f"Error: {str(e)}"
        # Log email error
        try:
            log_system_event('email_error', f'Failed to send email to {to_email}', {'to': to_email, 'subject': subject, 'error': error_msg}, 'error')
        except Exception:
            pass
        return False, error_msg

@app.route('/api/send-test-email', methods=['POST'])
@parent_required
def send_test_email():
    """Send a test email to verify email configuration."""
    data = request.get_json()
    
    # Get parent email addresses from request
    parent_emails = data.get('parent_email_addresses', [])
    
    # Get tenant-scoped email settings from database
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        cursor.close()
        conn.close()
        return jsonify({'error': 'Tenant context required'}), 400
    cursor.execute('SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = %s AND setting_key IN (%s, %s)', (tenant_id, 'email_username', 'parent_email_addresses'))
    settings = cursor.fetchall()
    cursor.close()
    conn.close()
    
    settings_dict = {row['setting_key']: row['setting_value'] for row in settings}
    username = settings_dict.get('email_username', '').strip()
    stored_parent_emails = settings_dict.get('parent_email_addresses', '').strip()
    
    # Determine recipient emails
    if parent_emails and len(parent_emails) > 0:
        # Use provided emails
        email_list = [e.strip() for e in parent_emails if e.strip()]
    elif stored_parent_emails:
        # Use stored parent emails
        email_list = [e.strip() for e in stored_parent_emails.split(',') if e.strip()]
    elif username:
        # Fallback to username
        email_list = [username]
    else:
        return jsonify({'error': 'Please provide parent email addresses or configure a username in email settings'}), 400
    
    # Validate email formats (basic check)
    for email in email_list:
        if '@' not in email or '.' not in email.split('@')[1]:
            return jsonify({'error': f'Invalid email address format: {email}'}), 400
    
    # Send test email to all addresses
    subject = "Family Chores - Test Email"
    body_html = """
    <html>
      <head></head>
      <body>
        <h2>Test Email from Family Chores</h2>
        <p>This is a test email to verify that your email notification settings are configured correctly.</p>
        <p>If you received this email, your SMTP settings are working properly!</p>
        <hr>
        <p style="color: #666; font-size: 12px;">Sent from Family Chores application</p>
      </body>
    </html>
    """
    body_text = """Test Email from Family Chores

This is a test email to verify that your email notification settings are configured correctly.

If you received this email, your SMTP settings are working properly!

Sent from Family Chores application
    """
    
    # Send email to each address
    success_count = 0
    error_messages = []
    for email in email_list:
        success, message = send_email(email, subject, body_html, body_text)
        if success:
            success_count += 1
        else:
            error_messages.append(f'{email}: {message}')
    
    # Log test email results
    try:
        if success_count == len(email_list):
            status = 'success'
            message = f'Test email sent successfully to {success_count} address(es)'
        elif success_count > 0:
            status = 'error'
            message = f'Partially sent: {success_count}/{len(email_list)} successful'
        else:
            status = 'error'
            message = f'Failed to send test email to all addresses'
        
        log_system_event('test_email', message, 
                        {'recipients': email_list, 'success_count': success_count, 'total': len(email_list), 
                         'errors': error_messages if error_messages else []}, status)
    except Exception:
        pass  # Don't fail if logging fails
    
    if success_count == len(email_list):
        return jsonify({'message': f'Test email sent successfully to {success_count} address(es)'}), 200
    elif success_count > 0:
        return jsonify({'error': f'Partially sent: {success_count}/{len(email_list)} successful. Errors: {"; ".join(error_messages)}'}), 400
    else:
        return jsonify({'error': f'Failed to send: {"; ".join(error_messages)}'}), 400

@app.route('/api/send-daily-digest', methods=['POST'])
@parent_required
def send_daily_digest_manual():
    """Manually trigger sending of daily digest email."""
    try:
        send_daily_digest_email(triggered_manually=True)
        return jsonify({'message': 'Daily digest email sent successfully'}), 200
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error manually sending daily digest: {error_msg}", exc_info=True)
        return jsonify({'error': f'Error sending daily digest: {error_msg}'}), 500

@app.route('/api/withdraw-cash', methods=['POST'])
@kid_permission_required('kid_allowed_withdraw_cash')
def withdraw_cash():
    """Withdraw cash from a user's cash balance."""
    data = request.get_json()
    
    if not data.get('user_id'):
        return jsonify({'error': 'user_id is required'}), 400
    if 'amount' not in data:
        return jsonify({'error': 'amount is required'}), 400
    
    try:
        amount = float(data['amount'])
        if amount <= 0:
            return jsonify({'error': 'Amount must be greater than 0'}), 400
        if amount != int(amount):
            return jsonify({'error': 'Amount must be a whole dollar amount'}), 400
        amount = int(amount)
    except (ValueError, TypeError):
        return jsonify({'error': 'Amount must be a number'}), 400
    
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        return jsonify({'error': 'tenant context required'}), 401

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    # Check user exists and get cash balance (tenant-scoped)
    cursor.execute('''
        SELECT user_id, cash_balance
        FROM tenant_users
        WHERE user_id = %s AND tenant_id = %s
    ''', (data['user_id'], tenant_id))
    user = cursor.fetchone()
    
    if not user:
        cursor.close()
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    
    current_cash = user.get('cash_balance') or 0.0
    if current_cash < amount:
        cursor.close()
        conn.close()
        return jsonify({'error': f'Insufficient cash balance. User has ${current_cash:.2f}.'}), 400

    # Update cash_balance (subtract amount)
    cursor.execute('''
        UPDATE tenant_users 
        SET cash_balance = cash_balance - %s 
        WHERE user_id = %s AND tenant_id = %s
    ''', (float(amount), data['user_id'], tenant_id))

    # Create transaction record for the withdrawal (tenant-scoped)
    # Store amount as negative value in tenant_transactions table
    cursor.execute('''
        INSERT INTO tenant_transactions (tenant_id, user_id, description, value, transaction_type, timestamp)
        VALUES (%s, %s, NULL, %s, 'cash_withdrawal', %s)
        RETURNING transaction_id
    ''', (tenant_id, data['user_id'], -amount, get_system_timestamp()))
    result = cursor.fetchone()
    transaction_id = result['transaction_id'] if result else None

    # Get user name for email notification (tenant-scoped)
    cursor.execute('SELECT full_name FROM tenant_users WHERE user_id = %s AND tenant_id = %s', (data['user_id'], tenant_id))
    user_result = cursor.fetchone()
    user_name = user_result.get('full_name') if user_result else 'Unknown User'
    
    conn.commit()
    cursor.close()
    conn.close()
    
    # Log cash withdrawal
    try:
        log_system_event('cash_withdrawn', f'{user_name} withdrew ${amount:.2f}', 
                        {'user_id': data['user_id'], 'user_name': user_name, 'amount': amount, 
                         'old_balance': current_cash, 'new_balance': current_cash - amount, 'transaction_id': transaction_id}, 'success')
    except Exception:
        pass  # Don't fail if logging fails
    
    # Send email notification if enabled
    send_notification_email('cash_withdrawn', user_name, f'Cash withdrawal of ${amount:.2f}', amount, data['user_id'])
    
    return jsonify({
        'transaction_id': transaction_id,
        'message': f'Successfully withdrew ${amount:.2f}',
        'new_balance': current_cash - amount
    }), 200

def get_setting(key, default):
    """Get a setting value from the database."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    result = None
    try:
        if tenant_id:
            cursor.execute('SELECT setting_value FROM tenant_settings WHERE tenant_id = %s AND setting_key = %s', (tenant_id, key))
            result = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if result and result.get('setting_value') is not None:
        if key == 'automatic_daily_cash_out':
            return result.get('setting_value') == '1'
        elif key == 'max_rollover_points':
            try:
                return int(result.get('setting_value'))
            except Exception:
                return default
        return result.get('setting_value')
    return default

def process_daily_cash_out(triggered_manually=False):
    """Process daily cash out for all users at midnight.
    
    Args:
        triggered_manually: True if triggered manually (process only active tenant), 
                           False if triggered by timer (process all tenants)
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    if triggered_manually:
        # Manual trigger: only process users for the active tenant using that tenant's settings
        tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
        if not tenant_id:
            cursor.close()
            conn.close()
            logger.warning("Manual cash out triggered without tenant context")
            return
        
        # Get settings for this specific tenant
        cursor.execute('SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = %s AND setting_key IN (%s, %s)', 
                      (tenant_id, 'automatic_daily_cash_out', 'max_rollover_points'))
        settings = cursor.fetchall()
        settings_dict = {row['setting_key']: row['setting_value'] for row in settings}
        
        automatic_cash_out = settings_dict.get('automatic_daily_cash_out', '1') == '1'
        try:
            max_rollover = int(settings_dict.get('max_rollover_points', '4'))
        except (ValueError, TypeError):
            max_rollover = 4
        
        # Get users only for this tenant
        cursor.execute('SELECT tenant_id, user_id, points_balance FROM tenant_users WHERE tenant_id = %s', (tenant_id,))
        users = cursor.fetchall()
        
        # Process users with tenant-specific settings
        for user in users:
            tenant_id_row = user.get('tenant_id')
            user_id = user.get('user_id')
            balance = user.get('points_balance') or 0

            if automatic_cash_out:
                # Convert (balance - max_rollover) to cash, keep max_rollover points
                if balance > max_rollover:
                    cash_amount = balance // 5
                    points_to_convert = cash_amount * 5
                    remainder = balance % 5
                    rollover = min(max_rollover, remainder)
                    
                    # Update cash_balance
                    cursor.execute('''
                        UPDATE tenant_users 
                        SET cash_balance = cash_balance + %s 
                        WHERE user_id = %s AND tenant_id = %s
                    ''', (cash_amount, user_id, tenant_id_row))
                    
                    # Update point balance to rollover amount
                    cursor.execute('''
                        UPDATE tenant_users 
                        SET points_balance = %s 
                        WHERE user_id = %s AND tenant_id = %s
                    ''', (rollover, user_id, tenant_id_row))
                    
                    # Create transaction record for the conversion
                    description = f'Daily cash out: Redeemed {points_to_convert} points for ${cash_amount:.2f}'
                    cursor.execute('''
                        INSERT INTO tenant_transactions (tenant_id, user_id, description, value, transaction_type, timestamp)
                        VALUES (%s, %s, %s, %s, 'points_redemption', %s)
                    ''', (tenant_id_row, user_id, description, -points_to_convert, get_system_timestamp()))
            else:
                # Just cap the balance at max_rollover if it exceeds it
                if balance > max_rollover:
                    cursor.execute('''
                        UPDATE tenant_users 
                        SET points_balance = %s 
                        WHERE user_id = %s AND tenant_id = %s
                    ''', (max_rollover, user_id, tenant_id_row))
        
        processed_count = len(users)
        
    else:
        # Automatic trigger: process all users across all tenants, each with their own settings
        # First get all unique tenants
        cursor.execute('SELECT DISTINCT tenant_id FROM tenant_users')
        all_tenants = cursor.fetchall()
        
        processed_count = 0
        
        for tenant_row in all_tenants:
            tenant_id = tenant_row.get('tenant_id')
            
            # Get settings for this tenant
            cursor.execute('SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = %s AND setting_key IN (%s, %s)', 
                          (tenant_id, 'automatic_daily_cash_out', 'max_rollover_points'))
            settings = cursor.fetchall()
            settings_dict = {row['setting_key']: row['setting_value'] for row in settings}
            
            automatic_cash_out = settings_dict.get('automatic_daily_cash_out', '1') == '1'
            try:
                max_rollover = int(settings_dict.get('max_rollover_points', '4'))
            except (ValueError, TypeError):
                max_rollover = 4
            
            # Get users for this tenant
            cursor.execute('SELECT tenant_id, user_id, points_balance FROM tenant_users WHERE tenant_id = %s', (tenant_id,))
            users = cursor.fetchall()
            
            # Process each user with this tenant's settings
            for user in users:
                tenant_id_row = user.get('tenant_id')
                user_id = user.get('user_id')
                balance = user.get('points_balance') or 0

                if automatic_cash_out:
                    # Convert (balance - max_rollover) to cash, keep max_rollover points
                    if balance > max_rollover:
                        cash_amount = balance // 5
                        points_to_convert = cash_amount * 5
                        remainder = balance % 5
                        rollover = min(max_rollover, remainder)
                        
                        # Update cash_balance
                        cursor.execute('''
                            UPDATE tenant_users 
                            SET cash_balance = cash_balance + %s 
                            WHERE user_id = %s AND tenant_id = %s
                        ''', (cash_amount, user_id, tenant_id_row))
                        
                        # Update point balance to rollover amount
                        cursor.execute('''
                            UPDATE tenant_users 
                            SET points_balance = %s 
                            WHERE user_id = %s AND tenant_id = %s
                        ''', (rollover, user_id, tenant_id_row))
                        
                        # Create transaction record for the conversion
                        description = f'Daily cash out: Redeemed {points_to_convert} points for ${cash_amount:.2f}'
                        cursor.execute('''
                            INSERT INTO tenant_transactions (tenant_id, user_id, description, value, transaction_type, timestamp)
                            VALUES (%s, %s, %s, %s, 'points_redemption', %s)
                        ''', (tenant_id_row, user_id, description, -points_to_convert, get_system_timestamp()))
                else:
                    # Just cap the balance at max_rollover if it exceeds it
                    if balance > max_rollover:
                        cursor.execute('''
                            UPDATE tenant_users 
                            SET points_balance = %s 
                            WHERE user_id = %s AND tenant_id = %s
                        ''', (max_rollover, user_id, tenant_id_row))
                
                processed_count += 1
    
    conn.commit()
    cursor.close()
    conn.close()
    
    # Log cash out processing
    try:
        trigger_type = 'manual' if triggered_manually else 'automatic (timer)'
        log_system_event('cash_out_run', f'Daily cash out processed for {processed_count} user(s) ({trigger_type})', 
                        {'user_count': processed_count, 'triggered_manually': triggered_manually, 'trigger_type': trigger_type}, 'success')
    except Exception:
        pass  # Don't fail if logging fails
    
    logger.info(f"Daily cash out processed at {datetime.now()}")




@app.route('/api/record-chore', methods=['POST'])
@kid_permission_required('kid_allowed_record_chore')
def record_chore():
    """Record a chore completion as a transaction (kids can call this if permitted)."""
    data = request.get_json() or {}

    if not data.get('user_id'):
        return jsonify({'error': 'user_id is required'}), 400
    chore_id = data.get('chore_id')

    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        return jsonify({'error': 'tenant context required'}), 401

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    description = None
    points = None

    try:
        if chore_id:
            # Lookup stored chore (tenant-scoped)
            cursor.execute('SELECT chore, point_value FROM tenant_chores WHERE chore_id = %s AND tenant_id = %s', (chore_id, tenant_id))
            chore = cursor.fetchone()
            if not chore:
                cursor.close()
                conn.close()
                return jsonify({'error': 'Chore not found'}), 404
            description = chore.get('chore')
            points = int(chore.get('point_value') or 0)
            try:
                points = int(data.get('points'))
            except (ValueError, TypeError):
                cursor.close()
                conn.close()
                return jsonify({'error': 'points must be an integer'}), 400
        else:
            cursor.close()
            conn.close()
            return jsonify({'error': 'chore_id with points is required'}), 400

        if points is None or points <= 0:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Points must be greater than 0'}), 400

        # Insert transaction and update balance (tenant-scoped)
        timestamp = get_system_timestamp()
        cursor.execute(
            'INSERT INTO tenant_transactions (tenant_id, user_id, description, value, transaction_type, timestamp) VALUES (%s, %s, %s, %s, %s, %s) RETURNING transaction_id',
            (tenant_id, data['user_id'], description, points, 'chore_completed', timestamp)
        )
        res = cursor.fetchone()
        transaction_id = res['transaction_id'] if res else None

        cursor.execute('UPDATE tenant_users SET points_balance = points_balance + %s WHERE user_id = %s AND tenant_id = %s', (points, data['user_id'], tenant_id))

        # Get user name for notification/logging (tenant-scoped)
        cursor.execute('SELECT full_name FROM tenant_users WHERE user_id = %s AND tenant_id = %s', (data['user_id'], tenant_id))
        user_result = cursor.fetchone()
        user_name = user_result.get('full_name') if user_result else 'Unknown User'

        conn.commit()
        cursor.close()
        conn.close()

        # Log and notify
        try:
            log_system_event('chore_completed', f'{user_name} completed chore', {'user_id': data['user_id'], 'description': description, 'points': points}, 'success')
        except Exception:
            pass

        try:
            send_notification_email('chore_completed', user_name, description, points, data['user_id'])
        except Exception:
            pass

        return jsonify({'transaction_id': transaction_id, 'message': f'Chore recorded: {description}', 'points': points}), 200
    except Exception as e:
        error_msg = str(e)
        try:
            log_system_event('chore_record_error', f'Error recording chore: {error_msg}', {'error': error_msg}, 'error')
        except Exception:
            pass
        try:
            cursor.close()
            conn.close()
        except Exception:
            pass
        return jsonify({'error': f'Error recording chore: {error_msg}'}), 500


@app.route('/api/redeem-points', methods=['POST'])
@kid_permission_required('kid_allowed_redeem_points')
def redeem_points():
    """Redeem points for rewards or cash (kids can call this if permitted)."""
    data = request.get_json() or {}

    if not data.get('user_id'):
        return jsonify({'error': 'user_id is required'}), 400

    # Expect positive integer 'points' to redeem
    try:
        points = int(data.get('points'))
    except (ValueError, TypeError):
        return jsonify({'error': 'points must be an integer'}), 400

    if points <= 0:
        return jsonify({'error': 'points must be greater than 0'}), 400

    redemption_type = data.get('redemption_type')  # e.g. 'money' or other
    description = data.get('description') or (f'Redemed {points} points' + (f' for {redemption_type}' if redemption_type else ''))

    tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
    if not tenant_id:
        return jsonify({'error': 'tenant context required'}), 401

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    try:
        # Verify user balance (tenant-scoped)
        cursor.execute('SELECT points_balance FROM tenant_users WHERE user_id = %s AND tenant_id = %s', (data['user_id'], tenant_id))
        user_row = cursor.fetchone()
        if not user_row:
            cursor.close()
            conn.close()
            return jsonify({'error': 'User not found'}), 404

        current_balance = int(user_row.get('points_balance') or 0)
        if current_balance < points:
            cursor.close()
            conn.close()
            return jsonify({'error': f'Insufficient points balance. User has {current_balance} points.'}), 400

        # If redeeming for money, require multiples of 5 points (5 points = $1)
        if redemption_type == 'money':
            if points % 5 != 0:
                cursor.close()
                conn.close()
                return jsonify({'error': 'Points must be a multiple of 5 to redeem for money (5 points = $1)'}), 400
            cash_amount = points // 5
            # Update cash_balance in tenant_users
            cursor.execute('UPDATE tenant_users SET cash_balance = cash_balance + %s WHERE user_id = %s AND tenant_id = %s', (float(cash_amount), data['user_id'], tenant_id))

        # Insert transaction (store negative points)
        timestamp = get_system_timestamp()
        cursor.execute(
            'INSERT INTO tenant_transactions (tenant_id, user_id, description, value, transaction_type, timestamp) VALUES (%s, %s, %s, %s, %s, %s) RETURNING transaction_id',
            (tenant_id, data['user_id'], description, -points, 'points_redemption', timestamp)
        )
        res = cursor.fetchone()
        transaction_id = res['transaction_id'] if res else None

        # Subtract points from user balance (tenant-scoped)
        cursor.execute('UPDATE tenant_users SET points_balance = points_balance - %s WHERE user_id = %s AND tenant_id = %s', (points, data['user_id'], tenant_id))

        # Get user name for notification/logging
        cursor.execute('SELECT full_name FROM tenant_users WHERE user_id = %s AND tenant_id = %s', (data['user_id'], tenant_id))
        user_result = cursor.fetchone()
        user_name = user_result.get('full_name') if user_result else 'Unknown User'

        conn.commit()
        cursor.close()
        conn.close()

        # Log and notify
        try:
            log_system_event('points_redeemed', f'{user_name} redeemed points', {'user_id': data['user_id'], 'points': points, 'redemption_type': redemption_type}, 'success')
        except Exception:
            pass

        try:
            send_notification_email('points_redeemed', user_name, description, points, data['user_id'])
        except Exception:
            pass

        return jsonify({'transaction_id': transaction_id, 'message': f'Redeemed {points} points', 'new_balance': current_balance - points}), 200
    except Exception as e:
        error_msg = str(e)
        try:
            log_system_event('redeem_points_error', f'Error redeeming points: {error_msg}', {'error': error_msg}, 'error')
        except Exception:
            pass
        try:
            cursor.close()
            conn.close()
        except Exception:
            pass
        return jsonify({'error': f'Error redeeming points: {error_msg}'}), 500

def send_daily_digest_email(triggered_manually=False):
    """Generate and send daily digest email with today's history and current balances.
    
    Args:
        triggered_manually: If True, send digest only for active tenant using that tenant's settings.
                           If False, send digests for all tenants using each tenant's settings.
    """
    
    try:
        # Get yesterday's date in local timezone (since digest triggers at midnight)
        now = datetime.now()
        yesterday = now - timedelta(days=1)
        yesterday_start = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
        yesterday_end = yesterday.replace(hour=23, minute=59, second=59, microsecond=999999)
        date_str = yesterday.strftime('%B %d, %Y')
        
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        if triggered_manually:
            # Manual trigger: only process the active tenant using that tenant's settings
            tenant_id = getattr(g, 'tenant_id', None) or request.cookies.get('tenant_id')
            if not tenant_id:
                raise ValueError('No tenant context for daily digest')
            
            # Get this tenant's email settings
            cursor.execute('SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = %s AND setting_key IN (%s, %s, %s, %s, %s, %s)', 
                          (tenant_id, 'parent_email_addresses', 'email_username', 'email_smtp_server', 'email_smtp_port', 'email_password', 'email_sender_name'))
            results = cursor.fetchall()
            settings_dict = {row['setting_key']: row['setting_value'] for row in results}
            
            parent_emails_str = settings_dict.get('parent_email_addresses', '').strip()
            if not parent_emails_str:
                cursor.close()
                conn.close()
                raise ValueError("No parent email addresses configured")
            
            parent_emails = [e.strip() for e in parent_emails_str.split(',') if e.strip()]
            if not parent_emails:
                cursor.close()
                conn.close()
                raise ValueError("No parent email addresses configured")
            
            # Get transactions and users for this tenant
            cursor.execute('''
                SELECT 
                    t.transaction_id,
                    t.user_id,
                    t.description,
                    t.value,
                    t.transaction_type,
                    t.timestamp,
                    u.full_name as user_name
                FROM tenant_transactions t
                LEFT JOIN tenant_users u ON t.user_id = u.user_id AND t.tenant_id = u.tenant_id
                WHERE t.tenant_id = %s AND t.timestamp >= %s AND t.timestamp <= %s
                ORDER BY t.timestamp DESC
            ''', (tenant_id, yesterday_start, yesterday_end))
            transactions = cursor.fetchall()

            cursor.execute('''
                SELECT 
                    u.user_id,
                    u.full_name,
                    u.points_balance as point_balance,
                    u.cash_balance
                FROM tenant_users u
                WHERE u.tenant_id = %s
                ORDER BY u.user_id
            ''', (tenant_id,))
            users = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            # Generate and send digest for this tenant
            _send_digest_for_tenant(parent_emails, transactions, users, date_str, triggered_manually, settings_dict)
        
        else:
            # Automatic trigger: process all tenants with their own settings
            cursor.execute('SELECT DISTINCT tenant_id FROM tenant_users')
            all_tenants = cursor.fetchall()
            cursor.close()
            
            for tenant_row in all_tenants:
                tenant_id = tenant_row.get('tenant_id')
                
                # Get this tenant's email settings
                conn = get_db_connection()
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                
                # Check if daily digest is enabled for this tenant
                cursor.execute('SELECT setting_value FROM tenant_settings WHERE tenant_id = %s AND setting_key = %s', (tenant_id, 'email_notify_daily_digest'))
                digest_enabled_result = cursor.fetchone()
                digest_enabled = digest_enabled_result and digest_enabled_result.get('setting_value') == '1'
                
                if not digest_enabled:
                    cursor.close()
                    conn.close()
                    continue  # Skip this tenant if daily digest is not enabled
                
                cursor.execute('SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = %s AND setting_key IN (%s, %s, %s, %s, %s, %s)', 
                              (tenant_id, 'parent_email_addresses', 'email_username', 'email_smtp_server', 'email_smtp_port', 'email_password', 'email_sender_name'))
                results = cursor.fetchall()
                settings_dict = {row['setting_key']: row['setting_value'] for row in results}
                
                parent_emails_str = settings_dict.get('parent_email_addresses', '').strip()
                if not parent_emails_str:
                    cursor.close()
                    conn.close()
                    continue  # Skip this tenant if no emails configured
                
                parent_emails = [e.strip() for e in parent_emails_str.split(',') if e.strip()]
                if not parent_emails:
                    cursor.close()
                    conn.close()
                    continue  # Skip this tenant if no valid emails
                
                # Get transactions and users for this tenant
                cursor.execute('''
                    SELECT 
                        t.transaction_id,
                        t.user_id,
                        t.description,
                        t.value,
                        t.transaction_type,
                        t.timestamp,
                        u.full_name as user_name
                    FROM tenant_transactions t
                    LEFT JOIN tenant_users u ON t.user_id = u.user_id AND t.tenant_id = u.tenant_id
                    WHERE t.tenant_id = %s AND t.timestamp >= %s AND t.timestamp <= %s
                    ORDER BY t.timestamp DESC
                ''', (tenant_id, yesterday_start, yesterday_end))
                transactions = cursor.fetchall()

                cursor.execute('''
                    SELECT 
                        u.user_id,
                        u.full_name,
                        u.points_balance as point_balance,
                        u.cash_balance
                    FROM tenant_users u
                    WHERE u.tenant_id = %s
                    ORDER BY u.user_id
                ''', (tenant_id,))
                users = cursor.fetchall()
                
                cursor.close()
                conn.close()
                
                # Generate and send digest for this tenant
                _send_digest_for_tenant(parent_emails, transactions, users, date_str, triggered_manually, settings_dict)
    
    except Exception as e:
        logger.error(f"Error sending daily digest email: {e}", exc_info=True)


def _send_digest_for_tenant(parent_emails, transactions, users, date_str, triggered_manually, settings_dict=None):
    """Helper function to generate and send digest email for a specific tenant.
    
    Args:
        parent_emails: List of email addresses to send to
        transactions: Transactions for the tenant
        users: Users for the tenant
        date_str: Formatted date string for the email
        triggered_manually: Whether this was manually triggered
        settings_dict: Optional pre-fetched email settings dict. If not provided, settings will be fetched from request context.
    """
    # Format transactions for email
    transactions_html = ""
    transactions_text = ""
    if transactions:
        for t in transactions:
            transaction_type = t.get('transaction_type', '')
            value = t.get('value', 0)
            description = t.get('description', '')
            user_name = t.get('user_name', 'Unknown')
            timestamp = t.get('timestamp')
            
            if timestamp:
                timestamp_aware = make_timezone_aware(timestamp)
                time_str = timestamp_aware.strftime('%I:%M %p')
            else:
                time_str = 'N/A'
            
            if transaction_type == 'chore_completed':
                type_label = "Chore Completed"
                value_display = f"+{value} points"
            elif transaction_type == 'points_redemption':
                type_label = "Points Redeemed"
                value_display = f"-{abs(value)} points"
            elif transaction_type == 'cash_withdrawal':
                type_label = "Cash Withdrawn"
                value_display = f"-${abs(value):.2f}"
            else:
                type_label = "Transaction"
                if value >= 0:
                    value_display = f"+{value} points"
                else:
                    value_display = f"{value} points"
            
            transactions_html += f"""
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #eee;">{time_str}</td>
                <td style="padding: 8px; border-bottom: 1px solid #eee;">{user_name}</td>
                <td style="padding: 8px; border-bottom: 1px solid #eee;">{type_label}</td>
                <td style="padding: 8px; border-bottom: 1px solid #eee;">{description}</td>
                <td style="padding: 8px; border-bottom: 1px solid #eee; text-align: right;">{value_display}</td>
            </tr>
            """
            transactions_text += f"{time_str} - {user_name}: {type_label} - {description} ({value_display})\n"
    else:
        transactions_html = "<tr><td colspan='5' style='padding: 8px; text-align: center; color: #666;'>No transactions yesterday</td></tr>"
        transactions_text = "No transactions yesterday\n"
    
    # Format user balances
    balances_html = ""
    balances_text = ""
    for user in users:
        user_name = user.get('full_name', 'Unknown')
        point_balance = user.get('point_balance', 0) or 0
        cash_balance = user.get('cash_balance', 0) or 0
        balances_html += f"""
        <tr>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">{user_name}</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee; text-align: right;">{point_balance} points</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee; text-align: right;">${cash_balance:.2f}</td>
        </tr>
        """
        balances_text += f"{user_name}: {point_balance} points, ${cash_balance:.2f}\n"
    
    # Generate email content
    subject = f"Family Chores Daily Digest - {date_str}"
    
    body_html = f"""
    <html>
      <head></head>
      <body>
        <h2>Daily Digest - {date_str}</h2>
        
        <h3>Yesterday's Activity</h3>
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
            <thead>
                <tr style="background-color: #f5f5f5;">
                    <th style="padding: 8px; text-align: left; border-bottom: 2px solid #ddd;">Time</th>
                    <th style="padding: 8px; text-align: left; border-bottom: 2px solid #ddd;">User</th>
                    <th style="padding: 8px; text-align: left; border-bottom: 2px solid #ddd;">Type</th>
                    <th style="padding: 8px; text-align: left; border-bottom: 2px solid #ddd;">Description</th>
                    <th style="padding: 8px; text-align: right; border-bottom: 2px solid #ddd;">Value</th>
                </tr>
            </thead>
            <tbody>
                {transactions_html}
            </tbody>
        </table>
        
        <h3>Current Balances</h3>
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
            <thead>
                <tr style="background-color: #f5f5f5;">
                    <th style="padding: 8px; text-align: left; border-bottom: 2px solid #ddd;">User</th>
                    <th style="padding: 8px; text-align: right; border-bottom: 2px solid #ddd;">Points</th>
                    <th style="padding: 8px; text-align: right; border-bottom: 2px solid #ddd;">Cash</th>
                </tr>
            </thead>
            <tbody>
                {balances_html}
            </tbody>
        </table>
        
        <hr>
        <p style="color: #666; font-size: 12px;">Sent from Family Chores application</p>
      </body>
    </html>
    """
    
    body_text = f"""Daily Digest - {date_str}

Yesterday's Activity:
{transactions_text}

Current Balances:
{balances_text}

Sent from Family Chores application
    """
    
    # Send email to all parent addresses
    success_count = 0
    error_messages = []
    for email in parent_emails:
        success, message = send_email(email, subject, body_html, body_text, settings_dict=settings_dict)
        if success:
            logger.info(f"Daily digest email sent to {email}")
            success_count += 1
        else:
            logger.error(f"Failed to send daily digest email to {email}: {message}")
            error_messages.append(f"{email}: {message}")
    
    # If manual send, raise exception if all failed
    if triggered_manually and success_count == 0:
        raise Exception(f"Failed to send daily digest to any address: {'; '.join(error_messages) if error_messages else 'Unknown error'}")





################################

def job_timer():
    """Background worker that runs the job timer."""
    thread_id = threading.current_thread().ident
    thread_name = threading.current_thread().name
    logger.debug(f"Job_timer worker thread started (thread_id={thread_id}, name={thread_name})")
    
    while True:
        try:
            # Automatic jobs trigger at midnight
            trigger_hour = 0
            trigger_minute = 0

            # Get current time in local system timezone
            now = datetime.now()

            jobs_to_trigger = []
            if now.hour == trigger_hour and now.minute == trigger_minute:
                jobs_to_trigger.append("cash_out")
                jobs_to_trigger.append("daily_digest")

            if "cash_out" in jobs_to_trigger:
                logger.info(f"Triggering automatic daily cash out.")
                process_daily_cash_out()
            if "daily_digest" in jobs_to_trigger:
                logger.info(f"Sending daily digest email.)")
                send_daily_digest_email()
            #if not jobs_to_trigger:
            #    logger.debug(f"No jobs to trigger at {now.strftime('%H:%M')}.")
            # Sleep for 1 minute and check again
            time_module.sleep(60)
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in job_timer: {error_msg}", exc_info=True)
            time_module.sleep(60)


def start_job_timer():
    """Start the background thread for automatic daily cash out and daily digest emails."""
    try:
        thread = threading.Thread(target=job_timer, daemon=True, name="JobTimerWorker")
        thread.start()
        logger.info("job_timer started successfully")
    except Exception as e:
        logger.error(f"Failed to start job_timer: {e}", exc_info=True)

################################

# Start the job timer for automatic daily cash out and daily digest emails
start_job_timer()


if __name__ == '__main__':    
    from init_db import init_database
    from backup_db import backup_database, delete_old_backups

    # Ensure existing database is backed up on startup
    try:
        backup_database()
    except Exception as e:
        logger.info(f"Database backup failed (this is OK if this is a new environment): {e}")

    # Delete old database backups
    try:
        delete_old_backups()
    except Exception as e:
        logger.info(f"Failed to deleted old database backups: {e}")

    # Ensure database is initialized
    try:
        init_database()
    except Exception as e:
        logger.info(f"Database initialization check failed (this is OK if tables already exist): {e}")
    
    app.run(host='0.0.0.0', port=8000, debug=False)

