from flask import Flask, jsonify, request, render_template, send_from_directory, session, redirect, url_for
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import csv
import io
from datetime import datetime, timezone
import uuid
import threading
import time as time_module
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Application version
__version__ = '0.9.5'
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

# Allowed avatar file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_AVATAR_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    """Get a database connection with dictionary cursor."""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def get_system_timestamp():
    """Get current timestamp in system timezone as ISO format string."""
    # Get current time in UTC first, then convert to system's local timezone
    # This ensures we have a timezone-aware datetime
    now_utc = datetime.now(timezone.utc)
    # Convert to system's local timezone
    now_local = now_utc.astimezone()
    # Return as ISO format string with timezone offset
    return now_local.isoformat()

def parent_required(f):
    """Decorator to require parent role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_role = session.get('user_role')
        if user_role != 'parent':
            # Redirect to index if not parent
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def kid_or_parent_required(f):
    """Decorator to require kid or parent role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_role = session.get('user_role')
        if user_role not in ['kid', 'parent']:
            # Redirect to index if no role set
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
                conn = get_db_connection()
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute('SELECT setting_value FROM settings WHERE setting_key = %s', (permission_key,))
                result = cursor.fetchone()
                cursor.close()
                conn.close()
                
                if result and result['setting_value'] == '1':
                    return f(*args, **kwargs)
                else:
                    # Permission not allowed - redirect to index
                    return redirect(url_for('index'))
            
            # No role set - redirect to index
            return redirect(url_for('index'))
        return decorated_function
    return decorator

@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')

@app.route('/api/validate-pin', methods=['POST'])
def validate_pin():
    """Validate parent PIN."""
    data = request.get_json()
    pin = data.get('pin', '')
    
    if pin == PARENT_PIN:
        session['user_role'] = 'parent'
        return jsonify({'valid': True, 'message': 'PIN validated successfully'}), 200
    else:
        return jsonify({'valid': False, 'error': 'Invalid PIN'}), 401

@app.route('/api/set-role', methods=['POST'])
def set_role():
    """Set user role (for kid login)."""
    data = request.get_json()
    role = data.get('role', '')
    
    if role == '':
        # Clear role (for logout)
        session.pop('user_role', None)
        return jsonify({'success': True, 'message': 'Role cleared'}), 200
    elif role in ['kid', 'parent']:
        session['user_role'] = role
        return jsonify({'success': True, 'message': f'Role set to {role}'}), 200
    else:
        return jsonify({'error': 'Invalid role'}), 400

@app.route('/api/get-role', methods=['GET'])
def get_role():
    """Get current user role."""
    user_role = session.get('user_role')
    return jsonify({'role': user_role}), 200

@app.route('/api/version', methods=['GET'])
def get_version():
    """Get application version and GitHub repo URL."""
    return jsonify({
        'version': __version__,
        'github_url': GITHUB_REPO_URL
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
def get_chores():
    """Get all chores."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM chores')
    chores = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([dict(chore) for chore in chores])

@app.route('/api/chores/<int:chore_id>', methods=['DELETE'])
def delete_chore(chore_id):
    """Delete a chore without affecting existing transactions."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # First, check if chore exists
        cursor.execute('SELECT chore_id FROM chores WHERE chore_id = %s', (chore_id,))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Chore not found'}), 404
        
        # Delete the chore (transactions keep their original description)
        cursor.execute('DELETE FROM chores WHERE chore_id = %s', (chore_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Chore deleted successfully'}), 200
    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return jsonify({'error': f'Error deleting chore: {str(e)}'}), 500

@app.route('/api/chores/<int:chore_id>', methods=['PUT'])
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
    cursor = conn.cursor()
    
    # Build update query dynamically based on provided fields
    updates = []
    params = []
    
    if 'chore' in data:
        updates.append('chore = %s')
        params.append(data['chore'])
    
    if point_value is not None:
        updates.append('point_value = %s')
        params.append(point_value)
    
    if 'repeat' in data:
        updates.append('"repeat" = %s')
        params.append(repeat_value)
    
    if not updates:
        cursor.close()
        conn.close()
        return jsonify({'error': 'No fields to update'}), 400
    
    params.append(chore_id)
    
    cursor.execute(
        f'UPDATE chores SET {", ".join(updates)} WHERE chore_id = %s',
        params
    )
    
    if cursor.rowcount == 0:
        cursor.close()
        conn.close()
        return jsonify({'error': 'Chore not found'}), 404
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({'message': 'Chore updated successfully'}), 200

@app.route('/api/chores', methods=['POST'])
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
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO chores (chore, point_value, "repeat") VALUES (%s, %s, %s) RETURNING chore_id',
        (data['chore'], point_value, repeat_value)
    )
    chore_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'chore_id': chore_id, 'message': 'Chore created successfully'}), 201

@app.route('/api/chores/import', methods=['POST'])
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
                'INSERT INTO chores (chore, point_value, "repeat") VALUES (%s, %s, %s)',
                (chore, point_value, repeat)
            )
            imported += 1
        except Exception as e:
            errors += 1
            print(f"Error importing chore: {e}")
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({
        'imported': imported,
        'errors': errors,
        'message': f'Imported {imported} chore(s)'
    }), 201

# User endpoints
@app.route('/api/users', methods=['GET'])
def get_users():
    """Get all users with their cash balances."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('''
        SELECT 
            u.user_id,
            u.full_name,
            u.balance,
            u.avatar_path,
            COALESCE(cb.cash_balance, 0.0) as cash_balance
        FROM "user" u
        LEFT JOIN cash_balances cb ON u.user_id = cb.user_id
        ORDER BY u.user_id
    ''')
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([dict(user) for user in users])

@app.route('/api/users/<int:user_id>/avatar', methods=['POST'])
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
    
    # Verify user exists
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT user_id FROM "user" WHERE user_id = %s', (user_id,))
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
    
    # Delete old avatar if exists
    cursor.execute('SELECT avatar_path FROM "user" WHERE user_id = %s', (user_id,))
    old_avatar = cursor.fetchone()
    if old_avatar and old_avatar.get('avatar_path'):
        old_path = os.path.join(AVATAR_DIR, os.path.basename(old_avatar['avatar_path']))
        if os.path.exists(old_path):
            try:
                os.remove(old_path)
            except:
                pass  # Ignore errors deleting old file
    
    # Update database
    relative_path = os.path.join('avatars', filename)
    cursor.execute('UPDATE "user" SET avatar_path = %s WHERE user_id = %s', (relative_path, user_id))
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({
        'avatar_path': relative_path,
        'message': 'Avatar uploaded successfully'
    }), 200

@app.route('/avatars/<path:filename>')
def serve_avatar(filename):
    """Serve avatar images."""
    return send_from_directory(AVATAR_DIR, filename)

@app.route('/api/users', methods=['POST'])
def create_user():
    """Create a new user."""
    # Handle both JSON and form data
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()
        if 'balance' in data:
            try:
                data['balance'] = int(data['balance'])
            except (ValueError, TypeError):
                data['balance'] = 0
    
    if not data.get('full_name'):
        return jsonify({'error': 'full_name is required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO "user" (full_name, balance) VALUES (%s, %s) RETURNING user_id',
        (data['full_name'], data.get('balance', 0))
    )
    user_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'user_id': user_id, 'message': 'User created successfully'}), 201

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@parent_required
def delete_user(user_id):
    """Delete a user and all associated data."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # Check if user exists
    cursor.execute('SELECT avatar_path FROM "user" WHERE user_id = %s', (user_id,))
    user = cursor.fetchone()
    if not user:
        cursor.close()
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    
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
    # cursor.execute('DELETE FROM transactions WHERE user_id = %s', (user_id,))
    cursor.execute('DELETE FROM cash_balances WHERE user_id = %s', (user_id,))
    
    # Delete user
    cursor.execute('DELETE FROM "user" WHERE user_id = %s', (user_id,))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({'message': 'User deleted successfully'}), 200

# Transactions endpoints
@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    """Get all transactions with user and chore names."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    # Join with users to get user name, description is now directly in transactions table
    cursor.execute('''
        SELECT 
            t.transaction_id,
            t.user_id,
            t.description,
            t.value,
            t.transaction_type,
            t.timestamp,
            u.full_name as user_name
        FROM transactions t
        LEFT JOIN "user" u ON t.user_id = u.user_id
        ORDER BY t.timestamp DESC
    ''')
    transactions = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([dict(transaction) for transaction in transactions])

@app.route('/history')
@kid_permission_required('kid_allowed_view_history')
def history_page():
    """Page to view transaction history."""
    return render_template('history.html')

@app.route('/api/transactions', methods=['POST'])
def create_transaction():
    """Create a new transaction."""
    data = request.get_json()
    
    # Validate required fields
    if not data.get('user_id'):
        return jsonify({'error': 'user_id is required'}), 400
    if 'value' not in data:
        return jsonify({'error': 'value is required'}), 400
    
    try:
        value = int(data['value'])
    except (ValueError, TypeError):
        return jsonify({'error': 'value must be a number'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # Check user balance for redemptions (negative values)
    if value < 0:
        cursor.execute('SELECT balance FROM "user" WHERE user_id = %s', (data['user_id'],))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        current_balance = user.get('balance') or 0
        if current_balance + value < 0:
            cursor.close()
            conn.close()
            return jsonify({'error': f'Insufficient points. User has {current_balance} points.'}), 400
    
    # Determine transaction type and get description
    transaction_type = None
    description = None
    redemption_type = data.get('redemption_type')
    
    if data.get('chore_id'):
        transaction_type = 'chore_completed'
        # Get chore name from chores table
        cursor.execute('SELECT chore FROM chores WHERE chore_id = %s', (data['chore_id'],))
        chore_result = cursor.fetchone()
        if chore_result:
            description = chore_result['chore']
        
        # Update last_completed timestamp for the chore (in local system time)
        completion_timestamp = data.get('timestamp') or get_system_timestamp()
        cursor.execute('''
            UPDATE chores 
            SET last_completed = %s 
            WHERE chore_id = %s
        ''', (completion_timestamp, data['chore_id']))
    elif data.get('chore_name'):
        transaction_type = 'chore_completed'
        description = data['chore_name']
    elif data.get('description') and not redemption_type:
        # Only use provided description if not a redemption (redemptions should generate their own)
        transaction_type = 'chore_completed'
        description = data['description']
    elif redemption_type:
        transaction_type = 'points_redemption'
        # Generate description for point redemption
        points_redeemed = abs(value)
        if redemption_type == 'money':
            dollars = points_redeemed / 5.0
            description = f'Redeemed {points_redeemed} points for ${dollars:.2f}'
        elif redemption_type == 'media':
            minutes = (points_redeemed / 5) * 30
            description = f'Redeemed {points_redeemed} points for {int(minutes)} minutes of media/device time'
        else:
            description = f'Redeemed {points_redeemed} points'
    elif data.get('cash_withdrawal'):
        transaction_type = 'cash_withdrawal'
    elif value < 0:
        # Default for negative values without explicit type or redemption_type
        transaction_type = 'points_redemption'
        points_redeemed = abs(value)
        description = f'Redeemed {points_redeemed} points'
    
    # Insert transaction
    # Store timestamp in system timezone (local time)
    timestamp = data.get('timestamp') or get_system_timestamp()
    
    cursor.execute(
        'INSERT INTO transactions (user_id, description, value, transaction_type, timestamp) VALUES (%s, %s, %s, %s, %s) RETURNING transaction_id',
        (data['user_id'], description, value, transaction_type, timestamp)
    )
    result = cursor.fetchone()
    transaction_id = result['transaction_id'] if result else None
    
    # Update user balance
    cursor.execute(
        'UPDATE "user" SET balance = balance + %s WHERE user_id = %s',
        (value, data['user_id'])
    )
    
    # If redeeming for money (negative value and redemption_type is 'money'), update cash_balance
    if value < 0 and redemption_type == 'money':
        # Calculate cash amount: every 5 points = $1
        cash_amount = abs(value) / 5.0
        
        # Ensure cash_balance record exists
        cursor.execute('''
            INSERT INTO cash_balances (user_id, cash_balance) 
            VALUES (%s, 0.0)
            ON CONFLICT (user_id) DO NOTHING
        ''', (data['user_id'],))
        
        # Update cash_balance
        cursor.execute('''
            UPDATE cash_balances 
            SET cash_balance = cash_balance + %s 
            WHERE user_id = %s
        ''', (cash_amount, data['user_id']))
    
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'transaction_id': transaction_id, 'message': 'Transaction created successfully'}), 201

# Settings endpoints
@app.route('/settings')
@parent_required
def settings_page():
    """Page to view and edit settings."""
    return render_template('settings.html')

@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Get all settings."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT setting_key, setting_value FROM settings')
    settings = cursor.fetchall()
    cursor.close()
    conn.close()
    
    settings_dict = {row['setting_key']: row['setting_value'] for row in settings}
    
    # Convert string values to appropriate types
    result = {
        'automatic_daily_cash_out': settings_dict.get('automatic_daily_cash_out', '1') == '1',
        'max_rollover_points': int(settings_dict.get('max_rollover_points', '4')),
        'daily_cooldown_hours': int(settings_dict.get('daily_cooldown_hours', '12')),
        'weekly_cooldown_days': int(settings_dict.get('weekly_cooldown_days', '4')),
        'monthly_cooldown_days': int(settings_dict.get('monthly_cooldown_days', '14')),
        'kid_allowed_record_chore': settings_dict.get('kid_allowed_record_chore', '0') == '1',
        'kid_allowed_redeem_points': settings_dict.get('kid_allowed_redeem_points', '0') == '1',
        'kid_allowed_withdraw_cash': settings_dict.get('kid_allowed_withdraw_cash', '0') == '1',
        'kid_allowed_view_history': settings_dict.get('kid_allowed_view_history', '0') == '1'
    }
    
    return jsonify(result)

@app.route('/api/settings', methods=['PUT'])
def update_settings():
    """Update settings."""
    data = request.get_json()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if 'automatic_daily_cash_out' in data:
        value = '1' if data['automatic_daily_cash_out'] else '0'
        cursor.execute('''
            INSERT INTO settings (setting_key, setting_value)
            VALUES ('automatic_daily_cash_out', %s)
            ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
        ''', (value,))
    
    if 'max_rollover_points' in data:
        try:
            max_points = int(data['max_rollover_points'])
            if max_points < 0:
                cursor.close()
                conn.close()
                return jsonify({'error': 'Max rollover points must be non-negative'}), 400
            cursor.execute('''
                INSERT INTO settings (setting_key, setting_value)
                VALUES ('max_rollover_points', %s)
                ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
            ''', (str(max_points),))
        except (ValueError, TypeError):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Max rollover points must be a number'}), 400
    
    # Handle cooldown period settings
    if 'daily_cooldown_hours' in data:
        try:
            daily_hours = int(data['daily_cooldown_hours'])
            if daily_hours < 0:
                cursor.close()
                conn.close()
                return jsonify({'error': 'Daily cooldown hours must be non-negative'}), 400
            cursor.execute('''
                INSERT INTO settings (setting_key, setting_value)
                VALUES ('daily_cooldown_hours', %s)
                ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
            ''', (str(daily_hours),))
        except (ValueError, TypeError):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Daily cooldown hours must be a number'}), 400
    
    if 'weekly_cooldown_days' in data:
        try:
            weekly_days = int(data['weekly_cooldown_days'])
            if weekly_days < 0:
                cursor.close()
                conn.close()
                return jsonify({'error': 'Weekly cooldown days must be non-negative'}), 400
            cursor.execute('''
                INSERT INTO settings (setting_key, setting_value)
                VALUES ('weekly_cooldown_days', %s)
                ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
            ''', (str(weekly_days),))
        except (ValueError, TypeError):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Weekly cooldown days must be a number'}), 400
    
    if 'monthly_cooldown_days' in data:
        try:
            monthly_days = int(data['monthly_cooldown_days'])
            if monthly_days < 0:
                cursor.close()
                conn.close()
                return jsonify({'error': 'Monthly cooldown days must be non-negative'}), 400
            cursor.execute('''
                INSERT INTO settings (setting_key, setting_value)
                VALUES ('monthly_cooldown_days', %s)
                ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
            ''', (str(monthly_days),))
        except (ValueError, TypeError):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Monthly cooldown days must be a number'}), 400
    
    # Handle kid permission settings
    if 'kid_allowed_record_chore' in data:
        value = '1' if data['kid_allowed_record_chore'] else '0'
        cursor.execute('''
            INSERT INTO settings (setting_key, setting_value)
            VALUES ('kid_allowed_record_chore', %s)
            ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
        ''', (value,))
    
    if 'kid_allowed_redeem_points' in data:
        value = '1' if data['kid_allowed_redeem_points'] else '0'
        cursor.execute('''
            INSERT INTO settings (setting_key, setting_value)
            VALUES ('kid_allowed_redeem_points', %s)
            ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
        ''', (value,))
    
    if 'kid_allowed_withdraw_cash' in data:
        value = '1' if data['kid_allowed_withdraw_cash'] else '0'
        cursor.execute('''
            INSERT INTO settings (setting_key, setting_value)
            VALUES ('kid_allowed_withdraw_cash', %s)
            ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
        ''', (value,))
    
    if 'kid_allowed_view_history' in data:
        value = '1' if data['kid_allowed_view_history'] else '0'
        cursor.execute('''
            INSERT INTO settings (setting_key, setting_value)
            VALUES ('kid_allowed_view_history', %s)
            ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
        ''', (value,))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({'message': 'Settings updated successfully'}), 200

@app.route('/api/daily-cash-out', methods=['POST'])
def manual_daily_cash_out():
    """Manually trigger daily cash out process."""
    try:
        process_daily_cash_out()
        return jsonify({'message': 'Daily cash out processed successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'Error processing daily cash out: {str(e)}'}), 500

@app.route('/api/reset-points', methods=['POST'])
def reset_points():
    """Reset all users' points balances to 0."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE "user" SET balance = 0')
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'message': 'All points balances have been reset to 0'}), 200
    except Exception as e:
        return jsonify({'error': f'Error resetting points balances: {str(e)}'}), 500

@app.route('/api/reset-cash', methods=['POST'])
def reset_cash():
    """Reset all users' cash balances to 0."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE cash_balances SET cash_balance = 0.0')
        conn.commit()
        conn.close()
        return jsonify({'message': 'All cash balances have been reset to $0.00'}), 200
    except Exception as e:
        return jsonify({'error': f'Error resetting cash balances: {str(e)}'}), 500

@app.route('/api/reset-transactions', methods=['POST'])
def reset_transactions():
    """Delete all transactions from the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM transactions')
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'message': 'All transactions have been deleted'}), 200
    except Exception as e:
        return jsonify({'error': f'Error deleting transactions: {str(e)}'}), 500

@app.route('/api/withdraw-cash', methods=['POST'])
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
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # Check user exists and get cash balance
    cursor.execute('''
        SELECT u.user_id, COALESCE(cb.cash_balance, 0.0) as cash_balance
        FROM "user" u
        LEFT JOIN cash_balances cb ON u.user_id = cb.user_id
        WHERE u.user_id = %s
    ''', (data['user_id'],))
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
    
    # Ensure cash_balance record exists
    cursor.execute('''
        INSERT INTO cash_balances (user_id, cash_balance) 
        VALUES (%s, 0.0)
        ON CONFLICT (user_id) DO NOTHING
    ''', (data['user_id'],))
    
    # Update cash_balance (subtract amount)
    cursor.execute('''
        UPDATE cash_balances 
        SET cash_balance = cash_balance - %s 
        WHERE user_id = %s
    ''', (float(amount), data['user_id']))
    
    # Create transaction record for the withdrawal
    # Store amount as negative value in transactions table (for consistency with redemptions)
    # Store timestamp in system timezone
    cursor.execute('''
        INSERT INTO transactions (user_id, description, value, transaction_type, timestamp)
        VALUES (%s, NULL, %s, 'cash_withdrawal', %s)
        RETURNING transaction_id
    ''', (data['user_id'], -amount, get_system_timestamp()))
    result = cursor.fetchone()
    transaction_id = result['transaction_id'] if result else None
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({
        'transaction_id': transaction_id,
        'message': f'Successfully withdrew ${amount:.2f}',
        'new_balance': current_cash - amount
    }), 200

def get_setting(key, default):
    """Get a setting value from the database."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT setting_value FROM settings WHERE setting_key = %s', (key,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if result:
        if key == 'automatic_daily_cash_out':
            return result.get('setting_value') == '1'
        elif key == 'max_rollover_points':
            return int(result.get('setting_value'))
        return result.get('setting_value')
    return default

def process_daily_cash_out():
    """Process daily cash out for all users at midnight."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    automatic_cash_out = get_setting('automatic_daily_cash_out', True)
    max_rollover = get_setting('max_rollover_points', 4)
    
    # Get all users
    cursor.execute('SELECT user_id, balance FROM "user"')
    users = cursor.fetchall()
    
    for user in users:
        user_id = user.get('user_id')
        balance = user.get('balance') or 0
        
        if automatic_cash_out:
            # Convert (balance - max_rollover) to cash, keep max_rollover points
            if balance > max_rollover:
                cash_amount = balance // 5
                points_to_convert = cash_amount * 5
                remainder = balance % 5
                rollover = min(max_rollover, remainder)
                
                # Ensure cash_balance record exists
                cursor.execute('''
                    INSERT INTO cash_balances (user_id, cash_balance) 
                    VALUES (%s, 0.0)
                    ON CONFLICT (user_id) DO NOTHING
                ''', (user_id,))
                
                # Update cash_balance
                cursor.execute('''
                    UPDATE cash_balances 
                    SET cash_balance = cash_balance + %s 
                    WHERE user_id = %s
                ''', (cash_amount, user_id))
                
                # Update point balance to max_rollover
                cursor.execute('''
                    UPDATE "user" 
                    SET balance = %s 
                    WHERE user_id = %s
                ''', (rollover, user_id))
                
                # Create transaction record for the conversion
                # Store timestamp in system timezone
                description = f'Daily cash out: Redeemed {points_to_convert} points for ${cash_amount:.2f}'
                cursor.execute('''
                    INSERT INTO transactions (user_id, description, value, transaction_type, timestamp)
                    VALUES (%s, %s, %s, 'points_redemption', %s)
                ''', (user_id, description, -points_to_convert, get_system_timestamp()))
        else:
            # Just cap the balance at max_rollover if it exceeds it
            if balance > max_rollover:
                cursor.execute('''
                    UPDATE "user" 
                    SET balance = %s 
                    WHERE user_id = %s
                ''', (max_rollover, user_id))
    
    conn.commit()
    cursor.close()
    conn.close()
    print(f"Daily cash out processed at {datetime.now()}")

def daily_cash_out_worker():
    """Background worker that checks for midnight and processes daily cash out."""
    last_processed_date = None
    
    print("Daily cash out worker thread started")
    
    while True:
        try:
            now = datetime.now()
            current_date = now.date()
            
            # Check if it's midnight (00:00 to 00:04) and we haven't processed today
            if now.hour == 0 and now.minute < 5:
                if last_processed_date != current_date:
                    print(f"Triggering daily cash out at {now.strftime('%Y-%m-%d %H:%M:%S')}")
                    process_daily_cash_out()
                    last_processed_date = current_date
                    print(f"Daily cash out completed for {current_date}")
            
            # Sleep for 1 minute
            time_module.sleep(60)
        except Exception as e:
            print(f"Error in daily cash out worker: {e}")
            import traceback
            traceback.print_exc()
            time_module.sleep(60)

def start_daily_cash_out_scheduler():
    """Start the background thread for daily cash out."""
    try:
        thread = threading.Thread(target=daily_cash_out_worker, daemon=True, name="DailyCashOutWorker")
        thread.start()
        print("Daily cash out scheduler started successfully")
    except Exception as e:
        print(f"Failed to start daily cash out scheduler: {e}")
        import traceback
        traceback.print_exc()

# Start the scheduler when module is imported (works in all deployment scenarios)
start_daily_cash_out_scheduler()

if __name__ == '__main__':
    # Ensure database is initialized
    from init_db import init_database
    try:
        init_database()
    except Exception as e:
        print(f"Note: Database initialization check failed (this is OK if tables already exist): {e}")
    
    app.run(host='0.0.0.0', port=8000, debug=True)

