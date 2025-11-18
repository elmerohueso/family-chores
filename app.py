from flask import Flask, jsonify, request, render_template, send_from_directory
import sqlite3
import os
import csv
import io
from datetime import datetime, timezone
import uuid
import threading
import time as time_module

app = Flask(__name__)
# Store database in /data directory which is persisted via Docker volume
DB_DIR = '/data'
os.makedirs(DB_DIR, exist_ok=True)
DB_FILE = os.path.join(DB_DIR, 'family_chores.db')

# Avatar storage directory
AVATAR_DIR = os.path.join(DB_DIR, 'avatars')
os.makedirs(AVATAR_DIR, exist_ok=True)

# Allowed avatar file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_AVATAR_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    """Get a database connection."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
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

@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')

@app.route('/add-user')
def add_user_page():
    """Page to add a new user."""
    return render_template('add_user.html')

@app.route('/add-chore')
def add_chore_page():
    """Page to add new chores."""
    return render_template('add_chore.html')

@app.route('/users')
def users_page():
    """Page to view all users."""
    return render_template('users.html')

@app.route('/chores')
def chores_page():
    """Page to view all chores."""
    return render_template('chores.html')

@app.route('/record-chore')
def record_chore_page():
    """Page to record a completed chore."""
    return render_template('record_chore.html')

@app.route('/redeem-points')
def redeem_points_page():
    """Page to redeem points for rewards."""
    return render_template('redeem_points.html')

@app.route('/withdraw-cash')
def withdraw_cash_page():
    """Page to withdraw cash from user's cash balance."""
    return render_template('withdraw_cash.html')

# Chores endpoints
@app.route('/api/chores', methods=['GET'])
def get_chores():
    """Get all chores."""
    conn = get_db_connection()
    chores = conn.execute('SELECT * FROM chores').fetchall()
    conn.close()
    return jsonify([dict(chore) for chore in chores])

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
        updates.append('chore = ?')
        params.append(data['chore'])
    
    if point_value is not None:
        updates.append('point_value = ?')
        params.append(point_value)
    
    if 'repeat' in data:
        updates.append('repeat = ?')
        params.append(repeat_value)
    
    if not updates:
        conn.close()
        return jsonify({'error': 'No fields to update'}), 400
    
    params.append(chore_id)
    
    cursor.execute(
        f'UPDATE chores SET {", ".join(updates)} WHERE chore_id = ?',
        params
    )
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({'error': 'Chore not found'}), 404
    
    conn.commit()
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
        'INSERT INTO chores (chore, point_value, repeat) VALUES (?, ?, ?)',
        (data['chore'], point_value, repeat_value)
    )
    conn.commit()
    chore_id = cursor.lastrowid
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
                'INSERT INTO chores (chore, point_value, repeat) VALUES (?, ?, ?)',
                (chore, point_value, repeat)
            )
            imported += 1
        except Exception as e:
            errors += 1
            print(f"Error importing chore: {e}")
    
    conn.commit()
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
    users = conn.execute('''
        SELECT 
            u.user_id,
            u.full_name,
            u.balance,
            u.avatar_path,
            COALESCE(cb.cash_balance, 0.0) as cash_balance
        FROM user u
        LEFT JOIN cash_balances cb ON u.user_id = cb.user_id
    ''').fetchall()
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
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM user WHERE user_id = ?', (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    
    # Generate unique filename
    file_ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f'{user_id}_{uuid.uuid4().hex}.{file_ext}'
    filepath = os.path.join(AVATAR_DIR, filename)
    
    # Save file
    file.save(filepath)
    
    # Delete old avatar if exists
    cursor.execute('SELECT avatar_path FROM user WHERE user_id = ?', (user_id,))
    old_avatar = cursor.fetchone()
    if old_avatar and old_avatar['avatar_path']:
        old_path = os.path.join(DB_DIR, old_avatar['avatar_path'])
        if os.path.exists(old_path):
            try:
                os.remove(old_path)
            except:
                pass  # Ignore errors deleting old file
    
    # Update database
    relative_path = os.path.join('avatars', filename)
    cursor.execute('UPDATE user SET avatar_path = ? WHERE user_id = ?', (relative_path, user_id))
    conn.commit()
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
        'INSERT INTO user (full_name, balance) VALUES (?, ?)',
        (data['full_name'], data.get('balance', 0))
    )
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    return jsonify({'user_id': user_id, 'message': 'User created successfully'}), 201

# Transactions endpoints
@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    """Get all transactions with user and chore names."""
    conn = get_db_connection()
    # Join with users and chores to get names, include all transaction columns
    transactions = conn.execute('''
        SELECT 
            t.transaction_id,
            t.user_id,
            t.chore_id,
            t.value,
            t.transaction_type,
            t.timestamp,
            u.full_name as user_name,
            c.chore as chore_name
        FROM transactions t
        LEFT JOIN user u ON t.user_id = u.user_id
        LEFT JOIN chores c ON t.chore_id = c.chore_id
        ORDER BY t.timestamp DESC
    ''').fetchall()
    conn.close()
    return jsonify([dict(transaction) for transaction in transactions])

@app.route('/history')
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
    cursor = conn.cursor()
    
    # Check user balance for redemptions (negative values)
    if value < 0:
        cursor.execute('SELECT balance FROM user WHERE user_id = ?', (data['user_id'],))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        current_balance = user['balance'] or 0
        if current_balance + value < 0:
            conn.close()
            return jsonify({'error': f'Insufficient points. User has {current_balance} points.'}), 400
    
    # Determine transaction type
    transaction_type = None
    if data.get('chore_id'):
        transaction_type = 'chore_completed'
    elif data.get('redemption_type'):
        transaction_type = 'points_redemption'
    elif data.get('cash_withdrawal'):
        transaction_type = 'cash_withdrawal'
    elif value < 0:
        transaction_type = 'points_redemption'  # Default for negative values without explicit type
    
    # Insert transaction
    # Store timestamp in system timezone (local time)
    timestamp = data.get('timestamp') or get_system_timestamp()
    
    cursor.execute(
        'INSERT INTO transactions (user_id, chore_id, value, transaction_type, timestamp) VALUES (?, ?, ?, ?, ?)',
        (data['user_id'], data.get('chore_id'), value, transaction_type, timestamp)
    )
    
    # Update user balance
    cursor.execute(
        'UPDATE user SET balance = balance + ? WHERE user_id = ?',
        (value, data['user_id'])
    )
    
    # If redeeming for money (negative value and redemption_type is 'money'), update cash_balance
    redemption_type = data.get('redemption_type')
    if value < 0 and redemption_type == 'money':
        # Calculate cash amount: every 5 points = $1
        cash_amount = abs(value) / 5.0
        
        # Ensure cash_balance record exists
        cursor.execute('''
            INSERT OR IGNORE INTO cash_balances (user_id, cash_balance) 
            VALUES (?, 0.0)
        ''', (data['user_id'],))
        
        # Update cash_balance
        cursor.execute('''
            UPDATE cash_balances 
            SET cash_balance = cash_balance + ? 
            WHERE user_id = ?
        ''', (cash_amount, data['user_id']))
    
    conn.commit()
    transaction_id = cursor.lastrowid
    conn.close()
    return jsonify({'transaction_id': transaction_id, 'message': 'Transaction created successfully'}), 201

# Settings endpoints
@app.route('/settings')
def settings_page():
    """Page to view and edit settings."""
    return render_template('settings.html')

@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Get all settings."""
    conn = get_db_connection()
    settings = conn.execute('SELECT setting_key, setting_value FROM settings').fetchall()
    conn.close()
    
    settings_dict = {row['setting_key']: row['setting_value'] for row in settings}
    
    # Convert string values to appropriate types
    result = {
        'automatic_daily_cash_out': settings_dict.get('automatic_daily_cash_out', '1') == '1',
        'max_rollover_points': int(settings_dict.get('max_rollover_points', '4'))
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
            INSERT OR REPLACE INTO settings (setting_key, setting_value)
            VALUES ('automatic_daily_cash_out', ?)
        ''', (value,))
    
    if 'max_rollover_points' in data:
        try:
            max_points = int(data['max_rollover_points'])
            if max_points < 0:
                conn.close()
                return jsonify({'error': 'Max rollover points must be non-negative'}), 400
            cursor.execute('''
                INSERT OR REPLACE INTO settings (setting_key, setting_value)
                VALUES ('max_rollover_points', ?)
            ''', (str(max_points),))
        except (ValueError, TypeError):
            conn.close()
            return jsonify({'error': 'Max rollover points must be a number'}), 400
    
    conn.commit()
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
        cursor.execute('UPDATE user SET balance = 0')
        conn.commit()
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
    cursor = conn.cursor()
    
    # Check user exists and get cash balance
    cursor.execute('''
        SELECT u.user_id, COALESCE(cb.cash_balance, 0.0) as cash_balance
        FROM user u
        LEFT JOIN cash_balances cb ON u.user_id = cb.user_id
        WHERE u.user_id = ?
    ''', (data['user_id'],))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    
    current_cash = user['cash_balance'] or 0.0
    if current_cash < amount:
        conn.close()
        return jsonify({'error': f'Insufficient cash balance. User has ${current_cash:.2f}.'}), 400
    
    # Ensure cash_balance record exists
    cursor.execute('''
        INSERT OR IGNORE INTO cash_balances (user_id, cash_balance) 
        VALUES (?, 0.0)
    ''', (data['user_id'],))
    
    # Update cash_balance (subtract amount)
    cursor.execute('''
        UPDATE cash_balances 
        SET cash_balance = cash_balance - ? 
        WHERE user_id = ?
    ''', (float(amount), data['user_id']))
    
    # Create transaction record for the withdrawal
    # Store amount as negative value in transactions table (for consistency with redemptions)
    # Store timestamp in system timezone
    cursor.execute('''
        INSERT INTO transactions (user_id, chore_id, value, transaction_type, timestamp)
        VALUES (?, NULL, ?, 'cash_withdrawal', ?)
    ''', (data['user_id'], -amount, get_system_timestamp()))
    
    conn.commit()
    transaction_id = cursor.lastrowid
    conn.close()
    
    return jsonify({
        'transaction_id': transaction_id,
        'message': f'Successfully withdrew ${amount:.2f}',
        'new_balance': current_cash - amount
    }), 200

def get_setting(key, default):
    """Get a setting value from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT setting_value FROM settings WHERE setting_key = ?', (key,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        if key == 'automatic_daily_cash_out':
            return result['setting_value'] == '1'
        elif key == 'max_rollover_points':
            return int(result['setting_value'])
        return result['setting_value']
    return default

def process_daily_cash_out():
    """Process daily cash out for all users at midnight."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    automatic_cash_out = get_setting('automatic_daily_cash_out', True)
    max_rollover = get_setting('max_rollover_points', 4)
    
    # Get all users
    users = cursor.execute('SELECT user_id, balance FROM user').fetchall()
    
    for user in users:
        user_id = user['user_id']
        balance = user['balance'] or 0
        
        if automatic_cash_out:
            # Convert (balance - max_rollover) to cash, keep max_rollover points
            if balance > max_rollover:
                cash_amount = balance // 5
                points_to_convert = cash_amount * 5
                remainder = balance % 5
                rollover = min(max_rollover, remainder)
                
                # Ensure cash_balance record exists
                cursor.execute('''
                    INSERT OR IGNORE INTO cash_balances (user_id, cash_balance) 
                    VALUES (?, 0.0)
                ''', (user_id,))
                
                # Update cash_balance
                cursor.execute('''
                    UPDATE cash_balances 
                    SET cash_balance = cash_balance + ? 
                    WHERE user_id = ?
                ''', (cash_amount, user_id))
                
                # Update point balance to max_rollover
                cursor.execute('''
                    UPDATE user 
                    SET balance = ? 
                    WHERE user_id = ?
                ''', (rollover, user_id))
                
                # Create transaction record for the conversion
                # Store timestamp in system timezone
                cursor.execute('''
                    INSERT INTO transactions (user_id, chore_id, value, transaction_type, timestamp)
                    VALUES (?, NULL, ?, 'points_redemption', ?)
                ''', (user_id, -points_to_convert, get_system_timestamp()))
        else:
            # Just cap the balance at max_rollover if it exceeds it
            if balance > max_rollover:
                cursor.execute('''
                    UPDATE user 
                    SET balance = ? 
                    WHERE user_id = ?
                ''', (max_rollover, user_id))
    
    conn.commit()
    conn.close()
    print(f"Daily cash out processed at {datetime.now()}")

def daily_cash_out_worker():
    """Background worker that checks for midnight and processes daily cash out."""
    last_processed_date = None
    
    while True:
        try:
            now = datetime.now()
            current_date = now.date()
            
            # Check if it's midnight (or just past) and we haven't processed today
            if now.hour == 0 and now.minute < 5:  # 5 minute window
                if last_processed_date != current_date:
                    process_daily_cash_out()
                    last_processed_date = current_date
            
            # Sleep for 1 minute
            time_module.sleep(60)
        except Exception as e:
            print(f"Error in daily cash out worker: {e}")
            time_module.sleep(60)

def start_daily_cash_out_scheduler():
    """Start the background thread for daily cash out."""
    thread = threading.Thread(target=daily_cash_out_worker, daemon=True)
    thread.start()
    print("Daily cash out scheduler started")

if __name__ == '__main__':
    # Ensure database exists and has avatar_path column
    if not os.path.exists(DB_FILE):
        from init_db import init_database
        init_database()
    else:
        # Add avatar_path column if it doesn't exist (migration)
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        try:
            cursor.execute('ALTER TABLE user ADD COLUMN avatar_path TEXT')
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        # Create cash_balances table if it doesn't exist (migration)
        try:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cash_balances (
                    user_id INTEGER PRIMARY KEY,
                    cash_balance REAL DEFAULT 0.0,
                    FOREIGN KEY (user_id) REFERENCES user(user_id)
                )
            ''')
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Table already exists
        
        # Create settings table if it doesn't exist (migration)
        try:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL
                )
            ''')
            # Initialize default settings if they don't exist
            cursor.execute('''
                INSERT OR IGNORE INTO settings (setting_key, setting_value) 
                VALUES ('automatic_daily_cash_out', '1')
            ''')
            cursor.execute('''
                INSERT OR IGNORE INTO settings (setting_key, setting_value) 
                VALUES ('max_rollover_points', '4')
            ''')
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Table already exists
        
        # Add transaction_type column if it doesn't exist (migration)
        try:
            cursor.execute('ALTER TABLE transactions ADD COLUMN transaction_type TEXT')
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        conn.close()
    
    # Start background thread for daily cash out
    start_daily_cash_out_scheduler()
    
    app.run(host='0.0.0.0', port=8000, debug=True)

