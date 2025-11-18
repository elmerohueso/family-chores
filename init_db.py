import sqlite3
import os

# Database file path - use /data directory for persistence
DB_DIR = '/data'
os.makedirs(DB_DIR, exist_ok=True)
DB_FILE = os.path.join(DB_DIR, 'family_chores.db')

def init_database():
    """Initialize the SQLite database with the required tables."""
    
    # Remove existing database if it exists (for clean initialization)
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    
    # Connect to database (creates it if it doesn't exist)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create chores table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chores (
            chore_id INTEGER PRIMARY KEY AUTOINCREMENT,
            chore TEXT NOT NULL,
            point_value INTEGER NOT NULL,
            repeat TEXT
        )
    ''')
    
    # Create user table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            balance INTEGER DEFAULT 0,
            avatar_path TEXT
        )
    ''')
    
    
    # Create transactions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            chore_id INTEGER,
            value INTEGER NOT NULL,
            transaction_type TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user(user_id),
            FOREIGN KEY (chore_id) REFERENCES chores(chore_id)
        )
    ''')
    
    
    # Create cash_balances table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cash_balances (
            user_id INTEGER PRIMARY KEY,
            cash_balance REAL DEFAULT 0.0,
            FOREIGN KEY (user_id) REFERENCES user(user_id)
        )
    ''')
    
    # Create settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL
        )
    ''')
    
    # Initialize default settings
    cursor.execute('''
        INSERT OR IGNORE INTO settings (setting_key, setting_value) 
        VALUES ('automatic_daily_cash_out', '1')
    ''')
    cursor.execute('''
        INSERT OR IGNORE INTO settings (setting_key, setting_value) 
        VALUES ('max_rollover_points', '4')
    ''')
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    
    print(f"Database '{DB_FILE}' initialized successfully!")
    print("Tables created: chores, user, transactions, cash_balances, settings")

if __name__ == '__main__':
    init_database()

