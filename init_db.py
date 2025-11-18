import psycopg2
from psycopg2.extras import execute_values
import os
from urllib.parse import urlparse

# Database connection configuration from environment variables
POSTGRES_HOST = os.environ.get('POSTGRES_HOST', 'localhost')
POSTGRES_DATABASE = os.environ.get('POSTGRES_DATABASE', 'family_chores')
POSTGRES_USER = os.environ.get('POSTGRES_USER', 'family_chores')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'family_chores')
POSTGRES_PORT = os.environ.get('POSTGRES_PORT', '5432')

# Construct database connection string
DATABASE_URL = f'postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DATABASE}'

def init_database():
    """Initialize the PostgreSQL database with the required tables."""
    
    # Connect to database
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()
    
    # Create chores table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chores (
            chore_id SERIAL PRIMARY KEY,
            chore VARCHAR(255) NOT NULL,
            point_value INTEGER NOT NULL,
            repeat VARCHAR(50)
        )
    ''')
    
    # Create user table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS "user" (
            user_id SERIAL PRIMARY KEY,
            full_name VARCHAR(255) NOT NULL,
            balance INTEGER DEFAULT 0,
            avatar_path VARCHAR(500)
        )
    ''')
    
    # Add avatar_path column if it doesn't exist (for existing databases)
    cursor.execute('''
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'user' AND column_name = 'avatar_path'
            ) THEN
                ALTER TABLE "user" ADD COLUMN avatar_path VARCHAR(500);
            END IF;
        END $$;
    ''')
    
    # Create transactions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            chore_id INTEGER,
            value INTEGER NOT NULL,
            transaction_type VARCHAR(50),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES "user"(user_id),
            FOREIGN KEY (chore_id) REFERENCES chores(chore_id)
        )
    ''')
    
    # Add transaction_type column if it doesn't exist (for existing databases)
    cursor.execute('''
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'transactions' AND column_name = 'transaction_type'
            ) THEN
                ALTER TABLE transactions ADD COLUMN transaction_type VARCHAR(50);
            END IF;
        END $$;
    ''')
    
    # Create cash_balances table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cash_balances (
            user_id INTEGER PRIMARY KEY,
            cash_balance DOUBLE PRECISION DEFAULT 0.0,
            FOREIGN KEY (user_id) REFERENCES "user"(user_id)
        )
    ''')
    
    # Create settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            setting_key VARCHAR(100) PRIMARY KEY,
            setting_value VARCHAR(255) NOT NULL
        )
    ''')
    
    # Initialize default settings
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('automatic_daily_cash_out', '1')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('max_rollover_points', '4')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    
    print(f"Database initialized successfully!")
    print("Tables created: chores, user, transactions, cash_balances, settings")

if __name__ == '__main__':
    init_database()

