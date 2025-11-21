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
            repeat VARCHAR(50),
            last_completed TIMESTAMP
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
    
    # Add last_completed column to chores table if it doesn't exist (for existing databases)
    cursor.execute('''
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'chores' AND column_name = 'last_completed'
            ) THEN
                ALTER TABLE chores ADD COLUMN last_completed TIMESTAMP;
            END IF;
        END $$;
    ''')
    
    # Create transactions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            description VARCHAR(255),
            value INTEGER NOT NULL,
            transaction_type VARCHAR(50),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES "user"(user_id)
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
    
    # Migration: Add description column (or rename chore_name to description) and migrate data from chores table
    cursor.execute('''
        DO $$
        BEGIN
            -- If chore_name exists but description doesn't, rename it
            IF EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'transactions' AND column_name = 'chore_name'
            ) AND NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'transactions' AND column_name = 'description'
            ) THEN
                ALTER TABLE transactions RENAME COLUMN chore_name TO description;
            ELSIF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'transactions' AND column_name = 'description'
            ) THEN
                -- Add description column if it doesn't exist
                ALTER TABLE transactions ADD COLUMN description VARCHAR(255);
                
                -- Populate description from chores table for existing transactions
                UPDATE transactions t
                SET description = c.chore
                FROM chores c
                WHERE t.chore_id = c.chore_id AND t.chore_id IS NOT NULL;
            END IF;
        END $$;
    ''')
    
    # Migration: Remove chore_id foreign key constraint and column
    cursor.execute('''
        DO $$
        BEGIN
            -- Drop foreign key constraint if it exists
            IF EXISTS (
                SELECT 1 FROM information_schema.table_constraints 
                WHERE constraint_name = 'transactions_chore_id_fkey' 
                AND table_name = 'transactions'
            ) THEN
                ALTER TABLE transactions DROP CONSTRAINT transactions_chore_id_fkey;
            END IF;
            
            -- Drop chore_id column if it exists
            IF EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'transactions' AND column_name = 'chore_id'
            ) THEN
                ALTER TABLE transactions DROP COLUMN chore_id;
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
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('daily_cooldown_hours', '12')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('weekly_cooldown_days', '4')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('monthly_cooldown_days', '14')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('kid_allowed_record_chore', '0')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('kid_allowed_redeem_points', '0')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('kid_allowed_withdraw_cash', '0')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('kid_allowed_view_history', '0')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('email_smtp_server', '')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('email_smtp_port', '587')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('email_username', '')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('email_password', '')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('email_sender_name', 'Family Chores')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('email_notify_chore_completed', '0')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('email_notify_points_redeemed', '0')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('email_notify_cash_withdrawn', '0')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('parent_email_addresses', '')
        ON CONFLICT (setting_key) DO NOTHING
    ''')
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    
    print(f"Database initialized successfully!")
    print("Tables created: chores, user, transactions, cash_balances, settings")

if __name__ == '__main__':
    init_database()

