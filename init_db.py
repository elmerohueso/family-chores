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
    
    # If an old "user" table exists, rename it to family_members for clarity
    cursor.execute('''
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.tables WHERE table_name = 'user'
            ) AND NOT EXISTS (
                SELECT 1 FROM information_schema.tables WHERE table_name = 'family_members'
            ) THEN
                ALTER TABLE "user" RENAME TO family_members;
            END IF;
        END $$;
    ''')

    # Create family_members table (new name for users)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS family_members (
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
                WHERE table_name = 'family_members' AND column_name = 'avatar_path'
            ) THEN
                ALTER TABLE family_members ADD COLUMN avatar_path VARCHAR(500);
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
    
    # Add requires_approval column to chores table if it doesn't exist (for existing databases)
    cursor.execute('''
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'chores' AND column_name = 'requires_approval'
            ) THEN
                -- First check if hide_from_kids exists and rename it, otherwise add new column
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'chores' AND column_name = 'hide_from_kids'
                ) THEN
                    ALTER TABLE chores RENAME COLUMN hide_from_kids TO requires_approval;
                ELSE
                    ALTER TABLE chores ADD COLUMN requires_approval BOOLEAN DEFAULT FALSE;
                END IF;
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
            FOREIGN KEY (user_id) REFERENCES family_members(user_id)
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
            FOREIGN KEY (user_id) REFERENCES family_members(user_id)
        )
    ''')
    
    # Create roles table and seed defaults only if the table does not already exist
    cursor.execute('''
        DO $$
        BEGIN
            -- Ensure pgcrypto extension for gen_random_uuid()
            IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto') THEN
                CREATE EXTENSION pgcrypto;
            END IF;

            -- Create table and seed defaults only when table is not present
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.tables WHERE table_name = 'roles'
            ) THEN
                CREATE TABLE roles (
                    role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    role_name VARCHAR(100) NOT NULL UNIQUE,
                    can_record_chore BOOLEAN DEFAULT FALSE,
                    can_redeem_points BOOLEAN DEFAULT FALSE,
                    can_withdraw_cash BOOLEAN DEFAULT FALSE,
                    can_view_history BOOLEAN DEFAULT FALSE,
                    is_parent BOOLEAN DEFAULT FALSE
                );

                -- Seed default roles
                INSERT INTO roles (role_name, can_record_chore, can_redeem_points, can_withdraw_cash, can_view_history, is_parent)
                VALUES
                    ('parent', TRUE, TRUE, TRUE, TRUE, TRUE),
                    ('kid', FALSE, FALSE, FALSE, FALSE, FALSE);
            END IF;
        END
        $$;
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
        VALUES ('daily_cash_out_time', '00:00')
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
    
    # Migrate kid permission settings into roles table if present, then remove old keys
    cursor.execute('''
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'roles')
               AND EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'settings') THEN
                -- Only update if the 'kid' role exists
                IF EXISTS (SELECT 1 FROM roles WHERE role_name = 'kid') THEN
                    -- For each legacy setting, if present update corresponding roles column
                    IF EXISTS (SELECT 1 FROM settings WHERE setting_key = 'kid_allowed_record_chore') THEN
                        UPDATE roles
                        SET can_record_chore = (SELECT setting_value = '1' FROM settings WHERE setting_key = 'kid_allowed_record_chore')
                        WHERE role_name = 'kid';
                    END IF;

                    IF EXISTS (SELECT 1 FROM settings WHERE setting_key = 'kid_allowed_redeem_points') THEN
                        UPDATE roles
                        SET can_redeem_points = (SELECT setting_value = '1' FROM settings WHERE setting_key = 'kid_allowed_redeem_points')
                        WHERE role_name = 'kid';
                    END IF;

                    IF EXISTS (SELECT 1 FROM settings WHERE setting_key = 'kid_allowed_withdraw_cash') THEN
                        UPDATE roles
                        SET can_withdraw_cash = (SELECT setting_value = '1' FROM settings WHERE setting_key = 'kid_allowed_withdraw_cash')
                        WHERE role_name = 'kid';
                    END IF;

                    IF EXISTS (SELECT 1 FROM settings WHERE setting_key = 'kid_allowed_view_history') THEN
                        UPDATE roles
                        SET can_view_history = (SELECT setting_value = '1' FROM settings WHERE setting_key = 'kid_allowed_view_history')
                        WHERE role_name = 'kid';
                    END IF;

                    -- Remove legacy settings keys now that they're stored on roles
                    DELETE FROM settings WHERE setting_key IN (
                        'kid_allowed_record_chore',
                        'kid_allowed_redeem_points',
                        'kid_allowed_withdraw_cash',
                        'kid_allowed_view_history'
                    );
                END IF;
            END IF;
        END $$;
    ''')
    cursor.execute('''
        INSERT INTO settings (setting_key, setting_value) 
        VALUES ('email_notify_daily_digest', '0')
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

    # Create tenants table if missing and seed default tenant when newly created.
    cursor.execute("""
        SELECT EXISTS (
            SELECT 1 FROM information_schema.tables WHERE table_name = 'tenants'
        )
    """)
    tenants_exists = cursor.fetchone()[0]

    if not tenants_exists:
        # Create the table using gen_random_uuid() when available
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tenants (
                tenant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_name TEXT NOT NULL,
                tenant_password TEXT NOT NULL
            )
        ''')

        # Insert default seeded tenant with Argon2-hashed password.
        default_name = 'Change Me'
        default_password = 'Abc.123!'

        # Use Argon2 (argon2-cffi) exclusively for password hashing.
        # If argon2-cffi is not installed this will raise ImportError to surface the problem.
        from argon2 import PasswordHasher
        ph = PasswordHasher()
        hashed = ph.hash(default_password)
        cursor.execute(
            "INSERT INTO tenants (tenant_name, tenant_password) VALUES (%s, %s)",
            (default_name, hashed)
        )
    
    # Create refresh_tokens table for opaque refresh token storage
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id SERIAL PRIMARY KEY,
            tenant_id UUID REFERENCES tenants(tenant_id) ON DELETE CASCADE,
            token_hash VARCHAR(128) NOT NULL,
            issued_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            revoked BOOLEAN DEFAULT FALSE,
            user_agent TEXT,
            ip_address TEXT
        )
    ''')
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    
    print(f"Database initialized successfully!")
    print("Tables created: chores, family_members, transactions, cash_balances, settings")

if __name__ == '__main__':
    init_database()

