"""
init_db.py

Creates the original database schema (tables) used by the application.
This file intentionally contains only the original schema creation SQL
and does not include migration logic.
"""

import os
import psycopg2

try:
    from argon2 import PasswordHasher
    _ph = PasswordHasher()
except Exception:
    _ph = None

try:
    import base64
    import hashlib
    from cryptography.fernet import Fernet
    _fernet_available = True
except Exception:
    _fernet_available = False

# Database connection configuration from environment variables
POSTGRES_HOST = os.environ.get('POSTGRES_HOST', 'localhost')
POSTGRES_DATABASE = os.environ.get('POSTGRES_DATABASE', 'family_chores')
POSTGRES_USER = os.environ.get('POSTGRES_USER', 'family_chores')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'family_chores')
POSTGRES_PORT = os.environ.get('POSTGRES_PORT', '5432')

# Construct database connection string
DATABASE_URL = f'postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DATABASE}'


def create_tenants_table(cursor):
    """Create the `tenants` table if it does not exist."""
    # Ensure pgcrypto extension is available for gen_random_uuid()
    try:
        cursor.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    except Exception:
        # If creating the extension fails, table creation will still attempt
        # to declare a UUID default; the database may provide uuid-ossp instead.
        pass

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            tenant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_name VARCHAR(255) NOT NULL UNIQUE,
            tenant_password VARCHAR(1000) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


def create_tenant_settings_table(cursor):
    """Create the `tenant_settings` table if it does not exist.

    This table is tenant-scoped and uses a composite primary key
    (tenant_id, setting_key) so the application can `ON CONFLICT` update
    tenant-scoped settings.
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenant_settings (
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
            setting_key VARCHAR(100) NOT NULL,
            setting_value TEXT,
            PRIMARY KEY (tenant_id, setting_key)
        )
    """)


def create_refresh_tokens_table(cursor):
    """Create the `refresh_tokens` table if it does not exist.

    The application stores a SHA256 hash of the token in `token_hash` and
    records issuance/expiry and optional metadata.
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id SERIAL PRIMARY KEY,
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
            token_hash VARCHAR(255) NOT NULL,
            issued_at TIMESTAMP,
            expires_at TIMESTAMP,
            revoked BOOLEAN DEFAULT FALSE,
            user_agent VARCHAR(1000),
            ip_address VARCHAR(100)
        )
    """)


def create_tenant_chores_table(cursor):
    """Create tenant-scoped chores table with the same columns as `chores` plus `tenant_id`.

    Columns mirror the global `chores` table but include a `tenant_id` UUID
    foreign key so each tenant can have its own chore set.
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenant_chores (
            chore_id SERIAL PRIMARY KEY,
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
            chore VARCHAR(255) NOT NULL,
            point_value INTEGER NOT NULL,
            repeat VARCHAR(50),
            last_completed TIMESTAMP,
            requires_approval BOOLEAN DEFAULT FALSE
        )
    """)


def create_default_admin_if_missing(cursor):
    """Insert a default Administrator tenant with password 'ChangeMe!' if no Administrator exists.

    Uses Argon2 to hash the password so the application will accept the credential format.
    If Argon2 is not available, this function will skip creating the default tenant and
    print a warning.
    """
    admin_name = 'Administrator'
    admin_password = 'ChangeMe!'
    if _ph is None:
        print('Warning: argon2 PasswordHasher not available; skipping default tenant creation')
        return

    # Find existing tenant (case-insensitive)
    cursor.execute("SELECT tenant_id FROM tenants WHERE LOWER(tenant_name) = LOWER(%s)", (admin_name,))
    row = cursor.fetchone()
    tenant_id = None
    if row:
        tenant_id = row[0]
    else:
        # Create tenant if possible
        if _ph is None:
            print('Warning: argon2 PasswordHasher not available; skipping default tenant creation')
            return
        try:
            hashed = _ph.hash(admin_password)
            cursor.execute(
                "INSERT INTO tenants (tenant_name, tenant_password) VALUES (%s, %s) RETURNING tenant_id",
                (admin_name, hashed)
            )
            tenant_id = cursor.fetchone()[0]
        except Exception as e:
            print(f'Failed to create default Administrator tenant: {e}')
            return

    # At this point we have a tenant_id; insert or update the parent_pin in tenant_settings
    # Migrate any existing global `settings` into tenant_settings for this Administrator
    try:
        cursor.execute("SELECT setting_key, setting_value FROM settings")
        all_settings = cursor.fetchall()
        if all_settings:
            for sk, sv in all_settings:
                try:
                    cursor.execute('''
                        INSERT INTO tenant_settings (tenant_id, setting_key, setting_value)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (tenant_id, setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
                    ''', (tenant_id, sk, sv))
                except Exception as e:
                    print(f'Warning: failed to migrate setting {sk}: {e}')
            # Drop the global settings table now that values have been migrated
            try:
                cursor.execute('DROP TABLE IF EXISTS settings')
            except Exception as e:
                print(f'Warning: failed to drop settings table after migration: {e}')
    except Exception:
        # If settings table doesn't exist or migration fails, continue gracefully
        pass

    # Migrate global `chores` into `tenant_chores` for this Administrator tenant
    try:
        cursor.execute("SELECT chore, point_value, repeat, last_completed, requires_approval FROM chores")
        all_chores = cursor.fetchall()
        if all_chores:
            for chore, pv, rpt, last_completed, req_appr in all_chores:
                try:
                    cursor.execute('''
                        INSERT INTO tenant_chores (tenant_id, chore, point_value, repeat, last_completed, requires_approval)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    ''', (tenant_id, chore, pv, rpt, last_completed, req_appr))
                except Exception as e:
                    print(f'Warning: failed to migrate chore "{chore}": {e}')
            # Drop the global chores table now that values have been migrated
            try:
                cursor.execute('DROP TABLE IF EXISTS chores')
            except Exception as e:
                print(f'Warning: failed to drop chores table after migration: {e}')
    except Exception:
        # If chores table doesn't exist or migration fails, continue gracefully
        pass

    encrypted_pin = None
    pin_value = '1234'
    if _fernet_available:
        try:
            secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
            key = hashlib.sha256(secret_key.encode('utf-8')).digest()
            fernet_key = base64.urlsafe_b64encode(key)
            f = Fernet(fernet_key)
            encrypted_pin = f.encrypt(pin_value.encode('utf-8')).decode('utf-8')
        except Exception as e:
            print(f'Warning: failed to encrypt parent_pin, storing plaintext: {e}')
            encrypted_pin = pin_value
    else:
        print('Warning: cryptography.fernet not available; storing parent_pin as plaintext')
        encrypted_pin = pin_value

    try:
        cursor.execute('''
            INSERT INTO tenant_settings (tenant_id, setting_key, setting_value)
            VALUES (%s, %s, %s)
            ON CONFLICT (tenant_id, setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
        ''', (tenant_id, 'parent_pin', encrypted_pin))
    except Exception as e:
        print(f'Failed to upsert parent_pin for Administrator tenant: {e}')


def init_database():
    """Create the original database schema matching the provided SQL dump."""
    conn = psycopg2.connect(DATABASE_URL)
    try:
        cursor = conn.cursor()

        # Original `user` table (named "user" in the dump)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS "user" (
                user_id SERIAL PRIMARY KEY,
                full_name VARCHAR(255) NOT NULL,
                balance INTEGER DEFAULT 0,
                avatar_path VARCHAR(500)
            )
        """)

        # Chores table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chores (
                chore_id SERIAL PRIMARY KEY,
                chore VARCHAR(255) NOT NULL,
                point_value INTEGER NOT NULL,
                repeat VARCHAR(50),
                last_completed TIMESTAMP,
                requires_approval BOOLEAN DEFAULT FALSE
            )
        """)

        # Transactions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                description VARCHAR(255),
                value INTEGER NOT NULL,
                transaction_type VARCHAR(50),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES "user"(user_id)
            )
        """)

        # Cash balances
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cash_balances (
                user_id INTEGER PRIMARY KEY,
                cash_balance DOUBLE PRECISION DEFAULT 0.0,
                FOREIGN KEY (user_id) REFERENCES "user"(user_id)
            )
        """)

        # Settings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                setting_key VARCHAR(100) PRIMARY KEY,
                setting_value VARCHAR(255) NOT NULL
            )
        """)

        # System log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_log (
                log_id SERIAL PRIMARY KEY,
                "timestamp" TIMESTAMP,
                log_type VARCHAR(100),
                message TEXT,
                details TEXT,
                status VARCHAR(50),
                ip_address VARCHAR(50)
            )
        """)

        # Create tenants and related tables via helper functions
        create_tenants_table(cursor)
        create_tenant_settings_table(cursor)
        create_refresh_tokens_table(cursor)
        create_tenant_chores_table(cursor)

        # Ensure a default Administrator tenant exists when the tenants table is new/empty
        create_default_admin_if_missing(cursor)

        conn.commit()
    finally:
        conn.close()


if __name__ == '__main__':
    init_database()

