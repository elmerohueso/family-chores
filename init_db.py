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


def create_tenant_users_table(cursor):
    """Create tenant-scoped users table with the same columns as `user` plus `tenant_id`.

    Columns mirror the global `user` table but include a `tenant_id` UUID
    foreign key so each tenant can have its own users.
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenant_users (
            user_id SERIAL PRIMARY KEY,
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
            full_name VARCHAR(255) NOT NULL,
            balance INTEGER DEFAULT 0,
            avatar_path VARCHAR(500)
        )
    """)


def create_tenant_cash_balances_table(cursor):
    """Create tenant-scoped cash balances table mirroring `cash_balances` plus `tenant_id`.

    Uses a composite primary key (tenant_id, user_id) and references `tenant_users(user_id)`.
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenant_cash_balances (
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES tenant_users(user_id) ON DELETE CASCADE,
            cash_balance DOUBLE PRECISION DEFAULT 0.0,
            PRIMARY KEY (tenant_id, user_id)
        )
    """)


def create_tenant_transactions_table(cursor):
    """Create tenant-scoped transactions table mirroring `transactions` plus `tenant_id`.

    The `user_id` foreign key references `tenant_users(user_id)` so tenant-scoped
    transactions are tied to tenant-specific users.
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenant_transactions (
            transaction_id SERIAL PRIMARY KEY,
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL,
            description VARCHAR(255),
            value INTEGER NOT NULL,
            transaction_type VARCHAR(50),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES tenant_users(user_id)
        )
    """)


def create_tenant_roles_table(cursor):
    """Create tenant-scoped roles/permissions table if it does not exist.

    This table stores role names (e.g. 'kid', 'parent') and permission
    boolean columns. It uses a composite primary key (tenant_id, role_name)
    so the application can `ON CONFLICT` update tenant-scoped roles.
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenant_roles (
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
            role_name VARCHAR(50) NOT NULL,
            can_record_chore BOOLEAN DEFAULT FALSE,
            can_redeem_points BOOLEAN DEFAULT FALSE,
            can_withdraw_cash BOOLEAN DEFAULT FALSE,
            can_view_history BOOLEAN DEFAULT FALSE,
            PRIMARY KEY (tenant_id, role_name)
        )
    """)


def create_default_admin_if_missing(cursor):
    """Inserts the first tenant. This also migrates any existing
    global data into the new tenant-scoped tables and associates it to that tenant.

    Uses Argon2 to hash the password so the application will accept the credential format.
    If Argon2 is not available, this function will skip creating the default tenant and
    print a warning.
    """
    # Allow the default admin credentials to be configured via environment variables
    # (recommended: set these in your .env file or container environment).
    admin_name = os.environ.get('ADMIN_NAME', 'Administrator')
    admin_password = os.environ.get('ADMIN_PASSWORD', 'ChangeMe!')
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

    except Exception:
        # If chores table doesn't exist or migration fails, continue gracefully
        pass

    # Migrate global `user` rows into `tenant_users` for this Administrator tenant
    # Preserve original `user_id` values so other tables can be migrated reliably.
    try:
        cursor.execute('SELECT user_id, full_name, balance, avatar_path FROM "user"')
        all_users = cursor.fetchall()
        if all_users:
            for old_user_id, full_name, balance, avatar_path in all_users:
                try:
                    cursor.execute('''
                        INSERT INTO tenant_users (user_id, tenant_id, full_name, balance, avatar_path)
                        VALUES (%s, %s, %s, %s, %s)
                    ''', (old_user_id, tenant_id, full_name, balance, avatar_path))
                except Exception as e:
                    print(f'Warning: failed to migrate user "{full_name}" (id={old_user_id}): {e}')
            # Attempt to advance the tenant_users sequence to avoid future conflicts
            try:
                cursor.execute("SELECT MAX(user_id) FROM tenant_users")
                max_id = cursor.fetchone()[0]
                if max_id:
                    cursor.execute("SELECT setval(pg_get_serial_sequence('tenant_users', 'user_id'), %s, true)", (max_id,))
            except Exception:
                pass
    except Exception:
        # If "user" table doesn't exist or migration fails, continue gracefully
        pass

    # Migrate global `cash_balances` into `tenant_cash_balances` for this Administrator tenant
    # Do not drop the original `cash_balances` table.
    try:
        cursor.execute('SELECT user_id, cash_balance FROM cash_balances')
        all_balances = cursor.fetchall()
        if all_balances:
            for uid, cb in all_balances:
                try:
                    # Insert only if tenant_users contains this user_id (preserved above)
                    cursor.execute('''
                        INSERT INTO tenant_cash_balances (tenant_id, user_id, cash_balance)
                        VALUES (%s, %s, %s)
                    ''', (tenant_id, uid, cb))
                except Exception as e:
                    print(f'Warning: failed to migrate cash balance for user_id={uid}: {e}')
    except Exception:
        # If cash_balances doesn't exist or migration fails, continue gracefully
        pass

    # Migrate global `transactions` into `tenant_transactions` for this Administrator tenant
    # Preserve original `transaction_id` values so references remain consistent.
    try:
        cursor.execute('SELECT transaction_id, user_id, description, value, transaction_type, timestamp FROM transactions')
        all_tx = cursor.fetchall()
        if all_tx:
            for tx_id, uid, desc, val, tx_type, ts in all_tx:
                try:
                    cursor.execute('''
                        INSERT INTO tenant_transactions (transaction_id, tenant_id, user_id, description, value, transaction_type, timestamp)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ''', (tx_id, tenant_id, uid, desc, val, tx_type, ts))
                except Exception as e:
                    print(f'Warning: failed to migrate transaction id={tx_id}: {e}')
            # Advance tenant_transactions sequence to avoid collisions on future inserts
            try:
                cursor.execute("SELECT MAX(transaction_id) FROM tenant_transactions")
                max_tx = cursor.fetchone()[0]
                if max_tx:
                    cursor.execute("SELECT setval(pg_get_serial_sequence('tenant_transactions', 'transaction_id'), %s, true)", (max_tx,))
            except Exception:
                pass
    except Exception:
        # If transactions table doesn't exist or migration fails, continue gracefully
        pass

    encrypted_pin = None
    # Parent PIN can be provided via env var `PIN_VALUE`; default kept for dev convenience
    pin_value = os.environ.get('PIN_VALUE', '1234')
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
    
    # Migrate kid permission settings from tenant_settings into tenant_roles (role_name='kid')
    try:
        perm_keys = ['kid_allowed_record_chore', 'kid_allowed_redeem_points', 'kid_allowed_withdraw_cash', 'kid_allowed_view_history']

        # Only migrate if a 'kid' role does not already exist for this tenant
        cursor.execute("SELECT 1 FROM tenant_roles WHERE tenant_id = %s AND role_name = %s", (tenant_id, 'kid'))
        existing_kid = cursor.fetchone()
        if not existing_kid:
            cursor.execute("SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = %s AND setting_key = ANY(%s)", (tenant_id, perm_keys))
            perm_rows = cursor.fetchall()
            perm_map = {k: v for k, v in perm_rows} if perm_rows else {}

            def _to_bool(val):
                if val is None:
                    return False
                if isinstance(val, bool):
                    return val
                s = str(val).strip().lower()
                return s in ('1', 'true', 't', 'yes', 'y')

            can_record = _to_bool(perm_map.get('kid_allowed_record_chore'))
            can_redeem = _to_bool(perm_map.get('kid_allowed_redeem_points'))
            can_withdraw = _to_bool(perm_map.get('kid_allowed_withdraw_cash'))
            can_view = _to_bool(perm_map.get('kid_allowed_view_history'))

            # Insert kid role only when absent (so we don't reset existing permissions on rerun)
            cursor.execute('''
                INSERT INTO tenant_roles (tenant_id, role_name, can_record_chore, can_redeem_points, can_withdraw_cash, can_view_history)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, role_name) DO NOTHING
            ''', (tenant_id, 'kid', can_record, can_redeem, can_withdraw, can_view))

            # Remove the migrated permission keys from tenant_settings so they no longer
            # live in the settings table (idempotent)
            try:
                cursor.execute("DELETE FROM tenant_settings WHERE tenant_id = %s AND setting_key = ANY(%s)", (tenant_id, perm_keys))
            except Exception:
                # Don't fail the migration if cleanup fails; leave keys in settings as a fallback
                pass

        # Ensure a parent role exists with all permissions enabled for administrative purposes
        try:
            cursor.execute('''
                INSERT INTO tenant_roles (tenant_id, role_name, can_record_chore, can_redeem_points, can_withdraw_cash, can_view_history)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, role_name) DO UPDATE
                SET can_record_chore = TRUE,
                    can_redeem_points = TRUE,
                    can_withdraw_cash = TRUE,
                    can_view_history = TRUE
            ''', (tenant_id, 'parent', True, True, True, True))
        except Exception:
            # Non-fatal: don't block migration if this insert fails
            pass
    except Exception as e:
        print(f'Warning: failed to migrate kid permissions into tenant_roles for tenant {tenant_id}: {e}')
    
    # Drop foreign key constraints that reference the legacy tables, then drop the legacy tables themselves.
    try:
        legacy_tables = ['user', 'chores', 'settings', 'cash_balances', 'transactions', 'system_log']

        for legacy in legacy_tables:
            # Find foreign key constraints that reference this legacy table
            cursor.execute("""
                SELECT con.conname AS constraint_name,
                       conrel.relname AS referencing_table
                FROM pg_constraint con
                JOIN pg_class confrel ON confrel.oid = con.confrelid
                JOIN pg_class conrel ON conrel.oid = con.conrelid
                WHERE con.contype = 'f' AND confrel.relname = %s
            """, (legacy,))

            fks = cursor.fetchall()
            for constraint_name, referencing_table in fks:
                try:
                    cursor.execute(f'ALTER TABLE "{referencing_table}" DROP CONSTRAINT IF EXISTS "{constraint_name}" CASCADE')
                except Exception as e:
                    print(f'Warning: failed to drop constraint {constraint_name} on {referencing_table}: {e}')

        # Also attempt to drop any explicit constraints defined on the legacy tables themselves
        for legacy in legacy_tables:
            try:
                # Drop all constraints on the table (if present)
                cursor.execute("""
                    SELECT con.conname
                    FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    WHERE rel.relname = %s
                """, (legacy,))
                own_constraints = cursor.fetchall()
                for (conname,) in own_constraints:
                    try:
                        cursor.execute(f'ALTER TABLE "{legacy}" DROP CONSTRAINT IF EXISTS "{conname}" CASCADE')
                    except Exception as e:
                        print(f'Warning: failed to drop own constraint {conname} on {legacy}: {e}')
            except Exception:
                # If table doesn't exist or query fails, continue
                pass

        # Finally, drop the legacy tables if they exist
        for legacy in legacy_tables:
            try:
                # Quote "user" properly
                if legacy == 'user':
                    cursor.execute('DROP TABLE IF EXISTS "user" CASCADE')
                else:
                    cursor.execute(f'DROP TABLE IF EXISTS {legacy} CASCADE')
            except Exception as e:
                print(f'Warning: failed to drop table {legacy}: {e}')

    except Exception as e:
        print(f'Warning: error while removing legacy tables/constraints: {e}')


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
        create_tenant_users_table(cursor)
        create_tenant_cash_balances_table(cursor)
        create_tenant_transactions_table(cursor)
        create_tenant_roles_table(cursor)

        # Create an initial tenant if none exist
        cursor.execute("SELECT COUNT(*) FROM tenants")
        tenant_count = cursor.fetchone()[0]
        if tenant_count == 0:
            create_default_admin_if_missing(cursor)

        conn.commit()
    finally:
        conn.close()


if __name__ == '__main__':
    init_database()

