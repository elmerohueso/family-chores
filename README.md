
# Family Chores

A web application for managing family chores, points, and rewards using Python and PostgreSQL.

**Now with multi-tenancy support:** The app is designed to support multiple independent families (tenants) on a single deployment, with strict data isolation and tenant-aware APIs. See tenant creation and management details below.


## Features

- **Progressive Web App (PWA)**: Install on mobile and desktop devices for app-like experience
- **Multi-Tenancy**: Host multiple independent families (tenants) in a single deployment. Each tenant's data is strictly isolated. Tenant creation is protected by a management key.
- **User Management**: Add and delete family members with customizable avatars
- **Chore Tracking**: Create, edit, and delete chores with point values and repeat intervals
- **Point System**: Track points earned from completed chores
- **Rewards**: Redeem points for media time or cash (5 points = 30 minutes OR $1)
- **Cash Management**: Track cash balances, withdrawals, and automatic conversions
- **Transaction History**: View complete history of chores, redemptions, and withdrawals with filtering
- **Role-Based Access**: Separate Kid and Parent interfaces with PIN protection
- **Kid Permissions**: Granular control over what kids can do (record chores, redeem points, withdraw cash, view history)
- **Automatic Daily Cash Out**: Configurable automatic conversion of points to cash at midnight
- **Chore Cooldown Periods**: Prevent chores from being completed too frequently (daily, weekly, monthly)
- **Email Notifications**: Receive immediate email alerts for chore completions, point redemptions, and cash withdrawals, plus optional daily digest summary
- **Settings Management**: Configure system settings, manage chores list, and reset data
- **CSV Import**: Bulk import chores from CSV files
- **Multi-Architecture**: Supports both ARM64 (Apple Silicon, Raspberry Pi) and AMD64 (Intel/AMD) architectures

#### Progressive Web App (PWA)
- **Install on Any Device**: Add to home screen on iOS/Android or install on desktop (Chrome/Edge)
- **App-like Experience**: Runs in standalone mode without browser chrome
- **Fast Loading**: Aggressive caching for instant subsequent loads
- See [INSTALL_PWA.md](INSTALL_PWA.md) for installation instructions

#### CSV Import
- Import multiple chores at once via CSV file
- CSV format: `chore,point_value,repeat`
- Null repeat values default to "as_needed"

#### Point Redemption
- Points can be redeemed in multiples of 5
- 5 points = 30 minutes of media/device time OR $1
- Redemptions are tracked in the transactions table

#### Automatic Daily Cash Out
- **Automatic Daily Cash Out**: When enabled, converts excess points to cash at a configurable time (default: midnight) in local system time
- **Cash Out Time**: Configure the time when daily cash out runs (default: midnight)
- **Max Rollover Points**: Maximum points to keep in point balance (default: 4)
- Conversion rate: 5 points = $1

#### Avatar Management
- Parents can upload custom avatars for each kid
- Supported formats: PNG, JPG, JPEG, GIF, WEBP
- Maximum file size: 5MB
- Avatars are stored persistently in Docker volume

#### Chore Cooldown Periods
- **Daily chores**: Cannot be completed again within configured hours (default: 12 hours)
- **Weekly chores**: Cannot be completed again within configured days (default: 4 days)
- **Monthly chores**: Cannot be completed again within configured days (default: 14 days)
- Chores on cooldown are visually indicated and cannot be selected

#### Email Notifications
- Configure SMTP settings for email alerts
- Receive immediate notifications for chore completions, point redemptions, and cash withdrawals
- **Daily Digest**: Receive a daily summary email at midnight with today's transaction history and current balances for all users
- Support for multiple parent email addresses
- Encrypted password storage for SMTP authentication
- Test email functionality to verify configuration
- Manual daily digest send button for testing

## User Roles
Parents have full control over what kids can access through granular permission settings.

## Quick Start

### Prerequisites
- Docker
- Docker Compose

### Run using pre-built image
1. Download docker-compose.yml from this repository
2. Edit the environment variables, ports, and volumes as desired
- Set the credentials for your initial tenant: `ADMIN_NAME`, `ADMIN_PASSWORD`, `PARENT_PIN`.
- Set a secure management key: `TENANT_CREATION_KEY`.
3. From the directory housing docker-compose.yml, run the following commands:

`docker compose up -d`

The application will be available at `http://localhost:8000` (or at the specified port)



#### Environment Variables

These variables control application security, database access, multi-tenancy, and operational settings. For multi-tenant deployments, each tenant's data is isolated, but global variables (like `TENANT_CREATION_KEY`) control tenant creation and access.

- `SECRET_KEY` — Flask session encryption and Fernet key for sensitive data (default: `dev-secret-key-change-in-production`).
- `POSTGRES_HOST` — PostgreSQL hostname (default: `familychores-db`).
- `POSTGRES_DATABASE` — Database name (default: `family_chores`).
- `POSTGRES_USER` — Database user (default: `family_chores`).
- `TZ` — Set to your local timezone (default: `America/Denver`).
- `LOG_LEVEL` — Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: `INFO`).
- `ACCESS_TOKEN_EXPIRES` — Access token lifetime in seconds (default: `900` (15 minutes)).
- `REFRESH_TOKEN_EXPIRES` — Refresh token lifetime in seconds (default: `2592000` (30 days)).

**Sensitive credentials** (store these in a `.env` file):
- `ADMIN_NAME` — Username for the first tenant.
- `ADMIN_PASSWORD` — Password for the first tenant (can be changed later within the application).
- `PARENT_PIN` — Parent PIN for the first tenant (can be changed later within the application).
- `TENANT_CREATION_KEY` — Management key used to protect the tenant-creation API.



### Multi-Tenancy and Tenant Creation

The application is designed for multi-tenancy: each family (tenant) has its own isolated data and settings. Tenant creation uses single-use invite tokens that are protected by a management key (`TENANT_CREATION_KEY`).

#### Generating a Management Key

You can generate a secure tenant creation key using Python:
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

`secrets.token_urlsafe(48)` produces a URL-safe, high-entropy token (~64 characters).

#### Creating Tenant Invites

Use the included interactive PowerShell script to create invite tokens for new tenants. The script reads `TENANT_CREATION_KEY` from the environment variable or prompts for it.

**Interactive mode (recommended):**
```powershell
./scripts/create_invite.ps1
```

The script will prompt for:
- **Server URL** (default: `http://localhost:8000`)
- **Management Key** (reads from `INVITE_CREATION_KEY` env var or prompts)
- **Creator Email** (optional, for audit trail)
- **Email Restriction** (optional, restrict invite to specific email)
- **Notes** (optional, for admin reference)
- **Custom Expiration** (optional, defaults to 7 days from now)

**Non-interactive mode (for automation):**
```powershell
./scripts/create_invite.ps1 -ManagementKey "your-key-here" -CreatedBy "admin@example.com" -NonInteractive
```

The script outputs:
- **Token**: Single-use invite token
- **Shareable URL**: Pre-filled registration link (e.g., `http://localhost:8000/create-tenant?token=xxx`)
- **Response JSON**: Full invite details (ID, expiration time, etc.)

#### Tenant Registration

New tenants complete registration by:
1. Visiting the shareable invite URL (or navigating to `/create-tenant`)
2. Entering the invite token (pre-filled if using shareable URL)
3. Choosing a unique tenant name (username, no spaces)
4. Setting a strong password (12+ chars, must include uppercase, lowercase, numbers, special characters)
5. Confirming the password
6. Setting a 4-digit parent PIN for future logins

After registration, the new tenant is redirected to the login page. All session data is cleared to ensure a fresh start.



#### Volumes
- `db_data`: PostgreSQL data directory
- `avatar_data`: User avatar images
- `backup_data`: Database backups
- `syslog_data`: System event logs

---

**Multi-tenancy note:** All features (users, chores, points, rewards, settings, history, etc.) are tenant-scoped. No data is ever shared between tenants. Tenant-aware APIs and database schema ensure strict isolation.
