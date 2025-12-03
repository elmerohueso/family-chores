# Family Chores

A web application for managing family chores, points, and rewards using Python and PostgreSQL.

## Features

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
- Can manage users, chores, and settings
- Can record chores, redeem points, and withdraw cash

### New / Recent Improvements
- **CSV Export (Parent)**: Parents can now export the chores list (from the Chores page) and transaction history (History page) to CSV with a column-selection dialog. Exports respect any active filters.
- **Standardized toasts**: High-level system and network messages are shown via top-center toasts for consistent feedback across pages.
- **Layout tweak**: User cards on the Home page now use a Flexbox-based layout to stay centered (especially for 1–2 users).
- **Backend deletion order**: When deleting a user, their transactions are removed first to avoid foreign-key constraint errors.
 - **Responsive / Mobile support**: Improved handling for narrow displays (phones and small tablets).


### Prerequisites
- Docker
- Docker Compose

### Run using pre-built image
1. Download docker-compose.yml from this repository
2. Edit the environment variables, ports, and volumes as desired
3. From the directory housing docker-compose.yml, run the following commands:

`docker compose up -d`

The application will be available at `http://localhost:8000` (or at the specified port)

#### Environment Variables
- `SECRET_KEY` - Flask secret key (default: `dev-secret-key-change-in-production`)
- `POSTGRES_HOST` - PostgreSQL hostname (default: `familychores-db`)
- `POSTGRES_DATABASE` - Database name (default: `family_chores`)
- `POSTGRES_USER` - Database user (default: `family_chores`)
- `POSTGRES_PASSWORD` - Database password (default: `family_chores`)
- `PARENT_PIN` - PIN required for Parent login (default: `1234`)
- `PARENT_PIN` - PIN required for Parent login (default: `1234`). The application now prefers an encrypted `parent_pin` value stored in the `settings` table (if present) and will fall back to this environment variable only when no DB value exists or a DB read fails. Use the Settings page to update the Parent PIN (enter exactly 4 digits or leave empty to keep the existing value). Stored PINs are encrypted in the database for security.
- `TZ` - Set to your local timezone (default: `America/Denver`)
- `LOG_LEVEL` - Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: `INFO`)
- `ACCESS_TOKEN_EXPIRES` - Access token lifetime in seconds (default: `900` (15 minutes))
- `REFRESH_TOKEN_EXPIRES` - Refresh token lifetime in seconds (default: `2592000` (30 days))
- `TENANT_CREATION_KEY` - Management key used to protect the tenant-creation API (default: empty)
	You can generate a secure key using Python. Example (recommended):
### Create tenant helper script

Use the included PowerShell helper to interactively create a tenant. The script reads `TENANT_CREATION_KEY` from the environment or from a top-level `.env` file.

Interactive usage (recommended):

```powershell
.\scripts
eate_tenant.ps1
```

Override the server URL (if different):

```powershell
.\scripts
eate_tenant.ps1 -Url "http://localhost:8000"
```

Make sure `TENANT_CREATION_KEY` is set before running the script.

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

`secrets.token_urlsafe(48)` produces a URL-safe, high-entropy token (~64 characters).

#### Volumes
- `db_data`: PostgreSQL data directory
- `avatar_data`: User avatar images
- `backup_data`: Database backups
