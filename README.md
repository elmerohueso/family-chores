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

### Kid Role
- Can view the home page (user list)
- Can view chores list
- Can view transaction history (if enabled by parent)
- Can record chores (if enabled by parent)
- Can redeem points (if enabled by parent)
- Can withdraw cash (if enabled by parent)
- Cannot add users, chores, or access settings
- Cannot delete users or chores

### Parent Role
- Full access to all features
- Requires PIN authentication (set via `PARENT_PIN` environment variable)
- Can manage users, chores, and settings
- Can record chores, redeem points, and withdraw cash

## Quick Start

### Prerequisites
- Docker and Docker Compose installed

### Run using pre-built image
1. Download docker-compose.yml from this repository
2. Edit the environment variables, ports, and volumes as desired
3. Run `docker-compose up` from the directory housing docker-compose.yml

The application will be available at `http://localhost:8000` (or at the specified port)

### Build and run with Docker Compose
1. Clone this repository
2. Edit the environment variables, ports, and volumes in docker-compose-dev.yml as desired
3. Run `docker-compose -f .\docker-compose-dev.yml up --build` from the directory housing docker-compose-dev.yml

The application will be available at `http://localhost:8000` (or at the specified port)

#### Environment Variables
- `SECRET_KEY` - Flask secret key (default: `dev-secret-key-change-in-production`)
- `POSTGRES_HOST` - PostgreSQL hostname (default: `familychores-db`)
- `POSTGRES_DATABASE` - Database name (default: `family_chores`)
- `POSTGRES_USER` - Database user (default: `family_chores`)
- `POSTGRES_PASSWORD` - Database password (default: `family_chores`)
- `PARENT_PIN` - PIN required for Parent login (default: `1234`)
- `TZ` - Set to your local timezone (default: `America/Denver`)
- `LOG_LEVEL` - Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: `INFO`)

#### Volumes
- `db_data`: PostgreSQL data directory
- `avatar_data`: User avatar images
