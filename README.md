# Family Chores

A web application for managing family chores, points, and rewards using Python and PostgreSQL.

## Features

- **User Management**: Add family members with customizable avatars
- **Chore Tracking**: Create and manage chores with point values
- **Point System**: Track points earned from completed chores
- **Rewards**: Redeem points for media time or cash
- **Cash Management**: Track cash balances and withdrawals
- **Transaction History**: View complete history of chores, redemptions, and withdrawals
- **Role-Based Access**: Separate Kid and Parent interfaces with PIN protection
- **Automatic Daily Cash Out**: Configurable automatic conversion of points to cash at midnight
- **Settings Management**: Configure system settings and manage chores list

#### CSV Import
- Import multiple chores at once via CSV file
- CSV format: `chore,point_value,repeat`
- Null repeat values default to "as_needed"

#### Point Redemption
- Points can be redeemed in multiples of 5
- 5 points = 30 minutes of media/device time OR $1
- Redemptions are tracked in the transactions table

#### Automatic Daily Cash Out
- **Automatic Daily Cash Out**: When enabled, converts excess points to cash at midnight
- **Max Rollover Points**: Maximum points to keep in point balance (default: 4)
- Conversion rate: 5 points = $1

#### Avatar Management
- Parents can upload custom avatars for each kid
- Supported formats: PNG, JPG, JPEG, GIF, WEBP
- Maximum file size: 5MB
- Avatars are stored persistently in Docker volume

## User Roles
To prevent kids from tampering with settings or dishonestly marking chores as completed, kids have "read-only" access.

### Kid Role
- Can view the home page (user list)
- Can view chores list
- Can view transaction history
- Cannot add users, chores, or record transactions
- Cannot access settings or redeem points

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

#### Volumes
- `db_data`: PostgreSQL data directory
- `avatar_data`: User avatar images
