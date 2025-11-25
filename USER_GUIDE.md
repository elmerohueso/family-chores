# Family Chores - User Guide

Welcome to Family Chores! This guide will help you get started and make the most of your family's chore management system.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Understanding Points and Rewards](#understanding-points-and-rewards)
3. [Settings and Configuration](#settings-and-configuration)
4. [Typical Usage](#typical-usage)
5. [Tips and Best Practices](#tips-and-best-practices)
6. [Troubleshooting](#troubleshooting)

---

## Getting Started

### First Time Setup

1. **Access the Application**
   - Open your web browser and navigate to `http://localhost:8000` (or your configured port)
   - You'll see the home page with a role selection screen

2. **Choose Your Role**
   - **Parent**: Click "Parent" and enter your PIN (default: `1234`, can be changed in docker-compose environment variables)
   - **Kid**: Click "Kid" to access the kid interface

3. **Initial Setup (Parent Only)**
   - Add family members (users)
   - Create chores with point values
   - Configure settings and permissions

---

## Understanding Points and Rewards

### Point System

- **Earning Points**: Complete chores to earn points
- **Point Value**: Each chore has a point value set by parents
- **Point Balance**: Tracked per user on the home page

### Redemption Options

**Media Time:**
- 5 points = 30 minutes of media/device time
- Redeem in multiples of 5 points
- Example: 15 points = 90 minutes

**Money:**
- 5 points = $1.00
- Redeem in multiples of 5 points
- Example: 25 points = $5.00
- Money is added to cash balance

### Automatic Cash Out

When enabled:
- Excess points above "Max Rollover Points" are automatically converted to cash
- Conversion happens at the configured time (default: midnight)
- Conversion rate: 5 points = $1.00
- Remaining points (up to Max Rollover) stay in point balance

**Example:**
- Max Rollover Points: 4
- User has 24 points
- At midnight: 20 points convert to $4.00, 4 points remain

### Withdrawing Cash
Parents can choose do either directly pay out, or to treat this as an expense balance. Withdrawals against this balance can be tracked within the app.

---

## Settings and Configuration

### Accessing Settings

Only parents can access settings. Click the ⚙️ icon in the top right corner when logged in as parent.

### Key Settings

**Automatic Daily Cash Out:**
- Toggle on/off
- Set cash out time (HH:MM format)
- Set maximum rollover points

**Chore Cooldowns:**
- Daily chore cooldown (hours)
- Weekly chore cooldown (days)
- Monthly chore cooldown (days)

**Kid Permissions:**
- Toggle each permission individually
- Changes take effect immediately

**Email Notifications:**
- SMTP Server: Your email provider's SMTP server
- SMTP Port: Usually 587 (TLS) or 465 (SSL)
- Username: Your email address
- Password: Your email password (stored encrypted in the database)
- Sender Name: Name that will show in the "From" field on notifications
- Parent Addresses: Email addresses for ne or more parents (comma-separated)
- Notification toggles: Enable/disable specific notifications
- Daily Digest: Receive summary email at midnight

### Resetting Data

**Reset Points:**
- Sets all user point balances to 0
- Does not affect cash or action history

**Reset Cash:**
- Sets all user cash balances to $0.00
- Does not affect points or action history

**Reset actions:**
- Deletes all action history
- Does not affect current point or cash balances

**⚠️ Warning**: These actions cannot be undone!

---

## Typical Usage

### Home Page

The home page displays all family members with their:
- **Point Balance**: Points earned from completed chores
- **Cash Balance**: Money available for withdrawal
- **Avatar**: Custom profile picture (click to change)

### Managing Users

**Add a New User:**
1. Go to Settings
2. Scroll to the "User Management" section
3. Click "Add User" button
4. Enter the user's full name
5. Set the user's initial point balance
6. Optionally, upload an avatar image (PNG, JPG, JPEG, GIF, WEBP, max 5MB)
7. Click "Add User"

**Delete a User:**
1. Go to Settings
2. Scroll to and expand the "User Management" section
3. Click the delete button (✕) next to the user you want to remove
4. Confirm deletion

**Change Avatar:**
1. On the home page, click the user's avatar
2. Select a new image file (PNG, JPG, JPEG, GIF, WEBP, max 5MB)
3. Click "Upload"

### Managing Chores

**Add a Chore Manually:**
1. Go to Settings
2. Scroll to the "Chore List" section
3. Click "Add Chore" button
4. Click the "Manual Entry" tab
5. Enter the chore name (e.g., "Take out trash")
6. Set the point value (how many points this chore is worth)
7. Choose the repeat frequency:
   - **As Needed**: Can be done anytime
   - **Daily**: Can be done once per day (with cooldown period)
   - **Weekly**: Can be done once per week (with cooldown period)
   - **Monthly**: Can be done once per month (with cooldown period)
6. Click "Add Chore"

**Import Chores from CSV:**
1. Go to Settings
2. Scroll to the "Chore List" section
3. Click "Add Chore" button
4. Click the "CSV Import" tab
5. Select the desired CSV file
5. Click "Import Chores"

**Edit a Chore:**
1. Go to Settings
2. Scroll to and expand the "Chore List" section
3. Click directly on the chore name, point value, or repeat frequency you want to edit
4. Modify the value in the edit field that appears
5. Click "Save" or press Enter to save, or "Cancel" to discard changes

**Delete a Chore:**
1. Go to Settings
2. Scroll to and expand the "Chore List" section
3. Click the delete button (✕) next to the chore
4. Confirm deletion


### Exporting Chores to CSV (Parents)

1. Go to the Chore List page
2. Click "Export CSV" button in the top-right corner
3. When prompted, select the columns you want included in the export
4. Click the "Export" button to download the CSV





### Recording Chores

**Record a Completed Chore:**
1. Click "Record a Chore" under the desired user
2. Select the chore from the list
   - Chores on cooldown will be grayed out and cannot be selected
4. Depending how well the chorse was done, change the points to give
5. Click "Record Chore"

### Redeeming Points

**Redeem Points for Rewards:**
1. Click "Redeem Points" under the desired user
2. Enter the number of points to redeem (must be a multiple of 5)
3. Choose the redemption type:
   - **Media Time**: 5 points = 30 minutes
   - **Money**: 5 points = $1.00

4 Click "Redeem Points"

### Withdrawing Cash

**Withdraw Cash:**
1. Click "Withdraw Cash" under the desired user
2. Enter the amount to withdraw (whole dollars only)
4. Click "Withdraw Cash"

### Viewing History

**Action History:**
1. Click "View History" under the desired user

### Exporting History to CSV (Parents)
1. Click "View History" under the desired user
2. Click "Export CSV" button in the top-right corner
3. When prompted, select the columns you want included in the export
4. Click the "Export" button to download the CSV

### Settings

Access Settings by clicking the ⚙️ icon in the top right corner (parent role only).

**Automatic Daily Cash Out:**
- Enable/disable automatic conversion of excess points to cash
- Set the time when cash out runs (default: midnight)
- Configure maximum rollover points (default: 4)
- Excess points above the limit are converted to cash at 5 points = $1

**Chore Cooldown Periods:**
- **Daily chores**: Hours before the chore can be done again (default: 12 hours)
- **Weekly chores**: Days before the chore can be done again (default: 4 days)
- **Monthly chores**: Days before the chore can be done again (default: 14 days)

**Kid Permissions:**
Control what kids can do:
- Record Chore: Allow kids to mark chores as complete on their own
- Redeem Points: Allow kids to redeem points on their own
- Withdraw Cash: Allow kids to withdraw cash on their own
- View History: Allow kids to see action history on their own

**Email Notifications:**
- Configure SMTP server settings
- Set up email alerts for:
  - Chore completions
  - Point redemptions
  - Cash withdrawals
  - Daily digest (summary email at midnight)
- Add parent email addresses (comma-separated)
- Test email configuration with "Send Test Email" button
- Manually send daily digest with "Send Daily Digest" button

**Data Management:**
- Reset all point balances to 0
- Reset all cash balances to $0
- Delete all action history (does not affect current balances)
- Run one-time cash out manually

### Daily Workflow

1. **Kids complete chores:**
   - Record completed chores (if permission enabled)
   - Points are automatically added

2. **Kids redeem points:**
   - Choose media time or money
   - Points are deducted, rewards are granted

3. **Automatic cash out:**
   - Runs at configured time (default: midnight)
   - Converts excess points to cash automatically

### Weekly Tasks

1. **Review action history:**
   - Check who completed what chores
   - Review point redemptions and cash withdrawals

2. **Adjust chores:**
   - Add new chores as needed
   - Edit point values if needed
   - Remove chores that are no longer relevant

### Monthly Tasks

1. **Review settings:**
   - Check cooldown periods are appropriate
   - Verify email notifications are working
   - Adjust kid permissions as children grow

---

## Tips and Best Practices

### Point Values

- **Start Simple**: Begin with lower point values (1-5 points) for easy chores
- **Value Appropriately**: More difficult or time-consuming chores should be worth more points
- **Consistency**: Keep similar chores at similar point values
- **Adjust Over Time**: Increase point values if chores aren't being completed

### Chore Management

- **Be Specific**: Use clear, specific chore names (e.g., "Take out kitchen trash" vs "Take out trash")
- **Set Appropriate Intervals**: Use daily/weekly/monthly intervals to prevent over-completion
- **Regular Updates**: Add new chores and remove outdated ones regularly
- **Use CSV Import**: Import multiple chores at once for faster setup

### Cooldown Periods

- **Daily Chores**: 12 hours prevents doing the same chore twice in one day
- **Weekly Chores**: 4 days allows flexibility while preventing abuse
- **Monthly Chores**: 14 days provides a reasonable window

### Permissions

- **Start Restrictive**: Begin with fewer permissions for younger kids
- **Gradually Increase**: Add permissions as kids demonstrate responsibility
- **Age Appropriate**: Match permissions to child's age and maturity

### Email Notifications

- **Test First**: Always use "Send Test Email" before relying on notifications
- **Daily Digest**: Great for getting a summary without constant interruptions
- **Multiple Addresses**: Add both parents' emails for better coverage

### Cash Management

- **Set Limits**: Use Max Rollover Points to encourage spending or saving
- **Automatic Conversion**: Helps prevent point hoarding
- **Manual Cash Out**: Use "Run One-Time Cash Out" button for immediate conversion

### Best Practices

1. **Regular Reviews**: Check action history weekly to ensure accuracy
2. **Clear Communication**: Explain the system to all family members
3. **Consistency**: Apply rules consistently to all kids
4. **Celebrate Success**: Acknowledge when kids complete chores and earn rewards
5. **Adjust as Needed**: Modify point values, cooldowns, and permissions based on what works for your family

---

## Troubleshooting

### Common Issues

**Chore can't be selected:**
- Check if the chore is on cooldown (will be grayed out)
- Wait for the cooldown period to expire

**Points not showing:**
- Refresh the page
- Check action history to verify the chore was recorded

**Email not working:**
- Verify SMTP settings are correct
- Use "Send Test Email" to diagnose issues
- Check spam folder

**Can't access a page:**
- Verify you're logged in with the correct role
- Check if the permission is enabled in Settings (for kids)

**Avatar not showing:**
- Check file size (max 5MB)
- Verify file format (PNG, JPG, JPEG, GIF, WEBP)
- Try uploading again

---
