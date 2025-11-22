# Family Chores - User Guide

Welcome to Family Chores! This guide will help you get started and make the most of your family's chore management system.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Parent Guide](#parent-guide)
3. [Kid Guide](#kid-guide)
4. [Understanding Points and Rewards](#understanding-points-and-rewards)
5. [Settings and Configuration](#settings-and-configuration)
6. [Common Tasks](#common-tasks)
7. [Tips and Best Practices](#tips-and-best-practices)

---

## Getting Started

### First Time Setup

1. **Access the Application**
   - Open your web browser and navigate to `http://localhost:8000` (or your configured port)
   - You'll see the home page with a role selection screen

2. **Choose Your Role**
   - **Parent**: Click "Parent" and enter your PIN (default: `1234`, can be changed in environment variables)
   - **Kid**: Click "Kid" to access the kid interface

3. **Initial Setup (Parent Only)**
   - Add family members (users)
   - Create chores with point values
   - Configure settings and permissions

---

## Parent Guide

### Home Page

The home page displays all family members with their:
- **Point Balance**: Points earned from completed chores
- **Cash Balance**: Money available for withdrawal
- **Avatar**: Custom profile picture (click to change)

### Managing Users

**Add a New User:**
1. Click "Add User" button (or navigate to `/add-user`)
2. Enter the user's full name
3. Click "Add User"
4. Optionally upload an avatar image (PNG, JPG, JPEG, GIF, WEBP, max 5MB)

**Delete a User:**
1. Go to Settings
2. Scroll to "Manage Users" section
3. Click the delete button (🗑️) next to the user you want to remove
4. Confirm deletion

**Change Avatar:**
1. On the home page, click the user's avatar
2. Select a new image file
3. Click "Upload"

### Managing Chores

**Add a Chore:**
1. Click "Add Chore" button (or navigate to `/add-chore`)
2. Enter chore name (e.g., "Take out trash")
3. Set point value (how many points this chore is worth)
4. Choose repeat interval:
   - **As Needed**: Can be done anytime
   - **Daily**: Can be done once per day (with cooldown period)
   - **Weekly**: Can be done once per week (with cooldown period)
   - **Monthly**: Can be done once per month (with cooldown period)
5. Click "Add Chore"

**Edit a Chore:**
1. Go to Chores page (`/chores`)
2. Click the edit button (✏️) next to the chore
3. Modify name, point value, or repeat interval
4. Click "Save Changes"

**Delete a Chore:**
1. Go to Chores page (`/chores`)
2. Click the delete button (🗑️) next to the chore
3. Confirm deletion

**Import Chores from CSV:**
1. Go to Settings
2. Scroll to "Manage Chores" section
3. Click "Choose File" and select a CSV file
4. CSV format: `chore,point_value,repeat`
   - Example: `Take out trash,5,daily`
   - Leave repeat empty for "as_needed"
5. Click "Import Chores"

### Recording Chores

**Record a Completed Chore:**
1. Click "Record Chore" (or navigate to `/record-chore`)
2. Select the user who completed the chore
3. Select the chore from the list
   - Chores on cooldown will be grayed out and cannot be selected
4. Click "Record Chore"
5. Points are automatically added to the user's balance

### Redeeming Points

**Redeem Points for Rewards:**
1. Click "Redeem Points" (or navigate to `/redeem-points`)
2. Select the user
3. Choose redemption type:
   - **Media Time**: 5 points = 30 minutes
   - **Money**: 5 points = $1.00
4. Enter the number of points (must be a multiple of 5)
5. Click "Redeem"
6. Points are deducted and cash is added (if redeeming for money)

### Withdrawing Cash

**Withdraw Cash:**
1. Click "Withdraw Cash" (or navigate to `/withdraw-cash`)
2. Select the user
3. Enter the amount to withdraw (whole dollars only)
4. Click "Withdraw"
5. Cash balance is reduced by the withdrawal amount

### Viewing History

**Transaction History:**
1. Click "History" (or navigate to `/history`)
2. View all transactions:
   - Chore completions
   - Point redemptions
   - Cash withdrawals
3. Filter by:
   - User
   - Transaction type
   - Date range
4. Search by description

### Settings

Access Settings by clicking the ⚙️ icon in the top right corner (parent role only).

**Automatic Daily Cash Out:**
- Enable/disable automatic conversion of excess points to cash
- Set the time when cash out runs (default: midnight)
- Configure maximum rollover points (default: 4)
- Excess points above the limit are converted to cash at 5 points = $1

**Chore Cooldown Periods:**
- **Daily chores**: Hours before can be done again (default: 12 hours)
- **Weekly chores**: Days before can be done again (default: 4 days)
- **Monthly chores**: Days before can be done again (default: 14 days)

**Kid Permissions:**
Control what kids can do:
- ✅ Record Chore: Allow kids to mark chores as complete
- ✅ Redeem Points: Allow kids to redeem their points
- ✅ Withdraw Cash: Allow kids to withdraw cash
- ✅ View History: Allow kids to see transaction history

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
- Reset all points to 0
- Reset all cash balances to $0.00
- Delete all transactions
- Run one-time cash out manually

---

## Kid Guide

### Home Page

Kids can view the home page to see:
- All family members
- Point and cash balances
- User avatars

### Viewing Chores

1. Click "Chores" (or navigate to `/chores`)
2. View all available chores
3. See point values and repeat intervals
4. Chores on cooldown are shown in gray

### Recording Chores (If Enabled)

1. Click "Record Chore" (or navigate to `/record-chore`)
2. Select yourself from the user list
3. Select a chore (only available chores can be selected)
4. Click "Record Chore"
5. Points are added to your balance

### Redeeming Points (If Enabled)

1. Click "Redeem Points" (or navigate to `/redeem-points`)
2. Select yourself
3. Choose:
   - **Media Time**: 5 points = 30 minutes
   - **Money**: 5 points = $1.00
4. Enter points (multiples of 5)
5. Click "Redeem"

### Withdrawing Cash (If Enabled)

1. Click "Withdraw Cash" (or navigate to `/withdraw-cash`)
2. Select yourself
3. Enter amount (whole dollars)
4. Click "Withdraw"

### Viewing History (If Enabled)

1. Click "History" (or navigate to `/history`)
2. View your transaction history
3. Filter and search as needed

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
- Password: Your email password (encrypted in database)
- Sender Name: Name shown in email "From" field
- Parent Addresses: Comma-separated email addresses
- Notification toggles: Enable/disable specific notifications
- Daily Digest: Receive summary email at midnight

### Resetting Data

**Reset Points:**
- Sets all user point balances to 0
- Does not affect cash or transaction history

**Reset Cash:**
- Sets all user cash balances to $0.00
- Does not affect points or transaction history

**Reset Transactions:**
- Deletes all transaction history
- Does not affect current point or cash balances

**⚠️ Warning**: These actions cannot be undone!

---

## Common Tasks

### Setting Up Your Family

1. **Add Family Members:**
   - Go to "Add User"
   - Enter each family member's name
   - Upload avatars (optional)

2. **Create Chores:**
   - Go to "Add Chore"
   - Create common chores with appropriate point values
   - Set repeat intervals for recurring chores

3. **Configure Permissions:**
   - Go to Settings
   - Set kid permissions based on age and responsibility

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

1. **Review transaction history:**
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

1. **Regular Reviews**: Check transaction history weekly to ensure accuracy
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
- Check transaction history to verify the chore was recorded

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

## Support

For technical issues or questions about the application:
- Check the README.md for technical documentation
- Review the Settings page for configuration options
- Check transaction history to verify system behavior

---

**Happy Chore Managing! 🏠✨**

