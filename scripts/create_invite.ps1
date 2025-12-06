<#
Creates an invite token by calling POST /api/tenants/invites on the FamilyChores server.

The management key must be provided to create invites. This key should be kept secure
and only shared with trusted administrators.

Interactive Mode (default):
  .\scripts\create_invite.ps1
  Prompts for all required and optional parameters.

Command-line Mode:
  .\scripts\create_invite.ps1 -Url "http://localhost:8000" -ManagementKey "QsB7QkqVRUQzlg4P..." -CreatedBy "admin@example.com"

Notes:
 - ManagementKey: Retrieved from INVITE_CREATION_KEY environment variable or prompted interactively
 - All invites are single-use
 - Invite tokens can be shared publicly; the management key should remain secret
#>

param(
    # Base URL of the FamilyChores server (default: http://localhost:8000)
    [string]$Url = '',
    
    # Management key for creating invites (reads INVITE_CREATION_KEY env var if not provided)
    [string]$ManagementKey = '',
    
    # Optional: ISO8601 expiration date/time for the invite (e.g., "2024-12-31T23:59:59Z")
    [string]$ExpiresAt = '',
    
    # Optional: Restrict this invite to a specific email address
    [string]$AllowedEmail = '',
    
    # Optional: Notes about the invite (for admin reference)
    [string]$Notes = '',
    
    # Optional: Who created this invite (for audit trail)
    [string]$CreatedBy = '',
    
    # Switch to skip interactive mode if any parameters are provided
    [switch]$NonInteractive
)

# Determine if running in interactive mode (no params provided)
$IsInteractive = -not ($PSBoundParameters.Count -gt 0 -or $NonInteractive)

# Interactive mode
if ($IsInteractive) {
    Write-Host "=== Create Family Chores Invite ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Prompt for URL
    $defaultUrl = 'http://localhost:8000'
    $Url = Read-Host "Enter server URL (default: $defaultUrl)"
    if (-not $Url -or $Url -eq '') {
        $Url = $defaultUrl
    }
    
    # Prompt for management key
    Write-Host ""
    $env_key = $env:INVITE_CREATION_KEY
    if ($env_key) {
        Write-Host "Management key found in INVITE_CREATION_KEY environment variable." -ForegroundColor Green
        $use_env = Read-Host "Use it? (Y/n)"
        if ($use_env -ne 'n' -and $use_env -ne 'N') {
            $ManagementKey = $env_key
        } else {
            $ManagementKey = Read-Host "Enter management key"
        }
    } else {
        $ManagementKey = Read-Host "Enter management key"
    }
    
    # Prompt for optional parameters
    Write-Host ""
    Write-Host "Optional parameters (press Enter to skip):" -ForegroundColor Gray
    
    $CreatedBy = Read-Host "Who created this invite? (e.g., admin@example.com)"
    $AllowedEmail = Read-Host "Restrict to email address? (leave empty for no restriction)"
    $Notes = Read-Host "Notes about this invite? (for admin reference)"
    
    # Ask about custom expiration
    Write-Host ""
    $custom_exp = Read-Host "Set custom expiration date? (y/N) (No to default 7 days)"
    if ($custom_exp -eq 'y' -or $custom_exp -eq 'Y') {
        Write-Host "Enter date/time (ISO8601 format, e.g., 2024-12-25T23:59:59Z):" -ForegroundColor Gray
        $ExpiresAt = Read-Host "Expiration"
    }
}

# Set defaults for non-interactive mode
if (-not $Url -or $Url -eq '') {
    $Url = 'http://localhost:8000'
}

# Use environment variable if management key not provided
if (-not $ManagementKey -or $ManagementKey -eq '') {
    $ManagementKey = $env:INVITE_CREATION_KEY
}

# Set default expiration to 7 days from now if not provided
if (-not $ExpiresAt -or $ExpiresAt -eq '') {
    $ExpiresAt = (Get-Date).AddDays(7).ToUniversalTime().ToString('o')
}

# Require management key
if (-not $ManagementKey -or $ManagementKey -eq '') {
    Write-Error "ManagementKey is required. Set INVITE_CREATION_KEY env var or provide -ManagementKey parameter."
    exit 1
}

$bodyHash = @{}
if ($ExpiresAt -and $ExpiresAt -ne '') { $bodyHash['expires_at'] = $ExpiresAt }
if ($AllowedEmail -and $AllowedEmail -ne '') { $bodyHash['allowed_email'] = $AllowedEmail }
if ($Notes -and $Notes -ne '') { $bodyHash['notes'] = $Notes }
if ($CreatedBy -and $CreatedBy -ne '') { $bodyHash['created_by'] = $CreatedBy }

$body = $bodyHash | ConvertTo-Json

$uri = ($Url.TrimEnd('/')) + '/api/tenants/invites'

Write-Host "POST $uri" -ForegroundColor Cyan
Write-Host "Single-use invite" -ForegroundColor Gray
try {
    $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -Headers @{ 'X-Invite-Creation-Key' = $ManagementKey } -ErrorAction Stop
    Write-Host "Invite created successfully:" -ForegroundColor Green
    Write-Host ""
    Write-Host "Token: $($resp.token)" -ForegroundColor Yellow
    
    # Build shareable URL
    $baseUrl = $Url.TrimEnd('/')
    $shareUrl = "$baseUrl/create-tenant?token=$($resp.token)"
    Write-Host "`nShareable URL:" -ForegroundColor Cyan
    Write-Host $shareUrl -ForegroundColor Yellow
    
    Write-Host ""
    $resp | ConvertTo-Json -Depth 5 | Write-Host
    exit 0
} catch {
    $err = $_.Exception
    if ($err.Response -ne $null) {
        try {
            $status = $err.Response.StatusCode.Value__ 2>$null
        } catch {
            $status = $null
        }
        try {
            $sr = New-Object System.IO.StreamReader($err.Response.GetResponseStream())
            $text = $sr.ReadToEnd()
            $sr.Close()
            if ($status) { Write-Error "Request failed: HTTP $status`n$text" } else { Write-Error "Request failed:`n$text" }
        } catch {
            Write-Error "Request failed: $($err.Message)"
        }
    } else {
        Write-Error "Request failed: $($_.Exception.Message)"
    }
    exit 2
}
