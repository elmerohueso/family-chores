<#
Creates an invite token by calling POST /api/tenants/invites on the FamilyChores server.

The management key must be provided to create invites. This key should be kept secure
and only shared with trusted administrators.

Usage:
  .\scripts\create_invite.ps1 -ManagementKey "QsB7QkqVRUQzlg4P..." -MaxUses 1 -CreatedBy "admin@example.com"

  .\scripts\create_invite.ps1 -Url "https://myserver.com" -ManagementKey "..." -MaxUses 3

Notes:
 - ManagementKey: Retrieved from TENANT_CREATION_KEY environment variable or passed directly
 - MaxUses: Number of times this invite can be used (1 = single-use, 0 = unlimited)
 - Invite tokens can be shared publicly; the management key should remain secret
#>

param(
    [string]$Url = 'http://localhost:8000',
    [string]$ManagementKey = '',
    [int]$MaxUses = 1,
    [string]$ExpiresAt = '',
    [string]$AllowedEmail = '',
    [string]$Notes = '',
    [string]$CreatedBy = ''
)

# Use environment variable if management key not provided
if (-not $ManagementKey -or $ManagementKey -eq '') {
    $ManagementKey = $env:INVITE_CREATION_KEY
}

# Require management key
if (-not $ManagementKey -or $ManagementKey -eq '') {
    Write-Error "ManagementKey is required. Set INVITE_CREATION_KEY env var or pass -ManagementKey parameter."
    exit 1
}

$bodyHash = @{ max_uses = $MaxUses }
if ($ExpiresAt -and $ExpiresAt -ne '') { $bodyHash['expires_at'] = $ExpiresAt }
if ($AllowedEmail -and $AllowedEmail -ne '') { $bodyHash['allowed_email'] = $AllowedEmail }
if ($Notes -and $Notes -ne '') { $bodyHash['notes'] = $Notes }
if ($CreatedBy -and $CreatedBy -ne '') { $bodyHash['created_by'] = $CreatedBy }

$body = $bodyHash | ConvertTo-Json

$uri = ($Url.TrimEnd('/')) + '/api/tenants/invites'

Write-Host "POST $uri" -ForegroundColor Cyan
Write-Host "MaxUses: $MaxUses  AllowedEmail: $AllowedEmail  CreatedBy: $CreatedBy" -ForegroundColor Gray
try {
    $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -Headers @{ 'X-Invite-Creation-Key' = $ManagementKey } -ErrorAction Stop
    Write-Host "Invite created successfully:`n" -ForegroundColor Green
    Write-Host "Token: $($resp.token)" -ForegroundColor Yellow
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
