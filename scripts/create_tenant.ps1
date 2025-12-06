<#
Creates a tenant by calling POST /api/tenants on the FamilyChores server.

Behavior:
 - Requires an invite token to create a tenant (invite-only).
 - Prompts for tenant name and password (password read securely).
 - Sends JSON { tenant_name, password, parent_pin, invite_token } to server.

Usage examples:
  # interactive (prompts for tenant name, password, parent PIN)
  .\scripts\create_tenant.ps1 -InviteToken "eyJhbGc..."

  # non-interactive
  .\scripts\create_tenant.ps1 -TenantName "acme-family" -Password "Secur3Pass!" -InviteToken "eyJhbGc..."

  # override server URL
  .\scripts\create_tenant.ps1 -Url "https://myserver.com" -InviteToken "eyJhbGc..."

Notes:
 - Invite token is required. Get one from an admin using create_invite.ps1.
#>

param(
    [string]$Url = 'http://localhost:8000',
    [string]$ParentPin = '',
    [string]$TenantName = '',
    [string]$Password = '',
    [string]$InviteToken = ''
)

# 1) Require invite token
if (-not $InviteToken -or $InviteToken -eq '') {
    Write-Error "InviteToken is required (invite-only tenant creation)"
    exit 1
}

# 2) Tenant name and password (interactive if not provided)
if (-not $TenantName -or $TenantName -eq '') {
    $TenantName = Read-Host "Tenant name"
    if (-not $TenantName) {
        Write-Error "tenant name is required"
        exit 3
    }
}
# Disallow whitespace in tenant name
if ($TenantName -match '\s') {
    Write-Error "Tenant name must not contain spaces or whitespace characters."
    exit 7
}

if (-not $Password -or $Password -eq '') {
    function ConvertTo-PlainText([System.Security.SecureString]$ss) {
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
        try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    }
    $secure = Read-Host -AsSecureString "Password (input hidden)"
    $Password = ConvertTo-PlainText $secure
}

# 3b) Prompt for Parent PIN (required 4-digit). Allow a few attempts.
if (-not $ParentPin -or $ParentPin -eq '') {
    $attempts = 0
    while ($true) {
        $ParentPin = Read-Host "Parent PIN (4 digits)"
        if ($ParentPin -match '^[0-9]{4}$') { break }
        $attempts += 1
        if ($attempts -ge 3) {
            Write-Error "Invalid Parent PIN entered too many times. Expected exactly 4 digits."
            exit 5
        }
        Write-Host "Parent PIN must be exactly 4 digits. Please try again." -ForegroundColor Yellow
    }
} else {
    if (-not ($ParentPin -match '^[0-9]{4}$')) {
        Write-Error "Provided -ParentPin must be exactly 4 digits."
        exit 6
    }
}

# 4) Build JSON body (include tenant-scoped parent_pin and invite_token)
$bodyHash = @{ tenant_name = $TenantName; password = $Password; parent_pin = $ParentPin; invite_token = $InviteToken }
$body = $bodyHash | ConvertTo-Json

# 5) Send request (no headers needed, invite token in body)
$uri = ($Url.TrimEnd('/')) + '/api/tenants'

Write-Host "POST $uri" -ForegroundColor Cyan
Write-Host "Tenant: $TenantName  ParentPin: **** (masked)  InviteToken: **** (masked)" -ForegroundColor Gray
try {
    $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop
    Write-Host "Tenant created successfully:`n" -ForegroundColor Green
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
    exit 4
}
