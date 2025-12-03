<#
Creates a tenant by calling POST /api/tenants on the FamilyChores server.

Behavior:
 - Reads TENANT_CREATION_KEY from environment or from a top-level `.env` file.
 - Prompts for tenant name and password (password read securely).
 - Sends JSON { tenant_name, password } with header `X-Tenant-Creation-Key`.

Usage examples:
  # interactive
  .\scripts\create_tenant.ps1

  # non-interactive (insecure password on command line)
  .\scripts\create_tenant.ps1 -TenantName "acme-family" -Password "Secur3Pass!"

  # override server URL
  .\scripts\create_tenant.ps1 -Url "http://localhost:8000"

Notes:
 - Make sure TENANT_CREATION_KEY is set in the environment or present in `.env` at the repo root.
 - Do not commit secrets to source control.
#>

param(
    [string]$Url = 'http://localhost:8000',
    [string]$ParentPin = ''
)

function Read-EnvFile([string]$path) {
    if (-not (Test-Path $path)) { return @{} }
    $pairs = @{}
    foreach ($line in Get-Content $path -ErrorAction SilentlyContinue) {
        $trim = $line.Trim()
        if ($trim -eq '' -or $trim.StartsWith('#')) { continue }
        # split on first = only
        $idx = $trim.IndexOf('=')
        if ($idx -lt 0) { continue }
        $k = $trim.Substring(0,$idx).Trim()
        $v = $trim.Substring($idx+1).Trim()
        # Remove surrounding quotes if present
        if (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))) {
            $v = $v.Substring(1,$v.Length-2)
        }
        $pairs[$k] = $v
    }
    return $pairs
}

# 1) Locate management key
$key = $env:TENANT_CREATION_KEY
if (-not $key -or $key -eq '') {
    # Try to find .env in repo root relative to script location
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $repoRoot = Resolve-Path (Join-Path $scriptDir "..")
    $envPath = Join-Path $repoRoot '.env'
    if (-not (Test-Path $envPath)) {
        # Also check current directory as fallback
        $envPath = Join-Path (Get-Location) '.env'
    }
    $envVars = Read-EnvFile $envPath
    if ($envVars.ContainsKey('TENANT_CREATION_KEY')) { $key = $envVars['TENANT_CREATION_KEY'] }
}

if (-not $key -or $key -eq '') {
    Write-Error "TENANT_CREATION_KEY not found in environment or .env. Set the env var or add TENANT_CREATION_KEY to .env to enable tenant creation."
    exit 2
}

# 2) Prompt for tenant name and password (interactive)
$TenantName = Read-Host "Tenant name"
if (-not $TenantName) {
    Write-Error "tenant name is required"
    exit 3
}
# Disallow whitespace in tenant name
if ($TenantName -match '\s') {
    Write-Error "Tenant name must not contain spaces or whitespace characters."
    exit 7
}

# 3) Get password (secure)
function ConvertTo-PlainText([System.Security.SecureString]$ss) {
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

$secure = Read-Host -AsSecureString "Password (input hidden)"
$Password = ConvertTo-PlainText $secure

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

# 4) Build JSON body (include tenant-scoped parent_pin)
$body = @{ tenant_name = $TenantName; password = $Password; parent_pin = $ParentPin } | ConvertTo-Json

# 5) Send request
$headers = @{ 'X-Tenant-Creation-Key' = $key }
$uri = ($Url.TrimEnd('/')) + '/api/tenants'

Write-Host "POST $uri" -ForegroundColor Cyan
Write-Host "Tenant: $TenantName  ParentPin: **** (masked)" -ForegroundColor Gray
try {
    $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -Headers $headers -ErrorAction Stop
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
