function IsDockerDesktopRunning() {
    $dockerPsResult = docker ps 2>&1 | Out-String
    if ($dockerPsResult -match "error") {
        return $false
    }
    return $true
}

function StartDockerDesktop() {
    $dockerDesktopPath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Docker Desktop" -Name "InstallLocation" -ErrorAction SilentlyContinue
    if (-not $dockerDesktopPath) {
        $dockerDesktopPath = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Docker Desktop" -Name "InstallLocation" -ErrorAction SilentlyContinue
    }
    if ($dockerDesktopPath) {
        Write-Host "Starting Docker Desktop..."
        $exePath = Join-Path $dockerDesktopPath "Docker Desktop.exe"
        Start-Process -FilePath $exePath
    } else {
        Write-Host "No Docker Desktop installation found."
    }
    
}

if (IsDockerDesktopRunning) {
    Write-Host "Docker Desktop is running."
} else {
    Write-Host "Docker Desktop is not running."
    StartDockerDesktop
    Write-Host "Waiting for Docker Desktop to start..."
    while (-not (IsDockerDesktopRunning)) {
        Start-Sleep -Seconds 2
    }
    Write-Host "Docker Desktop has started."
}
Write-Host "Building and starting development Docker containers..."
Write-Host ""
docker compose -f docker-compose-dev.yml up -d --build
Write-Host ""
Write-Host "Development Docker containers are up and running in DETACHED mode."
Write-Host "You can access the application at http://localhost:8000"
Write-Host "To stop the containers, run: docker compose -f docker-compose-dev.yml down"
Write-Host "To view logs, run: docker compose -f docker-compose-dev.yml logs -f"
