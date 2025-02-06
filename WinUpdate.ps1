# Disable Progress Bar
$ProgressPreference = 'SilentlyContinue'

# Check if PSWindowsUpdate is installed

$module = Get-InstalledModule -Name PSWindowsUpdate -ErrorAction SilentlyContinue | Select Name -ExpandProperty Name
if ($module -eq $NULL) {
    Install-Module PSWindowsUpdate
}

# Import PSWindowsUpdate module
Import-Module PSWindowsUpdate

# Perform a windows update scan
Write-Host "Scanning for updates..." -ForegroundColor Yellow
$updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll

# Check for a available updates
if ($updates.Count -eq 0) {
    Write-Host "No updates available." -ForegroundColor Green
    Exit
}

# Install updates
Write-Host "Found $($updates.Count) update(s)." -ForegroundColor Yellow
Install-WindowsUpdate -AcceptAll

# Check for success & Restart prompt
if (-not $?) {
    Write-Host "Failed to install updates." -ForegroundColor Red
} 
else {
    $restartChoice = Read-Host "Updates successfully installed! Do you want to restart the computer now? (Y/n):"
    if ($restartChoice -eq 'Y' -or $restartChoice -eq 'y') {
        Restart-Computer -Force
    }
    else {
        Write-Host "Restart later to complete installation." -ForegroundColor Green
    }
}
