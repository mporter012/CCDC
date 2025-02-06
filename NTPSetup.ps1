# Ensure the script is running as Administrator
$elevated = [bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-Not $elevated) {
    Write-Host "Please run this script as an Administrator!" -ForegroundColor Red
    Exit
}

# Update the NTP to point to the internal Debian machine
# Update "[placeholder]" to point to the NTP NameServer you want the NTP to point to
w32tm /config /syncfromflags:manual /manualpeerlist: /manualpeerlist: "[placeholder]" /update

# Restart the w32time service
Write-Host "Stopping w32time Service"
Stop-Service w32time
Start-Sleep -Seconds 2
Write-Host "w32time Service Status: $(Get-Service w32time).Status"

Write-Host "Starting w32time Service"
Start-Service w32time
Start-Sleep -Seconds 2
Write-Host "w32time Service Status: $(Get-Service w32time).Status"
