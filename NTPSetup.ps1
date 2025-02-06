# Ensure the script is running as Administrator
$elevated = [bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-Not $elevated) {
    Write-Host "Please run this script as an Administrator!" -ForegroundColor Red
    Exit
}
$currentNTPServer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters").NtpServer
$updateToNameServer = "time-a-b.nist.gov"

Write-Host "Current NTPServer: $currentNTPServer"

# Update the NTP to point to the internal Debian machine
# Update "[placeholder]" to point to the NTP NameServer you want the NTP to point to
w32tm /config /syncfromflags:manual /manualpeerlist: /manualpeerlist: "$updateToNameServer" /update

# Restart the w32time service
Restart-Service w32time
Write-Host "w32time Service Restarted"

Write-Host "Current NTPServer: $currentNTPServer"
