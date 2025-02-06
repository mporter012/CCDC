# Ensure the script is running as Administrator
$elevated = [bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-Not $elevated) {
    Write-Host "Please run this script as an Administrator!" -ForegroundColor Red
    Exit
}
$currentNTPServer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters").NtpServer
$updateToNameServer = "time-a-b.nist.gov"

Write-Host "Current NTPServer: $currentNTPServer"

#Update the NTP to point to the specified NTP NameServer
w32tm /config /syncfromflags:manual /manualpeerlist:"$updateToNameServer" /update > $null 2>&1

#Restart the w32time Service
Restart-Service w32time
Write-Host "w32time Service Restarted"

#Verify and display the new NTPServer
$newNTPServer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters").NtpServer
Write-Host "New NTPServer: $newNTPServer"
