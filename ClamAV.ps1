# Ensure the script is running as Administrator
$elevated = [bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-Not $elevated) {
    Write-Host "Please run this script as an Administrator!" -ForegroundColor Red
    Exit
}

# Disables the download progress bar
# This significantly speeds up download speeds
$ProgressPreference = 'SilentlyContinue'
Write-Host "Disabled progress bar"

# Install ClamAV
$clamavInstallerUrl = "https://www.clamav.net/downloads/production/clamav-0.105.2.win.x64.msi"
$installerPath = "$env:USERPROFILE\Downloads\clamav_installer.msi"
Invoke-WebRequest -Uri $clamavInstallerUrl -OutFile $InstallerPath

# Run ClamAV Installer
Write-Host "Launching Installer"

Start-Sleep -Seconds 3

Start-Process -FilePath $installerPath -Wait

# IF CLAMAV SERVICE DOESN'T SETUP, UNCOMMENT BELOW
<#
New-Service -Name "ClamAV" -Binary "C:\Program Files\ClamAV\clamad.exe" -StartupType Automatic
Start-Service -Name "ClamAV"
#>

# Update ClamAV Virus Database
Write-Host "Updating ClamAV Virus Database"

# Define the path to the freshclam.conf file
$freshClamConfigPath = "C:\Program Files\ClamAV\freshclam.conf"

if(-not (Test-Path $freshClamConfigPath)){
    Write-Host "FreshClam Config not found"
    Write-Host "Generating new config"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/aosm/clamav/refs/heads/master/clamav.Conf/freshclam.conf.default" -OutFile "$freshClamConfigPath"
    if (Test-Path $freshClamConfigPath){
        Write-Host "FreshClam Config Successfully Generated"
    }else{
        Write-Host "FreshClam Config Unable to Generate"
    }
}

# Run an automatic scan
# & "C:\Program Files\ClamAV\clamscan.exe" -r "C:\Users\Administrator\Documents\ClamAV.txt"