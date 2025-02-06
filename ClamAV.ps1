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
$clamDatabaseConfigPath = "C:\Program Files\ClamAV\clamd.conf"

# If freshclam.conf does not exist, re-creates the file from the config examples
if (-not (TestPath $freshClamConfigPath)){
    Write-Host "FreshClam Config Not Found. Generating New Config"
    copy C:\Program Files\conf_exmaples\freshclam.conf.sample $freshClamConfigPath
    Write-Host "Config Generated."
    #Write-Host "Delete The Line That Says "Example" on Line 9. Then Save & Continue" -ForegroundColor Yellow
    #write-exe .\freshclam.conf -Wait
    Write-Host "Modifying the freshclam.conf file..." -ForegroundColor Green
    $fileContent = Get-Content $freshClamConfigPath
    #Remove the line containing "Example" and uncomment the UpdateLogFile line
    $fileContent = $fileContent | ForEach-Object {
        #Remove the line containing 'Example'
        if ($_ -match "Example"){
            $null #Exclude this line
        }
        # Uncomment the UpdateLogfile line
        elseif ($_ -match "^#\s*UpdateLogFile") {
            $_ -replace "^#\s*", ""
        }
        else {
            $_
        }
    }
    #Write the modified content back to the file
    $fileContent | Set-Content $freshClamConfigPath

    Write-Host "freshclam.conf has been modified successfully." -ForegroundColor Green
}

# If clamd.conf does not exist, re-creates the file from the config samples
if (-not (TestPath $clamDatabaseConfigPath)){
    Write-Host "FreshClam Config Not Found. Generating New Config"
    copy C:\Program Files\conf_exmaples\clamd.conf.sample $clamDatabaseConfigPath
    Write-Host "Config Generated. Opening Config"
    Write-Host "Delete The Line That Says "Example" on Line 9. Then Save & Continue" -ForegroundColor Yellow
    write-exe .\clamd.conf -Wait
}

# Run an automatic scan
# & "C:\Program Files\ClamAV\clamscan.exe" -r "C:\Users\Administrator\Documents\ClamAV.txt"
