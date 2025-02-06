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
$installerPath = "$env:USERPROFILE\Downloads\clamav_installer.msi"
if (-not (Test-Path $installerPath)){
    Write-Host "Downloading Installer"
    $clamavInstallerUrl = "https://www.clamav.net/downloads/production/clamav-0.105.2.win.x64.msi"
    Invoke-WebRequest -Uri $clamavInstallerUrl -OutFile $InstallerPath
}
# Run ClamAV Installer
Write-Host "Launching Installer"

Start-Sleep -Seconds 3

Start-Process -FilePath $installerPath -Wait

# Update ClamAV Virus Database
Write-Host "Updating ClamAV Virus Database"

# Define the path to the freshclam.conf file
$freshClamConfigPath = "C:\Program Files\ClamAV\freshclam.conf"
$clamDatabaseConfigPath = "C:\Program Files\ClamAV\clamd.conf"

# If freshclam.conf does not exist, re-creates the file from the config examples
if (-not (Test-Path $freshClamConfigPath)){
    Write-Host "FreshClam Config Not Found. Generating New Config"
    Copy-Item "C:\Program Files\ClamAV\conf_examples\freshclam.conf.sample" $freshClamConfigPath
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
if (-not (Test-Path $clamDatabaseConfigPath)){
    Write-Host "clamd Config Not Found. Generating New Config"
    Copy-Item "C:\Program Files\ClamAV\conf_examples\clamd.conf.sample" $clamDatabaseConfigPath
    Write-Host "Config Generated."
    Write-Host "Modifiying the clamd.conf file..." -ForegroundColor Green
    $fileContent = Get-Content $clamDatabaseConfigPath
    $fileContent = $fileContent | ForEach-Object {
        if ($_ -match "Example") {
            $null  # Skip lines with "Example"
        }
        # Uncomment specific logging options by removing the '#' from the beginning
        elseif ($_ -match "^#LogTime") {
            $_ -replace "^#LogTime", "LogTime"
        }
        elseif ($_ -match "^#LogVerbose") {
            $_ -replace "^#LogVerbose", "LogVerbose"
        }
        elseif ($_ -match "^#ExtendedDetectionInfo") {
            $_ -replace "^#ExtendedDetectionInfo", "ExtendedDetectionInfo"
        }
        elseif ($_ -match "^#DetectPUA") {
            $_ -replace "^#DetectPUA", "DetectPUA"
        }
        elseif ($_ -match "^#HeuristicAlerts") {
            $_ -replace "^#HeuristicAlerts", "HeuristicAlerts"
        }
        else {
            $_  # Keep all other lines unchanged
        }
    }

    $fileContent | Set-Content $clamDatabaseConfigPath
    Write-Host "clamd.conf has been modified successfully." -ForegroundColor Green
}
$logFile = "C:\Program Files\ClamAV\freshclam.log"
$user = "Administrator"
# Create the freshclam log file if it does not already exist
if (-not (Test-Path $logFile)){
    New-Item -Path $logFile -ItemType File -Force | Out-Null
    if (Test-Path $logFile){
        Write-Host "Log File Created Successfully at $logFile" -ForegroundColor Green
    }else{
        Write-Host "Log File Failed Creation" -ForegroundColor Red
    }
}

# Run freshclam.exe
$freshClam
Write-Host "Running freshclam.exe"
Start-Process "$freshClam" -Wait
Write-Host $freshClam

# Run an automatic scan
& "C:\Program Files\ClamAV\clamscan.exe" -r "C:\" | Tee-Object -FilePath "$env:USERPROFILE\Administrator\Documents\full_scan_results.txt" | Select-String -Pattern "FOUND" | Tee-Object -FilePath "$env:USERPROFILE\Administrator\Documents\detection_results.txt" -ErrorAction SilentlyContinue
