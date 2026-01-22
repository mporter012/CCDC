# ---- Logging Setup ----
$LogDir = "C:\Logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$TimestampName = Get-Date -Format "HHmm"
$TranscriptLog = Join-Path $LogDir "ClamScan_Transcript_$TimestampName.log"
$FullScanResults = Join-Path $LogDir "full_scan_results_$TimestampName.txt"
$DetectionResults = Join-Path $LogDir "detection_results_$TimestampName.txt"

Start-Transcript -Path $TranscriptLog

# ----
# Status Function
# ----
function Write-Status {
 param (
    [Parameter(Mandatory)]
    [string]$Message,

    [ValidateSet("Info","Success","Warning","Error")]
    [string]$Level = "Info"
 ) 
 
 $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
 $LogEntry = "$Timestamp [$Level] $Message"
 switch ($Level) {
    "Success" {Write-Host "[SUCCESS] $Message" -ForegroundColor Green}
    "Warning" {Write-Host "[WARNING] $Message" -ForegroundColor Yellow}
    "Error" {Write-Host "[ERROR] $Message" -ForegroundColor Red}
    default {Write-Host "[INFO] $Message"}
 }
}

# ---- High-priority scan targets ----
$ScanTargets = @(
    "C:\Users",
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\Windows\Temp",
    "$env:TEMP"
)

Write-Status "Starting ClamScan on high-priority directories..." "Info"

$ClamScanPath = "C:\Program Files\ClamAV\clamscan.exe"

# ---- Scan each directory ----
foreach ($Target in $ScanTargets) {
    if (Test-Path $Target) {
        Write-Status "Scanning $Target..." "Info"

        & $ClamScanPath `
            -r $Target `
            --infected `
            --quiet `
            --exclude-dir="C:\\Users\\All Users" `
            2>$null |
            Tee-Object -FilePath $FullScanResults -Append |
            Select-String -Pattern "FOUND$" |
            Tee-Object -FilePath $DetectionResults -Append | Out-Null

    } else {
        Write-Status "$Target does not exist. Skipping." "Warning"
    }
}

Write-Status "ClamScan completed." "Success"

# ---- Notify User if Detections Found ----
if (Test-Path $DetectionResults) {
    $Detections = Get-Content $DetectionResults | Where-Object { $_ -match "FOUND$" }
    if ($Detections) {
        # Windows popup notification
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        [System.Windows.Forms.MessageBox]::Show(
            "ClamAV detected threats on this system. Please check the log file:`n$LogFile",
            "ClamAV Detection",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        Write-Status "Detections found. User notified." "Warning"
    } else {
        Write-Status "No threats detected." "Success"
    }
} else {
    Write-Status "No detection file created; assuming no threats found." "Info"
}

Stop-Transcript
