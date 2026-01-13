# Inprogress PowerShell Script



# ----
# Logging
# ----
$LogDir = "$env:USERPROFILE\Documents\Logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $Path $LogDir -Force | Out-Null
}
$TimestampName = Get-Date -Format "HHmm"
$LogFile = Join-Path $LogDir "initialHardening_$TimestampName.log"

Start-Transcript -Path $LogFile

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
    Add-Content -Path %LogFile -Value %LogEntry
}

# ----
# Detect Active Directory
# ----
$ADAvailable = $false
if (Get-module -ListAvailable -Name ActiveDirectory) {
    $ADAvailable = $true
    Write-Status "Active Directory module detected" "Success"
} else {
    $ADAvailable = $false
    Write-Status "Active Directory module not detected" "Warning"
}

# ----
# Accounts that should be disabled
# ----
$Accounts = @(
    "Administrator",
    "Guest"
)

# ----
# Active Directory Accounts
# ----
if ($ADAvailable) {
    foreach ($Account in $Accounts) {
        try {
            $User = Get-ADUser -Identity $Account -Properties Enabled -ErrorAction Stop
            if ($User.Enabled){
                Disable-ADAccount -Identity $Account -Confirm:$false
                Write-Status "AD account '$Account' was enabled and has been disabled." "Success"
            }
            else {
                Write-Status "AD account '$Account' is already disabled." "Info"
            }
        } catch {
            Write-Status "AD account '$Account' does not exist or access was denied." "Warning"
        }
    }
}

# ----
# Local Accounts
# ----
else {
    foreach ($Account in $Accounts) {
        try{
            $User = Get-LocalUser -Name $Account -ErrorAction Stop
            if ($User.Enabled) {
                Disable-LocalUser -Name $Account
                Write-Status "Local account '$Account' was enabled and has been disabled." "Success"
            } else {
                Write-Status "Local account '$Account' is already disabled." "Info"
            }
        }
        catch {
            Write-Status "Local account '$Account' does not exist." "Warning" 
        }
    }
}

Stop-Transcript
