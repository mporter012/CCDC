# ----
# This script creates a new GPO on an Active Directory computer's connected Domain.
# When downloaded, the other 'inprogress.ps1' script gets installed with this. This script also connects the 'inprogress' script to a startup script in the GPO
# More functionality will come soon with deploying firewall rules.
# ----

Import-Module ActiveDirectory
Import-module GroupPolicy

# Variables
$GPOName = "TestingGPO" # Change name to what the GPO does
$ScriptDirectory = "C:\Scripts"
$ScriptName = "myscript.ps1" # Change to name of the initial hardening script
$ScriptSource = Join-Path $ScriptDirectory $ScriptName

# Obtaining current domain
$CurrentDomain = (Get-ADDomain).DNSRoot
$DomainDN = (Get-ADDomain).DistinguishedName
Write-host "Current domain detected: $Currentdomain"

# Creating New GPO
try {
    $GPO = New-GPO -Name $GPOName -Comment "Deploy startup script and firewall rules"
    Write-Host "GPO '$GPOName' created successfully."
} catch {
    Write-Host "Error creating GPO: $_"
    exit
}

# Linking Created GPO to existing Domain
try {
    New-GPLink -Name $GPOName -Target $DomainDN
    Write-Host "GPO '$GPOName' linked to domain root ($CurrentDomain)."
} catch {
    Write-Host "Error linking GPO: $_"
}

# Finding File Directory for Startup Scripts for GPO
$GPO = Get-GPO -Name $GPOName
Write-Host "GPO GUID: $($GPO.Id)"

$GPOId = $GPO.Id.ToString().ToUpper()
$StartupFolder = "\\$CurrentDomain\SYSVOL\$CurrentDomain\Policies\{$GPOId}\Machine\Scripts\Startup"
Write-Host "Startup script folder: $StartupFolder"

if (-not (Test-Path $Startupfolder)){
    New-Item -ItemType Directory -Path $StartupFolder -Force | Out-Null
    Write-Host "Created folder path: $StartupFolder"
} else {
    Write-Host "Folder path already exists: $StartupFolder"
}

# Copy Script into Folder
Copy-Item -Path $ScriptSource -Destination $StartupFolder -Force
Write-Host "Script '$ScriptName' copied to startup Folder."

# Register script in GPO for startup
Set-GPStartupScript -Name $GPOName -ScriptName $ScriptName
Write-Host "Script '$ScriptName' registered as startup script in GPO '$GPOName'."
