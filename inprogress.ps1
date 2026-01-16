# Inprogress PowerShell Script


# Logs are created at "C:\Logs"

# Change the below parameters for competition
# ----
# Parameters
# ----
$CCDCPassword = "!Changeme123"


# ----
# Logging
# ----
$LogDir = "C:\Logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
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
}

# ----
# Detects Active Directory (If applicable)
# ----
$ADAvailable = $false

if (Get-InstalledModule -Name ActiveDirectory -ErrorAction SilentlyContinue) {
    $ADAvailable = $true
    Write-Status "Active Directory module detected" "Success"
} else {

    Write-Status "Active Directory module not detected" "Info"
}

# ----
# Determine Windows Version
# ----
$OSInfo = Get-CimInstance Win32_OperatingSystem
$OSCaption = $OSInfo.Caption
Write-Status "Detected OS: $OSCaption" "Info"

# ----
# Set password based on OS and AD presence
# ----
if ($OSCaption -match "Windows Server 2019") {
    if ($ADAvailable) {
        $CCDCPassword = "Level-president00!"      # Password if Server 2019 with AD
    } else {
        $CCDCPassword = "Purpose-brought15!"   # Password if Server 2019 without AD
    }
} elseif ($OSCaption -match "Windows Server 2022") {
    $CCDCPassword = "Washington-hours00!"            # Same for AD or local on 2022
} elseif ($OSCaption -match "Windows 11") {
    $CCDCPassword = "Services-brought41!"             # Workstation Windows 11
} else {
    $CCDCPassword = "Cases-planning30!"              # Default fallback
} 

# ----
# CCDCAdmin Account
# ----
$SecureCCDCPassword = ConvertTo-SecureString $CCDCPassword -AsPlainText -Force
$CCDCAccountName = "ccdcadmin"

try {
    if ($ADAvailable) {
        if (-not (Get-ADUser -Identity $CCDCAccountName -ErrorAction SilentlyContinue)) {
            New-ADUser -Name $CCDCAccountName -SamAccountName $CCDCAccountName `
                       -AccountPassword $SecureCCDCPassword -Enabled $true -PasswordNeverExpires $true
            $AdminGroups = @("Administrators","Domain Admins","Enterprise Admins","Group Policy Creator Owners","Schema Admins","DnsAdmins")
            foreach ($Group in $AdminGroups) { Add-ADGroupMember -Identity $Group -Members $CCDCAccountName -ErrorAction SilentlyContinue }
            Write-Status "AD account '$CCDCAccountName' created and added to admin groups" "Success"
        } else {
            Write-Status "AD account '$CCDCAccountName' already exists" "Info"
        }
    } else {
        if (-not (Get-LocalUser -Name $CCDCAccountName -ErrorAction SilentlyContinue)) {
            New-LocalUser -Name $CCDCAccountName -Password $SecureCCDCPassword -FullName "CCDC Administrator" -PasswordNeverExpires | Out-Null
            Add-LocalGroupMember -Group "Administrators" -Member $CCDCAccountName
            Write-Status "Local account '$CCDCAccountName' created and added to Administrators group" "Success"
        } else {
            Write-Status "Local account '$CCDCAccountName' already exists" "Info"
        }
    }
} catch {
    Write-Status "Failed to create $CCDCAccountName account: $_" "Error"
}


# ----
# Security Policies and Interactive Logon Banner
# ----

$LegalNoticeTitle = "Authorized Use Notice"

$LegalNoticeText = @"
This computer system is restricted to authorized users only.
Activities on this system may be monitored, logged, and reviewed.
By continuing, you consent to monitoring and acknowledge your responsibility.
Unauthorized access is prohibited and may result in disciplinary or legal action.
"@

if ($ADAvailable) {

    Write-Status "Checking Active Directory password policy and logon banner" "Info"

    try {
        $CurrentPolicy = Get-ADDefaultDomainPasswordPolicy
        if ($CurrentPolicy.MinPasswordLength -eq 14 -and $CurrentPolicy.ComplexityEnabled -eq $true -and $CurrentPolicy.MaxPasswordAge.Days -eq 90) {
            Write-Status "Domain password policy already compliant" "Info"
        } else {
            Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -ComplexityEnabled $true -MaxPasswordAge (New-TimeSpan -Days 90) -ErrorAction Stop
            Write-Status "Domain password policy applied successfully" "Success"
        }
    } catch {
        Write-Status "Failed to process domain password policy: $_" "Error"
    }

    try {
        $SysReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $CurrentTitle = (Get-ItemProperty -Path $SysReg -Name legalnoticecaption -ErrorAction SilentlyContinue).legalnoticecaption
        $CurrentText  = (Get-ItemProperty -Path $SysReg -Name legalnoticetext -ErrorAction SilentlyContinue).legalnoticetext

        if ($CurrentTitle -eq $LegalNoticeTitle -and $CurrentText -eq $LegalNoticeText) {
            Write-Status "Domain interactive logon banner already configured" "Info"
        } else {
            Set-ItemProperty -Path $SysReg -Name legalnoticecaption -Value $LegalNoticeTitle -Force
            Set-ItemProperty -Path $SysReg -Name legalnoticetext -Value $LegalNoticeText -Force
            Write-Status "Domain interactive logon banner configured" "Success"
        }
    } catch {
        Write-Status "Failed to configure domain logon banner: $_" "Error"
    }

} else {

    Write-Status "Checking local password policy and logon banner" "Info"

    try {
        secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
        $SecPol = Get-Content "$env:TEMP\secpol.cfg"

        $MinLenOK = ($SecPol -match "^MinimumPasswordLength\s*=\s*9$")
        $ComplexOK = ($SecPol -match "^PasswordComplexity\s*=\s*1$")
        $MaxAgeOK = ($SecPol -match "^MaximumPasswordAge\s*=\s*90$")

        if ($MinLenOK -and $ComplexOK -and $MaxAgeOK) {
            Write-Status "Local password policy already compliant" "Info"
        } else {
            $SecPol.Replace("MinimumPasswordLength =", "MinimumPasswordLength = 9").
                    Replace("PasswordComplexity =", "PasswordComplexity = 1").
                    Replace("MaximumPasswordAge =", "MaximumPasswordAge = 90") |
                    Set-Content "$env:TEMP\secpol.cfg"

            secedit /configure /db "$env:TEMP\secedit.sdb" /cfg "$env:TEMP\secpol.cfg" /areas SECURITYPOLICY | Out-Null
            Write-Status "Local password policy applied successfully" "Success"
        }
    } catch {
        Write-Status "Failed to process local password policy: $_" "Error"
    }

    try {
        $SysReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $CurrentTitle = (Get-ItemProperty -Path $SysReg -Name legalnoticecaption -ErrorAction SilentlyContinue).legalnoticecaption
        $CurrentText  = (Get-ItemProperty -Path $SysReg -Name legalnoticetext -ErrorAction SilentlyContinue).legalnoticetext

        if ($CurrentTitle -eq $LegalNoticeTitle -and $CurrentText -eq $LegalNoticeText) {
            Write-Status "Local interactive logon banner already configured" "Info"
        } else {
            Set-ItemProperty -Path $SysReg -Name legalnoticecaption -Value $LegalNoticeTitle -Force
            Set-ItemProperty -Path $SysReg -Name legalnoticetext -Value $LegalNoticeText -Force
            Write-Status "Local interactive logon banner configured" "Success"
        }
    } catch {
        Write-Status "Failed to configure local logon banner: $_" "Error"
    }
}


# DNS Configuration and Logging
try {
    if ($ADAvailable) {
        $DNSLog = Join-Path $LogDir "DNS-Log.txt"
        Set-DNSServerDiagnostics -All $true -Verbose
        Set-DNSServerDiagnostics -LogFilePath $DNSLog -Verbose
        Write-Status "DNS logging enabled at $DNSLog" "Success"
    } else {
        Write-Status "Active Directory not detected, skipping DNS server logging" "Info"
    }

    AuditPol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
    AuditPol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
    AuditPol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null

    Write-Status "Audit policy configured for Logon Events, Account Management, and Policy Changes" "Success"

} catch {
    Write-Status "Failed to configure DNS or audit policy: $_" "Error"
}

# Disable Default Accounts
$AccountsToDisable = @("Administrator","Guest")

foreach ($Account in $AccountsToDisable) {
    try {
        if ($ADAvailable) {
            $User = Get-ADUser -Identity $Account -Properties Enabled -ErrorAction SilentlyContinue
            if ($User) {
                if ($User.Enabled) {
                    Disable-ADAccount -Identity $Account -Confirm:$false
                    Write-Status "Disabled AD account: '$Account'" "Success"
                } else {
                    Write-Status "AD account '$Account' already disabled" "Info"
                }
            } else {
                Write-Status "AD account '$Account' does not exist" "Warning"
            }
        } else {
            $User = Get-LocalUser -Name $Account -ErrorAction SilentlyContinue
            if ($User) {
                if ($User.Enabled) {
                    Disable-LocalUser -Name $Account
                    Write-Status "Disabled local account '$Account'" "Success"
                } else {
                    Write-Status "Local account '$Account' already disabled" "Info"
                }
            } else {
                Write-Status "Local account '$Account' does not exist" "Warning"
            }
        }
    } catch {
        Write-Status "Error processing account '$Account': $_" "Error"
    }
}

# Reset Password for Sensitive Accounts
# ----
# Reset Passwords for Sensitive Accounts
# ----
$SensitiveAccounts = @("krbtgt","Administrator","Guest")  # Add more accounts here if needed

if ($ADAvailable) {
    foreach ($Acct in $SensitiveAccounts) {
        try {
            $CurrentUser = Get-ADUser -Identity $Acct -ErrorAction SilentlyContinue
            if ($CurrentUser) {
                Add-Type -AssemblyName System.Web
                $Password = [System.Web.Security.Membership]::GeneratePassword(100,20)
                $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
                Set-ADAccountPassword -Identity $CurrentUser -NewPassword $SecurePassword -Reset -ErrorAction Stop
                Write-Status "Password reset for AD account '$Acct'" "Success"
            } else {
                Write-Status "AD account '$Acct' does not exist" "Warning"
            }
        } catch {
            Write-Status "Failed to reset password for AD account '$Acct': $_" "Error"
        }
    }
} else {
    foreach ($Acct in $SensitiveAccounts) {
        try {
            $LocalUser = Get-LocalUser -Name $Acct -ErrorAction SilentlyContinue
            if ($LocalUser) {
                Add-Type -AssemblyName System.Web
                $Password = [System.Web.Security.Membership]::GeneratePassword(100,20)
                $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
                $LocalUser | Set-LocalUser -Password $SecurePassword
                Write-Status "Password reset for local account '$Acct'" "Success"
            } else {
                Write-Status "Local account '$Acct' does not exist" "Warning"
            }
        } catch {
            Write-Status "Failed to reset password for local account '$Acct': $_" "Error"
        }
    }
}

# ----
# Ensure Windows Defender Firewall is enabled
# ----

try {
    # Explicitly define firewall profiles
    $FirewallProfiles = @("Domain","Private","Public")

    foreach ($Profile in $FirewallProfiles) {
        $ProfileStatus = (Get-NetFirewallProfile -Profile $Profile).Enabled
        if ($ProfileStatus -eq $false) {
            Set-NetFirewallProfile -Profile $Profile -Enabled True
            Write-Status "Firewall enabled for $Profile profile" "Success"
        } else {
            Write-Status "Firewall already enabled for $Profile profile" "Info"
        }
    }
} catch {
    Write-Status "Failed to configure Windows Defender Firewall: $_" "Error"
}

# ----
# Disable legacy services: NetBIOS, Telnet, and SMBv1
# ----

try {
    $NetAdapters = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
    foreach ($Adapter in $NetAdapters) {
        $Adapter | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} | Out-Null
    }
    Write-Status "NetBIOS over TCP/IP disabled on all active adapters" "Success"
} catch {
    Write-Status "Failed to disable NetBIOS: $_" "Warning"
}

try {
    if (Get-Service -Name TlntSvr -ErrorAction SilentlyContinue) {
        Stop-Service -Name TlntSvr -Force -ErrorAction SilentlyContinue
        Set-Service -Name TlntSvr -StartupType Disabled
        Write-Status "Telnet service stopped and disabled" "Success"
    } else {
        Write-Status "Telnet service not installed or already disabled" "Info"
    }
} catch {
    Write-Status "Failed to stop/disable Telnet service: $_" "Warning"
}

try {
    $SMB1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    if ($SMB1Feature.State -ne "Disabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop
        Write-Status "SMBv1 protocol disabled" "Success"
    } else {
        Write-Status "SMBv1 protocol already disabled" "Info"
    }
} catch {
    Write-Status "Failed to disable SMBv1: $_" "Warning"
}



Stop-Transcript
