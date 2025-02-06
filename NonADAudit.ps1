# Set up logging directory and log file name
$AuditLogDir = "$env:USERPROFILE\Documents"
$DateTime = Get-Date -Format "yyyyMMdd_HH-mm-ss"
$LogName = "Local_Audit_$DateTime.txt"
$LogPath = Join-Path -Path $AuditLogDir -ChildPath $LogName

# Start transcript (logging)
Start-Transcript -LiteralPath $LogPath

# Get local users
$LocalUsers = Get-LocalUser | Select Name, PrincipalSource, Enabled

Write-Host "AUDITING USERS ------ LOCAL USERS" -BackgroundColor Cyan
foreach ($User in $LocalUsers) {
    Write-Host ("User: " + $User.Name + " | Source: " + $User.PrincipalSource + " | Enabled: " + $User.Enabled)
}

# Get local groups and memberships
Write-Host "`n`nAUDITING GROUP MEMBERSHIPS -----" -BackgroundColor Cyan
$Groups = Get-LocalGroup | Select Name

foreach ($Group in $Groups) {
    Write-Host ("Group: " + $Group.Name) -BackgroundColor Yellow
    try {
        $GroupMembers = Get-LocalGroupMember -Group $Group.Name | Select Name, ObjectClass
        if ($GroupMembers) {
            $GroupMembers | Format-Table
        } else {
            Write-Host "No members found in this group."
        }
    }
    catch {
        Write-Host "Unable to retrieve members for group: $($Group.Name)."
    }
}

# Get running and stopped services
Write-Host "`n`nAUDITING SYSTEM SERVICES -----" -BackgroundColor Cyan
$Services = Get-Service | Select DisplayName, Status | Sort-Object Status, DisplayName -Descending
$Services | Format-Table -AutoSize

$Running = ($Services | Where-Object { $_.Status -eq "Running" }).Count
Write-Host ("There are " + $Running + " running services") -ForegroundColor Yellow

$Stopped = ($Services | Where-Object { $_.Status -eq "Stopped" }).Count
Write-Host ("There are " + $Stopped + " stopped services") -ForegroundColor Yellow

# Get listening and established network connections
Write-Host "`n`nAUDITING NETWORK CONNECTIONS -----" -BackgroundColor Cyan
Write-Host "Listening Ports:"
Get-NetTCPConnection -State Listen | Format-Table -AutoSize

Write-Host "`nEstablished Ports:"
Get-NetTCPConnection -State Established | Format-Table -AutoSize

Write-Host "`nPort Status with Process Names:"
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, `
    @{Name = 'ProcessName'; Expression = { (Get-Process -Id $_.OwningProcess).Name } } | `
    Sort-Object State, LocalAddress, LocalPort | Format-Table -AutoSize

# Get local security policies (Password Policy)
Write-Host "`n`nCONFIGURING PASSWORD POLICY -----" -BackgroundColor Cyan
Write-Host "Password Policy:"
secedit /export /cfg "$AuditLogDir\SecPolicy.inf"
$PasswordPolicy = Get-Content "$AuditLogDir\SecPolicy.inf" | Select-String "Password"
$PasswordPolicy | ForEach-Object { Write-Host $_ }

# Get DNS Client and Server settings
Write-Host "`n`nCONFIGURING DNS SETTINGS -----" -BackgroundColor Cyan
Write-Host "DNS Client Cache:"
Get-DnsClientCache | Format-Table -AutoSize

Write-Host "`nDNS Server Cache:"
try {
    Get-DnsServerCache | Format-Table -AutoSize
} catch {
    Write-Host "Could not retrieve DNS Server Cache (Requires Admin Privileges or DNS Server Role)."
}

# Audit hosts file
Write-Host "`n`nAUDITING HOSTS FILE -----" -BackgroundColor Cyan
Get-Content -LiteralPath "C:\Windows\System32\drivers\etc\hosts"

Stop-Transcript

Write-Host "`nAudit log saved to: $LogPath" -ForegroundColor Green
