$DateTime = Get-Date -Format "DD_HH_mm"
$LogName = "Initial_LocalSetup_" + $DateTime + ".txt"

Start-Transcript -LiteralPath ("C:\Windows\Temp\" + $LogName)

$LocalUsers = Get-LocalUser -ErrorAction SilentlyContinue | Select Name, Enabled

Write-Host "Creating local CCDC user"
New-LocalUser -Name 'ccdc' -FullName 'CCDC User' -Password (ConvertTo-SecureString 'Password123!' -AsPlainText -Force) -Verbose
Add-LocalGroupMember -Group 'Administrators' -Member 'ccdc' -Verbose
Add-LocalGroupMember -Group 'Domain Admins' -Member 'ccdc' -Verbose
Add-LocalGroupMember -Group 'Enterprise Admins' -Member 'ccdc' -Verbose
Set-LocalUser -Name 'ccdc' -Enabled $True -Verbose

Write-Host "AUDITING USERS ------ LOCAL USERS" -BackgroundColor Cyan
if ($LocalUsers -ne $NULL) {
    $LocalUsers | Format-Table Name, Enabled
}
else {
    Write-Host ("No local accounts found!")
}

Write-Host "`n`nAUDITING ADMIN GROUP MEMBERSHIPS -----"
foreach ($User in $LocalUsers) {
    Write-Host ("Memberships for: " + $User.Name)
    $groups = Get-LocalGroupMember -Group 'Administrators' | Select -ExpandProperty Name
    foreach ($group in $groups) { Write-Host (" " + $group) }
    Write-Host ("")
}

Write-Host "`n`nAUDITING FOREIGN SECURITY PRINCIPALS -----"
Write-Host ("No foreign security principals in a local setup.")

$LocalUser = Get-LocalUser -Name 'Guest'
$Password = [System.Web.Security.Membership]::GeneratePassword(100, 20)
$Password = ConvertTo-SecureString -String $Password -AsPlainText -Force
Set-LocalUserPassword -Name 'Guest' -Password $Password -Verbose

Stop-Service -Name NetBIOS -Verbose
