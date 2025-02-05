# Script to audit system configuration without Active Directory

# Output file to save results
$outputFile = "C:\AuditReport.txt"

# Start writing results to file
"Audit Report - $(Get-Date)" | Out-File $outputFile -Append

# 1. List all local users
"Local Users:" | Out-File $outputFile -Append
Get-LocalUser | Select-Object Name, Enabled, LastLogon | Out-File $outputFile -Append

# 2. List all local groups and their members
"Local Groups and Members:" | Out-File $outputFile -Append
Get-LocalGroup | ForEach-Object {
    $group = $_
    $groupName = $group.Name
    $groupMembers = Get-LocalGroupMember -Group $groupName | Select-Object Name, ObjectClass
    $groupName
    $groupMembers | Out-File $outputFile -Append
}

# 3. List file and folder permissions (example for a common folder like C:\)
"Permissions on C:\ folder:" | Out-File $outputFile -Append
Get-Acl -Path "C:\" | Select-Object Path, Owner, Access | Out-File $outputFile -Append

# 4. Local Security Policies (example: password policy)
"Local Security Policy - Password Policy:" | Out-File $outputFile -Append
secpol.msc /export /file:"C:\secpol_export.inf"
Get-Content "C:\secpol_export.inf" | Out-File $outputFile -Append

# 5. Audit Policies (Security Logs)
"Audit Policies:" | Out-File $outputFile -Append
auditpol /get /category:* | Out-File $outputFile -Append

# 6. Services - List installed services
"Installed Services:" | Out-File $outputFile -Append
Get-Service | Select-Object Name, DisplayName, Status | Out-File $outputFile -Append

# 7. Event Logs - Security logs
"Security Event Logs (Last 10 Events):" | Out-File $outputFile -Append
Get-WinEvent -LogName Security -MaxEvents 10 | Select-Object TimeCreated, Id, Message | Out-File $outputFile -Append

# 8. Scheduled Tasks
"Scheduled Tasks:" | Out-File $outputFile -Append
Get-ScheduledTask | Select-Object TaskName, State, LastRunTime | Out-File $outputFile -Append

# 9. System Information
"System Information:" | Out-File $outputFile -Append
Get-ComputerInfo | Select-Object CsName, OsArchitecture, WindowsVersion, WindowsBuildLabEx | Out-File $outputFile -Append

# Finish
"Audit complete. Results saved to $outputFile" | Out-File $outputFile -Append
