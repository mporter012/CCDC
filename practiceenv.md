# Active Directory

### Suspicious Things

#### Users
Group Name: Computer, under Enterprise Admins Group
Name, Richard G., under Domain Admins Group
Name: Admin admin, under Computer Group
## Group Policies
Password History = 24 
Account lockout threshold = 0 (change to 3 invalid attempts)
Accounts lockout duration = 5 minutes
## Local Policies
Audit Policy
- Enable account logon events, account management, policy change, privilege use, process tracking
Security Policies
- "Accounts: Administrator account status = Disable"
- "Accounts: Guest account status = Disable"
- "Devices: Prevent users from installing printer drivers = Enable"
- "User Account Control: Behavior of the elevation prompt = Prompt for credentials on the secure desktop"
Administrative Templates > Windows Components
- Windows Remote Shell
	- Disable "Allow Remote Shell Access"
- Windows PowerShell
	- Enable "Turn on Module Logging"
	- Enable "Turn on PowerShell Script Block Logging"
	- Enable "Turn on PowerShell Transcription"
- Windows Logon Options
	- Disable "Sign-in last interactive user automatically"
- Windows Defender Antirvitus
	- Disable "Turn off Windows Defender Antirvirus"
	- Set "Configure detection for potentially unwanted applications" to "block"
	- Enable 'Allow antimalware service to startup with normal priority'
	- Controlled Folder Access
		- Protected Folders:
	- Scan
		- Enable 'Check for the latest virus and spyware definitions before running a scheduled scan'
		- Disable 'Allow users to pause scan'
		- Enable "Turn on heuristics"
		- Set "Specify the interval to run quick scans per day" to 1 (runs every hour)
		- Enable "Scan archive files"
	- Task Scheduler
		- Enable "Prohibit New Task Creation"
	- Security Center
		- Enable
	- File Explorer
		- Enable "Configure Windows Defender SmartScreen"
## Firewall
Set to "not configured", enable it

# FTP

# Other Notes
Can change default lock screen and logon image and other stuff within Policy Management > Administrative Templates > Control Panel > Personalization
Can change folder to redirect to other places in Policy Management > Windows Settings > Folder Redirection

https://github.com/atlantsecurity/windows-hardening-scripts/blob/main/windows-server-2019-hardening-script.cmd

Windows server 2019 Atlant Security Hardening Script
`Invoke-WebRequest -Uri "https://raw.githubusercontent.com/atlantsecurity/windows-hardening-scripts/refs/heads/main/windows-server-2019-hardening-script.cmd" -OutFile "C:\Tools\windows-server-2019-hardening-script.cmd"`

Windows 11 Atlant Security Hardening Script
`Invoke-WebRequest -Uri "https://raw.githubusercontent.com/atlantsecurity/windows-hardening-scripts/refs/heads/main/windows-11-hardening-script" -OutFile "C:\Tools\windows-11-hardening-script.cmd"`
