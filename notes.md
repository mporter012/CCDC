
# Scripts
- [ ] Make a "launcher" for scripts that will run all the scripts with the correct execution policy
- [ ] Make a script that will run on the AD/DNS server that will run and push scripts for initial hardening to all other windows machines

- [x] Audit (AD & Non-AD)
	- [ ] Make a scheduled task that audits the system every 30 minutes to an hour
	- [x] Audit MAC Addresses
	- [x] Audit ARP cache
	- [x] Audit active sessions
	- [x] Audit file-sharing
	- [x] Audit hosts file
	- [x] Audit Scheduled Tasks
- [ ] Installing & Running ClamAV
	- [ ] Make a scheduled task that runs the script every 30 minutes to an hour
	- [ ] Have a popup be made for detections
- [x] Basic hardening (AD & Non-AD)
- [ ] Installing and deploy the Wazuh Agent
- [ ] Getting Inventory
- [x] Changing login banner
- [ ] Add end-to-end hardening
- [x] Change DSRM password
- [ ] Research DeepBlue CLI
- [x] Raise UAC level
- [ ] Change Firewall Rules
- [ ] 

# Scripts in Progress
## Basic Hardening (Non-AD)
### Accounts / Permissions
- [ ] Disables default guest account
- [ ] Disables default administrator account
### Firewall
- [ ] Enable Windows Defender Firewall
- [ ] Restrict inbound rules to only required services
- [ ] Disable Telnet
- [ ] Disable SMBv1
- [ ] Enable logging for failed and successful logins
### Security Policies & Audit
- [ ] Enforce password policies
- [ ] Configure account lockout policy
- [ ] Enable Audit Policy for logon events, account management, and policy changes

# Things to Research
- How to allow the Wazuh Manager (on Splunk) to communicate with the agents under the cisco firewall
- Research how to make a script that will return the items needed for inventory
- How to lock down the AD/DNS machine
- How to use Cisco FTD 
	- Limiting connections/actions of users
	- Monitoring packets
	- What ports to shut down
	- If/how to run a script to apply changes quickly

# Invitational Injects

In this section, I only document the processes and specific injects that have to do with Windows and/or Cisco FTD.
Using these injects, I will build scripts for all the Windows machines and instructions on managing the Cisco FTD.

## EVAL04T - External Perimeter Assessment

### Summary
Evaluate the perimeter of the network in order to capture all network services that are exposed. 

### Details about the example commands
1. User Masscan for high speed initial discovery
	- Example command: masscan `192.168.1.0/24 -p0-65535 —rate=500 —wait=10`
		- `/24` = 256 ip addresses (from 192.168.1.0 to 192.168.1.255) = **Replace with external firewall ip**
		- `-p0-65535` scans all TCP ports from `0` to `65535` (every possible TCP port)
		- `rate` controls packets per second. Used to reduce false positives
		- `wait` controls how many seconds it takes to exit after finishing
2. Use Nmap for detailed TCP followup on the hosts discovered by Masscan
	This tells you the port's protocol, Software, and 
	- Example command: `map -sS -sV -T4 -Pn -p <open ports> <target IPs>`
		- `-sS` is a TCP SYN scan - checks to see if the port is open. If port is open, immediately stops the Nmap scan and does not complete handshake
		- `-sV` is Service & Version detection. If SYN scan confirms port is open, this parameter obtains the Protocol, Software, and Version running on the port.
		- `-T4` is a Timing Template
			- Aggressive timing template. The scan happens fast and doesn't crash services
		- `-Pn` means No Ping
			- Makes it automatically assume that the host is up
3. Use Nmap for limited UDP scan of common ports.
	- Example command: `map -sU -T4 -top-ports 10 <target IPs>`
		- `-sU` means UDP scan
		- `-top-ports 10` instead of scanning all 65,535 UDP ports, it only scans the top 10 most commonly exposed UDP ports. Those being:
			1. 53 (DNS)
			2. 67/68 (DHCP)
			3. 69 (TFTP)
			4. 123 (NTP)
			5. 161 (SNMP)
			6. 500 (ISAKMP)
			7. 1900 (UPnP)

### If Tools are Not Installed on VyOS
`run bash` - enter operational mode
`vyos@vyos:~$ which apt` - check if `apt` exists
- If nothing returns, then installs are blocked
- Otherwise, continue
`sudo apt update` - update package list
`sudo apt install nmap` - Install Nmap
`sudo apt install masscan` - Install masscan
`nmap --version` - Verify that nmap is installed
`masscan --version` - Verify that masscan is installed
### What to Do
1. `sudo masscan <target-subnet-or-IP> -p0-65535 --rate=500 --wait=10`
	1. Screenshot the terminal showing the command
	2. Screenshot the initial output showing open ports
2. `sudo nmap -sS -sV -T4 -Pn -p <open-ports> <target-IPs>`
	1. Screenshot the terminal showing the command
	2. Screenshot the output showing service name and version info
3. `sudo nmap -sU -T4 --top-ports 10 <target-IPs>`
	1. Screenshot the terminal showing the command
	2. Screenshot any discovered UDP services (even if none are found, take a screenshot)
### Required table to build
| Host IP | Port | Protocol | Service | Needed Externally? | Recommendation       |
| ------- | ---- | -------- | ------- | ------------------ | -------------------- |
| ...     | ...  | ...      | ...     | <Yes/No>           | \<What will be done> |
### Response

Executive Summary
- Evaluated exposed services on perimeter firewalls
- Identified unnecessary services that were revealed in the scans
- The recommendations we conclude to reduce attack surface
Methodology
1. Masscan used for rapid discovery
	1. Document exact command
	2. Send screenshot of the result
2. Nmap TCP scans for service identification
	1. Document exact command
	2. Send screenshot of the result
3. Nmap UDP scans for common high-risk services
	1. Document exact command
	2. Send screenshot of the result
Findings
- Table you built
Risk analysis
- Admin services exposed = high risk
- Legacy protocols = medium risk
Recommendations
- Restrict management access
- Disable unused services
- Apply firewall rule refinement

## EVAL07T - Audit & Enumerate Needed Services

### Ecom (Ubuntu 24)

| Direction | Service                   | Protocol / Port      | Source / Destination  | Internal / External | Notes                  |
| --------- | ------------------------- | -------------------- | --------------------- | ------------------- | ---------------------- |
| Inbound   | SMTP (mail receive)       | TCP 25               | Internet mail servers | External            | Receive external email |
| Inbound   | Submission (mail send)    | TCP 587              | Internal users        | Internal            | Secure mail submission |
| Inbound   | POP3                      | TCP 110 / 995 (SSL)  | Internal users        | Internal            | Email retrieval tested |
| Outbound  | SMTP relay                | TCP 25               | External mail servers | External            | Send mail externally   |
| Outbound  | DNS                       | UDP/TCP 53           | Internal DNS          | Internal            | Resolve mail domains   |
| Outbound  | Wazuh Agent Communication | TCP 1514 / TCP 55000 | Splunk/Wazuh Manager  | Internal            | Send logs and alerts   |
### Webmail (Fedora 42)
| Direction | Service                   | Protocol / Port      | Source / Destination | Internal / External | Notes                        |
| --------- | ------------------------- | -------------------- | -------------------- | ------------------- | ---------------------------- |
| Inbound   | HTTP / HTTPS              | TCP 80 / 443         | Internal users       | Internal            | Webmail interface            |
| Outbound  | POP3 / SMTP               | TCP 110 / 587        | Email Server         | Internal            | Email delivery and retrieval |
| Outbound  | DNS                       | UDP/TCP 53           | Internal DNS         | Internal            | Service name resolution      |
| Outbound  | Wazuh Agent Communication | TCP 1514 / TCP 55000 | Splunk/Wazuh Manager | Internal            | Send logs and alerts         |
### Splunk / Wazuh Manager Server (Ubuntu 24)

| Direction | Service                   | Protocol / Port      | Source / Destination              | Internal / External | Notes                               |
| --------- | ------------------------- | -------------------- | --------------------------------- | ------------------- | ----------------------------------- |
| Inbound   | Wazuh Agent Communication | TCP 1514 / TCP 55000 | All internal hosts (Wazuh agents) | Internal            | Receive logs and alerts from agents |
| Inbound   | Log Ingest (Splunk)       | TCP 9997             | All servers                       | Internal            | Splunk log ingestion                |
| Inbound   | Web UI                    | TCP 8000 / HTTPS 443 | Admin workstations                | Internal            | Splunk/Wazuh web interface          |
| Outbound  | DNS                       | UDP/TCP 53           | Internal DNS                      | Internal            | Name resolution                     |
| Outbound  | Updates                   | HTTPS 443            | External Splunk repositories      | External            | Product updates and threat feeds    |
### Web Server (Windows Server 2019)
|Direction|Service|Protocol / Port|Source / Destination|Internal / External|Notes|
|---|---|---|---|---|---|
|Inbound|HTTP / HTTPS|TCP 80 / 443|Internal & External users|Both|Serve tested webpages|
|Outbound|DNS|UDP/TCP 53|Internal DNS|Internal|Resolve domain names|
|Outbound|Wazuh Agent Communication|TCP 1514 / TCP 55000|Splunk/Wazuh Manager|Internal|Send logs and alerts|
### FTP Server (Windows Server 2022)
| Direction | Service                   | Protocol / Port                 | Source / Destination | Internal / External | Notes                     |
| --------- | ------------------------- | ------------------------------- | -------------------- | ------------------- | ------------------------- |
| Inbound   | FTP control / data        | TCP 21 / TCP 20 / Passive Range | Internal users       | Internal            | Authenticated file access |
| Outbound  | DNS                       | UDP/TCP 53                      | Internal DNS         | Internal            | Resolve domain names      |
| Outbound  | Wazuh Agent Communication | TCP 1514 / TCP 55000            | Splunk/Wazuh Manager | Internal            | Send logs and alerts      |
### AD / DNS Server (Windows Server 2019)
| Direction | Service                   | Protocol / Port      | Source / Destination | Internal / External | Notes                  |
| --------- | ------------------------- | -------------------- | -------------------- | ------------------- | ---------------------- |
| Inbound   | DNS                       | UDP/TCP 53           | All internal hosts   | Internal            | Serve DNS lookups      |
| Outbound  | DNS forwarding            | UDP/TCP 53           | External DNS servers | External            | Resolve Internet names |
| Outbound  | Wazuh Agent Communication | TCP 1514 / TCP 55000 | Splunk/Wazuh Manager | Internal            | Send logs and alerts   |

## SVRA05T - Basic Server Hardening Checklist

### Windows Server Hardening
1. User Account & Access Management
	- Disable the default Guest account
	- Make new administrator account, disable the default
	- Enforce strong password policies
		- minimum: 14 characters
		- complexity: enabled
		- expiration: every 90 days
	- Configure account lockout policy: 3 failed login attempts = 15 minute lockout
	- Apply Least Privilege Principle for all accounts
2. Network and Firewall Configuration
	- Enable Windows Defender Firewall and restricted inbound rules to only required services
	- Disable unnecessary network services (Telnet, SMBv1)
	- Enable logging for failed and successful logins
3. Security Policy & Audit Settings
	- Enable Audit Policy for logon events, account management, and policy changes
	- Configure User Rights Assignment according to CIS benchmarks
	- Enable Windows Defender Antivirus with real-time protection
4. System Updates & Patching
	- Configure automatic updates for Windows and critical applications
	- Verified all servers are patched to latest security updates
5. Additional Hardening Steps
	- Disable unused ports and services
	- Configure security event forwarding to centralized SIEM
	- Implement BitLocker encryption for data drives
### Tools Used
Windows Servers: Microsoft Security Compliance Toolkit, Event Viewer, PowerShell scripts for policy verification

## TOOL23T - Firewall Setup & Configuration
Notice: This section was obtained and polished with the help of AI as no useable free versions of Cisco FTD were able to be found
### Description
Review and modified the security policies of the perimeter firewall in accordance with the analysis of currently exposed services and required services (ingress & egress) for the services and other devices on the internal network. 

Configure the security policies so that only expected outbound and inbound packets are allowed. 

Write the polices at the application-layer as much as possible rather than layer-3 protocol and ports. 

Enable packet inspection as available in the specific firewall’s IPS and scanning features. 

All denied packets should be logged.

### How to do this
1. Access the Cisco FTD Management Console
2. Review Existing Access Control Policies
	- Go to Policies > Access Control
	- Identify the currenr ules governing ingress and egress traffic
	- Take note of the applications, protocols, source/destination IPs, and ports allowed or denied
3. Modify Security Policies to Allow Only Needed Services
	- Add or edit rules to explicitly **allow** only the services required by internal devices
	- Use **application-based rules** rather than generic port/protocol rules to tighten security.
		- Instead of allowing TCP port 80, only allow the HTTP application
	- Define source and destination zones/networks properly to reflect internal and external networks
4. Enable Intrusion Prevention System (IPS) and Packet Inspection **(License given might not allow this)**
	- Within the Access Control policy, enable **IPS Policy** for the rules.
	- Apply a tailored or recommended IPS policy that inspects allowed traffic
	- Enable additional inspection features such as:
		- Malware scanning 
		- File and protocol analysis
		- SSL inspection
	- Set the inspection to **inline*** so that packets are actively scanned and malicious traffic is blocked
5. Configure Logging
	- For all **deny** rules, ensure **logging** is **enabled**
	- This is configured in the Access Control rules under the logging section
	- Make sure logs include dropped packets with timestamps and reasons for denial
6. Test and Validate Configuration
	- Deploy the updated policy
	- Test access to ensure only required services are reachable
	- Monitor logs for denied packets and suspicious activity
7. Document Configuration and Changes
	- Take screenshots of:
		- Original policy summary
		- Modified rules allowing only expected applications
		- IPS policy enabled on rules
		- Logging settings for denied packets
### Example using Cisco FMC UI
- **Policies > Access Control > Select Policy > Rules tab** — Review and edit rules
- **Rules > Add/Edit > Applications tab** — Specify application-layer filtering
- **Rules > Add/Edit > Intrusion Policy** — Enable and select IPS policy
- **Rules > Logging** — Enable logging on deny
## TOOL24T - Define Firewalls on Windows & Linux Servers
### Define Default-Deny Firewall Policies on Each Server
Use Windows Defender Firewall with Advanced Security:
1. Set the Default Inbound Policy to Block (default-deny)
2. Set the Default Outbound Policy to Block (default-deny)
3. Create Inbound Rules to allow only expected traffic
4. Create Outbound Rules for expected outgoing traffic
5. Enable logging of dropped packets:
	1. Go to Properties > Logging
	2. Set Log dropped packets to Yes
	3. Specify the log file location (default: `%systemroot%\system32\LogFiles\Firewall\pfirewall.log`)
### Monitor Logs and Adjust Policies
Regularly review the `pfirewall.log` file.
- Identify legitimate denied packets that need exceptions
- Identify suspicious denied packets for investigation
- Modify firewall rules to allow legitimate flow or escalate suspicious traffic for further analysis
## TOOL25T - Setup Centralized Logging
### Prepare Environment
- Ensure the Splunk/Wazuh Manager machine is reachable from the Windows servers
- Confirm the managers IP address and port Wazuh Manager listens on (default is TCP 1514 for agents)
- Make sure firewall ports are open on both ends
### Download and Install Wazuh Agent on Windows
1. Download the latest Wazuh Agent MSI Installer
2. Run it with administrator
3. During installation, specify the Wazuh Manager IP and port
4. Finish installing and verify that the service starts automatically
### Configure Firewall Rules
- On Windows Servers (agent-side):
	- Open Windows Defender Firewall with Advanced Security
	- Create an Outbound Rule to allow TCP traffic to the Wazuh Manager IP on port 1514
	- Ensure the Wazuh Agent executable is allowed network access
- On the Splunk/Wazuh machine
	- Open Inbound Firewall Rules to allow TCP port 1514
	- Confirm the Wazuh Manager service is listening on this port
### Verify Agent Connectivity
1. Open Powershell as admin
2. Run `sc query wazuh-agent`
	- Confirm that is it running
- You can also check the agent log file at:
  `C:\Program Files (x86)\ossec-agent\ossec.log`  
	or  
	`C:\Program Files\ossec-agent\ossec.log`
- Look for successful connection messages to the manager
### Test Log Forwarding
- Create a test event on the Windows machine using:
		`eventcreate /T INFORMATION /ID 1002 /L APPLICATION /D "Wazuh agent test event from <hostname>"`
- On the splunk interface, verify the event appears (under index or search)
## TOOL26T - Export Firewall Security Policy for Auditors
### Description
Extract the current firewall’s security policy configurations for analysis by an external auditor which we have hired to certify our security posture for a large customer that is important to the organization. Consider the following scripts, noted in the Reference section, for use with Palo Alto and Cisco Fire Power firewalls to accomplish this. Be sure to enable SSH and obtain CLI rights. API rights need to be enabled for Cisco.

### Prerequisites
1. Python
		`python --version` or `python3 --verison`
	1. Installing Python
		1. Download the latest Python 3.x executable installer
		2. Run the installer:
			1. Check the box "Add Python to PATH" at beginning
			2. Choose Install Now
		3. verify Installation
	2. Install the `requests` library
		1. `pip install requests`
2. Network access
	1. Ensure you can reach the Cisco FMC IP via HTTPS
	2. Make sure API access is enabled on the FMC
	3. Admin creds are required
3. Firewall Settings
	1. Ensure your host's firewall allows outbound HTTPS (port 443) to FMC
	2. API access on FMC must be enabled
### Use Provided Python Script
```fmc_export.py
import requests 
import json 

FMC_IP = "192.0.2.10" 
USERNAME = "admin" 
PASSWORD = "yourpassword" 

def get_auth_token(): 
    url = f"https://{FMC_IP}/api/fmc_platform/v1/auth/generatetoken" 
    response = requests.post(url, auth=(USERNAME, PASSWORD), verify=False) 
    token = response.headers["X-auth-access-token"] 
    domain_uuid = response.headers["DOMAIN_UUID"] 
    return token, domain_uuid 

def export_fmc_policies(): 
    token, domain_uuid = get_auth_token() 
    headers = { 
        "X-auth-access-token": token, 
        "Content-Type": "application/json" 
    } 
    url = f"https://{FMC_IP}/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies" 
    resp = requests.get(url, headers=headers, verify=False) 
    policies = resp.json()["items"] 
    for policy in policies: 
        policy_id = policy["id"] 
        policy_name = policy["name"] 
        rules_url = f"https://{FMC_IP}/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{policy_id}/accessrules?limit=1000" 
        rules_resp = requests.get(rules_url, headers=headers, verify=False) 
        rules = rules_resp.json() 
        with open(f"fmc_policy_{policy_name}.json", "w") as f: 
            json.dump(rules, f, indent=2) 
        print(f"Exported policy {policy_name} to fmc_policy_{policy_name}.json") 

if __name__ == "__main__": 
    requests.packages.urllib3.disable_warnings() 
    export_fmc_policies() 

```
1. Save the provided script as `fmc_export.py`
2. Open powershell and run
	`python fmc_export.py`
	- If successful, you should see something like
		`Exported policy 'Perimeter Firewall' to fmc_policy_Perimeter Firewall.json`
		`Exported policy 'Internal Policy' to fmc_policy_Internal Policy.json`
### Verify the Export
- Open any exported JSON file in a text editor to verify that it contains the `accessrules` array and policy details
- Make sure all policies that exist in FMC are exported
- Once verified, export the JSON files to NextCloud

# Troubleshooting Internet Connectivity
1. run `ipconfig /all`
	- DNS server should be the Domain Controller's primary IP
2. `ping 8.8.8.8`
	- works: routing is fine, DNS issue
	- fails: gateway or firewall issue
3. `nslookup google.com`
	- times out: DNS forwarders are missing
	- Non-authoritative answer is fine
4. `ipconfig`
	- Ensure Default Gateway exists
	- Must be valid Default Gateway (routes to internet)
		- `<ip>.2`
	- Ensure no Alternate DNS
## Script for Testing
This script tests for DNS, TCP/HTTPS, HTTP/HTTPS connectivity

```PowerShell
# -------------------------------
# Internet Connectivity Test Script
# For Domain Controllers / Windows Servers
# -------------------------------

# Target host for testing
$HostName = "www.microsoft.com"
$OutputFile = "$env:TEMP\test.ico"

# -------------------------------
# 1. DNS Resolution Test
# -------------------------------
Write-Host "=== DNS Resolution Test ==="
try {
    $ip = Resolve-DnsName $HostName -ErrorAction Stop
    Write-Host "DNS OK: Resolved $HostName to $($ip.IPAddress)"
} catch {
    Write-Host "DNS FAILED: Could not resolve $HostName"
    exit
}

# -------------------------------
# 2. TCP / HTTPS Connectivity Test
# -------------------------------
Write-Host "`n=== TCP/HTTPS Connectivity Test ==="
try {
    $tcpTest = Test-NetConnection -ComputerName $HostName -Port 443
    if ($tcpTest.TcpTestSucceeded) {
        Write-Host "TCP/HTTPS OK: Port 443 reachable"
    } else {
        Write-Host "TCP/HTTPS FAILED: Port 443 not reachable"
        exit
    }
} catch {
    Write-Host "TCP Test ERROR: $_"
    exit
}

# -------------------------------
# 3. HTTP/HTTPS Download Test
# -------------------------------
Write-Host "`n=== HTTP/HTTPS Download Test ==="
try {
    Invoke-WebRequest -Uri "https://$HostName/favicon.ico" -OutFile $OutputFile -UseBasicParsing
    Write-Host "HTTP(S) download OK: File saved to $OutputFile"
} catch {
    Write-Host "HTTP(S) download FAILED: $_"
}

```
# Ensure Same Time zone
In order to update group policy on Domain connected machines, their time zone must be within 5 minutes of the Domain Controller.
Since our competition network is on Central Standard Time (CST), we will:
-  On AD/Domain Controller, run:
```PowerShell
w32tm /config /manualpeerlist:"time.windows.com,0x9 pool.ntp.org,0x9" /syncfromflags:manual /reliable:YES /update
```
- If Domain Joined machine, run:
```cmd
tzutil "Central Standard Time"
```
