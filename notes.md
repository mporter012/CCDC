# Scripts
- [ ] Audit (AD & Non-AD)
- [ ] Installing & Running ClamAV
- [ ] Basic hardening (AD & Non-AD)
- [ ] Installing the Wazuh Agent
- [ ] Getting Inventory
- [ ] Changing login banner

# Things to Research
- How to allow the Wazuh Manager (on Splunk) to communicate with the agents under the cisco firewall
- Research how to make a script that will return the items needed for inventory
- How to lock down the AD/DNS machine
- How to use Cisco FTD 
	- Limiting connections/actions of users
	- Monitoring packets
	- What ports to shut down
	- If/how to run a script to apply changes quickly

# Injects

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
