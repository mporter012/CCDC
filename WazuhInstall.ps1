﻿# TODO: Add WAZUH_AGENT_GROUP value to the CLI command call

# Download the most recent version of the Wazuh windows agent
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi" -Outfile C:\Users\ccdc\wazuh-agent-4.9.2-1.msi

# Install the agent with all options presented.
C:\Users\ccdc\wazuh-agent-4.9.2-1.msi /q WAZUH_MANAGER="172.20.241.20" WAZUH_MANAGER_PORT="514" WAZUH_PROTOCOL="UDP" 