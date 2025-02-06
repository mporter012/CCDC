# Download the most recent version of the Wazuh windows agent
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi" -Outfile "$env:USERPROFILE\wazuh-agent-4.9.2-1.msi"

# Install the agent with all options presented.
& "$env:USERPROFILE\wazuh-agent-4.9.2-1.msi" /q WAZUH_MANAGER="172.20.241.20" WAZUH_MANAGER_PORT="514" WAZUH_PROTOCOL="UDP" 

# Check if the Wazuh Agent service exists
$Service = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue

if ($Service) {
    # If the service exists, check its status
    if ($Service.Status -eq "Stopped"){
        Write-Host "Wazuh Agent service is stopped. Starting it now..." -ForegroundColor Yellow
        Start-Service -Name WazuhSvc
        Write-Host "Wazuh Agent service started successfully." -ForegroundColor Green
    }
    elseif ($Service.Status -eq "Running") {
        Write-Host "Wazuh Agent is already running." -ForegroundColor Cyan
    }
} else {
    Write-Host "Wazuh Agent service is NOT installed!" -ForegroundColor Red
}
