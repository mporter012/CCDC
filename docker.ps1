# Ensure the script runs with administrative privileges
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as an Administrator."; exit 1
}

# Install required packages and components
Write-Host "Installing required packages..."
Install-WindowsFeature -Name Containers -IncludeAllSubFeature -IncludeManagementTools

# Enable Hyper-V feature
Write-Host "Enabling Hyper-V feature..."
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart:$false

# Add Docker's repository key
Write-Host "Adding Docker's repository key..."
Invoke-WebRequest -Uri https://download.docker.com/windows/ee/docker-ee.repo -OutFile "$env:TEMP\docker-ee.repo"

# Install Docker EE
Write-Host "Installing Docker EE..."
$repositoryUrl = "https://download.docker.com/windows/ee"
Install-PackageProvider -Name NuGet -Force -Scope CurrentUser
Register-PackageSource -Name DockerEE -Location $repositoryUrl -ProviderName NuGet -Trusted

# Install Docker from the repository
Install-Package -Name docker -Source DockerEE -Force

# Start and configure Docker service
Write-Host "Starting and configuring Docker service..."
Start-Service Docker
Set-Service -Name Docker -StartupType Automatic

# Verify Docker installation
Write-Host "Verifying Docker installation..."
docker --version

Write-Host "Docker EE installation completed successfully."
