# Ensure the script is running as Administrator
$elevated = [bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-Not $elevated) {
    Write-Host "Please run this script as an Administrator!" -ForegroundColor Red
    Exit
}

# Enable required Windows features
Write-Host "Installing required Windows features..." -ForegroundColor Yellow
Install-WindowsFeature -Name Containers -Restart:$false
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart:$false

# Install DockerMsftProvider
Write-Host "Installing Docker Provider..." -ForegroundColor Yellow
Install-Module -Name DockerMsftProvider -Repository PSGallery -Force

# Install Docker
Write-Host "Installing Docker..." -ForegroundColor Yellow
Install-Package -Name docker -ProviderName DockerMsftProvider -Force

# Restart the system to apply changes
Write-Host "Installation complete. A restart is required for Docker to function properly." -ForegroundColor Green
$restart = Read-Host "Do you want to restart now? (Y/N)"
if ($restart -match "[Yy]") {
    Restart-Computer -Force
} else {
    Write-Host "Please restart your server manually to complete the installation." -ForegroundColor Yellow
}
