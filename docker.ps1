# Ensure the script is running as Administrator
$elevated = [bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-Not $elevated) {
    Write-Host "Please run this script as an Administrator!" -ForegroundColor Red
    Exit
}

# Disables the download progress bar
# This significantly speeds up download speeds
$ProgressPreference = 'SilentlyContinue'
Write-Host "Disabled progress bar"

# Install the DockerMsftProvider Module
Write-Host "Installing DockerMsftProvider Module"
Install-Module DockerMsftProvider -Force
if (Get-Module -ListAvailable -Name DockerMsftProvider) {
	Write-Host "Module Successfully Installed"
} else {
	Write-Host "Module Installation Failed"
}

# Download the Docker Install Script
Write-Host "Downloading Docker Install Script"
Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1" -o install-docker-ce.ps1
$path = "$env:USERPROFILE\install-docker-ce.ps1"
if (Test-Path $path) {
    Write-Host "Docker Script Installed at: $path"

    # Execute the Script
    & $path

    # Verify Installation
    try {
        $dockerVersion = docker --version
        if ($dockerVersion){
            Write-Host "Docker is installed: $dockerVersion"
        }else{
            Write-Host "Docker is not installed"
            Exit
        }
    }catch{
        Write-Host "Docker is not installed or not found in the system path"
        Exit
    } else {
        Write-Host "Docker Script Installation Failed"
        Exit
    }
}
