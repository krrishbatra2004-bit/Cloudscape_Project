$ErrorActionPreference = "SilentlyContinue"

Write-Host "--- PROJECT CLOUDSCAPE: SYSTEM PURGE ---" -ForegroundColor Cyan

Write-Host "1. Cleaning Processes..." -ForegroundColor Yellow
docker compose down --volumes --remove-orphans
wsl --shutdown
Stop-Process -Name "Docker Desktop" -Force
Stop-Process -Name "com.docker.backend" -Force
Stop-Process -Name "wslhost" -Force

Write-Host "2. Clearing WSL Registry..." -ForegroundColor Yellow
wsl --unregister docker-desktop
wsl --unregister docker-desktop-data

Write-Host "3. Wiping E: Drive Vault..." -ForegroundColor Yellow
Remove-Item -Path "E:\Cloudscape_Data\DockerDesktopWSL\*" -Recurse -Force

Write-Host "4. Rebuilding Folders..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path "E:\Cloudscape_Data\DockerDesktopWSL"
New-Item -ItemType Directory -Force -Path "E:\Cloudscape_Data\DockerDesktopWSL\manifests"
New-Item -ItemType Directory -Force -Path "E:\Cloudscape_Data\DockerDesktopWSL\logs"
New-Item -ItemType Directory -Force -Path "E:\Cloudscape_Data\DockerDesktopWSL\moto_data"
New-Item -ItemType Directory -Force -Path "E:\Cloudscape_Data\DockerDesktopWSL\neo4j_data"
New-Item -ItemType Directory -Force -Path "E:\Cloudscape_Data\DockerDesktopWSL\disk"

Write-Host "--- RESET COMPLETE ---" -ForegroundColor Cyan