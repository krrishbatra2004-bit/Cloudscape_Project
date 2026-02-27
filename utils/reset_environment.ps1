# ==============================================================================
# PROJECT CLOUDSCAPE: SYSTEM DEEP-CLEAN & RESET
# ==============================================================================

Write-Host "`n--- [PHASE 1: DOCKER TERMINATION] ---" -ForegroundColor Cyan

# 1. Stop all containers and remove volumes (wipes Neo4j and LocalStack state)
Write-Host "[*] Stopping containers and wiping volumes..." -ForegroundColor Yellow
docker-compose down -v

# 2. Prune orphan networks that might cause IP conflicts
Write-Host "[*] Cleaning orphan networks..." -ForegroundColor Yellow
docker network prune -f

Write-Host "`n--- [PHASE 2: FILESYSTEM SANITATION] ---" -ForegroundColor Cyan

# 3. Recursively remove all __pycache__ folders to prevent import logic errors
Write-Host "[*] Purging Python bytecode caches..." -ForegroundColor Yellow
Get-ChildItem -Path . -Include __pycache__ -Recurse | Remove-Item -Recurse -Force

# 4. Remove temporary log and data files from the forensic tier (E: Drive or local)
Write-Host "[*] Clearing temporary logs..." -ForegroundColor Yellow
Remove-Item -Path ".\logs\*" -Filter *.log -ErrorAction SilentlyContinue

Write-Host "`n[SUCCESS] Environment is now pristine. Run launch/cloudscape.ps1 next." -ForegroundColor Green