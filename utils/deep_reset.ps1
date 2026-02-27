# ==============================================================================
# PROJECT CLOUDSCAPE: 2026 ULTIMATE DEEP CLEAN & RE-INITIALIZER
# ==============================================================================

Write-Host "`n[!] INITIALIZING PROJECT SANITIZATION..." -ForegroundColor Red -BackgroundColor Black

# 1. FORCE KILL DOCKER STACK
Write-Host "[*] Purging Docker Mesh and Volumes..." -ForegroundColor Yellow
docker-compose down -v --remove-orphans
docker system prune --volumes -f  # Force clear any dangling cache

# 2. PORT SANITATION (Ensure no ghost processes)
$Ports = @(4566, 4567, 4568, 7474, 7687, 8501, 10000)
Write-Host "[*] Checking for port conflicts on: $Ports" -ForegroundColor Yellow
foreach ($Port in $Ports) {
    $Process = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if ($Process) {
        Write-Host "[!] Found process $($Process.OwningProcess) on port $Port. Terminating..." -ForegroundColor Red
        Stop-Process -Id $Process.OwningProcess -Force -ErrorAction SilentlyContinue
    }
}

# 3. FILESYSTEM RE-INITIALIZATION
Write-Host "[*] Re-building Python Package Structure..." -ForegroundColor Yellow
$Folders = @(
    "core", "core/processor", "core/correlation", "core/simulation", 
    "engines", "dashboard", "registry", "utils", "logs"
)

foreach ($Folder in $Folders) {
    $Path = Join-Path "D:\Cloudscape_Project" $Folder
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Host "[+] Created Folder: $Folder" -ForegroundColor Cyan
    }
    # Ensure every folder is a valid Python package
    $InitPath = Join-Path $Path "__init__.py"
    if (-not (Test-Path $InitPath)) {
        New-Item -ItemType File -Path $InitPath -Force | Out-Null
        Write-Host "[+] Created Package Init: $Folder/__init__.py" -ForegroundColor Cyan
    }
}

# 4. PYCACHE & LOG PURGE
Write-Host "[*] Cleaning up metadata and legacy logs..." -ForegroundColor Yellow
Get-ChildItem -Path . -Include __pycache__ -Recurse | Remove-Item -Recurse -Force
if (Test-Path ".\logs") { Remove-Item ".\logs\*" -Include *.log -Force -ErrorAction SilentlyContinue }

Write-Host "`n[SUCCESS] Project Cloudscape is now in a PRISTINE state." -ForegroundColor Green
Write-Host "Next Step: Run .\utils\launch_cloudscape.ps1" -ForegroundColor White