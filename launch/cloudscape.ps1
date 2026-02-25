Write-Host "--- [PROJECT CLOUDSCAPE: SESSION INITIALIZER] ---" -ForegroundColor Cyan

# 1. FIX PATH FOR THIS SESSION ONLY (Logic Layer)
$env:Path += ";C:\Program Files\Docker\Docker\resources\bin;C:\Program Data\DockerDesktop\version-bin"

# 2. ACTIVATE VIRTUAL ENVIRONMENT
if (Test-Path ".\.venv\Scripts\Activate.ps1") {
    .\.venv\Scripts\Activate.ps1
    Write-Host "[OK] Virtual Environment Active." -ForegroundColor Green
} else {
    Write-Host "[FAIL] .venv missing! Run 'python -m venv .venv' first." -ForegroundColor Red
    exit
}

# 3. VERIFY DOCKER ENGINE
$dockerCheck = docker info
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Docker Engine is not running. Please start Docker Desktop!" -ForegroundColor Red
    exit
}

# 4. START LOCALSTACK (Persistence on E:)
Write-Host "[OK] Docker detected. Starting LocalStack..." -ForegroundColor Yellow
docker compose up -d

Write-Host "--- [ENVIRONMENT READY] ---" -ForegroundColor Green
Write-Host "Run 'python main.py' to start Phase 1." -ForegroundColor White