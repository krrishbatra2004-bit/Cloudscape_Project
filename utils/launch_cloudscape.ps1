# ==============================================================================
# PROJECT CLOUDSCAPE: 2026 ENTERPRISE LAUNCHER (OPTIMIZED)
# ==============================================================================

function Show-Header {
    Clear-Host
    Write-Host "====================================================================" -ForegroundColor Cyan
    Write-Host "   PROJECT CLOUDSCAPE: MULTI-TENANT GRAPH ORCHESTRATOR v2.0" -ForegroundColor Cyan
    Write-Host "====================================================================" -ForegroundColor Cyan
}

Show-Header

# 1. ENVIRONMENT VALIDATION
Write-Host "[1/4] Validating Virtual Environment..." -ForegroundColor White
if ($null -eq $env:VIRTUAL_ENV) {
    if (Test-Path ".\.venv\Scripts\Activate.ps1") {
        . .\.venv\Scripts\Activate.ps1
        Write-Host "[OK] .venv activated successfully." -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Virtual Environment not detected! Run 'python -m venv .venv'" -ForegroundColor Red
        exit
    }
}

# 2. PATH CONFIGURATION
Write-Host "[2/4] Configuring Global PYTHONPATH..." -ForegroundColor White
$env:PYTHONPATH = "D:\Cloudscape_Project"
Write-Host "[OK] Source root set to $env:PYTHONPATH" -ForegroundColor Green

# 3. DOCKER BOOTSTRAP
Write-Host "[3/4] Initializing Cloud Mock Infrastructure..." -ForegroundColor White
docker-compose up -d --wait

# 4. SERVICE HEARTBEAT VERIFICATION
Write-Host "[4/4] Performing Service Health Checks..." -ForegroundColor White

$Services = @(
    @{ Name = "Neo4j API"; Url = "http://localhost:7474"; Color = "Yellow" },
    @{ Name = "AWS Finance (Port 4566)"; Url = "http://localhost:4566/_localstack/health"; Color = "Blue" },
    @{ Name = "AWS Prod (Port 4567)"; Url = "http://localhost:4567/_localstack/health"; Color = "Blue" }
)

foreach ($Service in $Services) {
    $Success = $false
    # Increased to 25 retries (75 seconds total) for slower system initializations
    for ($i=1; $i -le 25; $i++) {
        try {
            # UseBasicParsing avoids the IE engine security popup
            $Check = Invoke-WebRequest -Uri $Service.Url -Method Get -TimeoutSec 2 -ErrorAction Stop -UseBasicParsing
            Write-Host "[READY] $($Service.Name) is responding." -ForegroundColor Green
            $Success = $true
            break
        } catch {
            Write-Host "[-] Waiting for $($Service.Name)... ($i/25)" -ForegroundColor $($Service.Color)
            Start-Sleep -Seconds 3
        }
    }
    if (-not $Success) {
        Write-Host "[FATAL] $($Service.Name) failed to start. Check docker logs." -ForegroundColor Red
        exit
    }
}

Write-Host "`n--- [ ALL SYSTEMS OPERATIONAL ] ---" -ForegroundColor Green -BackgroundColor Black
Write-Host "Run: python main.py --mode seed" -ForegroundColor Cyan