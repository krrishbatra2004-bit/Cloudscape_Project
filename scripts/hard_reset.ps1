<#
.SYNOPSIS
    CloudScape Nexus 5.2 - TITAN HARD RESET (SCORCHED EARTH)

.DESCRIPTION
    Performs absolute annihilation of the CloudScape Nexus state.
    WARNING: THIS IS IRREVERSIBLE.
    
    Features:
    - Destroys all running containers, networks, AND anonymous/named volumes attached to the mesh.
    - Obliterates the Python Virtual Environment (.venv).
    - Recursively hunts and destroys all Python bytecode (__pycache__ / .pyc).
    - Wipes out all local forensic logs, exported JSON reports, and caches.
    - Performs an aggressive Docker system prune (dangling images/build caches).
    - Purges the complete graph database and LocalStack local data volumes.

.PARAMETER Confirm
    Requires user confirmation to prevent accidental detonation. Pass -Force to bypass.

.PARAMETER BypassConfirmation
    Bypasses the safety confirmation prompt.

.EXAMPLE
    .\hard_reset.ps1 -BypassConfirmation
    Executes scorched earth without prompting.
#>
[CmdletBinding()]
Param(
    [switch]$BypassConfirmation,
    [switch]$VerboseUI
)

$ErrorActionPreference = "Stop"

function Write-Echo {
    param([string]$Message, [string]$Level="INFO")
    $Color = switch($Level) {
        "INFO" { "White" }
        "WARN" { "Yellow" }
        "CRIT" { "Red" }
        "DONE" { "Green" }
    }
    Write-Host "[$Level] $Message" -ForegroundColor $Color
}

Write-Host @"
   _____  _____  ____  _____   _____  _    _  ______  _____  
  / ____|/ ____|/ __ \|  __ \ / ____|| |  | ||  ____||  __ \ 
 | (___ | |    | |  | | |__) | (___  | |__| || |__   | |__) |
  \___ \| |    | |  | |  _  / \___ \ |  __  ||  __|  |  _  / 
  ____) | |____| |__| | | \ \ ____) || |  | || |____ | | \ \ 
 |_____/ \_____|\____/|_|  \_|_____/ |_|  |_||______||_|  \_\
                                                             
        T I T A N   S C O R C H E D   E A R T H   P R O T O C O L
"@ -ForegroundColor Red

if (-not $BypassConfirmation) {
    Write-Echo "WARNING: This will DESTROY ALL GRAPH DATA, VENV, CONTAINERS, AND VOLUMES." "CRIT"
    $Response = Read-Host "Type 'ANNIHILATE' to proceed"
    if ($Response -cne "ANNIHILATE") {
        Write-Echo "Abort sequence accepted. Returning to safety." "DONE"
        exit 0
    }
}

$Global:RootDir = (Get-Item $PSScriptRoot).Parent.FullName

try {
    # 1. DOCKER OBLITERATION
    Write-Echo "Executing Docker Volume & Container Destruction Phase..." "WARN"
    cd $Global:RootDir
    
    # Down with volumes and orphans
    docker compose down -v --remove-orphans
    
    # Aggressive system prune for dangling assets
    Write-Echo "Purging dangling Docker caches and builder networks..." "WARN"
    docker system prune -f --volumes
    Write-Echo "Docker matrix eradicated." "DONE"


    # 2. PYTHON VIRTUAL ENVIRONMENT PURGE
    Write-Echo "Targeting Python Virtual Ecosystem (.venv)..." "WARN"
    $VenvPath = Join-Path $Global:RootDir ".venv"
    if (Test-Path $VenvPath) {
        Remove-Item -Path $VenvPath -Recurse -Force
        Write-Echo "Virtual Environment disintegrated." "DONE"
    } else {
        Write-Echo "Virtual Environment already barren." "INFO"
    }


    # 3. BYTECODE HUNT & DESTROY
    Write-Echo "Executing recursive bytecode (__pycache__) extermination..." "WARN"
    $Pycaches = Get-ChildItem -Path $Global:RootDir -Recurse -Filter "__pycache__" -Directory -ErrorAction SilentlyContinue
    $Count = 0
    foreach ($Cache in $Pycaches) {
        Remove-Item -Path $Cache.FullName -Recurse -Force
        $Count++
    }
    Write-Echo "Liquidated $Count bytecode clusters." "DONE"


    # 4. FORENSIC ARTIFACT PURGE
    Write-Echo "Obliterating Local Persistent States & Logs..." "WARN"
    $ToDestroy = @(
        "forensics\logs\*",
        "forensics\reports\*",
        "volume\neo4j\*",
        "volume\localstack\*"
    )
    
    $ArtifactCount = 0
    foreach ($T in $ToDestroy) {
        $TargetPath = Join-Path $Global:RootDir $T
        if (Test-Path $TargetPath) {
            Remove-Item -Path $TargetPath -Recurse -Force -ErrorAction SilentlyContinue
            $ArtifactCount++
        }
    }
    Write-Echo "Erased $ArtifactCount forensic and volume persistence paths." "DONE"

    
    # 5. ORPHAN PYTHON MURDER
    Write-Echo "Scanning for memory-resident orphans..." "WARN"
    $Orphans = Get-Process -Name "python" -ErrorAction SilentlyContinue
    foreach ($O in $Orphans) {
        Stop-Process -Id $O.Id -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host "`n"
    Write-Echo "SYSTEM NULLIFIED. SCORCHED EARTH COMPLETE. READY FOR GENESIS." "CRIT"

} catch {
    Write-Echo "AN ERROR FRAGMENTED THE ANNIHILATION SEQUENCE: $_" "CRIT"
    exit 1
}
exit 0
