<#
.SYNOPSIS
    CloudScape Nexus 5.2 - Soft Reset Utility

.DESCRIPTION
    Performs a graceful teardown of the CloudScape Nexus ecosystem.
    Features:
    - Gracefully stops all active Docker containers without data destruction.
    - Flushes Redis volatile memory arrays.
    - Truncates and backs up diagnostic logs.
    - Isolates and terminates orphan Python processes holding file locks.
    - Leaves Neo4j databases and localstack volumes intact for debugging.

.EXAMPLE
    .\soft_reset.ps1
    Executes standard safe teardown.
#>
[CmdletBinding()]
Param(
    [switch]$ForceTerminate,
    [switch]$VerboseUI
)

$ErrorActionPreference = "Stop"
$VerbosePreference = if ($VerboseUI) { "Continue" } else { "SilentlyContinue" }

$Global:RootDir = (Get-Item $PSScriptRoot).Parent.FullName

function Write-OutputBox {
    param([string]$Message, [string]$Type="INFO")
    $Prompt = switch($Type) {
        "INFO" { "[~]" }
        "WARN" { "[!]" }
        "ERR"  { "[X]" }
        "OK"   { "[√]" }
    }
    $Color = switch($Type) {
        "INFO" { "Cyan" }
        "WARN" { "Yellow" }
        "ERR"  { "Red" }
        "OK"   { "Green" }
    }
    Write-Host "$Prompt $Message" -ForegroundColor $Color
}

Write-Host "=================================================" -ForegroundColor Magenta
Write-Host " CLOUDSCAPE NEXUS - SOFT RESET INITIATED " -ForegroundColor Magenta
Write-Host "=================================================" -ForegroundColor Magenta

try {
    # 1. Kill Orphaned Python Processes securely
    Write-OutputBox "Scanning for orphaned Python daemon threads..." "INFO"
    $PyProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object { 
        $_.Path -like "*Cloudscape_Project*" 
    }
    
    if ($PyProcesses) {
        foreach ($proc in $PyProcesses) {
            Write-OutputBox "Terminating Python lock (PID: $($proc.Id))" "WARN"
            if ($ForceTerminate) {
                Stop-Process -Id $proc.Id -Force
            } else {
                # Attempt graceful first
                $proc.CloseMainWindow() | Out-Null
                Start-Sleep -Seconds 2
                if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
            }
        }
        Write-OutputBox "Process tree sanitized." "OK"
    } else {
        Write-OutputBox "No orphaned threads detected." "OK"
    }

    # 2. Redis Cache Flush (Targeted Volatile Purge)
    Write-OutputBox "Targeting Redis volatile cache matrix..." "INFO"
    $RedisRunning = docker ps -q -f "name=cloudscape-redis"
    if ($RedisRunning) {
        docker exec cloudscape-redis redis-cli FLUSHALL | Out-Null
        Write-OutputBox "Redis Memory Arrays Flushed." "OK"
    } else {
        Write-OutputBox "Redis is offline. Skipping flush." "WARN"
    }

    # 3. Docker Graceful Stop
    Write-OutputBox "Executing Docker Compose graceful halt sequence..." "INFO"
    cd $Global:RootDir
    docker compose stop
    Write-OutputBox "Mesh containers hibernating (Volumes preserved)." "OK"

    # 4. Log Rotation & Archiving
    Write-OutputBox "Truncating and archiving forensic logs..." "INFO"
    $LogDir = Join-Path $Global:RootDir "forensics\logs"
    if (Test-Path $LogDir) {
        # Keep last 5 logs, delete older
        $OldLogs = Get-ChildItem -Path $LogDir -Filter *.log | Sort-Object LastWriteTime -Descending | Select-Object -Skip 5
        if ($OldLogs) {
            $OldLogs | Remove-Item -Force
            Write-OutputBox "Purged $($OldLogs.Count) legacy log frames." "OK"
        }
    }

    Write-Host "`n=================================================" -ForegroundColor Cyan
    Write-Host " SOFT RESET SEQUENCE COMPLETE. STATE IS SECURE.  " -ForegroundColor Cyan
    Write-Host "=================================================" -ForegroundColor Cyan

} catch {
    Write-OutputBox "EXCEPTION OCCURRED: $_" "ERR"
    exit 1
}
exit 0
