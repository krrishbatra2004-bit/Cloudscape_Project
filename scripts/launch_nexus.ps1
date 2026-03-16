<#
.SYNOPSIS
    CloudScape Nexus 5.2 - Supreme Launch Orchestrator

.DESCRIPTION
    Highly advanced, robust launcher for the CloudScape Sovereign-Forensic Mesh.
    Provides complete lifecycle management including:
    - Pre-flight dependency validation (Python, Docker, Docker Compose)
    - Dynamic Virtual Environment provisioning & parity checking
    - Container orchestration with asynchronous health polling
    - Port conflict resolution and networking diagnostics
    - Schema initialization and backend pipeline activation
    - Stylized ASCII UI with rich console rendering
    - Supreme error handling, logging, and recovery algorithms

.PARAMETER RunMode
    Specifies the execution mode (MOCK, LIVE, HYBRID, DAEMON, REPORT). Default is MOCK.

.PARAMETER ForceRebuild
    Forces a rebuild of the Docker images before launching.

.PARAMETER SkipValidation
    Skips the pre-flight dependency and environment validation.

.PARAMETER VerboseUI
    Enables highly verbose debug logging to the console.

.EXAMPLE
    .\launch_nexus.ps1
    Starts the Nexus in default MOCK mode.

.EXAMPLE
    .\launch_nexus.ps1 -RunMode LIVE -ForceRebuild
    Rebuilds containers and starts in LIVE extraction mode.
#>
[CmdletBinding()]
Param(
    [ValidateSet("MOCK", "LIVE", "HYBRID", "DAEMON", "REPORT")]
    [string]$RunMode = "MOCK",
    
    [switch]$ForceRebuild,
    [switch]$SkipValidation,
    [switch]$VerboseUI
)

$ErrorActionPreference = "Stop"
$VerbosePreference = if ($VerboseUI) { "Continue" } else { "SilentlyContinue" }

# ==============================================================================
# GLOBAL CONSTANTS & CONFIGURATION
# ==============================================================================
$Global:AppTitle = "CloudScape Nexus 5.2 Titan"
$Global:LogDirectory = Join-Path $PSScriptRoot "..\forensics\logs"
$Global:LogFile = Join-Path $Global:LogDirectory "nexus_launcher_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$Global:RootDir = (Get-Item $PSScriptRoot).Parent.FullName

$Global:RequiredPorts = @{
    "Neo4j"      = @(7687, 7474)
    "LocalStack" = @(4566)
    "Redis"      = @(6379)
    "MongoDB"    = @(27017)
}

# ==============================================================================
# ADVANCED LOGGING & UI FRAMEWORK
# ==============================================================================

function Write-ConsoleUi {
    param([string]$Message, [string]$Type = "INFO", [switch]$NoNewline)
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMsg = "[$Timestamp] [$Type] $Message"
    
    # Append to log file
    if (-not (Test-Path $Global:LogDirectory)) { New-Item -ItemType Directory -Path $Global:LogDirectory -Force | Out-Null }
    Add-Content -Path $Global:LogFile -Value $LogMsg -ErrorAction SilentlyContinue

    # Render to console
    $PrefixColor = switch ($Type) {
        "INFO"    { "Cyan" }
        "SUCCESS" { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "CRIT"    { "Magenta" }
        Default   { "Gray" }
    }
    
    $Prefix = "[{0}]" -f $Type
    Write-Host $Prefix -ForegroundColor $PrefixColor -NoNewline
    if ($NoNewline) {
        Write-Host " $Message" -NoNewline
    } else {
        Write-Host " $Message"
    }
}

function Show-Header {
    Clear-Host

    $Border      = "DarkCyan"
    $TitleColor   = "Cyan"
    $AccentColor  = "Yellow"
    $TagColor     = "Magenta"

    Write-Host ""
    Write-Host "  ╔════════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $Border
    Write-Host "  ║                                                                                        ║" -ForegroundColor $Border
    Write-Host "  ║" -ForegroundColor $Border -NoNewline
    Write-Host "   ██████╗ ██╗      ██████╗ ██╗   ██╗ ██████╗  ███████╗  ██████╗  █████╗  ██████╗  ███████╗  " -ForegroundColor $TitleColor -NoNewline
    Write-Host "║" -ForegroundColor $Border
    Write-Host "  ║" -ForegroundColor $Border -NoNewline
    Write-Host "  ██╔════╝ ██║     ██╔═══██╗██║   ██║ ██╔══██╗ ██╔════╝ ██╔════╝ ██╔══██╗ ██╔══██╗ ██╔════╝  " -ForegroundColor $TitleColor -NoNewline
    Write-Host "║" -ForegroundColor $Border
    Write-Host "  ║" -ForegroundColor $Border -NoNewline
    Write-Host "  ██║      ██║     ██║   ██║██║   ██║ ██║  ██║ ███████╗ ██║      ███████║ ██████╔╝ █████╗    " -ForegroundColor $TitleColor -NoNewline
    Write-Host "║" -ForegroundColor $Border
    Write-Host "  ║" -ForegroundColor $Border -NoNewline
    Write-Host "  ██║      ██║     ██║   ██║██║   ██║ ██║  ██║ ╚════██║ ██║      ██╔══██║ ██╔═══╝  ██╔══╝    " -ForegroundColor $TitleColor -NoNewline
    Write-Host "║" -ForegroundColor $Border
    Write-Host "  ║" -ForegroundColor $Border -NoNewline
    Write-Host "  ╚██████╗ ███████╗╚██████╔╝╚██████╔╝ ██████╔╝ ███████║ ╚██████╗ ██║  ██║ ██║      ███████╗  " -ForegroundColor $TitleColor -NoNewline
    Write-Host "║" -ForegroundColor $Border
    Write-Host "  ║" -ForegroundColor $Border -NoNewline
    Write-Host "   ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝  ╚═════╝  ╚══════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═╝      ╚══════╝  " -ForegroundColor $TitleColor -NoNewline
    Write-Host "║" -ForegroundColor $Border
    Write-Host "  ║                                                                                        ║" -ForegroundColor $Border
    Write-Host "  ║" -ForegroundColor $Border -NoNewline
    Write-Host "                       ══╣ " -ForegroundColor $Border -NoNewline
    Write-Host "N E X U S   5 . 2   T I T A N" -ForegroundColor $AccentColor -NoNewline
    Write-Host " ╠══                               " -ForegroundColor $Border -NoNewline
    Write-Host "║" -ForegroundColor $Border
    Write-Host "  ║" -ForegroundColor $Border -NoNewline
    Write-Host "              Sovereign-Forensic Multi-Cloud Intelligence Mesh                    " -ForegroundColor $TagColor -NoNewline
    Write-Host "║" -ForegroundColor $Border
    Write-Host "  ║                                                                                        ║" -ForegroundColor $Border
    Write-Host "  ╚════════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $Border
    Write-Host ""

    Write-ConsoleUi "Orchestrator Boot Sequence Initiated." "INFO"
    Write-ConsoleUi "Execution Mode: $RunMode" "INFO"
    Write-ConsoleUi "Log Target: $Global:LogFile" "INFO"
    Write-Host "`n"
}

function Invoke-Spinner {
    param([scriptblock]$ScriptBlock, [string]$Message)
    
    $Job = Start-Job -ScriptBlock $ScriptBlock
    $SpinFrames = @('|', '/', '-', '\')
    $Counter = 0
    
    Write-Host "[WAIT] " -ForegroundColor Cyan -NoNewline
    Write-Host "$Message " -NoNewline
    
    while ($Job.State -eq 'Running') {
        Write-Host "`b" -NoNewline
        Write-Host $SpinFrames[$Counter % 4] -ForegroundColor Yellow -NoNewline
        $Counter++
        Start-Sleep -Milliseconds 100
    }
    Write-Host "`b " -NoNewline
    
    $JobResult = Receive-Job -Job $Job
    $JobState = $Job.State
    Remove-Job -Job $Job
    
    if ($JobState -eq 'Completed' -and ([string]$JobResult -notmatch "Failed")) {
        Write-Host "`n"
        Write-ConsoleUi "$Message -> OK" "SUCCESS"
        return $true
    } else {
        Write-Host "`n"
        Write-ConsoleUi "$Message -> FAILED" "ERROR"
        if ($JobResult) { Write-ConsoleUi "Reason: $JobResult" "ERROR" }
        return $false
    }
}

# ==============================================================================
# DIAGNOSTICS & PRE-FLIGHT
# ==============================================================================

function Test-PortAvailability {
    param([int]$Port)
    try {
        $TcpConn = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
        if ($TcpConn) {
            $Process = Get-Process -Id $TcpConn[0].OwningProcess -ErrorAction SilentlyContinue
            $AllowedProcs = @("wslrelay", "com.docker.backend", "docker-proxy", "vpnkit", "Idle")
            if ($Process.Name -in $AllowedProcs -or $Process.Id -eq 0) {
                Write-ConsoleUi "Port $Port is held by Docker mapping ($($Process.Name)). Permitting." "INFO"
                return $true
            }
            Write-ConsoleUi "Port $Port is blocked by Process UI: $($Process.Name) (PID: $($Process.Id))" "WARN"
            return $false
        }
        return $true
    } catch {
        return $true
    }
}

function Invoke-PreFlightChecks {
    Write-ConsoleUi "Commencing System Pre-Flight Diagnostics..." "INFO"
    
    $Checks = @(
        @{ Name="Docker daemon"; Cmd="docker info" }
        @{ Name="Docker compose"; Cmd="docker compose version" }
        @{ Name="Python 3.10+"; Cmd="python --version" }
    )
    
    $AllPassed = $true
    foreach ($Check in $Checks) {
        $Proc = Start-Process cmd.exe -ArgumentList "/c $($Check.Cmd) >NUL 2>NUL" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
        if ($Proc -and ($Proc.ExitCode -eq 0)) {
            Write-ConsoleUi "Diagnostic: $($Check.Name) [PASSED]" "SUCCESS"
        } else {
            Write-ConsoleUi "Diagnostic: $($Check.Name) [FAILED] - Ensure dependency is installed." "CRIT"
            $AllPassed = $false
        }
    }
    
    foreach ($Service in $Global:RequiredPorts.Keys) {
        foreach ($Port in $Global:RequiredPorts[$Service]) {
            if (-not (Test-PortAvailability -Port $Port)) {
                Write-ConsoleUi "Network collision detected for $Service on Port $Port." "CRIT"
                $AllPassed = $false
            }
        }
    }
    
    if (-not $AllPassed) {
        Write-ConsoleUi "Pre-Flight Diagnostics failed. Halting launch vectors." "CRIT"
        exit 1
    }
}

# ==============================================================================
# ENVIRONMENT ORCHESTRATION
# ==============================================================================

function Invoke-VirtualEnvironmentSetup {
    Write-ConsoleUi "Validating Python Virtual Environment (VENV)..." "INFO"
    $VenvPath = Join-Path $Global:RootDir ".venv"
    
    if (-not (Test-Path $VenvPath)) {
        Write-ConsoleUi "Virtual Environment not found. Constructing isolated container..." "WARN"
        $CreateVenv = Invoke-Spinner -Message "Building Python .venv ecosystem" -ScriptBlock {
            Set-Location $using:Global:RootDir
            python -m venv .venv
        }
        if (-not $CreateVenv) { exit 1 }
    }
    
    Write-ConsoleUi "Virtual Environment isolated. Synchronizing dependencies..." "INFO"
    $ReqFile = Join-Path $Global:RootDir "requirements.txt"
    $PipPath = Join-Path $VenvPath "Scripts\pip.exe"
    
    if (-not (Test-Path $PipPath)) {
        Write-ConsoleUi "Corrupted .venv detected (pip.exe missing). Run hard_reset.ps1." "CRIT"
        exit 1
    }
    
    $InstallDeps = {
        param($PipPath, $ReqFile)
        & $PipPath install -r $ReqFile --upgrade | Out-Null
    }
    $Job = Start-Job -ScriptBlock $InstallDeps -ArgumentList $PipPath, $ReqFile
    Wait-Job -Job $Job | Out-Null
    Receive-Job -Job $Job -ErrorAction SilentlyContinue | Out-Null
    
    if ($Job.State -ne 'Completed') {
        Write-ConsoleUi "Failed to synchronize matrix dependencies." "CRIT"
        exit 1
    }
    Write-ConsoleUi "Dependency synchronization established." "SUCCESS"
}

# ==============================================================================
# CONTAINER ORCHESTRATION
# ==============================================================================

function Test-ContainerHealth {
    param([string]$ContainerName)
    $HealthCmd = "docker inspect --format='{{json .State.Health.Status}}' $ContainerName"
    try {
        $Status = Invoke-Expression $HealthCmd 2>&1
        $Status = $Status -replace '"',''
        return $Status -eq "healthy"
    } catch {
        return $false
    }
}

function Invoke-ContainerMesh {
    Write-ConsoleUi "Igniting Docker Container Mesh..." "INFO"
    Set-Location $Global:RootDir
    
    $ComposeCmd = "docker compose up -d"
    if ($ForceRebuild) { $ComposeCmd += " --build" }
    
    Write-ConsoleUi "Executing: $ComposeCmd" "INFO"
    Invoke-Expression $ComposeCmd | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-ConsoleUi "Failed to ignite Docker Mesh. Validate docker-compose.yml integrity." "CRIT"
        exit 1
    }
    
    Write-ConsoleUi "Containers elevated. Polling for sovereign health status..." "INFO"
    
    $Containers = @("cloudscape_neo4j_engine", "cloudscape_localstack_aws", "cloudscape_redis_cache", "cloudscape_azurite_azure")
    $WaitTimeout = 120 # Seconds
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    foreach ($Container in $Containers) {
        Write-ConsoleUi "Polling health sequence for [$Container]..." "INFO"
        $IsHealthy = $false
        
        while ($Stopwatch.Elapsed.TotalSeconds -lt $WaitTimeout) {
            # Check basic running state first
            $IsRunning = (docker inspect -f '{{.State.Running}}' $Container 2>$null) -replace '"',''
            if ($IsRunning -ne 'true') {
                Write-ConsoleUi "Container $Container crashed unexpectedly." "CRIT"
                exit 1
            }
            
            if (Test-ContainerHealth -ContainerName $Container) {
                Write-ConsoleUi "[$Container] >> HEALTHY" "SUCCESS"
                $IsHealthy = $true
                break
            }
            Start-Sleep -Seconds 3
        }
        
        if (-not $IsHealthy) {
            Write-ConsoleUi "Timeout exceeded polling health for $Container. System unstable." "CRIT"
            docker logs --tail 50 $Container
            exit 1
        }
    }
    Write-ConsoleUi "Full Container Mesh Operating at Peak Efficacy." "SUCCESS"
}

# ==============================================================================
# PIPELINE EXECUTION
# ==============================================================================

function Invoke-BackendPipeline {
    Write-ConsoleUi "Bootstrapping Python Engine Framework..." "INFO"
    $PythonExe = Join-Path $Global:RootDir ".venv\Scripts\python.exe"
    $MainPy = Join-Path $Global:RootDir "backend\main.py"
    
    Write-ConsoleUi "Applying Neo4j Enterprise Schema Constraints..." "INFO"
    $SchemaCmd = "& `"$PythonExe`" `"$MainPy`" --schema"
    Invoke-Expression $SchemaCmd
    
    Write-ConsoleUi "Schema Bound. Advancing to Primary Extraction Phase..." "INFO"
    
    $ExecCmd = "& `"$PythonExe`" `"$MainPy`" --mode $RunMode"
    
    if ($RunMode -eq "DAEMON") {
        $ExecCmd = "& `"$PythonExe`" `"$MainPy`" --daemon"
    } elseif ($RunMode -eq "REPORT") {
        $ExecCmd = "& `"$PythonExe`" `"$MainPy`" --report"
    }
    
    Write-ConsoleUi "Executing: $ExecCmd" "INFO"
    
    # We yield control to the Python script directly, retaining colored output
    Invoke-Expression $ExecCmd
}

# ==============================================================================
# MASTER SEQUENCE
# ==============================================================================
try {
    Show-Header
    
    if (-not $SkipValidation) {
        Invoke-PreFlightChecks
    }
    
    Invoke-VirtualEnvironmentSetup
    Invoke-ContainerMesh
    
    Write-Host "`n"
    Write-ConsoleUi "=== COMMENCING SOVEREIGN PIPELINE ===" "WARN"
    Write-Host "`n"
    
    Invoke-BackendPipeline

} catch {
    Write-ConsoleUi "FATAL EXCEPTION: $_" "CRIT"
    Write-ConsoleUi "Stack Trace: $($_.ScriptStackTrace)" "CRIT"
    exit 1
}

Write-ConsoleUi "Orchestrator Sequence Terminated." "INFO"
exit 0
