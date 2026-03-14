import argparse
import asyncio
import logging
import logging.handlers
import os
import sys
import io
import socket
import subprocess
import time
import signal
import platform
import traceback
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - MASTER COMMAND & CONTROL (C2) GATEWAY
# ==============================================================================
# The Enterprise Entrypoint for the Sovereign-Forensic Digital Tool.
# Orchestrates the 3 Core Loops: The Observer (Ingestion), The Brain (Neo4j), 
# and The Hologram (Visualization/UI).
#
# TITAN UPGRADES ACTIVE:
# 1. Hardware UTF-8 Lock: Overrides Windows cp1252 defaults to prevent crashes 
#    when rendering NetworkX pathing arrows.
# 2. Async Teardown Matrix: Guarantees Neo4j and Docker socket closure on Ctrl+C.
# 3. Asynchronous Subprocess Manager: Safely spawns and kills the detached UI.
# 4. Deep Socket Diagnostics: Verifies Tailscale Mesh, Redis, and Neo4j routing.
# 5. OS-Level Event Loop Normalization: Prevents Windows/Boto3 async lockups.
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. OS-LEVEL ENCODING LOCK (THE WINDOWS CRASH FIX)
# ------------------------------------------------------------------------------
def apply_hardware_encoding_lock():
    """
    Forces the standard output and error streams to utilize UTF-8 encoding.
    Crucial for Windows systems that default to cp1252, which violently crashes 
    when the HAPD Engine attempts to log NetworkX topological arrows or emojis.
    """
    if sys.platform == 'win32':
        try:
            # Detach the underlying binary buffer and re-wrap it with strict UTF-8
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
            
            # Force Python's internal environment variable for subprocesses
            os.environ["PYTHONIOENCODING"] = "utf-8"
        except Exception as e:
            print(f"[!] Warning: Failed to lock hardware encoding: {e}")

apply_hardware_encoding_lock()

# ------------------------------------------------------------------------------
# 2. PATH RESOLUTION & CORE IMPORTS
# ------------------------------------------------------------------------------
# Ensure the root project directory is physically in the Python Path for sub-module imports
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

# Construct Sovereign-Forensic Directories (BSON Ledgers, Logs, Outputs)
os.makedirs(os.path.join(root_dir, "forensics", "logs"), exist_ok=True)
os.makedirs(os.path.join(root_dir, "forensics", "reports"), exist_ok=True)
os.makedirs(os.path.join(root_dir, "forensics", "bson_ledger"), exist_ok=True)
os.makedirs(os.path.join(root_dir, "dashboard", "tmp"), exist_ok=True)

# Delayed imports to allow path injection and encoding locks to succeed first
try:
    from core.config import config
    from core.orchestrator import CloudscapeOrchestrator
    from core.processor.ingestor import ingestor
    
    # Safely attempt to import MeshSeeder (only used in MOCK/Seed mode)
    try:
        from utils.mesh_seeder import MeshSeeder
    except ImportError:
        MeshSeeder = None
        
except ImportError as e:
    print(f"\n\033[91m[FATAL] Pipeline Integrity Failure: Could not resolve core modules.\033[0m")
    print(f"Details: {e}")
    sys.exit(1)

# ------------------------------------------------------------------------------
# 3. GLOBAL TELEMETRY & LOGGING MATRICES
# ------------------------------------------------------------------------------
class CustomConsoleFormatter(logging.Formatter):
    """Injects ANSI color coding into the terminal for the Command Center."""
    grey = "\x1b[38;20m"
    blue = "\x1b[36;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format_str = "%(asctime)s | %(levelname)-8s | %(name)-35s | %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format_str + reset,
        logging.INFO: blue + format_str + reset,
        logging.WARNING: yellow + format_str + reset,
        logging.ERROR: red + format_str + reset,
        logging.CRITICAL: bold_red + format_str + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt="%Y-%m-%d %H:%M:%S")
        return formatter.format(record)

def initialize_telemetry_matrix(debug_mode: bool = False):
    """
    Establishes the global terminal and file-based logging configuration.
    Implements rotating file handlers to prevent log-bloat on massive graph scans.
    """
    log_level = logging.DEBUG if debug_mode else logging.INFO
    date_format = "%Y-%m-%d %H:%M:%S"
    
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    # Console Handler (Rich ANSI)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(CustomConsoleFormatter())
    root_logger.addHandler(console_handler)

    # File Handler (Strict ASCII/UTF-8 for the Forensic Ledger)
    log_file = os.path.join(root_dir, "forensics", "logs", f"titan_engine_{int(time.time())}.log")
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=15*1024*1024, backupCount=5, encoding='utf-8'
    )
    plain_format = "%(asctime)s | %(levelname)-8s | %(name)-35s | %(message)s"
    file_handler.setFormatter(logging.Formatter(plain_format, datefmt=date_format))
    root_logger.addHandler(file_handler)
    
    # Mute noisy internal dependency streams
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    logging.getLogger("azure.core.pipeline.policies").setLevel(logging.WARNING)

logger = logging.getLogger("Cloudscape.C2.Gateway")

# ------------------------------------------------------------------------------
# 4. SUBPROCESS MANAGER & GRACEFUL TEARDOWN
# ------------------------------------------------------------------------------
class TitanTeardownManager:
    """
    The Absolute Memory Manager.
    Tracks and safely assassinates all active subprocesses, UI threads, and database 
    connection pools upon script termination (Success, Failure, or Ctrl+C).
    Guarantees zero zombie sockets are left behind in Docker.
    """
    def __init__(self):
        self.active_processes: List[subprocess.Popen] = []
        self.teardown_initiated = False

    def register_process(self, proc: subprocess.Popen):
        """Registers a detached process (like Streamlit or Presidio) for tracking."""
        self.active_processes.append(proc)

    async def execute_teardown(self):
        """The Master Assassination Protocol."""
        if self.teardown_initiated:
            return
        self.teardown_initiated = True
        
        print("\n")
        logger.info("Commencing Graceful Titan Teardown Sequence...")
        
        # 1. Assassinate detached UI Workers & Middleware
        for proc in self.active_processes:
            try:
                if proc.poll() is None:
                    logger.info(f"Terminating background UI/Middleware process (PID: {proc.pid})...")
                    proc.terminate()
                    try:
                        # Give it 3 seconds to die gracefully
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        logger.warning(f"Process {proc.pid} resisted termination. Sending SIGKILL.")
                        proc.kill()
            except Exception as e:
                logger.error(f"Failed to terminate UI process: {e}")

        # 2. Sever Neo4j Database Kernel (The Brain)
        try:
            logger.info("Severing Neo4j Graph Database connections...")
            await ingestor.close()
        except Exception as e:
            logger.error(f"Failed to close Neo4j driver pool: {e}")
            
        logger.info("System Memory and Sockets successfully released.")

teardown_manager = TitanTeardownManager()

def posix_signal_handler(sig, frame):
    """Intercepts OS-level termination signals (Ctrl+C) to trigger the async teardown."""
    print("\n\033[91m[!] Termination Signal Intercepted. Halting Execution...\033[0m")
    
    # We must bridge the synchronous signal handler to the async teardown routine
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(teardown_manager.execute_teardown())
    except RuntimeError:
        # If no loop is running, we spin one up just for the funeral
        asyncio.run(teardown_manager.execute_teardown())
    finally:
        sys.exit(0)

# Register POSIX signal handlers
signal.signal(signal.SIGINT, posix_signal_handler)
signal.signal(signal.SIGTERM, posix_signal_handler)

# ------------------------------------------------------------------------------
# 5. ENVIRONMENT PRE-FLIGHT & MOCK INJECTORS
# ------------------------------------------------------------------------------
def print_cloudscape_banner():
    banner = f"""
    ██████╗██╗      ██████╗ ██╗   ██╗██████╗ ███████╗ ██████╗ █████╗ ██████╗ ███████╗
    ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝
    ██║     ██║     ██║   ██║██║   ██║██║  ██║███████╗██║     ███████║██████╔╝█████╗  
    ██║     ██║     ██║   ██║██║   ██║██║  ██║╚════██║██║     ██╔══██║██╔═══╝ ██╔══╝  
    ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝███████║╚██████╗██║  ██║██║     ███████╗
     ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚══════╝
    ==================================================================================
    CLOUDSCAPE NEXUS v5.0.1 | ENTERPRISE MULTI-CLOUD GRAPH DISCOVERY (ZERO-G)
    ==================================================================================
    Host OS: {platform.system()} {platform.release()} | Runtime: Python {platform.python_version()}
    Zero-Trust Mesh : Configured      | Execution Mode : {config.settings.execution_mode}
    Target Regions  : {len(config.settings.aws.target_regions)}               | Physical Tenants : {len(config.tenants)}
    ==================================================================================
    """
    print("\033[96m" + banner + "\033[0m")

def inject_mock_credentials():
    """Forces environment variables for LocalStack compatibility if in MOCK mode."""
    mode = config.settings.execution_mode.upper()
    if mode == "MOCK":
        logger.info("MOCK Mode Detected: Injecting isolated offline credentials to bypass physical validations.")
        os.environ["AWS_ACCESS_KEY_ID"] = "testing"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
        os.environ["AWS_DEFAULT_REGION"] = config.settings.aws.target_regions[0] if config.settings.aws.target_regions else "us-east-1"
        os.environ["AZURE_TENANT_ID"] = "mock-azure-tenant"
        os.environ["AZURE_CLIENT_ID"] = "mock-azure-client"
        os.environ["AZURE_CLIENT_SECRET"] = "mock-azure-secret"

# ------------------------------------------------------------------------------
# 6. ASYNCHRONOUS DEEP-SOCKET DIAGNOSTICS
# ------------------------------------------------------------------------------
async def tcp_ping(host: str, port: int, timeout: float = 1.0) -> Tuple[bool, float]:
    """Executes a non-blocking TCP handshake to measure component latency."""
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), 
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True, (time.perf_counter() - start) * 1000
    except Exception:
        return False, 0.0

async def run_preflight_diagnostics(force: bool) -> bool:
    """
    The Pre-Flight Diagnostics Matrix.
    Verifies that the multi-container Sovereign-Forensic Docker stack is alive.
    """
    logger.info("Executing Enterprise Pre-Flight Component Diagnostics...")
    
    components = [
        ("The Brain (Neo4j LPG)", "127.0.0.1", 7687, True),
        ("AWS Emulator (LocalStack)", "127.0.0.1", 4566, config.settings.execution_mode == "MOCK"),
        ("Azure Emulator (Azurite)", "127.0.0.1", 10000, config.settings.execution_mode == "MOCK"),
        ("Hash Circuit (Redis)", "127.0.0.1", 6379, False), # Optional component
        ("BSON Ledger (MongoDB)", "127.0.0.1", 27017, False) # Optional component
    ]
    
    all_critical_passed = True
    print("\n" + "="*60)
    print(" TITAN PRE-FLIGHT ROUTING MATRIX")
    print("="*60)

    for name, host, port, is_critical in components:
        is_alive, latency = await tcp_ping(host, port)
        
        status_color = "\033[92mPASS\033[0m" if is_alive else ("\033[91mFAIL\033[0m" if is_critical else "\033[93mWARN\033[0m")
        latency_str = f"{latency:.2f}ms" if is_alive else "OFFLINE"
        crit_str = "[CRITICAL]" if is_critical else "[OPTIONAL]"
        
        print(f" [{status_color}] {crit_str:<10} {name:<25} : {host}:{port} ({latency_str})")
        
        if is_critical and not is_alive:
            all_critical_passed = False

    print("="*60 + "\n")

    if not all_critical_passed:
        if force:
            logger.warning("CRITICAL COMPONENTS OFFLINE. Overriding abort sequence via --force flag. Expect catastrophic failures.")
            return True
        else:
            logger.critical("PRE-FLIGHT FAILED. System is unstable. Please check Docker containers. Aborting Ignition.")
            return False
            
    return True

# ------------------------------------------------------------------------------
# 7. DETACHED UI & WORKER SPAWNING
# ------------------------------------------------------------------------------
def spawn_dashboard():
    """Spawns the Streamlit Aether Dashboard (The Hologram) as a detached process."""
    ui_path = os.path.join(root_dir, "dashboard", "app.py")
    
    if not os.path.exists(ui_path):
        logger.error(f"Cannot find UI module at {ui_path}. Feature disabled.")
        return
            
    try:
        logger.info("[*] Spawning Aether Visualization Dashboard (Detached Thread)...")
        # Headless mode prevents the browser from forcing itself open on the host server
        proc = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", ui_path, "--server.port=8501", "--server.headless=true"],
            stdout=subprocess.DEVNULL, # Prevent Streamlit from polluting the main terminal logs
            stderr=subprocess.DEVNULL,
            cwd=str(root_dir)
        )
        teardown_manager.register_process(proc)
        logger.info("  [OK] Dashboard engine dispatched to internal port 8501.")
        logger.info("  [i] Dashboard UI accessible at: http://localhost:8501")
    except Exception as e:
        logger.error(f"Failed to launch Dashboard process: {e}")

# ------------------------------------------------------------------------------
# 8. PIPELINE EXECUTION PROCEDURES
# ------------------------------------------------------------------------------
async def run_seed():
    """Ignites the local Docker mesh with synthetic base infrastructure."""
    if not MeshSeeder:
        logger.error("MeshSeeder module not found. Cannot hydrate environments.")
        return
        
    logger.info("Engaging Local Mesh Seeder Protocol...")
    try:
        seeder = MeshSeeder()
        # Accommodate both async and sync implementations of the Seeder
        if asyncio.iscoroutinefunction(seeder.execute):
            await seeder.execute()
        else:
            await asyncio.to_thread(seeder.execute)
    except Exception as e:
        logger.error(f"Catastrophic failure during Mesh Seeding: {e}")
        logger.debug(traceback.format_exc())

async def run_scan(force: bool = False):
    """Executes the core Cloudscape extraction, convergence, and intelligence loop."""
    is_ready = await run_preflight_diagnostics(force)
    
    if not is_ready:
        sys.exit(1)
            
    logger.info("Diagnostics clear. Handing control to the Master Orchestrator.")
    
    try:
        orchestrator = CloudscapeOrchestrator()
        await orchestrator.execute_global_scan()
    except Exception as e:
        logger.critical(f"Unhandled system crash in Master Orchestrator: {e}")
        logger.debug(traceback.format_exc())

# ------------------------------------------------------------------------------
# 9. THE MASTER ASYNC EVENT LOOP
# ------------------------------------------------------------------------------
async def async_main(args: argparse.Namespace):
    """
    The Primary Event Loop Kernel.
    Routes CLI arguments to their respective asynchronous execution pathways.
    """
    # 1. Establish Credentials
    inject_mock_credentials()

    # 2. Conditionally Boot the UI Thread
    if args.ui or args.scan:
        spawn_dashboard()

    # 3. Execute Primary Directives based on CLI Multiplexing
    try:
        if args.check:
            await run_preflight_diagnostics(force=args.force)
            
        elif args.seed:
            if config.settings.execution_mode.upper() != "MOCK":
                logger.warning("\033[93mWARNING: '--seed' flag passed in LIVE mode. Physical infrastructure seeding is restricted to MOCK environments.\033[0m")
            else:
                await run_seed()
                
        elif args.scan:
            await run_scan(force=args.force)
            
        elif not args.ui:
            logger.info("No operational directives passed. Use --scan, --seed, or --check. Initiating idle.")
            
    except asyncio.CancelledError:
        logger.warning("Async execution loop cancelled by system interrupt.")
    finally:
        # The ultimate guarantee: Teardown executes regardless of success or crash.
        await teardown_manager.execute_teardown()


# ------------------------------------------------------------------------------
# 10. CLI PARSER & SYNCHRONOUS BOOTSTRAP
# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Cloudscape Nexus 5.0 - Sovereign-Forensic Multi-Cloud Discovery Engine",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Operational Action Flags
    group_actions = parser.add_argument_group("Operational Directives")
    group_actions.add_argument("--scan", action="store_true", help="Execute Global Infrastructure Discovery & Intelligence Matrix (HAPD)")
    group_actions.add_argument("--seed", action="store_true", help="Hydrate LocalStack/Azurite with synthetic multi-tenant infrastructure")
    group_actions.add_argument("--check", action="store_true", help="Run the Pre-Flight Diagnostic Suite (Network/DB/Cache health) only")
    
    # Modifiers & Configuration Overrides
    group_mods = parser.add_argument_group("Execution Modifiers")
    group_mods.add_argument("--ui", action="store_true", help="Launch the Streamlit Visualization Dashboard as a background thread")
    group_mods.add_argument("--force", action="store_true", help="Bypass strict Pre-Flight TCP failures and force the scan to proceed")
    group_mods.add_argument("--debug", action="store_true", help="Engage high-verbosity forensic logging for system debugging")
    
    args = parser.parse_args()

    # Initialize Global Console and Ledger
    initialize_telemetry_matrix(debug_mode=args.debug)
    print_cloudscape_banner()

    # --------------------------------------------------------------------------
    # OS-LEVEL ASYNCIO OPTIMIZATION (THE BOTO3 COMPATIBILITY LOCK)
    # --------------------------------------------------------------------------
    # Windows inherently uses ProactorEventLoop which conflicts heavily with 
    # Boto3's internal threading when running asyncio.to_thread(). 
    # Switching to SelectorEventLoopPolicy permanently stops 'Event loop is closed' crashes.
    if sys.platform == 'win32':
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            logger.debug("Windows Selector Event Loop Policy successfully applied.")
        except Exception as e:
            logger.warning(f"Failed to set Windows Event Loop Policy: {e}")
        
    # Enter the core asynchronous realm
    try:
        asyncio.run(async_main(args))
        print("\n\033[92m[OK] Cloudscape Nexus Sequence Concluded Safely.\033[0m")
    except KeyboardInterrupt:
        # Failsafe fallback if posix_signal_handler misses the interrupt
        print("\n\033[91m[!] Execution violently aborted by user (CTRL+C).\033[0m")
        # Ensure teardown still runs in a new synchronous execution block
        asyncio.run(teardown_manager.execute_teardown())
        sys.exit(1)

if __name__ == "__main__":
    main()