import argparse
import asyncio
import logging
import os
import sys
import subprocess
import time
import signal
from pathlib import Path

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - MASTER ENTRYPOINT (TITAN EDITION)
# ==============================================================================
# The Command and Control (C2) interface for the Cloudscape architecture.
# Features automated mock credential injection, regional synchronization, 
# detached UI threading, and guaranteed memory-safe graceful teardowns.
# ==============================================================================

# Ensure the root project directory is physically in the Python Path for sub-module imports
root_dir = Path(__file__).parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

# Configure Global Base Logging Matrix
os.makedirs("forensics/logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"forensics/logs/cloudscape_engine_{int(time.time())}.log")
    ]
)
logger = logging.getLogger("Cloudscape.CLI")

# Global tracking for background UI subprocesses to ensure clean teardown
active_subprocesses = []

def print_cloudscape_banner():
    banner = f"""
    ██████╗██╗      ██████╗ ██╗   ██╗██████╗ ███████╗ ██████╗ █████╗ ██████╗ ███████╗
    ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝
    ██║     ██║     ██║   ██║██║   ██║██║  ██║███████╗██║     ███████║██████╔╝█████╗  
    ██║     ██║     ██║   ██║██║   ██║██║  ██║╚════██║██║     ██╔══██║██╔═══╝ ██╔══╝  
    ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝███████║╚██████╗██║  ██║██║     ███████╗
     ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚══════╝
    ==================================================================================
    CLOUDSCAPE NEXUS v5.0.1 | ENTERPRISE MULTI-CLOUD GRAPH DISCOVERY
    ==================================================================================
    """
    print("\033[96m" + banner + "\033[0m")

def inject_mock_credentials():
    """Forces environment variables for LocalStack compatibility if in MOCK mode."""
    mode = os.getenv("NEXUS_EXECUTION_MODE", "MOCK").upper()
    if mode == "MOCK":
        logger.info("MOCK Mode Detected: Injecting dummy AWS credentials for ap-south-1...")
        os.environ["AWS_ACCESS_KEY_ID"] = "testing"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
        os.environ["AWS_DEFAULT_REGION"] = "ap-south-1"

# ==============================================================================
# PIPELINE EXECUTION PROCEDURES
# ==============================================================================

async def run_scan(force: bool = False):
    """Executes the Global Cloudscape Scan with integrated Pre-Flight checks."""
    # Delayed imports to prevent circular dependencies before the Python Path is set
    from titan_preflight import TitanPreFlight
    from core.orchestrator import CloudscapeOrchestrator
    
    logger.info("Initializing Cloudscape Pre-Flight Diagnostics...")
    preflight = TitanPreFlight()
    
    await preflight.check_dependencies()
    await preflight.check_network_fabric()
    await preflight.check_project_sentinels()
    await preflight.check_cloud_mode()
    
    is_ready = preflight.render_report()
    
    if not is_ready:
        if force:
            logger.warning("PRE-FLIGHT FAILED. Overriding abort sequence via --force flag. Proceed with extreme caution.")
        else:
            logger.critical("PRE-FLIGHT FAILED. Aborting Ignition. Use --force to bypass.")
            sys.exit(1)
            
    logger.info("Pre-Flight sequence complete. Engaging Master Orchestrator.")
    orchestrator = CloudscapeOrchestrator()
    await orchestrator.execute_global_scan()

async def run_seed():
    """Ignites the local Docker mesh with base infrastructure."""
    try:
        from utils.mesh_seeder import MeshSeeder
        seeder = MeshSeeder()
        logger.info("Engaging Local Mesh Seeder for ap-south-1...")
        
        # Heuristic detection of the seeder's async nature
        if asyncio.iscoroutinefunction(seeder.execute):
            await seeder.execute()
        else:
            await asyncio.to_thread(seeder.execute)
            
    except ImportError:
        logger.error("Mesh Seeder module not found. Ensure utils/mesh_seeder.py exists.")
    except Exception as e:
        logger.error(f"Seeding failed: {e}")

def spawn_ui():
    """Spawns the Streamlit Aether Dashboard as a detached background process."""
    # Note: Streamlit paths are highly sensitive. We dynamically resolve to the actual dashboard path.
    ui_path = os.path.join(root_dir, "dashboard", "app.py")
    
    if not os.path.exists(ui_path):
        # Fallback check just in case you kept it in ui/ instead of dashboard/
        ui_path = os.path.join(root_dir, "ui", "app.py")
        if not os.path.exists(ui_path):
            logger.error(f"Cannot find UI module. Ensure the dashboard/app.py file exists.")
            return
            
    try:
        logger.info("[*] Spawning Aether Visualization Dashboard...")
        proc = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", ui_path, "--server.port=8501", "--server.headless=true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(root_dir)
        )
        active_subprocesses.append(proc)
        logger.info("  [OK] Dashboard process dispatched to port 8501.")
        logger.info("  [i] You can view the UI at: http://localhost:8501 (Once scan completes)")
    except Exception as e:
        logger.error(f"Failed to launch Dashboard: {e}")

# ==============================================================================
# GRACEFUL TEARDOWN PROTOCOLS
# ==============================================================================

async def execute_teardown_matrix():
    """Physically terminates DB pools and kills background UI threads."""
    logger.info("Commencing Graceful Teardown Sequence...")
    
    # 1. Sever the physical database connection pool
    try:
        from core.processor.ingestor import ingestor
        await ingestor.close()
        logger.info("Graph Database Kernel connections severed.")
    except Exception as e:
        logger.error(f"Failed to close Neo4j driver pool: {e}")

    # 2. Terminate background Streamlit workers
    for proc in active_subprocesses:
        try:
            if proc.poll() is None:
                logger.info(f"Terminating background UI process (PID: {proc.pid})...")
                proc.terminate()
                proc.wait(timeout=3)
        except Exception as e:
            logger.error(f"Failed to terminate UI process: {e}")

# ==============================================================================
# THE ASYNC MASTER LOOP
# ==============================================================================

async def main():
    parser = argparse.ArgumentParser(description="Cloudscape Nexus 5.0 - C2 Interface")
    
    # Action Flags
    parser.add_argument("--scan", action="store_true", help="Execute Global Infrastructure Discovery & HAPD")
    parser.add_argument("--seed", action="store_true", help="Seed LocalStack/Azurite with mock infrastructure")
    parser.add_argument("--ui", action="store_true", help="Launch the Streamlit Visualization Dashboard")
    parser.add_argument("--check", action="store_true", help="Run the Pre-Flight Diagnostic Suite only")
    
    # Modifier Flags
    parser.add_argument("--force", action="store_true", help="Bypass Pre-Flight failures when using --scan")
    
    args = parser.parse_args()
    print_cloudscape_banner()
    
    # Ensure credentials exist before any boto3 client initializes
    inject_mock_credentials()

    try:
        # Conditionally boot the UI Thread so it runs parallel to the scan
        if args.ui or args.scan:
            spawn_ui()

        if args.check:
            from titan_preflight import main as pf_main
            await pf_main()
        elif args.seed:
            await run_seed()
        elif args.scan:
            await run_scan(force=args.force)
        elif not args.ui:
            parser.print_help()
            
    finally:
        # No matter what happens (success, failure, or Ctrl+C), run the teardown
        await execute_teardown_matrix()


if __name__ == "__main__":
    # OS-Level Asyncio Optimization
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    try:
        asyncio.run(main())
        print("\n\033[92m[OK] Cloudscape Nexus Sequence Concluded Safely.\033[0m")
    except KeyboardInterrupt:
        print("\n\033[91m[!] Execution aborted by user (CTRL+C). Process terminated.\033[0m")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Unhandled system crash in Cloudscape Core: {e}")
        sys.exit(1)