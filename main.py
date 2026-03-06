import argparse
import asyncio
import logging
import os
import sys
import subprocess
import time

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - MASTER ENTRYPOINT
# ==============================================================================
# The Command and Control (C2) interface for the Cloudscape architecture.
# Features automated mock credential injection and regional synchronization.
# ==============================================================================

# Configure Global Base Logging
os.makedirs("forensics/logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"forensics/logs/cloudscape_engine_{int(time.time())}.log")
    ]
)
logger = logging.getLogger("Cloudscape.CLI")

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
    REGION: AP-SOUTH-1 (MUMBAI)
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

async def run_scan(force: bool = False):
    """Executes the Global Cloudscape Scan with integrated Pre-Flight checks."""
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
        
        if asyncio.iscoroutinefunction(seeder.execute):
            await seeder.execute()
        else:
            await asyncio.to_thread(seeder.execute)
            
    except ImportError:
        logger.error("Mesh Seeder module not found. Ensure utils/mesh_seeder.py exists.")
    except Exception as e:
        logger.error(f"Seeding failed: {e}")

def run_ui():
    """Spawns the Streamlit Aether Dashboard."""
    ui_path = "ui/app.py" 
    if not os.path.exists(ui_path):
        logger.error(f"Cannot find UI module at {ui_path}. Ensure the ui/ directory exists.")
        return
        
    try:
        logger.info("Spawning Visualization Dashboard on port 8501...")
        subprocess.run([sys.executable, "-m", "streamlit", "run", ui_path], check=True)
    except KeyboardInterrupt:
        logger.info("Dashboard shutdown requested.")
    except Exception as e:
        logger.error(f"Failed to launch Dashboard: {e}")

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

    if args.check:
        from titan_preflight import main as pf_main
        await pf_main()
    elif args.seed:
        await run_seed()
    elif args.scan:
        await run_scan(force=args.force)
    elif args.ui:
        run_ui()
    else:
        parser.print_help()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\033[91m[!] Execution aborted by user (CTRL+C). Shutting down gracefully...\033[0m")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Unhandled system crash in Cloudscape Core: {e}")
        sys.exit(1)