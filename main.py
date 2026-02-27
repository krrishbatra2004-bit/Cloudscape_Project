import sys
import time
import asyncio
import argparse
import logging
from typing import List

# Import our custom enterprise modules
from core.config import settings, tenants
from core.orchestrator import DiscoveryOrchestrator
from core.simulation.enterprise_seeder import EnterpriseMeshSeeder

# ==============================================================================
# PROJECT CLOUDSCAPE 2026: MASTER EXECUTION ENGINE
# ==============================================================================

def setup_logger(debug_mode: bool) -> logging.Logger:
    """Configures a professional, timestamped console logger."""
    log_level = logging.DEBUG if debug_mode else logging.INFO
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    
    # Silence noisy third-party libraries
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("neo4j").setLevel(logging.WARNING)

    return logging.getLogger("Cloudscape.CLI")

def print_banner():
    """Generates the startup banner for the CLI."""
    banner = """
    ====================================================================
      ██████╗██╗      ██████╗ ██╗   ██╗██████╗ ███████╗ ██████╗ █████╗ ██████╗ ███████╗
     ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝
     ██║     ██║     ██║   ██║██║   ██║██║  ██║███████╗██║     ███████║██████╔╝█████╗  
     ██║     ██║     ██║   ██║██║   ██║██║  ██║╚════██║██║     ██╔══██║██╔═══╝ ██╔══╝  
     ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝███████║╚██████╗██║  ██║██║     ███████╗
      ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚══════╝
    ====================================================================
    ENTERPRISE CLOUD DISCOVERY & GRAPH CORRELATION FABRIC (v2.0)
    ====================================================================
    """
    print(banner)

def run_seeder(logger: logging.Logger):
    """Executes the vulnerable-by-design infrastructure seeder."""
    logger.info("Initializing LocalStack Infrastructure Seeder...")
    start_time = time.time()
    
    seeder = EnterpriseMeshSeeder(tenants)
    seeder.run()
    
    elapsed = time.time() - start_time
    logger.info(f"Seeding completed in {elapsed:.2f} seconds.")

async def run_discovery_mesh(logger: logging.Logger):
    """Executes the asynchronous multi-tenant discovery and graph ingestion."""
    logger.info("Initializing Asynchronous Discovery Orchestrator...")
    start_time = time.time()
    
    orchestrator = DiscoveryOrchestrator(tenants)
    await orchestrator.execute_mesh_scan()
    
    elapsed = time.time() - start_time
    logger.info(f"Enterprise Mesh Discovery completed in {elapsed:.2f} seconds.")

def main():
    """Main CLI Entry Point."""
    parser = argparse.ArgumentParser(
        description="Cloudscape: Multi-Tenant Cloud Security Graph Engine",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Define CLI Arguments
    parser.add_argument(
        "--mode", 
        type=str, 
        choices=["seed", "scan", "full"], 
        default="full",
        help="Execution mode:\n"
             "  seed : Builds the vulnerable mock infrastructure in LocalStack.\n"
             "  scan : Runs the Discovery Engines and ingests to Neo4j.\n"
             "  full : (Default) Runs seed, waits 5 seconds, then runs scan."
    )
    parser.add_argument(
        "--debug", 
        action="store_true", 
        help="Enable verbose debug logging."
    )

    args = parser.parse_args()
    logger = setup_logger(args.debug)
    print_banner()

    try:
        if args.mode in ["seed", "full"]:
            logger.info("--- PHASE 1: MESH SEEDING ---")
            run_seeder(logger)
            
            if args.mode == "full":
                logger.info("Cooling down for 5 seconds to ensure eventual consistency...")
                time.sleep(5)

        if args.mode in ["scan", "full"]:
            logger.info("--- PHASE 2: GRAPH DISCOVERY ---")
            # We must use asyncio.run() to properly manage the async event loop
            asyncio.run(run_discovery_mesh(logger))
            
        logger.info("SUCCESS: Cloudscape execution pipeline finished without errors.")
        
    except KeyboardInterrupt:
        print("\n")
        logger.warning("Execution interrupted by user (Ctrl+C). Shutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"FATAL ERROR: An unhandled exception crashed the pipeline: {e}", exc_info=args.debug)
        sys.exit(1)

if __name__ == "__main__":
    main()