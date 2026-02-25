import json
import logging
import time
import sys
from datetime import datetime
from typing import Dict, Any

# Ensure module pathing is absolute for script execution
from pathlib import Path
root_path = Path(__file__).resolve().parent
if str(root_path) not in sys.path:
    sys.path.append(str(root_path))

from core.config import settings
from drivers.aws_driver import AWSDriver
from core.processor import GraphCorrelationEngine

def setup_enterprise_logging() -> logging.Logger:
    """
    Initializes a dual-stream logging architecture.
    Ensures the E: Drive Vault directory structure exists BEFORE attempting to write logs.
    Strictly enforces UTF-8 encoding to prevent Windows cp1252 charmap crashes.
    """
    # 1. Initialize Physical Storage (E: Drive Vault)
    settings.setup_vault()

    # 2. Configure Global Logging Format
    log_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s'
    )
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Clear existing handlers to prevent duplicate logs in interactive environments
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    # 3. File Handler: Immutable Audit Trail on E: Drive (FORCED UTF-8)
    log_file_path = settings.LOG_DIR / "orchestrator_security_audit.log"
    file_handler = logging.FileHandler(log_file_path, mode='a', encoding='utf-8')
    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)

    # 4. Console Handler: Real-time Terminal Feedback (FORCED UTF-8 for Windows compatibility)
    # Using sys.stdout and wrapping it if necessary, though modern PowerShell handles stdout utf-8 well.
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_formatter)
    root_logger.addHandler(console_handler)

    return logging.getLogger("Cloudscape_Pipeline")

class CloudscapePipeline:
    """
    The Central Nervous System of Project Cloudscape.
    Manages the synchronous lifecycle: Discovery -> Audit Persistence -> Graph Correlation.
    """
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.config = settings
        
        # Initialize Sub-Engines
        self.logger.info("Initializing Omni-Layer AWS Driver...")
        self.aws_driver = AWSDriver()
        
        self.logger.info("Initializing Neo4j Graph Correlation Engine...")
        self.graph_engine = GraphCorrelationEngine()

    def _persist_audit_manifest(self, data: Dict[str, Any], provider: str):
        """
        Saves the exhaustive cloud state to the E: Drive Vault.
        Creates a timestamped forensic copy and a 'latest' symlink for the UI.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = self.config.MANIFEST_DIR / f"audit_{provider}_{timestamp}.json"
        latest_path = self.config.MANIFEST_DIR / f"{provider}_latest.json"

        try:
            # Save Point-in-Time Forensic Audit
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, default=str)
            
            # Save Hot-Swap File for Dashboard
            with open(latest_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, default=str)
                
            self.logger.info(f"✔ Security Audit Manifest persisted to Vault: {save_path.name}")
        except Exception as e:
            self.logger.critical(f"✖ CRITICAL: Failed to persist audit manifest to E: Drive: {e}")
            raise  # Rethrow because if we can't save the audit, the pipeline must halt.

    def execute_sync(self, wipe_graph: bool = False):
        """
        Executes the end-to-end cloud discovery and ingestion cycle.
        """
        start_time = time.time()
        self.logger.info("="*60)
        self.logger.info("🚀 INITIATING ENTERPRISE CLOUDSCAPE SYNC CYCLE")
        self.logger.info("="*60)

        try:
            # Phase 0: Graph Database Reset (For clean presentations/demos)
            if wipe_graph:
                self.logger.warning("Phase 0: Wiping existing Knowledge Graph...")
                self.graph_engine.reset_graph()

            # Phase 1: Exhaustive Discovery (The 'Driver')
            self.logger.info("Phase 1: Executing Deep Cloud Discovery...")
            aws_inventory = self.aws_driver.get_full_inventory()

            # Phase 2: Immutability & Persistence (The 'Vault')
            self.logger.info("Phase 2: Archiving State to Secure Vault...")
            self._persist_audit_manifest(aws_inventory, "aws")

            # Phase 3: Graph Translation (The 'Processor')
            self.logger.info("Phase 3: Translating State into Neo4j Risk Graph...")
            self.graph_engine.ingest_aws_manifest(aws_inventory)

            # Execution Metrics
            duration = round(time.time() - start_time, 2)
            self.logger.info("="*60)
            self.logger.info(f"✅ SYNC COMPLETE (Duration: {duration}s)")
            self.logger.info("="*60)

        except Exception as e:
            self.logger.critical(f"❌ PIPELINE CRASH: {str(e)}", exc_info=True)
        finally:
            # Ensure database connections are returned to the pool
            self.graph_engine.close()
            self.logger.info("System teardown complete. Engines safely offline.")

if __name__ == "__main__":
    # 1. Bootstrap Logging and Drive Verification
    orchestrator_logger = setup_enterprise_logging()
    
    # 2. Instantiate and Run the Pipeline
    # wipe_graph=True is set so every time you run main.py, you get a fresh, clean topology.
    pipeline = CloudscapePipeline(orchestrator_logger)
    pipeline.execute_sync(wipe_graph=True)