import asyncio
import logging
import time
import traceback
from typing import List, Dict, Any

from core.config import config
from core.processor.ingestor import ingestor

# Core Discovery Engines (Physical/Mock Telemetry)
from engines.aws_engine import AWSEngine
from engines.azure_engine import AzureEngine

# Intelligence, Simulation & Convergence Modules
from simulation.state_factory import StateFactory
from engines.hybrid_bridge import hybrid_bridge
from core.logic.identity_fabric import IdentityFabric
from core.logic.attack_path import AttackPathEngine

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - GLOBAL ORCHESTRATOR (ZERO-G EDITION)
# ==============================================================================
# The Master Controller and Intelligence Coordinator.
#
# TITAN UPGRADES ACTIVE:
# - Asymmetric Discovery Matrix: Solves the "RDS Glass Ceiling" by processing 
#   AWS strictly sequentially (saving LocalStack CPU Mutex) while allowing 
#   Azure to run completely asynchronously.
# - Phase-Isolated Materialization: Streams data directly to the Database Kernel 
#   at the end of each phase to prevent RAM saturation on massive meshes.
# - Absolute Metric Preservation: Guarantees exact timing and node counts for 
#   the final Graceful Teardown report.
# ==============================================================================

class CloudscapeOrchestrator:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Core.Orchestrator")
        self.mode = config.settings.execution_mode.upper()
        
        # Initialize Core Intelligence Modules
        self.state_factory = StateFactory()
        self.identity_fabric = IdentityFabric()
        self.attack_path_engine = AttackPathEngine()
        
        # High-Fidelity Execution Metrics & State Tracking
        self.metrics = {
            "live_aws_nodes": 0,
            "live_azure_nodes": 0,
            "synthetic_nodes": 0,
            "unified_nodes": 0,
            "identity_bridges": 0,
            "attack_paths": 0,
            "timings": {
                "phase_1_extraction": 0.0,
                "phase_2_forging": 0.0,
                "phase_3_convergence": 0.0,
                "phase_4_intelligence": 0.0,
                "total_execution": 0.0
            }
        }

    async def execute_global_scan(self) -> None:
        """
        The Master Titan Sequence.
        Executes the 4-Phase Intelligence Lifecycle with strict timing metrics, 
        blast radius containment, and phase-isolated database materialization.
        """
        self.logger.info("=" * 80)
        self.logger.info(f" IGNITING NEXUS 5.0 TITAN PIPELINE ({len(config.tenants)} Tenants Detected)")
        self.logger.info("=" * 80)
        
        absolute_start = time.perf_counter()

        try:
            # ==================================================================
            # PHASE 0: PRE-FLIGHT & KERNEL READINESS
            # ==================================================================
            self.logger.info("Executing Titan Pre-Flight Diagnostics & Schema Validation...")
            try:
                await ingestor.validate_schema()
            except Exception as schema_err:
                self.logger.critical(f"Database Kernel Schema Validation Failed: {schema_err}")
                raise

            # ==================================================================
            # PHASE 1: ASYMMETRIC RESOURCE EXTRACTION
            # ==================================================================
            p1_start = time.perf_counter()
            live_nodes = await self._execute_phase_1_extraction()
            self.metrics["timings"]["phase_1_extraction"] = time.perf_counter() - p1_start

            # ==================================================================
            # PHASE 2: SYNTHETIC THREAT FORGING
            # ==================================================================
            p2_start = time.perf_counter()
            self.logger.info("Igniting the Titan Synthetic State Factory...")
            synthetic_nodes = self._execute_phase_2_forging()
            self.metrics["timings"]["phase_2_forging"] = time.perf_counter() - p2_start

            # ==================================================================
            # PHASE 3: HYBRID CONVERGENCE & KERNEL INGESTION
            # ==================================================================
            p3_start = time.perf_counter()
            self.logger.info("Initializing Chunked Hybrid Convergence Stream...")
            
            # Execute heuristic algorithms to fuse live and mock infrastructure
            unified_graph = hybrid_bridge.merge_payload_streams(live_nodes, synthetic_nodes)
            self.metrics["unified_nodes"] = len(unified_graph)
            
            # Phase-Isolated Materialization: Immediately flush unified nodes to Neo4j
            if unified_graph:
                self.logger.info(f"Materializing chunk of {len(unified_graph)} Unified Nodes to Database...")
                await ingestor.process_payloads("HybridBridge", unified_graph)
            else:
                self.logger.warning("Convergence yielded 0 nodes. Skipping Database Materialization.")
                
            self.metrics["timings"]["phase_3_convergence"] = time.perf_counter() - p3_start

            # ==================================================================
            # PHASE 4: INTELLIGENCE FABRIC & PATHING
            # ==================================================================
            p4_start = time.perf_counter()
            self.logger.info("Commencing Global Intelligence Enrichment & Graph Traversal...")
            
            # 4A. Identity Bridge Calculation (Cross-Cloud Entanglement)
            trust_edges = self.identity_fabric.calculate_cross_cloud_trusts(unified_graph)
            self.metrics["identity_bridges"] = len(trust_edges)
            
            if trust_edges:
                await ingestor.process_payloads("IdentityFabric", trust_edges)
            
            # 4B. Exhaustive Heuristic Attack Path Discovery (HAPD)
            # Passes both nodes and identity edges to enable exact graph recreation in memory
            attack_paths = self.attack_path_engine.calculate_attack_paths(unified_graph, trust_edges)
            self.metrics["attack_paths"] = len(attack_paths)
            
            if attack_paths:
                self.logger.info(f"Materializing {len(attack_paths)} Critical Attack Paths to Graph Database...")
                await ingestor.process_payloads("AttackPathEngine", attack_paths)
            
            self.metrics["timings"]["phase_4_intelligence"] = time.perf_counter() - p4_start

        except asyncio.CancelledError:
            self.logger.warning("Pipeline execution cancelled by external interruption.")
        except Exception as e:
            self.logger.critical(f"Catastrophic Pipeline Collapse: {e}")
            self.logger.debug(traceback.format_exc())
        finally:
            # Ensure the final reporting runs regardless of success or failure
            self.metrics["timings"]["total_execution"] = time.perf_counter() - absolute_start
            self._render_forensic_report()

    # ==========================================================================
    # CORE PHASE IMPLEMENTATIONS
    # ==========================================================================

    async def _execute_phase_1_extraction(self) -> List[Dict[str, Any]]:
        """
        The Asymmetric Extraction Matrix.
        1. Azure: Executed fully concurrently (Azurite handles heavy parallel I/O smoothly).
        2. AWS: Executed via Strict Sequential Mutex. LocalStack crashes if 5 tenants 
           attempt to fork PostgreSQL RDS instances simultaneously. The mutex forces a queue.
        """
        unified_live_nodes = []
        self.logger.info("Deploying Asymmetric Extraction Matrix for Multi-Cloud Sensors...")

        # ----------------------------------------------------------------------
        # PART A: AZURE CONCURRENT FAN-OUT
        # ----------------------------------------------------------------------
        azure_tasks = []
        for tenant in config.tenants:
            try:
                azure_engine = AzureEngine(tenant)
                azure_tasks.append(azure_engine.discover())
            except Exception as e:
                self.logger.error(f"Failed to initialize Azure Engine for {tenant.id}: {e}")

        if azure_tasks:
            az_results = await asyncio.gather(*azure_tasks, return_exceptions=True)
            for res in az_results:
                if isinstance(res, list):
                    unified_live_nodes.extend(res)
                    self.metrics["live_azure_nodes"] += len(res)
                elif isinstance(res, Exception):
                    self.logger.error(f"Azure parallel extraction catastrophic fault: {res}")
                    self.logger.debug(traceback.format_exception(type(res), res, res.__traceback__))

        # ----------------------------------------------------------------------
        # PART B: AWS STRICT SEQUENTIAL MUTEX
        # ----------------------------------------------------------------------
        self.logger.info("Dispatching AWS Sensors under Strict Sequential Mutex to protect LocalStack RDS...")
        
        for tenant in config.tenants:
            self.logger.info(f"[{tenant.id}] Acquiring AWS Mutex for isolated discovery...")
            try:
                aws_engine = AWSEngine(tenant)
                
                # By `await`ing directly inside the sequential loop, we guarantee Tenant B 
                # does not start until Tenant A's heavy Boto3 requests are 100% complete.
                aws_nodes = await aws_engine.discover()
                
                if aws_nodes:
                    unified_live_nodes.extend(aws_nodes)
                    self.metrics["live_aws_nodes"] += len(aws_nodes)
                    
            except Exception as e:
                self.logger.error(f"[{tenant.id}] AWS Extraction Mutex fault: {e}")
                self.logger.debug(traceback.format_exc())
                
        return unified_live_nodes

    def _execute_phase_2_forging(self) -> List[Dict[str, Any]]:
        """
        Iterates over the tenant matrix and generates localized Advanced Persistent 
        Threat (APT) vectors perfectly mapped to the tenant's exact configuration.
        """
        synthetic_nodes = []
        
        for tenant in config.tenants:
            try:
                nodes = self.state_factory.generate_synthetic_topology(tenant)
                if nodes:
                    synthetic_nodes.extend(nodes)
            except Exception as e:
                self.logger.error(f"[{tenant.id}] State Factory injection failed: {e}")
                self.logger.debug(traceback.format_exc())
                
        self.metrics["synthetic_nodes"] = len(synthetic_nodes)
        return synthetic_nodes

    # ==========================================================================
    # FORENSIC TELEMETRY OUTPUT
    # ==========================================================================

    def _render_forensic_report(self) -> None:
        """
        Renders the final, strict ASCII Titan Global Scan metric block.
        Outputs directly to the terminal to bypass logging prefixes for clean formatting.
        """
        self.logger.info("Executing Graceful Pipeline Teardown...")
        
        t = self.metrics["timings"]
        
        report = f"""
================================================================================
 🌌 TITAN GLOBAL SCAN COMPLETE
================================================================================
 [ INFRASTRUCTURE MESH ]
   ├─ Live AWS Nodes Discovered   : {self.metrics["live_aws_nodes"]}
   ├─ Live Azure Nodes Discovered : {self.metrics["live_azure_nodes"]}
   ├─ Synthetic Nodes Forged      : {self.metrics["synthetic_nodes"]}
   └─ Total Unified Graph Nodes   : {self.metrics["unified_nodes"]}
--------------------------------------------------------------------------------
 [ INTELLIGENCE FABRIC ]
   ├─ Cross-Cloud Identity Bridges: {self.metrics["identity_bridges"]}
   └─ Critical Attack Paths Found : {self.metrics["attack_paths"]}
--------------------------------------------------------------------------------
 [ LATENCY FORENSICS ]
   ├─ Phase_1_Extraction        : {t['phase_1_extraction']:.2f}s
   ├─ Phase_2_Forging           : {t['phase_2_forging']:.2f}s
   ├─ Phase_3_Convergence       : {t['phase_3_convergence']:.2f}s
   ├─ Phase_4_Intelligence      : {t['phase_4_intelligence']:.2f}s
   └─ Total Execution Time        : {t['total_execution']:.2f}s
================================================================================
"""
        # Print directly to guarantee ASCII display formatting
        print(report)
        self.logger.info("Cloudscape Nexus Titan Sequence Concluded.")