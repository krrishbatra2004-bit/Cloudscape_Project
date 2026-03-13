import asyncio
import logging
import time
import traceback
import sys
import importlib
from pathlib import Path
from typing import List, Dict, Any

from core.config import config
from engines.aws_engine import AWSEngine
from engines.azure_engine import AzureEngine

# ==============================================================================
# TITAN DYNAMIC NAMESPACE RESOLVER
# ==============================================================================
# Eliminates all "ModuleNotFoundError" crashes by physically mapping the 
# directory tree and bypassing hardcoded Python namespace expectations.
# ==============================================================================

def _dynamic_titan_import(file_stems: list, class_hints: list):
    root_dir = Path(__file__).parent.parent
    if str(root_dir) not in sys.path:
        sys.path.insert(0, str(root_dir))
        
    target_import_str = None
    
    for stem in file_stems:
        for p in root_dir.rglob(f"{stem}.py"):
            # Exclude virtual environments and caches from the hunt
            if "venv" not in p.parts and ".venv" not in p.parts and "__pycache__" not in p.parts:
                rel_path = p.relative_to(root_dir)
                target_import_str = ".".join(rel_path.with_suffix("").parts)
                break
        if target_import_str:
            break
            
    if not target_import_str:
        raise FileNotFoundError(f"Titan Resolver Failed: Could not locate any physical files matching {file_stems}")
        
    module = importlib.import_module(target_import_str)
    
    for hint in class_hints:
        if hasattr(module, hint):
            return getattr(module, hint)
            
    raise ImportError(f"Titan Resolver loaded {target_import_str}, but failed to extract classes {class_hints}")

# Dynamically bind the core subsystems regardless of folder capitalization
try:
    from engines.hybrid_bridge import HybridBridge
except ImportError:
    from Engines.hybrid_bridge import HybridBridge

GraphIngestorClass = _dynamic_titan_import(["ingestor", "graph_ingestor"], ["GraphIngestor", "Ingestor"])
StateFactoryClass = _dynamic_titan_import(["state_factory", "simulation"], ["StateFactory"])
IdentityFabricClass = _dynamic_titan_import(["identity_fabric"], ["IdentityFabric"])
AttackPathEngineClass = _dynamic_titan_import(["attack_path", "hapd"], ["AttackPathEngine", "AttackPath"])


# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - MASTER ORCHESTRATOR (TITAN EDITION)
# ==============================================================================
# The Central Nervous System of the Nexus Multi-Cloud Scan.
# Perfectly synchronized with the physical API contracts of the sub-modules.
# ==============================================================================

class CloudscapeOrchestrator:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Core.Orchestrator")
        
        # Instantiate the dynamically resolved classes
        self.ingestor = GraphIngestorClass()
        self.state_factory = StateFactoryClass()
        self.hybrid_bridge = HybridBridge()
        self.identity_fabric = IdentityFabricClass()
        self.attack_path_engine = AttackPathEngineClass()
        
        # Pydantic Configuration Pulls
        self.max_tenants = config.settings.orchestrator.max_concurrent_tenants
        self.mode = config.settings.execution_mode.upper()
        
        # Titan Gatekeeper: Prevents Docker Mutex Deadlocks
        self._heavy_service_semaphore = asyncio.Semaphore(3 if self.mode == "MOCK" else 20)
        
        # Master State Containers
        self.discovery_results: List[Dict[str, Any]] = []
        self.synthetic_nodes: List[Dict[str, Any]] = []
        self.unified_graph: List[Dict[str, Any]] = []
        self.trust_edges: List[Dict[str, Any]] = []
        self.path_results: List[Dict[str, Any]] = []
        
        # Forensic Latency Trackers
        self.forensics = {
            "Phase_1_Extraction": 0.0,
            "Phase_2_Forging": 0.0,
            "Phase_3_Convergence": 0.0,
            "Phase_4_Intelligence": 0.0,
        }

    async def execute_global_scan(self):
        """
        Executes the absolute 4-Phase Titan Convergence Sequence.
        """
        self.logger.info("=" * 80)
        self.logger.info(f" IGNITING NEXUS 5.0 TITAN PIPELINE ({len(config.tenants)} Tenants Detected)")
        self.logger.info("=" * 80)

        global_start_time = time.perf_counter()

        # ----------------------------------------------------------------------
        # PRE-FLIGHT: Schema & Kernel Validation
        # ----------------------------------------------------------------------
        self.logger.info("Executing Titan Pre-Flight Diagnostics & Schema Validation...")
        try:
            await self.ingestor.validate_schema()
        except Exception as e:
            self.logger.critical(f"FATAL: Database Kernel Validation Failed: {e}")
            self.logger.debug(traceback.format_exc())
            return

        # ----------------------------------------------------------------------
        # PHASE 1: ASYNCHRONOUS EXTRACTION (GATEKEEPER FAN-OUT)
        # ----------------------------------------------------------------------
        self.logger.info("Deploying Asynchronous Fan-Out Matrix for Multi-Cloud Sensors...")
        p1_start = time.perf_counter()
        
        aws_tasks = []
        azure_tasks = []

        for index, tenant in enumerate(config.tenants):
            azure_engine = AzureEngine(tenant)
            aws_engine = AWSEngine(tenant)
            
            azure_tasks.append(self._execute_engine_safe(azure_engine))
            aws_tasks.append(self._staggered_aws_execution(aws_engine, index))

        try:
            results = await asyncio.gather(*azure_tasks, *aws_tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    self.logger.error(f"Catastrophic failure in Engine Task: {result}")
                elif isinstance(result, list):
                    self.discovery_results.extend(result)
        except Exception as e:
            self.logger.error(f"Phase 1 Fan-Out collapsed: {e}")
            
        self.forensics["Phase_1_Extraction"] = time.perf_counter() - p1_start

        # ----------------------------------------------------------------------
        # PHASE 2: SYNTHETIC STATE FORGING (PHYSICALLY ALIGNED)
        # ----------------------------------------------------------------------
        self.logger.info("Igniting the Titan Synthetic State Factory...")
        p2_start = time.perf_counter()
        
        try:
            for tenant in config.tenants:
                # Contract Alignment: Passed full TenantConfig to correct method name
                vulnerabilities = self.state_factory.generate_synthetic_topology(tenant)
                if vulnerabilities:
                    self.synthetic_nodes.extend(vulnerabilities)
        except Exception as e:
            self.logger.error(f"Phase 2 Synthetic Forging Failed: {e}")
            self.logger.debug(traceback.format_exc())
            
        self.forensics["Phase_2_Forging"] = time.perf_counter() - p2_start

        # ----------------------------------------------------------------------
        # PHASE 3: HYBRID CONVERGENCE (PHYSICALLY ALIGNED)
        # ----------------------------------------------------------------------
        self.logger.info("Initializing Chunked Hybrid Convergence Stream...")
        p3_start = time.perf_counter()
        
        try:
            # Contract Alignment: Employs empty constructor and dedicated merge method
            self.unified_graph = self.hybrid_bridge.merge_payload_streams(
                live_stream=self.discovery_results, 
                synthetic_stream=self.synthetic_nodes
            )
            
            if self.unified_graph:
                self.logger.info(f"Materializing chunk of {len(self.unified_graph)} Unified Nodes to Database...")
                # Contract Alignment: Uses the unified process_payloads gateway
                await self.ingestor.process_payloads("HybridBridge", self.unified_graph)
            else:
                self.logger.warning("Hybrid Convergence yielded 0 nodes. Database materialization skipped.")
                
        except Exception as e:
            self.logger.error(f"Phase 3 Convergence and Materialization Failed: {e}")
            self.logger.debug(traceback.format_exc())
            
        self.forensics["Phase_3_Convergence"] = time.perf_counter() - p3_start

        # ----------------------------------------------------------------------
        # PHASE 4: GLOBAL INTELLIGENCE ENRICHMENT (PHYSICALLY ALIGNED)
        # ----------------------------------------------------------------------
        self.logger.info("Commencing Global Intelligence Enrichment & Graph Traversal...")
        p4_start = time.perf_counter()
        
        try:
            # 4a. Cross-Cloud Identity Fabric
            self.logger.info("Igniting Cross-Cloud Identity Traversal Matrix...")
            self.trust_edges = self.identity_fabric.calculate_cross_cloud_trusts(self.unified_graph)
            
            if self.trust_edges:
                self.logger.info(f"Materializing {len(self.trust_edges)} Cross-Cloud Identity Bridges...")
                await self.ingestor.process_payloads("IdentityFabric", self.trust_edges)
            
            # 4b. Heuristic Attack Path Discovery
            self.logger.info("Initializing NetworkX Directed Topological Graph...")
            self.path_results = self.attack_path_engine.calculate_attack_paths(
                unified_graph=self.unified_graph, 
                identity_edges=self.trust_edges
            )
            
            if self.path_results:
                self.logger.info(f"Materializing {len(self.path_results)} Critical Attack Paths...")
                await self.ingestor.process_payloads("AttackPathEngine", self.path_results)
            
        except Exception as e:
            self.logger.error(f"Phase 4 Intelligence Traversal Failed: {e}")
            self.logger.debug(traceback.format_exc())
            
        self.forensics["Phase_4_Intelligence"] = time.perf_counter() - p4_start

        # ----------------------------------------------------------------------
        # PIPELINE TEARDOWN & LATENCY FORENSICS
        # ----------------------------------------------------------------------
        self.logger.info("Executing Graceful Pipeline Teardown...")
        total_time = time.perf_counter() - global_start_time
        self._render_terminal_forensics(total_time)

    # ==========================================================================
    # GATEKEEPER ASYNC ROUTING LOGIC
    # ==========================================================================

    async def _execute_engine_safe(self, engine) -> List[Dict[str, Any]]:
        try:
            return await engine.discover()
        except Exception as e:
            self.logger.error(f"Engine execution halted for {engine.tenant.id}: {e}")
            self.logger.debug(traceback.format_exc())
            return []

    async def _staggered_aws_execution(self, engine: AWSEngine, index: int) -> List[Dict[str, Any]]:
        """Prevents LocalStack Mutex Deadlocks by staggering the AWS thread launch."""
        if self.mode == "MOCK":
            delay = 4.5 * index
            if delay > 0:
                self.logger.info(f"[{engine.tenant.id}] Gatekeeper Holding AWS ignition for {delay:.1f}s to prevent emulator saturation...")
                await asyncio.sleep(delay)
                
        async with self._heavy_service_semaphore:
            return await self._execute_engine_safe(engine)

    # ==========================================================================
    # FORENSIC REPORTING
    # ==========================================================================

    def _render_terminal_forensics(self, total_time: float):
        live_aws = len([n for n in self.discovery_results if n.get("cloud_provider") == "aws"])
        live_azure = len([n for n in self.discovery_results if n.get("cloud_provider") == "azure"])
        synthetic_count = len(self.synthetic_nodes)
        total_nodes = len(self.unified_graph)
        
        edges_count = len(self.trust_edges) if self.trust_edges else 0
        paths_count = len(self.path_results) if self.path_results else 0

        print("\n" + "=" * 80)
        print(" 🌌 TITAN GLOBAL SCAN COMPLETE")
        print("=" * 80)
        print(f" [ INFRASTRUCTURE MESH ]")
        print(f"   ├─ Live AWS Nodes Discovered   : {live_aws}")
        print(f"   ├─ Live Azure Nodes Discovered : {live_azure}")
        print(f"   ├─ Synthetic Nodes Forged      : {synthetic_count}")
        print(f"   └─ Total Unified Graph Nodes   : {total_nodes}")
        print("-" * 80)
        print(f" [ INTELLIGENCE FABRIC ]")
        print(f"   ├─ Cross-Cloud Identity Bridges: {edges_count}")
        print(f"   └─ Critical Attack Paths Found : {paths_count}")
        print("-" * 80)
        print(f" [ LATENCY FORENSICS ]")
        print(f"   ├─ Phase_1_Extraction        : {self.forensics['Phase_1_Extraction']:.2f}s")
        print(f"   ├─ Phase_2_Forging           : {self.forensics['Phase_2_Forging']:.2f}s")
        print(f"   ├─ Phase_3_Convergence       : {self.forensics['Phase_3_Convergence']:.2f}s")
        print(f"   ├─ Phase_4_Intelligence      : {self.forensics['Phase_4_Intelligence']:.2f}s")
        print(f"   └─ Total Execution Time        : {total_time:.2f}s")
        print("=" * 80 + "\n")
        
        self.logger.info("Cloudscape Nexus Titan Sequence Concluded.")