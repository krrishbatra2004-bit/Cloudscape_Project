import asyncio
import logging
import time
import traceback
from typing import List, Dict, Any

from core.config import config

# ==============================================================================
# TITAN SINGLETON IMPORTS
# ==============================================================================
# Importing the explicitly instantiated singletons to ensure memory is preserved
# and database connection pools are shared across the entire event loop.
from core.processor.ingestor import graph_ingestor 
from engines.hybrid_bridge import hybrid_bridge
from core.logic.attack_path import attack_path_engine
from core.logic.identity_fabric import IdentityFabric

# ==============================================================================
# ENGINE & FACTORY IMPORTS
# ==============================================================================
from engines.aws_engine import AWSEngine
from engines.azure_engine import AzureEngine
from simulation.state_factory import StateFactory

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - GLOBAL ORCHESTRATOR
# ==============================================================================
# The Master Control Plane. 
# Executes the 5-Phase Discovery, Convergence, and Heuristic Analysis lifecycle.
# Features strict fault-domain isolation and chunked streaming materialization.
# ==============================================================================

class CloudscapeOrchestrator:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Core.Orchestrator")
        
        # Subsystem Initialization
        self.state_factory = StateFactory()
        self.identity_fabric = IdentityFabric()
        
        # Exhaustive Metrics Matrix
        self.metrics = {
            "live_aws_nodes": 0,
            "live_azure_nodes": 0,
            "synthetic_nodes": 0,
            "unified_nodes": 0,
            "identity_bridges": 0,
            "attack_paths": 0,
            "phase_latencies": {}
        }

    async def _run_pre_flight_diagnostics(self) -> bool:
        """
        The Gatekeeper. Verifies that the Neo4j Graph Data Science constraints
        are active before allowing the pipeline to hit cloud APIs.
        """
        self.logger.info("Executing Titan Pre-Flight Diagnostics & Schema Validation...")
        try:
            # Resolves the previous AttributeError by aligning with Titan Ingestor naming
            await graph_ingestor.validate_schema()
            self.logger.info("Graph Schema Validation Complete. Constraints enforced.")
            return True
        except AttributeError as ae:
            self.logger.critical(f"Architecture Desync: graph_ingestor is missing validate_schema(). {ae}")
            return False
        except Exception as e:
            self.logger.critical(f"Pre-Flight Failure: Database unreachable or schema invalid: {e}")
            return False

    async def execute_global_scan(self) -> None:
        """
        The Master Execution Sequence.
        Wraps the entire lifecycle in a protective block to ensure database
        connections are closed cleanly regardless of API or logic failures.
        """
        global_start_time = time.perf_counter()
        tenant_count = len(config.tenants)
        
        self.logger.info("=" * 80)
        self.logger.info(f" IGNITING NEXUS 5.0 TITAN PIPELINE ({tenant_count} Tenants Detected)")
        self.logger.info("=" * 80)

        # Pre-Flight Phase
        if not await self._run_pre_flight_diagnostics():
            self.logger.error("Global Scan Aborted by Pre-Flight Gatekeeper.")
            return

        live_payloads: List[Dict[str, Any]] = []
        synth_payloads: List[Dict[str, Any]] = []
        unified_graph_cache: List[Dict[str, Any]] = []

        try:
            # ------------------------------------------------------------------
            # PHASE 1: ASYNC TELEMETRY EXTRACTION (LIVE MESH)
            # ------------------------------------------------------------------
            phase_start = time.perf_counter()
            for tenant in config.tenants:
                self.logger.info(f"[{tenant.id}] Initiating Multi-Cloud Telemetry Extraction...")
                
                # AWS Isolation Block
                try:
                    aws_engine = AWSEngine(tenant)
                    if await aws_engine.test_connection():
                        aws_data = await aws_engine.discover()
                        live_payloads.extend(aws_data)
                        self.metrics["live_aws_nodes"] += len(aws_data)
                except Exception as e:
                    self.logger.error(f"[{tenant.id}] AWS Sensor Array collapsed: {e}")
                    self.logger.debug(traceback.format_exc())

                # Azure Isolation Block
                try:
                    azure_engine = AzureEngine(tenant)
                    if await azure_engine.test_connection():
                        azure_data = await azure_engine.discover()
                        live_payloads.extend(azure_data)
                        self.metrics["live_azure_nodes"] += len(azure_data)
                except Exception as e:
                    self.logger.error(f"[{tenant.id}] Azure Sensor Array collapsed: {e}")
                    self.logger.debug(traceback.format_exc())

            self.metrics["phase_latencies"]["Phase_1_Extraction"] = round(time.perf_counter() - phase_start, 2)

            # ------------------------------------------------------------------
            # PHASE 2: SYNTHETIC STATE FORGING (SIMULATION)
            # ------------------------------------------------------------------
            phase_start = time.perf_counter()
            self.logger.info("Igniting the Titan Synthetic State Factory...")
            
            for tenant in config.tenants:
                try:
                    synth_data = self.state_factory.generate_synthetic_topology(tenant)
                    synth_payloads.extend(synth_data)
                except Exception as e:
                    self.logger.error(f"[{tenant.id}] Synthetic Factory anomaly: {e}")
                    
            self.metrics["synthetic_nodes"] = len([p for p in synth_payloads if p.get("type") != "explicit_edge"])
            self.metrics["phase_latencies"]["Phase_2_Forging"] = round(time.perf_counter() - phase_start, 2)

            # ------------------------------------------------------------------
            # PHASE 3: HYBRID STREAMING & CHUNKED MATERIALIZATION
            # ------------------------------------------------------------------
            phase_start = time.perf_counter()
            self.logger.info("Initializing Chunked Hybrid Convergence Stream...")
            
            try:
                chunk_size = getattr(config.settings.system, "ingestion_chunk_size", 500)
            except AttributeError:
                chunk_size = 500
                
            try:
                stream = hybrid_bridge.stream_unified_graph(live_payloads, synth_payloads, chunk_size=chunk_size)
                for chunk in stream:
                    if not chunk: 
                        continue
                    
                    # Store in RAM exclusively for the Mathematical Engines downstream
                    unified_graph_cache.extend(chunk)
                    
                    # Pump directly to Neo4j to clear the transaction log buffer
                    self.logger.info(f"Materializing chunk of {len(chunk)} Unified Nodes to Database...")
                    await graph_ingestor.process_payloads("TITAN-CONVERGENCE", chunk)
                    
                self.metrics["unified_nodes"] = len(unified_graph_cache)
            except Exception as e:
                self.logger.critical(f"Hybrid Convergence Stream Collapsed: {e}\n{traceback.format_exc()}")
                
            self.metrics["phase_latencies"]["Phase_3_Convergence"] = round(time.perf_counter() - phase_start, 2)

            # ------------------------------------------------------------------
            # PHASE 4: INTELLIGENCE FABRIC & HEURISTIC ATTACK PATHS (HAPD)
            # ------------------------------------------------------------------
            phase_start = time.perf_counter()
            self.logger.info("Commencing Global Intelligence Enrichment & Graph Traversal...")
            
            try:
                # 4A. Identity Fabric (Cross-Cloud Trusts)
                identity_edges = self.identity_fabric.calculate_cross_cloud_trusts(unified_graph_cache)
                self.metrics["identity_bridges"] = len(identity_edges)
                
                if identity_edges:
                    self.logger.info(f"Materializing {len(identity_edges)} Cross-Cloud Identity Bridges...")
                    await graph_ingestor.process_payloads("IDENTITY-FABRIC", identity_edges)

                # 4B. HAPD Engine (Dijkstra/A* NetworkX Calculations)
                attack_edges = attack_path_engine.calculate_attack_paths(unified_graph_cache, identity_edges)
                self.metrics["attack_paths"] = len(attack_edges)
                
                if attack_edges:
                    self.logger.info(f"Materializing {len(attack_edges)} Critical Attack Paths...")
                    await graph_ingestor.process_payloads("HAPD-ENGINE", attack_edges)
                    
            except Exception as e:
                self.logger.error(f"Logic Engine Matrix Failure: {e}\n{traceback.format_exc()}")

            self.metrics["phase_latencies"]["Phase_4_Intelligence"] = round(time.perf_counter() - phase_start, 2)

        except Exception as fatal_e:
            self.logger.critical(f"FATAL: Unhandled exception in Titan Global Sequence: {fatal_e}\n{traceback.format_exc()}")
            
        finally:
            # ------------------------------------------------------------------
            # PHASE 5: GRACEFUL TEARDOWN & FORENSIC REPORTING
            # ------------------------------------------------------------------
            self.logger.info("Executing Graceful Pipeline Teardown...")
            try:
                await graph_ingestor.close()
            except Exception as e:
                self.logger.error(f"Failed to cleanly close Database Driver: {e}")
                
            total_time = round(time.perf_counter() - global_start_time, 2)
            self._render_forensic_report(total_time)

    def _render_forensic_report(self, total_time: float) -> None:
        """
        Renders the highly detailed terminal UI summary, isolating 
        cloud-specific metrics and exact latency bottlenecks.
        """
        print("\n" + "="*80)
        print(" 🌌 TITAN GLOBAL SCAN COMPLETE")
        print("="*80)
        print(" [ INFRASTRUCTURE MESH ]")
        print(f"   ├─ Live AWS Nodes Discovered   : {self.metrics['live_aws_nodes']}")
        print(f"   ├─ Live Azure Nodes Discovered : {self.metrics['live_azure_nodes']}")
        print(f"   ├─ Synthetic Nodes Forged      : {self.metrics['synthetic_nodes']}")
        print(f"   └─ Total Unified Graph Nodes   : {self.metrics['unified_nodes']}")
        print("-" * 80)
        print(" [ INTELLIGENCE FABRIC ]")
        print(f"   ├─ Cross-Cloud Identity Bridges: {self.metrics['identity_bridges']}")
        print(f"   └─ Critical Attack Paths Found : {self.metrics['attack_paths']}")
        print("-" * 80)
        print(" [ LATENCY FORENSICS ]")
        for phase, latency in self.metrics["phase_latencies"].items():
            print(f"   ├─ {phase:<25} : {latency}s")
        print(f"   └─ Total Execution Time        : {total_time}s")
        print("="*80 + "\n")
        self.logger.info("Cloudscape Nexus Titan Sequence Concluded.")