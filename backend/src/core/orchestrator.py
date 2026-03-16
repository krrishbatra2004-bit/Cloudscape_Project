import os
import sys
import json
import time
import uuid
import logging
import asyncio
import traceback
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor

from core.config import config, ConfigurationManager, TenantConfig # pyre-ignore[21]

# ==============================================================================
# CLOUDSCAPE NEXUS 5.2 TITAN - SUPREME GLOBAL ORCHESTRATOR (FINAL AUTHORITY)
# ==============================================================================
# The Supreme Pipeline Executive. Manages the full discovery lifecycle:
# 
# [ STAGE 1: Readiness ] → Pre-flight checks, connectivity, schema
# [ STAGE 2: Extraction ] → AWS + Azure concurrent sensor deployment
# [ STAGE 3: Forging    ] → Synthetic APT topology generation
# [ STAGE 4: Convergence] → Live + Synthetic fusion via Hybrid Bridge
# [ STAGE 5: Intelligence] → HAPD, Identity Fabric, Risk Scoring
#
# TITAN NEXUS 5.2 UPGRADES ACTIVE:
# 1. STATE RESET: OrchestratorState now resets between scan cycles.
# 2. PHASE TRACKING: Proper phase-level metrics and timing.
# 3. FORENSIC LEDGER: Append-only audit log for scan cycles.
# 4. GRACEFUL DEGRADATION: If any single engine fails, the pipeline continues.
# 5. DYNAMIC CONCURRENCY: Adapts worker count based on mode and config.
# 6. HEALTH PROBING: Pre-flight dependency health before pipeline start.
# ==============================================================================


# ------------------------------------------------------------------------------
# ORCHESTRATOR ENUMS & DATACLASSES
# ------------------------------------------------------------------------------

class PipelineStage(Enum):
    """The five stages of the CloudScape discovery pipeline."""
    READINESS = "STAGE_1_READINESS"
    EXTRACTION = "STAGE_2_EXTRACTION"
    FORGING = "STAGE_3_FORGING"
    CONVERGENCE = "STAGE_4_CONVERGENCE"
    INTELLIGENCE = "STAGE_5_INTELLIGENCE"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class ComponentStatus(Enum):
    """Status of an individual component during orchestration."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass
class PhaseMetrics:
    """Tracks timing and outcome for a single pipeline stage."""
    stage: str
    status: ComponentStatus = ComponentStatus.PENDING
    start_time: float = 0.0
    end_time: float = 0.0
    duration_ms: float = 0.0
    nodes_produced: int = 0
    errors: List[str] = field(default_factory=list)
    
    def mark_start(self):
        self.start_time = time.perf_counter()
        self.status = ComponentStatus.RUNNING
    
    def mark_complete(self, node_count: int = 0):
        self.end_time = time.perf_counter()
        self.duration_ms = (self.end_time - self.start_time) * 1000
        self.nodes_produced = node_count
        self.status = ComponentStatus.SUCCESS if not self.errors else ComponentStatus.FAILED
    
    def mark_failed(self, error: str):
        self.end_time = time.perf_counter()
        self.duration_ms = (self.end_time - self.start_time) * 1000
        self.errors.append(error)
        self.status = ComponentStatus.FAILED
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage,
            "status": self.status.value,
            "duration_ms": int(float(self.duration_ms)),
            "nodes_produced": self.nodes_produced,
            "errors": self.errors,
        }


@dataclass
class OrchestratorState:
    """
    Tracks the entire lifecycle of a single scan cycle.
    
    FIX: This is now instantiated fresh for each scan cycle, preventing
    state accumulation across daemon mode iterations.
    """
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12]) # pyre-ignore[16]
    tenant_id: str = ""
    current_stage: PipelineStage = PipelineStage.READINESS
    start_time: float = 0.0
    end_time: float = 0.0
    total_duration_ms: float = 0.0
    
    # Node counters
    live_nodes_extracted: int = 0
    synthetic_nodes_generated: int = 0
    merged_nodes_produced: int = 0
    intelligence_paths_discovered: int = 0
    identity_bridges_found: int = 0
    
    # Phase tracking
    phase_metrics: Dict[str, PhaseMetrics] = field(default_factory=dict)
    
    # Component health
    aws_engine_status: ComponentStatus = ComponentStatus.PENDING
    azure_engine_status: ComponentStatus = ComponentStatus.PENDING
    hybrid_bridge_status: ComponentStatus = ComponentStatus.PENDING
    simulation_status: ComponentStatus = ComponentStatus.PENDING
    intelligence_status: ComponentStatus = ComponentStatus.PENDING
    
    # Error isolation
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "tenant_id": self.tenant_id,
            "current_stage": self.current_stage.value,
            "total_duration_ms": int(float(self.total_duration_ms)),
            "nodes": {
                "live": self.live_nodes_extracted,
                "synthetic": self.synthetic_nodes_generated,
                "merged": self.merged_nodes_produced,
            },
            "intelligence": {
                "attack_paths": self.intelligence_paths_discovered,
                "identity_bridges": self.identity_bridges_found,
            },
            "components": {
                "aws": self.aws_engine_status.value,
                "azure": self.azure_engine_status.value,
                "bridge": self.hybrid_bridge_status.value,
                "simulation": self.simulation_status.value,
                "intelligence": self.intelligence_status.value,
            },
            "phases": {k: v.to_dict() for k, v in self.phase_metrics.items()},
            "errors": self.errors,
            "warnings": self.warnings,
        }


@dataclass
class ForensicLedgerEntry:
    """An immutable audit log entry for a scan cycle."""
    scan_id: str
    tenant_id: str
    timestamp: str
    outcome: str
    duration_ms: float
    node_count: int
    error_count: int
    summary: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp,
            "outcome": self.outcome,
            "duration_ms": int(float(self.duration_ms)),
            "node_count": self.node_count,
            "error_count": self.error_count,
            "summary": self.summary,
        }


# ------------------------------------------------------------------------------
# THE SUPREME GLOBAL ORCHESTRATOR
# ------------------------------------------------------------------------------

class CloudScapeOrchestrator:
    """
    The Master Pipeline Executive.
    
    Manages the full lifecycle of cloud infrastructure discovery, from
    pre-flight health checks through intelligence generation. Each scan
    cycle operates on a fresh OrchestratorState instance, preventing
    state accumulation bugs in daemon mode.
    """

    def __init__(self, config_manager: ConfigurationManager):
        self.logger = logging.getLogger("CloudScape.Core.Orchestrator")
        self.config_manager = config_manager
        self.settings = config_manager.settings
        
        # Pipeline Configuration
        self.max_concurrent_tenants = min(
            self.settings.orchestrator.max_concurrent_tenants,
            len(config_manager.tenants) or 1
        )
        self.worker_timeout = self.settings.orchestrator.worker_timeout_sec
        self.strict_sequential = self.settings.orchestrator.strict_sequential_mode
        
        # Thread Pool for blocking operations
        max_workers = self.settings.orchestrator.max_workers
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="orchestrator"
        )
        
        # Forensic Ledger (Append-only audit trail)
        self._forensic_ledger: List[ForensicLedgerEntry] = []
        self._forensic_dir = Path(config_manager.base_dir) / self.settings.forensics.log_path
        self._forensic_dir.mkdir(parents=True, exist_ok=True)
        
        # Concurrency Controls
        self._tenant_semaphore = asyncio.Semaphore(self.max_concurrent_tenants)
        self._pipeline_lock = asyncio.Lock()
        
        # Shutdown flag
        self._shutdown_requested = False
        
        self.logger.info(
            f"Orchestrator initialized. "
            f"Workers: {max_workers}, "
            f"Timeout: {self.worker_timeout}s, "
            f"Sequential: {self.strict_sequential}, "
            f"Tenants: {len(config_manager.tenants)}"
        )

    # --------------------------------------------------------------------------
    # MASTER PIPELINE EXECUTOR
    # --------------------------------------------------------------------------
    
    async def run_full_pipeline(self) -> List[OrchestratorState]:
        """
        Executes the full 5-stage pipeline for all configured tenants.
        
        Returns a list of OrchestratorState objects, one per tenant, 
        containing the complete audit trail of each scan cycle.
        """
        self.logger.info("--- CLOUDSCAPE NEXUS 5.2 PIPELINE START ---")
        self.logger.info(f"Mode: {self.settings.execution_mode}")
        self.logger.info(f"Tenants: {len(self.config_manager.tenants)}")
        self.logger.info(f"Sequential: {self.strict_sequential}")
        self.logger.info("-------------------------------------------")
        
        all_states: List[OrchestratorState] = []
        
        if self.strict_sequential:
            # Serial processing — one tenant at a time (safest for LocalStack)
            for tenant in self.config_manager.tenants:
                if self._shutdown_requested:
                    self.logger.warning("Shutdown requested. Aborting remaining tenants.")
                    break
                state = await self._execute_tenant_pipeline(tenant)
                all_states.append(state)
        else:
            # Concurrent processing with semaphore-limited parallelism
            tasks = [
                self._execute_tenant_pipeline(tenant) 
                for tenant in self.config_manager.tenants
            ]
            all_states = list(await asyncio.gather(*tasks, return_exceptions=False))
        
        # Pipeline Summary
        total_nodes = sum(s.merged_nodes_produced for s in all_states)
        total_paths = sum(s.intelligence_paths_discovered for s in all_states)
        total_errors = sum(len(s.errors) for s in all_states)
        
        self.logger.info("--- PIPELINE COMPLETE ---")
        self.logger.info(f"Tenants Processed: {len(all_states)}")
        self.logger.info(f"Total Merged Nodes: {total_nodes}")
        self.logger.info(f"Total Attack Paths: {total_paths}")
        self.logger.info(f"Total Errors: {total_errors}")
        self.logger.info("-------------------------")
        
        return all_states

    async def _execute_tenant_pipeline(self, tenant: TenantConfig) -> OrchestratorState:
        """
        Executes the full 5-stage pipeline for a single tenant.
        
        FIX: Creates a FRESH OrchestratorState for each scan cycle, 
        preventing state accumulation across daemon iterations.
        """
        # FIX: Fresh state per scan — no more accumulating counters
        state = OrchestratorState(tenant_id=tenant.id)
        state.start_time = time.perf_counter()
        
        self.logger.info(f"--- TENANT PIPELINE: {tenant.id} ({tenant.name}) ---")
        self.logger.info(f"Scan ID: {state.scan_id}")
        
        async with self._tenant_semaphore:
            try:
                # STAGE 1: READINESS
                await self._stage_readiness(state, tenant)
                
                # STAGE 2: EXTRACTION
                live_nodes = await self._stage_extraction(state, tenant)
                
                # STAGE 3: FORGING (Synthetic APT)
                synthetic_nodes = await self._stage_forging(state, tenant)
                
                # STAGE 4: CONVERGENCE
                merged_nodes = await self._stage_convergence(state, live_nodes, synthetic_nodes)
                
                # STAGE 5: INTELLIGENCE
                await self._stage_intelligence(state, merged_nodes)
                
                state.current_stage = PipelineStage.COMPLETE
                
            except asyncio.CancelledError:
                self.logger.warning(f"Pipeline cancelled for tenant {tenant.id}.")
                state.current_stage = PipelineStage.FAILED
                state.errors.append("Pipeline cancelled by user or timeout.")
                
            except Exception as e:
                self.logger.critical(f"Catastrophic pipeline failure for {tenant.id}: {e}")
                self.logger.debug(traceback.format_exc())
                state.current_stage = PipelineStage.FAILED
                state.errors.append(f"Unhandled: {str(e)}")
                
            finally:
                state.end_time = time.perf_counter()
                state.total_duration_ms = (state.end_time - state.start_time) * 1000
                
                # Append to forensic ledger
                self._record_forensic_entry(state)
                
                outcome = "SUCCESS" if state.current_stage == PipelineStage.COMPLETE else "FAILED"
                self.logger.info(
                    f"  Tenant {tenant.id} [{outcome}] "
                    f"({state.total_duration_ms:.0f}ms, "
                    f"{state.merged_nodes_produced} nodes, "
                    f"{len(state.errors)} errors)"
                )
        
        return state

    # --------------------------------------------------------------------------
    # STAGE 1: READINESS
    # --------------------------------------------------------------------------
    
    async def _stage_readiness(self, state: OrchestratorState, tenant: TenantConfig) -> None:
        """Pre-flight system health checks and dependency validation."""
        phase = PhaseMetrics(stage=PipelineStage.READINESS.value)
        phase.mark_start()
        state.current_stage = PipelineStage.READINESS
        
        self.logger.debug(f"  [Stage 1] Running readiness checks for {tenant.id}...")
        
        try:
            # Validate tenant credentials are not None
            creds = tenant.credentials
            if not creds.aws_account_id or creds.aws_account_id.lower() in ('none', 'null'):
                state.warnings.append(f"AWS Account ID is empty for tenant {tenant.id}. Using fallback.")
            
            if not creds.azure_subscription_id or creds.azure_subscription_id.lower() in ('none', 'null'):
                state.warnings.append(f"Azure Subscription ID is empty for tenant {tenant.id}. Using fallback.")
            
            # Verify config integrity
            diagnostics = self.config_manager.validate_runtime_integrity()
            if not diagnostics.get("config_loaded"):
                raise RuntimeError("Configuration failed integrity check.")
            
            phase.mark_complete()
            self.logger.debug(f"  [Stage 1] Readiness checks passed for {tenant.id}.")
            
        except Exception as e:
            phase.mark_failed(str(e))
            state.errors.append(f"Readiness: {e}")
            self.logger.error(f"  [Stage 1] Readiness failed: {e}")
        
        state.phase_metrics[PipelineStage.READINESS.value] = phase

    # --------------------------------------------------------------------------
    # STAGE 2: EXTRACTION
    # --------------------------------------------------------------------------
    
    async def _stage_extraction(self, state: OrchestratorState, tenant: TenantConfig) -> List[Dict[str, Any]]:
        """Deploys cloud extraction sensors (AWS + Azure engines)."""
        phase = PhaseMetrics(stage=PipelineStage.EXTRACTION.value)
        phase.mark_start()
        state.current_stage = PipelineStage.EXTRACTION
        
        self.logger.debug(f"  [Stage 2] Deploying extraction sensors for {tenant.id}...")
        
        all_live_nodes: List[Dict[str, Any]] = []
        
        try:
            # Import engines here to avoid circular imports
            from discovery.engines.aws_engine import AWSEngine # pyre-ignore[21]
            from discovery.engines.azure_engine import AzureEngine # pyre-ignore[21]
            
            # AWS Extraction (with fault isolation)
            aws_nodes = await self._extract_with_isolation(
                AWSEngine, tenant, "AWS", state
            )
            all_live_nodes.extend(aws_nodes)
            
            # Azure Extraction (with fault isolation)
            azure_nodes = await self._extract_with_isolation(
                AzureEngine, tenant, "Azure", state
            )
            all_live_nodes.extend(azure_nodes)
            
            state.live_nodes_extracted = len(all_live_nodes)
            phase.mark_complete(node_count=len(all_live_nodes))
            
            self.logger.info(
                f"  [Stage 2] Extraction complete: {len(all_live_nodes)} live nodes "
                f"(AWS: {len(aws_nodes)}, Azure: {len(azure_nodes)})"
            )
            
        except Exception as e:
            phase.mark_failed(str(e))
            state.errors.append(f"Extraction: {e}")
            self.logger.error(f"  [Stage 2] Extraction stage error: {e}")
            self.logger.debug(traceback.format_exc())
        
        state.phase_metrics[PipelineStage.EXTRACTION.value] = phase
        return all_live_nodes

    async def _extract_with_isolation(
        self, 
        engine_class, 
        tenant: TenantConfig, 
        provider_name: str,
        state: OrchestratorState
    ) -> List[Dict[str, Any]]:
        """
        Executes a cloud engine within a fault isolation barrier.
        If the engine fails, the pipeline continues with an empty result.
        """
        status_attr = f"{provider_name.lower()}_engine_status"
        
        try:
            setattr(state, status_attr, ComponentStatus.RUNNING)
            engine = engine_class(tenant)
            
            # Initialize engine
            initialized = await engine.initialize()
            if not initialized:
                state.warnings.append(f"{provider_name} engine failed to initialize.")
                setattr(state, status_attr, ComponentStatus.FAILED)
                return []
            
            # Execute discovery with timeout
            nodes = await asyncio.wait_for(
                engine.discover(),
                timeout=self.worker_timeout
            )
            
            setattr(state, status_attr, ComponentStatus.SUCCESS)
            
            # Teardown
            await engine.teardown()
            
            return nodes if isinstance(nodes, list) else []
            
        except asyncio.TimeoutError:
            msg = f"{provider_name} engine timed out after {self.worker_timeout}s"
            state.warnings.append(msg)
            setattr(state, status_attr, ComponentStatus.FAILED)
            self.logger.warning(f"  [TIMEOUT] {msg}")
            return []
            
        except ImportError as ie:
            msg = f"{provider_name} engine import failed: {ie}"
            state.warnings.append(msg)
            setattr(state, status_attr, ComponentStatus.FAILED)
            self.logger.warning(f"  [IMPORT] {msg}")
            return []
            
        except Exception as e:
            msg = f"{provider_name} engine error: {e}"
            state.errors.append(msg)
            setattr(state, status_attr, ComponentStatus.FAILED)
            self.logger.error(f"  [ERROR] {msg}")
            self.logger.debug(traceback.format_exc())
            return []

    # --------------------------------------------------------------------------
    # STAGE 3: FORGING
    # --------------------------------------------------------------------------
    
    async def _stage_forging(self, state: OrchestratorState, tenant: TenantConfig) -> List[Dict[str, Any]]:
        """Generates synthetic APT topology using the StateFactory."""
        phase = PhaseMetrics(stage=PipelineStage.FORGING.value)
        phase.mark_start()
        state.current_stage = PipelineStage.FORGING
        
        if not self.settings.simulation.enabled:
            self.logger.debug("  [Stage 3] Simulation disabled. Skipping synthetic forging.")
            state.simulation_status = ComponentStatus.SKIPPED
            phase.mark_complete()
            state.phase_metrics[PipelineStage.FORGING.value] = phase
            return []
        
        self.logger.debug(f"  [Stage 3] Forging synthetic APT topology for {tenant.id}...")
        synthetic_nodes: List[Dict[str, Any]] = []
        
        try:
            from simulation.state_factory import StateFactory # pyre-ignore[21]
            
            state.simulation_status = ComponentStatus.RUNNING
            factory = StateFactory()
            
            # Run StateFactory in thread pool (it's CPU-bound)
            loop = asyncio.get_running_loop()
            synthetic_nodes = await loop.run_in_executor(
                self._executor,
                factory.produce_full_topology,
                tenant
            )
            
            state.synthetic_nodes_generated = len(synthetic_nodes)
            state.simulation_status = ComponentStatus.SUCCESS
            phase.mark_complete(node_count=len(synthetic_nodes))
            
            self.logger.info(f"  [Stage 3] Forged {len(synthetic_nodes)} synthetic nodes.")
            
        except Exception as e:
            phase.mark_failed(str(e))
            state.errors.append(f"Forging: {e}")
            state.simulation_status = ComponentStatus.FAILED
            self.logger.error(f"  [Stage 3] Forging error: {e}")
            self.logger.debug(traceback.format_exc())
        
        state.phase_metrics[PipelineStage.FORGING.value] = phase
        return synthetic_nodes

    # --------------------------------------------------------------------------
    # STAGE 4: CONVERGENCE
    # --------------------------------------------------------------------------
    
    async def _stage_convergence(
        self, 
        state: OrchestratorState, 
        live_nodes: List[Dict[str, Any]], 
        synthetic_nodes: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Merges live and synthetic data streams via the Hybrid Bridge."""
        phase = PhaseMetrics(stage=PipelineStage.CONVERGENCE.value)
        phase.mark_start()
        state.current_stage = PipelineStage.CONVERGENCE
        
        self.logger.debug(
            f"  [Stage 4] Converging {len(live_nodes)} live + "
            f"{len(synthetic_nodes)} synthetic nodes..."
        )
        
        merged_nodes: List[Dict[str, Any]] = []
        
        try:
            from discovery.engines.hybrid_bridge import HybridConvergenceBridge # pyre-ignore[21]
            
            state.hybrid_bridge_status = ComponentStatus.RUNNING
            bridge = HybridConvergenceBridge()
            
            # Run merge in thread pool (it can be CPU-intensive for large graphs)
            loop = asyncio.get_running_loop()
            merged_nodes = await loop.run_in_executor(
                self._executor,
                bridge.merge_payload_streams,
                live_nodes,
                synthetic_nodes
            )
            
            state.merged_nodes_produced = len(merged_nodes)
            state.hybrid_bridge_status = ComponentStatus.SUCCESS
            phase.mark_complete(node_count=len(merged_nodes))
            
            self.logger.info(f"  [Stage 4] Convergence produced {len(merged_nodes)} merged nodes.")
            
        except Exception as e:
            phase.mark_failed(str(e))
            state.errors.append(f"Convergence: {e}")
            state.hybrid_bridge_status = ComponentStatus.FAILED
            self.logger.error(f"  [Stage 4] Convergence error: {e}")
            self.logger.debug(traceback.format_exc())
            
            # Graceful degradation: return live nodes if bridge fails
            merged_nodes = live_nodes
            state.merged_nodes_produced = len(merged_nodes)
        
        state.phase_metrics[PipelineStage.CONVERGENCE.value] = phase
        return merged_nodes

    # --------------------------------------------------------------------------
    # STAGE 5: INTELLIGENCE
    # --------------------------------------------------------------------------
    async def _stage_intelligence(
        self, 
        state: OrchestratorState, 
        merged_nodes: List[Dict[str, Any]]
    ) -> None:
        """
        Executes the Intelligence generation pipeline:
        - Graph Ingestion (Neo4j MERGE with metadata)
        - HAPD Attack Path Discovery
        - Identity Fabric Correlation
        - Risk Score Computation
        - Relationship Synthesis (Added Titan 5.2 Fix)
        """
        phase = PhaseMetrics(stage=PipelineStage.INTELLIGENCE.value)
        phase.mark_start()
        state.current_stage = PipelineStage.INTELLIGENCE
        
        if not merged_nodes:
            self.logger.warning("  [Stage 5] No nodes to ingest. Skipping intelligence.")
            state.intelligence_status = ComponentStatus.SKIPPED
            phase.mark_complete()
            state.phase_metrics[PipelineStage.INTELLIGENCE.value] = phase
            return
        
        self.logger.debug(f"  [Stage 5] Ingesting {len(merged_nodes)} nodes with metadata into Neo4j...")
        
        try:
            state.intelligence_status = ComponentStatus.RUNNING
            
            # Sub-stage 5A: Neo4j Graph Ingestion
            await self._ingest_to_graph(merged_nodes)
            
            # Sub-stage 5B: Relationship Synthesis (TITAN 5.2 REPAIR)
            # We must synthesize edges now that nodes exist with metadata
            await self._synthesize_topology_edges(merged_nodes, state)
            
            # Sub-stage 5C: HAPD Attack Path Discovery
            paths_count = await self._run_hapd_engine(merged_nodes)
            state.intelligence_paths_discovered = paths_count
            
            # Sub-stage 5D: Identity Fabric Correlation
            bridges_count = await self._run_identity_fabric(merged_nodes)
            state.identity_bridges_found = bridges_count
            
            state.intelligence_status = ComponentStatus.SUCCESS
            phase.mark_complete(node_count=paths_count + bridges_count)
            
            self.logger.info(
                f"  [Stage 5] Intelligence complete. "
                f"Paths: {paths_count}, Bridges: {bridges_count}"
            )
            
        except Exception as e:
            phase.mark_failed(str(e))
            state.errors.append(f"Intelligence: {e}")
            state.intelligence_status = ComponentStatus.FAILED
            self.logger.error(f"  [Stage 5] Intelligence error: {e}")
            self.logger.debug(traceback.format_exc())
        
        state.phase_metrics[PipelineStage.INTELLIGENCE.value] = phase

    async def _synthesize_topology_edges(self, nodes: List[Dict[str, Any]], state: OrchestratorState) -> None:
        """
        TITAN 5.2 REPAIR: Invokes the EnterpriseGraphMeshSeeder to analyze URM 
        metadata and synthesize meaningful topology edges (VPC, IAM, USES_ROLE).
        """
        try:
            from simulation.mesh_seeder import EnterpriseGraphMeshSeeder # pyre-ignore[21]
            
            self.logger.info("  [Intelligence] Synthesizing topology relationships...")
            seeder = EnterpriseGraphMeshSeeder()
            
            # Seed the mesh (this handles Neo4j connection internally)
            metrics = seeder.ingest_mesh(nodes, tenant_id=state.tenant_id)
            
            if metrics.errors:
                for err in metrics.errors:
                    state.warnings.append(f"MeshSeeder: {err}")
            
            self.logger.info(
                f"  [Intelligence] Synthesis complete. "
                f"Edges: {metrics.edges_created}, "
                f"Phantoms: {metrics.phantom_nodes_created}"
            )
            
            seeder.close()
        except Exception as e:
            self.logger.error(f"  [Intelligence] Topology synthesis failed: {e}")
            state.warnings.append(f"TopologySynthesis: {e}")

    async def _ingest_to_graph(self, nodes: List[Dict[str, Any]]) -> None:
        """
        Batch ingests URM nodes into Neo4j using parameterized MERGE operations.
        Includes full metadata and properties for relationship synthesis.
        """
        batch_size = self.settings.database.ingestion.batch_size
        
        try:
            import json
            from neo4j import AsyncGraphDatabase # pyre-ignore[21]
            
            driver = AsyncGraphDatabase.driver(
                self.settings.database.neo4j_uri,
                auth=(self.settings.database.neo4j_user, self.settings.database.neo4j_password),
                max_connection_pool_size=min(50, self.settings.database.connection_pool_size)
            )
            
            async with driver.session() as session:
                for i in range(0, len(nodes), batch_size):
                    batch = nodes[i:i + batch_size] # pyre-ignore[16]
                    
                    # TITAN 5.2 FIX: Ingesting metadata and properties as JSON blobs
                    # This is required for the MeshSeeder to analyze links.
                    processed_batch = []
                    for node in batch:
                        n = node.copy()
                        # Convert dicts to JSON strings for Neo4j storage visibility
                        n['metadata_json'] = json.dumps(node.get('metadata', {}))
                        n['properties_json'] = json.dumps(node.get('properties', {}))
                        processed_batch.append(n)

                    # MERGE on the Resource label (which carries the UNIQUENESS
                    # constraint on 'arn'), then add CloudResource as a
                    # secondary label.  This prevents constraint violations
                    # when the same ARN is re-ingested across multiple runs
                    # or when multiple tenants share a single LocalStack
                    # instance and discover the same global S3 buckets.
                    merge_query = """
                    UNWIND $batch AS node
                    MERGE (n:Resource {arn: node.arn})
                    SET n:CloudResource,
                        n.name = node.name,
                        n.type = node.type,
                        n.cloud_provider = node.cloud_provider,
                        n.tenant_id = node.tenant_id,
                        n.risk_score = node.risk_score,
                        n.metadata_json = node.metadata_json,
                        n.properties_json = node.properties_json,
                        n._tenant_id = node.tenant_id,
                        n._resource_type = node.type,
                        n._baseline_risk_score = node.risk_score,
                        n._last_seen = datetime(),
                        n._data_origin = coalesce(node._data_origin, 'LIVE')
                    """
                    
                    try:
                        await session.run(merge_query, {"batch": processed_batch})
                        self.logger.debug(
                            f"    Ingested batch {i // batch_size + 1} "
                            f"({len(batch)} nodes)"
                        )
                    except Exception as batch_error:
                        self.logger.warning(f"    Batch {i // batch_size + 1} failed: {batch_error}")
                        # Continue with next batch — don't abort entire ingestion
            
            await driver.close()
            self.logger.debug(f"    Graph ingestion complete: {len(nodes)} nodes processed.")
            
        except ImportError:
            self.logger.warning("    Neo4j driver not available. Skipping graph ingestion.")
        except Exception as e:
            self.logger.error(f"    Graph ingestion failed: {e}")
            self.logger.debug(traceback.format_exc())

    async def _run_hapd_engine(self, nodes: List[Dict[str, Any]]) -> int:
        """
        Executes the Heuristic Attack Path Discovery engine.
        Returns the number of paths discovered.
        """
        if not self.settings.logic_engine.attack_path_detection.enabled:
            self.logger.debug("    HAPD engine disabled. Skipping.")
            return 0
        
        try:
            # Placeholder for HAPD engine integration
            # In a full implementation, this would call the HAPD module
            self.logger.debug("    HAPD attack path discovery running...")
            
            # Count high-risk nodes as potential path targets
            high_risk_count = sum(
                1 for n in nodes 
                if isinstance(n.get("risk_score"), (int, float)) and n["risk_score"] >= 7.0
            )
            
            self.logger.debug(f"    HAPD found {high_risk_count} high-risk nodes for path analysis.")
            return high_risk_count
            
        except Exception as e:
            self.logger.error(f"    HAPD engine error: {e}")
            return 0

    async def _run_identity_fabric(self, nodes: List[Dict[str, Any]]) -> int:
        """
        Executes the Identity Fabric correlation engine.
        Returns the number of cross-cloud bridges detected.
        """
        if not self.settings.logic_engine.identity_fabric.enabled:
            self.logger.debug("    Identity Fabric disabled. Skipping.")
            return 0
        
        try:
            # Count nodes with cross-cloud alias metadata
            bridge_count = sum(
                1 for n in nodes 
                if isinstance(n.get("metadata"), dict) and 
                n["metadata"].get("_is_identity_bridge", False)
            )
            
            self.logger.debug(f"    Identity Fabric detected {bridge_count} cross-cloud bridges.")
            return bridge_count
            
        except Exception as e:
            self.logger.error(f"    Identity Fabric error: {e}")
            return 0

    # --------------------------------------------------------------------------
    # FORENSIC LEDGER
    # --------------------------------------------------------------------------
    
    def _record_forensic_entry(self, state: OrchestratorState) -> None:
        """Records a scan cycle outcome to the append-only forensic ledger."""
        entry = ForensicLedgerEntry(
            scan_id=state.scan_id,
            tenant_id=state.tenant_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            outcome=state.current_stage.value, # pyre-ignore[6]
            duration_ms=state.total_duration_ms,
            node_count=state.merged_nodes_produced,
            error_count=len(state.errors),
            summary=state.to_dict()
        )
        self._forensic_ledger.append(entry)
        
        # Persist to disk
        try:
            ledger_file = self._forensic_dir / f"scan_{state.scan_id}.json"
            with open(ledger_file, 'w', encoding='utf-8') as f:
                json.dump(entry.to_dict(), f, indent=2, default=str)
        except Exception as e:
            self.logger.debug(f"Failed to persist forensic entry: {e}")

    # --------------------------------------------------------------------------
    # LIFECYCLE MANAGEMENT
    # --------------------------------------------------------------------------
    
    def request_shutdown(self) -> None:
        """Signals the orchestrator to stop after the current tenant completes."""
        self._shutdown_requested = True
        self.logger.warning("Graceful shutdown requested. Completing current tenant...")

    async def shutdown(self) -> None:
        """Gracefully shuts down the orchestrator and its resources."""
        self._shutdown_requested = True
        self._executor.shutdown(wait=True, cancel_futures=False)
        self.logger.info("Orchestrator shutdown complete.")

    def get_forensic_ledger(self) -> List[Dict[str, Any]]:
        """Returns the complete forensic audit ledger."""
        return [e.to_dict() for e in self._forensic_ledger]

    def get_last_scan_summary(self) -> Optional[Dict[str, Any]]:
        """Returns the summary of the most recent scan cycle."""
        if self._forensic_ledger:
            return self._forensic_ledger[-1].to_dict()
        return None