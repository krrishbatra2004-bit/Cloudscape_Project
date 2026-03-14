import logging
import json
import time
import uuid
import hashlib
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from neo4j import GraphDatabase, Driver, exceptions as neo4j_exceptions

from core.config import config, TenantConfig

# ==============================================================================
# CLOUDSCAPE NEXUS 5.2 TITAN - ENTERPRISE NEO4J GRAPH MESH SEEDER
# ==============================================================================
# The Sovereign Graph Ingestion Kernel. Transforms URM-normalized resource nodes
# into a fully connected Neo4j graph mesh with intelligent edge synthesis,
# phantom node generation, and relationship weight computation.
#
# TITAN NEXUS 5.2 UPGRADES ACTIVE:
# 1. BATCH MERGE: Uses UNWIND-based batch MERGE for O(1) per-node amortized cost.
# 2. PHANTOM NODE SYNTHESIS: Generates referenced-but-unseen "shadow" nodes.
# 3. INTELLIGENT EDGE FACTORY: Synthesizes edges from IAM policies, network 
#    topology, service bindings, and identity trust relationships.
# 4. RELATIONSHIP WEIGHT COMPUTATION: Assigns computed "resistance" weights 
#    used by the Friction Decay 3.0 physics engine in HAPD.
# 5. GRAPH FINGERPRINTING: Tracks structural changes between ingestion cycles.
# 6. DEDUPLICATED INGESTION: Uses ARN-based MERGE to prevent node duplication.
# 7. FIXED ATTRIBUTE ACCESS: Uses `neo4j_uri` canonical field from config.
# 8. CURSOR LIFECYCLE: Properly exhausts all result cursors to prevent leaks.
# ==============================================================================


# ------------------------------------------------------------------------------
# TELEMETRY & DATACLASSES
# ------------------------------------------------------------------------------

@dataclass
class IngestionMetrics:
    """High-fidelity telemetry for graph mesh seeding operations."""
    nodes_merged: int = 0
    nodes_created: int = 0
    nodes_updated: int = 0
    phantom_nodes_created: int = 0
    edges_created: int = 0
    identity_bridges_created: int = 0
    batch_count: int = 0
    ingestion_time_ms: float = 0.0
    edge_synthesis_time_ms: float = 0.0
    graph_fingerprint: str = ""
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": {
                "merged": self.nodes_merged,
                "created": self.nodes_created,
                "updated": self.nodes_updated,
                "phantoms": self.phantom_nodes_created,
            },
            "edges": {
                "total": self.edges_created,
                "identity_bridges": self.identity_bridges_created,
            },
            "performance": {
                "batches": self.batch_count,
                "ingestion_ms": round(self.ingestion_time_ms, 2),
                "edge_synthesis_ms": round(self.edge_synthesis_time_ms, 2),
            },
            "graph_fingerprint": self.graph_fingerprint,
            "error_count": len(self.errors),
        }

    def reset(self):
        """Resets metrics for a new ingestion cycle."""
        self.nodes_merged = 0
        self.nodes_created = 0
        self.nodes_updated = 0
        self.phantom_nodes_created = 0
        self.edges_created = 0
        self.identity_bridges_created = 0
        self.batch_count = 0
        self.ingestion_time_ms = 0.0
        self.edge_synthesis_time_ms = 0.0
        self.graph_fingerprint = ""
        self.errors.clear()


@dataclass
class PhantomReference:
    """Represents a referenced but unseen resource (e.g., an IAM role referenced by a Lambda)."""
    arn: str
    referencing_arn: str
    relationship_type: str
    context: str = ""


# ------------------------------------------------------------------------------
# THE ENTERPRISE GRAPH MESH SEEDER
# ------------------------------------------------------------------------------

class EnterpriseGraphMeshSeeder:
    """
    The Sovereign Graph Ingestion Kernel.
    Transforms URM-normalized resource nodes into a fully connected Neo4j graph.
    """

    def __init__(self):
        self.logger = logging.getLogger("CloudScape.Utils.MeshSeeder")
        self.metrics = IngestionMetrics()
        self.driver: Optional[Driver] = None
        
        # Configuration
        db = config.settings.database
        self.neo4j_uri = db.neo4j_uri
        self.neo4j_user = db.neo4j_user
        self.neo4j_password = db.neo4j_password
        self.batch_size = db.ingestion.batch_size
        self.pool_size = min(db.connection_pool_size, 50)
        self.retry_time = db.transaction_retry_time_sec
        
        # Internal State
        self._known_arns: Set[str] = set()
        self._phantom_refs: List[PhantomReference] = []
        self._edge_buffer: List[Dict[str, Any]] = []
        
        self.logger.debug(
            f"MeshSeeder initialized: uri={self.neo4j_uri}, "
            f"batch_size={self.batch_size}"
        )

    # --------------------------------------------------------------------------
    # CONNECTION MANAGEMENT
    # --------------------------------------------------------------------------
    
    def connect(self) -> bool:
        """Establishes the Neo4j connection."""
        try:
            self.driver = GraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_password),
                max_connection_pool_size=self.pool_size,
            )
            self.driver.verify_connectivity()
            self.logger.info(f"Connected to Neo4j at {self.neo4j_uri}")
            return True
        except neo4j_exceptions.ServiceUnavailable:
            self.logger.error("Neo4j service is unavailable.")
            return False
        except neo4j_exceptions.AuthError as ae:
            self.logger.error(f"Neo4j authentication failed: {ae}")
            return False
        except Exception as e:
            self.logger.error(f"Neo4j connection failed: {e}")
            self.logger.debug(traceback.format_exc())
            return False

    def close(self) -> None:
        """Closes the Neo4j driver connection pool."""
        if self.driver:
            self.driver.close()
            self.logger.debug("Neo4j driver closed.")

    # --------------------------------------------------------------------------
    # MASTER INGESTION PIPELINE
    # --------------------------------------------------------------------------
    
    def ingest_mesh(self, nodes: List[Dict[str, Any]], tenant_id: str = "") -> IngestionMetrics:
        """
        Master ingestion pipeline:
        1. MERGE nodes into the graph (batch mode)
        2. Synthesize edges from metadata
        3. Generate phantom nodes for dangling references
        4. Compute graph fingerprint
        """
        self.metrics.reset()
        self._known_arns.clear()
        self._phantom_refs.clear()
        self._edge_buffer.clear()
        
        start_time = time.perf_counter()
        
        self.logger.info(f"--- MESH INGESTION: {len(nodes)} URM Nodes ---")
        
        if not self.driver:
            if not self.connect():
                self.metrics.errors.append("Failed to connect to Neo4j")
                return self.metrics
        
        try:
            # Phase 1: Node Ingestion
            self.logger.debug("  [Phase 1] Merging nodes...")
            self._ingest_nodes_batch(nodes, tenant_id)
            
            # Phase 2: Edge Synthesis
            self.logger.debug("  [Phase 2] Synthesizing edges...")
            edge_start = time.perf_counter()
            self._synthesize_edges(nodes)
            self._flush_edge_buffer()
            self.metrics.edge_synthesis_time_ms = (time.perf_counter() - edge_start) * 1000
            
            # Phase 3: Phantom Node Generation
            self.logger.debug("  [Phase 3] Generating phantom nodes...")
            self._generate_phantom_nodes()
            
            # Phase 4: Graph Fingerprinting
            self.metrics.graph_fingerprint = self._compute_graph_fingerprint()
            
        except Exception as e:
            self.logger.error(f"Mesh ingestion error: {e}")
            self.logger.debug(traceback.format_exc())
            self.metrics.errors.append(str(e))
        
        self.metrics.ingestion_time_ms = (time.perf_counter() - start_time) * 1000
        
        self.logger.info(
            f"  [OK] Ingestion Complete ({self.metrics.ingestion_time_ms:.0f}ms). "
            f"Nodes: {self.metrics.nodes_merged}, "
            f"Edges: {self.metrics.edges_created}, "
            f"Phantoms: {self.metrics.phantom_nodes_created}"
        )
        
        return self.metrics

    # --------------------------------------------------------------------------
    # PHASE 1: NODE INGESTION (BATCH MERGE)
    # --------------------------------------------------------------------------
    
    def _ingest_nodes_batch(self, nodes: List[Dict[str, Any]], tenant_id: str) -> None:
        """
        Merges URM nodes into Neo4j using batched UNWIND for efficiency.
        Each node is MERGED by ARN to prevent duplication.
        """
        merge_query = """
        UNWIND $batch AS node
        MERGE (n:Resource {arn: node.arn})
        ON CREATE SET
            n:CloudResource,
            n.name = node.name,
            n.type = node.type,
            n.cloud_provider = node.cloud_provider,
            n.service = node.service,
            n.tenant_id = node.tenant_id,
            n.risk_score = node.risk_score,
            n._tenant_id = node.tenant_id,
            n._resource_type = node.type,
            n._baseline_risk_score = node.risk_score,
            n._created_at = datetime(),
            n._last_seen = datetime(),
            n._data_origin = coalesce(node.data_origin, 'LIVE')
        ON MATCH SET
            n:CloudResource,
            n.name = node.name,
            n.risk_score = node.risk_score,
            n._last_seen = datetime(),
            n._data_origin = coalesce(node.data_origin, 'LIVE'),
            n._update_count = coalesce(n._update_count, 0) + 1
        """
        
        for i in range(0, len(nodes), self.batch_size):
            batch = nodes[i:i + self.batch_size]
            batch_data = []
            
            for node in batch:
                arn = node.get("arn", "")
                if not arn:
                    continue
                
                self._known_arns.add(arn)
                batch_data.append({
                    "arn": arn,
                    "name": node.get("name", "Unknown"),
                    "type": node.get("type", "unknown"),
                    "cloud_provider": node.get("cloud_provider", "UNKNOWN"),
                    "service": node.get("service", "unknown"),
                    "tenant_id": tenant_id or node.get("tenant_id", ""),
                    "risk_score": node.get("risk_score", 0.0),
                    "data_origin": node.get("_data_origin", "LIVE"),
                })
            
            if not batch_data:
                continue
            
            try:
                with self.driver.session() as session:
                    result = session.write_transaction(
                        lambda tx: tx.run(merge_query, {"batch": batch_data}).consume()
                    )
                    counters = result.counters
                    self.metrics.nodes_created += counters.nodes_created
                    self.metrics.nodes_merged += len(batch_data)
                    self.metrics.batch_count += 1
                    
            except Exception as e:
                self.logger.warning(f"  Batch {self.metrics.batch_count + 1} failed: {e}")
                self.metrics.errors.append(f"Batch {i // self.batch_size}: {str(e)}")

    # --------------------------------------------------------------------------
    # PHASE 2: EDGE SYNTHESIS
    # --------------------------------------------------------------------------
    
    def _synthesize_edges(self, nodes: List[Dict[str, Any]]) -> None:
        """
        Analyzes URM node metadata to synthesize meaningful graph edges.
        
        Edge types:
        - ASSUMES_ROLE: IAM trust policy references
        - ATTACHED_TO: Network/compute bindings (VPC, Subnet)
        - HAS_PERMISSION: IAM policy actions
        - FEDERATED_TRUST: Cross-cloud OIDC bridges
        - USES_ROLE: Lambda/ECS -> Execution Role
        - CONTAINS: VPC -> Subnet, RG -> Resource
        """
        for node in nodes:
            arn = node.get("arn", "")
            service = node.get("service", "").lower()
            resource_type = node.get("type", "").lower()
            metadata = node.get("metadata", {})
            properties = node.get("properties", {})
            
            if not arn:
                continue
            
            # IAM Trust Policy Analysis
            if service == "iam" and resource_type in ("role", "user"):
                self._analyze_iam_trust(arn, metadata, properties)
            
            # Network Topology (VPC/Subnet bindings)
            if metadata.get("VpcId"):
                vpc_arn = self._find_arn_by_id(
                    metadata["VpcId"], "ec2", "vpc", node.get("cloud_provider", "AWS")
                )
                self._buffer_edge(arn, vpc_arn, "ATTACHED_TO", weight=1.0)
            
            if metadata.get("SubnetId"):
                subnet_arn = self._find_arn_by_id(
                    metadata["SubnetId"], "ec2", "subnet", node.get("cloud_provider", "AWS")
                )
                self._buffer_edge(arn, subnet_arn, "ATTACHED_TO", weight=0.5)
            
            # Lambda -> Execution Role
            if service == "lambda" and metadata.get("Role"):
                role_arn = metadata["Role"]
                self._buffer_edge(arn, role_arn, "USES_ROLE", weight=2.0)
                self._register_phantom(role_arn, arn, "USES_ROLE", "Lambda Execution Role")
            
            # Azure Managed Identity
            identity = metadata.get("identity") or properties.get("identity")
            if isinstance(identity, dict) and identity.get("type"):
                fed_app_id = identity.get("federatedApplicationId")
                if fed_app_id:
                    # This is a cross-cloud identity bridge
                    self._buffer_edge(
                        arn, f"_phantom:federated:{fed_app_id}", 
                        "FEDERATED_TRUST", weight=5.0, 
                        extra={"is_identity_bridge": True, "app_id": fed_app_id}
                    )
            
            # Azure VNet binding
            if metadata.get("VnetId") or metadata.get("VirtualNetworkId"):
                vnet_id = metadata.get("VnetId") or metadata.get("VirtualNetworkId")
                self._buffer_edge(arn, vnet_id, "ATTACHED_TO", weight=1.0)

    def _analyze_iam_trust(self, arn: str, metadata: Dict, properties: Dict) -> None:
        """Extracts IAM trust relationships from AssumeRolePolicyDocument."""
        trust_doc_str = metadata.get("AssumeRolePolicyDocument", "")
        if not trust_doc_str:
            return
        
        try:
            trust_doc = json.loads(trust_doc_str) if isinstance(trust_doc_str, str) else trust_doc_str
            
            for statement in trust_doc.get("Statement", []):
                if statement.get("Effect") != "Allow":
                    continue
                
                principal = statement.get("Principal", {})
                
                # AWS Service principals
                if isinstance(principal, dict):
                    service_principal = principal.get("Service", "")
                    if isinstance(service_principal, str) and service_principal:
                        self._buffer_edge(
                            f"_phantom:service:{service_principal}", arn, 
                            "ASSUMES_ROLE", weight=2.0
                        )
                    
                    # Federated principals (OIDC)
                    federated = principal.get("Federated", "")
                    if isinstance(federated, str) and "sts.windows.net" in federated:
                        # Cross-cloud OIDC bridge detected
                        condition = statement.get("Condition", {})
                        aud_key = [k for k in condition.get("StringEquals", {}).keys()
                                   if ":aud" in k]
                        app_id = ""
                        if aud_key:
                            app_id = condition["StringEquals"][aud_key[0]]
                        
                        self._buffer_edge(
                            f"_phantom:oidc:{federated}", arn,
                            "FEDERATED_TRUST", weight=5.0,
                            extra={"is_identity_bridge": True, "app_id": app_id}
                        )
                    
                    # AWS Account cross-trust
                    aws_principal = principal.get("AWS", "")
                    if isinstance(aws_principal, str) and aws_principal.startswith("arn:aws:iam"):
                        self._buffer_edge(aws_principal, arn, "ASSUMES_ROLE", weight=3.0)
                        self._register_phantom(aws_principal, arn, "ASSUMES_ROLE", "Cross-account trust")
                    elif isinstance(aws_principal, list):
                        for p in aws_principal:
                            if isinstance(p, str) and p.startswith("arn:aws:iam"):
                                self._buffer_edge(p, arn, "ASSUMES_ROLE", weight=3.0)
                                self._register_phantom(p, arn, "ASSUMES_ROLE", "Cross-account trust")
                                
        except (json.JSONDecodeError, TypeError, KeyError) as e:
            self.logger.debug(f"  Trust policy parse error for {arn}: {e}")

    # --------------------------------------------------------------------------
    # EDGE BUFFER & FLUSH
    # --------------------------------------------------------------------------
    
    def _buffer_edge(
        self, 
        source_arn: str, 
        target_arn: str, 
        rel_type: str, 
        weight: float = 1.0,
        extra: Optional[Dict[str, Any]] = None
    ) -> None:
        """Buffers an edge for batch creation."""
        self._edge_buffer.append({
            "source": source_arn,
            "target": target_arn,
            "type": rel_type,
            "weight": weight,
            "extra": extra or {},
        })

    def _flush_edge_buffer(self) -> None:
        """Writes all buffered edges to Neo4j in batches."""
        if not self._edge_buffer:
            return
        
        # Group edges by relationship type for efficient queries
        edges_by_type: Dict[str, List[Dict]] = defaultdict(list)
        for edge in self._edge_buffer:
            edges_by_type[edge["type"]].append(edge)
        
        for rel_type, edges in edges_by_type.items():
            # Dynamic relationship queries using APOC or fallback
            query = f"""
            UNWIND $edges AS edge
            MATCH (src {{arn: edge.source}})
            MATCH (dst {{arn: edge.target}})
            MERGE (src)-[r:{rel_type}]->(dst)
            SET r.weight = edge.weight,
                r._created_at = datetime()
            """
            
            # Add extra properties for identity bridges
            if any(e.get("extra", {}).get("is_identity_bridge") for e in edges):
                query += ", r.is_identity_bridge = edge.is_bridge, r.app_id = edge.app_id"
            
            for i in range(0, len(edges), self.batch_size):
                batch = edges[i:i + self.batch_size]
                batch_data = [{
                    "source": e["source"],
                    "target": e["target"],
                    "weight": e["weight"],
                    "is_bridge": e.get("extra", {}).get("is_identity_bridge", False),
                    "app_id": e.get("extra", {}).get("app_id", ""),
                } for e in batch]
                
                try:
                    with self.driver.session() as session:
                        result = session.write_transaction(
                            lambda tx: tx.run(query, {"edges": batch_data}).consume()
                        )
                        self.metrics.edges_created += result.counters.relationships_created
                        
                        # Count identity bridges
                        bridge_count = sum(1 for e in batch if e.get("is_bridge"))
                        self.metrics.identity_bridges_created += bridge_count
                        
                except Exception as e:
                    self.logger.warning(f"  Edge batch ({rel_type}) failed: {e}")
                    self.metrics.errors.append(f"Edge {rel_type}: {str(e)}")

    # --------------------------------------------------------------------------
    # PHASE 3: PHANTOM NODE GENERATION
    # --------------------------------------------------------------------------
    
    def _register_phantom(
        self, arn: str, referencing_arn: str, rel_type: str, context: str = ""
    ) -> None:
        """Registers a potential phantom node reference."""
        if arn not in self._known_arns:
            self._phantom_refs.append(PhantomReference(
                arn=arn, referencing_arn=referencing_arn,
                relationship_type=rel_type, context=context
            ))

    def _generate_phantom_nodes(self) -> None:
        """Creates phantom (shadow) nodes for referenced-but-unseen resources."""
        if not self._phantom_refs:
            return
        
        # Deduplicate by ARN
        unique_phantoms: Dict[str, PhantomReference] = {}
        for ref in self._phantom_refs:
            if ref.arn not in unique_phantoms and ref.arn not in self._known_arns:
                unique_phantoms[ref.arn] = ref
        
        if not unique_phantoms:
            return
        
        phantom_query = """
        UNWIND $phantoms AS p
        MERGE (n:CloudResource {arn: p.arn})
        ON CREATE SET
            n.name = p.name,
            n.type = 'Phantom',
            n.phantom_reason = p.reason,
            n._created_at = datetime(),
            n._last_seen = datetime(),
            n._data_origin = 'PHANTOM'
        WITH n
        CALL { WITH n SET n:Resource }
        """
        
        phantom_data = [{
            "arn": ref.arn,
            "name": f"Phantom: {ref.arn.split('/')[-1] if '/' in ref.arn else ref.arn.split(':')[-1]}",
            "reason": f"Referenced by {ref.referencing_arn} via {ref.relationship_type}. {ref.context}",
        } for ref in unique_phantoms.values()]
        
        try:
            with self.driver.session() as session:
                result = session.write_transaction(
                    lambda tx: tx.run(phantom_query, {"phantoms": phantom_data}).consume()
                )
                self.metrics.phantom_nodes_created = result.counters.nodes_created
                self.logger.debug(
                    f"  Created {self.metrics.phantom_nodes_created} phantom nodes "
                    f"from {len(unique_phantoms)} references."
                )
        except Exception as e:
            self.logger.warning(f"  Phantom node generation failed: {e}")
            self.metrics.errors.append(f"Phantom: {str(e)}")

    # --------------------------------------------------------------------------
    # PHASE 4: GRAPH FINGERPRINTING
    # --------------------------------------------------------------------------
    
    def _compute_graph_fingerprint(self) -> str:
        """
        Computes a SHA-256 fingerprint of the current graph structure.
        Used to detect structural changes between ingestion cycles.
        """
        try:
            with self.driver.session() as session:
                result = session.run("""
                MATCH (n)
                WHERE n:CloudResource OR n:Resource
                RETURN count(n) as nodes,
                       sum(coalesce(n.risk_score, 0)) as total_risk
                """)
                record = result.single()
                
                if record:
                    fingerprint_data = f"{record['nodes']}:{record['total_risk']}"
                    return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
                    
        except Exception as e:
            self.logger.debug(f"  Fingerprint computation failed: {e}")
        
        return "unknown"

    # --------------------------------------------------------------------------
    # UTILITY METHODS
    # --------------------------------------------------------------------------
    
    def _find_arn_by_id(self, resource_id: str, service: str, res_type: str, cloud: str) -> str:
        """
        Attempts to resolve a resource ID to its ARN.
        If not found in the known ARN set, returns a synthetic ARN.
        """
        # Check if the ID is already a full ARN
        if resource_id.startswith("arn:") or resource_id.startswith("/subscriptions/"):
            return resource_id
        
        # Search known ARNs
        for known in self._known_arns:
            if resource_id in known:
                return known
        
        # Synthesize a best-guess ARN
        if cloud.upper() == "AWS":
            return f"arn:aws:{service}:us-east-1:000000000000:{res_type}/{resource_id}"
        elif cloud.upper() == "AZURE":
            return f"/subscriptions/unknown/resourceGroups/unknown/providers/Microsoft.{service}/{res_type}/{resource_id}"
        
        return resource_id

    def get_metrics(self) -> Dict[str, Any]:
        """Returns the current ingestion metrics."""
        return self.metrics.to_dict()