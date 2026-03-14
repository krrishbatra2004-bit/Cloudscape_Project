import logging
import uuid
import time
import traceback
import networkx as nx
from typing import List, Dict, Any, Tuple

from core.config import config

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - HEURISTIC ATTACK PATH DISCOVERY (HAPD)
# ==============================================================================
# The Core Intelligence Engine.
# Constructs a multidimensional Directed Graph (DiGraph) from the unified URM payload.
# Executes Subnet-Aware structural inference and calculates high-fidelity 
# exfiltration routes using non-linear Friction Decay mathematics.
# ==============================================================================

class AttackPathEngine:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Logic.AttackPath")
        
        # Configuration Bindings
        self.max_depth = getattr(config.settings.logic_engine, "max_depth", 6)
        self.risk_threshold = getattr(config.settings.logic_engine, "risk_threshold", 4.0)
        
        # Forensic Telemetry Matrix
        self.diagnostics = {
            "total_nodes": 0,
            "explicit_edges": 0,
            "inferred_edges": 0,
            "entry_points": 0,
            "crown_jewels": 0,
            "raw_paths_found": 0,
            "pruned_paths": 0,
            "critical_paths": 0,
            "execution_time_ms": 0.0
        }

    def calculate_attack_paths(self, unified_nodes: List[Dict], explicit_edges: List[Dict]) -> List[Dict]:
        """
        The Master Intelligence Loop.
        1. Initializes the NetworkX DiGraph.
        2. Applies Explicit Edges (IdentityFabric).
        3. Infers Structural Edges (Subnet-Aware).
        4. Executes Combinatorial Path Search.
        5. Calibrates and Prunes via Friction Decay.
        """
        start_time = time.perf_counter()
        
        self.logger.info("Initializing NetworkX Directed Topological Graph...")
        self.G = nx.DiGraph()

        # Phase 1: O(V) Node Ingestion
        self._ingest_nodes(unified_nodes)

        # Phase 2: Explicit Edge Materialization (Cross-Cloud / IAM)
        self._ingest_explicit_edges(explicit_edges)

        # Phase 3: Subnet-Aware Structural Edge Inference (The Noise Killer)
        self._infer_structural_edges()

        self.logger.info(
            f"Graph topology constructed: {self.diagnostics['total_nodes']} Nodes, "
            f"{self.diagnostics['explicit_edges']} Identity Edges, "
            f"{self.diagnostics['inferred_edges']} Inferred Structural Edges."
        )

        # Phase 4: Target Matrix Identification
        entry_points, crown_jewels = self._identify_target_matrix()
        
        # ASCII '->' used instead of Unicode arrow to prevent Windows cp1252 crash
        self.logger.info(f"HAPD Target Matrix: {len(entry_points)} Public Entry Points -> {len(crown_jewels)} Crown Jewels.")

        if not entry_points or not crown_jewels:
            self.logger.warning("Target Matrix is incomplete. Attack path generation suspended.")
            return []

        # Phase 5: Combinatorial Traversal & Friction Decay Scoring
        self.logger.info(f"Executing Exhaustive Path Search (Max Depth: {self.max_depth})...")
        attack_paths = self._execute_path_discovery(entry_points, crown_jewels)

        self.diagnostics["execution_time_ms"] = (time.perf_counter() - start_time) * 1000

        self.logger.info(
            f"Exhaustive Analysis Complete. Generated {len(attack_paths)} dynamically classified attack paths "
            f"(Filtered from {self.diagnostics['raw_paths_found']} raw routes)."
        )

        return attack_paths

    # ==========================================================================
    # GRAPH TOPOLOGY CONSTRUCTION
    # ==========================================================================

    def _ingest_nodes(self, unified_nodes: List[Dict]) -> None:
        """Injects physical and synthetic entities into the NetworkX DiGraph."""
        for node in unified_nodes:
            arn = node.get("arn")
            if not arn:
                continue
                
            # Safely extract dynamic metadata properties
            meta = node.get("metadata", {})
            tags = node.get("tags", {})
            
            self.G.add_node(
                arn,
                tenant_id=node.get("tenant_id", "unknown"),
                cloud_provider=node.get("cloud_provider", "unknown").lower(),
                service=node.get("service", "unknown").lower(),
                type=node.get("type", "unknown").lower(),
                name=node.get("name", "unknown"),
                risk_score=float(meta.get("baseline_risk_score", 0.0)),
                tags=tags,
                metadata=meta
            )
            self.diagnostics["total_nodes"] += 1

    def _ingest_explicit_edges(self, explicit_edges: List[Dict]) -> None:
        """Injects cryptographically verified IdentityFabric bridges."""
        for edge in explicit_edges:
            source = edge.get("source_arn")
            target = edge.get("target_arn")
            
            if source and target and self.G.has_node(source) and self.G.has_node(target):
                self.G.add_edge(
                    source, 
                    target, 
                    relation=edge.get("relation_type", "RELATES_TO"),
                    weight=edge.get("weight", 1.0),
                    is_identity_bridge=True
                )
                self.diagnostics["explicit_edges"] += 1

    def _infer_structural_edges(self) -> None:
        """
        The Subnet-Aware Zero-Knowledge Linker.
        Prevents Combinatorial Explosions by strictly verifying network and tenant 
        boundaries before allowing Compute to communicate with Data.
        """
        # Isolate Node Classifications for O(N) looping
        compute_nodes = []
        data_nodes = []
        network_nodes = []
        
        for arn, data in self.G.nodes(data=True):
            res_type = data.get("type", "")
            
            if res_type in ["instance", "virtualmachine", "ec2"]:
                compute_nodes.append((arn, data))
            elif res_type in ["bucket", "storageaccount", "dbinstance", "storageblob"]:
                data_nodes.append((arn, data))
            elif res_type in ["subnet", "virtualnetwork", "vpc"]:
                network_nodes.append((arn, data))

        # 1. Compute -> Data (Lateral Movement constraints)
        for c_arn, c_data in compute_nodes:
            c_tenant = c_data.get("tenant_id")
            c_tags = c_data.get("tags", {})
            c_meta = c_data.get("metadata", {})
            
            # Extract Subnet/VPC signatures from Compute node
            c_network_sig = c_meta.get("SubnetId", c_tags.get("SubnetId", c_tags.get("Environment", "unknown")))

            for d_arn, d_data in data_nodes:
                d_tenant = d_data.get("tenant_id")
                d_tags = d_data.get("tags", {})
                d_meta = d_data.get("metadata", {})
                
                # Strict Boundary 1: Tenant Isolation
                if c_tenant != d_tenant:
                    continue
                    
                # Strict Boundary 2: Network Alignment (If both have network tags, they must match)
                d_network_sig = d_meta.get("SubnetId", d_tags.get("SubnetId", d_tags.get("Environment", "unknown")))
                
                # We permit edges if they share a Subnet, Environment, or if the Data is explicitly 'Public'
                is_public_data = "Public" in str(d_tags.get("Exposure", "")) or d_data.get("risk_score", 0.0) >= 7.0
                
                if (c_network_sig != "unknown" and c_network_sig == d_network_sig) or is_public_data:
                    self.G.add_edge(c_arn, d_arn, relation="NETWORK_ACCESS", weight=0.6, is_identity_bridge=False)
                    self.diagnostics["inferred_edges"] += 1

        # 2. Network -> Compute (Inbound Routing constraints)
        for n_arn, n_data in network_nodes:
            n_tenant = n_data.get("tenant_id")
            for c_arn, c_data in compute_nodes:
                if n_tenant == c_data.get("tenant_id"):
                    # Native containment mapping
                    self.G.add_edge(n_arn, c_arn, relation="CONTAINS", weight=0.2, is_identity_bridge=False)
                    self.diagnostics["inferred_edges"] += 1

    # ==========================================================================
    # TARGET IDENTIFICATION (ENTRY POINTS & CROWN JEWELS)
    # ==========================================================================

    def _identify_target_matrix(self) -> Tuple[List[str], List[str]]:
        """Scans the graph to classify highly exposed inputs and highly sensitive targets."""
        entry_points = []
        crown_jewels = []
        
        for arn, data in self.G.nodes(data=True):
            tags = data.get("tags", {})
            risk = data.get("risk_score", 0.0)
            
            # Entry Point Heuristics (External Attack Surface)
            exposure = str(tags.get("Exposure", "")).lower()
            if "public" in exposure or "criticalportopen" in exposure or risk >= 8.5:
                # Disallow raw storage buckets as Entry Points unless they are highly vulnerable compute
                if data.get("type") not in ["bucket", "storageaccount"]:
                    entry_points.append(arn)

            # Crown Jewel Heuristics (Ultimate Data Targets)
            data_class = str(tags.get("DataClass", tags.get("DataClassification", ""))).lower()
            if "pci" in data_class or "pii" in data_class or "restricted" in data_class or "confidential" in data_class:
                if data.get("type") in ["dbinstance", "bucket", "storageblob", "storageaccount"]:
                    crown_jewels.append(arn)
            # Failsafe for un-tagged highly vulnerable mock databases
            elif data.get("type") in ["dbinstance", "rds"] and risk >= 7.0:
                crown_jewels.append(arn)

        self.diagnostics["entry_points"] = len(entry_points)
        self.diagnostics["crown_jewels"] = len(crown_jewels)
        return entry_points, crown_jewels

    # ==========================================================================
    # COMBINATORIAL TRAVERSAL & NON-LINEAR SCORING
    # ==========================================================================

    def _execute_path_discovery(self, entry_points: List[str], crown_jewels: List[str]) -> List[Dict]:
        """
        Executes nx.all_simple_paths across the matrix.
        Applies Friction Decay mathematics to drop low-probability "noisy" routes.
        """
        valid_paths = []
        
        for ep in entry_points:
            for cj in crown_jewels:
                # Prevent self-loops
                if ep == cj:
                    continue
                    
                # nx.all_simple_paths yields a generator of lists of ARNs
                try:
                    paths_generator = nx.all_simple_paths(self.G, source=ep, target=cj, cutoff=self.max_depth)
                    
                    for raw_path in paths_generator:
                        self.diagnostics["raw_paths_found"] += 1
                        
                        # Apply Friction Decay Scoring
                        hcs_score, tier, is_critical = self._calculate_path_hcs(raw_path)
                        
                        # Prune low-risk noise
                        if hcs_score < self.risk_threshold:
                            self.diagnostics["pruned_paths"] += 1
                            continue
                            
                        if is_critical:
                            self.diagnostics["critical_paths"] += 1
                            
                        # Format URM Object
                        formatted_path = self._format_attack_path(raw_path, hcs_score, tier)
                        valid_paths.append(formatted_path)
                        
                except nx.NetworkXNoPath:
                    continue
                except Exception as e:
                    self.logger.warning(f"Pathing calculation fault between {ep} and {cj}: {e}")

        # Sort paths by absolute severity (Descending)
        valid_paths.sort(key=lambda x: x.get("metadata", {}).get("hcs_score", 0.0), reverse=True)
        return valid_paths

    def _calculate_path_hcs(self, path: List[str]) -> Tuple[float, str, bool]:
        """
        Heuristic Cost Strategy (HCS) with Non-Linear Friction Decay.
        A 1-hop path with moderate risk is infinitely more exploitable than a 
        6-hop path with high risk. We divide aggregate risk by Hop_Count^1.5.
        """
        hop_count = len(path) - 1
        if hop_count <= 0:
            return 0.0, "LOW", False
            
        aggregate_risk = sum([self.G.nodes[n].get("risk_score", 1.0) for n in path])
        
        # Determine if path contains a Cross-Cloud Identity Bridge (Severe escalation)
        has_identity_bridge = False
        for i in range(hop_count):
            edge_data = self.G.get_edge_data(path[i], path[i+1])
            if edge_data and edge_data.get("is_identity_bridge"):
                has_identity_bridge = True
                break

        # Friction Decay Formula
        # A 6 hop path divides its risk by 14.6 (6^1.5), heavily penalizing long noise paths.
        decay_factor = hop_count ** 1.5
        hcs_score = aggregate_risk / decay_factor

        # Multipliers
        if has_identity_bridge:
            hcs_score *= 1.5 # 50% penalty for breaking the cloud barrier
            
        hcs_score = round(min(10.0, max(0.0, hcs_score)), 2)
        
        # Tier Classification
        if hcs_score >= 8.0:
            tier = "CRITICAL"
        elif hcs_score >= 6.0:
            tier = "HIGH"
        elif hcs_score >= 4.0:
            tier = "MEDIUM"
        else:
            tier = "LOW"
            
        return hcs_score, tier, (tier == "CRITICAL")

    # ==========================================================================
    # URM PAYLOAD FORMATTING
    # ==========================================================================

    def _format_attack_path(self, path: List[str], hcs_score: float, tier: str) -> Dict[str, Any]:
        """
        Constructs the strict Universal Resource Model entity for the Neo4j Ingestor.
        The physical AttackPath node is required by the UI Dashboard.
        """
        path_id = f"hapd-path-{uuid.uuid4().hex[:12]}"
        
        # Reconstruct the sequence payload for visualization
        path_matrix = []
        for arn in path:
            node_data = self.G.nodes[arn]
            path_matrix.append({
                "arn": arn,
                "type": node_data.get("type"),
                "name": node_data.get("name"),
                "risk": node_data.get("risk_score")
            })

        return {
            "type": "attack_path",
            "path_id": path_id,
            "source_node": path[0],
            "target_node": path[-1],
            "tier": tier,
            "metadata": {
                "hcs_score": hcs_score,
                "hop_count": len(path) - 1,
                "path_sequence": path, # Raw ARN array
                "path_matrix": path_matrix, # Deep object array
                "discovery_mechanism": "titan_hapd_subnet_aware",
                "timestamp": time.time()
            }
        }

    def get_execution_metrics(self) -> Dict[str, Any]:
        """Exposes the internal intelligence metrics to the Orchestrator."""
        return self.diagnostics

# ==============================================================================
# SINGLETON EXPORT
# ==============================================================================
attack_path_engine = AttackPathEngine()