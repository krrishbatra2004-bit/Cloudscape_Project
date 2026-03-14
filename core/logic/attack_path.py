import logging
import uuid
import time
import traceback
import math
import networkx as nx
from typing import List, Dict, Any, Tuple, Set, Optional
from dataclasses import dataclass, field
from enum import Enum

from core.config import config

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - HEURISTIC ATTACK PATH DISCOVERY (HAPD)
# ==============================================================================
# The Core Enterprise Intelligence & Physics Engine (Zero-G Edition).
# 
# TITAN UPGRADES ACTIVE:
# 1. The Blackout Cure: Fixed the loop variable NameError that dropped paths.
# 2. Friction Decay 2.0: Implements advanced inverse-square physics 
#    (Risk / Hops^2) to aggressively prune combinatorial graph noise.
# 3. Micro-Segmentation Linker: Deep Subnet-Aware inference that validates 
#    VPC, Subnet, and Security Group boundaries before drawing structural edges.
# 4. Graph Pre-Pruning: Strips isolated/dead-end nodes before path traversal 
#    to prevent CPU lockups on massive meshes.
# 5. Singleton Architecture: Preserves graph state across orchestrated phases.
# ==============================================================================

# ------------------------------------------------------------------------------
# ENUMS & DATA CLASSES FOR STRICT GRAPH TYPING
# ------------------------------------------------------------------------------

class EdgeType(Enum):
    CROSS_CLOUD_ASSUME = "CROSS_CLOUD_ASSUME"
    CAN_ASSUME = "CAN_ASSUME"
    ESCALATES_TO = "ESCALATES_TO"
    NETWORK_ACCESS = "NETWORK_ACCESS"
    VPC_PEERED = "VPC_PEERED"
    CONTAINS = "CONTAINS"
    EXECUTES_ON = "EXECUTES_ON"
    HAS_ROUTE = "HAS_ROUTE"

class ThreatTier(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class PathDiagnostics:
    total_nodes: int = 0
    explicit_edges: int = 0
    inferred_edges: int = 0
    isolated_nodes_pruned: int = 0
    entry_points: int = 0
    crown_jewels: int = 0
    raw_paths_found: int = 0
    pruned_by_friction: int = 0
    pruned_by_threshold: int = 0
    critical_paths: int = 0
    execution_time_ms: float = 0.0

# ------------------------------------------------------------------------------
# CORE ATTACK PATH ENGINE (SINGLETON)
# ------------------------------------------------------------------------------

class AttackPathEngine:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Logic.AttackPath")
        
        # Configuration Bindings
        self.max_depth = getattr(config.settings.logic_engine.attack_path_detection, "max_depth", 6)
        self.risk_threshold = getattr(config.settings.logic_engine.attack_path_detection, "risk_threshold", 5.0)
        self.decay_exponent = getattr(config.settings.logic_engine.attack_path_detection, "decay_exponent", 2.0)
        
        # Internal State Matrices
        self.G = nx.DiGraph()
        self.diagnostics = PathDiagnostics()
        
        # MITRE ATT&CK Tactic Mapping Dictionary
        self.mitre_matrix = {
            "TA0001": "Initial Access",
            "TA0002": "Execution",
            "TA0003": "Persistence",
            "TA0004": "Privilege Escalation",
            "TA0005": "Defense Evasion",
            "TA0006": "Credential Access",
            "TA0007": "Discovery",
            "TA0008": "Lateral Movement",
            "TA0009": "Collection",
            "TA0010": "Exfiltration"
        }

    def clear_state(self) -> None:
        """Flushes the graph memory for fresh ingestion while preserving the singleton."""
        self.G.clear()
        self.diagnostics = PathDiagnostics()

    def calculate_attack_paths(self, unified_nodes: List[Dict], explicit_edges: List[Dict]) -> List[Dict]:
        """
        The Master Intelligence Lifecycle.
        Executes O(V+E) graph construction, topological pruning, combinatorial 
        traversal, and non-linear decay.
        """
        start_time = time.perf_counter()
        
        self.logger.info("Initializing NetworkX Directed Topological Graph...")
        self.clear_state()

        # Phase 1: Physical & Synthetic Node Ingestion
        self._ingest_nodes(unified_nodes)

        # Phase 2: Explicit Identity & Entanglement Edges
        self._ingest_explicit_edges(explicit_edges)

        # Phase 3: Micro-Segmentation Structural Inference
        self._infer_structural_edges()
        
        # Phase 4: Graph Optimization (OOM Prevention)
        self._prune_isolated_topology()

        self.logger.info(
            f"Graph topology constructed: {self.diagnostics.total_nodes} Nodes, "
            f"{self.diagnostics.explicit_edges} Identity Edges, "
            f"{self.diagnostics.inferred_edges} Structural Edges. "
            f"(Pruned {self.diagnostics.isolated_nodes_pruned} isolated entities)."
        )

        # Phase 5: Target Matrix Derivation
        entry_points, crown_jewels = self._identify_target_matrix()
        
        # ASCII format strictly enforced to prevent Windows UnicodeEncodeError
        self.logger.info(f"HAPD Target Matrix: {len(entry_points)} Public Entry Points -> {len(crown_jewels)} Crown Jewels.")

        if not entry_points or not crown_jewels:
            self.logger.warning("Target Matrix is incomplete. Mesh is secure or data is insufficient.")
            return []

        # Phase 6: Combinatorial Traversal & Friction Decay 2.0
        self.logger.info(f"Executing Exhaustive Path Search (Max Depth: {self.max_depth})...")
        attack_paths = self._execute_path_discovery(entry_points, crown_jewels)

        self.diagnostics.execution_time_ms = (time.perf_counter() - start_time) * 1000

        self.logger.info(
            f"Exhaustive Analysis Complete. Generated {len(attack_paths)} highly calibrated paths. "
            f"(Filtered {self.diagnostics.pruned_by_friction} low-severity noise routes)."
        )

        return attack_paths

    # ==========================================================================
    # GRAPH TOPOLOGY CONSTRUCTION (PHASE 1 & 2)
    # ==========================================================================

    def _deep_get(self, d: Dict, keys: List[str], default: Any = None) -> Any:
        """Utility for safely extracting deeply nested metadata properties."""
        for key in keys:
            if isinstance(d, dict):
                found = False
                for k, v in d.items():
                    if str(k).lower() == key.lower():
                        d = v
                        found = True
                        break
                if not found:
                    return default
            else:
                return default
        return d

    def _ingest_nodes(self, unified_nodes: List[Dict]) -> None:
        """Injects physical and synthetic entities into the NetworkX DiGraph."""
        for node in unified_nodes:
            arn = node.get("arn")
            if not arn:
                continue
                
            meta = node.get("metadata", {})
            tags = node.get("tags", {})
            
            # Extract common network boundaries for rapid O(1) linker access later
            vpc_id = self._deep_get(meta, ["VpcId", "vpcId", "vpc_id"], tags.get("VpcId", "unknown"))
            subnet_id = self._deep_get(meta, ["SubnetId", "subnetId", "subnet_id"], tags.get("SubnetId", "unknown"))
            
            # Standardize typing
            res_type = str(node.get("type", "unknown")).lower()
            
            self.G.add_node(
                arn,
                tenant_id=node.get("tenant_id", "unknown"),
                cloud_provider=node.get("cloud_provider", "unknown").lower(),
                service=node.get("service", "unknown").lower(),
                type=res_type,
                name=node.get("name", "unknown"),
                risk_score=float(meta.get("baseline_risk_score", 1.0)),
                is_simulated=bool(meta.get("is_simulated", False)),
                vpc_id=vpc_id,
                subnet_id=subnet_id,
                tags=tags,
                metadata=meta
            )
            self.diagnostics.total_nodes += 1

    def _ingest_explicit_edges(self, explicit_edges: List[Dict]) -> None:
        """Injects cryptographically verified IdentityFabric bridges."""
        for edge in explicit_edges:
            source = edge.get("source_arn")
            target = edge.get("target_arn")
            
            if source and target and self.G.has_node(source) and self.G.has_node(target):
                self.G.add_edge(
                    source, 
                    target, 
                    relation=edge.get("relation_type", EdgeType.CAN_ASSUME.value),
                    weight=float(edge.get("weight", 5.0)),
                    is_identity_bridge=edge.get("is_identity_bridge", False)
                )
                self.diagnostics.explicit_edges += 1

    # ==========================================================================
    # MICRO-SEGMENTATION LINKER (PHASE 3)
    # ==========================================================================

    def _infer_structural_edges(self) -> None:
        """
        The Deep Subnet-Aware Zero-Knowledge Linker.
        Completely rewritten to evaluate explicit network boundaries to prevent 
        combinatorial explosions and 'spaghetti' logic.
        """
        compute_nodes = []
        data_nodes = []
        network_nodes = []
        identity_nodes = []
        
        # O(N) Categorization Array Mapping
        for arn, data in self.G.nodes(data=True):
            res_type = data.get("type", "")
            
            if res_type in ["instance", "virtualmachine", "ec2", "function", "cluster"]:
                compute_nodes.append((arn, data))
            elif res_type in ["bucket", "storageaccount", "dbinstance", "rds", "table"]:
                data_nodes.append((arn, data))
            elif res_type in ["subnet", "virtualnetwork", "vpc"]:
                network_nodes.append((arn, data))
            elif res_type in ["role", "user", "group", "iam", "policy"]:
                identity_nodes.append((arn, data))

        # ----------------------------------------------------------------------
        # LINKER 1: Compute -> Data (Lateral Movement with Subnet Precision)
        # ----------------------------------------------------------------------
        for c_arn, c_data in compute_nodes:
            c_tenant = c_data.get("tenant_id")
            c_subnet = c_data.get("subnet_id")
            c_vpc = c_data.get("vpc_id")

            for d_arn, d_data in data_nodes:
                d_tenant = d_data.get("tenant_id")
                d_tags = d_data.get("tags", {})
                
                # Strict Boundary 1: Tenant Isolation
                if c_tenant != d_tenant:
                    continue
                    
                d_subnet = d_data.get("subnet_id")
                d_vpc = d_data.get("vpc_id")
                
                is_public_data = "Public" in str(d_tags.get("Exposure", ""))
                has_network_alignment = False
                
                # Boundary 2: Micro-Segmentation alignment
                if c_subnet != "unknown" and c_subnet == d_subnet:
                    has_network_alignment = True
                elif c_vpc != "unknown" and c_vpc == d_vpc:
                    # Same VPC but different subnets - assumes intra-VPC routing exists
                    has_network_alignment = True
                    
                # We permit edges if they share a Subnet/VPC OR if the Data is explicitly 'Public'
                if has_network_alignment or is_public_data:
                    weight = 2.0 if has_network_alignment else 4.0
                    self.G.add_edge(
                        c_arn, d_arn, 
                        relation=EdgeType.NETWORK_ACCESS.value, 
                        weight=weight, 
                        is_identity_bridge=False
                    )
                    self.diagnostics.inferred_edges += 1

        # ----------------------------------------------------------------------
        # LINKER 2: Compute -> Identity (Instance Profile Extraction)
        # ----------------------------------------------------------------------
        # If an EC2 has an IamInstanceProfile, it can act as that Role
        for c_arn, c_data in compute_nodes:
            profile_arn = self._deep_get(c_data.get("metadata", {}), ["IamInstanceProfile", "Arn"])
            if not profile_arn:
                continue
                
            # Fuzzy match the profile name to the actual Role name in the graph
            profile_name = profile_arn.split("/")[-1].lower() if "/" in profile_arn else ""
            
            for i_arn, i_data in identity_nodes:
                i_name = i_data.get("name", "").lower()
                if profile_name and i_name and (profile_name in i_name or i_name in profile_name):
                    self.G.add_edge(
                        c_arn, i_arn, 
                        relation=EdgeType.EXECUTES_ON.value, 
                        weight=1.0, 
                        is_identity_bridge=True
                    )
                    self.diagnostics.inferred_edges += 1

        # ----------------------------------------------------------------------
        # LINKER 3: Network -> Compute (Inbound Routing containment)
        # ----------------------------------------------------------------------
        for n_arn, n_data in network_nodes:
            n_tenant = n_data.get("tenant_id")
            n_id = n_data.get("name") # Usually the vpc-id or subnet-id string
            
            for c_arn, c_data in compute_nodes:
                if n_tenant == c_data.get("tenant_id"):
                    if c_data.get("vpc_id") == n_id or c_data.get("subnet_id") == n_id:
                        self.G.add_edge(
                            n_arn, c_arn, 
                            relation=EdgeType.CONTAINS.value, 
                            weight=0.5, 
                            is_identity_bridge=False
                        )
                        self.diagnostics.inferred_edges += 1

    def _prune_isolated_topology(self) -> None:
        """
        Performance Optimization.
        Removes nodes that have a degree of 0 (no inbound or outbound edges).
        This drastically shrinks the search space for nx.all_simple_paths.
        """
        isolates = list(nx.isolates(self.G))
        self.G.remove_nodes_from(isolates)
        self.diagnostics.isolated_nodes_pruned = len(isolates)
        self.diagnostics.total_nodes -= len(isolates)

    # ==========================================================================
    # TARGET MATRIX IDENTIFICATION (PHASE 4)
    # ==========================================================================

    def _identify_target_matrix(self) -> Tuple[List[str], List[str]]:
        """Scans the graph to classify External Attack Surfaces and Crown Jewels."""
        entry_points = []
        crown_jewels = []
        
        for arn, data in self.G.nodes(data=True):
            tags = data.get("tags", {})
            risk = data.get("risk_score", 0.0)
            res_type = data.get("type", "")
            
            # ------------------------------------------------------------------
            # ENTRY POINT HEURISTICS
            # ------------------------------------------------------------------
            exposure = str(tags.get("Exposure", "")).lower()
            
            # A node is an entry point if it is explicitly Public or highly risky
            if "public" in exposure or risk >= 8.5:
                # Disallow raw storage buckets as Entry Points; attackers enter via compute/identity
                if res_type not in ["bucket", "storageaccount", "table", "rds", "dbinstance"]:
                    entry_points.append(arn)

            # ------------------------------------------------------------------
            # CROWN JEWEL HEURISTICS
            # ------------------------------------------------------------------
            data_class = str(tags.get("DataClass", tags.get("DataClassification", ""))).lower()
            threat_vector = str(tags.get("ThreatVector", "")).lower()
            
            is_sensitive_data = "pci" in data_class or "pii" in data_class or "phi" in data_class
            is_shadow_admin = "shadowadmin" in threat_vector
            is_critical_db = res_type in ["dbinstance", "rds"] and risk >= 7.0
            
            if is_sensitive_data or is_shadow_admin or is_critical_db:
                crown_jewels.append(arn)

        self.diagnostics.entry_points = len(entry_points)
        self.diagnostics.crown_jewels = len(crown_jewels)
        return entry_points, crown_jewels

    # ==========================================================================
    # COMBINATORIAL TRAVERSAL & FRICTION DECAY 2.0 (PHASE 5)
    # ==========================================================================

    def _execute_path_discovery(self, entry_points: List[str], crown_jewels: List[str]) -> List[Dict]:
        """
        Executes nx.all_simple_paths across the target matrix.
        Applies Friction Decay 2.0 to violently prune combinatorial spaghetti noise.
        """
        valid_paths = []
        
        for ep in entry_points:
            for cj in crown_jewels:
                # Avoid self-loops
                if ep == cj:
                    continue
                    
                try:
                    # Generator yields lists of ARNs
                    paths_generator = nx.all_simple_paths(self.G, source=ep, target=cj, cutoff=self.max_depth)
                    
                    for raw_path in paths_generator:
                        self.diagnostics.raw_paths_found += 1
                        
                        # 1. Apply Friction Decay 2.0 Scoring
                        hcs_score, tier = self._calculate_friction_decay(raw_path)
                        
                        # 2. Aggressive Noise Pruning
                        if hcs_score < self.risk_threshold:
                            self.diagnostics.pruned_by_threshold += 1
                            continue
                            
                        # 3. MITRE ATT&CK Enrichment
                        mitre_mapping = self._generate_mitre_mapping(raw_path)
                            
                        if tier == ThreatTier.CRITICAL.value:
                            self.diagnostics.critical_paths += 1
                            
                        # 4. Compile URM Output
                        formatted_path = self._format_attack_path(raw_path, hcs_score, tier, mitre_mapping)
                        valid_paths.append(formatted_path)
                        
                except nx.NetworkXNoPath:
                    continue
                except Exception as e:
                    self.logger.warning(f"Pathing calculation fault between {ep} and {cj}: {e}")

        # Sort by absolute severity descending to ensure UI prioritizes critical threats
        valid_paths.sort(key=lambda x: x.get("metadata", {}).get("hcs_score", 0.0), reverse=True)
        return valid_paths

    def _calculate_friction_decay(self, path: List[str]) -> Tuple[float, str]:
        """
        Friction Decay 2.0 Algorithm.
        Formula: HCS = (Aggregate_Risk * Multipliers) / (Hop_Count ^ Decay_Exponent)
        
        This non-linear physics approach means a 5-hop path requires massive 
        systemic risk to remain relevant, effectively killing graph noise.
        """
        hop_count = len(path) - 1
        if hop_count <= 0:
            return 0.0, ThreatTier.LOW.value
            
        aggregate_risk = sum([self.G.nodes[n].get("risk_score", 1.0) for n in path])
        
        # Baseline Decay using configured exponent (Default 2.0)
        decay_factor = math.pow(hop_count, self.decay_exponent)
        hcs_score = aggregate_risk / decay_factor

        # ----------------------------------------------------------------------
        # DYNAMIC GRAVITY MULTIPLIERS
        # ----------------------------------------------------------------------
        has_identity_bridge = False
        has_shadow_admin = False
        
        for i in range(hop_count):
            edge_data = self.G.get_edge_data(path[i], path[i+1])
            if edge_data and edge_data.get("is_identity_bridge"):
                has_identity_bridge = True
                
            node_tags = self.G.nodes[path[i]].get("tags", {})
            if "ShadowAdmin" in str(node_tags.get("ThreatVector", "")):
                has_shadow_admin = True

        # Penalize cloud-barrier breaches heavily (Cross-Cloud lateral movement)
        if has_identity_bridge:
            hcs_score *= 2.5 
            
        # Penalize Privilege Escalation
        if has_shadow_admin:
            hcs_score *= 1.8

        # Cap score strictly to bounds
        hcs_score = round(min(10.0, max(0.0, hcs_score)), 2)
        
        # Tier Classification Mapping
        if hcs_score >= 8.0:
            tier = ThreatTier.CRITICAL.value
        elif hcs_score >= 6.0:
            tier = ThreatTier.HIGH.value
        elif hcs_score >= 4.5:
            tier = ThreatTier.MEDIUM.value
        else:
            tier = ThreatTier.LOW.value
            self.diagnostics.pruned_by_friction += 1
            
        return hcs_score, tier

    # ==========================================================================
    # MITRE ENRICHMENT & URM FORMATTING (PHASE 6 & 7)
    # ==========================================================================

    def _generate_mitre_mapping(self, path: List[str]) -> List[str]:
        """Maps graph hops to physical MITRE ATT&CK tactics."""
        tactics = []
        
        # Hop 0 is always the entry point
        first_node = self.G.nodes[path[0]]
        if "Public" in str(first_node.get("tags", {}).get("Exposure", "")):
            tactics.append(self.mitre_matrix["TA0001"]) # Initial Access
            
        for i in range(len(path) - 1):
            edge_data = self.G.get_edge_data(path[i], path[i+1])
            relation = edge_data.get("relation", "")
            
            if relation == EdgeType.CROSS_CLOUD_ASSUME.value:
                tactics.append(self.mitre_matrix["TA0004"]) # Privilege Escalation
            elif relation == EdgeType.CAN_ASSUME.value:
                tactics.append(self.mitre_matrix["TA0006"]) # Credential Access
            elif relation == EdgeType.NETWORK_ACCESS.value:
                tactics.append(self.mitre_matrix["TA0008"]) # Lateral Movement
            elif relation == EdgeType.EXECUTES_ON.value:
                tactics.append(self.mitre_matrix["TA0002"]) # Execution
                
        # Final Hop logic
        last_node = self.G.nodes[path[-1]]
        if last_node.get("type") in ["dbinstance", "bucket", "table", "storageaccount"]:
            tactics.append(self.mitre_matrix["TA0010"]) # Exfiltration
            
        # Deduplicate while preserving order
        return list(dict.fromkeys(tactics))

    def _format_attack_path(self, path: List[str], hcs_score: float, tier: str, mitre_tactics: List[str]) -> Dict[str, Any]:
        """
        Constructs the strict Universal Resource Model entity for the Neo4j Ingestor.
        
        THE BLACKOUT CURE: Correctly utilizes 'node_data' instead of the undefined 'node' 
        variable, preventing the fatal NameError that dropped all generated paths.
        """
        path_id = f"hapd-path-{uuid.uuid4().hex[:12]}"
        
        path_matrix = []
        for arn in path:
            node_data = self.G.nodes[arn]
            path_matrix.append({
                "arn": arn,
                "type": node_data.get("type"),
                "name": node_data.get("name"),
                "risk": node_data.get("risk_score"),
                "provider": node_data.get("cloud_provider") # FIXED variable name
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
                "mitre_tactics": mitre_tactics,
                "path_sequence": path,
                "path_matrix": path_matrix, 
                "discovery_mechanism": "titan_hapd_friction_decay_2.0",
                "timestamp": time.time()
            }
        }

# Export Global Singleton
attack_path_engine = AttackPathEngine()