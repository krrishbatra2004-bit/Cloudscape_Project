import logging
import uuid
import networkx as nx
from typing import List, Dict, Any, Tuple

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - HEURISTIC ATTACK PATH DISCOVERY (HAPD)
# ==============================================================================
# The Exhaustive Intelligence Analyzer.
# Re-engineered for Titan: Identifies ALL potential exfiltration routes, 
# infers implicit structural network bridges, and dynamically classifies path 
# severity using the Heuristic Composite Score (HCS) algorithm.
# ==============================================================================

class AttackPathEngine:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Logic.AttackPath")
        self.max_search_depth = 6  # Maximum lateral movement hops an attacker would realistically take
        
        # HCS (Heuristic Composite Score) Thresholds
        self.TIER_CRITICAL = 0.85
        self.TIER_HIGH = 0.65
        self.TIER_MEDIUM = 0.40

    def calculate_attack_paths(self, unified_graph: List[Dict[str, Any]], identity_edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        The Master Pathfinder Loop.
        Constructs a NetworkX Directed Graph, infers missing structural connections,
        and executes exhaustive all-paths analysis.
        """
        self.logger.info("Initializing NetworkX Directed Topological Graph...")
        
        G = nx.DiGraph()
        
        # 1. Materialize Nodes into NetworkX
        valid_nodes = [n for n in unified_graph if n.get("type") != "explicit_edge" and n.get("arn")]
        for node in valid_nodes:
            arn = node["arn"]
            G.add_node(
                arn, 
                risk_score=float(node.get("risk_score", 0.0)),
                tags=node.get("tags", {}),
                resource_type=str(node.get("type", "")).lower(),
                service=str(node.get("service", "")).lower(),
                cloud=str(node.get("cloud_provider", "")).lower(),
                name=node.get("name", "Unknown")
            )
            
        self.logger.debug(f"HAPD Graph seeded with {G.number_of_nodes()} physical/synthetic nodes.")

        # 2. Materialize Explicit Identity Fabric Edges
        edge_count = 0
        for edge in identity_edges:
            src = edge.get("source_arn")
            tgt = edge.get("target_arn")
            if src and tgt and G.has_node(src) and G.has_node(tgt):
                G.add_edge(
                    src, tgt, 
                    weight=float(edge.get("weight", 1.0)),
                    relation=edge.get("relation_type", "CROSS_CLOUD_TRUST"),
                    is_identity_bridge=True
                )
                edge_count += 1
                
        # 3. Infer Implicit Structural Edges (Network Lateral Movement)
        inferred_count = self._infer_structural_edges(G, valid_nodes)
        self.logger.info(f"Graph topology constructed: {G.number_of_nodes()} Nodes, {edge_count} Identity Edges, {inferred_count} Inferred Structural Edges.")

        # 4. Identify Entry Points and Crown Jewels
        entry_points, crown_jewels = self._designate_strategic_targets(G)
        self.logger.info(f"HAPD Target Matrix: {len(entry_points)} Public Entry Points ➔ {len(crown_jewels)} Crown Jewels.")

        if not entry_points or not crown_jewels:
            self.logger.warning("Graph lacks either Entry Points or Crown Jewels. Pathfinding terminated.")
            return []

        # 5. Exhaustive Path Discovery & Dynamic Scoring
        return self._execute_exhaustive_discovery(G, entry_points, crown_jewels)

    # ==========================================================================
    # STRUCTURAL INFERENCE ENGINE
    # ==========================================================================

    def _infer_structural_edges(self, G: nx.DiGraph, nodes: List[Dict[str, Any]]) -> int:
        """
        Zero-Knowledge Linker.
        Analyzes metadata to connect floating infrastructure logically. 
        Crucial for Mock environments where physical routing tables are absent.
        """
        inferred_edges = 0
        
        # Group nodes by cloud provider for logical network boundary simulation
        aws_compute = []
        aws_data = []
        azure_compute = []
        azure_data = []
        
        for node in nodes:
            arn = node["arn"]
            service = str(node.get("service", "")).lower()
            res_type = str(node.get("type", "")).lower()
            cloud = str(node.get("cloud_provider", "")).lower()
            
            if cloud == "aws":
                if service in ["ec2", "lambda", "ecs"]: aws_compute.append(arn)
                elif service in ["rds", "s3", "dynamodb"]: aws_data.append(arn)
            elif cloud == "azure":
                if service in ["compute", "virtualmachine"]: azure_compute.append(arn)
                elif service in ["storage", "cosmosdb", "sql"]: azure_data.append(arn)

        # Simulate Internal Network Lateral Movement: Compute ➔ Data within the same cloud
        for compute_arn in aws_compute:
            for data_arn in aws_data:
                if not G.has_edge(compute_arn, data_arn):
                    G.add_edge(compute_arn, data_arn, weight=2.0, relation="CAN_REACH_NETWORK", is_identity_bridge=False)
                    inferred_edges += 1
                    
        for compute_arn in azure_compute:
            for data_arn in azure_data:
                if not G.has_edge(compute_arn, data_arn):
                    G.add_edge(compute_arn, data_arn, weight=2.0, relation="CAN_REACH_NETWORK", is_identity_bridge=False)
                    inferred_edges += 1

        return inferred_edges

    # ==========================================================================
    # STRATEGIC TARGET IDENTIFICATION
    # ==========================================================================

    def _designate_strategic_targets(self, G: nx.DiGraph) -> Tuple[List[str], List[str]]:
        """Scans graph attributes to dynamically flag Initial Access vs Data Exfiltration nodes."""
        entry_points = []
        crown_jewels = []
        
        for node_id, data in G.nodes(data=True):
            tags = data.get("tags", {})
            res_type = data.get("resource_type", "")
            risk = data.get("risk_score", 0.0)
            
            # Identify Initial Access Vectors
            if str(tags.get("Exposure", "")).lower() == "public" or risk >= 8.5:
                # Prioritize Compute/Storage that is public
                if res_type in ["instance", "virtualmachine", "bucket", "storageaccount"]:
                    entry_points.append(node_id)
            
            # Identify Crown Jewels (High-Value Targets)
            if str(tags.get("DataClass", "")) in ["PCI-DSS", "PII", "PHI"] or res_type in ["dbinstance", "databaseaccount", "sqlserver"]:
                crown_jewels.append(node_id)
            elif "admin" in str(data.get("name", "")).lower() and risk >= 9.0:
                crown_jewels.append(node_id) # Shadow Admins are also crown jewels
                
        # Deduplicate sets
        return list(set(entry_points)), list(set(crown_jewels))

    # ==========================================================================
    # EXHAUSTIVE DISCOVERY & HEURISTIC COMPOSITE SCORING (HCS)
    # ==========================================================================

    def _execute_exhaustive_discovery(self, G: nx.DiGraph, entry_points: List[str], crown_jewels: List[str]) -> List[Dict[str, Any]]:
        """
        Executes nx.all_simple_paths. Extracts every route, applies the HCS algorithm, 
        classifies the threat tier, and returns formatted Universal Path Models.
        """
        self.logger.info(f"Executing Exhaustive Path Search (Max Depth: {self.max_search_depth})...")
        verified_paths = []
        
        for source in entry_points:
            for target in crown_jewels:
                if source == target:
                    continue
                
                try:
                    # Unearth EVERY possible route between the Entry Point and the Crown Jewel
                    path_generator = nx.all_simple_paths(G, source=source, target=target, cutoff=self.max_search_depth)
                    
                    for raw_path in path_generator:
                        formatted_path = self._score_and_classify_path(G, raw_path)
                        verified_paths.append(formatted_path)
                        
                except nx.NetworkXNoPath:
                    continue
                except Exception as e:
                    self.logger.debug(f"Pathfinding anomaly between {source} and {target}: {e}")

        # Sort paths by HCS Severity (Highest risk first)
        verified_paths.sort(key=lambda x: x["metadata"]["hcs_score"], reverse=True)
        self.logger.info(f"Exhaustive Analysis Complete. Generated {len(verified_paths)} dynamically classified attack paths.")
        return verified_paths

    def _score_and_classify_path(self, G: nx.DiGraph, path_nodes: List[str]) -> Dict[str, Any]:
        """
        The HCS (Heuristic Composite Score) Algorithm.
        Calculates severity dynamically based on node risk, identity bridges, and path friction.
        """
        total_node_risk = 0.0
        identity_bridges_crossed = 0
        path_edges = []
        
        # 1. Analyze Nodes
        for idx, node_arn in enumerate(path_nodes):
            node_data = G.nodes[node_arn]
            # Normalize risk from 0-10 scale down to 0.0-1.0 scale for HCS math
            normalized_risk = node_data.get("risk_score", 0.0) / 10.0 if node_data.get("risk_score", 0.0) > 1.0 else node_data.get("risk_score", 0.0)
            total_node_risk += normalized_risk
            
            # Analyze Edges
            if idx < len(path_nodes) - 1:
                next_node = path_nodes[idx + 1]
                edge_data = G.get_edge_data(node_arn, next_node)
                
                if edge_data.get("is_identity_bridge"):
                    identity_bridges_crossed += 1
                    
                path_edges.append({
                    "source": node_arn,
                    "target": next_node,
                    "relation": edge_data.get("relation", "TRANSITS")
                })

        # 2. HCS Mathematical Formulation
        base_hcs = total_node_risk / len(path_nodes)  # Average node vulnerability
        
        # Identity Bridge Multiplier: Crossing clouds/accounts is highly dangerous
        bridge_multiplier = 1.0 + (0.25 * identity_bridges_crossed) 
        
        # Friction Decay: Longer paths are harder for attackers to execute successfully
        friction_decay = (len(path_nodes) - 2) * 0.05 
        
        raw_hcs = (base_hcs * bridge_multiplier) - friction_decay
        final_hcs = max(0.01, min(raw_hcs, 1.0)) # Clamp between 0.01 and 1.0
        
        # 3. Dynamic Tier Classification
        if final_hcs >= self.TIER_CRITICAL:
            tier = "CRITICAL"
        elif final_hcs >= self.TIER_HIGH:
            tier = "HIGH"
        elif final_hcs >= self.TIER_MEDIUM:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        # 4. Format payload for Graph Ingestor
        return {
            "type": "attack_path",
            "path_id": f"path-{uuid.uuid4().hex[:12]}",
            "source_node": path_nodes[0],
            "target_node": path_nodes[-1],
            "tier": tier,
            "metadata": {
                "hcs_score": round(final_hcs, 3),
                "hop_count": len(path_nodes) - 1,
                "cross_cloud_bridges": identity_bridges_crossed,
                "node_sequence": path_nodes,
                "edge_sequence": path_edges
            }
        }

# ==============================================================================
# SINGLETON EXPORT
# ==============================================================================
attack_path_engine = AttackPathEngine()