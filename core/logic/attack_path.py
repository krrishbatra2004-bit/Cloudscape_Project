import logging
import traceback
from typing import List, Dict, Any, Tuple, Set
import networkx as nx

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - HEURISTIC ATTACK PATH DISCOVERY (HAPD)
# ==============================================================================
# The "Brain" of the Nexus Intelligence Tier.
# Transforms flat cloud nodes into a Directed Mathematical Topology. 
# Calculates physically viable exfiltration routes by evaluating network 
# boundaries, identity bridges, and public exposure tags using Graph Theory.
# ==============================================================================

class AttackPathEngine:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Logic.AttackPath")
        self.max_path_depth = 5  # Prevent infinite combinatorial explosions in massive environments

    # --------------------------------------------------------------------------
    # HEURISTIC CLASSIFICATION
    # --------------------------------------------------------------------------

    def _classify_nodes(self, nodes: List[Dict[str, Any]]) -> Tuple[Set[str], Set[str]]:
        """
        Scans the Unified Resource Model (URM) to designate Attack Vectors.
        Returns a tuple of (Entry_Point_ARNs, Crown_Jewel_ARNs).
        """
        entry_points = set()
        crown_jewels = set()

        for node in nodes:
            arn = node.get("arn")
            if not arn:
                continue

            tags = node.get("tags", {})
            risk_score = float(node.get("risk_score", 0.0))

            # 1. Identify Entry Points (Public Exposure)
            is_exposed = any(
                val for key, val in tags.items() 
                if key.lower() == 'exposure' and 'public' in str(val).lower()
            ) or tags.get("Exposure") in ["CriticalPortOpen", "PublicAccessBlockMissing"]
            
            if is_exposed or (node.get("type", "").lower() in ["instance", "virtualmachine"] and risk_score >= 0.7):
                entry_points.add(arn)

            # 2. Identify Crown Jewels (Restricted Data / High Value)
            is_restricted = any(
                val for key, val in tags.items()
                if key.lower() == 'dataclassification' and 'restricted' in str(val).lower()
            ) or tags.get("Infrastructure") == "StateFile"

            if is_restricted or (node.get("type", "").lower() in ["bucket", "storageblob", "dbinstance"] and risk_score >= 0.7):
                crown_jewels.add(arn)

        self.logger.debug(f"Heuristics Classified {len(entry_points)} Entry Points and {len(crown_jewels)} Crown Jewels.")
        return entry_points, crown_jewels

    # --------------------------------------------------------------------------
    # TOPOLOGY RECONSTRUCTION (THE REALITY CHECK)
    # --------------------------------------------------------------------------

    def _build_topology_edges(self, nodes: List[Dict[str, Any]]) -> List[Tuple[str, str, Dict[str, Any]]]:
        """
        The Hallucination Cure.
        Reconstructs physical network boundaries (VPC -> Subnet -> Compute) 
        so the graph algorithm respects actual cloud containment zones.
        """
        edges = []
        subnet_to_vpc = {}
        compute_to_subnet = {}

        for node in nodes:
            arn = node.get("arn")
            raw_data = node.get("raw_data", {})
            node_type = node.get("type", "").lower()

            # AWS Topologies
            if node_type == "subnet":
                vpc_id = raw_data.get("VpcId")
                if vpc_id:
                    # We create an edge FROM VPC TO Subnet
                    edges.append((f"arn:aws:ec2:*:*:vpc/{vpc_id}", arn, {"relation": "CONTAINS", "weight": 1.0}))
            elif node_type == "instance":
                subnet_id = raw_data.get("SubnetId")
                if subnet_id:
                    edges.append((f"arn:aws:ec2:*:*:subnet/{subnet_id}", arn, {"relation": "HOSTS", "weight": 1.0}))
            elif node_type == "dbinstance":
                subnets = raw_data.get("DBSubnetGroup", {}).get("Subnets", [])
                for sub in subnets:
                    sub_id = sub.get("SubnetIdentifier")
                    if sub_id:
                        edges.append((f"arn:aws:ec2:*:*:subnet/{sub_id}", arn, {"relation": "HOSTS", "weight": 1.0}))

            # Azure Topologies
            elif node_type == "virtualnetwork":
                for sub in raw_data.get("subnets", []):
                    sub_arn = sub.get("id")
                    if sub_arn:
                        edges.append((arn, sub_arn, {"relation": "CONTAINS", "weight": 1.0}))
            elif node_type == "virtualmachine":
                # Extrapolate Azure Subnet from Network Interfaces if available
                nics = raw_data.get("network_profile", {}).get("network_interfaces", [])
                for nic in nics:
                    nic_id = nic.get("id", "")
                    if nic_id:
                        # Draw soft topological edge
                        edges.append((nic_id, arn, {"relation": "ATTACHED_TO", "weight": 1.0}))

        return edges

    # --------------------------------------------------------------------------
    # ATTACK PATH EXECUTION MATRIX
    # --------------------------------------------------------------------------

    def calculate_attack_paths(self, unified_graph: List[Dict[str, Any]], identity_edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Ingests the Unified Graph and Identity Fabric bridges.
        Builds a Directed Graph (DiGraph) and runs bounded Simple Path searches
        to discover viable exfiltration routes without hallucinating impossible jumps.
        """
        if not unified_graph:
            return []

        self.logger.info("Initializing NetworkX Directed Topological Graph...")
        G = nx.DiGraph()

        try:
            # 1. Load Physical Nodes
            for node in unified_graph:
                arn = node.get("arn")
                if arn:
                    G.add_node(arn, type=node.get("type"), risk=node.get("risk_score", 0.0))

            # 2. Load Identity Edges (Logical Bridges from Identity Fabric)
            for edge in identity_edges:
                src = edge.get("source_arn")
                tgt = edge.get("target_arn")
                if src and tgt:
                    # Identity edges are highly viable paths (weight 0.5)
                    G.add_edge(src, tgt, relation=edge.get("relation_type"), weight=0.5)

            # 3. Load Physical Topology Edges (Network Boundaries)
            topo_edges = self._build_topology_edges(unified_graph)
            for src, tgt, attrs in topo_edges:
                # To allow reverse traversal (e.g. Instance accessing a Role via its Subnet boundary)
                # we add bidirectional soft edges with higher friction (weight 2.0)
                G.add_edge(src, tgt, **attrs)
                G.add_edge(tgt, src, relation=f"IN_{attrs['relation']}", weight=2.0)

            # 4. Resolve Entry and Target Vectors
            entry_points, crown_jewels = self._classify_nodes(unified_graph)

            # Filter valid nodes that actually exist in the constructed graph
            valid_entries = [n for n in entry_points if n in G]
            valid_targets = [n for n in crown_jewels if n in G]

            if not valid_entries or not valid_targets:
                self.logger.info("HAPD Scan completed: No complete vectors found between Entry Points and Crown Jewels.")
                return []

            # 5. Pathfinding Execution
            self.logger.info(f"Graph constructed: {G.number_of_nodes()} Nodes, {G.number_of_edges()} Edges.")
            self.logger.info(f"Executing Bounded Path Search (Max Depth: {self.max_path_depth}) across {len(valid_entries)} Entries to {len(valid_targets)} Targets...")
            
            attack_path_payloads = []
            
            for source in valid_entries:
                for target in valid_targets:
                    if source == target:
                        continue
                        
                    try:
                        # Calculate all physically viable paths up to the max hop depth
                        paths = list(nx.all_simple_paths(G, source=source, target=target, cutoff=self.max_path_depth))
                        
                        for path in paths:
                            # Generate an explicit neo4j edge for each exact path discovered
                            path_id = " -> ".join(path)
                            payload = {
                                "type": "explicit_edge",
                                "relation_type": "ATTACK_PATH",
                                "source_arn": source,
                                "target_arn": target,
                                "metadata": {
                                    "hop_count": len(path) - 1,
                                    "path_sequence": path_id,
                                    "severity": "CRITICAL",
                                    "discovery_engine": "NetworkX_HAPD",
                                    # Base attack weight calculated by hop count (shorter is more critical)
                                    "weight": round(1.0 / len(path), 3)
                                }
                            }
                            attack_path_payloads.append(payload)
                            
                    except nx.NetworkXNoPath:
                        continue
                    except Exception as e:
                        self.logger.debug(f"Path computation failed between {source} and {target}: {e}")

            # Return the deduplicated and verified attack edges
            # (Limiting return size to prevent downstream database OOM if graph is completely flat)
            MAX_PATHS = 5000
            if len(attack_path_payloads) > MAX_PATHS:
                self.logger.warning(f"Extremely high path density detected ({len(attack_path_payloads)}). Truncating to top {MAX_PATHS} to preserve database stability.")
                attack_path_payloads = sorted(attack_path_payloads, key=lambda x: x["metadata"]["weight"], reverse=True)[:MAX_PATHS]

            self.logger.info(f"Attack Path Analysis complete. Generated {len(attack_path_payloads)} verified exfiltration routes.")
            return attack_path_payloads

        except Exception as e:
            self.logger.error(f"Catastrophic failure in NetworkX Topology Engine: {e}")
            self.logger.debug(traceback.format_exc())
            return []

# ==============================================================================
# SINGLETON EXPORT
# ==============================================================================
attack_path_engine = AttackPathEngine()