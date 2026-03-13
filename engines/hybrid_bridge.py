import logging
import traceback
import copy
import random
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
from collections import defaultdict

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - HYBRID BRIDGE ENGINE
# ==============================================================================
# The Enterprise Convergence Matrix.
# Intelligently fuses live infrastructure telemetry with synthetic APT threat 
# vectors using deterministic (ARN) and heuristic (Topological Signature) algorithms.
# 
# Features:
# - O(1) Multi-dimensional Topological Indexing
# - Deep Heuristic Dictionary Merging (Tags & Metadata)
# - Synergistic Risk Compounding Mathematics
# - Cryptographic State Overlay Tracking
# ==============================================================================

class HybridBridge:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Engines.HybridBridge")
        
        # Performance and state tracking matrix
        self.diagnostics = {
            "live_base_nodes": 0,
            "pure_synthetic_nodes": 0,
            "heuristic_overlays": 0,
            "deterministic_overlays": 0,
            "failed_merges": 0,
            "total_unified": 0
        }

    def merge_payload_streams(self, live_stream: List[Dict[str, Any]], synthetic_stream: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        The Master Convergence Protocol.
        Fuses the raw infrastructure scan with the simulated APT threat matrix,
        ensuring absolute schema alignment before yielding the unified graph.
        """
        self.logger.info("Initializing Titan Hybrid Data Merge & Stream Sequence...")
        
        # Deep copy to guarantee immutable isolation from the orchestrator's original arrays
        try:
            live_nodes = copy.deepcopy(live_stream)
            synth_nodes = copy.deepcopy(synthetic_stream)
        except Exception as e:
            self.logger.error(f"Memory allocation fault during deepcopy: {e}")
            return live_stream # Fallback to live data

        # Pre-flight Isolation Barriers
        if not synth_nodes:
            self.logger.warning("Synthetic stream is empty. Yielding pure physical infrastructure graph.")
            return live_nodes
            
        if not live_nodes:
            self.logger.warning("Physical stream is empty. Yielding pure synthetic threat graph.")
            return synth_nodes

        try:
            unified_graph = self._execute_heuristic_merge(live_nodes, synth_nodes)
            
            # Post-Merge Validation
            valid_graph = self._validate_urm_compliance(unified_graph)
            
            self._render_telemetry_report()
            return valid_graph
            
        except Exception as e:
            self.logger.critical(f"Catastrophic Failure in Convergence Matrix: {e}")
            self.logger.debug(traceback.format_exc())
            self.logger.warning("Triggering Fail-Safe: Returning unmerged live stream to preserve pipeline integrity.")
            return live_nodes

    def _execute_heuristic_merge(self, live_nodes: List[Dict], synth_nodes: List[Dict]) -> List[Dict]:
        """
        Executes high-speed bindings to attach synthetic vulnerabilities to live nodes.
        Utilizes a dual-pass approach: Deterministic ARN matching followed by Heuristic Signature matching.
        """
        unified_graph = []
        pure_synthetic = []
        
        self.diagnostics["live_base_nodes"] = len(live_nodes)

        # 1. Construct O(1) Master Indices for rapid querying
        live_arn_index, live_signature_index = self._build_topological_indices(live_nodes)

        # 2. Iterate Synthetic Stream and Apply Advanced Bindings
        for synth in synth_nodes:
            synth_arn = synth.get("arn")
            
            # Generate the Topological Signature for this synthetic node
            sig = self._generate_topological_signature(synth)

            # Attempt A: Deterministic Exact ARN Match (100% Confidence)
            if synth_arn and synth_arn in live_arn_index:
                self._overlay_node(live_arn_index[synth_arn], synth, confidence="DETERMINISTIC")
                self.diagnostics["deterministic_overlays"] += 1
                continue
                
            # Attempt B: Heuristic Signature Match (Fuzzy Topology Binding)
            # If the synthetic node has a fabricated ARN but matches the cloud/service/type of a live node.
            if sig in live_signature_index and len(live_signature_index[sig]) > 0:
                # Randomly select a valid physical host within the same tenant/cloud/service boundary
                target_arn = random.choice(live_signature_index[sig])
                self._overlay_node(live_arn_index[target_arn], synth, confidence="HEURISTIC")
                self.diagnostics["heuristic_overlays"] += 1
                continue
                
            # Attempt C: No match found. Node is completely structural/pure synthetic (e.g., Azure Proxy VMs)
            pure_synthetic.append(self._synthesize_orphan_node(synth))
            self.diagnostics["pure_synthetic_nodes"] += 1

        # 3. Assemble the Unified Graph
        unified_graph.extend(list(live_arn_index.values()))
        unified_graph.extend(pure_synthetic)
        
        self.diagnostics["total_unified"] = len(unified_graph)

        return unified_graph

    # ==========================================================================
    # CORE INDEXING & SIGNATURE GENERATION
    # ==========================================================================

    def _build_topological_indices(self, live_nodes: List[Dict]) -> Tuple[Dict[str, Dict], Dict[Tuple, List[str]]]:
        """
        Constructs multi-dimensional hash maps for O(1) correlation speeds.
        Returns: (ARN_Index, Signature_Index)
        """
        arn_index = {}
        signature_index = defaultdict(list)
        
        for node in live_nodes:
            arn = node.get("arn")
            if not arn:
                continue
                
            arn_index[arn] = node
            
            # Extract signature for fuzzy heuristic binding
            sig = self._generate_topological_signature(node)
            signature_index[sig].append(arn)
            
        self.logger.debug(f"Topological Indices compiled. Unique ARNs: {len(arn_index)} | Unique Signatures: {len(signature_index)}.")
        return arn_index, signature_index

    def _generate_topological_signature(self, node: Dict) -> Tuple[str, str, str, str]:
        """
        Creates a strict 4-dimensional tuple representing the node's physical place in the mesh.
        Signature format: (TenantID, CloudProvider, Service, ResourceType)
        """
        return (
            str(node.get("tenant_id", "unknown")).upper(),
            str(node.get("cloud_provider", "unknown")).lower(),
            str(node.get("service", "unknown")).lower(),
            str(node.get("type", "unknown")).lower()
        )

    # ==========================================================================
    # COMPOUND OVERLAY MATHEMATICS
    # ==========================================================================

    def _overlay_node(self, live_node: Dict, synth_node: Dict, confidence: str) -> None:
        """
        Dynamically compounds the properties of a synthetic threat onto a live physical node.
        Applies deep dictionary merging and calculates non-linear risk synergy.
        """
        try:
            # 1. Execute Synergistic Risk Mathematics
            self._compound_risk_scores(live_node, synth_node)

            # 2. Deep Merge Tags and Metadata
            self._merge_tags_and_metadata(live_node, synth_node)

            # 3. Inject Threat Artifacts & Cryptographic Proof
            self._inject_threat_artifacts(live_node, synth_node, confidence)
            
            # 4. Flag the node as structurally compromised for downstream engines
            live_node["metadata"]["is_simulated"] = True
            live_node["metadata"]["hybrid_overlay_applied"] = True
            
        except Exception as e:
            self.logger.error(f"Overlay mathematical fault on node {live_node.get('arn')}: {e}")
            self.diagnostics["failed_merges"] += 1

    def _compound_risk_scores(self, live_node: Dict, synth_node: Dict) -> None:
        """
        Calculates the new risk score. If a node is inherently risky and is hit with a
        high-risk simulated APT, the resulting score receives a synergistic multiplier.
        """
        live_risk = float(live_node.get("metadata", {}).get("baseline_risk_score", 0.0))
        synth_risk = float(synth_node.get("metadata", {}).get("baseline_risk_score", 0.0))
        
        # If both vectors are significant, apply a synergy penalty (+1.5), capped at 10.0
        if live_risk >= 5.0 and synth_risk >= 5.0:
            new_risk = min(10.0, max(live_risk, synth_risk) + 1.5)
        else:
            # Otherwise, the dominant risk takes over
            new_risk = max(live_risk, synth_risk)
            
        live_node["metadata"]["baseline_risk_score"] = round(new_risk, 2)
        live_node["metadata"]["original_live_risk"] = live_risk

    def _merge_tags_and_metadata(self, live_node: Dict, synth_node: Dict) -> None:
        """
        Deep-merges tags to ensure the node is recognized by the AttackPathEngine 
        as a 'Crown Jewel' if the synthetic node classifies it as such.
        """
        live_tags = live_node.get("tags", {})
        synth_tags = synth_node.get("tags", {})
        
        for key, synth_val in synth_tags.items():
            if key not in live_tags:
                live_tags[key] = synth_val
            else:
                # Append string values to preserve both contexts (e.g. "Prod | PCI-DSS")
                if isinstance(live_tags[key], str) and isinstance(synth_val, str) and synth_val not in live_tags[key]:
                    live_tags[key] = f"{live_tags[key]} | {synth_val}"
                    
        live_node["tags"] = live_tags

    def _inject_threat_artifacts(self, live_node: Dict, synth_node: Dict, confidence: str) -> None:
        """
        Transfers the specific vulnerability details from the synthetic node into 
        a dedicated 'simulated_threats' array on the live node.
        """
        if "simulated_threats" not in live_node["metadata"]:
            live_node["metadata"]["simulated_threats"] = []
            
        threat_artifact = {
            k: v for k, v in synth_node.get("metadata", {}).items() 
            if k not in ["arn", "resource_type", "baseline_risk_score", "last_seen", "is_simulated"]
        }
        
        if threat_artifact:
            # Create a cryptographic hash to track the exact payload applied
            payload_str = f"{synth_node.get('arn')}-{datetime.now(timezone.utc).isoformat()}"
            threat_hash = hashlib.sha256(payload_str.encode()).hexdigest()[:12]
            
            threat_artifact["threat_id_hash"] = threat_hash
            threat_artifact["injected_from_synth_arn"] = synth_node.get("arn", "unknown")
            threat_artifact["binding_confidence"] = confidence
            
            live_node["metadata"]["simulated_threats"].append(threat_artifact)

    def _synthesize_orphan_node(self, synth_node: Dict) -> Dict:
        """
        Prepares a purely synthetic node (like a simulated Azure VM attacker) 
        for ingestion when it has no physical live counterpart to bind to.
        """
        synth_node["metadata"]["hybrid_overlay_applied"] = False
        synth_node["metadata"]["is_pure_synthetic"] = True
        return synth_node

    # ==========================================================================
    # VALIDATION & TELEMETRY
    # ==========================================================================

    def _validate_urm_compliance(self, graph: List[Dict]) -> List[Dict]:
        """
        Final safety check before passing data to the Intelligence Fabric.
        Ensures all nodes conform to the Universal Resource Model expectations.
        """
        valid_nodes = []
        for node in graph:
            if "arn" in node and "metadata" in node and "tags" in node:
                valid_nodes.append(node)
            else:
                self.logger.warning(f"Dropping malformed node from convergence stream: {node.get('arn', 'UNKNOWN')}")
                
        return valid_nodes

    def _render_telemetry_report(self) -> None:
        """Outputs strict, comprehensive metrics for the Orchestrator log."""
        self.logger.info(
            f"Hybrid Merge Complete. Total Unified Nodes: {self.diagnostics['total_unified']} "
            f"(Live Base: {self.diagnostics['live_base_nodes']}, "
            f"Pure Synthetic: {self.diagnostics['pure_synthetic_nodes']}, "
            f"Overlaid [Heuristic]: {self.diagnostics['heuristic_overlays']}, "
            f"Overlaid [Deterministic]: {self.diagnostics['deterministic_overlays']})"
        )


# ==============================================================================
# SINGLETON EXPORT (THE TITAN LINK)
# ==============================================================================
# The Orchestrator imports this instance directly to ensure the entire Nexus
# pipeline utilizes a single, memory-efficient data bridge.
hybrid_bridge = HybridBridge()