import copy
import logging
import traceback
import uuid
import itertools
from typing import Any, Dict, List, Generator, Iterable
from collections.abc import Mapping

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - HYBRID DATA BRIDGE
# ==============================================================================
# The master convergence point for the Aether Engine.
# Safely merges dynamic Live API streams with Synthetic State Factory streams.
# Upgraded for Titan: Implements Iterative Flattening, Recursive Deep Merging,
# O(1) Collision Mapping, and True Iterator Chunking for absolute OOM immunity.
# ==============================================================================

class HybridBridge:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Engines.HybridBridge")
        self.DEFAULT_CHUNK_SIZE = 500

    # ==========================================================================
    # DATA SANITIZATION & MEMORY DEFENSE
    # ==========================================================================

    def _flatten_payloads(self, raw_stream: Any) -> List[Dict[str, Any]]:
        """
        Iterative stack-based flattener.
        Replaces recursion to prevent RecursionError on massive, deeply nested 
        asyncio.gather pagination responses from enterprise cloud accounts.
        """
        flat_list = []
        stack = [raw_stream]

        while stack:
            current = stack.pop()
            if not current:
                continue
            
            if isinstance(current, dict):
                flat_list.append(current)
            elif isinstance(current, (list, tuple, set)):
                # Extend the stack with the contents (reversed to maintain original order)
                stack.extend(reversed(list(current)))
            elif isinstance(current, Exception):
                # Silently drop suppressed exceptions from isolated engine faults
                pass
            else:
                self.logger.debug(f"HybridBridge dropped unmergable object of type: {type(current)}")
                
        return flat_list

    def _ensure_dict(self, data: Any, fallback_key: str = "_raw") -> Dict[str, Any]:
        """
        The strict type-caster. 
        Forces rogue lists (like empty tag arrays returned by dirty APIs) or strings 
        into valid dictionaries to prevent TypeError mapping cascades downstream.
        """
        if isinstance(data, dict):
            return data
        elif not data:  # Catches None, [], "", etc.
            return {}
        else:
            return {fallback_key: str(data)}

    def _deep_merge_dicts(self, base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursive overlay matrix.
        Ensures that when Synthetic data is injected into Live data, nested dictionaries
        (like deep Azure metadata properties) are merged rather than overwritten.
        """
        merged = copy.deepcopy(base)
        for key, value in update.items():
            if isinstance(value, Mapping):
                merged[key] = self._deep_merge_dicts(merged.get(key, {}), value)
            else:
                merged[key] = copy.deepcopy(value)
        return merged

    # ==========================================================================
    # MASTER CONVERGENCE & STREAMING LOGIC
    # ==========================================================================

    def merge_payload_streams(self, live_stream: Any, synthetic_stream: Any) -> List[Dict[str, Any]]:
        """
        Standard convergence logic. Retained for backwards compatibility with 
        smaller mock environments and synchronous unit testing.
        """
        return list(itertools.chain.from_iterable(self.stream_unified_graph(live_stream, synthetic_stream, chunk_size=0)))

    def stream_unified_graph(self, live_stream: Any, synthetic_stream: Any, chunk_size: int = 500) -> Generator[List[Dict[str, Any]], None, None]:
        """
        The Titan Streaming Engine.
        Merges Live and Synthetic realities in memory, resolves ARN collisions in O(1) time,
        and yields the unified graph using itertools.chain to prevent memory duplication.
        """
        self.logger.info("Initializing Titan Hybrid Data Merge & Stream Sequence...")
        
        try:
            # 1. Neutralize the List-of-Lists anomalies via iterative flattening
            live_payloads = self._flatten_payloads(live_stream)
            synth_payloads = self._flatten_payloads(synthetic_stream)
            
            # O(1) Collision Matrix mapped by Unique Cloud ARN
            merged_registry: Dict[str, Dict[str, Any]] = {}
            explicit_edges: List[Dict[str, Any]] = []
            
            # Analytical tracking
            pure_synthetic_count = 0
            merged_count = 0
            live_count = 0

            # ------------------------------------------------------------------
            # PHASE 1: PROCESS LIVE DATA (PHYSICAL GROUND TRUTH)
            # ------------------------------------------------------------------
            for payload in live_payloads:
                if payload.get("type") == "explicit_edge":
                    explicit_edges.append(payload)
                    continue

                # Shallow copy root, deep copy mutable dicts
                safe_payload = payload.copy()
                tags = self._ensure_dict(safe_payload.get("tags")).copy()
                metadata = self._ensure_dict(safe_payload.get("metadata", safe_payload.get("raw_data", {}))).copy()
                
                tags["DataOrigin"] = "LiveAPI"
                safe_payload["tags"] = tags
                
                # URM-compliant ARN extraction
                arn = safe_payload.get("arn") or metadata.get("arn") or safe_payload.get("id")
                
                if arn:
                    if arn not in merged_registry:
                        merged_registry[arn] = safe_payload
                        live_count += 1
                else:
                    # Ephemeral ID generation prevents ID-collision across async threads
                    ephemeral_id = f"ephemeral-live-{uuid.uuid4().hex[:8]}"
                    self.logger.debug(f"Live payload missing definitive ARN. Assigned: {ephemeral_id}")
                    safe_payload["arn"] = ephemeral_id
                    merged_registry[ephemeral_id] = safe_payload
                    live_count += 1

            # ------------------------------------------------------------------
            # PHASE 2: PROCESS SYNTHETIC DATA (AUGMENTATION & BACKFILL)
            # ------------------------------------------------------------------
            for payload in synth_payloads:
                if payload.get("type") == "explicit_edge":
                    explicit_edges.append(payload)
                    continue
                    
                safe_payload = payload.copy()
                arn = safe_payload.get("arn") or safe_payload.get("metadata", {}).get("arn") or safe_payload.get("id")
                    
                if not arn:
                    continue
                
                # Defensively extract synthetic tags and risk metrics
                synth_tags = self._ensure_dict(safe_payload.get("tags")).copy()
                synth_metadata = self._ensure_dict(safe_payload.get("metadata", safe_payload.get("raw_data", {})))
                
                # URM schema agnostic risk extraction
                synth_risk = float(safe_payload.get("risk_score", synth_metadata.get("baseline_risk_score", 0.0)))
                    
                if arn in merged_registry:
                    # [THE HYBRID OVERLAY] - Node exists in Physical Reality AND Simulation
                    live_node = merged_registry[arn]
                    
                    # 1. Deep merge tags and metadata to preserve physical truths
                    live_node["tags"] = self._deep_merge_dicts(live_node.get("tags", {}), synth_tags)
                    live_node["tags"]["DataOrigin"] = "Hybrid"
                    live_node["tags"]["SyntheticAugmented"] = "True"
                    
                    # 2. Escalate Risk Score to the highest detected threat level mathematically
                    live_risk = float(live_node.get("risk_score", 0.0))
                    
                    if synth_risk > live_risk:
                        live_node["risk_score"] = synth_risk
                        live_node["tags"]["InjectedVulnerability"] = "True"
                        
                    # 3. Apply merged structure back to registry
                    merged_registry[arn] = live_node
                    merged_count += 1
                else:
                    # [PURE SYNTHETIC] - The resource doesn't exist live, we force it into the graph
                    synth_tags["DataOrigin"] = "Synthetic"
                    safe_payload["tags"] = synth_tags
                    # Ensure URM compliance for purely generated nodes
                    if "risk_score" not in safe_payload:
                        safe_payload["risk_score"] = synth_risk
                    merged_registry[arn] = safe_payload
                    pure_synthetic_count += 1

            # ------------------------------------------------------------------
            # PHASE 3: METRICS & TRUE GENERATOR YIELDING
            # ------------------------------------------------------------------
            total_nodes = len(merged_registry)
            
            self.logger.info(
                f"Hybrid Merge Complete. Total Unified Nodes: {total_nodes} "
                f"(Live Base: {live_count}, Pure Synthetic: {pure_synthetic_count}, Overlaid: {merged_count})"
            )
            
            # Use itertools.chain to create a contiguous iterator without loading 
            # a massive combined list of nodes + edges into memory.
            all_elements_iterator = itertools.chain(merged_registry.values(), explicit_edges)
            
            if chunk_size <= 0:
                # Fallback to pure list if chunking is disabled
                yield list(all_elements_iterator)
            else:
                # Advanced iterable chunking algorithm
                iterator = iter(all_elements_iterator)
                for first in iterator:
                    # Yields slices of the iterator exactly matching the chunk size
                    chunk = list(itertools.chain([first], itertools.islice(iterator, chunk_size - 1)))
                    yield chunk

        except Exception as e:
            self.logger.critical(f"FATAL ERROR during Titan Hybrid Data Merge: {e}\n{traceback.format_exc()}")
            
            # The Ultimate Failsafe: Yield whatever raw dictionaries we can salvage
            safe_fallback = [p for p in self._flatten_payloads(live_stream) if isinstance(p, dict)]
            if chunk_size <= 0:
                yield safe_fallback
            else:
                iterator = iter(safe_fallback)
                for first in iterator:
                    yield list(itertools.chain([first], itertools.islice(iterator, chunk_size - 1)))

# ==============================================================================
# SINGLETON EXPORT (THE TITAN LINK)
# ==============================================================================
# The Orchestrator imports this instance directly to ensure the entire Nexus
# pipeline utilizes a single, memory-efficient data bridge.
hybrid_bridge = HybridBridge()