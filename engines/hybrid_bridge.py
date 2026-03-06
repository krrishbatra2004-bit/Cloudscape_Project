import copy
import logging
import traceback
from typing import Any, Dict, List, Generator, Iterable

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - HYBRID DATA BRIDGE
# ==============================================================================
# The master convergence point for the Aether Engine.
# Safely merges dynamic Live API streams with Synthetic State Factory streams.
# Upgraded for Titan: Implements Iterative Flattening, O(1) Collision Mapping,
# and Chunked Generator Streaming to prevent OOM errors at production scale.
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
        [TITAN UPGRADE] Iterative stack-based flattener.
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
            elif isinstance(current, (list, tuple)):
                # Extend the stack with the contents (reversed to maintain original order)
                stack.extend(reversed(current))
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

    # ==========================================================================
    # MASTER CONVERGENCE & STREAMING LOGIC
    # ==========================================================================

    def merge_payload_streams(self, live_stream: Any, synthetic_stream: Any) -> List[Dict[str, Any]]:
        """
        Standard convergence logic. Retained for backwards compatibility with 
        smaller mock environments and testing.
        """
        return list(self.stream_unified_graph(live_stream, synthetic_stream, chunk_size=0))

    def stream_unified_graph(self, live_stream: Any, synthetic_stream: Any, chunk_size: int = 500) -> Generator[List[Dict[str, Any]], None, None]:
        """
        [TITAN UPGRADE] The Streaming Engine.
        Merges Live and Synthetic realities in memory, resolves ARN collisions in O(1) time,
        and yields the unified graph in manageable chunks to prevent Orchestrator memory bloat.
        """
        self.logger.info("Initializing Titan Hybrid Data Merge & Stream Sequence...")
        
        try:
            # 1. Neutralize the List-of-Lists anomalies via iterative flattening
            live_payloads = self._flatten_payloads(live_stream)
            synth_payloads = self._flatten_payloads(synthetic_stream)
            
            # O(1) Collision Matrix
            merged_registry: Dict[str, Dict[str, Any]] = {}
            
            # ------------------------------------------------------------------
            # PHASE 1: PROCESS LIVE DATA (PHYSICAL GROUND TRUTH)
            # ------------------------------------------------------------------
            for payload in live_payloads:
                # Shallow copy first, deep copy tags/metadata to save CPU cycles
                safe_payload = payload.copy()
                
                # Defensively cast tags and metadata
                tags = self._ensure_dict(safe_payload.get("tags")).copy()
                metadata = self._ensure_dict(safe_payload.get("metadata")).copy()
                
                tags["DataOrigin"] = "LiveAPI"
                safe_payload["tags"] = tags
                safe_payload["metadata"] = metadata
                
                # Extract ARN safely (Cross-cloud compatibility)
                arn = metadata.get("arn") or safe_payload.get("arn") or safe_payload.get("id")
                
                if arn:
                    if arn in merged_registry:
                        # Cross-Regional Deduplication (e.g., Global IAM roles fetched twice)
                        pass 
                    else:
                        merged_registry[arn] = safe_payload
                else:
                    self.logger.debug("Live payload missing definitive ARN. Assigning ephemeral UUID.")
                    merged_registry[f"ephemeral-live-{id(safe_payload)}"] = safe_payload

            # ------------------------------------------------------------------
            # PHASE 2: PROCESS SYNTHETIC DATA (AUGMENTATION & BACKFILL)
            # ------------------------------------------------------------------
            for payload in synth_payloads:
                safe_payload = payload.copy()
                is_edge = safe_payload.get("type") == "explicit_edge"
                
                if is_edge:
                    arn = f"edge::{safe_payload.get('source_arn')}::{safe_payload.get('target_arn')}::{safe_payload.get('relation_type', 'LINK')}"
                else:
                    arn = safe_payload.get("metadata", {}).get("arn") or safe_payload.get("arn") or safe_payload.get("id")
                    
                if not arn:
                    continue
                
                # Defensively cast synthetic tags
                synth_tags = self._ensure_dict(safe_payload.get("tags")).copy()
                    
                if arn in merged_registry and not is_edge:
                    # [THE HYBRID OVERLAY] - Node exists in Physical Reality AND Simulation
                    live_node = merged_registry[arn]
                    live_tags = live_node["tags"]
                    live_tags["DataOrigin"] = "Hybrid"
                    live_tags["SyntheticAugmented"] = "True"
                    
                    # Graft simulated vulnerabilities onto the Live Node
                    synth_risk = float(safe_payload.get("metadata", {}).get("baseline_risk_score", 0.0))
                    live_risk = float(live_node.get("metadata", {}).get("baseline_risk_score", 0.0))
                    
                    if synth_risk > live_risk:
                        live_node.setdefault("metadata", {})["baseline_risk_score"] = synth_risk
                        live_tags["InjectedVulnerability"] = "True"
                        
                    live_node["tags"] = live_tags
                else:
                    # Pure Synthetic Node (e.g., A hypothetical attacker VM)
                    synth_tags["DataOrigin"] = "Synthetic"
                    safe_payload["tags"] = synth_tags
                    merged_registry[arn] = safe_payload

            # ------------------------------------------------------------------
            # PHASE 3: METRICS & CHUNKED YIELDING
            # ------------------------------------------------------------------
            final_graph = list(merged_registry.values())
            total_nodes = len(final_graph)
            
            live_count = len(live_payloads)
            synth_count = len([p for p in synth_payloads if p.get("type") != "explicit_edge"])
            hybrid_count = len([p for p in final_graph if p.get("tags", {}).get("DataOrigin") == "Hybrid"])
            pure_synth_count = len([p for p in final_graph if p.get("tags", {}).get("DataOrigin") == "Synthetic" and p.get("type") != "explicit_edge"])
            
            self.logger.info(
                f"Hybrid Merge Complete. Total Unified Nodes: {total_nodes} "
                f"(Live: {live_count}, Pure Synthetic: {pure_synth_count}, Merged/Overlaid: {hybrid_count})"
            )
            
            # Chunking Logic (Yielding to the Orchestrator/Ingestor)
            if chunk_size <= 0:
                yield final_graph
            else:
                for i in range(0, total_nodes, chunk_size):
                    yield final_graph[i:i + chunk_size]

        except Exception as e:
            self.logger.critical(f"FATAL ERROR during Titan Hybrid Data Merge: {e}\n{traceback.format_exc()}")
            # The Ultimate Failsafe: Return whatever flat dictionaries we can salvage in one chunk
            safe_fallback = [p for p in self._flatten_payloads(live_stream) if isinstance(p, dict)]
            yield safe_fallback

# ==============================================================================
# SINGLETON EXPORT (THE TITAN LINK)
# ==============================================================================
# The Orchestrator imports this instance directly to ensure the entire Nexus
# pipeline utilizes a single, memory-efficient data bridge.
hybrid_bridge = HybridBridge()