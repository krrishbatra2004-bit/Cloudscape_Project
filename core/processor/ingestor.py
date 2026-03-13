import logging
import json
import asyncio
import traceback
import copy
from typing import List, Dict, Any
from neo4j import AsyncGraphDatabase, exceptions

from core.config import config

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - GRAPH INGESTOR ENGINE
# ==============================================================================
# The Physical Database Materialization Gateway.
# Employs highly optimized, chunked Cypher UNWIND transactions and leverages 
# APOC for dynamic relationship generation. 
# 
# Features:
# - Transient Lock Resilience (Survives parallel thread deadlocks)
# - Deep Payload Serialization (Prevents Neo4j array/dict schema crashes)
# - Singleton Connection Pooling (Memory efficiency)
# ==============================================================================

class Ingestor:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Processor.Ingestor")
        
        # Pull database connection telemetry from the central config manager
        self.uri = config.settings.database.neo4j_uri
        self.user = config.settings.database.neo4j_user
        self.password = config.settings.database.neo4j_password
        
        # 500 is the mathematical sweet spot for Cypher UNWIND performance 
        # before memory overhead degrades the transaction speed.
        self.batch_size = 500 
        
        # Initialize the high-performance async driver pool
        try:
            self.driver = AsyncGraphDatabase.driver(
                self.uri, 
                auth=(self.user, self.password),
                max_connection_lifetime=200,
                max_connection_pool_size=50
            )
            self.logger.debug("AsyncGraphDatabase driver pool initialized successfully.")
        except Exception as e:
            self.logger.critical(f"FATAL: Failed to initialize Neo4j driver: {e}")
            self.driver = None

    async def close(self):
        """Gracefully terminates the driver connection pool to prevent memory leaks."""
        if self.driver:
            await self.driver.close()
            self.logger.info("Neo4j connection pool gracefully terminated.")

    # ==========================================================================
    # SCHEMA & KERNEL VALIDATION
    # ==========================================================================

    async def validate_schema(self) -> None:
        """
        Polls the kernel for readiness and enforces strict structural constraints.
        Guarantees O(1) topological lookups via ARN uniqueness constraints.
        """
        self.logger.info("Polling Neo4j Database Kernel for physical write-readiness...")
        
        if not self.driver:
            raise ConnectionError("Neo4j driver is not initialized. Cannot validate schema.")
            
        try:
            async with self.driver.session() as session:
                # Enforce globally unique physical addresses to prevent graph duplication
                await session.run(
                    "CREATE CONSTRAINT resource_arn IF NOT EXISTS FOR (n:CloudNode) REQUIRE n.arn IS UNIQUE"
                )
                # Optimize resource type querying for massive datasets
                await session.run(
                    "CREATE INDEX resource_type_idx IF NOT EXISTS FOR (n:CloudNode) ON (n.resource_type)"
                )
            self.logger.info("Neo4j Kernel is online, unlocked, and accepting transactions.")
        except Exception as e:
            self.logger.critical(f"Database Kernel schema verification failed: {e}")
            self.logger.debug(traceback.format_exc())
            raise

    # ==========================================================================
    # UNIFIED PAYLOAD GATEWAY
    # ==========================================================================

    async def process_payloads(self, source: str, payloads: List[Dict[str, Any]]) -> None:
        """
        The Master Routing Switch. 
        Directs telemetry from specific upstream intelligence engines to their 
        strictly optimized Cypher materialization endpoints.
        """
        if not payloads:
            self.logger.debug(f"Source '{source}' provided an empty payload stream. Bypassing ingestion.")
            return

        self.logger.debug(f"Received {len(payloads)} validated payloads from {source} for materialization.")
        
        try:
            if source == "HybridBridge":
                await self._ingest_nodes(payloads)
            elif source == "IdentityFabric":
                await self._ingest_edges(payloads)
            elif source == "AttackPathEngine":
                await self._ingest_attack_paths(payloads)
            else:
                self.logger.warning(f"Unrecognized payload source '{source}'. Ingestion sequence rejected.")
                
        except Exception as e:
            self.logger.error(f"Materialization fault for source {source}: {e}")
            self.logger.debug(traceback.format_exc())

    # ==========================================================================
    # CHUNKED CYPHER MATERIALIZATION METHODS
    # ==========================================================================

    async def _ingest_nodes(self, nodes: List[Dict[str, Any]]) -> None:
        """
        Materializes standard CloudNodes using bulk UNWIND.
        Extracts high-value attributes for direct node querying while flattening 
        deep nested arrays into JSON strings to prevent driver schema crashes.
        """
        query = """
        UNWIND $batch AS row
        MERGE (n:CloudNode {arn: row.arn})
        SET n.tenant_id = row.tenant_id,
            n.cloud_provider = row.cloud_provider,
            n.service = row.service,
            n.resource_type = row.type,
            n.name = row.name,
            n.risk_score = toFloat(row.flat_risk),
            n.is_simulated = toBoolean(row.flat_simulated),
            n.tags = row.tags_json,
            n.metadata = row.metadata_json
        """
        
        serialized_batch = []
        for node in nodes:
            safe_node = self._serialize_for_neo4j(node)
            
            # Hoist critical metadata properties to the root for direct Cypher index access
            meta = node.get("metadata", {})
            safe_node["flat_risk"] = meta.get("baseline_risk_score", 0.0)
            safe_node["flat_simulated"] = meta.get("is_simulated", False)
            
            serialized_batch.append(safe_node)

        self.logger.debug(f"Executing UNWIND Node transaction for {len(serialized_batch)} entities...")
        await self._execute_batched_transaction(query, serialized_batch, "Nodes")

    async def _ingest_edges(self, edges: List[Dict[str, Any]]) -> None:
        """
        Materializes Cross-Cloud and Intra-Cloud connections.
        Leverages Neo4j APOC to dynamically assign the relationship type based on 
        the payload's 'relation_type' attribute, which standard Cypher cannot do.
        """
        query = """
        UNWIND $batch AS row
        MATCH (s:CloudNode {arn: row.source_arn})
        MATCH (t:CloudNode {arn: row.target_arn})
        CALL apoc.merge.relationship(s, row.relation_type, 
            {}, 
            {
                weight: toFloat(row.weight), 
                discovery_mechanism: row.discovery_mechanism, 
                is_synthetic: toBoolean(row.is_synthetic)
            }, 
            t, 
            {}
        ) YIELD rel
        RETURN count(rel)
        """
        
        serialized_batch = []
        for edge in edges:
            meta = edge.get("metadata", {})
            # Sanitize the relation type to ensure it is a valid Cypher relationship identifier
            raw_relation = str(edge.get("relation_type", "RELATES_TO")).upper()
            safe_relation = raw_relation.replace(" ", "_").replace("-", "_")
            
            safe_edge = {
                "source_arn": edge.get("source_arn"),
                "target_arn": edge.get("target_arn"),
                "relation_type": safe_relation,
                "weight": edge.get("weight", 1.0),
                "discovery_mechanism": meta.get("discovery_mechanism", "unknown"),
                "is_synthetic": meta.get("is_synthetic", False)
            }
            serialized_batch.append(safe_edge)

        self.logger.debug(f"Executing UNWIND APOC Edge transaction for {len(serialized_batch)} bridges...")
        await self._execute_batched_transaction(query, serialized_batch, "Identity Edges")

    async def _ingest_attack_paths(self, paths: List[Dict[str, Any]]) -> None:
        """
        Materializes fully validated exfiltration routes from the HAPD Engine.
        Creates an explicit `AttackPath` entity and physically links it to the 
        Entry Point and the Crown Jewel for instantaneous Dashboard visualization.
        """
        query = """
        UNWIND $batch AS row
        MERGE (p:AttackPath {path_id: row.path_id})
        SET p.tier = row.tier,
            p.hcs_score = toFloat(row.flat_hcs),
            p.hop_count = toInteger(row.flat_hops),
            p.path_matrix = row.metadata_json
            
        WITH p, row
        MATCH (s:CloudNode {arn: row.source_node})
        MATCH (t:CloudNode {arn: row.target_node})
        
        MERGE (s)-[:ORIGINATES_PATH]->(p)
        MERGE (p)-[:TARGETS_CROWN_JEWEL]->(t)
        """
        
        serialized_batch = []
        for path in paths:
            safe_path = self._serialize_for_neo4j(path)
            
            meta = path.get("metadata", {})
            safe_path["flat_hcs"] = meta.get("hcs_score", 0.0)
            safe_path["flat_hops"] = meta.get("hop_count", 0)
            
            serialized_batch.append(safe_path)

        self.logger.debug(f"Executing UNWIND Attack Path transaction for {len(serialized_batch)} routes...")
        await self._execute_batched_transaction(query, serialized_batch, "Attack Paths")

    # ==========================================================================
    # TRANSACTION EXECUTION & SERIALIZATION UTILITIES
    # ==========================================================================

    async def _execute_batched_transaction(self, query: str, full_batch: List[Dict], log_label: str) -> None:
        """
        Safely slices massive payload arrays into network-friendly chunks and 
        executes them with physical retry mechanisms to survive Transient Deadlocks.
        """
        if not self.driver:
            self.logger.error(f"Cannot execute transaction for {log_label}; database driver is offline.")
            return

        total = len(full_batch)
        for i in range(0, total, self.batch_size):
            chunk = full_batch[i : i + self.batch_size]
            
            # Transient Lock Survival Loop
            max_retries = 4
            for attempt in range(max_retries):
                try:
                    async with self.driver.session() as session:
                        await session.run(query, batch=chunk)
                    break # Success, break out of the retry loop
                    
                except exceptions.TransientError as te:
                    backoff = 1.5 * (attempt + 1)
                    self.logger.warning(f"Neo4j Lock Collision on {log_label} chunk {i}. Retrying in {backoff}s ({attempt+1}/{max_retries})...")
                    await asyncio.sleep(backoff)
                    
                except Exception as e:
                    self.logger.error(f"Failed to commit {log_label} chunk {i}-{i+len(chunk)}: {e}")
                    self.logger.debug(traceback.format_exc())
                    break # Break on non-transient errors (e.g. Cypher syntax faults)

    def _serialize_for_neo4j(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep payload flattener.
        Neo4j drivers natively crash if passed Python lists or dictionaries as node properties. 
        This method converts nested structures into strict JSON strings for safe transit.
        """
        # Deep copy to avoid mutating the live memory state
        serialized = copy.deepcopy(payload)
        
        # 1. Stringify Tags Matrix
        if "tags" in serialized and isinstance(serialized["tags"], dict):
            serialized["tags_json"] = json.dumps(serialized["tags"], default=str)
        else:
            serialized["tags_json"] = "{}"
            
        # 2. Stringify Metadata Matrix
        if "metadata" in serialized and isinstance(serialized["metadata"], dict):
            serialized["metadata_json"] = json.dumps(serialized["metadata"], default=str)
        else:
            serialized["metadata_json"] = "{}"
            
        # Optional Cleanup: Remove original dicts from the root payload to reduce transit weight
        serialized.pop("tags", None)
        serialized.pop("metadata", None)
            
        return serialized

# ==============================================================================
# SINGLETON EXPORT (THE TITAN LINK)
# ==============================================================================
# The Orchestrator and other Nexus systems import this instance directly 
# to utilize a single, memory-efficient Neo4j connection pool across the mesh.
ingestor = Ingestor()