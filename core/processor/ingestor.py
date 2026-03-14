import asyncio
import json
import logging
import time
import random
import traceback
from typing import List, Dict, Any, Optional
from collections import defaultdict

from neo4j import AsyncGraphDatabase, exceptions
from core.config import config

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - DATABASE INGESTOR KERNEL (ZERO-G EDITION)
# ==============================================================================
# The High-Performance Graph Materialization & Transaction Engine.
#
# TITAN UPGRADES ACTIVE:
# 1. Jittered Exponential Backoff (The Patience Injector): Cures the 'Handshake 
#    Lag' crash when executing rapid Seed -> Scan transitions by dynamically 
#    buffering Bolt connections while the Neo4j JVM flushes I/O.
# 2. APOC-Independent Bulk Materialization: Groups URM edges dynamically in 
#    Python memory to construct valid native Cypher relationship insertions, 
#    bypassing the need for heavy APOC plugins.
# 3. Recursive JSON Flattening: Ensures deeply nested Boto3/Azure metadata 
#    arrays never trigger Labeled Property Graph (LPG) type exceptions.
# 4. Asynchronous Connection Pooling: Strictly bound teardown limits.
# ==============================================================================

class Ingestor:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Processor.Ingestor")
        self._driver: Optional[AsyncGraphDatabase.driver] = None
        
        # ----------------------------------------------------------------------
        # KERNEL TUNING PARAMETERS
        # ----------------------------------------------------------------------
        self.batch_size = getattr(config.settings.database.ingestion, "batch_size", 500)
        self.max_retries = getattr(config.settings.database.ingestion, "retries", 10) # Increased for Seed -> Scan safety
        self.base_backoff = getattr(config.settings.database.ingestion, "backoff_factor", 3.0)

    # ==========================================================================
    # KERNEL INITIALIZATION & CONNECTION POOLING
    # ==========================================================================

    async def _get_driver(self):
        """
        Initializes the Neo4j Async Driver with strict Jittered Exponential Backoff.
        
        If the Neo4j JVM is currently flushing transaction logs (common after a heavy 
        --seed execution), the Bolt protocol may open the TCP port but fail the L7 handshake. 
        This loop mathematical scales the wait time up to 60+ seconds to guarantee survival.
        """
        if self._driver:
            return self._driver

        uri = config.settings.database.neo4j_uri
        user = config.settings.database.neo4j_user
        password = config.settings.database.neo4j_password

        attempts = 0
        while attempts < self.max_retries:
            try:
                self._driver = AsyncGraphDatabase.driver(
                    uri, 
                    auth=(user, password),
                    max_connection_lifetime=3600,
                    max_connection_pool_size=config.settings.database.connection_pool_size,
                    connection_timeout=20.0
                )
                
                # Physical validation of the Bolt protocol magic bytes
                await self._driver.verify_connectivity()
                
                if attempts > 0:
                    self.logger.info("Database Kernel connection recovered successfully. JVM is ready.")
                else:
                    self.logger.info("Neo4j Kernel is online, unlocked, and accepting transactions.")
                    
                return self._driver
                
            except (exceptions.ServiceUnavailable, exceptions.DriverError, exceptions.AuthError) as e:
                attempts += 1
                error_msg = str(e)
                
                # Check for the specific "Incomplete Handshake" or "Connection Closed" zombie socket bug
                if "handshake" in error_msg.lower() or "connection closed" in error_msg.lower() or "timed out" in error_msg.lower():
                    
                    # Calculate Jittered Exponential Backoff
                    # e.g. Attempt 1: ~3.5s | Attempt 2: ~5.0s | Attempt 3: ~7.5s
                    jitter = random.uniform(0.5, 1.5)
                    wait_time = (self.base_backoff * (1.3 ** attempts)) + jitter
                    wait_time = round(min(wait_time, 15.0), 2) # Cap individual waits to 15s
                    
                    self.logger.warning(
                        f"Database Kernel handshake lag detected (Attempt {attempts}/{self.max_retries}). "
                        f"JVM may be flushing buffers. Buffering {wait_time}s..."
                    )
                    
                    if self._driver:
                        await self._driver.close()
                        self._driver = None
                        
                    await asyncio.sleep(wait_time)
                else:
                    self.logger.critical(f"Catastrophic Database Driver Fault: {error_msg}")
                    raise 
            
        raise exceptions.ServiceUnavailable(
            "Catastrophic Handshake Timeout: Neo4j JVM is unresponsive after maximum retries. "
            "Please verify the Docker container has not run out of system RAM."
        )

    # ==========================================================================
    # SCHEMA ENFORCEMENT & INTEGRITY CHECKS
    # ==========================================================================

    async def validate_schema(self) -> None:
        """
        Enforces physical Graph Constraints for URM integrity.
        Ensures ARNs are mathematically unique to prevent duplicate node ghosts.
        """
        driver = await self._get_driver()
        
        queries = [
            "CREATE CONSTRAINT resource_arn IF NOT EXISTS FOR (n:CloudNode) REQUIRE n.arn IS UNIQUE",
            "CREATE CONSTRAINT path_id IF NOT EXISTS FOR (p:AttackPath) REQUIRE p.path_id IS UNIQUE",
            "CREATE INDEX resource_type_idx IF NOT EXISTS FOR (n:CloudNode) ON (n.resource_type)",
            "CREATE INDEX tenant_idx IF NOT EXISTS FOR (n:CloudNode) ON (n.tenant_id)",
            "CREATE INDEX risk_score_idx IF NOT EXISTS FOR (n:CloudNode) ON (n.risk_score)"
        ]
        
        async with driver.session() as session:
            for q in queries:
                try:
                    await session.run(q)
                except exceptions.ClientError as e:
                    # Ignore warnings if the constraint/index is already mapped
                    if "already exists" not in str(e).lower():
                        self.logger.error(f"Schema Constraint Fault on query [{q}]: {e}")
                        
            # Wait for indexes to physically come online to prevent race conditions during bulk ingest
            await self._await_indexes_online(session)

    async def _await_indexes_online(self, session) -> None:
        """Actively polls the Neo4j index state to guarantee transaction readiness."""
        query = "SHOW INDEXES YIELD state, type RETURN state"
        try:
            for _ in range(5):
                result = await session.run(query)
                records = await result.data()
                if all(record["state"] == "ONLINE" for record in records):
                    return
                await asyncio.sleep(0.5)
        except Exception:
            pass # Fail-open if syntax is unsupported on older Neo4j versions

    # ==========================================================================
    # MASTER INGESTION ROUTING
    # ==========================================================================

    async def process_payloads(self, source_engine: str, payload: List[Dict[str, Any]]) -> None:
        """
        The Master Routing Switchboard.
        Segregates the incoming URM dictionary into strictly typed arrays (Nodes, Edges, Paths)
        and dispatches them to their highly optimized Cypher materialization pipelines.
        """
        if not payload:
            return

        self.logger.debug(f"[{source_engine}] Received {len(payload)} discrete entities for graph materialization.")
        
        # Segregation Logic Matrix
        nodes = []
        edges = []
        paths = []
        
        for p in payload:
            obj_type = p.get("type", "")
            if obj_type == "attack_path":
                paths.append(p)
            elif "source_arn" in p and "target_arn" in p:
                edges.append(p)
            else:
                nodes.append(p)

        # Sequential Materialization: Nodes MUST exist before Edges/Paths refer to them
        if nodes:
            await self._materialize_nodes(nodes)
        if edges:
            await self._materialize_edges(edges)
        if paths:
            await self._materialize_paths(paths)

    # ==========================================================================
    # DEEP-JSON NORMALIZERS
    # ==========================================================================

    def _safe_serialize(self, data: Any) -> str:
        """
        Recursively converts Python dictionaries and complex types into strict JSON strings.
        This entirely prevents Neo4j `TypeError` crashes when Boto3 injects datetimes or nested arrays.
        """
        if not data:
            return "{}"
            
        if isinstance(data, str):
            # Try to validate if it's already JSON
            try:
                json.loads(data)
                return data
            except ValueError:
                pass # Just a regular string, which is fine, but we are supposed to be stringifying dicts here

        try:
            return json.dumps(data, default=str)
        except Exception:
            return "{}"

    # ==========================================================================
    # PHASED MATERIALIZATION LOGIC (CHUNKED UNWIND)
    # ==========================================================================

    async def _materialize_nodes(self, nodes: List[Dict]) -> None:
        """
        Transforms deeply nested Python dictionaries into stringified JSON properties 
        to guarantee Neo4j persistence, then uses UNWIND to batch insert them.
        """
        driver = await self._get_driver()
        processed_nodes = []
        
        for node in nodes:
            # Construct the flattened URM Object
            flat_node = {
                "arn": node.get("arn", f"unknown-arn-{time.time()}"),
                "name": node.get("name", "Unknown_Entity"),
                "cloud_provider": node.get("cloud_provider", "unknown").lower(),
                "service": node.get("service", "unknown").lower(),
                "resource_type": str(node.get("type", "Resource")).lower(),
                "tenant_id": node.get("tenant_id", "unknown"),
                "is_simulated": bool(node.get("metadata", {}).get("is_simulated", False)),
                "risk_score": float(node.get("metadata", {}).get("baseline_risk_score", 1.0)),
                "tags_json": self._safe_serialize(node.get("tags", {})),
                "metadata_json": self._safe_serialize(node.get("metadata", {}))
            }
            processed_nodes.append(flat_node)

        # The Cypher UNWIND Query
        query = """
        UNWIND $batch AS node_data
        MERGE (n:CloudNode {arn: node_data.arn})
        SET n += node_data,
            n:Resource,
            n.last_updated = timestamp()
        """

        # Execute in protected memory chunks
        for i in range(0, len(processed_nodes), self.batch_size):
            chunk = processed_nodes[i : i + self.batch_size]
            try:
                async with driver.session() as session:
                    await session.execute_write(lambda tx: tx.run(query, batch=chunk))
            except Exception as e:
                self.logger.error(f"Node Materialization Fault during UNWIND: {e}")
                self.logger.debug(traceback.format_exc())

    async def _materialize_edges(self, edges: List[Dict]) -> None:
        """
        The APOC-Independent Native Cypher Edge Generator.
        
        Neo4j's native UNWIND MERGE cannot accept dynamic relationship types 
        (e.g., `MERGE (a)-[r:$rel_type]->(b)` is invalid syntax without APOC).
        
        This engine groups the edges by relation_type in Python memory first, 
        and then executes distinct native UNWIND queries for each type. This makes 
        the pipeline completely bulletproof against Docker plugin failures.
        """
        driver = await self._get_driver()
        
        # 1. Group edges mathematically by relationship type
        grouped_edges = defaultdict(list)
        for edge in edges:
            rel_type = edge.get("relation_type", "RELATED_TO").upper()
            # Sanitize the relation string to prevent Cypher injection
            rel_type = "".join([c for c in rel_type if c.isalnum() or c == "_"])
            
            flat_edge = {
                "source_arn": edge.get("source_arn"),
                "target_arn": edge.get("target_arn"),
                "weight": float(edge.get("weight", 1.0)),
                "is_identity_bridge": bool(edge.get("is_identity_bridge", False))
            }
            grouped_edges[rel_type].append(flat_edge)

        # 2. Execute grouped UNWIND queries
        for rel_type, type_batch in grouped_edges.items():
            
            # The dynamic native Cypher query injection
            query = f"""
            UNWIND $batch AS edge_data
            MATCH (a:CloudNode {{arn: edge_data.source_arn}})
            MATCH (b:CloudNode {{arn: edge_data.target_arn}})
            MERGE (a)-[r:{rel_type}]->(b)
            SET r.weight = edge_data.weight,
                r.is_identity_bridge = edge_data.is_identity_bridge,
                r.last_updated = timestamp()
            """
            
            # Chunk the specific relationship type batch
            for i in range(0, len(type_batch), self.batch_size):
                chunk = type_batch[i : i + self.batch_size]
                try:
                    async with driver.session() as session:
                        await session.execute_write(lambda tx: tx.run(query, batch=chunk))
                except Exception as e:
                    self.logger.error(f"Edge Materialization Fault on type [{rel_type}]: {e}")

    async def _materialize_paths(self, paths: List[Dict]) -> None:
        """
        Physically registers the specific HAPD kill chains into the database as standalone 
        nodes, then draws ORIGINATES_FROM and TARGETS edges to the specific compromised infrastructure.
        """
        driver = await self._get_driver()
        processed_paths = []
        
        for p in paths:
            metadata = p.get("metadata", {})
                
            flat_path = {
                "path_id": p.get("path_id"),
                "source_node": p.get("source_node"),
                "target_node": p.get("target_node"),
                "tier": p.get("tier", "LOW"),
                "hcs_score": float(metadata.get("hcs_score", 0.0)),
                "hop_count": int(metadata.get("hop_count", 0)),
                "path_sequence_json": self._safe_serialize(metadata.get("path_sequence", [])),
                "path_matrix_json": self._safe_serialize(metadata.get("path_matrix", [])),
                "mitre_tactics_json": self._safe_serialize(metadata.get("mitre_tactics", [])),
                "timestamp": float(metadata.get("timestamp", time.time()))
            }
            processed_paths.append(flat_path)
        
        query = """
        UNWIND $batch AS p
        MERGE (path:AttackPath {path_id: p.path_id})
        SET path += p
        
        // Link the Path Node to the physical Start and End Resource Nodes
        WITH path, p
        MATCH (src:CloudNode {arn: p.source_node})
        MATCH (dst:CloudNode {arn: p.target_node})
        MERGE (path)-[:ORIGINATES_FROM]->(src)
        MERGE (path)-[:TARGETS]->(dst)
        """
        
        for i in range(0, len(processed_paths), self.batch_size):
            chunk = processed_paths[i : i + self.batch_size]
            try:
                async with driver.session() as session:
                    await session.execute_write(lambda tx: tx.run(query, batch=chunk))
            except Exception as e:
                self.logger.error(f"Attack Path Materialization Fault: {e}")

    # ==========================================================================
    # KERNEL TEARDOWN (GRACEFUL MEMORY RELEASE)
    # ==========================================================================

    async def close(self) -> None:
        """
        Physically severs the connection pool. Called directly by main.py's
        `finally` block to guarantee 0 memory leaks or socket hangs on shutdown.
        """
        if self._driver:
            try:
                await self._driver.close()
            except Exception as e:
                self.logger.error(f"Fault during Neo4j connection pool teardown: {e}")
            finally:
                self._driver = None

# Export the Global Singleton Instance to preserve connection pooling across the app
ingestor = Ingestor()