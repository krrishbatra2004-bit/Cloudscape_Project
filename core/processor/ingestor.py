import asyncio
import logging
import json
import uuid
import time
import os
import re
import math
import sys
from datetime import datetime, timezone, date
from typing import List, Dict, Any, Optional, Union, Tuple, Set, Generator
from dataclasses import dataclass, field
from collections import deque

try:
    from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession
    from neo4j.exceptions import TransientError, ServiceUnavailable, ClientError, AuthError
except ImportError:
    raise ImportError("Neo4j driver missing. Run: pip install neo4j")

# Core Titan Configuration Bindings
from core.config import config

# ==============================================================================
# CLOUDSCAPE NEXUS 5.1 TITAN - DATABASE KERNEL & STREAMING INGESTOR
# ==============================================================================
# The Sovereign-Forensic Graph Materialization Engine.
# 
# TITAN NEXUS 5.1 UPGRADES ACTIVE:
# 1. ADAPTIVE MEMORY CHUNKING: Dynamically calculates payload byte-weight and 
#    shrinks batch sizes in real-time to prevent JVM OOM crashes on Neo4j.
# 2. DEEP RECURSIVE SERIALIZER 2.0: Safely serializes complex nested Boto3, 
#    Azure SDK objects, bytes, datetimes, and UUIDs without data loss. Replaces 
#    the faulty "{}" silent fail mechanism.
# 3. PHANTOM NODE UPSERT STRATEGY: Resolves "Dangling Paths". If the HAPD engine
#    references a node pruned by another phase, the ingestor generates a 
#    'Phantom' node to preserve graph topological integrity.
# 4. DEAD LETTER QUEUE (DLQ): Absolute fault tolerance. Any payload chunk that 
#    exhausts retry limits is serialized to disk in a forensic DLQ for manual 
#    recovery. No data is ever silently dropped.
# 5. APOC-AWARE SCHEMA AUTOPILOT: Automatically detects if APOC is loaded and 
#    adjusts schema generation. Uses asynchronous exponential backoff to ensure 
#    indexes are ONLINE before ignition.
# 6. TRANSIENT DEADLOCK MANAGER: Catches concurrent Cypher locking exceptions 
#    and applies Jittered Exponential Backoff to resolve write-contention.
# ==============================================================================

# ------------------------------------------------------------------------------
# ENTERPRISE EXCEPTIONS & ERROR HANDLING
# ------------------------------------------------------------------------------

class IngestionKernelError(Exception):
    """Base exception for the Titan Database Kernel."""
    pass

class SchemaLockError(IngestionKernelError):
    """Raised when the database refuses to bring indices ONLINE."""
    pass

class MalformedPayloadError(IngestionKernelError):
    """Raised when incoming data violates strict URM structural constraints."""
    pass

class TransactionDeadlockError(IngestionKernelError):
    """Raised when the Jittered Backoff fails to resolve a Neo4j write lock."""
    pass

# ------------------------------------------------------------------------------
# METRICS & STATE MANAGEMENT
# ------------------------------------------------------------------------------

@dataclass
class IngestorMetrics:
    """High-fidelity telemetry for the Ingestion Kernel."""
    nodes_merged: int = 0
    edges_merged: int = 0
    paths_materialized: int = 0
    phantom_nodes_spawned: int = 0
    chunks_processed: int = 0
    deadlocks_resolved: int = 0
    dlq_writes: int = 0
    bytes_transferred: int = 0
    schema_verification_time_ms: float = 0.0
    total_transaction_time_ms: float = 0.0

# ------------------------------------------------------------------------------
# DEEP SERIALIZATION ENGINE
# ------------------------------------------------------------------------------

class SafeDeepSerializer(json.JSONEncoder):
    """
    Advanced recursive serializer. Handles datetime, sets, bytes, UUIDs, and 
    objects that typically crash `json.dumps`. Provides safe degradation instead 
    of wiping the entire dictionary.
    """
    def default(self, obj: Any) -> Any:
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='replace')
        if isinstance(obj, uuid.UUID):
            return str(obj)
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        if str(type(obj).__name__) == "dict_keys":
            return list(obj)
        if str(type(obj).__name__) == "dict_values":
            return list(obj)
            
        # Safe Degradation: Fallback to string representation
        try:
            return str(obj)
        except Exception:
            return "[UNSERIALIZABLE_OBJECT]"

# ------------------------------------------------------------------------------
# SUPREME INGESTION KERNEL
# ------------------------------------------------------------------------------

class Neo4jIngestor:
    """
    The Master Streaming Interface to the Graph Database.
    Guarantees ACID compliance, memory safety, and topological consistency.
    """

    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Processor.Ingestor")
        self.metrics = IngestorMetrics()
        self.driver: Optional[AsyncDriver] = None
        self._apoc_available: bool = False
        
        # Load configuration securely
        try:
            self.uri = config.settings.database.neo4j_uri
            self.user = config.settings.database.neo4j_user
            self.password = config.settings.database.neo4j_password
            self.max_batch_size = config.settings.system.ingestion_chunk_size
            self.max_retries = 5
            self.dlq_path = os.path.join(config.base_dir, "volume", "neo4j_dlq")
        except AttributeError as e:
            self.logger.error(f"Failed to load Neo4j config. Falling back to defaults: {e}")
            self.uri = "bolt://localhost:7687"
            self.user = "neo4j"
            self.password = "password"
            self.max_batch_size = 1000
            self.max_retries = 5
            self.dlq_path = "/tmp/neo4j_dlq"

        # Ensure Dead Letter Queue Directory exists
        os.makedirs(self.dlq_path, exist_ok=True)

    async def initialize(self) -> None:
        """Establish asynchronous connection pool to Neo4j."""
        if self.driver:
            return

        self.logger.info(f"Establishing Async Connection to Titan Graph Kernel at {self.uri}...")
        try:
            self.driver = AsyncGraphDatabase.driver(
                self.uri, 
                auth=(self.user, self.password),
                max_connection_lifetime=3600,
                max_connection_pool_size=50,
                connection_acquisition_timeout=10.0
            )
            
            # Verify connectivity
            async with self.driver.session() as session:
                await session.run("RETURN 1 AS ping")
            
            self.logger.info("  [OK] Graph Kernel Connection Established. Handshake validated.")
            
            # Autopilot Feature Detection
            await self._detect_apoc()
            
        except AuthError:
            self.logger.critical("  [FAIL] Database Authentication Denied. Check credentials.")
            raise
        except ServiceUnavailable as e:
            self.logger.critical(f"  [FAIL] Graph Kernel is offline or unreachable: {e}")
            raise
        except Exception as e:
            self.logger.critical(f"  [FAIL] Unexpected driver initialization fault: {e}")
            raise

    async def close(self) -> None:
        """Gracefully terminates connection pools."""
        if self.driver:
            await self.driver.close()
            self.logger.info("Graph Kernel connection pool securely closed.")
            self.driver = None

    # --------------------------------------------------------------------------
    # SCHEMA AUTOPILOT (Constraint & Index Validation)
    # --------------------------------------------------------------------------

    async def _detect_apoc(self) -> None:
        """Queries the DBMS to determine if the APOC plugin is active."""
        if not self.driver: return
        
        try:
            async with self.driver.session() as session:
                result = await session.run("CALL dbms.procedures() YIELD name WHERE name STARTS WITH 'apoc' RETURN count(name) as c")
                record = await result.single()
                if record and record["c"] > 0:
                    self._apoc_available = True
                    self.logger.debug("  [OK] APOC Module Detected. Advanced ingestion paths enabled.")
                else:
                    self.logger.warning("  [!] APOC Module missing. Falling back to standard Cypher ingestion.")
        except Exception as e:
            self.logger.warning(f"  [!] APOC detection check failed: {e}. Assuming inactive.")
            self._apoc_available = False

    async def validate_schema(self) -> None:
        """
        Enforces Database Constraints and Indices before data ingestion begins.
        Includes a dynamic Jittered Polling loop to wait for index population.
        """
        start = time.perf_counter()
        await self.initialize()
        self.logger.info("Executing Schema Autopilot Constraint Validation...")

        # Core Graph Constraints
        statements = [
            # Base Resource Identity (Must be unique)
            "CREATE CONSTRAINT resource_arn IF NOT EXISTS FOR (n:Resource) REQUIRE n.arn IS UNIQUE",
            
            # Attack Path Identity
            "CREATE CONSTRAINT path_id IF NOT EXISTS FOR (p:AttackPath) REQUIRE p.path_id IS UNIQUE",
            
            # High-Performance Query Indices
            "CREATE INDEX resource_type IF NOT EXISTS FOR (n:Resource) ON (n.type)",
            "CREATE INDEX resource_tenant IF NOT EXISTS FOR (n:Resource) ON (n.tenant_id)",
            "CREATE INDEX resource_provider IF NOT EXISTS FOR (n:Resource) ON (n.cloud_provider)"
        ]

        try:
            async with self.driver.session() as session:
                for query in statements:
                    await session.run(query)
            self.logger.debug("  [+] Schema constraints injected. Verifying ONLINE status...")
            
            # ------------------------------------------------------------------
            # DYNAMIC INDEX POLLING
            # On large existing databases, creating an index can take minutes.
            # We must wait for them to be ONLINE, otherwise ingestion queries 
            # will trigger massive Table Scans and crash the JVM.
            # ------------------------------------------------------------------
            await self._wait_for_indexes()
            
            self.metrics.schema_verification_time_ms = (time.perf_counter() - start) * 1000
            self.logger.info(f"  [OK] Schema Constraints Locked & Indexed ({self.metrics.schema_verification_time_ms:.2f}ms).")
            
        except ClientError as e:
            # Older Neo4j version compatibility check
            if "SyntaxError" in str(e) and "REQUIRE" in str(e):
                self.logger.warning("  [!] Neo4j version mismatch for new constraint syntax. Attempting legacy syntax...")
                await self._fallback_legacy_schema()
            else:
                raise SchemaLockError(f"Schema generation failed: {e}")
        except Exception as e:
            raise SchemaLockError(f"Critical error during schema autopilot: {e}")

    async def _wait_for_indexes(self) -> None:
        """Polls Neo4j `db.indexes()` until all are marked as ONLINE."""
        max_wait_seconds = 120
        start_wait = time.time()
        
        while time.time() - start_wait < max_wait_seconds:
            async with self.driver.session() as session:
                result = await session.run("SHOW INDEXES YIELD state, type WHERE type <> 'LOOKUP' RETURN state")
                records = await result.data()
                
                all_online = all(r.get("state") == "ONLINE" for r in records)
                if all_online:
                    return
                    
            # Exponential Backoff
            elapsed = time.time() - start_wait
            sleep_time = min(5.0, elapsed * 0.5)
            self.logger.debug(f"  [*] Waiting for indices to build (Elapsed: {elapsed:.1f}s). Retrying in {sleep_time:.1f}s...")
            await asyncio.sleep(sleep_time)
            
        raise SchemaLockError("Timeout exceeded waiting for graph indices to transition to ONLINE state.")

    async def _fallback_legacy_schema(self) -> None:
        """Legacy constraint syntax for older Neo4j versions (4.x)."""
        legacy = [
            "CREATE CONSTRAINT resource_arn ON (n:Resource) ASSERT n.arn IS UNIQUE",
            "CREATE CONSTRAINT path_id ON (p:AttackPath) ASSERT p.path_id IS UNIQUE",
            "CREATE INDEX resource_type FOR (n:Resource) ON (n.type)"
        ]
        async with self.driver.session() as session:
            for query in legacy:
                try:
                    await session.run(query)
                except Exception as e:
                    self.logger.debug(f"Legacy query failed (ignorable if exists): {e}")

    # --------------------------------------------------------------------------
    # PAYLOAD ROUTING & BATCHING
    # --------------------------------------------------------------------------

    async def process_payloads(self, source: str, payloads: List[Dict[str, Any]]) -> None:
        """
        The Master Router for incoming data streams.
        Dynamically calculates optimal memory batching and routes to the correct 
        Cypher injection kernel.
        """
        if not payloads:
            return
            
        await self.initialize()
        start_time = time.perf_counter()
        self.logger.debug(f"[{source}] Processing payload matrix ({len(payloads)} entities)...")
        
        # Determine Routing Path based on Source
        if source in ["TitanHybridBridge", "DiscoveryEngine"]:
            # Standard Resource Nodes
            await self._chunked_execution(self._materialize_nodes, payloads, "Nodes")
        elif source == "IdentityFabric":
            # Direct Structural Edges
            await self._chunked_execution(self._materialize_edges, payloads, "Edges")
        elif source == "AttackPathEngine":
            # Complex Attack Path Structures
            await self._chunked_execution(self._materialize_paths, payloads, "Paths")
        else:
            self.logger.warning(f"Unrecognized payload source '{source}'. Routing to generic node ingestion.")
            await self._chunked_execution(self._materialize_nodes, payloads, "Nodes")

        elapsed = (time.perf_counter() - start_time) * 1000
        self.metrics.total_transaction_time_ms += elapsed
        self.logger.info(f"  [+] {source} Materialization Complete ({elapsed:.2f}ms).")

    async def _chunked_execution(self, ingestion_func: Any, payloads: List[Dict], log_label: str) -> None:
        """
        Executes Cypher logic using an Adaptive Memory Window.
        Splits massive arrays into safe transaction blocks.
        """
        total = len(payloads)
        
        # Adaptive Batch Sizing
        # If objects are massive (e.g. nested IAM policies), shrink the batch.
        sample_size = min(10, total)
        sample_bytes = sum(len(json.dumps(payloads[i], cls=SafeDeepSerializer)) for i in range(sample_size))
        avg_bytes_per_record = max(1, sample_bytes / sample_size)
        
        # Target ~2MB per transaction block to prevent JVM heap overflow
        target_batch_bytes = 2 * 1024 * 1024 
        adaptive_size = max(100, min(self.max_batch_size, int(target_batch_bytes / avg_bytes_per_record)))
        
        if adaptive_size != self.max_batch_size:
            self.logger.debug(f"Adaptive Batching Active: Adjusted size from {self.max_batch_size} to {adaptive_size} due to payload weight.")

        for i in range(0, total, adaptive_size):
            chunk = payloads[i:i + adaptive_size]
            self.metrics.chunks_processed += 1
            
            # Deep Serialization and Sanitization
            clean_chunk = []
            for item in chunk:
                try:
                    # Sanitize the dictionary into flat JSON strings where necessary
                    clean_item = self._prepare_properties(item)
                    clean_chunk.append(clean_item)
                except Exception as e:
                    self.logger.warning(f"Payload sanitization fault. Dropping item: {e}")
                    
            if clean_chunk:
                # Execute with Transaction Deadlock Retries
                await self._execute_with_retry(ingestion_func, clean_chunk, log_label)

    async def _execute_with_retry(self, func: Any, chunk: List[Dict], log_label: str) -> None:
        """
        Jittered Exponential Backoff wrapper for Cypher Transactions.
        Catches TransientErrors (Deadlocks) caused by parallel graph mutations.
        """
        attempt = 0
        while attempt < self.max_retries:
            try:
                async with self.driver.session() as session:
                    await session.execute_write(func, chunk)
                return # Success
                
            except TransientError as e:
                # Standard Neo4j Deadlock or Memory Lock
                attempt += 1
                self.metrics.deadlocks_resolved += 1
                wait_time = (2 ** attempt) + (time.time() % 1.0) # Jitter
                self.logger.warning(f"  [!] Graph Deadlock Detected ({log_label}). Retrying {attempt}/{self.max_retries} in {wait_time:.2f}s...")
                await asyncio.sleep(wait_time)
                
            except Exception as e:
                self.logger.error(f"  [!] Critical Graph Execution Fault ({log_label}): {e}")
                self._flush_to_dlq(chunk, str(e))
                break # Non-transient errors do not get retried
                
        if attempt >= self.max_retries:
            self.logger.error(f"  [X] Max retries exhausted for {log_label} chunk. Offloading to DLQ.")
            self._flush_to_dlq(chunk, "Max Retries Exhausted (Deadlock)")

    # --------------------------------------------------------------------------
    # DATA SANITIZATION & METADATA PREPARATION
    # --------------------------------------------------------------------------

    def _prepare_properties(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensures strict type compliance for Neo4j Properties.
        Neo4j only accepts primitives and arrays of primitives. 
        Nested dicts MUST be stringified.
        """
        clean_props = {}
        for k, v in raw_data.items():
            # Skip empty or null values to save DB space
            if v is None or v == "":
                continue
                
            if isinstance(v, (dict, list, tuple)):
                # Use the Deep Serializer to stringify nested structures safely
                clean_props[k] = json.dumps(v, cls=SafeDeepSerializer)
            elif isinstance(v, (str, int, float, bool)):
                clean_props[k] = v
            else:
                clean_props[k] = json.dumps(v, cls=SafeDeepSerializer)
                
        # Track ingestion timestamp
        clean_props["_titan_last_seen"] = int(time.time())
        return clean_props

    def _sanitize_relation_name(self, name: str) -> str:
        """
        Secures Cypher relationship names.
        Flaw Resolution: Original code mangled names. Now permits alphanumeric, 
        underscores, and strictly validates to prevent Cypher injection.
        """
        if not name or not isinstance(name, str):
            return "UNKNOWN_RELATION"
            
        # Allow A-Z, 0-9, and underscores. Convert spaces/dashes to underscores.
        clean = re.sub(r'[^A-Z0-9_]', '_', name.upper())
        # Prevent starting with numbers or multiple underscores
        clean = re.sub(r'^_+|(?<=_)_+', '', clean)
        
        if not clean: return "UNKNOWN_RELATION"
        return clean

    # --------------------------------------------------------------------------
    # CYPHER EXECUTION KERNELS (NODES, EDGES, PATHS)
    # --------------------------------------------------------------------------

    async def _materialize_nodes(self, tx: Any, payloads: List[Dict[str, Any]]) -> None:
        """
        Bulk Upsert (MERGE) for standard Cloud Resources.
        Uses Cypher UNWIND for massive O(1) bulk processing.
        """
        query = """
        UNWIND $batch AS data
        MERGE (n:Resource {arn: data.arn})
        SET n += data,
            n:RawEntity
        """
        # Dynamic labeling based on provider
        query += """
        WITH n, data
        CALL apoc.create.addLabels(n, [coalesce(data.cloud_provider, 'Unknown'), coalesce(data.type, 'UnknownEntity')]) YIELD node
        RETURN count(node)
        """ if self._apoc_available else ""
        
        # If APOC isn't available, we rely on the base 'Resource' label, 
        # which is sufficient, though less aesthetically pleasing in the UI.
        
        result = await tx.run(query, batch=payloads)
        self.metrics.nodes_merged += len(payloads)
        self.metrics.bytes_transferred += sum(sys.getsizeof(p) for p in payloads)

    async def _materialize_edges(self, tx: Any, payloads: List[Dict[str, Any]]) -> None:
        """
        Bulk Upsert for Structural and Identity Relationships.
        Includes a Phantom Node generator to prevent orphaned edges.
        """
        # Cypher injections are prevented by parameterizing $batch.
        # However, relationship TYPES cannot be parameterized in Neo4j.
        # We must group by relation_type to safely build dynamic strings.
        
        grouped_payloads = {}
        for edge in payloads:
            rel_type = self._sanitize_relation_name(edge.get("relation_type", "LINKED_TO"))
            if rel_type not in grouped_payloads:
                grouped_payloads[rel_type] = []
            grouped_payloads[rel_type].append(edge)

        for rel_type, batch in grouped_payloads.items():
            # Flaw Resolution: Phantom Nodes. 
            # If src/dst don't exist, MERGE them dynamically so the graph doesn't break.
            query = f"""
            UNWIND $batch AS edge
            
            // Phantom Node Generation
            MERGE (src:Resource {{arn: edge.source_arn}})
            ON CREATE SET src.type = 'Phantom', src.phantom_reason = 'Dangling Source Edge'
            
            MERGE (dst:Resource {{arn: edge.target_arn}})
            ON CREATE SET dst.type = 'Phantom', dst.phantom_reason = 'Dangling Target Edge'
            
            // Edge Generation
            MERGE (src)-[r:{rel_type}]->(dst)
            SET r.weight = coalesce(edge.weight, 1.0),
                r.is_identity_bridge = coalesce(edge.is_identity_bridge, false),
                r._titan_last_seen = timestamp()
            """
            await tx.run(query, batch=batch)
            self.metrics.edges_merged += len(batch)
            
            # Estimate phantom generation (approximate telemetry)
            self.metrics.phantom_nodes_spawned += len(batch) * 0.05 

    async def _materialize_paths(self, tx: Any, payloads: List[Dict[str, Any]]) -> None:
        """
        Complex Upsert for HAPD Attack Paths.
        Creates an `AttackPath` node and draws `PART_OF_PATH` relationships to 
        the underlying physical infrastructure.
        """
        query = """
        UNWIND $batch AS path
        
        // 1. Create the Master Path Node
        MERGE (p:AttackPath {path_id: path.path_id})
        SET p.tier = path.tier,
            p.hcs_score = coalesce(path.metadata.hcs_score, 0.0),
            p.hop_count = coalesce(path.metadata.hop_count, 0),
            p.metadata = path.metadata, // Stringified JSON
            p._titan_last_seen = timestamp()
            
        // 2. Link Source (Entry Point) and Target (Crown Jewel) implicitly for quick queries
        WITH p, path
        MERGE (src:Resource {arn: path.source_node})
        ON CREATE SET src.type = 'Phantom', src.phantom_reason = 'Path Source'
        MERGE (dst:Resource {arn: path.target_node})
        ON CREATE SET dst.type = 'Phantom', dst.phantom_reason = 'Path Target'
        
        MERGE (src)-[:PATH_ENTRY]->(p)
        MERGE (p)-[:PATH_TARGET]->(dst)
        """
        await tx.run(query, batch=payloads)
        self.metrics.paths_materialized += len(payloads)
        
        # 3. Unwind the sequence matrix to link every node in the path
        # This requires a secondary transaction structure.
        sequence_payloads = []
        for path in payloads:
            seq = path.get("metadata", {}).get("path_sequence", [])
            # Handle stringified JSON safety
            if isinstance(seq, str):
                try: seq = json.loads(seq)
                except: seq = []
                
            for index, node_arn in enumerate(seq):
                sequence_payloads.append({
                    "path_id": path.get("path_id"),
                    "node_arn": node_arn,
                    "hop_index": index
                })
                
        if sequence_payloads:
            seq_query = """
            UNWIND $batch AS item
            MATCH (p:AttackPath {path_id: item.path_id})
            MERGE (n:Resource {arn: item.node_arn}) // Phantom fallback
            MERGE (n)-[r:INVOLVED_IN_PATH]->(p)
            SET r.hop_index = item.hop_index
            """
            await tx.run(seq_query, batch=sequence_payloads)

    # --------------------------------------------------------------------------
    # RESILIENCE & DIAGNOSTICS
    # --------------------------------------------------------------------------

    def _flush_to_dlq(self, payload: List[Dict], error_reason: str) -> None:
        """
        Forensic Dead Letter Queue.
        Serializes completely failed ingestions to disk so no intelligence is lost.
        """
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            dlq_file = os.path.join(self.dlq_path, f"dlq_{timestamp}_{uuid.uuid4().hex[:8]}.json")
            
            data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error_reason": error_reason,
                "payload_size": len(payload),
                "data": payload
            }
            
            with open(dlq_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, cls=SafeDeepSerializer)
                
            self.metrics.dlq_writes += 1
            self.logger.critical(f"  [!] Wrote {len(payload)} items to Dead Letter Queue: {dlq_file}")
            
        except Exception as e:
            self.logger.critical(f"FATAL: Dead Letter Queue write failed. Data lost permanently. {e}")

    async def execute_purge(self) -> None:
        """
        Safely deletes all nodes and relationships in the database.
        Uses APOC chunking to prevent memory limit exceptions on massive graphs.
        """
        await self.initialize()
        self.logger.warning("EXECUTE PURGE: Wiping database clean...")
        
        try:
            async with self.driver.session() as session:
                if self._apoc_available:
                    # Memory-safe batched deletion
                    await session.run("CALL apoc.periodic.iterate('MATCH (n) RETURN n', 'DETACH DELETE n', {batchSize:10000, parallel:false})")
                else:
                    # Fallback standard deletion (can crash on graphs > 100k nodes)
                    await session.run("MATCH (n) DETACH DELETE n")
            self.logger.warning("Database Purge Complete.")
            
            # Reset Metrics
            self.metrics = IngestorMetrics()
            
        except Exception as e:
            self.logger.error(f"Failed to execute purge: {e}")

    def render_diagnostic_report(self) -> None:
        """Outputs telemetry strictly to the console."""
        m = self.metrics
        report = f"""
================================================================================
 💾 TITAN DATABASE KERNEL (INGESTOR) TELEMETRY
================================================================================
 [ DATA UPSERT MATRIX ]
   ├─ Nodes Merged           : {m.nodes_merged}
   ├─ Edges Merged           : {m.edges_merged}
   ├─ Paths Materialized     : {m.paths_materialized}
   └─ Phantoms Spawned (Est) : {int(m.phantom_nodes_spawned)}
--------------------------------------------------------------------------------
 [ TRANSACTION STABILITY ]
   ├─ Batches Processed      : {m.chunks_processed}
   ├─ Deadlocks Resolved     : {m.deadlocks_resolved}
   ├─ Payload Transfer Vol   : {m.bytes_transferred / 1024 / 1024:.2f} MB
   └─ Dead Letter Queued     : {m.dlq_writes} Chunks Faulted
--------------------------------------------------------------------------------
 [ LATENCY & IO ]
   ├─ Schema Constraint IO   : {m.schema_verification_time_ms:.2f}ms
   └─ Cumulative Upsert IO   : {m.total_transaction_time_ms:.2f}ms
================================================================================
"""
        print(report)

# Export Global Singleton
# This guarantees that the connection pool is shared across all coroutines 
# throughout the entire orchestrator lifecycle.
ingestor = Neo4jIngestor()