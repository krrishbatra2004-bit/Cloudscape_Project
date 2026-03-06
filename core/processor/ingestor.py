import asyncio
import logging
import json
import traceback
import time
import datetime
import uuid
import random
from typing import List, Dict, Any

from neo4j import AsyncGraphDatabase
from neo4j.exceptions import ClientError, AuthError, ServiceUnavailable, TransientError

from core.config import config

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - GRAPH INGESTOR (MATERIALIZATION TIER)
# ==============================================================================
# The Enterprise Database Bridge.
# Handles asynchronous UNWIND batching, Just-In-Time (JIT) payload serialization,
# high-concurrency connection pooling, and strict Kernel Readiness polling with
# Transactional Write-Probing to prevent premature materialization failures.
# ==============================================================================

class _UniversalEncoder(json.JSONEncoder):
    """
    Advanced JSON Encoder for the JIT Flattener.
    Cloud SDKs frequently return complex Python objects (datetime, UUID, bytes) 
    in their raw payload. Standard JSON dumps will crash. This encoder safely 
    standardizes them to strings for Neo4j ingestion.
    """
    def default(self, obj):
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='ignore')
        if isinstance(obj, uuid.UUID):
            return str(obj)
        try:
            return str(obj)
        except Exception:
            return super().default(obj)


class GraphIngestor:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Processor.Ingestor")
        
        # Connection Pooling configuration mapped to Titan 5.0 settings
        self.uri = getattr(config.settings.database, "neo4j_uri", "bolt://127.0.0.1:7687")
        self.user = getattr(config.settings.database, "neo4j_user", "neo4j")
        self.password = getattr(config.settings.database, "neo4j_password", "Cloudscape2026!") # Must match Docker NEO4J_AUTH
        
        try:
            # Optimized connection pool for high-concurrency UNWIND batching
            self.driver = AsyncGraphDatabase.driver(
                self.uri, 
                auth=(self.user, self.password),
                max_connection_lifetime=200,
                max_connection_pool_size=100, # Scaled up to handle massive thread bursts
                connection_timeout=15.0
            )
            self.logger.debug("Cloudscape Graph Database Driver Initialized.")
        except Exception as e:
            self.logger.critical(f"Failed to initialize Neo4j Driver: {e}")
            self.driver = None

    async def close(self):
        """Gracefully tears down the connection pool to prevent memory leaks."""
        if self.driver:
            await self.driver.close()
            self.logger.debug("Cloudscape Graph Database Driver cleanly shut down.")

    async def wait_for_kernel(self, timeout: int = 60) -> bool:
        """
        Transactional Write-Poller (The Ignition Cure).
        Prevents 'Premature Handshake' failures. Reading 'RETURN 1' is insufficient 
        because Neo4j opens the bolt port before the system graph is write-ready.
        This executes a micro-transaction to definitively prove disk availability.
        """
        if not self.driver:
            return False

        self.logger.info("Polling Neo4j Database Kernel for physical write-readiness...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                async with self.driver.session() as session:
                    # Stage 1: Logical Connection Check
                    await session.run("RETURN 1")
                    
                    # Stage 2: Physical Write-Lock Allocation Check
                    probe_query = """
                    MERGE (t:_TitanSystemProbe {id: 'kernel_ignition_test'})
                    SET t.timestamp = timestamp()
                    WITH t
                    DELETE t
                    """
                    await session.run(probe_query)
                    
                self.logger.info("Neo4j Kernel is online, unlocked, and accepting transactions.")
                return True
            except (ServiceUnavailable, TransientError) as e:
                # Catching handshake drops and lock errors during the container boot sequence
                self.logger.debug(f"Kernel warming up... ({str(e).splitlines()[0]})")
                await asyncio.sleep(2)
            except Exception as e:
                self.logger.debug(f"Waiting for kernel initialization: {e}")
                await asyncio.sleep(2)
                
        self.logger.critical("Neo4j Kernel failed to report write-readiness within timeout.")
        return False

    async def validate_schema(self):
        """
        Enforces constraints and indices on the graph to ensure microsecond 
        lookups during the Convergence phase. Shielded by the kernel poller.
        """
        if not self.driver:
            return
            
        # Ensure database is actually capable of processing structural commands
        is_ready = await self.wait_for_kernel()
        if not is_ready:
            raise ServiceUnavailable("Cannot apply schema. Database kernel is unreachable.")
            
        queries = [
            "CREATE CONSTRAINT resource_arn IF NOT EXISTS FOR (n:CloudNode) REQUIRE n.arn IS UNIQUE",
            "CREATE INDEX resource_type_idx IF NOT EXISTS FOR (n:CloudNode) ON (n.resource_type)"
        ]
        
        async with self.driver.session() as session:
            for query in queries:
                try:
                    await session.run(query)
                except AuthError as auth_e:
                    self.logger.critical(f"Neo4j Authentication Lockout: {auth_e.message}. Check your password.")
                    raise
                except ClientError as e:
                    self.logger.warning(f"Schema constraint notice: {e.message}")
                except Exception as e:
                    self.logger.error(f"Failed to apply schema constraint: {e}")

    # ==========================================================================
    # DATA SANITIZATION (THE JIT FLATTENER)
    # ==========================================================================

    def _sanitize_for_graph(self, properties: Dict[str, Any]) -> Dict[str, Any]:
        """
        Neo4j STRICTLY requires primitive types (str, int, float, bool) or flat arrays.
        This method intercepts nested dictionaries (Maps) and complex lists, serializing
        them into JSON strings using the UniversalEncoder to prevent TypeErrors.
        """
        sanitized = {}
        for key, value in properties.items():
            if value is None:
                continue
            
            if isinstance(value, dict):
                # Flatten nested objects into JSON strings using the resilient encoder
                sanitized[key] = json.dumps(value, cls=_UniversalEncoder)
            elif isinstance(value, list):
                # Check if it's a list of strictly accepted primitives
                if all(isinstance(item, (int, float, str, bool)) for item in value):
                    sanitized[key] = value
                else:
                    # Complex lists (like list of dicts) must be serialized
                    sanitized[key] = json.dumps(value, cls=_UniversalEncoder)
            elif isinstance(value, (datetime.datetime, datetime.date)):
                sanitized[key] = value.isoformat()
            else:
                sanitized[key] = value
                
        return sanitized

    # ==========================================================================
    # BATCH MATERIALIZATION (UNWIND)
    # ==========================================================================

    async def process_payloads(self, source: str, payloads: List[Dict[str, Any]]):
        """
        The routing gateway for all ingested data.
        Separates physical nodes from mathematical edges and routes to the correct 
        UNWIND logic. Wrapped in a Jitter-Retry block to survive transient DB locks.
        """
        if not self.driver or not payloads:
            return

        nodes = [p for p in payloads if p.get("type") != "explicit_edge"]
        edges = [p for p in payloads if p.get("type") == "explicit_edge"]

        max_retries = 5
        for attempt in range(max_retries):
            try:
                async with self.driver.session() as session:
                    if nodes:
                        await session.execute_write(self._ingest_nodes_batch, nodes)
                    if edges:
                        await session.execute_write(self._ingest_edges_batch, edges)
                # Successful execution breaks the retry loop
                break
            except (TransientError, ServiceUnavailable) as transient_err:
                if attempt < max_retries - 1:
                    sleep_time = (2 ** attempt) + random.uniform(0.1, 1.0)
                    self.logger.warning(f"Transient Database Lock during materialization. Retrying in {sleep_time:.2f}s... ({transient_err})")
                    await asyncio.sleep(sleep_time)
                else:
                    self.logger.error(f"Catastrophic materialization failure from [{source}] after {max_retries} attempts.")
                    self.logger.debug(traceback.format_exc())
            except Exception as e:
                self.logger.error(f"Fatal Materialization Error from [{source}]: {e}")
                self.logger.debug(traceback.format_exc())
                break

    async def _ingest_nodes_batch(self, tx, nodes: List[Dict[str, Any]]):
        """
        Ingests nodes using high-performance UNWIND.
        Dynamically groups nodes by their specific Cloudscape 'type' so native 
        Neo4j labels can be applied without requiring the APOC plugin.
        """
        # Group by type to allow dynamic Cypher labels (e.g., :Instance, :Bucket)
        grouped_nodes = {}
        for node in nodes:
            # Fallback chains to handle different cloud formats gracefully
            node_type = str(node.get("type", node.get("resource_type", "Unknown"))).replace(" ", "").replace("-", "")
            grouped_nodes.setdefault(node_type, []).append(node)

        for node_type, batch in grouped_nodes.items():
            sanitized_batch = []
            for item in batch:
                # Merge core properties, tags, and metadata into the root for index querying,
                # then push through the JIT flattener to prevent type crashes.
                flat_props = {
                    "arn": item.get("arn"),
                    "name": item.get("name"),
                    "tenant_id": item.get("tenant_id"),
                    "cloud_provider": item.get("cloud_provider"),
                    "service": item.get("category", item.get("service")),
                    "resource_type": node_type,
                    "risk_score": float(item.get("risk_score", 0.0)),
                    "_state_hash": item.get("_state_hash", "UNKNOWN")
                }
                
                # Overlay tags directly onto the root node
                flat_props.update(item.get("tags", {}))
                
                # If raw_data exists, inject its metadata keys into the root
                raw_data = item.get("raw_data", {})
                flat_props.update(raw_data.get("Metadata", {}))
                
                sanitized_batch.append(self._sanitize_for_graph(flat_props))

            # Execute the high-efficiency UNWIND block
            query = f"""
            UNWIND $batch AS row
            MERGE (n:CloudNode {{arn: row.arn}})
            SET n:{node_type}
            SET n += row
            """
            await tx.run(query, batch=sanitized_batch)

    async def _ingest_edges_batch(self, tx, edges: List[Dict[str, Any]]):
        """
        Ingests relationships (Identity Bridges, Attack Paths) using UNWIND.
        """
        # Group by relationship type
        grouped_edges = {}
        for edge in edges:
            rel_type = str(edge.get("relation_type", "RELATED_TO")).upper().replace(" ", "_").replace("-", "_")
            grouped_edges.setdefault(rel_type, []).append(edge)

        for rel_type, batch in grouped_edges.items():
            sanitized_batch = []
            for item in batch:
                props = {"weight": float(item.get("weight", 1.0))}
                props.update(item.get("metadata", {}))
                
                sanitized_batch.append({
                    "source": item.get("source_arn"),
                    "target": item.get("target_arn"),
                    "props": self._sanitize_for_graph(props)
                })

            query = f"""
            UNWIND $batch AS row
            MATCH (s:CloudNode {{arn: row.source}})
            MATCH (t:CloudNode {{arn: row.target}})
            MERGE (s)-[r:{rel_type}]->(t)
            SET r += row.props
            """
            await tx.run(query, batch=sanitized_batch)

# ==============================================================================
# SINGLETON EXPORT
# ==============================================================================
graph_ingestor = GraphIngestor()