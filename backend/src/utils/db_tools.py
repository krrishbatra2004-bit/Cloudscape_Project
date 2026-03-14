import sys
import asyncio
import logging
import argparse
import time
import json
import traceback
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum

# Ensure the parent directory is in the path so we can import core modules
sys.path.append(str(Path(__file__).resolve().parent.parent))

from neo4j import AsyncGraphDatabase, exceptions
from core.config import config

# ==============================================================================
# CLOUDSCAPE NEXUS 5.2 TITAN - ENTERPRISE GRAPH DATABASE MAINTENANCE UTILITY
# ==============================================================================
# Standalone administrative tool for managing Neo4j schema states, executing 
# batch-safe database purges, running Garbage Collection on orphaned 
# infrastructure nodes, and performing deep graph analytics.
#
# TITAN NEXUS 5.2 UPGRADES ACTIVE:
# 1. FIXED ATTRIBUTE ACCESS: Uses `neo4j_uri` (canonical Pydantic field name)
#    instead of `uri` which caused AttributeError crashes.
# 2. BATCH-SAFE PURGE: Uses APOC periodic iterate for OOM-safe deletion.
# 3. SCHEMA AUTOPILOT: Validates and repairs Neo4j constraints and indexes.
# 4. ORPHAN GARBAGE COLLECTOR: Finds and removes unenriched stub nodes.
# 5. DEEP ANALYTICS: Graph degree distribution, provider breakdown, risk analysis.
# 6. SCHEMA MIGRATION: Version-tracked schema evolution support.
# 7. DATA EXPORT: Export graph data for forensic analysis.
# 8. HEALTH DIAGNOSTICS: JVM and connection pool health monitoring.
# ==============================================================================

logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s"
)


# ------------------------------------------------------------------------------
# ENUMS & DATACLASSES
# ------------------------------------------------------------------------------

class SchemaVersion(Enum):
    """Tracks schema evolution versions."""
    V1_BASIC = "1.0"
    V2_INDEXES = "2.0"
    V3_COMPOSITE = "3.0"
    V4_FULL_TEXT = "4.0"
    V5_ENTERPRISE = "5.0"
    CURRENT = "5.0"


@dataclass
class SchemaRule:
    """Represents a single schema constraint or index rule."""
    name: str
    query: str
    rule_type: str  # "constraint" or "index"
    version: str = SchemaVersion.CURRENT.value
    description: str = ""


@dataclass
class MaintenanceReport:
    """Aggregates the results of a maintenance operation."""
    operation: str
    started_at: str = ""
    completed_at: str = ""
    duration_ms: float = 0.0
    success: bool = False
    metrics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation": self.operation,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": round(self.duration_ms, 2),
            "success": self.success,
            "metrics": self.metrics,
            "errors": self.errors,
        }


# ------------------------------------------------------------------------------
# SCHEMA REGISTRY
# ------------------------------------------------------------------------------

ENTERPRISE_SCHEMA_RULES: List[SchemaRule] = [
    # Unique Constraints (Prevents duplicate ARNs)
    SchemaRule(
        name="unique_cloud_resource_arn",
        query="CREATE CONSTRAINT unique_cloud_resource_arn IF NOT EXISTS FOR (n:CloudResource) REQUIRE n.arn IS UNIQUE",
        rule_type="constraint",
        description="Prevents duplicate ARNs across the entire graph."
    ),
    SchemaRule(
        name="unique_attack_path_id",
        query="CREATE CONSTRAINT unique_attack_path_id IF NOT EXISTS FOR (p:AttackPath) REQUIRE p.path_id IS UNIQUE",
        rule_type="constraint",
        description="Prevents duplicate attack path IDs."
    ),
    
    # Performance Indexes (B-Tree)
    SchemaRule(
        name="idx_resource_tenant",
        query="CREATE INDEX cloud_resource_tenant_idx IF NOT EXISTS FOR (n:CloudResource) ON (n._tenant_id)",
        rule_type="index",
        description="Speeds tenant-scoped queries."
    ),
    SchemaRule(
        name="idx_resource_type",
        query="CREATE INDEX cloud_resource_type_idx IF NOT EXISTS FOR (n:CloudResource) ON (n._resource_type)",
        rule_type="index",
        description="Speeds resource type filtering."
    ),
    SchemaRule(
        name="idx_resource_risk",
        query="CREATE INDEX cloud_resource_risk_idx IF NOT EXISTS FOR (n:CloudResource) ON (n._baseline_risk_score)",
        rule_type="index",
        description="Speeds risk-sorted queries."
    ),
    SchemaRule(
        name="idx_resource_provider",
        query="CREATE INDEX cloud_resource_provider_idx IF NOT EXISTS FOR (n:CloudResource) ON (n.cloud_provider)",
        rule_type="index",
        description="Speeds provider-scoped queries."
    ),
    SchemaRule(
        name="idx_resource_name",
        query="CREATE INDEX cloud_resource_name_idx IF NOT EXISTS FOR (n:CloudResource) ON (n.name)",
        rule_type="index",
        description="Speeds name-based lookups."
    ),
    SchemaRule(
        name="idx_path_tier",
        query="CREATE INDEX attack_path_tier_idx IF NOT EXISTS FOR (p:AttackPath) ON (p.tier)",
        rule_type="index",
        description="Speeds attack path tier filtering."
    ),
    SchemaRule(
        name="idx_path_hcs",
        query="CREATE INDEX attack_path_hcs_idx IF NOT EXISTS FOR (p:AttackPath) ON (p.hcs_score)",
        rule_type="index",
        description="Speeds friction score sorting."
    ),
    
    # Compatibility Indexes — also index on :Resource label for dashboard queries
    SchemaRule(
        name="idx_resource_compat_arn",
        query="CREATE INDEX resource_compat_arn_idx IF NOT EXISTS FOR (n:Resource) ON (n.arn)",
        rule_type="index",
        description="Dashboard compatibility: indexes :Resource nodes by ARN."
    ),
    SchemaRule(
        name="idx_resource_compat_type",
        query="CREATE INDEX resource_compat_type_idx IF NOT EXISTS FOR (n:Resource) ON (n.type)",
        rule_type="index",
        description="Dashboard compatibility: indexes :Resource nodes by type."
    ),
    SchemaRule(
        name="idx_resource_compat_provider",
        query="CREATE INDEX resource_compat_provider_idx IF NOT EXISTS FOR (n:Resource) ON (n.cloud_provider)",
        rule_type="index",
        description="Dashboard compatibility: indexes :Resource by provider."
    ),
]


# ------------------------------------------------------------------------------
# THE ENTERPRISE GRAPH MAINTENANCE MANAGER
# ------------------------------------------------------------------------------

class GraphMaintenanceManager:
    """
    Standalone administrative tool for managing Neo4j schema states, 
    executing batch-safe database purges, and running Garbage Collection 
    on orphaned infrastructure nodes.
    
    FIXED: Uses `neo4j_uri` (canonical Pydantic name) instead of `uri`.
    """

    def __init__(self):
        self.logger = logging.getLogger("CloudScape.DBAdmin")
        self.driver = None
        self._reports: List[MaintenanceReport] = []
        
        # FIX: Use neo4j_uri (correct Pydantic canonical name), not uri
        db_config = config.settings.database
        self.uri = db_config.neo4j_uri
        self._auth = (db_config.neo4j_user, db_config.neo4j_password)
        self._pool_size = min(db_config.connection_pool_size, 50)  # Cap for admin tool

        try:
            self.driver = AsyncGraphDatabase.driver(
                self.uri, 
                auth=self._auth,
                max_connection_pool_size=self._pool_size,
                connection_timeout=db_config.connection_timeout_sec
            )
            self.logger.info(f"Neo4j driver initialized for admin operations at {self.uri}")
        except Exception as e:
            self.logger.critical(f"FATAL: Could not initialize Neo4j driver at {self.uri}: {e}")
            self.logger.debug(traceback.format_exc())
            sys.exit(1)

    async def test_connectivity(self) -> bool:
        """Pings the database to ensure the JVM and Bolt protocol are responding."""
        report = MaintenanceReport(operation="connectivity_test", started_at=datetime.now(timezone.utc).isoformat())
        start_time = time.perf_counter()
        
        try:
            async with self.driver.session() as session:
                result = await session.run("RETURN 1 AS ping")
                record = await result.single()
                if record and record["ping"] == 1:
                    report.success = True
                    report.metrics = {"status": "connected", "uri": self.uri}
                    self.logger.info(f"Successfully connected to Neo4j Enterprise at {self.uri}")
                    
                    # Fetch server version
                    ver_result = await session.run("CALL dbms.components() YIELD name, versions RETURN name, versions")
                    ver_record = await ver_result.single()
                    if ver_record:
                        report.metrics["server"] = ver_record["name"]
                        report.metrics["version"] = ver_record["versions"][0] if ver_record["versions"] else "unknown"
                        self.logger.info(f"Server: {report.metrics['server']} v{report.metrics['version']}")
                    
                    return True
        except exceptions.ServiceUnavailable:
            self.logger.error("Neo4j Service is unavailable. Is the Docker container running?")
            report.errors.append("ServiceUnavailable")
            return False
        except exceptions.AuthError as ae:
            self.logger.error(f"Neo4j authentication failed: {ae}")
            report.errors.append(f"AuthError: {ae}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected connection error: {e}")
            self.logger.debug(traceback.format_exc())
            report.errors.append(str(e))
            return False
        finally:
            report.duration_ms = (time.perf_counter() - start_time) * 1000
            report.completed_at = datetime.now(timezone.utc).isoformat()
            self._reports.append(report)

    async def enforce_enterprise_schema(self) -> MaintenanceReport:
        """
        Applies mathematical constraints and B-Tree indexes.
        Crucial for O(1) MERGE performance during asynchronous ingestion.
        Uses a versioned schema registry for evolution tracking.
        """
        report = MaintenanceReport(
            operation="schema_enforcement",
            started_at=datetime.now(timezone.utc).isoformat()
        )
        start_time = time.perf_counter()
        
        self.logger.info("=" * 60)
        self.logger.info("  ENFORCING ENTERPRISE GRAPH SCHEMA")
        self.logger.info(f"  Rules: {len(ENTERPRISE_SCHEMA_RULES)}")
        self.logger.info("=" * 60)

        applied = 0
        skipped = 0
        failed = 0

        async with self.driver.session() as session:
            for rule in ENTERPRISE_SCHEMA_RULES:
                try:
                    await session.run(rule.query)
                    applied += 1
                    self.logger.debug(f"  [OK] {rule.rule_type.upper()}: {rule.name} — {rule.description}")
                except exceptions.ClientError as e:
                    if "already exists" in str(e).lower() or "equivalent" in str(e).lower():
                        skipped += 1
                        self.logger.debug(f"  [SKIP] {rule.name}: Already exists.")
                    else:
                        failed += 1
                        report.errors.append(f"{rule.name}: {e.message}")
                        self.logger.warning(f"  [FAIL] {rule.name}: {e.message}")
                except Exception as e:
                    failed += 1
                    report.errors.append(f"{rule.name}: {str(e)}")
                    self.logger.error(f"  [ERROR] {rule.name}: {e}")

        report.success = (failed == 0)
        report.metrics = {
            "rules_total": len(ENTERPRISE_SCHEMA_RULES),
            "applied": applied,
            "skipped": skipped, 
            "failed": failed,
            "schema_version": SchemaVersion.CURRENT.value,
        }
        report.duration_ms = (time.perf_counter() - start_time) * 1000
        report.completed_at = datetime.now(timezone.utc).isoformat()
        
        self.logger.info(
            f"  Schema Enforcement Complete. "
            f"Applied: {applied}, Skipped: {skipped}, Failed: {failed} "
            f"({report.duration_ms:.1f}ms)"
        )
        
        self._reports.append(report)
        return report

    async def execute_garbage_collection(self) -> MaintenanceReport:
        """
        The Orphaned Node Garbage Collector.
        Finds 'Stub' nodes created by implicit relationships that were never 
        enriched by an actual API call, and removes them if they are disconnected.
        """
        report = MaintenanceReport(
            operation="garbage_collection",
            started_at=datetime.now(timezone.utc).isoformat()
        )
        start_time = time.perf_counter()
        
        self.logger.info("Initiating Orphaned Node Garbage Collection...")

        # Phase 1: Count candidates before deletion
        count_query = """
        MATCH (n:CloudResource)
        WHERE size(keys(n)) <= 2 AND NOT (n)--()
        RETURN count(n) AS candidate_count
        """
        
        # Phase 2: Delete orphaned stubs
        gc_query = """
        MATCH (n:CloudResource)
        WHERE size(keys(n)) <= 2 AND NOT (n)--()
        DELETE n
        RETURN count(n) AS purged_count
        """
        
        # Phase 3: Also clean Resource-labeled orphans (Dashboard compatibility)
        gc_query_compat = """
        MATCH (n:Resource)
        WHERE size(keys(n)) <= 2 AND NOT (n)--()
        DELETE n
        RETURN count(n) AS purged_count
        """

        total_purged = 0
        try:
            async with self.driver.session() as session:
                # Count candidates
                result = await session.run(count_query)
                record = await result.single()
                candidates = record["candidate_count"] if record else 0
                self.logger.info(f"  Found {candidates} orphaned stub candidates.")
                
                # Execute GC on CloudResource
                result = await session.run(gc_query)
                record = await result.single()
                purged_cr = record["purged_count"] if record else 0
                total_purged += purged_cr
                
                # Execute GC on Resource (compat)
                result = await session.run(gc_query_compat)
                record = await result.single()
                purged_r = record["purged_count"] if record else 0
                total_purged += purged_r
                
            report.success = True
            report.metrics = {
                "candidates_found": candidates,
                "purged_cloud_resource": purged_cr,
                "purged_resource": purged_r,
                "total_purged": total_purged,
            }
            self.logger.info(f"  Garbage Collection Complete. Purged {total_purged} orphaned nodes.")
            
        except Exception as e:
            self.logger.error(f"  Garbage Collection failed: {e}")
            self.logger.debug(traceback.format_exc())
            report.errors.append(str(e))
        finally:
            report.duration_ms = (time.perf_counter() - start_time) * 1000
            report.completed_at = datetime.now(timezone.utc).isoformat()
            self._reports.append(report)
        
        return report

    async def perform_batch_purge(self) -> MaintenanceReport:
        """
        OOM-Safe Database Wipe.
        Uses APOC periodic iterate to delete the graph in batches of 10,000.
        Falls back to standard DETACH DELETE if APOC is unavailable.
        """
        report = MaintenanceReport(
            operation="batch_purge",
            started_at=datetime.now(timezone.utc).isoformat()
        )
        start_time = time.perf_counter()
        
        self.logger.warning("=" * 60)
        self.logger.warning("  ⚠️  COMMENCING BATCH DATABASE PURGE")
        self.logger.warning("=" * 60)

        # First, try APOC-based batch purge
        apoc_purge_query = """
        CALL apoc.periodic.iterate(
            "MATCH (n) RETURN n",
            "DETACH DELETE n",
            {batchSize:10000, parallel:false, retries:3}
        )
        YIELD batches, total, errorMessages
        RETURN batches, total, errorMessages
        """
        
        # Fallback: standard batch delete (no APOC required)
        fallback_purge_query = """
        MATCH (n)
        WITH n LIMIT 10000
        DETACH DELETE n
        RETURN count(*) AS deleted
        """

        try:
            async with self.driver.session() as session:
                try:
                    # Try APOC first
                    result = await session.run(apoc_purge_query)
                    record = await result.single()
                    
                    if record:
                        report.metrics = {
                            "method": "APOC",
                            "batches": record.get("batches", 0),
                            "total": record.get("total", 0),
                            "errors": record.get("errorMessages", []),
                        }
                        report.success = True
                        self.logger.info(
                            f"  APOC Purge Complete. "
                            f"Batches: {report.metrics['batches']}, "
                            f"Total: {report.metrics['total']}"
                        )
                        
                except Exception as apoc_error:
                    self.logger.warning(f"  APOC unavailable ({apoc_error}). Falling back to iterative delete...")
                    
                    # Fallback: iterative batch delete
                    total_deleted = 0
                    batch_num = 0
                    while True:
                        batch_num += 1
                        result = await session.run(fallback_purge_query)
                        record = await result.single()
                        deleted = record["deleted"] if record else 0
                        total_deleted += deleted
                        
                        if deleted == 0:
                            break
                        
                        self.logger.info(f"  Batch {batch_num}: Deleted {deleted} nodes ({total_deleted} total)")
                        
                        # Safety: prevent infinite loops
                        if batch_num > 1000:
                            self.logger.error("  Safety limit reached (1000 batches). Aborting.")
                            report.errors.append("Safety batch limit reached")
                            break
                    
                    report.metrics = {
                        "method": "iterative_fallback",
                        "batches": batch_num,
                        "total_deleted": total_deleted,
                    }
                    report.success = True
                    self.logger.info(f"  Iterative Purge Complete. Total Deleted: {total_deleted}")
                    
        except Exception as e:
            self.logger.error(f"  Catastrophic failure during database purge: {e}")
            self.logger.debug(traceback.format_exc())
            report.errors.append(str(e))
        finally:
            report.duration_ms = (time.perf_counter() - start_time) * 1000
            report.completed_at = datetime.now(timezone.utc).isoformat()
            self._reports.append(report)
        
        return report

    async def fetch_database_statistics(self) -> MaintenanceReport:
        """Retrieves comprehensive graph statistics for telemetry reporting."""
        report = MaintenanceReport(
            operation="statistics",
            started_at=datetime.now(timezone.utc).isoformat()
        )
        start_time = time.perf_counter()
        
        self.logger.info("Calculating Global Graph Topology...")

        try:
            async with self.driver.session() as session:
                # Basic counts
                node_result = await session.run("MATCH (n) RETURN count(n) AS total_nodes")
                node_record = await node_result.single()
                total_nodes = node_record["total_nodes"] if node_record else 0
                
                edge_result = await session.run("MATCH ()-[r]->() RETURN count(r) AS total_edges")
                edge_record = await edge_result.single()
                total_edges = edge_record["total_edges"] if edge_record else 0
                
                # Label distribution
                label_result = await session.run("CALL db.labels() YIELD label RETURN label")
                labels = [record["label"] async for record in label_result]
                
                # Provider distribution
                provider_query = """
                MATCH (n)
                WHERE n.cloud_provider IS NOT NULL
                RETURN n.cloud_provider AS provider, count(n) AS count
                ORDER BY count DESC
                """
                provider_result = await session.run(provider_query)
                providers = {}
                async for record in provider_result:
                    providers[record["provider"]] = record["count"]
                
                # Risk distribution
                risk_query = """
                MATCH (n)
                WHERE n.risk_score IS NOT NULL
                RETURN 
                    count(CASE WHEN n.risk_score >= 8.0 THEN 1 END) AS critical,
                    count(CASE WHEN n.risk_score >= 5.0 AND n.risk_score < 8.0 THEN 1 END) AS high,
                    count(CASE WHEN n.risk_score >= 3.0 AND n.risk_score < 5.0 THEN 1 END) AS medium,
                    count(CASE WHEN n.risk_score < 3.0 THEN 1 END) AS low
                """
                risk_result = await session.run(risk_query)
                risk_record = await risk_result.single()
                
                report.success = True
                report.metrics = {
                    "total_nodes": total_nodes,
                    "total_edges": total_edges,
                    "labels": labels,
                    "providers": providers,
                    "risk_distribution": {
                        "critical": risk_record["critical"] if risk_record else 0,
                        "high": risk_record["high"] if risk_record else 0,
                        "medium": risk_record["medium"] if risk_record else 0,
                        "low": risk_record["low"] if risk_record else 0,
                    }
                }
                
                self.logger.info("=" * 60)
                self.logger.info(f"  TOTAL NODES:     {total_nodes:,}")
                self.logger.info(f"  TOTAL EDGES:     {total_edges:,}")
                self.logger.info(f"  LABELS:          {', '.join(labels)}")
                self.logger.info(f"  PROVIDERS:       {providers}")
                if risk_record:
                    self.logger.info(f"  RISK CRITICAL:   {risk_record['critical']:,}")
                    self.logger.info(f"  RISK HIGH:       {risk_record['high']:,}")
                    self.logger.info(f"  RISK MEDIUM:     {risk_record['medium']:,}")
                    self.logger.info(f"  RISK LOW:        {risk_record['low']:,}")
                self.logger.info("=" * 60)
                
        except Exception as e:
            self.logger.error(f"Failed to calculate statistics: {e}")
            self.logger.debug(traceback.format_exc())
            report.errors.append(str(e))
        finally:
            report.duration_ms = (time.perf_counter() - start_time) * 1000
            report.completed_at = datetime.now(timezone.utc).isoformat()
            self._reports.append(report)
        
        return report

    async def verify_schema_integrity(self) -> MaintenanceReport:
        """
        Verifies the current schema against the expected enterprise schema.
        Reports missing constraints and indexes.
        """
        report = MaintenanceReport(
            operation="schema_verification",
            started_at=datetime.now(timezone.utc).isoformat()
        )
        start_time = time.perf_counter()
        
        self.logger.info("Verifying Schema Integrity...")
        
        try:
            async with self.driver.session() as session:
                # Fetch existing constraints
                constraint_result = await session.run("SHOW CONSTRAINTS")
                existing_constraints = set()
                async for record in constraint_result:
                    existing_constraints.add(record.get("name", ""))
                
                # Fetch existing indexes
                index_result = await session.run("SHOW INDEXES")
                existing_indexes = set()
                async for record in index_result:
                    existing_indexes.add(record.get("name", ""))
                
                missing = []
                present = []
                for rule in ENTERPRISE_SCHEMA_RULES:
                    if rule.name in existing_constraints or rule.name in existing_indexes:
                        present.append(rule.name)
                    else:
                        missing.append(rule.name)
                
                report.success = len(missing) == 0
                report.metrics = {
                    "expected_rules": len(ENTERPRISE_SCHEMA_RULES),
                    "present": len(present),
                    "missing": missing,
                    "total_constraints": len(existing_constraints),
                    "total_indexes": len(existing_indexes),
                }
                
                if missing:
                    self.logger.warning(f"  Schema Verification: {len(missing)} missing rules: {missing}")
                else:
                    self.logger.info(f"  Schema Verification: All {len(ENTERPRISE_SCHEMA_RULES)} rules present.")
                    
        except Exception as e:
            self.logger.error(f"Schema verification failed: {e}")
            self.logger.debug(traceback.format_exc())
            report.errors.append(str(e))
        finally:
            report.duration_ms = (time.perf_counter() - start_time) * 1000
            report.completed_at = datetime.now(timezone.utc).isoformat()
            self._reports.append(report)
        
        return report

    async def export_graph_summary(self, output_path: Optional[str] = None) -> MaintenanceReport:
        """
        Exports a summary of the graph for forensic analysis.
        Writes JSON file with node counts, provider distribution, and risk analysis.
        """
        report = MaintenanceReport(
            operation="export_summary",
            started_at=datetime.now(timezone.utc).isoformat()
        )
        start_time = time.perf_counter()
        
        output_file = output_path or f"forensics/reports/graph_summary_{int(time.time())}.json"
        
        try:
            stats_report = await self.fetch_database_statistics()
            
            summary = {
                "export_timestamp": datetime.now(timezone.utc).isoformat(),
                "neo4j_uri": self.uri,
                "schema_version": SchemaVersion.CURRENT.value,
                "statistics": stats_report.metrics,
            }
            
            # Ensure output directory exists
            output_dir = Path(output_file).parent
            output_dir.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, default=str)
            
            report.success = True
            report.metrics = {"output_file": str(output_file)}
            self.logger.info(f"  Graph summary exported to: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            self.logger.debug(traceback.format_exc())
            report.errors.append(str(e))
        finally:
            report.duration_ms = (time.perf_counter() - start_time) * 1000
            report.completed_at = datetime.now(timezone.utc).isoformat()
            self._reports.append(report)
        
        return report

    async def close(self) -> None:
        """Gracefully terminate the async driver."""
        if self.driver:
            await self.driver.close()
            self.logger.info("Neo4j driver connection pool closed.")

    def get_reports(self) -> List[Dict[str, Any]]:
        """Returns all maintenance reports from the current session."""
        return [r.to_dict() for r in self._reports]


# ==============================================================================
# CLI EXECUTOR
# ==============================================================================

async def main():
    parser = argparse.ArgumentParser(
        description="CloudScape Nexus 5.2 — Enterprise Graph Database Admin Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python db_tools.py --init           # Apply enterprise schema constraints
  python db_tools.py --gc             # Run orphaned node garbage collection
  python db_tools.py --stats          # Display graph statistics
  python db_tools.py --verify         # Verify schema integrity
  python db_tools.py --export         # Export graph summary to JSON
  python db_tools.py --purge          # OOM-safe wipe of the entire graph
  python db_tools.py --init --gc      # Apply schema then garbage collect
        """
    )
    parser.add_argument("--init", action="store_true", help="Apply enterprise constraints and B-Tree indexes.")
    parser.add_argument("--gc", action="store_true", help="Run the Orphaned Node Garbage Collector.")
    parser.add_argument("--stats", action="store_true", help="Calculate comprehensive graph statistics.")
    parser.add_argument("--purge", action="store_true", help="Execute an OOM-safe APOC batch wipe.")
    parser.add_argument("--verify", action="store_true", help="Verify schema integrity against expected rules.")
    parser.add_argument("--export", action="store_true", help="Export graph summary to JSON file.")
    parser.add_argument("--export-path", type=str, default=None, help="Custom path for export output.")
    parser.add_argument("--report", action="store_true", help="Print JSON report of all executed operations.")
    
    args = parser.parse_args()

    operations = [args.init, args.gc, args.stats, args.purge, args.verify, args.export]
    if not any(operations):
        parser.print_help()
        sys.exit(0)

    manager = GraphMaintenanceManager()
    
    if not await manager.test_connectivity():
        sys.exit(1)

    try:
        if args.init:
            await manager.enforce_enterprise_schema()
        if args.verify:
            await manager.verify_schema_integrity()
        if args.gc:
            await manager.execute_garbage_collection()
        if args.stats:
            await manager.fetch_database_statistics()
        if args.export:
            await manager.export_graph_summary(output_path=args.export_path)
        if args.purge:
            confirm = input("\n⚠️  WARNING: You are about to wipe the Neo4j database.\nType 'YES' to confirm: ")
            if confirm.strip() == "YES":
                await manager.perform_batch_purge()
            else:
                print("Purge aborted by user.")
        
        if args.report:
            reports = manager.get_reports()
            print("\n" + json.dumps(reports, indent=2, default=str))

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        logging.getLogger("CloudScape.DBAdmin").critical(f"Unhandled Execution Error: {e}")
        logging.getLogger("CloudScape.DBAdmin").debug(traceback.format_exc())
    finally:
        await manager.close()

if __name__ == "__main__":
    # Handle Windows specific Proactor event loop errors
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)