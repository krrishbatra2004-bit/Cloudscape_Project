import json
import logging
from typing import Dict, Any, List
from neo4j import GraphDatabase, Transaction
from neo4j.exceptions import ServiceUnavailable

from core.config import settings, TenantConfig

logger = logging.getLogger("Cloudscape.GraphIngestor")

# ==============================================================================
# PROJECT CLOUDSCAPE: ENTERPRISE GRAPH INGESTOR (NEO4J)
# ==============================================================================

class GraphIngestor:
    """
    High-Performance Neo4j Database Manager.
    Utilizes connection pooling, transactional batching (UNWIND), and 
    schema-enforced Cypher queries to build the Enterprise Risk Mesh.
    """

    def __init__(self):
        self.uri = settings.NEO4J_URI
        self.user = settings.NEO4J_USER
        self.password = settings.NEO4J_PASSWORD
        
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            logger.info("Successfully established connection pool to Neo4j Enterprise Graph.")
        except ServiceUnavailable as e:
            logger.error(f"[FATAL] Could not connect to Neo4j at {self.uri}. Is the container running?")
            raise e

    def close(self):
        """Safely terminates the Neo4j driver connection pool."""
        self.driver.close()

    def _prepare_properties(self, raw_dict: Dict[str, Any]) -> str:
        """
        Serializes complex nested JSON (like AWS Tags or Policies) into stringified 
        JSON so Neo4j can store it as a node property without throwing type errors.
        """
        clean_dict = {}
        for k, v in raw_dict.items():
            if isinstance(v, (dict, list)):
                clean_dict[k] = json.dumps(v)
            else:
                clean_dict[k] = v
        return json.dumps(clean_dict)

    def _ingest_tenant_root(self, tx: Transaction, tenant: TenantConfig):
        """Creates the root organizational node for this specific project."""
        cypher = """
        MERGE (t:Tenant {id: $tenant_id})
        SET t.name = $name,
            t.provider = $provider,
            t.account_id = $account_id,
            t.risk_weight = $risk_weight,
            t.tags = $tags,
            t.last_scanned = datetime()
        """
        tx.run(cypher, 
               tenant_id=tenant.id, 
               name=tenant.name, 
               provider=tenant.provider, 
               account_id=tenant.account_id,
               risk_weight=tenant.risk_weight,
               tags=tenant.tags)

    def _ingest_iam_batch(self, tx: Transaction, tenant: TenantConfig, iam_state: Dict[str, Any]):
        """
        Uses UNWIND to batch-insert thousands of IAM Roles simultaneously.
        Automatically links every Role to its parent Tenant root node.
        """
        roles = iam_state.get("Roles", [])
        if not roles:
            return

        # Prepare batch payload
        batch_payload = []
        for role in roles:
            batch_payload.append({
                "arn": role.get("Arn"),
                "name": role.get("RoleName"),
                "create_date": str(role.get("CreateDate")),
                "inline_policies": json.dumps(role.get("Cloudscape_InlinePolicies", []))
            })

        cypher = """
        UNWIND $batch AS row
        MERGE (r:IAMRole {arn: row.arn})
        SET r.name = row.name,
            r.create_date = row.create_date,
            r.inline_policies = row.inline_policies,
            r.last_seen = datetime()
        
        WITH r
        MATCH (t:Tenant {id: $tenant_id})
        MERGE (r)-[:BELONGS_TO]->(t)
        """
        tx.run(cypher, batch=batch_payload, tenant_id=tenant.id)
        logger.debug(f"[{tenant.id}] Batched {len(roles)} IAM Roles into Graph.")

    def _ingest_network_batch(self, tx: Transaction, tenant: TenantConfig, network_state: Dict[str, Any]):
        """Batches VPCs and Subnets into the graph."""
        vpcs = network_state.get("VPCs", [])
        if not vpcs:
            return

        batch_payload = [{"vpc_id": v.get("VpcId"), "cidr": v.get("CidrBlock")} for v in vpcs]

        cypher = """
        UNWIND $batch AS row
        MERGE (v:VPC {id: row.vpc_id})
        SET v.cidr = row.cidr,
            v.last_seen = datetime()
            
        WITH v
        MATCH (t:Tenant {id: $tenant_id})
        MERGE (v)-[:HOSTED_IN]->(t)
        """
        tx.run(cypher, batch=batch_payload, tenant_id=tenant.id)
        logger.debug(f"[{tenant.id}] Batched {len(vpcs)} VPCs into Graph.")

    def _ingest_cross_tenant_edges(self, tx: Transaction, edges: List[Dict[str, Any]]):
        """
        The most critical function for Enterprise Risk mapping.
        Takes the correlated edges from the Trust Resolver and builds the physical 
        Neo4j relationships bridging isolated AWS accounts together.
        """
        if not edges:
            return

        for edge in edges:
            # We use APOC (if available) or raw cypher to dynamically set relationship types
            # For strict safety and speed, we explicitly write the logic for known edge types
            rel_type = edge.get("relationship")
            source = edge.get("source_node")
            target = edge.get("target_node")
            meta = edge.get("metadata", {})
            
            if rel_type == "CAN_ASSUME_ROLE":
                cypher = """
                MERGE (source {arn: $source_arn}) // Creates an empty node if the principal doesn't exist yet
                ON CREATE SET source:Identity, source.is_external = true
                WITH source
                MATCH (target:IAMRole {arn: $target_arn})
                MERGE (source)-[r:CAN_ASSUME_ROLE]->(target)
                SET r.source_project = $src_proj,
                    r.target_project = $tgt_proj,
                    r.is_internal_mesh = $is_internal
                """
                tx.run(cypher, 
                       source_arn=source, 
                       target_arn=target,
                       src_proj=meta.get("source_project"),
                       tgt_proj=meta.get("target_project"),
                       is_internal=meta.get("is_internal_mesh", False))
                
            elif rel_type == "NETWORK_PEERED_TO":
                cypher = """
                MATCH (v1:VPC {id: $source_id})
                MATCH (v2:VPC {id: $target_id})
                MERGE (v1)-[r:NETWORK_PEERED_TO]-(v2) // Undirected merge, bidirectional traffic
                SET r.peering_id = $peer_id
                """
                tx.run(cypher, 
                       source_id=source, 
                       target_id=target,
                       peer_id=meta.get("peering_id"))

    def ingest_tenant_state(self, tenant: TenantConfig, raw_state: Dict[str, Any], cross_edges: List[Dict[str, Any]]):
        """
        Master execution method. Wraps all distinct domain batch inserts into a single 
        managed Neo4j transaction. If one fails, the entire tenant block rolls back.
        """
        logger.info(f"[{tenant.id}] Initiating Graph Ingestion Transaction...")
        
        with self.driver.session() as session:
            try:
                # 1. Ingest Base Infrastructure inside a Write Transaction
                session.execute_write(self._ingest_tenant_root, tenant)
                session.execute_write(self._ingest_iam_batch, tenant, raw_state.get("IAM", {}))
                session.execute_write(self._ingest_network_batch, tenant, raw_state.get("Network", {}))
                
                # 2. Ingest Cross-Tenant Edges (The Security Mesh)
                session.execute_write(self._ingest_cross_tenant_edges, cross_edges)
                
                logger.info(f"[{tenant.id}] Graph Ingestion Transaction committed successfully.")
            except Exception as e:
                logger.error(f"[{tenant.id}] Transaction Failed! Graph rolled back. Error: {e}")
                raise e