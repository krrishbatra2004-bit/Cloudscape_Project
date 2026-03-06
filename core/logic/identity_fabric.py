import logging
import json
import urllib.parse
import traceback
from typing import List, Dict, Any

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - IDENTITY FABRIC
# ==============================================================================
# The Cross-Cloud Trust Engine.
# Parses complex IAM Trust Documents, Azure Role Assignments, OIDC federations,
# and Storage Metadata secrets to materialize implicit privilege escalation 
# pathways and cross-cloud bridges as physical Graph Edges.
# ==============================================================================

class IdentityFabric:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Logic.IdentityFabric")
        
        # Edge Weights for HAPD (Heuristic Attack Path Discovery)
        # Lower weight = easier/faster lateral movement path for an attacker
        self.WEIGHT_DIRECT_ASSUME = 1.0
        self.WEIGHT_MANAGED_IDENTITY = 1.2
        self.WEIGHT_FEDERATED_TRUST = 1.5
        self.WEIGHT_IMPLICIT_SERVICE = 2.0
        self.WEIGHT_CROSS_CLOUD_LEAK = 0.5  # Critical priority bypass route

    def calculate_cross_cloud_trusts(self, unified_graph: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        The Master Identity Execution Loop.
        Ingests the physical unified graph, analyzes Universal Resource Models (URM),
        and outputs explicit directional relationship edges.
        """
        self.logger.info("Igniting Cross-Cloud Identity Traversal Matrix...")
        explicit_edges: List[Dict[str, Any]] = []
        
        # 1. Build an O(1) Memory Registry for microsecond ARN lookups
        # Strictly binds to the 'arn' root key established by the BaseEngine URM
        registry = {node.get("arn"): node for node in unified_graph if node.get("type") != "explicit_edge" and node.get("arn")}
        
        if not registry:
            self.logger.warning("Unified graph is empty. Identity Fabric bypassing.")
            return []

        # 2. Parallel Evaluation Iteration
        for arn, node in registry.items():
            node_type = str(node.get("type", "")).lower()
            service = str(node.get("service", "")).lower()
            
            try:
                # --- AWS IDENTITY ANALYSIS ---
                if service == "iam" and node_type == "role":
                    edges = self._parse_aws_trust_policy(node, registry)
                    explicit_edges.extend(edges)
                    
                elif service == "ec2" and node_type == "instance":
                    edges = self._parse_aws_instance_profiles(node, registry)
                    explicit_edges.extend(edges)

                # --- AZURE IDENTITY ANALYSIS ---
                elif service == "compute" and node_type == "virtualmachine":
                    edges = self._parse_azure_managed_identities(node, registry)
                    explicit_edges.extend(edges)
                    
                # --- CROSS-CLOUD DATA PLANE ANALYSIS ---
                elif node_type in ["bucket", "storageblob", "storagecontainer"]:
                    edges = self._parse_cross_cloud_storage_metadata(node, registry)
                    explicit_edges.extend(edges)
                    
            except Exception as e:
                self.logger.error(f"Failed to calculate identity matrix for {arn}: {e}")
                self.logger.debug(traceback.format_exc())

        self.logger.info(f"Identity Fabric Complete. Materialized {len(explicit_edges)} Cross-Cloud Trust Edges.")
        return explicit_edges

    # ==========================================================================
    # EDGE GENERATION FACTORY
    # ==========================================================================

    def _generate_edge(self, source_arn: str, target_arn: str, relation: str, weight: float, vector: str) -> Dict[str, Any]:
        """Strictly formats an edge for the Titan Graph Ingestor UNWIND schema."""
        return {
            "type": "explicit_edge",
            "source_arn": source_arn,
            "target_arn": target_arn,
            "relation_type": relation,
            "weight": weight,
            "metadata": {
                "vector": vector,
                "discovery_engine": "IdentityFabric",
                "inferred": True
            }
        }

    # ==========================================================================
    # AWS PRIVILEGE ESCALATION LOGIC
    # ==========================================================================

    def _parse_aws_trust_policy(self, role_node: Dict[str, Any], registry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Deep-parses the AssumeRolePolicyDocument (The Trust Policy) of an AWS IAM Role.
        Identifies exact Principals (Services, Accounts, Federated OIDC) capable of assuming it.
        """
        edges = []
        target_role_arn = role_node.get("arn")
        raw_data = role_node.get("raw_data", {})
        raw_policy = raw_data.get("AssumeRolePolicyDocument")
        
        if not raw_policy or not target_role_arn:
            return edges

        # Defensively handle URL-encoded or stringified JSON policies returned by LocalStack
        if isinstance(raw_policy, str):
            try:
                decoded = urllib.parse.unquote(raw_policy)
                policy = json.loads(decoded)
            except json.JSONDecodeError:
                self.logger.debug(f"Could not parse stringified trust policy for {target_role_arn}")
                return edges
        else:
            policy = raw_policy

        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
                
            action = stmt.get("Action", "")
            if "sts:AssumeRole" not in action and "sts:AssumeRoleWithWebIdentity" not in action and "sts:AssumeRoleWithSAML" not in action:
                continue

            principals = stmt.get("Principal", {})
            if isinstance(principals, str):
                principals = {"AWS": principals} # Edge case normalization

            # 1. Map Explicit AWS Account / Role Principals
            aws_principals = principals.get("AWS", [])
            if isinstance(aws_principals, str): aws_principals = [aws_principals]
            
            for p in aws_principals:
                if p == "*":
                    # Critical Vulnerability: Globally assumable role
                    role_node.setdefault("tags", {})["Exposure"] = "Public"
                    role_node["risk_score"] = 1.0  # Maximize root risk score for URM
                elif isinstance(p, str) and "arn:aws:iam" in p:
                    edges.append(self._generate_edge(
                        source_arn=p, 
                        target_arn=target_role_arn, 
                        relation="CAN_ASSUME_ROLE", 
                        weight=self.WEIGHT_DIRECT_ASSUME, 
                        vector="Intra-Cloud-Trust"
                    ))

            # 2. Map Service Principals (e.g., ec2.amazonaws.com)
            svc_principals = principals.get("Service", [])
            if isinstance(svc_principals, str): svc_principals = [svc_principals]
            
            for svc in svc_principals:
                edges.append(self._generate_edge(
                    source_arn=f"aws:service:{svc}", 
                    target_arn=target_role_arn, 
                    relation="TRUSTS_SERVICE", 
                    weight=self.WEIGHT_IMPLICIT_SERVICE, 
                    vector="Service-Trust"
                ))

            # 3. Map Federated / OIDC Principals (The Cross-Cloud Shadow Bridge)
            fed_principals = principals.get("Federated", [])
            if isinstance(fed_principals, str): fed_principals = [fed_principals]
            
            for fed in fed_principals:
                edges.append(self._generate_edge(
                    source_arn=fed, # Often an OIDC URL like oidc.eks.region.amazonaws.com or graph.windows.net
                    target_arn=target_role_arn, 
                    relation="FEDERATED_TRUST", 
                    weight=self.WEIGHT_FEDERATED_TRUST, 
                    vector="Cross-Cloud-OIDC"
                ))

        return edges

    def _parse_aws_instance_profiles(self, ec2_node: Dict[str, Any], registry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Maps an EC2 instance directly to its IAM Role via the Instance Profile."""
        edges = []
        source_arn = ec2_node.get("arn")
        raw_data = ec2_node.get("raw_data", {})
        profile = raw_data.get("IamInstanceProfile", {})
        
        if not profile or not source_arn:
            return edges
            
        profile_arn = profile.get("Arn", "")
        if profile_arn:
            # Note: Instance Profile ARNs differ slightly from Role ARNs, 
            # NetworkX will traverse this gap during HAPD graph construction.
            edges.append(self._generate_edge(
                source_arn=source_arn,
                target_arn=profile_arn,
                relation="HAS_INSTANCE_PROFILE",
                weight=self.WEIGHT_DIRECT_ASSUME,
                vector="Compute-Identity"
            ))
            
        return edges

    # ==========================================================================
    # AZURE PRIVILEGE ESCALATION LOGIC
    # ==========================================================================

    def _parse_azure_managed_identities(self, vm_node: Dict[str, Any], registry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extracts SystemAssigned and UserAssigned Managed Identities from Azure Virtual Machines.
        Creates lateral movement edges from Compute to Identity.
        """
        edges = []
        source_arn = vm_node.get("arn")
        raw_data = vm_node.get("raw_data", {})
        identity = raw_data.get("identity", {})
        
        if not identity or not source_arn:
            return edges
            
        id_type = identity.get("type", "")
        
        # 1. System Assigned (Tied directly to the VM lifecycle)
        if "SystemAssigned" in id_type:
            principal_id = identity.get("principal_id")
            if principal_id:
                # We create a virtual "Principal" node ARN for the graph
                target_arn = f"azure:managed-identity:system/{principal_id}"
                edges.append(self._generate_edge(
                    source_arn=source_arn,
                    target_arn=target_arn,
                    relation="HAS_MANAGED_IDENTITY",
                    weight=self.WEIGHT_MANAGED_IDENTITY,
                    vector="System-Assigned-Trust"
                ))
                
        # 2. User Assigned (Shared identities attached to the VM)
        if "UserAssigned" in id_type:
            user_ids = identity.get("user_assigned_identities", {})
            for uid_arn, _ in user_ids.items():
                edges.append(self._generate_edge(
                    source_arn=source_arn,
                    target_arn=uid_arn,
                    relation="ASSUMES_USER_IDENTITY",
                    weight=self.WEIGHT_MANAGED_IDENTITY,
                    vector="User-Assigned-Trust"
                ))

        return edges

    # ==========================================================================
    # CROSS-CLOUD FEDERATION (THE HYBRID BRIDGE)
    # ==========================================================================

    def _parse_cross_cloud_storage_metadata(self, storage_node: Dict[str, Any], registry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        The true Hybrid Mesh linkage. 
        Actively inspects the URM metadata of Azure Blobs and S3 Buckets for 
        simulated or leaked cross-cloud credentials, drawing explicit bridges.
        """
        edges = []
        source_arn = storage_node.get("arn")
        raw_data = storage_node.get("raw_data", {})
        metadata = raw_data.get("Metadata", {})
        
        if not metadata or not source_arn:
            return edges

        # Ensure dictionary operations are case-insensitive for metadata keys
        clean_meta = {str(k).lower(): str(v) for k, v in metadata.items()}

        # 1. Detect AWS Keys residing in Azure Storage
        aws_key = clean_meta.get("aws_access_key_id") or clean_meta.get("x-amz-meta-aws_access_key_id")
        if aws_key:
            target_arn = f"arn:aws:iam::metadata_leak:access_key/{aws_key}"
            edges.append(self._generate_edge(
                source_arn=source_arn,
                target_arn=target_arn,
                relation="CONTAINS_CREDENTIAL",
                weight=self.WEIGHT_CROSS_CLOUD_LEAK,
                vector="Azure-to-AWS-Leak"
            ))
            # Escalate the source storage node risk
            storage_node["risk_score"] = 1.0
            storage_node.setdefault("tags", {})["DataClassification"] = "CompromisedSecret"

        # 2. Detect Azure Tenant/Client Secrets residing in AWS S3
        azure_secret = clean_meta.get("azure_tenant_id") or clean_meta.get("azure_client_secret")
        if azure_secret:
            target_arn = f"azure:active-directory:tenant/{azure_secret}"
            edges.append(self._generate_edge(
                source_arn=source_arn,
                target_arn=target_arn,
                relation="CONTAINS_CREDENTIAL",
                weight=self.WEIGHT_CROSS_CLOUD_LEAK,
                vector="AWS-to-Azure-Leak"
            ))
            # Escalate the source storage node risk
            storage_node["risk_score"] = 1.0
            storage_node.setdefault("tags", {})["DataClassification"] = "CompromisedSecret"

        return edges