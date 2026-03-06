import logging
import json
import traceback
from typing import List, Dict, Any

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - IDENTITY FABRIC
# ==============================================================================
# The Cross-Cloud Trust Engine.
# Parses complex IAM Trust Documents, Azure Role Assignments, and OIDC federations
# to materialize implicit privilege escalation pathways as physical Graph Edges.
# ==============================================================================

class IdentityFabric:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Logic.IdentityFabric")
        
        # Edge Weights for HAPD (Heuristic Attack Path Discovery)
        # Lower weight = easier/faster lateral movement path for an attacker
        self.WEIGHT_DIRECT_ASSUME = 1.0
        self.WEIGHT_FEDERATED_TRUST = 1.5
        self.WEIGHT_MANAGED_IDENTITY = 1.2
        self.WEIGHT_IMPLICIT_SERVICE = 2.0

    def calculate_cross_cloud_trusts(self, unified_graph: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        The Master Identity Execution Loop.
        Ingests the physical unified graph and outputs explicit relationship edges.
        """
        self.logger.info("Igniting Cross-Cloud Identity Traversal Matrix...")
        explicit_edges: List[Dict[str, Any]] = []
        
        # 1. Build an O(1) Memory Registry for microsecond ARN lookups
        registry = {node.get("arn") or node.get("metadata", {}).get("arn"): node for node in unified_graph if node.get("type") != "explicit_edge"}
        
        if not registry:
            self.logger.warning("Unified graph is empty. Identity Fabric bypassing.")
            return []

        # 2. Parallel Evaluation Iteration
        for arn, node in registry.items():
            if not arn: continue
            
            node_type = node.get("type", "").lower()
            service = node.get("service", "").lower()
            
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
                    
            except Exception as e:
                self.logger.error(f"Failed to calculate identity matrix for {arn}: {e}")
                self.logger.debug(traceback.format_exc())

        self.logger.info(f"Identity Fabric Complete. Materialized {len(explicit_edges)} Cross-Cloud Trust Edges.")
        return explicit_edges

    # ==========================================================================
    # EDGE GENERATION FACTORY
    # ==========================================================================

    def _generate_edge(self, source_arn: str, target_arn: str, relation: str, weight: float, vector: str) -> Dict[str, Any]:
        """Strictly formats an edge for the Titan Graph Ingestor."""
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
        target_role_arn = role_node.get("metadata", {}).get("arn")
        raw_policy = role_node.get("metadata", {}).get("AssumeRolePolicyDocument")
        
        if not raw_policy or not target_role_arn:
            return edges

        # Defensively handle URL-encoded or stringified JSON policies
        if isinstance(raw_policy, str):
            try:
                import urllib.parse
                decoded = urllib.parse.unquote(raw_policy)
                policy = json.loads(decoded)
            except json.JSONDecodeError:
                self.logger.debug(f"Could not parse stringified policy for {target_role_arn}")
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
                    role_node.setdefault("metadata", {})["baseline_risk_score"] = 10.0
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
        source_arn = ec2_node.get("metadata", {}).get("arn")
        profile = ec2_node.get("metadata", {}).get("IamInstanceProfile", {})
        
        if not profile or not source_arn:
            return edges
            
        profile_arn = profile.get("Arn", "")
        if profile_arn:
            # Note: Instance Profile ARNs are slightly different than Role ARNs, 
            # HAPD will traverse this to find the actual policies attached.
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
        source_arn = vm_node.get("metadata", {}).get("id") or vm_node.get("metadata", {}).get("arn")
        identity = vm_node.get("metadata", {}).get("identity", {})
        
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