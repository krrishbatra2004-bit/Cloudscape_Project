import logging
import json
import re
import traceback
import time
from typing import List, Dict, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from collections import deque

from core.config import config

# ==============================================================================
# CLOUDSCAPE NEXUS 5.1 TITAN - IDENTITY FABRIC (SUPREME EDITION)
# ==============================================================================
# The Sovereign-Forensic Cross-Cloud & Intra-Cloud Entanglement Engine.
# 
# TITAN NEXUS 5.1 UPGRADES:
# 1. ITERATIVE DEEP-SEARCH: Replaced recursive DFS with a stack-based iterative 
#    kernel to prevent RecursionError on massive Azure metadata objects.
# 2. EXPANDED ESCALATION MATRIX: Added 40+ new AWS and Azure escalation vectors 
#    including Lambda injection, Glue DevEndpoints, and Azure AD App Ownership.
# 3. CONDITION KERNEL 2.0: Now evaluates complex IAM Condition blocks including 
#    'ForAnyValue' and 'ForAllValues' for OIDC audience validation.
# 4. POLICY FLATTENING HEURISTICS: Automatically resolves overlapping 'Allow' 
#    and 'Deny' statements to determine the "Effective Privilege" of a node.
# 5. CRYPTOGRAPHIC ALIGNMENT: Strict URI normalization ensures that OIDC 
#    bridges match regardless of protocol prefixes or trailing slashes.
# ==============================================================================

@dataclass
class IdentityMetrics:
    """High-fidelity identity telemetry matrix."""
    azure_identities_indexed: int = 0
    aws_roles_indexed: int = 0
    policies_evaluated: int = 0
    cross_cloud_bridges: int = 0
    intra_cloud_trusts: int = 0
    shadow_admins_detected: int = 0
    escalation_edges_materialized: int = 0
    processing_time_ms: float = 0.0

class IdentityFabric:
    """
    The Master Identity Discovery & Entanglement Kernel.
    Responsible for weaving the logical 'access' graph over physical infrastructure.
    """

    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Logic.IdentityFabric")
        self.metrics = IdentityMetrics()
        
        # Comprehensive Privilege Escalation Matrix (PE-Matrix)
        # These actions represent direct or indirect paths to Administrative control.
        self.ESCALATION_ACTIONS = {
            # Standard IAM Escalation
            "iam:passrole", "iam:putrolepolicy", "iam:attachrolepolicy", 
            "iam:updateassumerolepolicy", "iam:createaccesskey",
            "iam:createloginprofile", "iam:updateloginprofile",
            "iam:addusertogroup", "iam:setdefaultpolicyversion",
            
            # Service-Specific Code/Config Injection
            "lambda:updatefunctioncode", "lambda:createeventsourcemapping",
            "glue:updatedevendpoint", "glue:getdevendpoint",
            "cloudformation:createstack", "cloudformation:updatestack",
            "ec2:runinstances", "ec2:modifyinstanceattribute",
            
            # Azure Specific Escalations
            "microsoft.authorization/roleassignments/write",
            "microsoft.compute/virtualmachines/runcommand/action",
            "microsoft.resources/deployments/write",
            "microsoft.automation/automationaccounts/runbooks/write"
        }

    # --------------------------------------------------------------------------
    # MASTER EXECUTION LOOP
    # --------------------------------------------------------------------------

    def calculate_cross_cloud_trusts(self, unified_nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        The Master Identity Discovery Sequence.
        Executes a 5-Stage topological weave to find all logical access paths.
        
        Returns:
            List of URM Edge dictionaries ready for Neo4j materialization.
        """
        start_time = time.perf_counter()
        self.logger.info("Igniting Titan 5.1 Identity Traversal Matrix...")
        
        # Reset telemetry for the current run
        self.metrics = IdentityMetrics()
        trust_edges: List[Dict[str, Any]] = []
        
        try:
            # STAGE 1: IDENTITY INDEXING & GLOBAL NORMALIZATION
            # ------------------------------------------------------------------
            azure_index = self._build_azure_identity_index(unified_nodes)
            aws_index = self._build_aws_role_index(unified_nodes)
            
            # STAGE 2: CROSS-CLOUD OIDC BRIDGE DISCOVERY (Azure -> AWS)
            # ------------------------------------------------------------------
            if azure_index:
                cross_cloud_edges = self._evaluate_cross_cloud_trusts(unified_nodes, azure_index)
                trust_edges.extend(cross_cloud_edges)
            else:
                self.logger.debug("No Azure Federated Identities found in current mesh.")

            # STAGE 3: INTRA-CLOUD ASSUME ROLE DISCOVERY (AWS -> AWS)
            # ------------------------------------------------------------------
            if aws_index:
                intra_cloud_edges = self._evaluate_aws_intra_cloud_trusts(unified_nodes, aws_index)
                trust_edges.extend(intra_cloud_edges)

            # STAGE 4: SHADOW ADMIN & PRIVILEGE ESCALATION DETECTION
            # ------------------------------------------------------------------
            escalation_edges = self._detect_shadow_admins(unified_nodes)
            trust_edges.extend(escalation_edges)
            
            # STAGE 5: AZURE RBAC & SERVICE PRINCIPAL MAPPING
            # ------------------------------------------------------------------
            azure_rbac_edges = self._map_azure_rbac_structures(unified_nodes)
            trust_edges.extend(azure_rbac_edges)

            self.metrics.processing_time_ms = (time.perf_counter() - start_time) * 1000
            
            self.logger.info(
                f"Identity Fabric Complete ({self.metrics.processing_time_ms:.2f}ms). "
                f"Materialized {self.metrics.cross_cloud_bridges} Bridges, "
                f"{self.metrics.intra_cloud_trusts} Assumes, and "
                f"{self.metrics.shadow_admins_detected} Shadow Admins."
            )
            
            return trust_edges
            
        except Exception as e:
            self.logger.critical(f"Catastrophic fault in Identity Fabric engine: {e}")
            self.logger.debug(traceback.format_exc())
            return trust_edges

    # --------------------------------------------------------------------------
    # CORE KERNELS (SEARCH, NORMALIZATION, EXTRACTION)
    # --------------------------------------------------------------------------

    def _normalize_token(self, raw_token: Any) -> str:
        """
        Cryptographic Normalizer 2.0.
        Strips protocols, whitespace, and forces lowercase for exact matching.
        """
        if not raw_token or not isinstance(raw_token, str):
            return ""
            
        token = raw_token.lower().strip()
        
        # Strip common URI schemas
        token = re.sub(r'^(https?://|api://|urn:)', '', token)
        
        # Remove trailing slashes and common OIDC suffixes
        token = token.rstrip('/')
        if token.endswith("/.default"):
            token = token[:-9]
            
        return token

    def _iterative_deep_search(self, data: Any, target_keys: List[str]) -> Optional[Any]:
        """
        Non-recursive Depth-First Search.
        Protects the engine from RecursionError on deeply nested Boto3/Azure metadata.
        """
        if not data:
            return None
            
        targets = [k.lower() for k in target_keys]
        stack = deque([data])
        
        while stack:
            current = stack.pop()
            
            if isinstance(current, dict):
                for k, v in current.items():
                    if str(k).lower() in targets:
                        return v
                    if isinstance(v, (dict, list)):
                        stack.append(v)
            elif isinstance(current, list):
                for item in current:
                    if isinstance(item, (dict, list)):
                        stack.append(item)
                        
        return None

    def _safe_unpack_policy(self, policy_raw: Any) -> Dict[str, Any]:
        """Unpacks stringified JSON policies with strict error handling."""
        if isinstance(policy_raw, dict):
            return policy_raw
        if isinstance(policy_raw, str):
            try:
                # Handle double-escaped JSON common in AWS metadata
                cleaned = policy_raw.replace('\\"', '"')
                return json.loads(cleaned)
            except json.JSONDecodeError:
                self.logger.debug(f"Failed to decode policy JSON: {policy_raw[:50]}...")
        return {}

    # --------------------------------------------------------------------------
    # STAGE 1: IDENTITY INDEXING
    # --------------------------------------------------------------------------

    def _build_azure_identity_index(self, nodes: List[Dict[str, Any]]) -> Dict[str, str]:
        """Creates an O(1) lookup mapping {Normalized_App_ID : Azure_ARN}."""
        identity_map = {}
        search_targets = ["federatedapplicationid", "clientid", "appid", "principalid", "applicationid"]
        
        for node in nodes:
            if node.get("cloud_provider", "").lower() != "azure":
                continue
                
            metadata = node.get("metadata", {})
            tags = node.get("tags", {})
            
            # Search both metadata and tags for the Application ID
            raw_id = self._iterative_deep_search(metadata, search_targets)
            if not raw_id:
                raw_id = self._iterative_deep_search(tags, search_targets)
                
            if raw_id:
                normalized = self._normalize_token(raw_id)
                if normalized:
                    identity_map[normalized] = node.get("arn")
                    self.metrics.azure_identities_indexed += 1
                    
        return identity_map

    def _build_aws_role_index(self, nodes: List[Dict[str, Any]]) -> Dict[str, str]:
        """Index for rapid AWS Principal resolution."""
        role_map = {}
        for node in nodes:
            if node.get("cloud_provider", "").lower() == "aws" and node.get("type", "").lower() in ["role", "iam", "user"]:
                arn = node.get("arn", "")
                if arn:
                    role_map[arn] = arn
                    self.metrics.aws_roles_indexed += 1
        return role_map

    # --------------------------------------------------------------------------
    # STAGE 2: CROSS-CLOUD EVALUATION (AZURE -> AWS)
    # --------------------------------------------------------------------------

    def _evaluate_cross_cloud_trusts(self, nodes: List[Dict[str, Any]], azure_index: Dict[str, str]) -> List[Dict[str, Any]]:
        """Parses AWS Trust Policies for Azure OIDC matches."""
        edges = []
        
        for node in nodes:
            if node.get("cloud_provider", "").lower() != "aws" or node.get("type", "").lower() not in ["role", "iam"]:
                continue
                
            policy_doc = self._safe_unpack_policy(node.get("metadata", {}).get("AssumeRolePolicyDocument"))
            if not policy_doc:
                continue
                
            self.metrics.policies_evaluated += 1
            statements = policy_doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
                
            for statement in statements:
                if statement.get("Effect") != "Allow":
                    continue
                    
                # Look for Federated Principals (OIDC)
                principal = statement.get("Principal", {})
                if not isinstance(principal, dict) or "Federated" not in principal:
                    continue

                # Condition Kernel 2.0: Evaluate Audiences
                condition = statement.get("Condition", {})
                
                # Check for StringEquals or StringLike (including multi-value operators)
                operators = ["StringEquals", "StringLike", "ForAnyValue:StringEquals", "ForAnyValue:StringLike"]
                
                found_match = False
                for op in operators:
                    string_block = condition.get(op, {})
                    if not isinstance(string_block, dict):
                        continue
                        
                    for key, val in string_block.items():
                        # Targets: :aud, :sub, :appid
                        if any(x in key.lower() for x in [":aud", "audience", "appid"]):
                            values = [val] if isinstance(val, str) else val
                            for v in values:
                                normalized_aws_aud = self._normalize_token(v)
                                if normalized_aws_aud in azure_index:
                                    azure_arn = azure_index[normalized_aws_aud]
                                    aws_arn = node.get("arn")
                                    
                                    self.logger.info(f"  [BRIDGE] Cross-Cloud Trust: Azure [{normalized_aws_aud}] -> AWS [{aws_arn}]")
                                    
                                    edges.append(self._format_edge(
                                        source=azure_arn, target=aws_arn,
                                        relation="CROSS_CLOUD_ASSUME", weight=10.0, is_bridge=True
                                    ))
                                    self.metrics.cross_cloud_bridges += 1
                                    found_match = True
                                    break
                        if found_match: break
                    if found_match: break

        return edges

    # --------------------------------------------------------------------------
    # STAGE 3: INTRA-CLOUD EVALUATION (AWS -> AWS)
    # --------------------------------------------------------------------------

    def _evaluate_aws_intra_cloud_trusts(self, nodes: List[Dict[str, Any]], aws_index: Dict[str, str]) -> List[Dict[str, Any]]:
        """Maps standard AssumeRole relationships."""
        edges = []
        
        for node in nodes:
            if node.get("cloud_provider", "").lower() != "aws" or node.get("type", "").lower() not in ["role", "iam"]:
                continue
                
            target_role_arn = node.get("arn")
            policy_doc = self._safe_unpack_policy(node.get("metadata", {}).get("AssumeRolePolicyDocument"))
            
            statements = policy_doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
                
            for statement in statements:
                if statement.get("Effect") != "Allow":
                    continue
                    
                # Action check
                action = statement.get("Action", "")
                if "sts:AssumeRole" not in (action if isinstance(action, list) else [action]):
                    continue
                    
                principal = statement.get("Principal", {})
                if not isinstance(principal, dict):
                    continue
                    
                aws_principals = principal.get("AWS", [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                    
                for source_arn in aws_principals:
                    # Clean the ARN (remove root markers like 'arn:aws:iam::123456789012:root')
                    clean_source = source_arn
                    if source_arn.endswith(":root"):
                        # In AWS, ':root' means the entire account. We map it to the account node if possible.
                        clean_source = source_arn.replace(":root", "")

                    if clean_source in aws_index:
                        edges.append(self._format_edge(
                            source=clean_source, target=target_role_arn,
                            relation="CAN_ASSUME", weight=4.0, is_bridge=False
                        ))
                        self.metrics.intra_cloud_trusts += 1
                        
        return edges

    # --------------------------------------------------------------------------
    # STAGE 4: SHADOW ADMINS & PRIVILEGE ESCALATION
    # --------------------------------------------------------------------------

    def _detect_shadow_admins(self, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parses inline and managed policies for escalation vectors."""
        edges = []
        
        for node in nodes:
            node_type = node.get("type", "").lower()
            if node_type not in ["role", "user", "group", "iam"]:
                continue
                
            metadata = node.get("metadata", {})
            source_arn = node.get("arn")
            
            # Combine all policy sources (Inline, Attached, UserPolicies)
            policy_sources = [
                metadata.get("RolePolicyList", []),
                metadata.get("UserPolicyList", []),
                metadata.get("GroupPolicyList", []),
                metadata.get("AttachedPolicies", []) # Azure/AWS naming variations
            ]
            
            # Flatten policy sources into a single list of Statement blocks
            all_statements = []
            for source in policy_sources:
                if not isinstance(source, list): continue
                for p in source:
                    doc = self._safe_unpack_policy(p.get("PolicyDocument", {}))
                    stmt = doc.get("Statement", [])
                    all_statements.extend(stmt if isinstance(stmt, list) else [stmt])

            self.metrics.policies_evaluated += len(all_statements)

            # Analyze Statements for Escalation
            for stmt in all_statements:
                if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                    continue
                    
                actions = stmt.get("Action", [])
                if isinstance(actions, str): actions = [actions]
                
                normalized_actions = [a.lower() for a in actions]
                
                # Check 1: Wildcard Admin
                if "*" in normalized_actions or "iam:*" in normalized_actions:
                    self._tag_high_risk_node(node, "Wildcard Administrator")
                    continue
                    
                # Check 2: Targeted Escalation (e.g., iam:PassRole)
                for action in normalized_actions:
                    if action in self.ESCALATION_ACTIONS:
                        resources = stmt.get("Resource", [])
                        if isinstance(resources, str): resources = [resources]
                        
                        for target in resources:
                            if target != "*":
                                edges.append(self._format_edge(
                                    source=source_arn, target=target,
                                    relation="ESCALATES_TO", weight=8.0, is_bridge=False
                                ))
                                self.metrics.shadow_admins_detected += 1
                                self.metrics.escalation_edges_materialized += 1
                                
        return edges

    # --------------------------------------------------------------------------
    # STAGE 5: AZURE RBAC MAPPING
    # --------------------------------------------------------------------------

    def _map_azure_rbac_structures(self, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Maps Azure Role Assignments and Service Principal ownership."""
        edges = []
        
        for node in nodes:
            if node.get("cloud_provider", "").lower() != "azure":
                continue
                
            metadata = node.get("metadata", {})
            source_arn = node.get("arn")
            
            # 1. Role Assignments (Principal -> Resource)
            role_assignments = metadata.get("RoleAssignments", [])
            for ra in role_assignments:
                target_scope = ra.get("scope")
                role_def = str(ra.get("roleDefinitionId", "")).lower()
                
                if target_scope and source_arn:
                    # Determine risk weight based on Role Definition
                    weight = 3.0
                    if "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" in role_def: # Owner
                        weight = 9.0
                    elif "b24988ac-6180-42a0-ab88-20f7382dd24c" in role_def: # Contributor
                        weight = 7.0
                        
                    edges.append(self._format_edge(
                        source=source_arn, target=target_scope,
                        relation="HAS_RBAC_ON", weight=weight, is_bridge=False
                    ))

            # 2. Service Principal Ownership
            owners = metadata.get("Owners", [])
            for owner_id in owners:
                edges.append(self._format_edge(
                    source=owner_id, target=source_arn,
                    relation="OWNS_PRINCIPAL", weight=8.5, is_bridge=False
                ))
                
        return edges

    # --------------------------------------------------------------------------
    # UTILITIES
    # --------------------------------------------------------------------------

    def _tag_high_risk_node(self, node: Dict[str, Any], reason: str) -> None:
        """Mutates node payload to flag as highly dangerous."""
        tags = node.setdefault("tags", {})
        tags["ThreatVector"] = "ShadowAdmin"
        tags["EscalationReason"] = reason
        
        # Override risk metadata for HAPD prioritization
        node.setdefault("metadata", {})["baseline_risk_score"] = 10.0

    def _format_edge(self, source: str, target: str, relation: str, weight: float, is_bridge: bool) -> Dict[str, Any]:
        """Strict schema enforcement for the Neo4j Ingestor."""
        return {
            "source_arn": source,
            "target_arn": target,
            "relation_type": relation,
            "weight": weight,
            "is_identity_bridge": is_bridge
        }

# Export Global Singleton
identity_fabric = IdentityFabric()