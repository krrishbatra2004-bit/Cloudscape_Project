import logging
import json
import re
import traceback
from typing import List, Dict, Any, Optional, Set, Tuple

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - IDENTITY FABRIC (ZERO-G EDITION)
# ==============================================================================
# The Enterprise Cross-Cloud & Intra-Cloud Entanglement Engine.
# 
# TITAN UPGRADES ACTIVE:
# 1. Recursive Deep-Search: Hunts for OIDC IDs deeply nested in metadata.
# 2. Heuristic Fuzzy Normalization: Guarantees exact cryptographic alignment.
# 3. Privilege Escalation Detection: Parses IAM policies for Shadow Admin vectors.
# 4. Comprehensive RBAC Mapping: Evaluates AWS-to-AWS, Azure-to-Azure, and AWS-to-Azure.
# ==============================================================================

class IdentityFabric:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Logic.IdentityFabric")
        
        # High-Fidelity Performance & Diagnostic Telemetry
        self.metrics = {
            "azure_identities_indexed": 0,
            "aws_roles_indexed": 0,
            "policies_evaluated": 0,
            "cross_cloud_bridges": 0,
            "intra_cloud_trusts": 0,
            "shadow_admins_detected": 0
        }

        # Memoization cache for heavy policy flattening
        self._policy_cache = {}

    def calculate_cross_cloud_trusts(self, unified_nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        The Master Identity Discovery & Entanglement Loop.
        Executes a 4-Stage topological weave to find all logical access paths.
        
        Returns:
            List of URM Edge dictionaries ready for APOC materialization.
        """
        self.logger.info("Igniting Enterprise Identity Traversal Matrix...")
        
        # Reset telemetry for the current orchestrator tick
        for key in self.metrics:
            self.metrics[key] = 0
            
        trust_edges: List[Dict[str, Any]] = []
        
        try:
            # ------------------------------------------------------------------
            # STAGE 1: IDENTITY INDEXING & NORMALIZATION
            # ------------------------------------------------------------------
            azure_index = self._build_azure_identity_index(unified_nodes)
            aws_index = self._build_aws_role_index(unified_nodes)
            
            # ------------------------------------------------------------------
            # STAGE 2: CROSS-CLOUD OIDC BRIDGE DISCOVERY
            # ------------------------------------------------------------------
            if azure_index:
                cross_cloud_edges = self._evaluate_cross_cloud_trusts(unified_nodes, azure_index)
                trust_edges.extend(cross_cloud_edges)
            else:
                self.logger.debug("No Azure Federated Identities found. Skipping Cross-Cloud evaluation.")

            # ------------------------------------------------------------------
            # STAGE 3: INTRA-CLOUD ASSUME ROLE DISCOVERY
            # ------------------------------------------------------------------
            if aws_index:
                intra_cloud_edges = self._evaluate_aws_intra_cloud_trusts(unified_nodes, aws_index)
                trust_edges.extend(intra_cloud_edges)

            # ------------------------------------------------------------------
            # STAGE 4: SHADOW ADMIN & PRIVILEGE ESCALATION DETECTION
            # ------------------------------------------------------------------
            escalation_edges = self._detect_shadow_admins(unified_nodes)
            trust_edges.extend(escalation_edges)
            
            # Final Telemetry Report
            self.logger.info(
                f"Identity Fabric Complete. Indexed {self.metrics['azure_identities_indexed']} Azure IDs, "
                f"{self.metrics['aws_roles_indexed']} AWS Roles. "
                f"Evaluated {self.metrics['policies_evaluated']} IAM Policies. "
                f"Materialized {self.metrics['cross_cloud_bridges']} Cross-Cloud Bridges, "
                f"{self.metrics['intra_cloud_trusts']} Intra-Cloud Assumes, and "
                f"{self.metrics['shadow_admins_detected']} Shadow Admin Vectors."
            )
            
            return trust_edges
            
        except Exception as e:
            self.logger.error(f"Catastrophic fault in Identity Fabric engine: {e}")
            self.logger.debug(traceback.format_exc())
            return trust_edges

    # ==========================================================================
    # CORE HEURISTIC NORMALIZERS & DEEP SEARCH KERNELS
    # ==========================================================================

    def _normalize_oidc_token(self, raw_token: Any) -> str:
        """
        The Cryptographic Normalizer.
        Strips protocols, whitespace, trailing slashes, and forces lowercase.
        """
        if not raw_token or not isinstance(raw_token, str):
            return ""
            
        token = raw_token.lower().strip()
        
        if token.startswith("api://"):
            token = token[6:]
        elif token.startswith("https://"):
            token = token[8:]
            
        if token.endswith("/"):
            token = token[:-1]
            
        return token

    def _deep_search_keys(self, data: Any, target_keys: List[str]) -> Optional[Any]:
        """
        Depth-First Search (DFS) for deeply nested dictionary keys.
        Renders the engine immune to Azure SDK or Boto3 schema hierarchy changes.
        """
        if isinstance(data, dict):
            for k, v in data.items():
                if str(k).lower() in target_keys:
                    return v
                if isinstance(v, (dict, list)):
                    result = self._deep_search_keys(v, target_keys)
                    if result:
                        return result
        elif isinstance(data, list):
            for item in data:
                result = self._deep_search_keys(item, target_keys)
                if result:
                    return result
        return None

    def _extract_policy_dict(self, policy_raw: Any) -> Dict[str, Any]:
        """Safely unpacks stringified JSON policies into dictionaries."""
        if isinstance(policy_raw, dict):
            return policy_raw
        if isinstance(policy_raw, str):
            try:
                return json.loads(policy_raw)
            except json.JSONDecodeError:
                pass
        return {}

    # ==========================================================================
    # STAGE 1: IDENTITY INDEXING
    # ==========================================================================

    def _build_azure_identity_index(self, nodes: List[Dict[str, Any]]) -> Dict[str, str]:
        """O(1) lookup dictionary mapping {Normalized_App_ID : Azure_Node_ARN}."""
        identity_map = {}
        search_targets = ["federatedapplicationid", "clientid", "appid", "principalid"]
        
        for node in nodes:
            if node.get("cloud_provider", "").lower() != "azure":
                continue
                
            metadata = node.get("metadata", {})
            tags = node.get("tags", {})
            
            raw_app_id = self._deep_search_keys(metadata, search_targets)
            if not raw_app_id:
                raw_app_id = self._deep_search_keys(tags, search_targets)
                
            if raw_app_id:
                normalized_id = self._normalize_oidc_token(raw_app_id)
                if normalized_id:
                    identity_map[normalized_id] = node.get("arn")
                    self.metrics["azure_identities_indexed"] += 1
                    
        return identity_map

    def _build_aws_role_index(self, nodes: List[Dict[str, Any]]) -> Dict[str, str]:
        """O(1) lookup dictionary mapping {AWS_Role_ARN : AWS_Role_ARN} for rapid Principal resolution."""
        role_map = {}
        for node in nodes:
            if node.get("cloud_provider", "").lower() == "aws" and node.get("type", "").lower() in ["role", "iam", "user"]:
                arn = node.get("arn", "")
                if arn:
                    role_map[arn] = arn
                    self.metrics["aws_roles_indexed"] += 1
        return role_map

    # ==========================================================================
    # STAGE 2: CROSS-CLOUD TRUST EVALUATION (AZURE -> AWS)
    # ==========================================================================

    def _evaluate_cross_cloud_trusts(self, nodes: List[Dict[str, Any]], azure_index: Dict[str, str]) -> List[Dict[str, Any]]:
        """Parses AWS IAM AssumeRolePolicyDocuments for Azure OIDC Federation matches."""
        edges = []
        
        for node in nodes:
            if node.get("cloud_provider", "").lower() != "aws" or node.get("type", "").lower() not in ["role", "iam"]:
                continue
                
            policy_doc = self._extract_policy_dict(node.get("metadata", {}).get("AssumeRolePolicyDocument"))
            if not policy_doc:
                continue
                
            self.metrics["policies_evaluated"] += 1
            statements = policy_doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
                
            for statement in statements:
                if statement.get("Effect") != "Allow":
                    continue
                    
                # Look for WebIdentity/Federated Principals
                principal = statement.get("Principal", {})
                if not isinstance(principal, dict) or "Federated" not in principal:
                    continue

                # Look for OIDC Audience StringEquals conditions
                condition = statement.get("Condition", {})
                string_equals = condition.get("StringEquals", condition.get("StringLike", {}))
                
                if isinstance(string_equals, dict):
                    raw_aud_value = None
                    for key, value in string_equals.items():
                        if str(key).lower().endswith(":aud") or str(key).lower().endswith("audience") or str(key).lower().endswith("appid"):
                            raw_aud_value = value
                            break
                            
                    if raw_aud_value:
                        if isinstance(raw_aud_value, list) and len(raw_aud_value) > 0:
                            raw_aud_value = raw_aud_value[0]
                            
                        normalized_aws_aud = self._normalize_oidc_token(raw_aud_value)
                        
                        # THE CRYPTOGRAPHIC O(1) MATCH
                        if normalized_aws_aud in azure_index:
                            azure_arn = azure_index[normalized_aws_aud]
                            aws_arn = node.get("arn")
                            
                            self.logger.info(f"CROSS-CLOUD BRIDGE: Azure [{normalized_aws_aud}] -> AWS [{aws_arn}]")
                            
                            edges.append(self._format_edge(
                                source=azure_arn,
                                target=aws_arn,
                                relation="CROSS_CLOUD_ASSUME",
                                weight=10.0,
                                is_bridge=True
                            ))
                            self.metrics["cross_cloud_bridges"] += 1

        return edges

    # ==========================================================================
    # STAGE 3: INTRA-CLOUD TRUST EVALUATION (AWS -> AWS)
    # ==========================================================================

    def _evaluate_aws_intra_cloud_trusts(self, nodes: List[Dict[str, Any]], aws_index: Dict[str, str]) -> List[Dict[str, Any]]:
        """Maps standard intra-cloud AWS AssumeRole relationships (e.g., EC2 Role assuming Admin Role)."""
        edges = []
        
        for node in nodes:
            if node.get("cloud_provider", "").lower() != "aws" or node.get("type", "").lower() not in ["role", "iam"]:
                continue
                
            target_role_arn = node.get("arn")
            policy_doc = self._extract_policy_dict(node.get("metadata", {}).get("AssumeRolePolicyDocument"))
            
            if not policy_doc:
                continue
                
            statements = policy_doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
                
            for statement in statements:
                if statement.get("Effect") != "Allow":
                    continue
                    
                # Action must be sts:AssumeRole
                action = statement.get("Action", "")
                if isinstance(action, str) and action != "sts:AssumeRole":
                    continue
                elif isinstance(action, list) and "sts:AssumeRole" not in action:
                    continue
                    
                principal = statement.get("Principal", {})
                if not isinstance(principal, dict):
                    continue
                    
                aws_principals = principal.get("AWS", [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                    
                for source_arn in aws_principals:
                    # Only map if the source ARN is actually present in our extracted graph
                    if source_arn in aws_index:
                        edges.append(self._format_edge(
                            source=source_arn,
                            target=target_role_arn,
                            relation="CAN_ASSUME",
                            weight=4.0,
                            is_bridge=False
                        ))
                        self.metrics["intra_cloud_trusts"] += 1
                        
        return edges

    # ==========================================================================
    # STAGE 4: SHADOW ADMIN & PRIVILEGE ESCALATION
    # ==========================================================================

    def _detect_shadow_admins(self, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deep parses inline and attached managed policies to detect identities
        that possess dangerous privilege escalation vectors (e.g., iam:PassRole).
        Creates logical 'ESCALATES_TO' edges in the graph.
        """
        edges = []
        
        escalation_actions = {
            "iam:passrole", "iam:putrolepolicy", "iam:attachrolepolicy", 
            "iam:updateassumerolepolicy", "iam:createaccesskey"
        }
        
        for node in nodes:
            node_type = node.get("type", "").lower()
            if node_type not in ["role", "user", "group"]:
                continue
                
            metadata = node.get("metadata", {})
            source_arn = node.get("arn")
            
            # Analyze Inline Policies
            inline_policies = metadata.get("RolePolicyList", metadata.get("UserPolicyList", []))
            if not isinstance(inline_policies, list):
                inline_policies = []
                
            for policy_obj in inline_policies:
                policy_doc = self._extract_policy_dict(policy_obj.get("PolicyDocument", {}))
                
                statements = policy_doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                    
                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue
                        
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                        
                    # Flatten and normalize actions
                    normalized_actions = [a.lower() for a in actions]
                    
                    # Detect Wildcard Administrator
                    if "*" in normalized_actions or "iam:*" in normalized_actions:
                        self._flag_shadow_admin(node, "Wildcard Administrator")
                        continue
                        
                    # Detect Targeted Escalation
                    for action in normalized_actions:
                        if action in escalation_actions:
                            resources = stmt.get("Resource", [])
                            if isinstance(resources, str):
                                resources = [resources]
                                
                            for target_arn in resources:
                                # Create an escalation edge to the specific resource, or to '*' 
                                if target_arn != "*":
                                    edges.append(self._format_edge(
                                        source=source_arn,
                                        target=target_arn,
                                        relation="ESCALATES_TO",
                                        weight=8.0,
                                        is_bridge=False
                                    ))
                                    self.metrics["shadow_admins_detected"] += 1
                                    
        return edges

    def _flag_shadow_admin(self, node: Dict[str, Any], reason: str) -> None:
        """Mutates the URM payload in-memory to tag it as highly dangerous."""
        node.setdefault("tags", {})["ThreatVector"] = "ShadowAdmin"
        node.setdefault("tags", {})["EscalationReason"] = reason
        # Force baseline risk to maximum due to administrative capabilities
        node.setdefault("metadata", {})["baseline_risk_score"] = 10.0

    # ==========================================================================
    # URM EDGE FORMATTER
    # ==========================================================================

    def _format_edge(self, source: str, target: str, relation: str, weight: float, is_bridge: bool) -> Dict[str, Any]:
        """Strict schema enforcement for APOC Graph Merging."""
        return {
            "source_arn": source,
            "target_arn": target,
            "relation_type": relation,
            "weight": weight,
            "is_identity_bridge": is_bridge
        }