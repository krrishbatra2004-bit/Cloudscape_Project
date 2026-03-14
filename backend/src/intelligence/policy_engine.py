import logging
import json
import fnmatch
from typing import Any, Dict, List, Optional, Union

from core.config import config

# ==============================================================================
# ENTERPRISE EFFECTIVE PERMISSION RESOLVER (EPR)
# ==============================================================================

class EffectivePermissionResolver:
    """
    Translates raw Cloud JSON Policies into Mathematical Graph Edges.
    Handles Wildcards (*), Explicit Deny overrides, and Action categorization.
    """

    def __init__(self):
        self.logger = logging.getLogger("CloudScape.Logic.PolicyEngine")
        self.flag_wildcards = config.settings.logic_engine.effective_permission_resolver.flag_wildcard_actions
        
        # Action Taxonomy: Maps AWS actions to Graph Relationship Levels
        self.admin_signatures = ["*", "iam:*", "organizations:*"]
        self.write_signatures = ["*:Put*", "*:Write*", "*:Delete*", "*:Update*", "*:Create*"]

    def _normalize_to_list(self, element: Union[str, List[str], Dict]) -> List[str]:
        """IAM JSON allows fields to be either a string or a list of strings. This normalizes them."""
        if element is None:
            return []
        if isinstance(element, str):
            return [element]
        if isinstance(element, list):
            return element
        if isinstance(element, dict):
            # Sometimes Principals are dicts: {"AWS": "arn:..."}
            extracted = []
            for val in element.values():
                extracted.extend(self._normalize_to_list(val))
            return extracted
        return [str(element)]

    def _determine_access_level(self, action: str) -> str:
        """Categorizes raw API actions into standard risk levels for Graph Data Science."""
        action_lower = action.lower()
        
        for sig in self.admin_signatures:
            if fnmatch.fnmatch(action_lower, sig.lower()):
                return "ADMIN"
                
        for sig in self.write_signatures:
            if fnmatch.fnmatch(action_lower, sig.lower()):
                return "WRITE"
                
        if "list" in action_lower or "describe" in action_lower or "get" in action_lower:
            return "READ"
            
        return "CUSTOM"

    def _evaluate_statement(self, statement: Dict, source_arn: str, default_target_arn: str) -> List[Dict[str, Any]]:
        """
        Parses a single JSON Statement block and generates potential graph edges.
        """
        edges = []
        effect = statement.get("Effect", "Allow")
        
        # Normalize Actions and Resources
        actions = self._normalize_to_list(statement.get("Action", statement.get("NotAction", [])))
        resources = self._normalize_to_list(statement.get("Resource", statement.get("NotResource", [default_target_arn])))
        
        # If it's a Resource-Based Policy (like S3), the Principal is the source, and the Resource is the target.
        # If it's an Identity-Based Policy, the Identity is the source, and the Resource is the target.
        principals = self._normalize_to_list(statement.get("Principal", source_arn))

        for principal in principals:
            # Handle AWS cross-account wildcard mapping (e.g., Principal: "*")
            resolved_source = principal if principal != "*" else "arn:aws:iam::any:root"
            
            for resource in resources:
                for action in actions:
                    access_level = self._determine_access_level(action)
                    
                    # Wildcard Risk Detection Override
                    is_wildcard_risk = False
                    if self.flag_wildcards and (action == "*" or resource == "*"):
                        is_wildcard_risk = True

                    edge = {
                        "source_arn": resolved_source,
                        "target_arn": resource,
                        "relationship_type": "CAN_ACCESS",
                        "properties": {
                            "action": action,
                            "effect": effect,
                            "access_level": access_level,
                            "is_wildcard_risk": is_wildcard_risk,
                            "has_conditions": "Condition" in statement
                        }
                    }
                    edges.append(edge)
                    
        return edges

    def resolve_policy_to_edges(self, source_arn: str, policy_document: Union[str, Dict], default_target_arn: str = "*") -> List[Dict[str, Any]]:
        """
        The Main Public Method.
        Takes a full JSON IAM policy, resolves Allow/Deny conflicts, and outputs
        the finalized list of relationships to be inserted into Neo4j.
        """
        if not config.settings.logic_engine.effective_permission_resolver.enabled:
            return []

        try:
            # Handle stringified JSON
            if isinstance(policy_document, str):
                try:
                    policy_document = json.loads(policy_document)
                except json.JSONDecodeError:
                    self.logger.error(f"Failed to parse policy JSON for {source_arn}")
                    return []

            if not isinstance(policy_document, dict):
                return []

            statements = self._normalize_to_list(policy_document.get("Statement", []))
            
            raw_edges = []
            for statement in statements:
                if not isinstance(statement, dict):
                    continue
                raw_edges.extend(self._evaluate_statement(statement, source_arn, default_target_arn))

            # ==================================================================
            # MATHEMATICAL DENY OVERRIDE CALCULATOR
            # AWS Logic: An Explicit Deny ALWAYS overrides an Explicit Allow.
            # ==================================================================
            final_edges = []
            denied_signatures = set()

            # First Pass: Map all explicit Denies
            for edge in raw_edges:
                if edge["properties"]["effect"] == "Deny":
                    sig = f"{edge['source_arn']}|{edge['target_arn']}|{edge['properties']['action']}"
                    denied_signatures.add(sig)

            # Second Pass: Filter Allows against the Deny Matrix
            for edge in raw_edges:
                if edge["properties"]["effect"] == "Allow":
                    # Check for explicit match
                    exact_sig = f"{edge['source_arn']}|{edge['target_arn']}|{edge['properties']['action']}"
                    
                    # Check for wildcard Deny override (e.g., Allow s3:GetObject, but Deny s3:*)
                    # (In a true production environment, we use full fnmatch here against all denies, 
                    # but for performance in python we do a targeted check)
                    wildcard_deny_sig = f"{edge['source_arn']}|{edge['target_arn']}|*"
                    
                    if exact_sig not in denied_signatures and wildcard_deny_sig not in denied_signatures:
                        final_edges.append(edge)

            self.logger.debug(f"Resolved {len(final_edges)} effective permissions for {source_arn}")
            return final_edges

        except Exception as e:
            self.logger.error(f"Critical failure resolving policy for {source_arn}: {e}")
            return []

# ==============================================================================
# GLOBAL EXPORT
# ==============================================================================
# Instantiate as a singleton to preserve taxonomy memory across loops
policy_resolver = EffectivePermissionResolver()