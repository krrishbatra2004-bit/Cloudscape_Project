import json
import logging
from datetime import datetime, date
from typing import Any, Dict, List, Tuple

from core.config import config

# ==============================================================================
# ENTERPRISE GRAPH DATA TRANSFORMER
# ==============================================================================

class GraphTransformer:
    """
    Sanitizes, flattens, and prepares Universal Resource Model (URM) payloads 
    for high-speed Neo4j UNWIND batch ingestion. Extracts implicit relationships 
    from raw cloud attributes.
    """

    def __init__(self):
        self.logger = logging.getLogger("CloudScape.Processor.Transformer")
        
        # The Implicit Edge Matrix
        # Maps raw cloud API keys to specific Graph Relationship semantics
        self.implicit_edge_matrix = {
            "VpcId": {"target_label": "Vpc", "rel_type": "HOSTED_IN", "target_key": "arn_pseudo"},
            "SubnetId": {"target_label": "Subnet", "rel_type": "HOSTED_IN", "target_key": "arn_pseudo"},
            "AttachedPolicies": {"target_label": "Policy", "rel_type": "HAS_POLICY", "target_key": "PolicyArn"},
            "RoleArn": {"target_label": "Role", "rel_type": "ASSUMES_ROLE", "target_key": "exact"},
            "SecurityGroups": {"target_label": "SecurityGroup", "rel_type": "PROTECTED_BY", "target_key": "GroupId"}
        }

    def _serialize_complex_types(self, value: Any) -> Any:
        """
        Neo4j properties only support primitives (str, int, float, bool) or 
        homogeneous arrays of primitives. This safely coerces complex types.
        """
        if value is None:
            return ""
        if isinstance(value, (int, float, bool, str)):
            return value
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if isinstance(value, list):
            # Ensure Neo4j arrays are strictly homogeneous (all strings)
            return [str(self._serialize_complex_types(item)) for item in value]
        if isinstance(value, dict):
            # Neo4j cannot store nested dictionaries. Convert to JSON string.
            try:
                return json.dumps(value, default=str, separators=(',', ':'))
            except Exception as e:
                self.logger.warning(f"Failed to serialize nested dictionary: {e}")
                return str(value)
        return str(value)

    def _flatten_properties(self, properties: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        """
        Flattens a deeply nested cloud dictionary into a flat key-value structure 
        using dot notation (e.g., 'Tags.Owner': 'Finance'). 
        """
        flattened = {}
        for key, value in properties.items():
            # Skip massive raw outputs that bloat the graph unnecessariliy
            if key in ["ResponseMetadata", "_raw_unserializable_value"]:
                continue
                
            new_key = f"{prefix}{key}" if prefix else key
            
            # If it's a small dict, flatten it. If it's massive, stringify it.
            if isinstance(value, dict) and len(value) < 10 and not new_key.startswith("_"):
                flattened.update(self._flatten_properties(value, f"{new_key}."))
            else:
                flattened[new_key] = self._serialize_complex_types(value)
                
        return flattened

    def _extract_implicit_edges(self, source_arn: str, source_provider: str, source_tenant: str, properties: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scans the flat properties for known foreign keys (like VpcId) and generates
        relationship definitions for the database to link later.
        """
        edges = []
        
        for prop_key, prop_val in properties.items():
            # Standard single-value extraction
            if prop_key in self.implicit_edge_matrix and isinstance(prop_val, str) and prop_val:
                rule = self.implicit_edge_matrix[prop_key]
                target_arn = self._construct_target_arn(prop_val, rule, source_provider, source_tenant)
                
                edges.append({
                    "source_arn": source_arn,
                    "target_arn": target_arn,
                    "target_label": f"{source_provider.upper()}{rule['target_label']}",
                    "relationship_type": rule["rel_type"],
                    "properties": {"extracted_from": prop_key}
                })
            
            # Array-based extraction (e.g., a list of SecurityGroups)
            elif prop_key in self.implicit_edge_matrix and isinstance(prop_val, list):
                rule = self.implicit_edge_matrix[prop_key]
                for item in prop_val:
                    # Depending on API, item could be a string "sg-123" or a dict {"GroupId": "sg-123"}
                    target_id = item if isinstance(item, str) else json.loads(item).get(rule.get("target_key", "GroupId"))
                    if not target_id:
                        continue
                        
                    target_arn = self._construct_target_arn(target_id, rule, source_provider, source_tenant)
                    edges.append({
                        "source_arn": source_arn,
                        "target_arn": target_arn,
                        "target_label": f"{source_provider.upper()}{rule['target_label']}",
                        "relationship_type": rule["rel_type"],
                        "properties": {"extracted_from": prop_key}
                    })

        return edges

    def _construct_target_arn(self, raw_id: str, rule: Dict[str, str], provider: str, tenant_id: str) -> str:
        """
        Helper to construct a valid ARN for implicit edge targets so the database 
        can execute a MERGE statement successfully.
        """
        if raw_id.startswith("arn:") or raw_id.startswith("/subscriptions/"):
            return raw_id
            
        if rule.get("target_key") == "arn_pseudo" and provider == "aws":
            # For things like VPCs that lack standard ARNs in describe calls
            return f"arn:aws:ec2:regional:{tenant_id}:resource/{raw_id}"
            
        return f"urn:{provider}:pseudo:{tenant_id}:{raw_id}"

    def process_payload(self, urm_payload: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        The Main Public Method.
        Takes a URM payload, calculates a sanitized Node definition, and an array of 
        Relationship definitions.
        
        Returns: Tuple(CleanNodeData, List[CleanEdgeData])
        """
        try:
            metadata = urm_payload.get("metadata", {})
            properties = urm_payload.get("properties", {})
            tags = urm_payload.get("tags", {})
            
            source_arn = metadata.get("arn")
            provider = metadata.get("provider", "unknown").upper()
            resource_type = metadata.get("resource_type", "Unknown")
            tenant_id = metadata.get("tenant_id")
            
            # 1. Flatten and Sanitize the Node Properties
            clean_properties = self._flatten_properties(properties)
            
            # Inject mandatory graph routing metadata into the flat properties
            clean_properties["_tenant_id"] = tenant_id
            clean_properties["_provider"] = provider
            clean_properties["_resource_type"] = resource_type
            clean_properties["_baseline_risk_score"] = float(metadata.get("baseline_risk_score", 0.0))
            clean_properties["_discovery_timestamp"] = metadata.get("discovery_timestamp")
            
            # Extract standard naming for graph UI rendering
            clean_properties["_display_name"] = tags.get("Name", tags.get("name", properties.get("Name", properties.get("name", source_arn.split(":")[-1]))))

            # 2. Construct the Neo4j Node Representation
            # Multiple labels allow for flexible querying (e.g., MATCH (n:AWSNode) vs MATCH (n:AWSEC2Instance))
            node_labels = ["CloudResource", f"{provider}Node", f"{provider}{resource_type}"]
            
            node_data = {
                "arn": source_arn,
                "labels": node_labels,
                "properties": clean_properties
            }
            
            # 3. Extract Implicit Edges (Infrastructure Topology)
            implicit_edges = self._extract_implicit_edges(source_arn, provider.lower(), tenant_id, clean_properties)
            
            # 4. Extract Explicit Edges (IAM Policy Relationships calculated by the EPR module)
            explicit_edges = properties.get("_resolved_policy_edges", [])
            all_edges = implicit_edges + explicit_edges

            return node_data, all_edges

        except Exception as e:
            self.logger.error(f"Failed to transform payload for {urm_payload.get('metadata', {}).get('arn', 'unknown')}: {e}")
            # Return empty safe defaults on failure to prevent pipeline crash
            return {}, []

# ==============================================================================
# GLOBAL EXPORT
# ==============================================================================
graph_transformer = GraphTransformer()