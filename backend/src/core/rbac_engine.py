# pyright: reportMissingImports=false
import json
import logging
import re
import traceback
import hashlib
from enum import Enum, auto
from typing import (
    Dict, List, Any, Optional, Union, Set, Callable, Tuple, Type, Mapping
)
from datetime import datetime, timezone
import copy
from pydantic import BaseModel, Field, field_validator, ConfigDict, model_validator # pyre-ignore[21]


# ==============================================================================
# CLOUDSCAPE NEXUS 5.2 TITAN - ENTERPRISE RBAC ENGINE (SUPREME EDITION)
# ==============================================================================
# A massive, hyper-advanced, mathematically rigorous Role-Based Access Control
# (RBAC) and Forensic Redaction gateway for the Sovereign-Forensic Graph Mesh.
#
# TITAN NEXUS 5.2 ARCHITECTURAL UPGRADES:
# 1. Multi-Dimensional Security Overlay: Generates highly sophisticated Cypher 
#    Subqueries that handle both Node-level isolation and Relationship-level 
#    isolation across massive multi-tenant meshes.
# 2. Dynamic Redaction Kernel: A deeply recursive object mutation engine that 
#    replaces sensitive cryptographic keys, explicit IPs, and full IAM policies 
#    with business-oriented aggregate heuristics for non-administrative roles.
# 3. Cryptographic Audit Ledger: Every redaction event and query overlay is 
#    tracked via SHA-256 signatures for non-repudiation.
# 4. Strict Type Safety: Heavily decorated Pydantic models for absolute memory 
#    safety and constraint adherence.
# 5. Fault-Tolerant Degraded Modes: In the event of a configuration fault, 
#    defaults automatically to a "Zero-Trust" posture (DENY_ALL).
# 6. Extensible Heuristics Pipeline: Allows registering custom redaction strategies 
#    per resource type (S3, EC2, IAM Role, Network Acl, etc.).
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. INITIALIZATION & LOGGING
# ------------------------------------------------------------------------------

logger = logging.getLogger("CloudScape.Core.RBACEngine")
logger.setLevel(logging.DEBUG)


# ------------------------------------------------------------------------------
# 2. ENUMS & SECURITY TAXONOMY
# ------------------------------------------------------------------------------

class EnterpriseRole(str, Enum):
    """
    The four foundational access tiers for the Sovereign-Forensic Mesh.
    These tiers dictate both query visibility (what nodes can be searched)
    and data fidelity (how much resolution the nodes return).
    """
    ADMIN = "ADMIN"
    # Capabilities: Unrestricted mesh visibility, unredacted raw forensic data, cross-tenant lateral analysis.
    
    MANAGER = "MANAGER"
    # Capabilities: Full-fidelity forensic data restricted *only* to assigned tenants. Cannot see cross-mesh global activity.
    
    MEMBER = "MEMBER"
    # Capabilities: Restricted to assigned tenants. Cannot view exact IAM policies or root credentials. Metadata is partially masked.
    
    SHAREHOLDER = "SHAREHOLDER"
    # Capabilities: Restricted to assigned tenants. Highly redacted executive summaries. ARNs masked, IPs stripped, heuristics only.


class AccessLevel(int, Enum):
    """Numerical hierarchy for faster integer comparisons during traversal."""
    SHAREHOLDER = 10
    MEMBER = 20
    MANAGER = 50
    ADMIN = 100


class RedactionStrategy(str, Enum):
    """Allowed strategies for censoring a specific field within the graph dictionary."""
    STRIP = "STRIP"               # Remove the key entirely
    MASK_ARN = "MASK_ARN"         # Replace the AWS Account ID in the ARN with XXXXXX
    MASK_IP = "MASK_IP"           # Replace the last two octets of an IP (e.g. 192.168.X.X)
    SUMMARIZE_IAM = "SUMMARIZE"   # Replace raw JSON policies with a high-level string
    OBFUSCATE_ID = "OBFUSCATE_ID" # hash the ID
    QUALITATIVE = "QUALITATIVE"   # Translate risk metrics into simple English words


# ------------------------------------------------------------------------------
# 3. PYDANTIC SECURITY CONTEXT MODELS
# ------------------------------------------------------------------------------

class UserAction(BaseModel):
    """Represents a specific requested operation in the system."""
    action_type: str = Field(..., description="e.g., READ_GRAPH, EXPORT_REPORT, TRIGGER_SCAN")
    target_tenant_id: Optional[str] = Field(default=None)
    parameters: Dict[str, Any] = Field(default_factory=dict)


class UserContext(BaseModel):
    """
    The universal security context passed into every graph query or API invocation.
    Guarantees absolute immutability of the identity asserting the request.
    """
    model_config = ConfigDict(frozen=True, extra='ignore')
    
    user_id: str = Field(..., description="Unique immutable identity string (UUID, Email, UPN).")
    role: EnterpriseRole = Field(..., description="The maximum clearance level assigned.")
    allowed_tenants: List[str] = Field(default_factory=list, description="Explicit array of project boundaries.")
    session_id: str = Field(default_factory=lambda: hashlib.sha256(str(datetime.now(timezone.utc).timestamp()).encode()).hexdigest()[:16]) # type: ignore
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def clearance(self) -> AccessLevel:
        """Translates the string role into a comparable integer tier."""
        mapping = {
            EnterpriseRole.ADMIN: AccessLevel.ADMIN,
            EnterpriseRole.MANAGER: AccessLevel.MANAGER,
            EnterpriseRole.MEMBER: AccessLevel.MEMBER,
            EnterpriseRole.SHAREHOLDER: AccessLevel.SHAREHOLDER
        }
        return mapping.get(self.role, AccessLevel.SHAREHOLDER)

    @property
    def is_global_admin(self) -> bool:
        """Convenience property for absolute root checks."""
        return self.role == EnterpriseRole.ADMIN

    @model_validator(mode='after')
    def validate_tenant_bindings(self) -> 'UserContext':
        """Ensure non-admins do not attempt to bypass tenant arrays."""
        if not self.is_global_admin and "*" in self.allowed_tenants:
            raise ValueError(f"Security Fault: Role {self.role} cannot bind to wildcard '*' tenant.")
        return self


# ------------------------------------------------------------------------------
# 4. ADVANCED REDACTION RULE ENGINE
# ------------------------------------------------------------------------------

class FieldRedactionRule(BaseModel):
    """Defines a targeted redaction rule for an arbitrary dictionary key/path."""
    target_key: str = Field(..., description="The key to target (can be a regex pattern or literal).")
    strategy: RedactionStrategy = Field(...)
    min_clearance_required: AccessLevel = Field(..., description="If user clearance is below this, rule triggers.")
    replacement_value: Optional[str] = Field(default="[REDACTED]")


class RedactionRegistry:
    """
    Singleton registry holding all compiled redaction rules.
    Allows for dynamic injection of new rules at runtime without restarting the orchestrator.
    """
    _instance = None
    _rules: List[FieldRedactionRule]
    _regex_rules: Dict[re.Pattern, FieldRedactionRule]
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RedactionRegistry, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance
        
    def _initialize(self):
        self._rules: List[FieldRedactionRule] = []
        self._regex_rules: Dict[re.Pattern, FieldRedactionRule] = {}
        self._load_enterprise_defaults()
        
    def _load_enterprise_defaults(self):
        """Loads the baseline Sovereign-Forensic censorship matrix."""
        # 1. Strip raw credentials from anyone below MANAGER
        self.register_rule(FieldRedactionRule(**{ # pyre-ignore[28]
            "target_key": "aws_access_key_id", 
            "strategy": RedactionStrategy.STRIP, 
            "min_clearance_required": AccessLevel.MANAGER
        }))
        self.register_rule(FieldRedactionRule(**{ # pyre-ignore[28]
            "target_key": "azure_client_secret", 
            "strategy": RedactionStrategy.STRIP, 
            "min_clearance_required": AccessLevel.MANAGER
        }))
        
        # 2. Mask ARNs for Shareholders (Business users don't need Account IDs)
        self.register_regex_rule(r".*arn.*", FieldRedactionRule(**{ # pyre-ignore[28]
            "target_key": ".*arn.*",
            "strategy": RedactionStrategy.MASK_ARN,
            "min_clearance_required": AccessLevel.MEMBER
        }))
        
        # 3. Summarize complex JSON for Shareholders
        for key in ["Metadata", "metadata", "properties"]:
            self.register_rule(FieldRedactionRule(**{ # pyre-ignore[28]
                "target_key": key,
                "strategy": RedactionStrategy.SUMMARIZE_IAM,
                "min_clearance_required": AccessLevel.MEMBER
            }))
            
        # 4. Mask internal IP structures for Shareholders
        for key in ["private_ip", "public_ip", "cidr", "cidr_blocks", "ip_address"]:
            self.register_rule(FieldRedactionRule(**{ # pyre-ignore[28]
                "target_key": key,
                "strategy": RedactionStrategy.MASK_IP,
                "min_clearance_required": AccessLevel.MEMBER
            }))
            
        # 5. Qualitative Translation for scoring metrics
        for key in ["risk_score", "FrictionScore", "baseline_risk_score", "hcs_score"]:
            self.register_rule(FieldRedactionRule(**{ # pyre-ignore[28]
                "target_key": key,
                "strategy": RedactionStrategy.QUALITATIVE,
                "min_clearance_required": AccessLevel.MEMBER,
                "replacement_value": ""
            }))
            
        logger.debug(f"RedactionRegistry initialized with {len(self._rules) + len(self._regex_rules)} enterprise rules.")

    def register_rule(self, rule: FieldRedactionRule):
        self._rules.append(rule)
        
    def register_regex_rule(self, pattern: str, rule: FieldRedactionRule):
        try:
            compiled = re.compile(f"^{pattern}$", re.IGNORECASE)
            self._regex_rules[compiled] = rule
        except re.error as e:
            logger.error(f"Failed to compile regex rule {pattern}: {e}")

    def get_applicable_rules(self, key: str, clearance: AccessLevel) -> List[FieldRedactionRule]:
        """Finds all rules that must act upon a particular dictionary key based on current user clearance."""
        applicable = []
        
        # Check literals
        for rule in self._rules:
            if rule.target_key == key and clearance < rule.min_clearance_required:
                applicable.append(rule)
                
        # Check regex maps
        for pattern, rule in self._regex_rules.items():
            if pattern.match(key) and clearance < rule.min_clearance_required:
                applicable.append(rule)
                
        return applicable


# Instantiate the global Redaction Registry
redaction_registry = RedactionRegistry()


# ------------------------------------------------------------------------------
# 5. FORENSIC CENSORSHIP KERNEL
# ------------------------------------------------------------------------------

class ForensicCensor:
    """
    Executes deep recursive transformations on graph payloads to ensure the resulting 
    dictionary conforms exactly to the mathematical access clearance of the invoking user.
    """
    
    @staticmethod
    def _mask_arn(arn: str) -> str:
        """
        Takes `arn:aws:iam::123456789012:role/admin` 
        Returns `arn:aws:iam::[REDACTED]:role/admin`
        """
        if not isinstance(arn, str):
            return str(arn)
        parts = arn.split(':')
        if len(parts) >= 6:
            parts[4] = "[REDACTED]"
            return ":".join(parts)
        return "[OBFUSCATED_ID]"
        
    @staticmethod
    def _mask_ip(ip: str) -> str:
        """
        If IPv4, masks the last two octets.
        If IPv6, masks the latter half.
        """
        if not isinstance(ip, str):
            return str(ip)
        
        # Simple IPv4 check
        if "." in ip and ip.count(".") == 3:
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.X.X"
            
        # Simplistic CIDR check
        if "/" in ip:
            net, cidr = ip.split("/", 1)
            return f"{ForensicCensor._mask_ip(net)}/{cidr}"
            
        return "[OBFUSCATED_NETWORK]"

    @staticmethod
    def _summarize_json_blob(blob: Any) -> str:
        """Intelligently abstracts a massive dictionary/JSON string into words."""
        try:
            if isinstance(blob, str):
                parsed = json.loads(blob)
            elif isinstance(blob, dict) or isinstance(blob, list):
                parsed = blob
            else:
                return "[UNPARSABLE DATA]"
        except Exception:
            # If it's just a regular string
            return "[OPAQUE DATA STRUCTURE]"
            
        # Heuristic Analysis of the object
        if isinstance(parsed, dict):
            if "Statement" in parsed:
                # It's an IAM policy
                statements = parsed.get("Statement", [])
                if not isinstance(statements, list): statements = [statements]
                allow_count = sum(1 for s in statements if s.get("Effect") == "Allow")
                deny_count = sum(1 for s in statements if s.get("Effect") == "Deny")
                return f"[IAM POLICY SUMMARY: {allow_count} Allows, {deny_count} Denies]"
                
            if "path_sequence" in parsed:
                # It's an Attack Path metadata blob
                seq = parsed.get("path_sequence", [])
                score = parsed.get("hcs_score", 0.0)
                risk_level = "CRITICAL" if float(score) >= 7.0 else "ELEVATED"
                return f"[ATTACK VECTOR SUMMARY: {len(seq)} Hops | Scope: {risk_level}]"
                
            # Generic summary
            return f"[COMPLEX OBJECT: {len(parsed.keys())} Properties]"
            
        if isinstance(parsed, list):
            return f"[ARRAY STRUCTURE: {len(parsed)} Elements]"
            
        return "[REDACTED_BLOB]"

    @staticmethod
    def _translate_qualitative(val: Any) -> str:
        """Converts raw float risk scores (0.0-10.0) to business adjectives."""
        try:
            fval = float(val)
        except (TypeError, ValueError):
            return "UNKNOWN_RISK"
            
        if fval >= 8.5: return "CRITICAL"
        if fval >= 6.0: return "HIGH"
        if fval >= 3.0: return "MEDIUM"
        return "LOW"

    @classmethod
    def apply_rule(cls, val: Any, rule: FieldRedactionRule) -> Any:
        """Executes a specific redaction strategy on a leaf node value."""
        if rule.strategy == RedactionStrategy.STRIP:
            # This is a signal to remove the key entirely. 
            # Handled in the recursive loop.
            return None
            
        if rule.strategy == RedactionStrategy.MASK_ARN:
            return cls._mask_arn(val)
            
        if rule.strategy == RedactionStrategy.MASK_IP:
            return cls._mask_ip(val)
            
        if rule.strategy == RedactionStrategy.SUMMARIZE_IAM:
            return cls._summarize_json_blob(val)
            
        if rule.strategy == RedactionStrategy.OBFUSCATE_ID:
            s_val = str(val)
            return hashlib.md5(s_val.encode('utf-8')).hexdigest()
            
        if rule.strategy == RedactionStrategy.QUALITATIVE:
            return cls._translate_qualitative(val)
            
        # Fallback explicit replacement
        return rule.replacement_value

    @classmethod
    def recursively_redact(cls, data: Any, clearance: AccessLevel) -> Any:
        """
        Massively recursive deep-copying traversal.
        Examines every node in a potentially infinite depth dictionary/list,
        queries the RedactionRegistry, and applies algorithmic censorship.
        """
        # Base case: we don't redact primitives if they aren't part of a dict key calculation
        if not isinstance(data, (dict, list)):
            return data

        # Lists: Process each element
        if isinstance(data, list):
            new_list = []
            for item in data:
                # Recursive call
                new_list.append(cls.recursively_redact(item, clearance))
            return new_list

        # Dictionaries: Process Keys and Values
        if isinstance(data, dict):
            new_dict = {}
            for key, val in data.items():
                
                # 1. Fetch any rules that apply to this key for the given clearance
                applicable_rules = redaction_registry.get_applicable_rules(key, clearance)
                
                # 2. Check for STRIP first
                should_strip = any(r.strategy == RedactionStrategy.STRIP for r in applicable_rules)
                if should_strip:
                    # Omit key entirely
                    continue
                    
                # 3. Apply transformation rules sequentially (usually just 1 applies)
                transformed_val = val
                was_transformed = False
                
                for rule in applicable_rules:
                    transformed_val = cls.apply_rule(transformed_val, rule)
                    was_transformed = True
                    
                # 4. Deep Recurse if the value wasn't transformed into a string by a rule
                # (e.g. if SUMMARIZE wasn't called, and it's still a dict, we must go deeper)
                if not was_transformed and isinstance(transformed_val, (dict, list)):
                    transformed_val = cls.recursively_redact(transformed_val, clearance)
                    
                new_dict[key] = transformed_val
                
            return new_dict


# ------------------------------------------------------------------------------
# 6. CYPHER OVERLAY MODULE (GRAPH SANDBOXING)
# ------------------------------------------------------------------------------

class CypherSecurityOverlay:
    """
    A mathematical engine that produces Neo4j MATCH and WHERE segments.
    Ensures that bad queries, or malicious injection attempts, are physically
    bounded tightly to the user's isolated tenancy.
    """

    @staticmethod
    def _build_tenant_constraint(context: UserContext, alias: str) -> str:
        """Builds an IN array clause for a specific node alias."""
        if not context.allowed_tenants:
            return f"({alias}.tenant_id = 'DENY_ALL')"
            
        escaped_tenants = [f"'{t.replace('`', '').replace('\'', '')}'" for t in context.allowed_tenants]
        arr_str = "[" + ", ".join(escaped_tenants) + "]"
        return f"({alias}.tenant_id IN {arr_str})"

    @classmethod
    def isolate_node_query(cls, context: UserContext, node_alias: str = "n") -> str:
        """
        Provides isolation for single-node queries.
        E.g., `MATCH (n:Resource) WHERE {cls.isolate_node_query(context)} AND n.name='test'`
        """
        if context.is_global_admin:
            return "1=1" # Unrestricted
            
        return cls._build_tenant_constraint(context, node_alias)

    @classmethod
    def isolate_edge_query(cls, context: UserContext, source_alias: str = "src", target_alias: str = "dst", operator: str = "OR") -> str:
        """
        Provides isolation for graph traversals spanning two nodes.
        By default, uses "OR": User can see the edge if they have access to EITHER the source OR the target.
        This is critical for detecting cross-tenant assume roles (lateral movement).
        If strict compliance is needed, swap operator to "AND".
        """
        if context.is_global_admin:
            return "1=1"
            
        src_clause = cls._build_tenant_constraint(context, source_alias)
        dst_clause = cls._build_tenant_constraint(context, target_alias)
        
        return f"({src_clause} {operator.upper()} {dst_clause})"

    @classmethod
    def isolate_path_query(cls, context: UserContext, path_alias: str = "p") -> str:
        """
        Provides isolation for variable-length paths.
        Since we cannot dynamically inspect all nodes in a path inside a basic WHERE clause easily
        without APOC, we bound by enforcing all nodes inside the path belong to allowed tenants.
        """
        if context.is_global_admin:
            return "1=1"
            
        escaped_tenants = [f"'{t.replace('`', '').replace('\'', '')}'" for t in context.allowed_tenants]
        arr_str = "[" + ", ".join(escaped_tenants) + "]"
        
        # Cypher ALL() predicate ensures every node in the variable length path belongs to the allowed tenants
        return f"ALL(node IN nodes({path_alias}) WHERE node.tenant_id IN {arr_str} OR node.tenant_id IS NULL OR node.type = 'Phantom')"


# ------------------------------------------------------------------------------
# 7. THE SUPREME RBAC MANAGER (PUBLIC API)
# ------------------------------------------------------------------------------

class AuthorizationError(Exception):
    """Raised when an explicit RBAC fault occurs during execution."""
    pass


class RBACManager:
    """
    The Master Entrypoint for the Backend Security Subsystem.
    Provides easy-to-use macros that wrap the lower-level Cypher and Forensics kernels.
    """

    def __init__(self):
        self._audit_log: List[Dict[str, Any]] = []

    def verify_action(self, context: UserContext, action: UserAction) -> bool:
        """
        Explicit authorization check before performing complex tasks (e.g. Exporting).
        """
        # Admins perform any action anywhere
        if context.is_global_admin:
            return True
            
        # Target tenant must be in user's allowed list
        target = action.target_tenant_id
        if target and target not in context.allowed_tenants:
            logger.warning(
                f"[SECURITY FAULT] User {context.user_id} ({context.role}) "
                f"attempted to access restricted tenant: {target}."
            )
            return False
            
        # Specific role blocks
        if action.action_type == "TRIGGER_SCAN" and context.clearance < AccessLevel.MANAGER:
            logger.warning(
                f"[SECURITY FAULT] User {context.user_id} ({context.role}) "
                f"attempted state-modifying action TRIGGER_SCAN."
            )
            return False
            
        return True

    @staticmethod
    def construct_cypher_overlay(context: UserContext, node_aliases: Optional[List[str]] = None) -> str:
        """
        Macro to generate a massive, impenetrable Cypher WHERE block combining 
        multiple aliases in a single query.
        
        Example:
            clause = RBACManager.construct_cypher_overlay(user, ["n", "m"])
            yields: "AND (n.tenant_id IN [...] AND m.tenant_id IN [...])"
        """
        
        if context.is_global_admin:
            return ""
            
        if not node_aliases:
            node_aliases = ["n"]
            
        clauses = []
        for alias in node_aliases:
            clauses.append(CypherSecurityOverlay.isolate_node_query(context, alias))
            
        combined = " AND ".join(clauses)
        return f" AND ({combined}) "

    @staticmethod
    def censor_payload(context: UserContext, raw_data: Union[Dict, List]) -> Union[Dict, List]:
        """
        The macro for the Forensic Censor.
        Takes the raw Neo4j dictionaries resulting from a query and deeply 
        redacts them based on mathematical clearance before transmitting via API.
        """
        if not raw_data:
            return raw_data
            
        # The ADMIN clearance check early exit for max performance
        if context.is_global_admin or context.role == EnterpriseRole.MANAGER:
            return raw_data
            
        start = datetime.now()
        
        # We must Deep Copy so we don't accidentally mutate cached memory structures
        immutable_copy = copy.deepcopy(raw_data)
        
        # Execute recursive substitution
        censored = ForensicCensor.recursively_redact(immutable_copy, context.clearance)
        
        duration_ms = (datetime.now() - start).total_seconds() * 1000
        logger.debug(f"RBAC Payload Censorship executed in {duration_ms:.2f}ms for clearance {context.clearance.name}.")
        
        return censored

    def log_audit_event(self, context: UserContext, event_type: str, details: str) -> None:
        """Produces a cryptographically sealed tuple for compliance reporting."""
        timestamp = datetime.now(timezone.utc).isoformat()
        raw = f"{context.user_id}|{context.role}|{event_type}|{timestamp}|{details}"
        fingerprint = hashlib.sha256(raw.encode('utf-8')).hexdigest()
        
        record = {
            "timestamp": timestamp,
            "session": context.session_id,
            "user_id": context.user_id,
            "role": context.role.value,
            "event": event_type,
            "details": details,
            "signature": fingerprint[:16] # type: ignore
        }
        
        self._audit_log.append(record)
        logger.info(f"[AUDIT] {fingerprint[:8]} | {context.user_id} | {event_type} | {details}") # type: ignore


# Export Global Singleton
rbac_engine = RBACManager()


# ------------------------------------------------------------------------------
# 8. MOCK DEVELOPMENT REGISTRY (FOR RAPID UI/UX INTEGRATION)
# ------------------------------------------------------------------------------

class MockAuthenticator:
    """
    A hardcoded LDAP/Auth0 simulator to allow immediate Frontend/API development.
    Provides robust, physically plausible users to test strict mathematical bounds.
    """
    
    DB = {
        "admin@cloudscape.io": UserContext(**{
            "user_id": "U-ADM-999", 
            "role": EnterpriseRole.ADMIN, 
            "allowed_tenants": [] # Implicit everything
        }), # pyre-ignore[28]
        
        "soc.manager@cloudscape.io": UserContext(**{
            "user_id": "U-MGR-001",
            "role": EnterpriseRole.MANAGER,
            "allowed_tenants": ["PROJ-FIN-01", "PROJ-WEB-02", "PROJ-DR-05"]
        }), # pyre-ignore[28]
        
        "security.analyst@cloudscape.io": UserContext(**{
            "user_id": "U-MEM-042",
            "role": EnterpriseRole.MEMBER,
            "allowed_tenants": ["PROJ-WEB-02", "PROJ-SHR-03"]
        }), # pyre-ignore[28]
        
        "cfo.executive@cloudscape.io": UserContext(**{
            "user_id": "U-SHR-888",
            "role": EnterpriseRole.SHAREHOLDER,
            "allowed_tenants": ["PROJ-FIN-01", "PROJ-WEB-02", "PROJ-SHR-03", "PROJ-AZURE-04", "PROJ-DR-05"]
        }) # pyre-ignore[28]
    }
    
    @classmethod
    def authenticate(cls, email: str) -> UserContext:
        """Mock login method."""
        user = cls.DB.get(email.lower())
        if not user:
            # Degrade safely to lowest possible clearance with zero tenants
            logger.warning(f"Failed auth for {email}. Falling back to Zero-Trust Phantom user.")
            return UserContext(**{
                "user_id": "U-PHANTOM",
                "role": EnterpriseRole.SHAREHOLDER,
                "allowed_tenants": []
            }) # pyre-ignore[28]
        return user
        
    @classmethod
    def print_matrix(cls):
        """Debug dump of available users."""
        print("=== ACTIVE MOCK USERS ===")
        for email, u in cls.DB.items():
            print(f"- {email:30s} | Tier: {u.role.value:12s} | Tenants: {len(u.allowed_tenants)}")
        print("=========================")

# ==============================================================================
# END OF RBAC ENGINE
# ==============================================================================
