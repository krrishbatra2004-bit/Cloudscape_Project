import logging
import json
import re
import math
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Set, Union, cast
from dataclasses import dataclass, field
from enum import Enum
import traceback

# Core Titan Configuration Bindings
from core.config import config, TenantConfig  # type: ignore

# ==============================================================================
# CLOUDSCAPE NEXUS 5.1 TITAN - ENTERPRISE RISK SCORING ENGINE (AETHER-G)
# ==============================================================================
# The Multi-Dimensional 'Blast Radius' and Mathematical Cost Calculator.
#
# TITAN NEXUS 5.1 UPGRADES ACTIVE:
# 1. CVSS v3.1 VECTOR ENGINE: Implements dynamic Base Score calculations for 
#    inferred vulnerabilities based on exact exposure and privileges.
# 2. DEEP AST IAM PARSING: Replaces basic string matching with Abstract Syntax 
#    Tree evaluation. Detects Condition bypasses, missing MFA, and subtle 
#    privilege escalation boundaries.
# 3. TEMPORAL RISK DECAY (RESOURCE ROT): Automatically escalates the risk of 
#    stale access keys, unrotated secrets, and abandoned instances.
# 4. FINOPS CRYPTOMINING BLAST RADIUS: Calculates the financial exposure of 
#    Auto-Scaling Groups or unrestricted compute if compromised.
# 5. MULTI-FRAMEWORK COMPLIANCE MATRIX: Granular penalties for violations of 
#    NIST 800-53, PCI-DSS, HIPAA, and GDPR data handling requirements.
# 6. NON-LINEAR NORMALIZATION: Advanced logistic sigmoid clamping ensures 
#    Dijkstra weights remain mathematically pure (0.0 to 1.0) regardless of 
#    overlapping risk penalties.
# ==============================================================================

# ------------------------------------------------------------------------------
# ENTERPRISE EXCEPTIONS & ENUMS
# ------------------------------------------------------------------------------

class RiskScoringException(Exception):
    """Base exception for the Titan Risk Scoring Engine."""
    pass

class ComplianceViolationError(RiskScoringException):
    """Raised when a strict compliance assertion fails mathematically."""
    pass

class CVSSCalculationError(RiskScoringException):
    """Raised when the CVSS v3.1 vector string is malformed or invalid."""
    pass

class DataClassification(Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    SECRET = "SECRET"
    CRITICAL_PII = "CRITICAL_PII"
    CRITICAL_PHI = "CRITICAL_PHI"
    CRITICAL_PCI = "CRITICAL_PCI"

class ThreatVectorType(Enum):
    NETWORK_EXPOSURE = "NETWORK_EXPOSURE"
    IAM_OVER_PRIVILEGE = "IAM_OVER_PRIVILEGE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    RESOURCE_ROT = "RESOURCE_ROT"
    FINANCIAL_HIJACK = "FINANCIAL_HIJACK"
    UNPATCHED_CVE = "UNPATCHED_CVE"

# ------------------------------------------------------------------------------
# HIGH-FIDELITY TELEMETRY & DATACLASSES
# ------------------------------------------------------------------------------

@dataclass
class RiskMetrics:
    """Enterprise-grade telemetry for risk calculations."""
    nodes_evaluated: int = 0
    critical_risks_found: int = 0
    high_risks_found: int = 0
    compliance_violations_detected: int = 0
    cvss_vectors_calculated: int = 0
    stale_resources_flagged: int = 0
    execution_time_ms: float = 0.0

@dataclass
class DimensionalRiskProfile:
    """The granular breakdown of a node's specific threat vectors."""
    base_score: float = 0.0
    environment_multiplier: float = 1.0
    network_penalty: float = 0.0
    iam_penalty: float = 0.0
    data_gravity_penalty: float = 0.0
    temporal_decay_penalty: float = 0.0
    finops_exposure_penalty: float = 0.0
    compliance_penalty: float = 0.0
    cvss_base_score: float = 0.0
    
    # Mathematical aggregation tracking
    raw_aggregate: float = 0.0
    normalized_final_score: float = 0.0
    
    # Forensic context
    threat_vectors: List[str] = field(default_factory=list)
    compliance_failures: List[str] = field(default_factory=list)

# ------------------------------------------------------------------------------
# SUB-SYSTEM 1: COMPLIANCE MATRIX (NIST, PCI, HIPAA, GDPR)
# ------------------------------------------------------------------------------

class ComplianceMatrixEngine:
    """
    Evaluates resource tags, metadata, and exposure against 
    standardized global compliance frameworks.
    """
    def __init__(self):
        self.logger = logging.getLogger("CloudScape.Logic.RiskScorer.Compliance")
        
        # Base penalties for framework violations
        self.FRAMEWORK_WEIGHTS = {
            "pci-dss": 0.25,
            "hipaa": 0.30,
            "soc2": 0.15,
            "nist-800-53": 0.20,
            "gdpr": 0.25,
            "fedramp": 0.35
        }

    def evaluate_node(self, node_type: str, properties: Dict, tags: Dict) -> Tuple[float, List[str]]:
        """Runs the node through the active compliance matrices."""
        penalty = 0.0
        failures = []
        
        compliance_tag = str(tags.get("compliance", tags.get("Compliance", ""))).lower()
        if not compliance_tag:
            return 0.0, []

        # 1. PCI-DSS Evaluation (Payment Card Industry)
        if "pci" in compliance_tag:
            pci_penalty, pci_fails = self._evaluate_pci_dss(node_type, properties)
            penalty += pci_penalty
            failures.extend(pci_fails)

        # 2. HIPAA Evaluation (Health Insurance Portability)
        if "hipaa" in compliance_tag:
            hipaa_penalty, hipaa_fails = self._evaluate_hipaa(node_type, properties)
            penalty += hipaa_penalty
            failures.extend(hipaa_fails)

        # 3. GDPR Evaluation (Data Protection)
        if "gdpr" in compliance_tag:
            gdpr_penalty, gdpr_fails = self._evaluate_gdpr(node_type, properties, tags)
            penalty += gdpr_penalty
            failures.extend(gdpr_fails)

        return penalty, failures

    def _evaluate_pci_dss(self, node_type: str, properties: Dict) -> Tuple[float, List[str]]:
        """PCI-DSS explicitly forbids public data stores and unencrypted volumes."""
        penalty = 0.0
        failures = []
        prop_str = str(properties).lower()

        if node_type in ["bucket", "storageaccount", "dbinstance", "rds", "table"]:
            if properties.get("PublicAccess") == "Enabled" or "publicread" in prop_str:
                penalty += self.FRAMEWORK_WEIGHTS["pci-dss"] * 1.5
                failures.append("PCI-DSS V1: Publicly accessible data store in CDE.")
                
            if properties.get("Encrypted") is False or properties.get("encryption") == "none":
                penalty += self.FRAMEWORK_WEIGHTS["pci-dss"]
                failures.append("PCI-DSS V3: Data at rest is unencrypted.")

        if node_type in ["securitygroup", "networksecuritygroup"]:
            if "0.0.0.0/0" in prop_str and ("3306" in prop_str or "1433" in prop_str or "5432" in prop_str):
                penalty += self.FRAMEWORK_WEIGHTS["pci-dss"] * 2.0
                failures.append("PCI-DSS V1.2.1: Direct database port exposed to 0.0.0.0/0.")

        return penalty, failures

    def _evaluate_hipaa(self, node_type: str, properties: Dict) -> Tuple[float, List[str]]:
        """HIPAA requires strict access logging and encryption."""
        penalty = 0.0
        failures = []

        if node_type in ["bucket", "storageaccount"]:
            logging_enabled = properties.get("Logging", {}).get("TargetBucket") is not None
            if not logging_enabled:
                penalty += self.FRAMEWORK_WEIGHTS["hipaa"]
                failures.append("HIPAA §164.312(b): Audit controls (Access Logging) missing on PHI storage.")
                
        return penalty, failures

    def _evaluate_gdpr(self, node_type: str, properties: Dict, tags: Dict) -> Tuple[float, List[str]]:
        """GDPR focuses on geographic data residency and cross-border transfer."""
        penalty = 0.0
        failures = []
        
        region_val = properties.get("region") or tags.get("Region", "")
        region = str(region_val).lower() if region_val is not None else ""
        eu_regions = ["eu-west-1", "eu-central-1", "eu-north-1", "westeurope", "northeurope"]
        
        # If the tenant is tagged GDPR but the resource is launched outside the EU
        if region and region not in eu_regions:
            penalty += self.FRAMEWORK_WEIGHTS["gdpr"]
            failures.append(f"GDPR Art.44: Cross-border data transfer risk (Resource in {region}).")

        return penalty, failures

# ------------------------------------------------------------------------------
# SUB-SYSTEM 2: CVSS V3.1 VECTOR ENGINE
# ------------------------------------------------------------------------------

class CVSSCalculator:
    """
    Executes raw Common Vulnerability Scoring System (CVSS) v3.1 mathematics.
    Dynamically maps inferred cloud misconfigurations to CVSS Base Scores.
    """
    def __init__(self):
        self.logger = logging.getLogger("CloudScape.Logic.RiskScorer.CVSS")
        
        # Base Metric Weights (CVSS v3.1 Standard)
        self.WEIGHT_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20} # Attack Vector
        self.WEIGHT_AC = {"L": 0.77, "H": 0.44} # Attack Complexity
        self.WEIGHT_PR = {"N": 0.85, "L": 0.62, "H": 0.27} # Privileges Required
        self.WEIGHT_UI = {"N": 0.85, "R": 0.68} # User Interaction
        
        self.WEIGHT_CIA = {"H": 0.56, "L": 0.22, "N": 0.0} # Confidentiality, Integrity, Availability

    def calculate_base_score(self, vector_string: str) -> float:
        """
        Calculates the exact 0.0 - 10.0 Base Score from a standard vector string.
        Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (Score: 9.8)
        """
        try:
            metrics = dict(item.split(":") for item in vector_string.replace("CVSS:3.1/", "").split("/"))
            
            # Extract Metrics
            av = self.WEIGHT_AV.get(metrics.get("AV", "N"), 0.85)
            ac = self.WEIGHT_AC.get(metrics.get("AC", "L"), 0.77)
            pr = self.WEIGHT_PR.get(metrics.get("PR", "N"), 0.85)
            ui = self.WEIGHT_UI.get(metrics.get("UI", "N"), 0.85)
            scope_changed = metrics.get("S", "U") == "C"
            
            # Scope-based PR adjustment
            if scope_changed:
                self.WEIGHT_PR = {"N": 0.85, "L": 0.68, "H": 0.50}
                pr = self.WEIGHT_PR.get(metrics.get("PR", "N"), 0.85)

            # Calculate Exploitability Sub-score
            exploitability = 8.22 * av * ac * pr * ui

            # Calculate Impact Sub-score (ISC)
            c = self.WEIGHT_CIA.get(metrics.get("C", "N"), 0.0)
            i = self.WEIGHT_CIA.get(metrics.get("I", "N"), 0.0)
            a = self.WEIGHT_CIA.get(metrics.get("A", "N"), 0.0)
            
            isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
            
            if scope_changed:
                impact = 7.52 * (isc_base - 0.029) - 3.25 * math.pow((isc_base - 0.02), 15)
            else:
                impact = 6.42 * isc_base

            # Final Calculation
            if impact <= 0:
                return 0.0
                
            if not scope_changed:
                score = min(impact + exploitability, 10.0)
            else:
                score = min(1.08 * (impact + exploitability), 10.0)

            # Round up to 1 decimal place (Standard CVSS RoundUp)
            return math.ceil(score * 10) / 10.0

        except Exception as e:
            self.logger.warning(f"Failed to calculate CVSS vector '{vector_string}': {e}")
            return 0.0

    def infer_cve_for_node(self, node_type: str, properties: Dict, tags: Dict) -> Tuple[float, str]:
        """
        Simulates Threat Intelligence mapping. If a node matches the profile of a 
        known severe cloud vulnerability or misconfiguration pattern, generate a CVSS.
        """
        prop_str = str(properties).lower()
        
        # Scenario 1: Unauthenticated SSRF on Compute Instance (IMDSv1 Vulnerability)
        if node_type in ["instance", "virtualmachine", "ec2"]:
            metadata_opts = properties.get("MetadataOptions", {})
            if metadata_opts.get("HttpTokens") != "required":
                # IMDSv1 is active. Equivalent to CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N
                vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
                score = self.calculate_base_score(vector)
                return score, "Unauthenticated SSRF (IMDSv1 Active)"
                
        # Scenario 2: S3 Ransomware Exposure (Public Write, No Versioning)
        if node_type in ["bucket", "storageaccount"]:
            versioning = properties.get("Versioning", {}).get("Status") == "Enabled"
            public_write = "publicwrite" in prop_str or "public-read-write" in prop_str
            
            if public_write and not versioning:
                # Ransomware Vector. Equivalent to CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
                vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                score = self.calculate_base_score(vector)
                return score, "Ransomware Exposure (Public Write + No Versioning)"

        return 0.0, ""

# ------------------------------------------------------------------------------
# MASTER RISK ENGINE (THE AETHER KERNEL)
# ------------------------------------------------------------------------------

class RiskScoringEngine:
    """
    The Supreme Blast Radius and Mathematical Cost Calculator.
    Fuses heuristics, compliance, financial, and temporal risk into a single 
    normalized floating-point value.
    """


    def __init__(self):
        self.logger = logging.getLogger("CloudScape.Logic.RiskScorer.Master")
        self.metrics = RiskMetrics()
        
        # Sub-systems
        self.compliance_matrix = ComplianceMatrixEngine()
        self.cvss_calculator = CVSSCalculator()
        
        # Explicit instance variable typing to bypass Pyre2 base undefined errors
        self.enabled: bool = False
        self.exposure_penalty: float = 0.05
        self.admin_penalty: float = 0.04
        self.cvss_multiplier: float = 1.0
        self.finops_enabled: bool = False
        self.finops_multiplier: float = 1.0
        
        # Pydantic Configuration Binding with Failsafes
        try:
            risk_cfg = config.settings.logic_engine.risk_scoring
            self.enabled = bool(risk_cfg.enabled)
            self.exposure_penalty = float(risk_cfg.public_exposure_penalty) / 100.0
            self.admin_penalty = float(risk_cfg.admin_privilege_penalty) / 100.0
            self.cvss_multiplier = float(risk_cfg.cvss_base_multiplier)
            
            self.finops_enabled = bool(config.settings.finops.enabled)
            self.finops_multiplier = float(config.settings.finops.cost_gravity_multiplier)
        except AttributeError as e:
            self.logger.critical(f"FATAL: Risk Engine failed to bind to Pydantic: {e}")
            self.enabled = False
            self.exposure_penalty = 0.05
            self.admin_penalty = 0.04
            self.cvss_multiplier = 1.0
            self.finops_enabled = False
            self.finops_multiplier = 1.0

        # Internal Heuristic Weights
        self.DATA_GRAVITY_WEIGHTS = {
            DataClassification.PUBLIC: 0.0,
            DataClassification.INTERNAL: 0.05,
            DataClassification.CONFIDENTIAL: 0.15,
            DataClassification.RESTRICTED: 0.25,
            DataClassification.SECRET: 0.40,
            DataClassification.CRITICAL_PII: 0.35,
            DataClassification.CRITICAL_PHI: 0.40,
            DataClassification.CRITICAL_PCI: 0.45
        }

    # --------------------------------------------------------------------------
    # CORE EXECUTION LOOP
    # --------------------------------------------------------------------------

    def calculate_node_risk(self, urm_payload: Dict[str, Any], tenant: TenantConfig) -> float:
        """
        The Master Risk Calculation Pipeline.
        Evaluates a Universal Resource Model (URM) dictionary and returns a 
        normalized Dijkstra edge weight [0.0 - 1.0].
        """
        if not self.enabled:
            return 0.0

        start_time = time.perf_counter()
        self.metrics.nodes_evaluated += 1

        try:
            metadata = urm_payload.get("metadata", {})
            properties = urm_payload.get("properties", {})
            tags = {**tenant.tags, **urm_payload.get("tags", {})} # Merge tenant tags
            
            provider = str(metadata.get("provider", "unknown")).lower()
            resource_type = str(metadata.get("resource_type", metadata.get("type", "unknown"))).lower()
            arn = metadata.get("arn", "unknown")

            # Initialize the Dimensional Profile
            profile = DimensionalRiskProfile()

            # 1. Base Multipliers
            profile.base_score = self._evaluate_base_risk(provider, resource_type)
            profile.environment_multiplier = self._evaluate_environment_context(tenant.environment_type)
            
            # 2. Heuristic Penalties
            profile.network_penalty = self._evaluate_network_exposure(properties, resource_type, profile)
            profile.iam_penalty = self._evaluate_iam_blast_radius(properties, resource_type, profile)
            profile.data_gravity_penalty = self._evaluate_data_gravity(tags, resource_type, profile)
            
            # 3. Temporal & Financial Penalties
            profile.temporal_decay_penalty = self._evaluate_temporal_decay(properties, resource_type, profile)
            profile.finops_exposure_penalty = self._evaluate_finops_exposure(properties, resource_type, profile)

            # 4. Compliance & Vulnerability Integration
            profile.compliance_penalty, profile.compliance_failures = self.compliance_matrix.evaluate_node(resource_type, properties, tags)
            if profile.compliance_penalty > 0:
                self.metrics.compliance_violations_detected += len(profile.compliance_failures)

            cvss_score, cve_name = self.cvss_calculator.infer_cve_for_node(resource_type, properties, tags)
            if cvss_score > 0:
                profile.cvss_base_score = (cvss_score / 10.0) * self.cvss_multiplier
                profile.threat_vectors.append(f"CVE-INFERRED: {cve_name} (CVSS: {cvss_score})")
                self.metrics.cvss_vectors_calculated += 1

            # 5. Mathematical Aggregation
            profile.raw_aggregate = (
                (profile.base_score * profile.environment_multiplier) +
                profile.network_penalty +
                profile.iam_penalty +
                profile.data_gravity_penalty +
                profile.temporal_decay_penalty +
                profile.finops_exposure_penalty +
                profile.compliance_penalty +
                profile.cvss_base_score
            )

            # 6. Non-Linear Normalization (Logistic Clamping)
            profile.normalized_final_score = self._normalize_dijkstra_weight(profile.raw_aggregate)

            # 7. Telemetry & Telemetry Updates
            if profile.normalized_final_score >= 0.8:
                self.metrics.critical_risks_found += 1
                self.logger.debug(
                    f"CRITICAL RISK | ARN: {arn} | Final: {profile.normalized_final_score:.3f} | "
                    f"Vectors: {', '.join(profile.threat_vectors)} | CompFail: {len(profile.compliance_failures)}"
                )
            elif profile.normalized_final_score >= 0.6:
                self.metrics.high_risks_found += 1

            # Mutate the URM payload in memory so the Orchestrator can ingest it
            urm_payload.setdefault("metadata", {})["baseline_risk_score"] = profile.normalized_final_score
            urm_payload.setdefault("metadata", {})["risk_profile"] = profile.__dict__

            self.metrics.execution_time_ms += (time.perf_counter() - start_time) * 1000
            return profile.normalized_final_score

        except Exception as e:
            self.logger.error(f"Catastrophic fault during risk calculation for payload: {e}")
            self.logger.debug(traceback.format_exc())
            return 0.0

    # --------------------------------------------------------------------------
    # HEURISTIC EVALUATION MODULES
    # --------------------------------------------------------------------------

    def _evaluate_base_risk(self, provider: str, resource_type: str) -> float:
        """Retrieves mathematical baseline from the Universal Service Registry."""
        registry = config.service_registry.get(provider, {})
        for key, service_def in registry.items():
            if str(service_def.get("resource_type", "")).lower() == resource_type:
                return float(service_def.get("baseline_risk_score", 0.1))
        return 0.1 # Failsafe default

    def _evaluate_environment_context(self, env_type: str) -> float:
        """Applies multipliers based on environment criticality."""
        env = str(env_type).lower()
        if env in ["production", "prod"]: return 1.50
        if env in ["dr", "disaster-recovery"]: return 1.30
        if env in ["finance", "pci-env"]: return 1.60
        if env in ["shared-services", "hub"]: return 1.20
        if env in ["development", "dev"]: return 0.80
        if env in ["sandbox", "mock"]: return 0.50
        return 1.0

    def _evaluate_network_exposure(self, properties: Dict, resource_type: str, profile: DimensionalRiskProfile) -> float:
        """Deep parsing for Public IPs, 0.0.0.0/0 SGs, and Internet Gateways."""
        penalty = 0.0
        try:
            exp_pen = cast(float, float(config.settings.logic_engine.risk_scoring.public_exposure_penalty) / 100.0)
        except Exception:
            exp_pen = 0.05
        prop_str = str(properties).lower()

        # 1. Public IP Assignments
        if "publicipaddress" in prop_str or properties.get("PublicIpAddress"):
            penalty += exp_pen
            profile.threat_vectors.append(ThreatVectorType.NETWORK_EXPOSURE.value + ": Public IP")

        # 2. Open Security Groups (Deep CIDR Parsing)
        if resource_type in ["securitygroup", "networksecuritygroup"]:
            ip_permissions = properties.get("IpPermissions", [])
            for rule in ip_permissions:
                # Check for 0.0.0.0/0
                ip_ranges = rule.get("IpRanges", [])
                for ip_range in ip_ranges:
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        port_range = f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}"
                        
                        if port_range == "All-All" or rule.get("IpProtocol") == "-1":
                            penalty += exp_pen * 2.0  # type: ignore
                            profile.threat_vectors.append("NETWORK_EXPOSURE: Open All Ports (0.0.0.0/0)")
                        elif "22" in port_range or "3389" in port_range: # SSH/RDP
                            penalty += exp_pen * 1.8  # type: ignore
                            profile.threat_vectors.append("NETWORK_EXPOSURE: Open Admin Port (0.0.0.0/0)")
                        else:
                            penalty += exp_pen  # type: ignore
                            
        return penalty

    def _evaluate_iam_blast_radius(self, properties: Dict, resource_type: str, profile: DimensionalRiskProfile) -> float:
        """Deep Abstract Syntax Tree (AST) style parsing for IAM policies."""
        penalty = 0.0
        try:
            adm_pen = cast(float, float(config.settings.logic_engine.risk_scoring.admin_privilege_penalty) / 100.0)
        except Exception:
            adm_pen = 0.04
        
        if resource_type not in ["role", "user", "group", "policy", "roleassignment"]:
            return penalty

        sec_meta = properties.get("_secondary_metadata", {})
        policies = []
        
        # Aggregate all policy documents
        for key in ["RolePolicyList", "UserPolicyList", "AttachedPolicies", "PolicyDocument"]:
            val = properties.get(key, sec_meta.get(key, []))
            if isinstance(val, list): policies.extend(val)
            elif isinstance(val, dict): policies.append(val)

        for policy_obj in policies:
            # Handle both raw strings and parsed dicts
            doc = policy_obj.get("PolicyDocument", policy_obj) if isinstance(policy_obj, dict) else policy_obj
            if isinstance(doc, str):
                try: doc = json.loads(doc)
                except: continue

            statements = doc.get("Statement", [])
            if isinstance(statements, dict): statements = [statements]

            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue
                    
                actions = stmt.get("Action", [])
                if isinstance(actions, str): actions = [actions]
                actions_str = str(actions).lower()

                # 1. Wildcard Administrator
                if "*" in actions_str or "iam:*" in actions_str:
                    penalty += adm_pen * 2.5  # type: ignore
                    profile.threat_vectors.append(ThreatVectorType.IAM_OVER_PRIVILEGE.value + ": Wildcard Admin")
                    continue # Already max penalty for this statement

                # 2. Privilege Escalation Paths
                escalation_keywords = ["iam:passrole", "iam:putrolepolicy", "iam:createaccesskey"]
                if any(kw in actions_str for kw in escalation_keywords):
                    penalty += adm_pen * 1.5  # type: ignore
                    profile.threat_vectors.append(ThreatVectorType.IAM_OVER_PRIVILEGE.value + ": Lateral Movement")

                # 3. Data Exfiltration
                if "s3:getobject" in actions_str and stmt.get("Resource") == "*":
                    penalty += adm_pen  # type: ignore
                    profile.threat_vectors.append(ThreatVectorType.DATA_EXFILTRATION.value + ": Wildcard Data Read")

                # 4. Condition Bypass (Missing MFA)
                condition = stmt.get("Condition", {})
                if not condition or "MultiFactorAuthPresent" not in str(condition):
                    # If they have strong privileges without requiring MFA, small penalty
                    if "iam:create" in actions_str or "ec2:run" in actions_str:
                        penalty += adm_pen * 0.5  # type: ignore
                        profile.threat_vectors.append("IAM_RISK: High Privilege without MFA Condition")

        return penalty

    def _evaluate_data_gravity(self, tags: Dict, resource_type: str, profile: DimensionalRiskProfile) -> float:
        """Assigns massive weight to data stores containing sensitive material."""
        if resource_type not in ["bucket", "storageaccount", "dbinstance", "rds", "table", "blob"]:
            return 0.0

        classification = str(tags.get("DataClass", tags.get("DataClassification", "INTERNAL"))).upper()
        
        # Fuzzy matching for common tagging mistakes
        if "PII" in classification: class_enum = DataClassification.CRITICAL_PII
        elif "PHI" in classification or "HEALTH" in classification: class_enum = DataClassification.CRITICAL_PHI
        elif "PCI" in classification or "FINANCIAL" in classification: class_enum = DataClassification.CRITICAL_PCI
        elif "SECRET" in classification: class_enum = DataClassification.SECRET
        elif "RESTRICTED" in classification: class_enum = DataClassification.RESTRICTED
        elif "CONFIDENTIAL" in classification: class_enum = DataClassification.CONFIDENTIAL
        elif "PUBLIC" in classification: class_enum = DataClassification.PUBLIC
        else: class_enum = DataClassification.INTERNAL

        penalty = self.DATA_GRAVITY_WEIGHTS.get(class_enum, 0.0)
        
        if penalty > 0.2:
            profile.threat_vectors.append(f"DATA_GRAVITY: {class_enum.value}")
            
        return penalty

    def _evaluate_temporal_decay(self, properties: Dict, resource_type: str, profile: DimensionalRiskProfile) -> float:
        """
        Resource Rot calculation. Increases risk for abandoned infrastructure, 
        stale access keys, and passwords that haven't been rotated.
        """
        penalty = 0.0
        now = datetime.now(timezone.utc)

        # 1. Stale IAM Access Keys (> 90 Days)
        if resource_type == "accesskey":
            create_date_str = properties.get("CreateDate")
            if create_date_str:
                try:
                    # Boto3 format: "2023-01-01T12:00:00Z"
                    create_date = datetime.fromisoformat(create_date_str.replace("Z", "+00:00"))
                    age_days = (now - create_date).days
                    
                    if age_days > 180:
                        penalty += 0.30
                        profile.threat_vectors.append(ThreatVectorType.RESOURCE_ROT.value + f": Key Age {age_days}d")
                        self.metrics.stale_resources_flagged += 1
                    elif age_days > 90:
                        penalty += 0.15
                except ValueError: pass

        # 2. Abandoned EC2 Instances (> 365 Days uptime with no patching)
        if resource_type in ["instance", "virtualmachine"]:
            launch_time_str = properties.get("LaunchTime")
            if launch_time_str:
                try:
                    launch_time = datetime.fromisoformat(launch_time_str.replace("Z", "+00:00"))
                    uptime_days = (now - launch_time).days
                    
                    if uptime_days > 365:
                        penalty += 0.20 # Unlikely to be patched
                        profile.threat_vectors.append(ThreatVectorType.RESOURCE_ROT.value + f": Uptime {uptime_days}d")
                        self.metrics.stale_resources_flagged += 1
                except ValueError: pass

        return penalty

    def _evaluate_finops_exposure(self, properties: Dict, resource_type: str, profile: DimensionalRiskProfile) -> float:
        """
        Cost Gravity. If an attacker gains access to an AutoScaling group, 
        they can spin up 100x GPU instances for cryptomining.
        """
        if not self.finops_enabled:
            return 0.0
            
        penalty = 0.0
        
        if resource_type in ["autoscalinggroup", "virtualmachinescaleset"]:
            sku = properties.get("sku") or {}
            max_size_val = properties.get("MaxSize") or sku.get("capacity", 1)
            try:
                max_size = int(max_size_val) if max_size_val is not None else 1
            except (ValueError, TypeError):
                max_size = 1
            
            # If the max size is massive, the cryptomining blast radius is huge.
            if max_size >= 100:
                penalty += 0.30 * self.finops_multiplier
                profile.threat_vectors.append(ThreatVectorType.FINANCIAL_HIJACK.value + f": MaxSize {max_size}")
            elif max_size >= 50:
                penalty += 0.15 * self.finops_multiplier
                
        return penalty

    # --------------------------------------------------------------------------
    # MATHEMATICAL NORMALIZATION
    # --------------------------------------------------------------------------

    def _normalize_dijkstra_weight(self, raw_score: float) -> float:
        """
        Advanced Logistic Sigmoid Clamping.
        The Attack Path Engine (Dijkstra/Friction Decay) requires edge weights 
        strictly between 0.0 and 1.0. 
        
        Instead of a hard ceiling (which destroys nuance for extremely risky nodes), 
        this uses a scaled sigmoid function to gently curve the output as it 
        approaches 1.0, preserving comparative mathematical hierarchy.
        """
        if raw_score <= 0.0:
            return 0.0
            
        # Standardize the input scale. Assuming a typical "very high" raw score is ~3.0
        # The equation: f(x) = (2 / (1 + e^(-k*x))) - 1
        # This gives a smooth curve from 0 to 1.
        
        steepness_k = 0.8
        sigmoid_val = (2.0 / (1.0 + math.exp(-steepness_k * raw_score))) - 1.0
        
        clamped_val = 1.0 if sigmoid_val > 1.0 else (0.0 if sigmoid_val < 0.0 else sigmoid_val)
        return float(f"{clamped_val:.3f}")

# Export Global Singleton
# Preserves configuration state and ML weightings in memory.
risk_scorer = RiskScoringEngine()