import logging
import random
import uuid
import time
import traceback
import hashlib
import json
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

# Core Titan Configuration Bindings
from core.config import config, TenantConfig

# ==============================================================================
# CLOUDSCAPE NEXUS 5.2 TITAN - SYNTHETIC STATE FACTORY (ZERO-G EDITION)
# ==============================================================================
# The Advanced Persistent Threat (APT) Simulation & Validation Engine.
# Dynamically forges URM-compliant synthetic infrastructure to stress-test the 
# HAPD (Heuristic Attack Path Discovery) and Identity Fabric engines.
#
# TITAN NEXUS 5.2 UPGRADES ACTIVE:
# 1. DETERMINISTIC KILL-CHAIN ORCHESTRATOR: No longer just random vulnerable 
#    nodes. It generates complete, multi-hop kill chains (e.g., Public API 
#    Gateway -> Lambda SSRF -> IAM Privilege Escalation -> S3 Exfiltration).
# 2. STOCHASTIC NOISE GENERATOR: Injects hundreds of mathematically secure, 
#    "benign" resources to intentionally bury the kill chains in graph noise. 
#    This proves the Friction Decay 3.0 physics engine actually works.
# 3. CRYPTOGRAPHIC OIDC SYNCHRONIZATION: Generates mathematically perfect 
#    Azure App IDs and AWS IAM Trust Conditions to guarantee the Identity Fabric 
#    detects cross-cloud lateral movement.
# 4. MICRO-SEGMENTATION ANCHORING: Dynamically builds synthetic VPCs, Vnets, 
#    and Subnets, and accurately places the vulnerable compute nodes inside them 
#    so the Micro-Segmentation Linker can route the attack paths correctly.
# 5. MITRE ATT&CK BINDING: Bakes explicit physical CVEs and MITRE TTPs into 
#    the generated telemetry for immediate SIEM correlation testing.
# 6. KILL-CHAIN MANIFEST: Generates a machine-readable summary of all injected 
#    kill chains for automated validation of the HAPD engine.
# 7. REPRODUCIBLE SEEDING: Supports deterministic random seeds for reproducible 
#    simulation runs for CI/CD validation.
# 8. FIXED VARIABLE SHADOWING: Azure subscription IDs are properly scoped.
# ==============================================================================

# ------------------------------------------------------------------------------
# ENTERPRISE EXCEPTIONS & ENUMS
# ------------------------------------------------------------------------------

class StateForgeError(Exception):
    """Base exception for the Synthetic State Factory."""
    pass

class TopologyCollisionError(StateForgeError):
    """Raised when the generator creates a mathematically impossible network overlap."""
    pass

class KillChainGenerationError(StateForgeError):
    """Raised when a kill chain cannot be fully assembled."""
    pass

class ThreatTier(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    BENIGN = "BENIGN"

class SimulationVector(Enum):
    CROSS_CLOUD_OIDC_ABUSE = "Cross-Cloud OIDC Lateral Movement"
    SERVERLESS_DATA_EXFIL = "Serverless RCE to Data Exfiltration"
    CONTAINER_ESCAPE_K8S = "Kubernetes Pod Escape to Node IAM"
    FINOPS_CRYPTOMINING = "ASG Hijack for Cryptomining"
    RANSOMWARE_BLOB_WIPE = "Public Blob Write Ransomware"
    IAM_PRIVILEGE_ESCALATION = "IAM Role Chain Privilege Escalation"

# ------------------------------------------------------------------------------
# TELEMETRY & DATACLASSES
# ------------------------------------------------------------------------------

@dataclass
class SimulationMetrics:
    """High-fidelity telemetry for the APT Generator."""
    kill_chains_forged: int = 0
    vulnerable_nodes_injected: int = 0
    benign_noise_injected: int = 0
    cross_cloud_bridges_seeded: int = 0
    synthetic_networks_created: int = 0
    generation_time_ms: float = 0.0
    kill_chain_vectors: List[str] = field(default_factory=list)
    total_nodes_generated: int = 0
    failed_vectors: List[str] = field(default_factory=list)
    random_seed_used: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Serializes metrics for forensic reporting."""
        return {
            "kill_chains": {
                "forged": self.kill_chains_forged,
                "vectors": self.kill_chain_vectors,
                "failed_vectors": self.failed_vectors,
            },
            "nodes": {
                "vulnerable": self.vulnerable_nodes_injected,
                "benign_noise": self.benign_noise_injected,
                "total": self.total_nodes_generated,
            },
            "topology": {
                "cross_cloud_bridges": self.cross_cloud_bridges_seeded,
                "synthetic_networks": self.synthetic_networks_created,
            },
            "performance": {
                "generation_time_ms": round(self.generation_time_ms, 2),
                "random_seed": self.random_seed_used,
            }
        }

    def reset(self) -> None:
        """Resets all metrics for a new run."""
        self.kill_chains_forged = 0
        self.vulnerable_nodes_injected = 0
        self.benign_noise_injected = 0
        self.cross_cloud_bridges_seeded = 0
        self.synthetic_networks_created = 0
        self.generation_time_ms = 0.0
        self.kill_chain_vectors.clear()
        self.total_nodes_generated = 0
        self.failed_vectors.clear()


@dataclass
class SyntheticNetworkAnchor:
    """Represents a forged network boundary to anchor compute nodes."""
    vpc_id: str
    subnet_id: str
    network_type: str  # "AWS_VPC" or "AZURE_VNET"
    region: str
    is_public: bool
    cidr: str = ""


@dataclass
class KillChainManifest:
    """Machine-readable summary of an injected kill chain for validation."""
    vector: str
    chain_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    entry_point_arn: str = ""
    target_arn: str = ""
    hop_count: int = 0
    hop_arns: List[str] = field(default_factory=list)
    shared_cryptographic_ids: List[str] = field(default_factory=list)
    expected_risk_score: float = 0.0
    mitre_techniques: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "vector": self.vector,
            "entry_point": self.entry_point_arn,
            "target": self.target_arn,
            "hop_count": self.hop_count,
            "hops": self.hop_arns,
            "shared_ids": self.shared_cryptographic_ids,
            "expected_risk": self.expected_risk_score,
            "mitre": self.mitre_techniques,
        }


# ------------------------------------------------------------------------------
# THE SUPREME STATE FACTORY KERNEL
# ------------------------------------------------------------------------------

class StateFactory:
    """
    The Master Simulation Coordinator.
    Generates complex, interconnected graph structures that perfectly mimic 
    enterprise cloud environments, heavily laced with targeted misconfigurations.
    """

    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Simulation.StateFactory")
        self.metrics = SimulationMetrics()
        
        # Configuration binding with safe fallbacks
        try:
            self.base_scale = config.settings.simulation.intensity_scale
            self.noise_ratio = config.settings.simulation.noise_ratio
        except AttributeError:
            self.base_scale = 10
            self.noise_ratio = 5.0
        
        # Deterministic seed for reproducible runs
        self._random_seed: Optional[int] = getattr(
            config.settings.simulation, 'deterministic_seed', None
        )
            
        # Global Simulation State
        self.network_anchors: List[SyntheticNetworkAnchor] = []
        self.synchronized_app_ids: List[str] = []
        self.tenant_cache: Optional[TenantConfig] = None
        self.kill_chain_manifests: List[KillChainManifest] = []

    def clear_state(self) -> None:
        """Flushes the simulation matrix for a new run."""
        self.metrics.reset()
        self.network_anchors.clear()
        self.synchronized_app_ids.clear()
        self.kill_chain_manifests.clear()

    # --------------------------------------------------------------------------
    # MASTER FORGING ORCHESTRATOR
    # --------------------------------------------------------------------------

    def generate_synthetic_topology(self, tenant: TenantConfig) -> List[Dict[str, Any]]:
        """
        The Master Forging Loop.
        Executes dynamic threat generation sequences behind strict fault isolation 
        barriers to ensure a robust, fail-safe synthetic matrix.
        """
        start_time = time.perf_counter()
        self.logger.info(f"--- SYNTHETIC APT MATRIX IGNITION: TENANT {tenant.id} ---")
        
        self.clear_state()
        self.tenant_cache = tenant
        synthetic_nodes: List[Dict[str, Any]] = []

        # Apply deterministic seed for reproducible runs
        if self._random_seed is not None:
            random.seed(self._random_seed)
            self.metrics.random_seed_used = self._random_seed
            self.logger.debug(f"Deterministic seed applied: {self._random_seed}")

        # Chaos Jitter: Varies the number of standard nodes per scan for topological realism
        variance = lambda base: max(1, int(base * random.uniform(0.8, 1.2)))
        active_scale = variance(self.base_scale)

        try:
            # STAGE 1: INFRASTRUCTURE ANCHORING (Networks & Identity Bridges)
            # ------------------------------------------------------------------
            self.logger.debug("  [*] Stage 1: Forging Network Backbone...")
            network_nodes = self._forge_network_backbone(active_scale)
            synthetic_nodes.extend(network_nodes)
            
            # Cryptographic ID Synchronization (The Zero-Bridge Fix)
            # Guarantees the IdentityFabric finds the Cross-Cloud bridges.
            bridge_count = variance(min(5, active_scale))
            self.synchronized_app_ids = [
                f"api://titan-sim-{tenant.id.lower()}-{uuid.uuid4().hex[:6]}" 
                for _ in range(bridge_count)
            ]
            self.metrics.cross_cloud_bridges_seeded = bridge_count

            # STAGE 2: DETERMINISTIC KILL-CHAIN ORCHESTRATION
            # ------------------------------------------------------------------
            self.logger.debug("  [*] Stage 2: Forging Kill Chains...")
            kill_chain_tasks = [
                (SimulationVector.CROSS_CLOUD_OIDC_ABUSE, self._forge_cross_cloud_killchain),
                (SimulationVector.SERVERLESS_DATA_EXFIL, self._forge_serverless_exfil_killchain),
                (SimulationVector.CONTAINER_ESCAPE_K8S, self._forge_k8s_escape_killchain),
                (SimulationVector.FINOPS_CRYPTOMINING, self._forge_finops_hijack_killchain),
                (SimulationVector.RANSOMWARE_BLOB_WIPE, self._forge_ransomware_killchain),
                (SimulationVector.IAM_PRIVILEGE_ESCALATION, self._forge_iam_escalation_killchain),
            ]

            for vector, generator_func in kill_chain_tasks:
                try:
                    self.logger.debug(f"    [>] Synthesizing Attack Vector: {vector.value}")
                    chain_scale = max(1, int(active_scale / 4))
                    chain_nodes = generator_func(chain_scale)
                    if chain_nodes:
                        synthetic_nodes.extend(chain_nodes)
                        self.metrics.kill_chains_forged += 1
                        self.metrics.vulnerable_nodes_injected += len(chain_nodes)
                        self.metrics.kill_chain_vectors.append(vector.value)
                except Exception as e:
                    self.logger.error(f"  [!] Forging Anomaly in {vector.value}: {e}")
                    self.logger.debug(traceback.format_exc())
                    self.metrics.failed_vectors.append(vector.value)
                    continue  # Fault Isolation Barrier

            # STAGE 3: STOCHASTIC NOISE GENERATION
            # ------------------------------------------------------------------
            noise_target = int(self.metrics.vulnerable_nodes_injected * self.noise_ratio)
            self.logger.debug(f"  [*] Stage 3: Generating Noise ({noise_target} benign entities)...")
            
            noise_nodes = self._forge_benign_noise(noise_target)
            synthetic_nodes.extend(noise_nodes)
            self.metrics.benign_noise_injected = len(noise_nodes)

            # STAGE 4: FINALIZATION & TELEMETRY
            # ------------------------------------------------------------------
            self.metrics.total_nodes_generated = len(synthetic_nodes)
            self.metrics.generation_time_ms = (time.perf_counter() - start_time) * 1000
            
            self.logger.info(
                f"  [OK] Synthetic Matrix Complete ({self.metrics.generation_time_ms:.2f}ms). "
                f"Yield: {len(synthetic_nodes)} Nodes "
                f"(Vuln: {self.metrics.vulnerable_nodes_injected}, "
                f"Noise: {self.metrics.benign_noise_injected}, "
                f"Kill Chains: {self.metrics.kill_chains_forged})."
            )
            return synthetic_nodes

        except Exception as e:
            self.logger.critical(f"Catastrophic failure in State Factory: {e}")
            self.logger.debug(traceback.format_exc())
            return []

    # ==========================================================================
    # CORE UTILITIES & URM STANDARDIZATION
    # ==========================================================================

    def _format_synthetic_node(
        self, 
        cloud: str, 
        service: str, 
        resource_type: str, 
        arn: str, 
        name: str, 
        base_risk: float, 
        specific_metadata: Dict, 
        anchor: Optional[SyntheticNetworkAnchor] = None
    ) -> Dict[str, Any]:
        """
        Strict Universal Resource Model (URM) compliance wrapper.
        Applies heuristic risk jitter and injects deterministic Network Anchors.
        """
        # Inject dynamic heuristic variance (-0.5 to +0.5) keeping limits 1.0 - 10.0
        jittered_risk = max(1.0, min(10.0, base_risk + random.uniform(-0.5, 0.5)))
        
        tags = {
            "environment": "Simulation",
            "managed_by": "Cloudscape-StateFactory",
            "data_origin": "Synthetic",
            "forge_id": uuid.uuid4().hex[:8]
        }
        
        metadata = {
            "arn": arn,
            "resource_type": resource_type.lower(),
            "baseline_risk_score": round(jittered_risk, 2),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "is_simulated": True,
            **specific_metadata
        }

        # Apply Structural Networking Anchors if provided
        if anchor:
            if anchor.network_type == "AWS_VPC":
                tags["vpc_id"] = anchor.vpc_id
                tags["subnet_id"] = anchor.subnet_id
                metadata["VpcId"] = anchor.vpc_id
                metadata["SubnetId"] = anchor.subnet_id
            elif anchor.network_type == "AZURE_VNET":
                tags["vpc_id"] = anchor.vpc_id
                tags["subnet_id"] = anchor.subnet_id
                metadata["VnetId"] = anchor.vpc_id
                metadata["SubnetId"] = anchor.subnet_id
                
            if anchor.is_public:
                tags["exposure"] = "Public"

        return {
            "tenant_id": self.tenant_cache.id,
            "cloud_provider": cloud.upper(),
            "service": service.lower(),
            "type": resource_type.lower(),
            "arn": arn.lower() if cloud.upper() == "AZURE" else arn,
            "name": name,
            "tags": tags,
            "metadata": metadata,
            "properties": specific_metadata,
            "risk_score": round(jittered_risk, 2),
        }

    def _get_random_anchor(self, cloud: str, public: Optional[bool] = None) -> Optional[SyntheticNetworkAnchor]:
        """Retrieves a pre-generated network anchor to place compute nodes."""
        valid_anchors = [a for a in self.network_anchors if a.network_type.startswith(cloud.upper())]
        if public is not None:
            valid_anchors = [a for a in valid_anchors if a.is_public == public]
            
        if valid_anchors:
            return random.choice(valid_anchors)
        return None

    def _get_tenant_aws_account(self) -> str:
        """Safely extracts the AWS Account ID from the tenant cache."""
        return getattr(self.tenant_cache.credentials, "aws_account_id", "123456789012")
    
    def _get_tenant_azure_sub(self) -> str:
        """Safely extracts the Azure Subscription ID from the tenant cache."""
        return getattr(self.tenant_cache.credentials, "azure_subscription_id", "00000000-0000-0000-0000-000000000000")
    
    def _get_tenant_azure_tenant(self) -> str:
        """Safely extracts the Azure Tenant ID from the tenant cache."""
        return getattr(self.tenant_cache.credentials, "azure_tenant_id", "simulated-azure-tenant")

    # ==========================================================================
    # STAGE 1: INFRASTRUCTURE ANCHORING
    # ==========================================================================

    def _forge_network_backbone(self, scale: int) -> List[Dict[str, Any]]:
        """
        Builds the physical network boundaries (VPCs, Vnets, Subnets).
        Compute resources will be attached to these to test the Micro-segmentation Linker.
        
        FIX: Uses separate variable names for AWS subnet IDs to prevent 
        shadowing the Azure subscription ID.
        """
        nodes = []
        aws_account = self._get_tenant_aws_account()
        azure_sub_id = self._get_tenant_azure_sub()  # Preserved throughout — never shadowed

        # 1. AWS VPCs and Subnets
        aws_vpc_count = max(2, int(scale / 3))
        for i in range(aws_vpc_count):
            vpc_id = f"vpc-sim-{uuid.uuid4().hex[:8]}"
            vpc_arn = f"arn:aws:ec2:us-east-1:{aws_account}:vpc/{vpc_id}"
            vpc_cidr = f"10.{i}.0.0/16"
            nodes.append(self._format_synthetic_node(
                "AWS", "ec2", "VPC", vpc_arn, f"Sim-VPC-{i}", 1.0, 
                {"VpcId": vpc_id, "CidrBlock": vpc_cidr}
            ))
            
            # 2 Subnets per VPC (1 Public, 1 Private)
            for j, is_pub in enumerate([True, False]):
                # FIX: Use `aws_subnet_id` instead of `sub_id` to prevent shadowing
                aws_subnet_id = f"subnet-sim-{uuid.uuid4().hex[:8]}"
                subnet_cidr = f"10.{i}.{j}.0/24"
                subnet_arn = f"arn:aws:ec2:us-east-1:{aws_account}:subnet/{aws_subnet_id}"
                nodes.append(self._format_synthetic_node(
                    "AWS", "ec2", "Subnet", subnet_arn, f"Sim-Subnet-{i}-{j}", 1.0, 
                    {"SubnetId": aws_subnet_id, "VpcId": vpc_id, "CidrBlock": subnet_cidr}
                ))
                
                # Register Anchor
                self.network_anchors.append(SyntheticNetworkAnchor(
                    vpc_id=vpc_id, subnet_id=aws_subnet_id, 
                    network_type="AWS_VPC", region="us-east-1", 
                    is_public=is_pub, cidr=subnet_cidr
                ))
                self.metrics.synthetic_networks_created += 1

        # 2. Azure Vnets and Subnets (azure_sub_id is never overwritten)
        az_vnet_count = max(2, int(scale / 3))
        for i in range(az_vnet_count):
            vnet_id = f"/subscriptions/{azure_sub_id}/resourceGroups/Sim-RG/providers/Microsoft.Network/virtualNetworks/Sim-Vnet-{i}"
            vnet_cidr = f"192.168.{i}.0/24"
            nodes.append(self._format_synthetic_node(
                "AZURE", "network", "VirtualNetwork", vnet_id, f"Sim-Vnet-{i}", 1.0, 
                {"addressSpace": {"addressPrefixes": [vnet_cidr]}}
            ))
            
            # 2 Subnets per Vnet
            for j, is_pub in enumerate([True, False]):
                az_subnet_id = f"{vnet_id}/subnets/Sim-Subnet-{j}"
                nodes.append(self._format_synthetic_node(
                    "AZURE", "network", "Subnet", az_subnet_id, f"Sim-Subnet-{j}", 1.0, 
                    {"VirtualNetworkId": vnet_id}
                ))
                
                # Register Anchor
                self.network_anchors.append(SyntheticNetworkAnchor(
                    vpc_id=vnet_id, subnet_id=az_subnet_id, 
                    network_type="AZURE_VNET", region="eastus", 
                    is_public=is_pub, cidr=vnet_cidr
                ))
                self.metrics.synthetic_networks_created += 1

        return nodes

    # ==========================================================================
    # STAGE 2: DETERMINISTIC KILL-CHAIN ORCHESTRATORS
    # ==========================================================================

    def _forge_cross_cloud_killchain(self, scale: int) -> List[Dict[str, Any]]:
        """
        KILL CHAIN 1: Public Azure VM -> Compromised Azure Managed Identity -> 
        AWS IAM OIDC Federation -> High Privilege AWS Role -> AWS Crown Jewel RDS.
        """
        nodes = []
        azure_sub_id = self._get_tenant_azure_sub()
        aws_account = self._get_tenant_aws_account()
        az_tenant = self._get_tenant_azure_tenant()

        for i in range(min(scale, len(self.synchronized_app_ids))):
            app_id = self.synchronized_app_ids[i]
            uid = uuid.uuid4().hex[:6]
            manifest = KillChainManifest(
                vector=SimulationVector.CROSS_CLOUD_OIDC_ABUSE.value,
                expected_risk_score=9.0,
                shared_cryptographic_ids=[app_id],
                mitre_techniques=["T1078.004", "T1550.001", "T1530"],
            )
            
            # HOP 1: Azure Public VM (Entry Point)
            vm_name = f"Sim-Bastion-VM-{uid}"
            vm_arn = f"/subscriptions/{azure_sub_id}/resourceGroups/Sim-RG/providers/Microsoft.Compute/virtualMachines/{vm_name}"
            vm_anchor = self._get_random_anchor("AZURE", public=True)
            vm_meta = {
                "hardwareProfile": {"vmSize": "Standard_DS1_v2"},
                "identity": {
                    "type": "SystemAssigned",
                    "tenantId": az_tenant,
                    "federatedApplicationId": app_id
                }
            }
            nodes.append(self._format_synthetic_node("AZURE", "compute", "VirtualMachine", vm_arn, vm_name, 8.5, vm_meta, vm_anchor))
            manifest.entry_point_arn = vm_arn
            manifest.hop_arns.append(vm_arn)

            # HOP 2: AWS Federated IAM Role (The Bridge)
            role_name = f"Sim-Federated-OIDC-Role-{uid}"
            role_arn = f"arn:aws:iam::{aws_account}:role/{role_name}"
            trust_doc = {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Federated": f"sts.windows.net/{az_tenant}/"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {"StringEquals": {f"sts.windows.net/{az_tenant}/:aud": app_id}}
                }]
            }
            policy_doc = {"Statement": [{"Effect": "Allow", "Action": ["rds:*", "ec2:RunInstances", "iam:PassRole"], "Resource": "*"}]}
            role_meta = {
                "AssumeRolePolicyDocument": json.dumps(trust_doc), 
                "_secondary_metadata": {"InlinePolicies": [{"PolicyName": "LateralMove", "PolicyDocument": json.dumps(policy_doc)}]}
            }
            nodes.append(self._format_synthetic_node("AWS", "iam", "Role", role_arn, role_name, 9.0, role_meta))
            manifest.hop_arns.append(role_arn)

            # HOP 3: AWS Crown Jewel RDS (The Target)
            db_id = f"sim-critical-db-{uid}"
            db_arn = f"arn:aws:rds:us-east-1:{aws_account}:db:{db_id}"
            db_anchor = self._get_random_anchor("AWS", public=False)
            db_meta = {"DBInstanceIdentifier": db_id, "Engine": "postgres", "PubliclyAccessible": False}
            
            db_node = self._format_synthetic_node("AWS", "rds", "DBInstance", db_arn, db_id, 9.5, db_meta, db_anchor)
            db_node["tags"]["data_classification"] = "CRITICAL_PII"
            nodes.append(db_node)
            manifest.target_arn = db_arn
            manifest.hop_arns.append(db_arn)
            manifest.hop_count = len(manifest.hop_arns)
            
            self.kill_chain_manifests.append(manifest)

        return nodes

    def _forge_serverless_exfil_killchain(self, scale: int) -> List[Dict[str, Any]]:
        """
        KILL CHAIN 2: Public API Gateway -> Vulnerable AWS Lambda (RCE) -> 
        Lambda Execution Role (Wildcard S3) -> Private S3 Bucket with PCI Data.
        """
        nodes = []
        aws_account = self._get_tenant_aws_account()

        for i in range(scale):
            uid = uuid.uuid4().hex[:6]
            manifest = KillChainManifest(
                vector=SimulationVector.SERVERLESS_DATA_EXFIL.value,
                expected_risk_score=8.5,
                mitre_techniques=["T1190", "T1059.006", "T1530"],
            )
            
            # HOP 1: API Gateway (Entry Point)
            api_id = f"sim-api-{uid}"
            api_arn = f"arn:aws:apigateway:us-east-1::/restapis/{api_id}"
            api_meta = {"endpointConfiguration": {"types": ["REGIONAL"]}}
            api_node = self._format_synthetic_node("AWS", "apigateway", "RestApi", api_arn, f"Sim-Public-API-{uid}", 7.0, api_meta)
            api_node["tags"]["exposure"] = "Public"
            nodes.append(api_node)
            manifest.entry_point_arn = api_arn
            manifest.hop_arns.append(api_arn)

            # HOP 2: Lambda Function (Vulnerable Compute)
            func_name = f"Sim-Processor-Func-{uid}"
            func_arn = f"arn:aws:lambda:us-east-1:{aws_account}:function:{func_name}"
            role_name = f"Sim-Lambda-Exec-Role-{uid}"
            role_arn = f"arn:aws:iam::{aws_account}:role/{role_name}"
            
            func_anchor = self._get_random_anchor("AWS", public=False)
            func_meta = {"Role": role_arn, "Runtime": "python3.12", "Timeout": 300, "MemorySize": 512}
            nodes.append(self._format_synthetic_node("AWS", "lambda", "Function", func_arn, func_name, 8.0, func_meta, func_anchor))
            manifest.hop_arns.append(func_arn)

            # HOP 3: Lambda Execution Role (Over-privileged)
            trust_doc = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
            policy_doc = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
            role_meta = {
                "AssumeRolePolicyDocument": json.dumps(trust_doc), 
                "_secondary_metadata": {"InlinePolicies": [{"PolicyName": "S3FullAccess", "PolicyDocument": json.dumps(policy_doc)}]}
            }
            nodes.append(self._format_synthetic_node("AWS", "iam", "Role", role_arn, role_name, 8.5, role_meta))
            manifest.hop_arns.append(role_arn)

            # HOP 4: S3 Bucket (The Target)
            bucket_name = f"sim-corp-vault-pci-{uid}"
            bucket_arn = f"arn:aws:s3:::{bucket_name}"
            bucket_meta = {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}}
            bucket_node = self._format_synthetic_node("AWS", "s3", "Bucket", bucket_arn, bucket_name, 9.0, bucket_meta)
            bucket_node["tags"]["data_classification"] = "CRITICAL_PCI"
            nodes.append(bucket_node)
            manifest.target_arn = bucket_arn
            manifest.hop_arns.append(bucket_arn)
            manifest.hop_count = len(manifest.hop_arns)
            
            self.kill_chain_manifests.append(manifest)

        return nodes

    def _forge_k8s_escape_killchain(self, scale: int) -> List[Dict[str, Any]]:
        """
        KILL CHAIN 3: Azure AKS Cluster (Public API) -> Node Resource Group -> 
        VMSS Instances -> Managed Identity -> KeyVault Secrets Exfiltration.
        """
        nodes = []
        azure_sub_id = self._get_tenant_azure_sub()

        for i in range(scale):
            uid = uuid.uuid4().hex[:6]
            node_rg = f"MC_Sim-RG_Sim-AKS-{uid}_eastus"
            manifest = KillChainManifest(
                vector=SimulationVector.CONTAINER_ESCAPE_K8S.value,
                expected_risk_score=9.5,
                mitre_techniques=["T1612", "T1552.004", "T1528"],
            )
            
            # HOP 1: AKS Cluster (Entry Point)
            aks_name = f"Sim-AKS-Cluster-{uid}"
            aks_arn = f"/subscriptions/{azure_sub_id}/resourceGroups/Sim-RG/providers/Microsoft.ContainerService/managedClusters/{aks_name}"
            aks_meta = {"enable_rbac": False, "node_resource_group": node_rg}
            aks_node = self._format_synthetic_node("AZURE", "containerservice", "ManagedCluster", aks_arn, aks_name, 9.5, aks_meta)
            aks_node["tags"]["exposure"] = "Public"
            nodes.append(aks_node)
            manifest.entry_point_arn = aks_arn
            manifest.hop_arns.append(aks_arn)

            # HOP 2: VMSS Node Pool
            vmss_name = f"aks-nodepool1-{uid}-vmss"
            vmss_arn = f"/subscriptions/{azure_sub_id}/resourceGroups/{node_rg}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmss_name}"
            sp_id = f"az-sp-aks-{uid}"
            vmss_meta = {"identity": {"type": "SystemAssigned", "principalId": sp_id}}
            nodes.append(self._format_synthetic_node("AZURE", "compute", "VirtualMachineScaleSet", vmss_arn, vmss_name, 8.0, vmss_meta))
            manifest.hop_arns.append(vmss_arn)

            # HOP 3: Key Vault (The Target)
            kv_name = f"sim-prod-vault-{uid}"
            kv_arn = f"/subscriptions/{azure_sub_id}/resourceGroups/Sim-RG/providers/Microsoft.KeyVault/vaults/{kv_name}"
            kv_meta = {"accessPolicies": [{"tenantId": "sim-tenant", "objectId": sp_id, "permissions": {"secrets": ["get", "list"]}}]}
            kv_node = self._format_synthetic_node("AZURE", "keyvault", "Vault", kv_arn, kv_name, 9.0, kv_meta)
            kv_node["tags"]["data_classification"] = "SECRET"
            nodes.append(kv_node)
            manifest.target_arn = kv_arn
            manifest.hop_arns.append(kv_arn)
            manifest.hop_count = len(manifest.hop_arns)
            
            self.kill_chain_manifests.append(manifest)

        return nodes

    def _forge_finops_hijack_killchain(self, scale: int) -> List[Dict[str, Any]]:
        """
        KILL CHAIN 4: Compromised Developer IAM User -> Hardcoded Access Keys -> 
        AutoScalingGroup modification -> 1000x GPU Instances (Cryptomining).
        """
        nodes = []
        aws_account = self._get_tenant_aws_account()

        for i in range(scale):
            uid = uuid.uuid4().hex[:6]
            manifest = KillChainManifest(
                vector=SimulationVector.FINOPS_CRYPTOMINING.value,
                expected_risk_score=8.5,
                mitre_techniques=["T1078.004", "T1496", "T1098"],
            )
            
            # HOP 1: IAM User (Entry Point)
            user_name = f"sim.dev.{uid}"
            user_arn = f"arn:aws:iam::{aws_account}:user/{user_name}"
            
            stale_date = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
            keys = [{"AccessKeyId": f"AKIA{uuid.uuid4().hex[:12].upper()}", "Status": "Active", "CreateDate": stale_date}]
            
            policy_doc = {"Statement": [{"Effect": "Allow", "Action": "autoscaling:*", "Resource": "*"}]}
            user_meta = {"_secondary_metadata": {"AccessKeys": keys, "InlinePolicies": [{"PolicyName": "ASGAdmin", "PolicyDocument": json.dumps(policy_doc)}]}}
            user_node = self._format_synthetic_node("AWS", "iam", "User", user_arn, user_name, 8.5, user_meta)
            nodes.append(user_node)
            manifest.entry_point_arn = user_arn
            manifest.hop_arns.append(user_arn)

            # HOP 2: AutoScaling Group (The Target)
            asg_name = f"Sim-GPU-Compute-Cluster-{uid}"
            asg_arn = f"arn:aws:autoscaling:us-east-1:{aws_account}:autoScalingGroup:uuid:autoScalingGroupName/{asg_name}"
            asg_meta = {"MaxSize": 500, "DesiredCapacity": 2, "Instances": []}
            asg_anchor = self._get_random_anchor("AWS", public=False)
            
            asg_node = self._format_synthetic_node("AWS", "autoscaling", "AutoScalingGroup", asg_arn, asg_name, 9.0, asg_meta, asg_anchor)
            nodes.append(asg_node)
            manifest.target_arn = asg_arn
            manifest.hop_arns.append(asg_arn)
            manifest.hop_count = len(manifest.hop_arns)
            
            self.kill_chain_manifests.append(manifest)

        return nodes

    def _forge_ransomware_killchain(self, scale: int) -> List[Dict[str, Any]]:
        """
        KILL CHAIN 5: Direct Public Blob Storage with write access and NO versioning.
        Immediate ransomware vector. No hops required, just extreme risk.
        """
        nodes = []
        azure_sub_id = self._get_tenant_azure_sub()

        for i in range(scale):
            uid = uuid.uuid4().hex[:6]
            manifest = KillChainManifest(
                vector=SimulationVector.RANSOMWARE_BLOB_WIPE.value,
                expected_risk_score=9.5,
                mitre_techniques=["T1486", "T1490", "T1565.001"],
            )
            
            # Azure Storage Account
            acc_name = f"simazbackup{uid}"
            acc_arn = f"/subscriptions/{azure_sub_id}/resourceGroups/Sim-RG/providers/Microsoft.Storage/storageAccounts/{acc_name}"
            
            acc_meta = {
                "allow_blob_public_access": True,
                "minimum_tls_version": "TLS1_0",
                "encryption": {"services": {"blob": {"enabled": False}}}
            }
            
            acc_node = self._format_synthetic_node("AZURE", "storage", "StorageAccount", acc_arn, acc_name, 9.5, acc_meta)
            acc_node["tags"]["data_classification"] = "CONFIDENTIAL"
            acc_node["tags"]["exposure"] = "Public"
            acc_node["metadata"]["mitre_tactic"] = "T1486 (Data Encrypted for Impact)"
            nodes.append(acc_node)
            manifest.entry_point_arn = acc_arn
            manifest.target_arn = acc_arn
            manifest.hop_arns.append(acc_arn)
            manifest.hop_count = 1
            
            self.kill_chain_manifests.append(manifest)

        return nodes

    def _forge_iam_escalation_killchain(self, scale: int) -> List[Dict[str, Any]]:
        """
        KILL CHAIN 6 (NEW): Low-privilege IAM User -> iam:PassRole -> 
        Lambda with admin execution role -> Full admin access via Lambda invoke.
        """
        nodes = []
        aws_account = self._get_tenant_aws_account()

        for i in range(scale):
            uid = uuid.uuid4().hex[:6]
            manifest = KillChainManifest(
                vector=SimulationVector.IAM_PRIVILEGE_ESCALATION.value,
                expected_risk_score=9.0,
                mitre_techniques=["T1078", "T1098.003", "T1548"],
            )
            
            # HOP 1: Low-privilege IAM User with iam:PassRole
            user_name = f"sim.junior.dev.{uid}"
            user_arn = f"arn:aws:iam::{aws_account}:user/{user_name}"
            user_policy = {"Statement": [
                {"Effect": "Allow", "Action": ["lambda:CreateFunction", "lambda:InvokeFunction", "iam:PassRole"], "Resource": "*"}
            ]}
            user_meta = {"_secondary_metadata": {"InlinePolicies": [{"PolicyName": "DevPerms", "PolicyDocument": json.dumps(user_policy)}]}}
            user_node = self._format_synthetic_node("AWS", "iam", "User", user_arn, user_name, 7.0, user_meta)
            nodes.append(user_node)
            manifest.entry_point_arn = user_arn
            manifest.hop_arns.append(user_arn)
            
            # HOP 2: Admin Lambda Execution Role (the target to PassRole into)
            admin_role_name = f"Sim-Admin-Lambda-Role-{uid}"
            admin_role_arn = f"arn:aws:iam::{aws_account}:role/{admin_role_name}"
            trust_doc = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
            admin_policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
            role_meta = {
                "AssumeRolePolicyDocument": json.dumps(trust_doc),
                "_secondary_metadata": {"InlinePolicies": [{"PolicyName": "FullAdmin", "PolicyDocument": json.dumps(admin_policy)}]}
            }
            nodes.append(self._format_synthetic_node("AWS", "iam", "Role", admin_role_arn, admin_role_name, 9.5, role_meta))
            manifest.hop_arns.append(admin_role_arn)
            manifest.target_arn = admin_role_arn
            manifest.hop_count = len(manifest.hop_arns)
            
            self.kill_chain_manifests.append(manifest)

        return nodes

    # ==========================================================================
    # STAGE 3: STOCHASTIC NOISE GENERATOR
    # ==========================================================================

    def _forge_benign_noise(self, count: int) -> List[Dict[str, Any]]:
        """
        Generates mathematically secure, tightly locked down resources.
        Populates the graph to test the Attack Path Engine pruning accuracy.
        """
        nodes = []
        aws_account = self._get_tenant_aws_account()
        azure_sub_id = self._get_tenant_azure_sub()

        noise_generators = [
            self._make_safe_aws_instance,
            self._make_safe_aws_bucket,
            self._make_safe_aws_role,
            self._make_safe_azure_vm,
            self._make_safe_azure_storage,
        ]

        for i in range(count):
            uid = uuid.uuid4().hex[:8]
            generator = random.choice(noise_generators)
            try:
                node = generator(uid, aws_account, azure_sub_id)
                if node:
                    nodes.append(node)
            except Exception as e:
                self.logger.debug(f"Noise generation fault (non-critical): {e}")
                continue

        return nodes

    def _make_safe_aws_instance(self, uid: str, account: str, _az_sub: str) -> Dict[str, Any]:
        """Generates a hardened AWS EC2 instance."""
        arn = f"arn:aws:ec2:us-east-1:{account}:instance/i-sim-safe-{uid}"
        anchor = self._get_random_anchor("AWS", public=False)
        meta = {"InstanceType": "t3.micro", "PublicIpAddress": None, "EbsOptimized": True}
        return self._format_synthetic_node("AWS", "ec2", "Instance", arn, f"Safe-App-Node-{uid}", 1.5, meta, anchor)

    def _make_safe_aws_bucket(self, uid: str, account: str, _az_sub: str) -> Dict[str, Any]:
        """Generates a hardened AWS S3 bucket."""
        arn = f"arn:aws:s3:::sim-safe-logs-{uid}"
        meta = {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "RestrictPublicBuckets": True}, "Versioning": "Enabled"}
        return self._format_synthetic_node("AWS", "s3", "Bucket", arn, f"sim-safe-logs-{uid}", 1.0, meta)

    def _make_safe_aws_role(self, uid: str, account: str, _az_sub: str) -> Dict[str, Any]:
        """Generates a hardened AWS IAM role with read-only permissions."""
        arn = f"arn:aws:iam::{account}:role/Sim-Safe-Read-Role-{uid}"
        doc = {"Statement": [{"Effect": "Allow", "Action": ["s3:List*", "ec2:Describe*"], "Resource": "*"}]}
        meta = {"AssumeRolePolicyDocument": "{}", "_secondary_metadata": {"InlinePolicies": [{"PolicyName": "Read", "PolicyDocument": json.dumps(doc)}]}}
        return self._format_synthetic_node("AWS", "iam", "Role", arn, f"Sim-Safe-Read-Role-{uid}", 2.0, meta)

    def _make_safe_azure_vm(self, uid: str, _account: str, az_sub: str) -> Dict[str, Any]:
        """Generates a hardened Azure VM."""
        arn = f"/subscriptions/{az_sub}/resourceGroups/Sim-RG/providers/Microsoft.Compute/virtualMachines/Sim-Safe-VM-{uid}"
        anchor = self._get_random_anchor("AZURE", public=False)
        meta = {"hardwareProfile": {"vmSize": "Standard_B1s"}, "identity": None}
        return self._format_synthetic_node("AZURE", "compute", "VirtualMachine", arn, f"Sim-Safe-VM-{uid}", 1.5, meta, anchor)

    def _make_safe_azure_storage(self, uid: str, _account: str, az_sub: str) -> Dict[str, Any]:
        """Generates a hardened Azure Storage Account."""
        short_uid = uid[:6]
        arn = f"/subscriptions/{az_sub}/resourceGroups/Sim-RG/providers/Microsoft.Storage/storageAccounts/simsafestrg{short_uid}"
        meta = {"allow_blob_public_access": False, "minimum_tls_version": "TLS1_2", "encryption": {"services": {"blob": {"enabled": True}}}}
        return self._format_synthetic_node("AZURE", "storage", "StorageAccount", arn, f"simsafestrg{short_uid}", 1.0, meta)

    # ==========================================================================
    # PUBLIC API
    # ==========================================================================
    
    def get_metrics(self) -> Dict[str, Any]:
        """Returns the current simulation metrics."""
        return self.metrics.to_dict()
    
    def get_kill_chain_manifests(self) -> List[Dict[str, Any]]:
        """Returns machine-readable summaries of all injected kill chains."""
        return [m.to_dict() for m in self.kill_chain_manifests]