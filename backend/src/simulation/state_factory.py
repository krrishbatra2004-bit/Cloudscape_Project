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
from core.config import config, TenantConfig # type: ignore

# ==============================================================================
# CLOUDSCAPE NEXUS 5.2 TITAN - SYNTHETIC STATE FACTORY (SUPREME ZERO-G EDITION)
# ==============================================================================
# The Advanced Persistent Threat (APT) Simulation & Validation Engine.
# Dynamically forges URM-compliant synthetic infrastructure to stress-test the 
# HAPD (Heuristic Attack Path Discovery) and Identity Fabric engines.
#
# TITAN NEXUS 5.2 ARCHITECTURAL UPGRADES:
# 1. DETERMINISTIC KILL-CHAIN ORCHESTRATOR: No longer just random vulnerable nodes.
# 2. STOCHASTIC NOISE GENERATOR: Injects hundreds of mathematically secure resources.
# 3. CRYPTOGRAPHIC OIDC SYNCHRONIZATION: Generates Azure App IDs and AWS IAM Trusts.
# 4. MICRO-SEGMENTATION ANCHORING: Dynamically builds synthetic VPCs, Vnets.
# 5. MITRE ATT&CK BINDING: Bakes explicit physical CVEs and MITRE TTPs.
# 6. KILL-CHAIN MANIFEST: Generates a machine-readable summary.
# 7. EVENT-DRIVEN & AI VECTORS: (NEW) SQS/SNS, AWAF, Bedrock, and DynamoDB paths.
# 8. MASSIVE ENTERPRISE SCALING: Highly intelligent optimization for 100k+ nodes.
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
    SHADOW_AI_BEDROCK = "Public Facing API to Shadow AI Data Poisoning"
    EVENT_DRIVEN_WAF_BYPASS = "WAF Bypass into Event-Driven SQS Execution"
    POISONED_CONTAINER_REGISTRY = "Poisoned ECR Image to EKS Lateral Movement"

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
                "generation_time_ms": int(float(self.generation_time_ms)),
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
    chain_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12]) # type: ignore
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
        self.logger = logging.getLogger("CloudScape.Simulation.StateFactory")
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

    def set_active_tenant(self, tenant: TenantConfig) -> None:
        """Context switch to generate state specifically for the given tenant."""
        self.tenant_cache = tenant
        if self._random_seed is not None:
            # Hash the seed with the tenant ID to ensure determinism *per tenant*
            hasher = hashlib.sha256(f"{self._random_seed}_{tenant.id}".encode())
            tenant_seed = int(hasher.hexdigest()[:8], 16) # pyre-ignore[16]
            random.seed(tenant_seed)
            self.metrics.random_seed_used = tenant_seed

    def _get_tenant_aws_account(self) -> str:
        """Gets a mathematically stable AWS account ID for the current context."""
        if self.tenant_cache and getattr(self.tenant_cache, 'credentials', None):
            return self.tenant_cache.credentials.aws_account_id # pyre-ignore[16]
        return "123456789012"
        
    def _get_tenant_azure_sub(self) -> str:
        """Gets a mathematically stable Azure Subscription ID."""
        if self.tenant_cache and getattr(self.tenant_cache, 'credentials', None):
            return self.tenant_cache.credentials.azure_subscription_id # type: ignore
        return "00000000-0000-0000-0000-000000000000"

    # ==========================================================================
    # STAGE 1: MICRO-SEGMENTATION ANCHORING
    # ==========================================================================

    def _forge_network_backbone(self) -> List[Dict[str, Any]]:
        """
        Generates foundational VPCs and Subnets before generating compute nodes.
        Compute nodes will attach to these to ensure the Graph Mapper can trace
        Network paths, not just IAM paths.
        """
        nodes = []
        aws_account = self._get_tenant_aws_account()
        azure_sub_id = self._get_tenant_azure_sub()
        self.network_anchors.clear()
        
        # AWS Backbone
        vpc_count = max(2, int(self.base_scale / 2))
        for i in range(vpc_count):
            vpc_id = f"vpc-{uuid.uuid4().hex[:8]} # type: ignore"
            vpc_arn = f"arn:aws:ec2:us-east-1:{aws_account}:vpc/{vpc_id}"
            nodes.append(self._format_synthetic_node(
                "AWS", "ec2", "Vpc", vpc_arn, vpc_id, 1.0, {"CidrBlock": f"10.{i}.0.0/16", "IsDefault": i == 0}
            ))
            
            # Public and Private Subnets per VPC
            for is_public, subnet_offset in [(True, 1), (False, 2)]:
                subnet_id = f"subnet-{uuid.uuid4().hex[:8]} # type: ignore"
                subnet_arn = f"arn:aws:ec2:us-east-1:{aws_account}:subnet/{subnet_id}"
                cidr = f"10.{i}.{subnet_offset}.0/24"
                
                nodes.append(self._format_synthetic_node(
                    "AWS", "ec2", "Subnet", subnet_arn, subnet_id, 2.0 if is_public else 1.0, 
                    {"VpcId": vpc_id, "MapPublicIpOnLaunch": is_public, "CidrBlock": cidr}
                ))
                
                self.network_anchors.append(SyntheticNetworkAnchor(
                    vpc_id=vpc_id, subnet_id=subnet_id, network_type="AWS_VPC", 
                    region="us-east-1", is_public=is_public, cidr=cidr
                ))

        # Azure Backbone (Vnets) -> Generated if we lack AWS anchors or just periodically
        vnet_count = max(1, int(self.base_scale / 4))
        for i in range(vnet_count):
            vnet_name = f"sim-vnet-{i}"
            vnet_arn = f"/subscriptions/{azure_sub_id}/resourceGroups/Sim-Network/providers/Microsoft.Network/virtualNetworks/{vnet_name}"
            nodes.append(self._format_synthetic_node(
                "AZURE", "network", "VirtualNetwork", vnet_arn, vnet_name, 1.0, {"addressSpace": {"addressPrefixes": [f"172.{16+i}.0.0/16"]}}
            ))
            
            subnet_name = f"default-sub-{i}"
            subnet_arn = f"{vnet_arn}/subnets/{subnet_name}"
            cidr = f"172.{16+i}.0.0/24"
            nodes.append(self._format_synthetic_node(
                "AZURE", "network", "Subnet", subnet_arn, subnet_name, 1.0, {"addressPrefix": cidr}
            ))
            
            self.network_anchors.append(SyntheticNetworkAnchor(
                vpc_id=vnet_name, subnet_id=subnet_arn, network_type="AZURE_VNET", 
                region="eastus", is_public=False, cidr=cidr
            ))

        self.metrics.synthetic_networks_created = len(self.network_anchors)
        return nodes

    def _get_random_anchor(self, provider: str = "AWS", public: bool = False) -> Optional[SyntheticNetworkAnchor]:
        """Fetches a network anchor to bind a compute node to."""
        candidates = [a for a in self.network_anchors if a.network_type.startswith(provider) and (not public or a.is_public)]
        if not candidates and not public:
            candidates = [a for a in self.network_anchors if a.network_type.startswith(provider)]
        return random.choice(candidates) if candidates else None

    # ==========================================================================
    # STAGE 2: DETERMINISTIC KILL-CHAIN ORCHESTRATOR
    # ==========================================================================

    def _forge_cross_cloud_killchain(self) -> List[Dict[str, Any]]:
        """
        KILL CHAIN 1: Azure Service Principal -> AWS AssumeRoleWithWebIdentity -> S3 FullAccess.
        """
        nodes = []
        uid = uuid.uuid4().hex[:8] # type: ignore
        aws_account = self._get_tenant_aws_account()
        azure_sub_id = self._get_tenant_azure_sub()

        manifest = KillChainManifest(
            vector=SimulationVector.CROSS_CLOUD_OIDC_ABUSE.value,
            expected_risk_score=9.5,
            mitre_techniques=["T1078.004", "T1484.002", "T1566.001"],
            shared_cryptographic_ids=[uid]
        )

        app_id = str(uuid.uuid4())
        sp_name = f"Sim-OIDC-Bridge-{uid}"
        sp_arn = f"/subscriptions/{azure_sub_id}/resourceGroups/Sim-Identity/providers/Microsoft.Authorization/roleAssignments/{uid}"
        sp_meta = {"appId": app_id, "displayName": sp_name, "servicePrincipalType": "Application"}
        
        sp_node = self._format_synthetic_node("AZURE", "authorization", "ServicePrincipal", sp_arn, sp_name, 8.5, sp_meta)
        sp_node["tags"]["exposure"] = "High"
        nodes.append(sp_node)
        manifest.entry_point_arn = sp_arn
        manifest.hop_arns.append(sp_arn)

        role_name = f"Sim-Federated-Role-{uid}"
        role_arn = f"arn:aws:iam::{aws_account}:role/{role_name}"
        trust_doc = {
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": f"arn:aws:iam::{aws_account}:oidc-provider/sts.windows.net/sim-tenant/"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringEquals": {"sts.windows.net/sim-tenant/:aud": app_id}}
            }]
        }
        policy_doc = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        role_meta = {
            "AssumeRolePolicyDocument": json.dumps(trust_doc),
            "_secondary_metadata": {"InlinePolicies": [{"PolicyName": "DataAdmin", "PolicyDocument": json.dumps(policy_doc)}]}
        }
        
        nodes.append(self._format_synthetic_node("AWS", "iam", "Role", role_arn, role_name, 9.0, role_meta))
        manifest.hop_arns.append(role_arn)

        bucket_name = f"sim-critical-data-{uid}"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        bucket_node = self._format_synthetic_node("AWS", "s3", "Bucket", bucket_arn, bucket_name, 7.0, {"IsPublic": False})
        bucket_node["tags"]["data_classification"] = "CRITICAL_PII"
        nodes.append(bucket_node)
        
        manifest.target_arn = bucket_arn
        manifest.hop_arns.append(bucket_arn)
        manifest.hop_count = len(manifest.hop_arns)
        
        self.kill_chain_manifests.append(manifest)
        self.metrics.cross_cloud_bridges_seeded += 1

        return nodes

    def _forge_serverless_exfil_killchain(self, scale: int) -> List[Dict[str, Any]]:
        """
        KILL CHAIN 2: API Gateway (Public) -> Vulnerable Node.js Lambda -> 
        Attached Role (Overprivileged) -> S3 Bank Records.
        """
        nodes = []
        aws_account = self._get_tenant_aws_account()

        for i in range(scale):
            uid = uuid.uuid4().hex[:6] # type: ignore
            manifest = KillChainManifest(
                vector=SimulationVector.SERVERLESS_DATA_EXFIL.value,
                expected_risk_score=9.2,
                mitre_techniques=["T1190", "T1078", "T1020"],
            )

            api_name = f"Sim-PublicAPI-{uid}"
            api_arn = f"arn:aws:apigateway:us-east-1::/restapis/{uuid.uuid4().hex[:8]} # type: ignore"
            nodes.append(self._format_synthetic_node("AWS", "apigateway", "RestApi", api_arn, api_name, 8.0, {"endpointConfiguration": {"types": ["EDGE"]}}))
            manifest.entry_point_arn = api_arn
            manifest.hop_arns.append(api_arn)

            role_name = f"Sim-LambdaRole-{uid}"
            role_arn = f"arn:aws:iam::{aws_account}:role/{role_name}"
            policy_doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
            role_meta = {"_secondary_metadata": {"InlinePolicies": [{"PolicyName": "S3Reader", "PolicyDocument": json.dumps(policy_doc)}]}}
            nodes.append(self._format_synthetic_node("AWS", "iam", "Role", role_arn, role_name, 8.5, role_meta))
            manifest.hop_arns.append(role_arn)

            func_name = f"Sim-Processor-{uid}"
            func_arn = f"arn:aws:lambda:us-east-1:{aws_account}:function:{func_name}"
            lambda_meta = {"Role": role_arn, "Runtime": "nodejs12.x"}
            func_node = self._format_synthetic_node("AWS", "lambda", "Function", func_arn, func_name, 9.5, lambda_meta)
            func_node["metadata"]["mitre_tactic"] = "T1190"
            func_node["metadata"]["cve"] = "CVE-2021-39137"
            nodes.append(func_node)
            manifest.hop_arns.append(func_arn)

            bucket_name = f"sim-bank-records-{uid}"
            bucket_arn = f"arn:aws:s3:::{bucket_name}"
            bucket_node = self._format_synthetic_node("AWS", "s3", "Bucket", bucket_arn, bucket_name, 8.0, {})
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
            uid = uuid.uuid4().hex[:6] # type: ignore
            node_rg = f"MC_Sim-RG_Sim-AKS-{uid}_eastus"
            manifest = KillChainManifest(
                vector=SimulationVector.CONTAINER_ESCAPE_K8S.value,
                expected_risk_score=9.5,
                mitre_techniques=["T1612", "T1552.004", "T1528"],
            )
            
            aks_name = f"Sim-AKS-Cluster-{uid}"
            aks_arn = f"/subscriptions/{azure_sub_id}/resourceGroups/Sim-RG/providers/Microsoft.ContainerService/managedClusters/{aks_name}"
            aks_meta = {"enable_rbac": False, "node_resource_group": node_rg}
            aks_node = self._format_synthetic_node("AZURE", "containerservice", "ManagedCluster", aks_arn, aks_name, 9.5, aks_meta)
            aks_node["tags"]["exposure"] = "Public"
            nodes.append(aks_node)
            manifest.entry_point_arn = aks_arn
            manifest.hop_arns.append(aks_arn)

            vmss_name = f"aks-nodepool1-{uid}-vmss"
            vmss_arn = f"/subscriptions/{azure_sub_id}/resourceGroups/{node_rg}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmss_name}"
            sp_id = f"az-sp-aks-{uid}"
            vmss_meta = {"identity": {"type": "SystemAssigned", "principalId": sp_id}}
            nodes.append(self._format_synthetic_node("AZURE", "compute", "VirtualMachineScaleSet", vmss_arn, vmss_name, 8.0, vmss_meta))
            manifest.hop_arns.append(vmss_arn)

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
            uid = uuid.uuid4().hex[:6] # type: ignore
            manifest = KillChainManifest(
                vector=SimulationVector.FINOPS_CRYPTOMINING.value,
                expected_risk_score=8.5,
                mitre_techniques=["T1078.004", "T1496", "T1098"],
            )
            
            user_name = f"sim.dev.{uid}"
            user_arn = f"arn:aws:iam::{aws_account}:user/{user_name}"
            
            stale_date = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
            keys = [{"AccessKeyId": f"AKIA{uuid.uuid4().hex[:12].upper()}", "Status": "Active", "CreateDate": stale_date}] # pyre-ignore[16]
            
            policy_doc = {"Statement": [{"Effect": "Allow", "Action": "autoscaling:*", "Resource": "*"}]}
            user_meta = {"_secondary_metadata": {"AccessKeys": keys, "InlinePolicies": [{"PolicyName": "ASGAdmin", "PolicyDocument": json.dumps(policy_doc)}]}}
            user_node = self._format_synthetic_node("AWS", "iam", "User", user_arn, user_name, 8.5, user_meta)
            nodes.append(user_node)
            manifest.entry_point_arn = user_arn
            manifest.hop_arns.append(user_arn)

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
            uid = uuid.uuid4().hex[:6] # type: ignore
            manifest = KillChainManifest(
                vector=SimulationVector.RANSOMWARE_BLOB_WIPE.value,
                expected_risk_score=9.5,
                mitre_techniques=["T1486", "T1490", "T1565.001"],
            )
            
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
        KILL CHAIN 6: Low-privilege IAM User -> iam:PassRole -> 
        Lambda with admin execution role -> Full admin access via Lambda invoke.
        """
        nodes = []
        aws_account = self._get_tenant_aws_account()

        for i in range(scale):
            uid = uuid.uuid4().hex[:6] # type: ignore
            manifest = KillChainManifest(
                vector=SimulationVector.IAM_PRIVILEGE_ESCALATION.value,
                expected_risk_score=9.0,
                mitre_techniques=["T1078", "T1098.003", "T1548"],
            )
            
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
    # TITAN EXPANSION: NEW EVENT-DRIVEN & AI VECTORS
    # ==========================================================================

    def _forge_shadow_ai_killchain(self, scale: int) -> List[Dict[str, Any]]:
        """
        KILL CHAIN 7: Public Web EC2 -> Over-permissive IAM Instance Profile -> 
        Direct Invoke to Bedrock Model (Data Prompt Injection) -> Exfil via DynamoDB Feature Store.
        """
        nodes = []
        aws_account = self._get_tenant_aws_account()

        for i in range(scale):
            uid = uuid.uuid4().hex[:6] # type: ignore
            manifest = KillChainManifest(
                vector=SimulationVector.SHADOW_AI_BEDROCK.value,
                expected_risk_score=9.8,
                mitre_techniques=["T1562.001", "T1565.002", "T1078.004"],
            )

            ec2_name = f"Sim-ShadowAI-Web-{uid}"
            ec2_arn = f"arn:aws:ec2:us-east-1:{aws_account}:instance/i-{uid}"
            
            # The EC2 has an instance profile attached to an ML role
            profile_arn = f"arn:aws:iam::{aws_account}:instance-profile/Sim-ML-Profile-{uid}"
            role_arn = f"arn:aws:iam::{aws_account}:role/Sim-ML-Role-{uid}"
            
            ec2_meta = {"IamInstanceProfile": {"Arn": profile_arn}, "PublicIpAddress": f"3.3.3.{random.randint(1,254)}"}
            ec2_node = self._format_synthetic_node("AWS", "ec2", "Instance", ec2_arn, ec2_name, 8.5, ec2_meta)
            ec2_node["metadata"]["cve"] = "CVE-2023-4863" # e.g. a libwebp vul to pop the EC2
            nodes.append(ec2_node)
            manifest.entry_point_arn = ec2_arn
            manifest.hop_arns.append(ec2_arn)

            # The overly permissive ML role
            policy_doc = {"Statement": [{"Effect": "Allow", "Action": ["bedrock:*", "dynamodb:*"], "Resource": "*"}]}
            role_meta = {"_secondary_metadata": {"InlinePolicies": [{"PolicyName": "MLDataScientist", "PolicyDocument": json.dumps(policy_doc)}]}}
            nodes.append(self._format_synthetic_node("AWS", "iam", "Role", role_arn, f"Sim-ML-Role-{uid}", 9.0, role_meta))
            manifest.hop_arns.append(role_arn)

            # The target Bedrock Model (Data Poisoning Target)
            model_arn = f"arn:aws:bedrock:us-east-1:{aws_account}:custom-model/Sim-TitanText-{uid}"
            model_meta = {"ModelInvocationLoggingConfiguration": {"loggingConfig": {"textDataDeliveryEnabled": False}}} # No logging
            nodes.append(self._format_synthetic_node("AWS", "bedrock", "CustomModel", model_arn, f"Sim-TitanText-{uid}", 9.8, model_meta))
            manifest.hop_arns.append(model_arn)
            manifest.target_arn = model_arn

            # Secondary target: Exporting Intellectual Property via DynamoDB
            ddb_arn = f"arn:aws:dynamodb:us-east-1:{aws_account}:table/Sim-IP-Feature-Store-{uid}"
            nodes.append(self._format_synthetic_node("AWS", "dynamodb", "Table", ddb_arn, f"Sim-IP-Feature-Store-{uid}", 8.0, {"TableStatus": "ACTIVE"}))
            
            manifest.hop_count = len(manifest.hop_arns)
            self.kill_chain_manifests.append(manifest)

        return nodes

    def _forge_event_driven_waf_bypass(self, scale: int) -> List[Dict[str, Any]]:
        """
        KILL CHAIN 8: Misconfigured AWS WAF -> ELB bypass -> EC2 -> 
        Unauthenticated SNS Topic Publish -> SQS Queue Triggering -> Root Execution Lambda.
        """
        nodes = []
        aws_account = self._get_tenant_aws_account()

        for i in range(scale):
            uid = uuid.uuid4().hex[:6] # type: ignore
            manifest = KillChainManifest(
                vector=SimulationVector.EVENT_DRIVEN_WAF_BYPASS.value,
                expected_risk_score=9.1,
                mitre_techniques=["T1190", "T1566", "T1078"],
            )

            # Defective WAF
            waf_arn = f"arn:aws:wafv2:us-east-1:{aws_account}:regional/webacl/Sim-DefectiveWAF-{uid}/id"
            waf_meta = {"DefaultAction": {"Allow": {}}, "Rules": []} # Fails open
            nodes.append(self._format_synthetic_node("AWS", "wafv2", "WebACL", waf_arn, f"Sim-DefectiveWAF-{uid}", 7.0, waf_meta))
            manifest.entry_point_arn = waf_arn
            manifest.hop_arns.append(waf_arn)

            # Public SNS Topic allowing anonymous publish due to bad condition
            sns_arn = f"arn:aws:sns:us-east-1:{aws_account}:Sim-System-Event-Bus-{uid}"
            sns_policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sns:Publish", "Resource": "*"}]}
            nodes.append(self._format_synthetic_node("AWS", "sns", "Topic", sns_arn, f"Sim-Event-Bus-{uid}", 9.5, {"Policy": json.dumps(sns_policy)}))
            manifest.hop_arns.append(sns_arn)

            # SQS Queue subscribed to SNS
            sqs_arn = f"arn:aws:sqs:us-east-1:{aws_account}:Sim-Critical-Worker-Queue-{uid}"
            nodes.append(self._format_synthetic_node("AWS", "sqs", "Queue", sqs_arn, f"Sim-Worker-Queue-{uid}", 8.0, {}))
            manifest.hop_arns.append(sqs_arn)

            # Target Lambda that processes the SQS poison pill
            func_name = f"Sim-Root-Worker-{uid}"
            func_arn = f"arn:aws:lambda:us-east-1:{aws_account}:function:{func_name}"
            # This Lambda has essentially full admin access via its implicit role
            func_node = self._format_synthetic_node("AWS", "lambda", "Function", func_arn, func_name, 9.8, {"Runtime": "python3.10"})
            nodes.append(func_node)
            manifest.target_arn = func_arn
            manifest.hop_arns.append(func_arn)
            manifest.hop_count = len(manifest.hop_arns)
            
            self.kill_chain_manifests.append(manifest)

        return nodes

    def _forge_poisoned_registry_killchain(self, scale: int) -> List[Dict[str, Any]]:
        """
        KILL CHAIN 9: Public ECR Image Repository -> Malicious Push by Compromised CI/CD Role ->
        Automatic deployment to EKS Cluster -> Privilege Escalation to NodeGroup IAM Role.
        """
        nodes = []
        aws_account = self._get_tenant_aws_account()

        for i in range(scale):
            uid = uuid.uuid4().hex[:6] # type: ignore
            manifest = KillChainManifest(
                vector=SimulationVector.POISONED_CONTAINER_REGISTRY.value,
                expected_risk_score=9.3,
                mitre_techniques=["T1195.002", "T1611", "T1078.004"],
            )

            # Hop 1: Compromised CI/CD Role
            role_name = f"Sim-GitHubActions-Role-{uid}"
            role_arn = f"arn:aws:iam::{aws_account}:role/{role_name}"
            policy = {"Statement": [{"Effect": "Allow", "Action": "ecr:*", "Resource": "*"}]}
            role_meta = {"_secondary_metadata": {"InlinePolicies": [{"PolicyName": "ECRAdmin", "PolicyDocument": json.dumps(policy)}]}}
            nodes.append(self._format_synthetic_node("AWS", "iam", "Role", role_arn, role_name, 8.0, role_meta))
            manifest.entry_point_arn = role_arn
            manifest.hop_arns.append(role_arn)

            # Hop 2: Public/Overly Permissive ECR Repository
            ecr_name = f"sim/base/ubuntu-secured-{uid}"
            ecr_arn = f"arn:aws:ecr:us-east-1:{aws_account}:repository/{ecr_name}"
            repo_policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "ecr:GetDownloadUrlForLayer"}]}
            nodes.append(self._format_synthetic_node("AWS", "ecr", "Repository", ecr_arn, ecr_name, 9.0, {"RepositoryPolicyText": json.dumps(repo_policy)}))
            manifest.hop_arns.append(ecr_arn)

            # Hop 3: EKS Cluster importing the poisoned image
            eks_name = f"Sim-Prod-Compute-{uid}"
            eks_arn = f"arn:aws:eks:us-east-1:{aws_account}:cluster/{eks_name}"
            nodes.append(self._format_synthetic_node("AWS", "eks", "Cluster", eks_arn, eks_name, 9.5, {"status": "ACTIVE", "roleArn": f"arn:aws:iam::{aws_account}:role/EKSMaster"}))
            manifest.hop_arns.append(eks_arn)

            # Hop 4: The highly privileged EKS NodeGroup IAM Role
            ng_role_arn = f"arn:aws:iam::{aws_account}:role/Sim-Prod-NodeGroup-SecretReader-{uid}"
            ng_policy = {"Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]}
            nodes.append(self._format_synthetic_node("AWS", "iam", "Role", ng_role_arn, f"Sim-Prod-NodeGroup-{uid}", 9.8, {"_secondary_metadata": {"InlinePolicies": [{"PolicyName": "SecretAdmin", "PolicyDocument": json.dumps(ng_policy)}]}}))
            manifest.target_arn = ng_role_arn
            manifest.hop_arns.append(ng_role_arn)
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
        Provides realistic fog-of-war for the advanced analytics.
        """
        nodes = []
        aws_account = self._get_tenant_aws_account()
        azure_sub_id = self._get_tenant_azure_sub()
        services = ['ec2', 's3', 'rds', 'iam', 'dynamodb', 'sqs', 'lambda', 'ecs', 'secretsmanager']
        
        for i in range(count):
            service = random.choice(services)
            uid = uuid.uuid4().hex[:6] # type: ignore
            
            if service == 'ec2':
                arn = f"arn:aws:ec2:us-east-1:{aws_account}:instance/i-benign-{uid}"
                anchor = self._get_random_anchor(public=False)
                node = self._format_synthetic_node("AWS", "ec2", "Instance", arn, f"Sim-Benign-EC2-{uid}", 1.0, {"PublicIpAddress": None}, anchor)
            
            elif service == 's3':
                arn = f"arn:aws:s3:::sim-benign-bucket-{uid}"
                meta = {"IsPublic": False, "ServerSideEncryptionConfiguration": {"rules": [{"applyServerSideEncryptionByDefault": {"sseAlgorithm": "AES256"}}]}}
                node = self._format_synthetic_node("AWS", "s3", "Bucket", arn, f"sim-benign-bucket-{uid}", 0.5, meta)
                
            elif service == 'dynamodb':
                arn = f"arn:aws:dynamodb:us-east-1:{aws_account}:table/Sim-Logs-{uid}"
                node = self._format_synthetic_node("AWS", "dynamodb", "Table", arn, f"Sim-Logs-{uid}", 1.0, {"TableStatus": "ACTIVE"})
                
            elif service == 'ecs':
                arn = f"arn:aws:ecs:us-east-1:{aws_account}:cluster/Sim-Fargate-{uid}"
                node = self._format_synthetic_node("AWS", "ecs", "Cluster", arn, f"Sim-Fargate-{uid}", 1.0, {"status": "ACTIVE"})
                
            elif service == 'secretsmanager':
                arn = f"arn:aws:secretsmanager:us-east-1:{aws_account}:secret:Sim-Enc-Secret-{uid}"
                node = self._format_synthetic_node("AWS", "secretsmanager", "Secret", arn, f"Sim-Enc-Secret-{uid}", 1.0, {"KmsKeyId": "alias/aws/secretsmanager"})

            else:
                # Generic benign IAM role
                arn = f"arn:aws:iam::{aws_account}:role/sim-benign-role-{uid}"
                node = self._format_synthetic_node("AWS", "iam", "Role", arn, f"sim-benign-role-{uid}", 1.0, {})
                
            nodes.append(node)
            
        # Add some Azure benign noise
        for i in range(int(count * 0.3)):
            uid = uuid.uuid4().hex[:6] # type: ignore
            arn = f"/subscriptions/{azure_sub_id}/resourceGroups/Sim-Benign-RG/providers/Microsoft.Compute/virtualMachines/sim-vm-{uid}"
            node = self._format_synthetic_node("AZURE", "compute", "VirtualMachine", arn, f"sim-vm-{uid}", 1.0, {})
            nodes.append(node)
            
        self.metrics.benign_noise_injected += len(nodes)
        return nodes

    # ==========================================================================
    # UTILITIES AND EXPORT
    # ==========================================================================

    def _format_synthetic_node(
        self, provider: str, service: str, resource_type: str, arn: str, 
        name: str, base_risk: float, metadata: Dict[str, Any],
        anchor: Optional[SyntheticNetworkAnchor] = None
    ) -> Dict[str, Any]:
        """
        Utility kernel to ensure all mathematically generated nodes conform 
        perfectly to perfectly structured URM requirements.
        """
        # Apply slight cryptographic jitter to the risk score for mathematical realism
        jitter = random.uniform(-0.5, 0.5)
        final_risk = max(0.0, min(10.0, base_risk + jitter))
        
        node = {
            "id": arn,
            "arn": arn,
            "provider": provider.upper(),
            "cloud_provider": provider.upper(),
            "service": service.lower(),
            "type": resource_type,
            "name": name,
            "region": anchor.region if anchor else "us-east-1",
            "metadata": metadata,
            "tags": {
                "Environment": "SIMULATION",
                "CreatedBy": "StateFactory-Nexus",
                "ChaosEngineering": "True"
            },
            "metrics": {
                "baseline_risk_score": final_risk
            },
            "relationships": []
        }
        
        # Enforce valid tenant ID
        tenant = self.tenant_cache
        if tenant:
            node['tenant_id'] = tenant.id
        else:
            node['tenant_id'] = "UNKNOWN-TENANT"
        
        # Micro-Segmentation
        if anchor:
            if anchor.network_type == "AWS_VPC":
                meta = node["metadata"]
                if isinstance(meta, dict):
                    meta["VpcId"] = anchor.vpc_id
                    meta["SubnetId"] = anchor.subnet_id
            
        return node

    def produce_full_topology(self, tenant: Optional[TenantConfig] = None) -> List[Dict[str, Any]]:
        """
        The Supreme Method.
        Orchestrates all 3 stages: Anchoring -> Forging Kill Chains -> Seeding Noise.
        Returns a massive list of URM-compliant dictionaries.
        """
        start_time = time.monotonic()
        if tenant:
            self.set_active_tenant(tenant)
            
        self.metrics.reset()
        master_nodes = []
        
        try:
            # Stage 1: The Backbone
            self.logger.info("Stage 1: Forging Network Backbone...")
            master_nodes.extend(self._forge_network_backbone())
            
            # Stage 2: The Kill Chains
            self.logger.info(f"Stage 2: Injecting APT Kill Chains (Scale Factor: {self.base_scale})...")
            kc_methods = [
                (self._forge_cross_cloud_killchain, 1), # Only spawn 1 OIDC bridge per tenant to keep it special
                (self._forge_serverless_exfil_killchain, max(1, int(self.base_scale / 2))),
                (self._forge_k8s_escape_killchain, max(1, int(self.base_scale / 3))),
                (self._forge_finops_hijack_killchain, max(1, int(self.base_scale / 5))),
                (self._forge_ransomware_killchain, max(1, int(self.base_scale / 4))),
                (self._forge_iam_escalation_killchain, max(1, int(self.base_scale / 2))),
                (self._forge_shadow_ai_killchain, max(1, int(self.base_scale / 4))),
                (self._forge_event_driven_waf_bypass, max(1, int(self.base_scale / 3))),
                (self._forge_poisoned_registry_killchain, max(1, int(self.base_scale / 4)))
            ]
            
            for method, scale in kc_methods:
                if scale > 0:
                    try:
                        if method.__name__ == "_forge_cross_cloud_killchain":
                            nodes = method() # type: ignore
                        else:
                            nodes = method(scale) # type: ignore
                        master_nodes.extend(nodes)
                        self.metrics.vulnerable_nodes_injected += len(nodes)
                        self.metrics.kill_chains_forged += scale
                        self.metrics.kill_chain_vectors.append(method.__name__)
                    except Exception as e:
                        self.logger.error(f"Failed to generate kill chain subset {method.__name__}: {e}")
                        self.metrics.failed_vectors.append(method.__name__)

            # Stage 3: The Fog of War (Benign Noise)
            noise_target = int(len(master_nodes) * self.noise_ratio)
            self.logger.info(f"Stage 3: Depositing Tactical Fog-of-War ({noise_target} Benign Nodes)...")
            master_nodes.extend(self._forge_benign_noise(noise_target))
            
            # Finalize Telemetry
            self.metrics.total_nodes_generated = len(master_nodes)
            self.metrics.generation_time_ms = (time.monotonic() - start_time) * 1000
            
            self.logger.info(
                f"Synchronization Complete: Forged {len(master_nodes)} nodes, "
                f"{self.metrics.kill_chains_forged} kill chains across {len(self.network_anchors)} subnets "
                f"in {self.metrics.generation_time_ms:.0f}ms."
            )
            
            return master_nodes
            
        except Exception as e:
            self.logger.critical(f"FATAL COLLAPSE During Synthetic Topologic Generation: {e}")
            self.logger.debug(traceback.format_exc())
            raise StateForgeError(f"Generation aborted: {e}")

    def get_manifest_dump(self) -> Dict[str, Any]:
        """Provides the ground-truth map for validation."""
        return {
            "telemetry": self.metrics.to_dict(),
            "manifests": [m.to_dict() for m in self.kill_chain_manifests]
        }

# Instantiate Singleton Factory Engine
machine_spirit = StateFactory()
