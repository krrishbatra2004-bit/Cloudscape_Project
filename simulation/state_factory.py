import logging
import random
import uuid
import traceback
from datetime import datetime, timezone
from typing import List, Dict, Any

from core.config import TenantConfig

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - SYNTHETIC STATE FACTORY (ZERO-G EDITION)
# ==============================================================================
# The Advanced Persistent Threat (APT) Simulation Engine.
# Dynamically forges URM-compliant synthetic infrastructure.
#
# TITAN UPGRADES:
# - Cryptographic ID Synchronization: Guarantees exact 1:1 Cross-Cloud OIDC 
#   entanglement to satisfy the IdentityFabric's strict bridge requirements.
# - Topological Network Anchoring: Injects deterministic Subnet IDs to ensure 
#   the synthetic graph physically merges with the Live HAPD paths.
# ==============================================================================

class StateFactory:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Simulation.StateFactory")
        # Base scale for threat generation. Modified by dynamic heuristic jitter per run.
        self.base_scale = 20

    def generate_synthetic_topology(self, tenant: TenantConfig) -> List[Dict[str, Any]]:
        """
        The Master Forging Loop.
        Executes dynamic threat generation sequences behind strict fault isolation 
        barriers to ensure a robust, fail-safe synthetic matrix.
        """
        self.logger.debug(f"[{tenant.id}] Igniting Synthetic Threat Matrix...")
        synthetic_nodes: List[Dict[str, Any]] = []

        # Chaos Jitter: Varies the number of standard nodes per scan for topological realism
        variance = lambda base: max(1, int(base * random.uniform(0.8, 1.2)))

        # ----------------------------------------------------------------------
        # CRYPTOGRAPHIC ID SYNCHRONIZATION (THE ZERO-BRIDGE FIX)
        # ----------------------------------------------------------------------
        # To guarantee the IdentityFabric finds the Cross-Cloud bridges, we must 
        # ensure the exact same App IDs are seeded into both Azure and AWS.
        bridge_count = variance(16)
        synchronized_app_ids = [f"api://titan-bridge-{tenant.id.lower()}-{i}" for i in range(bridge_count)]

        # The Forging Task Matrix
        forging_tasks = [
            ("AWS Exposed Compute", self._forge_exposed_compute, variance(self.base_scale)),
            ("AWS Shadow Admins", self._forge_shadow_admin_roles, synchronized_app_ids),
            ("Azure Compromised Identities", self._forge_azure_compromised_identities, synchronized_app_ids),
            ("AWS Vulnerable S3", self._forge_vulnerable_storage_aws, variance(self.base_scale)),
            ("AWS Unencrypted RDS", self._forge_unencrypted_databases, variance(self.base_scale)),
            ("Azure Public Blobs", self._forge_vulnerable_storage_azure, variance(self.base_scale))
        ]

        for task_name, generator_func, parameter in forging_tasks:
            try:
                # Pass either the random count OR the synchronized ID array
                nodes = generator_func(tenant, parameter)
                if nodes:
                    synthetic_nodes.extend(nodes)
                    self.logger.debug(f"[{tenant.id}] Forged {len(nodes)} {task_name} vectors.")
            except Exception as e:
                self.logger.error(f"[{tenant.id}] Forging Anomaly in {task_name}: {e}")
                self.logger.debug(traceback.format_exc())
                continue # Fault Isolation Barrier: Preserve graph integrity and continue

        self.logger.info(f"[{tenant.id}] State Factory cycle complete. Injected {len(synthetic_nodes)} dynamic vulnerabilities.")
        return synthetic_nodes

    # ==========================================================================
    # URM STANDARDIZATION & TOPOLOGICAL ANCHORING
    # ==========================================================================

    def _format_synthetic_node(self, tenant: TenantConfig, cloud: str, service: str, resource_type: str, arn: str, name: str, base_risk: float, specific_metadata: Dict) -> Dict[str, Any]:
        """
        Strict Universal Resource Model (URM) compliance wrapper.
        Applies heuristic risk jitter and injects deterministic Network Anchors.
        """
        # Inject dynamic heuristic variance (-0.5 to +0.5) keeping limits 1.0 - 10.0
        jittered_risk = max(1.0, min(10.0, base_risk + random.uniform(-0.5, 0.5)))
        
        # TOPOLOGICAL ANCHOR: This SubnetId ensures the HAPD Engine physically links 
        # these synthetic nodes to each other via NETWORK_ACCESS edges.
        anchor_subnet = f"subnet-titan-mesh-{tenant.id.lower()}"

        return {
            "tenant_id": tenant.id,
            "cloud_provider": cloud,
            "service": service,
            "type": resource_type,
            "arn": arn,
            "name": name,
            "tags": {
                "Environment": "Simulation",
                "DataOrigin": "Synthetic",
                "SubnetId": anchor_subnet,
                "VpcId": f"vpc-titan-{tenant.id.lower()}"
            },
            "metadata": {
                "arn": arn,
                "resource_type": resource_type,
                "baseline_risk_score": round(jittered_risk, 2),
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "is_simulated": True,
                "SubnetId": anchor_subnet,
                **specific_metadata
            }
        }

    # ==========================================================================
    # THREAT GENERATION LOGIC (AWS)
    # ==========================================================================

    def _forge_exposed_compute(self, tenant: TenantConfig, count: int) -> List[Dict[str, Any]]:
        """Generates Public-facing EC2 instances with highly permissive security groups."""
        nodes = []
        region = getattr(tenant.credentials, "aws_region", "us-east-1")
        account = getattr(tenant.credentials, "aws_account_id", "123456789012")

        for i in range(count):
            inst_id = f"i-synth{uuid.uuid4().hex[:8]}"
            arn = f"arn:aws:ec2:{region}:{account}:instance/{inst_id}"
            
            metadata = {
                "InstanceId": inst_id,
                "InstanceType": random.choice(["t3.micro", "m5.large", "c5.xlarge"]),
                "PublicIpAddress": f"{random.randint(11,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "State": {"Name": "running"},
                "SecurityGroups": [{"GroupId": "sg-synth-000000", "GroupName": "default-allow-all"}],
                "IamInstanceProfile": {"Arn": f"arn:aws:iam::{account}:instance-profile/Synth-Vulnerable-Profile-{i}"}
            }
            
            node = self._format_synthetic_node(tenant, "aws", "ec2", "Instance", arn, f"Synth-Web-Node-{i}", 8.5, metadata)
            node["tags"]["Exposure"] = "Public"
            nodes.append(node)
            
        return nodes

    def _forge_shadow_admin_roles(self, tenant: TenantConfig, synchronized_app_ids: List[str]) -> List[Dict[str, Any]]:
        """
        Generates IAM roles with explicit cross-cloud OIDC trusts.
        Utilizes the synchronized App ID array to guarantee IdentityFabric bridge detection.
        """
        nodes = []
        account = getattr(tenant.credentials, "aws_account_id", "123456789012")
        tenant_uuid = getattr(tenant.credentials, "azure_tenant_id", "simulated-azure-tenant-id")

        for idx, app_id in enumerate(synchronized_app_ids):
            role_name = f"Synth-Azure-Federated-Admin-{idx}"
            arn = f"arn:aws:iam::{account}:role/{role_name}"
            
            # Formulated specifically to trigger the IdentityFabric cross-cloud linkage
            # Must be a physically perfect JSON-compatible dictionary structure
            trust_doc = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": f"sts.windows.net/{tenant_uuid}/"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            # Perfect mathematical alignment with the Azure VM
                            f"sts.windows.net/{tenant_uuid}/:aud": app_id
                        }
                    }
                }]
            }
            
            metadata = {
                "RoleId": f"AROA{uuid.uuid4().hex[:16].upper()}",
                "AssumeRolePolicyDocument": trust_doc,
                "MaxSessionDuration": 43200, # 12 hours (High risk lateral movement window)
                "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
            }
            
            nodes.append(self._format_synthetic_node(tenant, "aws", "iam", "Role", arn, role_name, 9.5, metadata))
            
        return nodes

    def _forge_vulnerable_storage_aws(self, tenant: TenantConfig, count: int) -> List[Dict[str, Any]]:
        """Generates highly vulnerable, public S3 buckets containing PCI-DSS tags."""
        nodes = []
        for i in range(count):
            bucket_name = f"synth-corp-pci-data-{i}-{uuid.uuid4().hex[:6]}"
            arn = f"arn:aws:s3:::{bucket_name}"
            
            metadata = {
                "CreationDate": datetime.now(timezone.utc).isoformat(),
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False
                }
            }
            
            node = self._format_synthetic_node(tenant, "aws", "s3", "Bucket", arn, bucket_name, 7.8, metadata)
            node["tags"]["DataClass"] = "PCI-DSS"
            node["tags"]["Exposure"] = "Public"
            nodes.append(node)
            
        return nodes

    def _forge_unencrypted_databases(self, tenant: TenantConfig, count: int) -> List[Dict[str, Any]]:
        """Generates RDS instances exposed to the internet, acting as Ultimate Crown Jewels."""
        nodes = []
        region = getattr(tenant.credentials, "aws_region", "us-east-1")
        account = getattr(tenant.credentials, "aws_account_id", "123456789012")

        for i in range(count):
            db_id = f"synth-prod-db-{i}"
            arn = f"arn:aws:rds:{region}:{account}:db:{db_id}"
            
            metadata = {
                "DBInstanceIdentifier": db_id,
                "Engine": random.choice(["postgres", "mysql", "aurora"]),
                "StorageEncrypted": False,
                "PubliclyAccessible": True,
                "DBInstanceStatus": "available"
            }
            
            node = self._format_synthetic_node(tenant, "aws", "rds", "DBInstance", arn, db_id, 9.8, metadata)
            node["tags"]["DataClass"] = "PII"
            node["tags"]["Exposure"] = "Public"
            nodes.append(node)
            
        return nodes

    # ==========================================================================
    # THREAT GENERATION LOGIC (AZURE)
    # ==========================================================================

    def _forge_azure_compromised_identities(self, tenant: TenantConfig, synchronized_app_ids: List[str]) -> List[Dict[str, Any]]:
        """
        THE CROSS-CLOUD CATALYST.
        Generates Azure Virtual Machines equipped with System Assigned Managed Identities.
        These identities map perfectly to the AWS IAM OIDC roles above, completing the bridge.
        """
        nodes = []
        sub_id = getattr(tenant.credentials, "azure_subscription_id", "00000000-0000-0000-0000-000000000000")

        for idx, app_id in enumerate(synchronized_app_ids):
            vm_name = f"Synth-Azure-Proxy-VM-{idx}"
            arn = f"/subscriptions/{sub_id}/resourceGroups/Synth-RG-01/providers/Microsoft.Compute/virtualMachines/{vm_name}"
            
            metadata = {
                "location": "eastus",
                "hardwareProfile": {"vmSize": "Standard_B2s"},
                "identity": {
                    "type": "SystemAssigned",
                    "principalId": f"az-sp-{uuid.uuid4().hex[:8]}",
                    "tenantId": getattr(tenant.credentials, "azure_tenant_id", "simulated-azure-tenant-id"),
                    # The strict cryptographic link to the AWS IAM Condition
                    "federatedApplicationId": app_id 
                },
                "networkProfile": {"networkInterfaces": [{"id": "public-nic-01"}]}
            }
            
            node = self._format_synthetic_node(tenant, "azure", "compute", "VirtualMachine", arn, vm_name, 8.8, metadata)
            node["tags"]["Exposure"] = "Public"
            node["tags"]["Role"] = "Bastion"
            nodes.append(node)
            
        return nodes

    def _forge_vulnerable_storage_azure(self, tenant: TenantConfig, count: int) -> List[Dict[str, Any]]:
        """Generates Azure Storage Accounts with public blob access and legacy TLS enabled."""
        nodes = []
        sub_id = getattr(tenant.credentials, "azure_subscription_id", "00000000-0000-0000-0000-000000000000")

        for i in range(count):
            acc_name = f"synthazstorage{i}{uuid.uuid4().hex[:4]}"
            arn = f"/subscriptions/{sub_id}/resourceGroups/Synth-RG-01/providers/Microsoft.Storage/storageAccounts/{acc_name}"
            
            metadata = {
                "location": "eastus",
                "allow_blob_public_access": True,
                "minimum_tls_version": "TLS1_0", # Severe misconfiguration
                "encryption": {"services": {"blob": {"enabled": False}}}
            }
            
            node = self._format_synthetic_node(tenant, "azure", "storage", "StorageAccount", arn, acc_name, 7.5, metadata)
            node["tags"]["Exposure"] = "Public"
            node["tags"]["DataClass"] = "PHI"
            nodes.append(node)
            
        return nodes