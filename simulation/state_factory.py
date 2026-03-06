import logging
import random
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any

from core.config import TenantConfig

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - SYNTHETIC STATE FACTORY
# ==============================================================================
# The Simulation and Vulnerability Forging Engine.
# Generates URM-compliant synthetic infrastructure to simulate advanced persistent 
# threats (APTs), misconfigurations, and cross-cloud privilege escalation vectors.
# ==============================================================================

class StateFactory:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Simulation.StateFactory")
        # Deterministic seed ensures reproducible attack paths during testing
        random.seed(42)

    def generate_synthetic_topology(self, tenant: TenantConfig) -> List[Dict[str, Any]]:
        """
        The Master Forging Loop.
        Generates exactly 96 high-risk nodes designed to trigger the HAPD engine
        and test the Hybrid Bridge's overlay and collision capabilities.
        """
        self.logger.debug(f"[{tenant.id}] Forging synthetic threat matrix...")
        synthetic_nodes: List[Dict[str, Any]] = []

        # 1. Forge Initial Access Vectors (20 Nodes)
        synthetic_nodes.extend(self._forge_exposed_compute(tenant, count=20))
        
        # 2. Forge Privilege Escalation Bridges (16 Nodes)
        synthetic_nodes.extend(self._forge_shadow_admin_roles(tenant, count=16))
        
        # 3. Forge Data Exfiltration Targets (AWS) (40 Nodes)
        synthetic_nodes.extend(self._forge_vulnerable_storage_aws(tenant, count=20))
        synthetic_nodes.extend(self._forge_unencrypted_databases(tenant, count=20))
        
        # 4. Forge Data Exfiltration Targets (Azure) (20 Nodes)
        synthetic_nodes.extend(self._forge_vulnerable_storage_azure(tenant, count=20))

        self.logger.info(f"[{tenant.id}] State Factory generated {len(synthetic_nodes)} synthetic vulnerabilities.")
        return synthetic_nodes

    # ==========================================================================
    # URM STANDARDIZATION
    # ==========================================================================

    def _format_synthetic_node(self, tenant: TenantConfig, cloud: str, service: str, resource_type: str, arn: str, name: str, risk: float, specific_metadata: Dict) -> Dict[str, Any]:
        """Ensures synthetic data perfectly matches the HybridBridge specification."""
        return {
            "tenant_id": tenant.id,
            "cloud_provider": cloud,
            "service": service,
            "type": resource_type,
            "arn": arn,
            "name": name,
            "tags": {
                "Environment": "Simulation",
                "DataOrigin": "Synthetic"
            },
            "metadata": {
                "arn": arn,
                "resource_type": resource_type,
                "baseline_risk_score": float(risk),
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "is_simulated": True,
                **specific_metadata
            }
        }

    # ==========================================================================
    # THREAT GENERATION LOGIC
    # ==========================================================================

    def _forge_exposed_compute(self, tenant: TenantConfig, count: int) -> List[Dict[str, Any]]:
        """Generates Public-facing EC2 instances with vulnerable configurations."""
        nodes = []
        region = getattr(tenant.credentials, "aws_region", "us-east-1")
        account = getattr(tenant.credentials, "aws_account_id", "123456789012")

        for i in range(count):
            inst_id = f"i-synth{uuid.uuid4().hex[:8]}"
            arn = f"arn:aws:ec2:{region}:{account}:instance/{inst_id}"
            
            metadata = {
                "InstanceId": inst_id,
                "InstanceType": "t3.micro",
                "PublicIpAddress": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "State": {"Name": "running"},
                "SecurityGroups": [{"GroupId": "sg-synth-open-world"}],
                # Seeds a link for the Identity Fabric to pick up
                "IamInstanceProfile": {"Arn": f"arn:aws:iam::{account}:instance-profile/Synth-Vulnerable-Profile-{i}"}
            }
            
            node = self._format_synthetic_node(tenant, "aws", "ec2", "Instance", arn, f"Synth-Web-Node-{i}", 8.5, metadata)
            node["tags"]["Exposure"] = "Public"
            nodes.append(node)
            
        return nodes

    def _forge_shadow_admin_roles(self, tenant: TenantConfig, count: int) -> List[Dict[str, Any]]:
        """Generates IAM roles with cross-cloud OIDC trusts (Shadow Admins)."""
        nodes = []
        account = getattr(tenant.credentials, "aws_account_id", "123456789012")

        for i in range(count):
            role_name = f"Synth-Azure-Federated-Admin-{i}"
            arn = f"arn:aws:iam::{account}:role/{role_name}"
            
            # The exact payload the IdentityFabric looks for to map Cross-Cloud edges
            trust_doc = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "sts.windows.net/simulated-azure-tenant-id/"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity"
                }]
            }
            
            metadata = {
                "RoleId": f"AROA{uuid.uuid4().hex[:16].upper()}",
                "AssumeRolePolicyDocument": trust_doc,
                "MaxSessionDuration": 43200
            }
            
            nodes.append(self._format_synthetic_node(tenant, "aws", "iam", "Role", arn, role_name, 9.0, metadata))
            
        return nodes

    def _forge_vulnerable_storage_aws(self, tenant: TenantConfig, count: int) -> List[Dict[str, Any]]:
        """Generates highly vulnerable, public S3 buckets containing sensitive data tags."""
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
            
            node = self._format_synthetic_node(tenant, "aws", "s3", "Bucket", arn, bucket_name, 7.5, metadata)
            node["tags"]["DataClass"] = "PCI-DSS"
            node["tags"]["Exposure"] = "Public"
            nodes.append(node)
            
        return nodes

    def _forge_unencrypted_databases(self, tenant: TenantConfig, count: int) -> List[Dict[str, Any]]:
        """Generates RDS instances exposed to the internet with encryption disabled."""
        nodes = []
        region = getattr(tenant.credentials, "aws_region", "us-east-1")
        account = getattr(tenant.credentials, "aws_account_id", "123456789012")

        for i in range(count):
            db_id = f"synth-prod-db-{i}"
            arn = f"arn:aws:rds:{region}:{account}:db:{db_id}"
            
            metadata = {
                "DBInstanceIdentifier": db_id,
                "Engine": "postgres",
                "StorageEncrypted": False,
                "PubliclyAccessible": True,
                "DBInstanceStatus": "available"
            }
            
            node = self._format_synthetic_node(tenant, "aws", "rds", "DBInstance", arn, db_id, 9.5, metadata)
            node["tags"]["DataClass"] = "PII"
            node["tags"]["Exposure"] = "Public"
            nodes.append(node)
            
        return nodes

    def _forge_vulnerable_storage_azure(self, tenant: TenantConfig, count: int) -> List[Dict[str, Any]]:
        """Generates Azure Storage Accounts with public blob access enabled."""
        nodes = []
        sub_id = getattr(tenant.credentials, "azure_subscription_id", "00000000-0000-0000-0000-000000000000")

        for i in range(count):
            acc_name = f"synthazurestorage{i}"
            arn = f"/subscriptions/{sub_id}/resourceGroups/Synth-RG-01/providers/Microsoft.Storage/storageAccounts/{acc_name}"
            
            metadata = {
                "location": "eastus",
                "allow_blob_public_access": True,
                "minimum_tls_version": "TLS1_0" # Outdated TLS for risk inflation
            }
            
            node = self._format_synthetic_node(tenant, "azure", "storage", "StorageAccount", arn, acc_name, 7.0, metadata)
            node["tags"]["Exposure"] = "Public"
            nodes.append(node)
            
        return nodes