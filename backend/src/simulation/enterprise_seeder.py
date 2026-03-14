import json
import logging
import time
import boto3
from botocore.exceptions import ClientError
from typing import Dict, List

from core.config import config, TenantConfig

# Configure standard logging for the seeder
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [SEEDER] - %(message)s")
logger = logging.getLogger("CloudScape.Seeder")

# ==============================================================================
# PROJECT CLOUDSCAPE: VULNERABLE-BY-DESIGN ENTERPRISE SEEDER
# ==============================================================================

class EnterpriseMeshSeeder:
    """
    Automated Infrastructure-as-Code (IaC) generator for the local mesh.
    Injects specific cross-account vulnerabilities into LocalStack to test the
    Discovery and Correlation engines.
    """

    def __init__(self, tenant_registry: List[TenantConfig]):
        self.tenants = {t.id: t for t in tenant_registry if t.provider == "aws"}
        if len(self.tenants) < 2:
            logger.warning("At least 2 AWS tenants are required in tenants.yaml to seed cross-account links.")

    def _get_client(self, tenant_id: str, service_name: str) -> boto3.client:
        """Helper to generate targeted boto3 clients for specific LocalStack ports."""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant {tenant_id} not found.")
        
        return boto3.client(
            service_name,
            endpoint_url=tenant.endpoint_url,
            region_name=tenant.region,
            aws_access_key_id=tenant.auth.aws_access_key_id,
            aws_secret_access_key=tenant.auth.aws_secret_access_key
        )

    def wait_for_mesh(self):
        """Pings the STS service of all tenants to ensure Docker containers are ready."""
        logger.info("Waiting for LocalStack containers to initialize...")
        for t_id in self.tenants:
            client = self._get_client(t_id, 'sts')
            retries = 5
            while retries > 0:
                try:
                    client.get_caller_identity()
                    logger.info(f"[{t_id}] LocalStack Endpoint is Online.")
                    break
                except Exception:
                    logger.warning(f"[{t_id}] Endpoint not ready. Retrying in 3 seconds...")
                    time.sleep(3)
                    retries -= 1
            if retries == 0:
                raise ConnectionError(f"Failed to connect to Tenant {t_id} after multiple attempts.")

    def seed_finance_tenant(self, tenant_id: str):
        """Creates the 'Crown Jewel' environment (High Security)."""
        logger.info(f"[{tenant_id}] Seeding Finance Environment...")
        s3 = self._get_client(tenant_id, 's3')
        iam = self._get_client(tenant_id, 'iam')

        try:
            # 1. Create a highly sensitive data bucket
            bucket_name = "finance-payroll-vault-local"
            s3.create_bucket(Bucket=bucket_name)
            
            # 2. Create a restricted IAM Role
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }
            iam.create_role(
                RoleName="Finance_Strict_EC2_Role",
                AssumeRolePolicyDocument=json.dumps(trust_policy)
            )
            logger.info(f"[{tenant_id}] Finance base resources created.")
        except ClientError as e:
            logger.error(f"[{tenant_id}] Seeding failed: {e}")

    def seed_production_tenant(self, tenant_id: str):
        """Creates the 'Public Facing' environment (Lower Security)."""
        logger.info(f"[{tenant_id}] Seeding Production Environment...")
        ec2 = self._get_client(tenant_id, 'ec2')

        try:
            # 1. Create a basic VPC
            vpc_response = ec2.create_vpc(CidrBlock='10.0.0.0/16')
            vpc_id = vpc_response['Vpc']['VpcId']
            ec2.create_tags(Resources=[vpc_id], Tags=[{'Key': 'Name', 'Value': 'Prod-Public-VPC'}])
            logger.info(f"[{tenant_id}] Production base resources created (VPC: {vpc_id}).")
            return vpc_id
        except ClientError as e:
            logger.error(f"[{tenant_id}] Seeding failed: {e}")
            return None

    def inject_cross_account_vulnerabilities(self, finance_id: str, prod_id: str):
        """
        THE MASTER INJECTION: Creates the hidden attack paths your scanner must find.
        Injects a Trust Policy in Finance that allows Production to assume it.
        """
        logger.info("--- INJECTING CROSS-ACCOUNT VULNERABILITIES ---")
        
        finance_tenant = self.tenants.get(finance_id)
        prod_tenant = self.tenants.get(prod_id)
        
        if not finance_tenant or not prod_tenant:
            logger.error("Missing tenants for cross-account injection. Skipping.")
            return

        finance_iam = self._get_client(finance_id, 'iam')

        try:
            # VULNERABILITY 1: Cross-Account IAM Trust (The Backdoor)
            # We create a role in FINANCE that allows the PROD account to assume it.
            # This is a classic privilege escalation path.
            backdoor_trust_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{prod_tenant.account_id}:root"
                    },
                    "Action": "sts:AssumeRole"
                }]
            }
            
            finance_iam.create_role(
                RoleName="Vendor_CrossAccount_Access",
                AssumeRolePolicyDocument=json.dumps(backdoor_trust_policy)
            )
            logger.info(f"[VULN] Injected Cross-Account Role in {finance_id} trusting {prod_id}.")

        except ClientError as e:
            # Ignore EntityAlreadyExists if the script is run multiple times
            if e.response['Error']['Code'] != 'EntityAlreadyExists':
                logger.error(f"Failed to inject vulnerability: {e}")

    def run(self):
        """Executes the full enterprise mesh seeding sequence."""
        logger.info("Starting Enterprise Mesh Seeder...")
        try:
            self.wait_for_mesh()
            
            # Use specific tenant IDs based on the registry
            fin_id = "PROJ-FIN-01"
            prod_id = "PROJ-PROD-02"

            if fin_id in self.tenants:
                self.seed_finance_tenant(fin_id)
            if prod_id in self.tenants:
                self.seed_production_tenant(prod_id)
                
            if fin_id in self.tenants and prod_id in self.tenants:
                self.inject_cross_account_vulnerabilities(fin_id, prod_id)
                
            logger.info("Enterprise Mesh successfully seeded. Ready for Discovery Orchestrator.")
        except Exception as e:
            logger.error(f"Seeder aborted due to critical error: {e}")

if __name__ == "__main__":
    seeder = EnterpriseMeshSeeder(list(config.tenants.values()))
    seeder.run()