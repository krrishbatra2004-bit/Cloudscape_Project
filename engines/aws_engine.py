import logging
import boto3
from botocore.exceptions import ClientError
from typing import Dict, Any, List

from core.config import TenantConfig

logger = logging.getLogger("Cloudscape.AWSEngine")

# ==============================================================================
# PROJECT CLOUDSCAPE: AWS MULTI-TENANT DISCOVERY ENGINE
# ==============================================================================

class AWSEngine:
    """
    Enterprise-grade AWS API Crawler.
    Designed to extract Cloud Infrastructure State using Boto3, fully supporting
    custom endpoint routing for multi-tenant mock environments (LocalStack/Moto).
    """

    def __init__(self, config: TenantConfig):
        self.config = config
        self.region = config.region
        self.endpoint_url = config.endpoint_url
        
        # Initialize a dedicated session for this specific tenant to avoid cross-contamination
        self.session = boto3.Session(
            aws_access_key_id=config.auth.aws_access_key_id,
            aws_secret_access_key=config.auth.aws_secret_access_key,
            region_name=self.region
        )
        logger.debug(f"[{self.config.id}] Initialized AWS Engine targeting {self.endpoint_url}")

    def _get_client(self, service_name: str) -> boto3.client:
        """
        Factory method to generate boto3 clients that override the default AWS URLs.
        This is the mechanism that allows us to target LocalStack ports.
        """
        return self.session.client(
            service_name,
            endpoint_url=self.endpoint_url,
            region_name=self.region
        )

    def _discover_iam(self) -> Dict[str, Any]:
        """
        Recursively maps Identity and Access Management.
        CRITICAL: Extracts 'AssumeRolePolicyDocument' for cross-account correlation.
        """
        logger.info(f"[{self.config.id}] Scanning IAM Matrix...")
        iam = self._get_client('iam')
        state = {"Users": [], "Roles": [], "Policies": []}

        try:
            # 1. Fetch Users
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                state["Users"].extend(page.get('Users', []))

            # 2. Fetch Roles (Crucial for Transitive Trust Mapping)
            role_paginator = iam.get_paginator('list_roles')
            for page in role_paginator.paginate():
                for role in page.get('Roles', []):
                    # Attach inline policies for deeper analysis
                    try:
                        inline_policies = iam.list_role_policies(RoleName=role['RoleName']).get('PolicyNames', [])
                        role['Cloudscape_InlinePolicies'] = inline_policies
                    except ClientError:
                        role['Cloudscape_InlinePolicies'] = []
                    state["Roles"].append(role)

            # 3. Fetch Managed Policies
            policy_paginator = iam.get_paginator('list_policies')
            for page in policy_paginator.paginate(Scope='Local'): # Only get customer-managed
                state["Policies"].extend(page.get('Policies', []))

        except ClientError as e:
            logger.error(f"[{self.config.id}] IAM Discovery Failed: {e}")
            
        return state

    def _discover_network(self) -> Dict[str, Any]:
        """
        Maps the Network Fabric. Focuses heavily on VPC Peering and Transit Gateways
        to establish lateral movement paths across the Enterprise Mesh.
        """
        logger.info(f"[{self.config.id}] Scanning Network Topology...")
        ec2 = self._get_client('ec2')
        state = {"VPCs": [], "Subnets": [], "PeeringConnections": [], "TransitGateways": []}

        try:
            # VPCs and Subnets
            state["VPCs"] = ec2.describe_vpcs().get('Vpcs', [])
            state["Subnets"] = ec2.describe_subnets().get('Subnets', [])

            # Cross-Network Bridges
            state["PeeringConnections"] = ec2.describe_vpc_peering_connections().get('VpcPeeringConnections', [])
            
            # Note: TGW might not be fully supported in basic LocalStack, but we code for production
            try:
                state["TransitGateways"] = ec2.describe_transit_gateways().get('TransitGateways', [])
            except ClientError:
                logger.warning(f"[{self.config.id}] Transit Gateway API not supported/available in this environment.")

        except ClientError as e:
            logger.error(f"[{self.config.id}] Network Discovery Failed: {e}")

        return state

    def _discover_compute(self) -> Dict[str, Any]:
        """
        Maps Compute instances and their attached Security Groups.
        """
        logger.info(f"[{self.config.id}] Scanning Compute Assets...")
        ec2 = self._get_client('ec2')
        state = {"Instances": [], "SecurityGroups": []}

        try:
            # Extract Instances from Reservations
            reservations = ec2.describe_instances().get('Reservations', [])
            for res in reservations:
                state["Instances"].extend(res.get('Instances', []))

            # Fetch Security Groups
            state["SecurityGroups"] = ec2.describe_security_groups().get('SecurityGroups', [])

        except ClientError as e:
            logger.error(f"[{self.config.id}] Compute Discovery Failed: {e}")

        return state

    def run_full_discovery(self) -> Dict[str, Any]:
        """
        The Master Executor for this engine. Called by the Orchestrator thread.
        Aggregates all domain states into a single, massive JSON-serializable dictionary.
        """
        logger.info(f"[{self.config.id}] Commencing Full Discovery via {self.endpoint_url}")
        
        # Execute scans sequentially per tenant (The Orchestrator handles parallelizing the tenants)
        full_state = {
            "IAM": self._discover_iam(),
            "Network": self._discover_network(),
            "Compute": self._discover_compute()
        }
        
        # Calculate brief summary metrics for logging
        total_assets = sum(len(items) for category in full_state.values() for items in category.values())
        logger.info(f"[{self.config.id}] Discovery Complete. Extracted {total_assets} total resources.")
        
        return full_state