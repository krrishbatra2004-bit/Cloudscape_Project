import boto3
import logging
from botocore.config import Config as BotoConfig
from typing import Dict, Any, List
from drivers.base_driver import BaseCloudDriver
from core.config import settings

class AWSDriver(BaseCloudDriver):
    """
    Exhaustive AWS Discovery Driver.
    Extracts all compute, storage, networking, security, and integration services.
    Strictly implements the BaseCloudDriver contract.
    """

    def __init__(self):
        super().__init__()
        self.endpoint_url = settings.AWS_ENDPOINT_URL
        self.region = settings.AWS_REGION
        self.boto_config = BotoConfig(
            retries={'max_attempts': 3, 'mode': 'standard'}
        )
        # We satisfy the abstract method contract here
        self.session = self.initialize_session()

    def initialize_session(self) -> Any:
        """Implements abstract method: Initializes a local-compliant AWS session."""
        return boto3.Session(
            aws_access_key_id="test",
            aws_secret_access_key="test",
            region_name=self.region
        )

    def _get_client(self, service_name: str) -> Any:
        """Generates a highly-available Boto3 client pointing to the local Vault engine."""
        return self.session.client(
            service_name,
            endpoint_url=self.endpoint_url,
            config=self.boto_config
        )

    def scan_network(self) -> Dict[str, Any]:
        """Exhaustive scan of the VPC Topology and Firewalls (Security Groups)."""
        self.logger.info("Scanning Network & Security Layer...")
        network_manifest = {
            "vpcs": [],
            "subnets": [],
            "security_groups": [],
            "internet_gateways": [],
            "route_tables": []
        }
        try:
            ec2 = self._get_client('ec2')
            network_manifest['vpcs'] = ec2.describe_vpcs().get('Vpcs', [])
            network_manifest['subnets'] = ec2.describe_subnets().get('Subnets', [])
            network_manifest['security_groups'] = ec2.describe_security_groups().get('SecurityGroups', [])
            network_manifest['internet_gateways'] = ec2.describe_internet_gateways().get('InternetGateways', [])
            network_manifest['route_tables'] = ec2.describe_route_tables().get('RouteTables', [])
        except Exception as e:
            self.logger.error(f"Network Scan Failure: {e}", exc_info=True)
        return network_manifest

    def scan_identity(self) -> Dict[str, Any]:
        """Extracts IAM Roles and Profiles to calculate blast radius and access paths."""
        self.logger.info("Scanning Identity & Access Management Layer...")
        identity_manifest = {
            "roles": [],
            "instance_profiles": []
        }
        try:
            iam = self._get_client('iam')
            identity_manifest['roles'] = iam.list_roles().get('Roles', [])
            identity_manifest['instance_profiles'] = iam.list_instance_profiles().get('InstanceProfiles', [])
        except Exception as e:
            self.logger.error(f"IAM Scan Failure: {e}", exc_info=True)
        return identity_manifest

    def scan_compute(self) -> Dict[str, Any]:
        """Scans all compute workloads: EC2 instances, ECS clusters, and Serverless Lambdas."""
        self.logger.info("Scanning Compute & Container Workloads...")
        compute_manifest = {
            "ec2_instances": [],
            "ecs_clusters": [],
            "lambda_functions": []
        }
        try:
            ec2 = self._get_client('ec2')
            reservations = ec2.describe_instances().get('Reservations', [])
            for res in reservations:
                compute_manifest['ec2_instances'].extend(res.get('Instances', []))
            
            ecs = self._get_client('ecs')
            clusters = ecs.list_clusters().get('clusterArns', [])
            compute_manifest['ecs_clusters'] = clusters

            lmb = self._get_client('lambda')
            compute_manifest['lambda_functions'] = lmb.list_functions().get('Functions', [])
        except Exception as e:
            self.logger.error(f"Compute Scan Failure: {e}", exc_info=True)
        return compute_manifest

    def scan_storage(self) -> List[Dict[str, Any]]:
        """Scans global S3 bucket infrastructure."""
        self.logger.info("Scanning Storage Assets...")
        try:
            s3 = self._get_client('s3')
            return s3.list_buckets().get('Buckets', [])
        except Exception as e:
            self.logger.error(f"Storage Scan Failure: {e}", exc_info=True)
            return []

    def scan_databases(self) -> Dict[str, Any]:
        """Scans Relational (RDS) and NoSQL (DynamoDB) databases."""
        self.logger.info("Scanning Database Assets...")
        db_manifest = {
            "rds_clusters": [],
            "rds_instances": [],
            "dynamodb_tables": []
        }
        try:
            rds = self._get_client('rds')
            db_manifest['rds_clusters'] = rds.describe_db_clusters().get('DBClusters', [])
            db_manifest['rds_instances'] = rds.describe_db_instances().get('DBInstances', [])
            
            ddb = self._get_client('dynamodb')
            db_manifest['dynamodb_tables'] = ddb.list_tables().get('TableNames', [])
        except Exception as e:
            self.logger.error(f"Database Scan Failure: {e}", exc_info=True)
        return db_manifest

    def scan_integration(self) -> Dict[str, Any]:
        """Scans message queues and pub/sub topics (Microservice glue)."""
        self.logger.info("Scanning Integration & Event Services...")
        integration_manifest = {
            "sqs_queues": [],
            "sns_topics": []
        }
        try:
            sqs = self._get_client('sqs')
            integration_manifest['sqs_queues'] = sqs.list_queues().get('QueueUrls', [])
            
            sns = self._get_client('sns')
            integration_manifest['sns_topics'] = sns.list_topics().get('Topics', [])
        except Exception as e:
            self.logger.error(f"Integration Scan Failure: {e}", exc_info=True)
        return integration_manifest

    def get_full_inventory(self) -> Dict[str, Any]:
        """
        Orchestrates the exhaustive scan across all AWS domains.
        Returns a massive, strictly structured JSON dictionary ready for Graph correlation.
        """
        self.logger.info("--- INITIATING OMNI-LAYER CLOUD SCAN ---")
        
        inventory = {
            "provider": "aws",
            "metadata": {
                "region": self.region,
                "scan_type": "exhaustive_security_audit"
            },
            "network": self.scan_network(),
            "identity": self.scan_identity(),
            "compute": self.scan_compute(),
            "storage": self.scan_storage(),
            "database": self.scan_databases(),
            "integration": self.scan_integration()
        }
        
        self.logger.info("--- OMNI-LAYER CLOUD SCAN COMPLETE ---")
        return inventory