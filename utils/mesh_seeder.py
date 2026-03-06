import logging
import asyncio
import json
import time
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# Azure SDK Imports
try:
    from azure.storage.blob.aio import BlobServiceClient
    from azure.core.exceptions import ResourceExistsError
except ImportError:
    BlobServiceClient = None

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - TENANT-AWARE MESH SEEDER
# ==============================================================================
# Deep Hydration Engine. Provisions isolated network topologies and storage 
# mechanisms per tenant. Applies mandatory 'CloudscapeTenantID' tags and metadata 
# to bypass the Orchestrator's strict Cross-Contamination Gatekeeper.
# ==============================================================================

class MeshSeeder:
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Utils.MeshSeeder")
        
        # ----------------------------------------------------------------------
        # TARGET TENANT MATRIX
        # ----------------------------------------------------------------------
        self.tenants = [
            "PROJ-FIN-01", 
            "PROJ-WEB-02", 
            "PROJ-SHR-03", 
            "PROJ-AZURE-04", 
            "PROJ-DR-05"
        ]
        
        # ----------------------------------------------------------------------
        # EXPLICIT AWS GATEWAY (Shadowing Bypass)
        # ----------------------------------------------------------------------
        self.aws_region = "ap-south-1"
        self.aws_creds = {
            "aws_access_key_id": "testing",
            "aws_secret_access_key": "testing",
            "region_name": self.aws_region,
            "endpoint_url": "http://localhost:4566",
            "config": Config(retries={'max_attempts': 1})
        }

        # ----------------------------------------------------------------------
        # AZURE GATEWAY
        # ----------------------------------------------------------------------
        self.azure_conn_str = (
            "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
            "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
            "BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"
        )

    async def execute(self):
        """Master execution loop for Tenant-Aware deep hydration."""
        self.logger.info(f"Initializing Tenant-Aware Mesh Hydration Sequence in {self.aws_region}...")
        
        tasks = [self._seed_aws_infrastructure()]
        
        if BlobServiceClient is not None:
            tasks.append(self._seed_azure_infrastructure())
        else:
            self.logger.error("Azure SDK missing. Skipping Azurite hydration.")

        await asyncio.gather(*tasks)
        self.logger.info("======================================================")
        self.logger.info(" Tenant Mesh Hydration Complete. Sensors may now be engaged.")
        self.logger.info("======================================================")

    # ==========================================================================
    # AWS TENANT HYDRATION (LOCALSTACK)
    # ==========================================================================

    async def _seed_aws_infrastructure(self):
        """Asynchronous wrapper for the synchronous Boto3 SDK."""
        self.logger.info("Engaging AWS LocalStack Tenant Hydration Protocol...")
        try:
            await asyncio.to_thread(self._provision_aws_core)
        except Exception as e:
            self.logger.error(f"AWS Tenant Seeding collapsed: {e}")

    def _provision_aws_core(self):
        """
        Iterates through every tenant, calculating isolated CIDR blocks, 
        provisioning infrastructure, and applying mandatory ownership tags.
        """
        ec2 = boto3.client('ec2', **self.aws_creds)
        s3 = boto3.client('s3', **self.aws_creds)
        iam = boto3.client('iam', **self.aws_creds)

        for index, tenant_id in enumerate(self.tenants):
            self.logger.info(f" -> Forging Isolated AWS Infrastructure for: {tenant_id}")
            
            # Standardized Tenant Tags
            tenant_tags = [
                {'Key': 'CloudscapeTenantID', 'Value': tenant_id},
                {'Key': 'ManagedBy', 'Value': 'CloudscapeSeeder'}
            ]

            # 1. Identity Provisioning
            role_name = f"Cloudscape-Federation-Role-{tenant_id}"
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
            }
            try:
                iam.create_role(
                    RoleName=role_name, 
                    AssumeRolePolicyDocument=json.dumps(trust_policy),
                    Tags=tenant_tags
                )
            except ClientError as e:
                if e.response['Error']['Code'] != 'EntityAlreadyExists':
                    self.logger.error(f"IAM Error for {tenant_id}: {e}")

            # 2. Network Topology (Isolated CIDR per Tenant to prevent overlap)
            vpc_cidr = f"10.{index}.0.0/16"
            sub_cidr = f"10.{index}.1.0/24"
            
            try:
                # VPC
                vpc = ec2.create_vpc(CidrBlock=vpc_cidr)
                vpc_id = vpc['Vpc']['VpcId']
                ec2.create_tags(Resources=[vpc_id], Tags=[{'Key': 'Name', 'Value': f'Core-VPC-{tenant_id}'}] + tenant_tags)
                
                # Subnet
                subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock=sub_cidr)
                sub_id = subnet['Subnet']['SubnetId']
                ec2.create_tags(Resources=[sub_id], Tags=[{'Key': 'Name', 'Value': f'Public-Subnet-{tenant_id}'}] + tenant_tags)

                # Security Group
                sg = ec2.create_security_group(GroupName=f'web-sg-{tenant_id}', Description='Allow public inbound', VpcId=vpc_id)
                sg_id = sg['GroupId']
                ec2.create_tags(Resources=[sg_id], Tags=[{'Key': 'Name', 'Value': f'Web-SG-{tenant_id}'}] + tenant_tags)
                
                # 3. Compute Resources
                ec2.run_instances(
                    ImageId='ami-df5de72bdb3bfa507',
                    InstanceType='t3.micro',
                    MaxCount=1,
                    MinCount=1,
                    SubnetId=sub_id,
                    SecurityGroupIds=[sg_id],
                    TagSpecifications=[{
                        'ResourceType': 'instance',
                        'Tags': [{'Key': 'Name', 'Value': f'Worker-Node-{tenant_id}'}] + tenant_tags
                    }]
                )
            except ClientError as e:
                self.logger.debug(f"Network infrastructure for {tenant_id} already exists or failed: {e.response['Error']['Code']}")

            # 4. Storage Resources
            bucket_name = f"cloudscape-assets-{tenant_id.lower()}-v5"
            try:
                s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': self.aws_region})
                # Apply Tenant Signature to Bucket
                s3.put_bucket_tagging(Bucket=bucket_name, Tagging={'TagSet': tenant_tags})
                
                # Inject Physical Object with Metadata Signature
                s3.put_object(
                    Bucket=bucket_name, 
                    Key='sensitive_payload.csv', 
                    Body=b'record_id,secret\n1,REDACTED',
                    Metadata={'cloudscapetenantid': tenant_id}
                )
            except ClientError as e:
                if e.response['Error']['Code'] not in ['BucketAlreadyExists', 'BucketAlreadyOwnedByYou']:
                    self.logger.error(f"S3 Error for {tenant_id}: {e}")

    # ==========================================================================
    # AZURE TENANT HYDRATION (AZURITE)
    # ==========================================================================

    async def _seed_azure_infrastructure(self):
        """Provisions Blob Containers and injects files with Tenant Metadata."""
        self.logger.info("Engaging Azure Azurite Tenant Hydration Protocol...")
        
        try:
            blob_service_client = BlobServiceClient.from_connection_string(self.azure_conn_str)
            async with blob_service_client:
                for tenant_id in self.tenants:
                    self.logger.info(f" -> Forging Azure Storage for: {tenant_id}")
                    
                    container_name = f"data-lake-{tenant_id.lower()}"
                    tenant_metadata = {"cloudscapetenantid": tenant_id, "managedby": "cloudscapeseeder"}
                    
                    container_client = blob_service_client.get_container_client(container_name)
                    try:
                        await container_client.create_container(metadata=tenant_metadata)
                    except ResourceExistsError:
                        pass # Container exists, proceed to inject file
                        
                    # Inject physical blob with Tenant Signature to trigger AzureEngine
                    blob_client = container_client.get_blob_client("infrastructure_state.tfstate")
                    await blob_client.upload_blob(
                        b'{"version": 4, "state": "active"}', 
                        metadata=tenant_metadata, 
                        overwrite=True
                    )
                    
        except Exception as e:
            self.logger.error(f"Azure Tenant Seeding collapsed: {e}")