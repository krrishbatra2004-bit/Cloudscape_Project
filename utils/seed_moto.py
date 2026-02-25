import boto3
import logging
import json
import time
from botocore.config import Config

# ==========================================
# ADVANCED SECURITY SEEDER
# Purpose: Generates a topology with specific 'Attack Paths' for Graph Analysis.
# ==========================================

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Cloudscape_Security_Seeder")

class SecurityTopologySeeder:
    def __init__(self, endpoint_url="http://localhost:4566", region="us-east-1"):
        self.endpoint_url = endpoint_url
        self.region = region
        self.boto_config = Config(retries={'max_attempts': 3, 'mode': 'standard'})
        self.creds = {"aws_access_key_id": "test", "aws_secret_access_key": "test"}
        
        # State tracking for cross-referencing IDs
        self.state = {
            "vpc": None,
            "subnets": {},
            "sgs": {},
            "roles": {},
            "instances": []
        }

    def _get_client(self, service):
        return boto3.client(service, endpoint_url=self.endpoint_url, region_name=self.region, config=self.boto_config, **self.creds)

    def _get_resource(self, service):
        return boto3.resource(service, endpoint_url=self.endpoint_url, region_name=self.region, config=self.boto_config, **self.creds)

    def seed_iam_identities(self):
        """Creates IAM Roles with specific privilege levels (Attack Vectors)."""
        logger.info("[1/6] Seeding Identity & Access Management (IAM)...")
        iam = self._get_client('iam')

        # 1. High-Privilege Role (The "Crown Jewel" access)
        admin_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }
        try:
            role = iam.create_role(
                RoleName='Admin_Maintenance_Role',
                AssumeRolePolicyDocument=json.dumps(admin_policy) # Simplified for Moto
            )
            self.state['roles']['admin'] = 'Admin_Maintenance_Role'
            
            # 2. Web Role (Limited access, but has S3 Read)
            web_policy = {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::cloudscape-public-assets/*"}]
            }
            iam.create_role(
                RoleName='Web_Server_Role',
                AssumeRolePolicyDocument=json.dumps(web_policy)
            )
            self.state['roles']['web'] = 'Web_Server_Role'
            
            # 3. Instance Profiles (To attach roles to EC2)
            iam.create_instance_profile(InstanceProfileName='Web_Profile')
            iam.add_role_to_instance_profile(InstanceProfileName='Web_Profile', RoleName='Web_Server_Role')
            
            logger.info("✔ IAM Roles & Profiles Created.")
        except Exception as e:
            logger.warning(f"IAM Seed Warning (ignore if exists): {e}")

    def seed_network_security(self):
        """Creates VPC and complex Security Groups (Firewalls)."""
        logger.info("[2/6] Seeding Network Security Groups...")
        ec2 = self._get_resource('ec2')
        client = self._get_client('ec2')

        # 1. VPC
        vpc = ec2.create_vpc(CidrBlock='10.10.0.0/16')
        vpc.create_tags(Tags=[{'Key': 'Name', 'Value': 'Enterprise-Secure-VPC'}])
        self.state['vpc'] = vpc.id

        # 2. Subnets
        pub_sub = vpc.create_subnet(CidrBlock='10.10.1.0/24', AvailabilityZone=f'{self.region}a')
        priv_sub = vpc.create_subnet(CidrBlock='10.10.2.0/24', AvailabilityZone=f'{self.region}b')
        self.state['subnets']['public'] = pub_sub.id
        self.state['subnets']['private'] = priv_sub.id

        # 3. Security Groups (The "Lateral Movement" Path)
        # SG-Web: Open to World (0.0.0.0/0)
        sg_web = vpc.create_security_group(GroupName='SG-Web-Frontend', Description='Public Access')
        sg_web.authorize_ingress(IpProtocol='tcp', FromPort=80, ToPort=80, CidrIp='0.0.0.0/0')
        self.state['sgs']['web'] = sg_web.id

        # SG-App: Only allows traffic from SG-Web (The trust link)
        sg_app = vpc.create_security_group(GroupName='SG-App-Backend', Description='Internal Only')
        # Moto specific permission structure for SG-to-SG reference
        client.authorize_security_group_ingress(
            GroupId=sg_app.id,
            IpPermissions=[{
                'IpProtocol': 'tcp', 'FromPort': 8080, 'ToPort': 8080,
                'UserIdGroupPairs': [{'GroupId': sg_web.id}]
            }]
        )
        self.state['sgs']['app'] = sg_app.id
        
        logger.info("✔ Network Firewalls Configured (Web -> App trust established).")

    def seed_compute_workloads(self):
        """Deploys EC2 instances with attached Security Groups and IAM Roles."""
        logger.info("[3/6] Deploying Compute with Security Context...")
        ec2 = self._get_resource('ec2')

        # 1. Public Web Server (The Entry Point)
        # Has Public IP + Web Role + Web SG
        ec2.create_instances(
            ImageId='ami-12345678', MinCount=1, MaxCount=1,
            InstanceType='t3.micro',
            SubnetId=self.state['subnets']['public'],
            SecurityGroupIds=[self.state['sgs']['web']],
            IamInstanceProfile={'Name': 'Web_Profile'},
            TagSpecifications=[{'ResourceType': 'instance', 'Tags': [{'Key': 'Name', 'Value': 'Public-Web-Node'}]}]
        )

        # 2. Private App Server (The Target)
        # Has Internal SG (only accessible via Web Node)
        ec2.create_instances(
            ImageId='ami-87654321', MinCount=1, MaxCount=1,
            InstanceType='m5.large',
            SubnetId=self.state['subnets']['private'],
            SecurityGroupIds=[self.state['sgs']['app']],
            TagSpecifications=[{'ResourceType': 'instance', 'Tags': [{'Key': 'Name', 'Value': 'Internal-API-Node'}]}]
        )
        logger.info("✔ EC2 Instances deployed with IAM and SG contexts.")

    def seed_data_layer(self):
        """Creates S3 and RDS to demonstrate Data Gravity."""
        logger.info("[4/6] Seeding Data Assets...")
        s3 = self._get_client('s3')
        rds = self._get_client('rds')

        # S3: One Public, One Sensitive
        s3.create_bucket(Bucket='cloudscape-public-assets')
        s3.create_bucket(Bucket='cloudscape-financial-records-confidential') # The target

        # RDS: Deployed in Private Subnet
        try:
            rds.create_db_subnet_group(
                DBSubnetGroupName='private-db-subnet',
                DBSubnetGroupDescription='Private DB Access',
                SubnetIds=[self.state['subnets']['private']]
            )
            rds.create_db_cluster(
                DBClusterIdentifier='legacy-payroll-db',
                Engine='aurora',
                DBSubnetGroupName='private-db-subnet'
            )
        except Exception:
            pass # Handle potential Moto RDS quirks gracefully
        
        logger.info("✔ Data Layer (S3/RDS) provisioned.")

    def run(self):
        logger.info("--- STARTING SECURITY TOPOLOGY GENERATION ---")
        self.seed_iam_identities()
        self.seed_network_security()
        self.seed_compute_workloads()
        self.seed_data_layer()
        logger.info("--- TOPOLOGY GENERATION COMPLETE ---")

if __name__ == "__main__":
    seeder = SecurityTopologySeeder()
    seeder.run()