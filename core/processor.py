import logging
from typing import Dict, Any, List
from neo4j import GraphDatabase, Transaction
from core.config import settings

class GraphCorrelationEngine:
    """
    Exhaustive Graph Correlation Engine.
    Translates raw cloud manifests into a complex, multi-dimensional Risk Graph.
    Maps infrastructure, network reachability, and IAM trust paths.
    """

    def __init__(self):
        self.uri = settings.NEO4J_URI
        self.auth = (settings.NEO4J_USER, settings.NEO4J_PASS)
        self.driver = GraphDatabase.driver(self.uri, auth=self.auth)
        self.logger = logging.getLogger(self.__class__.__name__)

    def close(self):
        """Cleanly terminates the Neo4j connection pool."""
        self.driver.close()

    def reset_graph(self):
        """Purges the entire graph for a fresh ingestion cycle."""
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
            self.logger.warning("Knowledge Graph purged. Ready for clean ingestion.")

    def ingest_aws_manifest(self, manifest: Dict[str, Any]):
        """
        Orchestrates the topological ingestion of the exhaustive cloud state.
        Order matters: Base network and identity must exist before compute is attached.
        """
        self.logger.info("--- INITIATING GRAPH CORRELATION ---")
        with self.driver.session() as session:
            try:
                self._map_network_and_firewalls(session, manifest.get('network', {}))
                self._map_identity_plane(session, manifest.get('identity', {}))
                self._map_storage_and_databases(session, manifest.get('storage', []), manifest.get('database', {}))
                self._map_compute_workloads(session, manifest.get('compute', {}))
                self._map_integration_services(session, manifest.get('integration', {}))
                self.logger.info("--- GRAPH CORRELATION COMPLETE ---")
            except Exception as e:
                self.logger.error(f"Critical Failure during Graph Ingestion: {e}", exc_info=True)

    # ==========================================
    # LAYER 1: NETWORK & REACHABILITY (FIREWALLS)
    # ==========================================
    def _map_network_and_firewalls(self, session, net_data: Dict[str, Any]):
        self.logger.info("Injecting Network Topology & Security Groups...")
        
        # 1. VPCs & Internet Gateways (The Perimeter)
        for vpc in net_data.get('vpcs', []):
            session.run(
                "MERGE (v:VPC {id: $id}) SET v.cidr = $cidr, v.state = $state",
                id=vpc['VpcId'], cidr=vpc.get('CidrBlock', 'N/A'), state=vpc.get('State', 'N/A')
            )
        
        for igw in net_data.get('internet_gateways', []):
            for attachment in igw.get('Attachments', []):
                session.run("""
                    MERGE (igw:InternetGateway {id: $igw_id})
                    MERGE (v:VPC {id: $vpc_id})
                    MERGE (igw)-[:ATTACHED_TO]->(v)
                """, igw_id=igw['InternetGatewayId'], vpc_id=attachment['VpcId'])

        # 2. Subnets
        for sub in net_data.get('subnets', []):
            session.run("""
                MERGE (s:Subnet {id: $id})
                SET s.cidr = $cidr, s.az = $az
                MERGE (v:VPC {id: $vpc_id})
                MERGE (s)-[:PART_OF_NETWORK]->(v)
            """, id=sub['SubnetId'], cidr=sub.get('CidrBlock', 'N/A'), 
                 az=sub.get('AvailabilityZone', 'N/A'), vpc_id=sub['VpcId'])

        # 3. Security Groups (The Blast Radius Enablers)
        for sg in net_data.get('security_groups', []):
            session.run("""
                MERGE (sg:SecurityGroup {id: $id})
                SET sg.name = $name, sg.desc = $desc
                MERGE (v:VPC {id: $vpc_id})
                MERGE (sg)-[:PROTECTS_VPC]->(v)
            """, id=sg['GroupId'], name=sg.get('GroupName', 'N/A'), 
                 desc=sg.get('Description', 'N/A'), vpc_id=sg.get('VpcId'))

            # Map Ingress Rules (Lateral Movement Paths)
            for rule in sg.get('IpPermissions', []):
                protocol = rule.get('IpProtocol', 'all')
                port = str(rule.get('FromPort', 'all'))
                
                # Rule 1: IP Ranges (0.0.0.0/0 means Publicly Exposed)
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp')
                    session.run("""
                        MERGE (ip:IPRange {cidr: $cidr})
                        MERGE (sg:SecurityGroup {id: $sg_id})
                        MERGE (ip)-[:ALLOWS_TRAFFIC_TO {port: $port, protocol: $protocol}]->(sg)
                    """, cidr=cidr, sg_id=sg['GroupId'], port=port, protocol=protocol)
                
                # Rule 2: SG-to-SG Trust (Internal Lateral Movement)
                for pair in rule.get('UserIdGroupPairs', []):
                    source_sg_id = pair.get('GroupId')
                    session.run("""
                        MERGE (source:SecurityGroup {id: $source_id})
                        MERGE (target:SecurityGroup {id: $target_id})
                        MERGE (source)-[:ALLOWS_TRAFFIC_TO {port: $port, protocol: $protocol}]->(target)
                    """, source_id=source_sg_id, target_id=sg['GroupId'], port=port, protocol=protocol)

    # ==========================================
    # LAYER 2: IDENTITY & TRUST
    # ==========================================
    def _map_identity_plane(self, session, id_data: Dict[str, Any]):
        self.logger.info("Injecting IAM Roles & Profiles...")
        for role in id_data.get('roles', []):
            session.run(
                "MERGE (r:IAMRole {id: $id, name: $name, arn: $arn})",
                id=role['RoleId'], name=role['RoleName'], arn=role['Arn']
            )
        
        for profile in id_data.get('instance_profiles', []):
            session.run(
                "MERGE (p:InstanceProfile {id: $id, name: $name, arn: $arn})",
                id=profile['InstanceProfileId'], name=profile['InstanceProfileName'], arn=profile['Arn']
            )
            # Link Profile to underlying Roles
            for role in profile.get('Roles', []):
                session.run("""
                    MATCH (p:InstanceProfile {id: $profile_id})
                    MERGE (r:IAMRole {id: $role_id})
                    MERGE (p)-[:CONTAINS_ROLE]->(r)
                """, profile_id=profile['InstanceProfileId'], role_id=role['RoleId'])

    # ==========================================
    # LAYER 3: COMPUTE WORKLOADS
    # ==========================================
    def _map_compute_workloads(self, session, compute_data: Dict[str, Any]):
        self.logger.info("Injecting Compute, ECS, and Lambda...")
        
        # 1. EC2 Instances
        for inst in compute_data.get('ec2_instances', []):
            session.run("""
                MERGE (i:Instance {id: $id})
                SET i.type = $type, i.state = $state, i.private_ip = $ip, i.public_ip = $pub_ip
            """, id=inst['InstanceId'], type=inst.get('InstanceType', 'N/A'), 
                 state=inst.get('State', {}).get('Name', 'unknown'),
                 ip=inst.get('PrivateIpAddress', 'N/A'), pub_ip=inst.get('PublicIpAddress', 'N/A'))
            
            # Link Instance -> Subnet
            if inst.get('SubnetId'):
                session.run("""
                    MATCH (i:Instance {id: $inst_id})
                    MERGE (s:Subnet {id: $subnet_id})
                    MERGE (i)-[:RUNNING_IN]->(s)
                """, inst_id=inst['InstanceId'], subnet_id=inst['SubnetId'])

            # Link Instance -> Security Groups (Firewall Context)
            for sg in inst.get('SecurityGroups', []):
                session.run("""
                    MATCH (i:Instance {id: $inst_id})
                    MERGE (sg:SecurityGroup {id: $sg_id})
                    MERGE (i)-[:SECURED_BY]->(sg)
                """, inst_id=inst['InstanceId'], sg_id=sg['GroupId'])

            # Link Instance -> IAM Role (Trust Context)
            if 'IamInstanceProfile' in inst:
                profile_arn = inst['IamInstanceProfile']['Arn']
                session.run("""
                    MATCH (i:Instance {id: $inst_id})
                    MERGE (p:InstanceProfile {arn: $arn})
                    MERGE (i)-[:ASSUMES_PROFILE]->(p)
                """, inst_id=inst['InstanceId'], arn=profile_arn)

        # 2. ECS Clusters
        for cluster_arn in compute_data.get('ecs_clusters', []):
            session.run("MERGE (c:ECSCluster {arn: $arn})", arn=cluster_arn)

        # 3. Lambda Functions
        for func in compute_data.get('lambda_functions', []):
            session.run("""
                MERGE (l:LambdaFunction {name: $name})
                SET l.runtime = $runtime, l.arn = $arn
                MERGE (r:IAMRole {arn: $role_arn})
                MERGE (l)-[:EXECUTES_AS_ROLE]->(r)
            """, name=func['FunctionName'], runtime=func.get('Runtime', 'N/A'), 
                 arn=func['FunctionArn'], role_arn=func.get('Role', ''))

    # ==========================================
    # LAYER 4: STORAGE & DATABASES
    # ==========================================
    def _map_storage_and_databases(self, session, storage_data: List[Any], db_data: Dict[str, Any]):
        self.logger.info("Injecting S3, RDS, and DynamoDB Data Gravity nodes...")
        
        # S3 Buckets
        for bucket in storage_data:
            session.run("MERGE (b:S3Bucket {name: $name})", name=bucket['Name'])

        # RDS Clusters
        for rds in db_data.get('rds_clusters', []):
            session.run(
                "MERGE (db:RDSCluster {id: $id, engine: $engine, status: $status})",
                id=rds['DBClusterIdentifier'], engine=rds['Engine'], status=rds['Status']
            )

        # DynamoDB Tables
        for table in db_data.get('dynamodb_tables', []):
            session.run("MERGE (ddb:DynamoDBTable {name: $name})", name=table)

    # ==========================================
    # LAYER 5: INTEGRATION (QUEUES/TOPICS)
    # ==========================================
    def _map_integration_services(self, session, int_data: Dict[str, Any]):
        self.logger.info("Injecting SQS Queues and SNS Topics...")
        for queue in int_data.get('sqs_queues', []):
            session.run("MERGE (q:SQSQueue {url: $url})", url=queue)
        
        for topic in int_data.get('sns_topics', []):
            session.run("MERGE (t:SNSTopic {arn: $arn})", arn=topic)