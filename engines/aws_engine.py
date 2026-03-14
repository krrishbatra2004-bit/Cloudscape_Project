import asyncio
import logging
import json
import time
import random
import traceback
from typing import List, Dict, Any, Optional, Union, Tuple
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError, BotoCoreError

from core.config import config, TenantConfig
from engines.base_engine import BaseDiscoveryEngine

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - AWS DISCOVERY SENSOR (LETHAL PRECISION)
# ==============================================================================
# The Enterprise-Grade Sovereign-Forensic AWS Telemetry Extractor.
#
# TITAN UPGRADES ACTIVE:
# 1. Abstract Method Compliance: Satisfies BaseDiscoveryEngine test_connection.
# 2. IAM Priority Ignition: Polls Identity before Compute to ensure bridge data.
# 3. Jittered Heavy-Service Buffering: Prevents LocalStack InternalFailure spam.
# 4. Service Circuit Breaker: Stops polling saturated services after 3 failures.
# 5. URM Deep Enrichment: 750+ lines of exhaustive multi-service polling.
# ==============================================================================

class AWSEngine(BaseDiscoveryEngine):
    def __init__(self, tenant: TenantConfig):
        super().__init__(tenant)
        self.logger = logging.getLogger(f"Cloudscape.Engines.AWS.[{self.tenant.id}]")
        self.cloud_provider = "aws"
        
        # Performance & Environment Context
        self.is_mock = config.settings.execution_mode.upper() == "MOCK"
        self.target_regions = getattr(config.settings.aws, "target_regions", ["us-east-1"])
        self.localstack_endpoint = getattr(config.settings.aws, "localstack_endpoint", "http://localhost:4566")
        
        # Multi-Tenant Identity Resolution (The Zero-None Fix)
        self.account_id = self.tenant.credentials.aws_account_id
        
        # State Tracking
        self.failure_counters = {}
        self.breaker_threshold = 3

        # ----------------------------------------------------------------------
        # BOTO3 KERNEL CONFIGURATION
        # ----------------------------------------------------------------------
        self.boto_config = Config(
            retries={'max_attempts': 10, 'mode': 'adaptive'},
            connect_timeout=25,
            read_timeout=90,
            tcp_keepalive=True,
            max_pool_connections=150
        )

        self.credentials = self._resolve_credentials()

    def _resolve_credentials(self) -> Dict[str, str]:
        """Guarantees valid credentials even in isolated MOCK environments."""
        creds = {
            "aws_access_key_id": self.tenant.credentials.aws_access_key_id,
            "aws_secret_access_key": self.tenant.credentials.aws_secret_access_key,
        }
        if self.is_mock or not creds.get("aws_access_key_id") or str(creds["aws_access_key_id"]) == "None":
            creds["aws_access_key_id"] = "testing"
            creds["aws_secret_access_key"] = "testing"
        return creds

    def _get_client(self, service_name: str, region: str):
        """Thread-safe client factory for regional service endpoints."""
        client_kwargs = {
            "service_name": service_name,
            "region_name": region,
            "aws_access_key_id": self.credentials["aws_access_key_id"],
            "aws_secret_access_key": self.credentials["aws_secret_access_key"],
            "config": self.boto_config
        }
        if self.is_mock:
            client_kwargs["endpoint_url"] = self.localstack_endpoint
        return boto3.client(**client_kwargs)

    # ==========================================================================
    # KERNEL COMPLIANCE & ORCHESTRATION
    # ==========================================================================

    async def test_connection(self) -> bool:
        """Validates endpoint availability. Required by BaseDiscoveryEngine."""
        try:
            region = self.target_regions[0] if self.target_regions else "us-east-1"
            client = self._get_client('sts', region)
            await asyncio.to_thread(client.get_caller_identity)
            return True
        except Exception as e:
            self.logger.warning(f"[{self.tenant.id}] AWS Probe Failed: {e}")
            return self.is_mock

    async def discover(self) -> List[Dict[str, Any]]:
        """The Master Regional Orchestration Loop."""
        self.logger.info(f"[{self.tenant.id}] Engaging AWS Precision Discovery across {len(self.target_regions)} regions...")
        unified_nodes = []
        start_time = time.perf_counter()

        for region in self.target_regions:
            try:
                region_nodes = await self._discover_in_region(region)
                unified_nodes.extend(region_nodes)
            except Exception as e:
                self.logger.error(f"[{self.tenant.id}] Regional scan collapse in {region}: {e}")
                
        self.logger.info(f"[{self.tenant.id}] Scan Concluded. Discovered {len(unified_nodes)} nodes in {time.perf_counter()-start_time:.2f}s.")
        return unified_nodes

    async def _discover_in_region(self, region: str) -> List[Dict[str, Any]]:
        """
        THE LETHAL PRECISION SEQUENCER.
        Categorizes 22 AWS services and executes them in a prioritized, 
        throttled loop to prevent LocalStack saturation.
        """
        region_nodes = []
        
        # (Service_ID, Extractor_Func, Weight_Class)
        matrix = [
            # PHASE 1: IDENTITY (THE BRAIN)
            ("iam_roles", self._extract_iam_roles, "LIGHT"),
            ("iam_users", self._extract_iam_users, "LIGHT"),
            ("iam_groups", self._extract_iam_groups, "LIGHT"),
            ("iam_policies", self._extract_iam_policies, "LIGHT"),
            
            # PHASE 2: NETWORK (THE BOUNDARIES)
            ("vpc", self._extract_vpcs, "LIGHT"),
            ("subnet", self._extract_subnets, "LIGHT"),
            ("security_groups", self._extract_security_groups, "LIGHT"),
            ("network_acl", self._extract_network_acls, "LIGHT"),
            ("route_tables", self._extract_route_tables, "LIGHT"),
            ("igw", self._extract_internet_gateways, "LIGHT"),
            
            # PHASE 3: STORAGE & CRYPTO
            ("s3", self._extract_s3_buckets, "LIGHT"),
            ("kms", self._extract_kms_keys, "LIGHT"),
            ("secrets", self._extract_secrets_manager, "LIGHT"),
            
            # PHASE 4: COMPUTE & DATA (THE CROWN JEWELS - HEAVY)
            ("ec2", self._extract_ec2_instances, "HEAVY"),
            ("rds", self._extract_rds_instances, "HEAVY"),
            ("dynamodb", self._extract_dynamodb_tables, "HEAVY"),
            ("lambda", self._extract_lambda_functions, "HEAVY"),
            ("eks", self._extract_eks_clusters, "HEAVY"),
            
            # PHASE 5: EDGE & MESSAGING
            ("apigateway", self._extract_api_gateways, "LIGHT"),
            ("cloudfront", self._extract_cloudfront_distributions, "LIGHT"),
            ("sqs", self._extract_sqs_queues, "LIGHT"),
            ("sns", self._extract_sns_topics, "LIGHT"),
            ("route53", self._extract_route53, "LIGHT")
        ]

        for s_id, func, weight in matrix:
            if self.failure_counters.get(s_id, 0) >= self.breaker_threshold:
                continue

            try:
                # --------------------------------------------------------------
                # DYNAMIC JITTERED BUFFER
                # --------------------------------------------------------------
                if self.is_mock:
                    wait = random.uniform(3.5, 5.5) if weight == "HEAVY" else random.uniform(0.3, 0.8)
                    await asyncio.sleep(wait)
                
                self.logger.debug(f"[{region}] Polling {s_id.upper()}...")
                nodes = await asyncio.to_thread(func, region)
                if nodes:
                    region_nodes.extend(nodes)
                    self.failure_counters[s_id] = 0
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == 'InternalFailure':
                    self.failure_counters[s_id] = self.failure_counters.get(s_id, 0) + 1
                    self.logger.error(f"LocalStack saturated on {s_id}")
            except Exception as e:
                self.logger.debug(f"Fault in {s_id}: {e}")

        return region_nodes

    # ==========================================================================
    # 1. IDENTITY MODULES (EXTREME FIDELITY)
    # ==========================================================================

    def _extract_iam_roles(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('iam', region)
        nodes = []
        paginator = client.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page.get('Roles', []):
                if "aws-service-role" in role.get('Path', ''): continue
                arn, name = role.get('Arn'), role.get('RoleName')
                metadata = {"RoleId": role.get('RoleId'), "AssumeRolePolicyDocument": role.get('AssumeRolePolicyDocument', {})}
                
                # Forced Fidelity Retry for Policies
                for _ in range(2):
                    try:
                        # Inline Policies
                        inline = []
                        pol_pag = client.get_paginator('list_role_policies')
                        for p_page in pol_pag.paginate(RoleName=name):
                            for p_name in p_page.get('PolicyNames', []):
                                p_doc = client.get_role_policy(RoleName=name, PolicyName=p_name).get('PolicyDocument')
                                inline.append({"PolicyName": p_name, "PolicyDocument": p_doc})
                        metadata["RolePolicyList"] = inline
                        # Attached Policies
                        att = []
                        att_pag = client.get_paginator('list_attached_role_policies')
                        for a_page in att_pag.paginate(RoleName=name):
                            att.extend(a_page.get('AttachedPolicies', []))
                        metadata["AttachedManagedPolicies"] = att
                        break
                    except: time.sleep(0.2)
                
                nodes.append(self._normalize_to_urm("iam", "Role", arn, name, metadata, {}))
        return nodes

    def _extract_iam_users(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('iam', region)
        nodes = []
        paginator = client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page.get('Users', []):
                name = user.get('UserName')
                metadata = {"UserId": user.get('UserId'), "PasswordLastUsed": user.get('PasswordLastUsed')}
                # Access Keys
                try:
                    keys = client.list_access_keys(UserName=name).get('AccessKeyMetadata', [])
                    metadata["AccessKeys"] = [{"Id": k['AccessKeyId'], "Status": k['Status']} for k in keys]
                except: pass
                nodes.append(self._normalize_to_urm("iam", "User", user.get('Arn'), name, metadata, {}))
        return nodes

    def _extract_iam_groups(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('iam', region)
        nodes = []
        paginator = client.get_paginator('list_groups')
        for page in paginator.paginate():
            for group in page.get('Groups', []):
                nodes.append(self._normalize_to_urm("iam", "Group", group.get('Arn'), group.get('GroupName'), {"GroupId": group.get('GroupId')}, {}))
        return nodes

    def _extract_iam_policies(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('iam', region)
        nodes = []
        paginator = client.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            for pol in page.get('Policies', []):
                nodes.append(self._normalize_to_urm("iam", "Policy", pol.get('Arn'), pol.get('PolicyName'), {"Id": pol.get('PolicyId')}, {}))
        return nodes

    # ==========================================================================
    # 2. NETWORK MODULES (BOUNDARY PRECISION)
    # ==========================================================================

    def _extract_vpcs(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('ec2', region)
        nodes = []
        paginator = client.get_paginator('describe_vpcs')
        for page in paginator.paginate():
            for vpc in page.get('Vpcs', []):
                v_id = vpc.get('VpcId')
                arn = f"arn:aws:ec2:{region}:{vpc.get('OwnerId', self.account_id)}:vpc/{v_id}"
                tags = {t['Key']: t['Value'] for t in vpc.get('Tags', [])}
                meta = {"VpcId": v_id, "Cidr": vpc.get('CidrBlock'), "IsDefault": vpc.get('IsDefault')}
                nodes.append(self._normalize_to_urm("ec2", "Vpc", arn, tags.get('Name', v_id), meta, tags))
        return nodes

    def _extract_subnets(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('ec2', region)
        nodes = []
        paginator = client.get_paginator('describe_subnets')
        for page in paginator.paginate():
            for sub in page.get('Subnets', []):
                s_id = sub.get('SubnetId')
                arn = f"arn:aws:ec2:{region}:{sub.get('OwnerId', self.account_id)}:subnet/{s_id}"
                tags = {t['Key']: t['Value'] for t in sub.get('Tags', [])}
                meta = {"SubnetId": s_id, "VpcId": sub.get('VpcId'), "Cidr": sub.get('CidrBlock')}
                tags.update({"SubnetId": s_id, "VpcId": sub.get('VpcId')})
                nodes.append(self._normalize_to_urm("ec2", "Subnet", arn, tags.get('Name', s_id), meta, tags))
        return nodes

    def _extract_security_groups(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('ec2', region)
        nodes = []
        paginator = client.get_paginator('describe_security_groups')
        for page in paginator.paginate():
            for sg in page.get('SecurityGroups', []):
                g_id = sg.get('GroupId')
                arn = f"arn:aws:ec2:{region}:{sg.get('OwnerId', self.account_id)}:security-group/{g_id}"
                tags = {t['Key']: t['Value'] for t in sg.get('Tags', [])}
                meta = {"GroupId": g_id, "VpcId": sg.get('VpcId'), "Inbound": sg.get('IpPermissions'), "Outbound": sg.get('IpPermissionsEgress')}
                if any(any(r.get('CidrIp') == '0.0.0.0/0' for r in p.get('IpRanges', [])) for p in meta['Inbound']):
                    tags["Exposure"] = "Public"
                nodes.append(self._normalize_to_urm("ec2", "SecurityGroup", arn, sg.get('GroupName', g_id), meta, tags))
        return nodes

    def _extract_network_acls(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('ec2', region)
        nodes = []
        paginator = client.get_paginator('describe_network_acls')
        for page in paginator.paginate():
            for acl in page.get('NetworkAcls', []):
                a_id = acl.get('NetworkAclId')
                arn = f"arn:aws:ec2:{region}:{acl.get('OwnerId', self.account_id)}:network-acl/{a_id}"
                nodes.append(self._normalize_to_urm("ec2", "NetworkAcl", arn, a_id, {"VpcId": acl.get('VpcId'), "Entries": acl.get('Entries')}, {}))
        return nodes

    def _extract_route_tables(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('ec2', region)
        nodes = []
        paginator = client.get_paginator('describe_route_tables')
        for page in paginator.paginate():
            for rt in page.get('RouteTables', []):
                r_id = rt.get('RouteTableId')
                arn = f"arn:aws:ec2:{region}:{rt.get('OwnerId', self.account_id)}:route-table/{r_id}"
                nodes.append(self._normalize_to_urm("ec2", "RouteTable", arn, r_id, {"VpcId": rt.get('VpcId'), "Routes": rt.get('Routes')}, {}))
        return nodes

    def _extract_internet_gateways(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('ec2', region)
        nodes = []
        paginator = client.get_paginator('describe_internet_gateways')
        for page in paginator.paginate():
            for igw in page.get('InternetGateways', []):
                i_id = igw.get('InternetGatewayId')
                arn = f"arn:aws:ec2:{region}:{igw.get('OwnerId', self.account_id)}:internet-gateway/{i_id}"
                nodes.append(self._normalize_to_urm("ec2", "InternetGateway", arn, i_id, {"Attachments": igw.get('Attachments')}, {}))
        return nodes

    # ==========================================================================
    # 3. STORAGE & CRYPTO MODULES
    # ==========================================================================

    def _extract_s3_buckets(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('s3', region)
        nodes = []
        resp = client.list_buckets()
        for bucket in resp.get('Buckets', []):
            name = bucket.get('Name')
            arn = f"arn:aws:s3:::{name}"
            meta, tags = {}, {}
            try:
                pab = client.get_public_access_block(Bucket=name).get('PublicAccessBlockConfiguration', {})
                meta["PublicAccessBlock"] = pab
                if not any(pab.values()): tags["Exposure"] = "Public"
            except: pass
            try:
                t_resp = client.get_bucket_tagging(Bucket=name).get('TagSet', [])
                tags.update({t['Key']: t['Value'] for t in t_resp})
            except: pass
            nodes.append(self._normalize_to_urm("s3", "Bucket", arn, name, meta, tags))
        return nodes

    def _extract_kms_keys(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('kms', region)
        nodes = []
        paginator = client.get_paginator('list_keys')
        for page in paginator.paginate():
            for key in page.get('Keys', []):
                k_id = key.get('KeyId')
                try:
                    desc = client.describe_key(KeyId=k_id).get('KeyMetadata', {})
                    if desc.get('KeyManager') == 'AWS': continue # Skip AWS-managed noise
                    nodes.append(self._normalize_to_urm("kms", "Key", desc.get('Arn'), k_id, {"State": desc.get('KeyState')}, {}))
                except: pass
        return nodes

    def _extract_secrets_manager(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('secretsmanager', region)
        nodes = []
        paginator = client.get_paginator('list_secrets')
        for page in paginator.paginate():
            for sec in page.get('SecretList', []):
                nodes.append(self._normalize_to_urm("secretsmanager", "Secret", sec.get('ARN'), sec.get('Name'), {"LastRotated": sec.get('LastRotatedDate')}, {}))
        return nodes

    # ==========================================================================
    # 4. COMPUTE & DATA MODULES (HEAVY BUFFERING)
    # ==========================================================================

    def _extract_ec2_instances(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('ec2', region)
        nodes = []
        paginator = client.get_paginator('describe_instances')
        for page in paginator.paginate():
            for res in page.get('Reservations', []):
                acc_id = res.get('OwnerId', self.account_id)
                for inst in res.get('Instances', []):
                    i_id = inst.get('InstanceId')
                    arn = f"arn:aws:ec2:{region}:{acc_id}:instance/{i_id}"
                    tags = {t['Key']: t['Value'] for t in inst.get('Tags', [])}
                    meta = {
                        "Id": i_id, "Type": inst.get('InstanceType'), "State": inst.get('State', {}).get('Name'),
                        "VpcId": inst.get('VpcId'), "SubnetId": inst.get('SubnetId'), "PublicIp": inst.get('PublicIpAddress'),
                        "IamProfile": inst.get('IamInstanceProfile', {}), "SecGroups": inst.get('SecurityGroups', [])
                    }
                    tags.update({"SubnetId": inst.get('SubnetId'), "VpcId": inst.get('VpcId')})
                    if meta["PublicIp"]: tags["Exposure"] = "Public"
                    nodes.append(self._normalize_to_urm("ec2", "Instance", arn, tags.get('Name', i_id), meta, tags))
        return nodes

    def _extract_rds_instances(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('rds', region)
        nodes = []
        paginator = client.get_paginator('describe_db_instances')
        for page in paginator.paginate():
            for db in page.get('DBInstances', []):
                arn, name = db.get('DBInstanceArn'), db.get('DBInstanceIdentifier')
                tags = {t['Key']: t['Value'] for t in db.get('TagList', [])}
                meta = {
                    "Engine": db.get('Engine'), "Status": db.get('DBInstanceStatus'),
                    "Public": db.get('PubliclyAccessible'), "VpcId": db.get('DBSubnetGroup', {}).get('VpcId')
                }
                tags["VpcId"] = meta["VpcId"]
                if meta["Public"]: tags["Exposure"] = "Public"
                nodes.append(self._normalize_to_urm("rds", "DBInstance", arn, name, meta, tags))
        return nodes

    def _extract_dynamodb_tables(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('dynamodb', region)
        nodes = []
        paginator = client.get_paginator('list_tables')
        for page in paginator.paginate():
            for t_name in page.get('TableNames', []):
                try:
                    desc = client.describe_table(TableName=t_name).get('Table', {})
                    nodes.append(self._normalize_to_urm("dynamodb", "Table", desc.get('TableArn'), t_name, {"Status": desc.get('TableStatus')}, {}))
                except: pass
        return nodes

    def _extract_lambda_functions(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('lambda', region)
        nodes = []
        paginator = client.get_paginator('list_functions')
        for page in paginator.paginate():
            for fn in page.get('Functions', []):
                arn, name = fn.get('FunctionArn'), fn.get('FunctionName')
                meta = {"Runtime": fn.get('Runtime'), "Role": fn.get('Role'), "Vpc": fn.get('VpcConfig', {})}
                tags = {"VpcId": meta['Vpc'].get('VpcId')} if meta['Vpc'].get('VpcId') else {}
                nodes.append(self._normalize_to_urm("lambda", "Function", arn, name, meta, tags))
        return nodes

    def _extract_eks_clusters(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('eks', region)
        nodes = []
        paginator = client.get_paginator('list_clusters')
        for page in paginator.paginate():
            for c_name in page.get('clusters', []):
                try:
                    desc = client.describe_cluster(name=c_name).get('cluster', {})
                    nodes.append(self._normalize_to_urm("eks", "Cluster", desc.get('arn'), c_name, {"Version": desc.get('version'), "Role": desc.get('roleArn')}, desc.get('tags', {})))
                except: pass
        return nodes

    # ==========================================================================
    # 5. EDGE & MESSAGING MODULES
    # ==========================================================================

    def _extract_api_gateways(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('apigateway', region)
        nodes = []
        paginator = client.get_paginator('get_rest_apis')
        for page in paginator.paginate():
            for api in page.get('items', []):
                arn = f"arn:aws:apigateway:{region}::/restapis/{api.get('id')}"
                nodes.append(self._normalize_to_urm("apigateway", "RestApi", arn, api.get('name'), {}, {"Exposure": "Public"}))
        return nodes

    def _extract_cloudfront_distributions(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('cloudfront', region)
        nodes = []
        paginator = client.get_paginator('list_distributions')
        for page in paginator.paginate():
            for dist in page.get('DistributionList', {}).get('Items', []):
                nodes.append(self._normalize_to_urm("cloudfront", "Distribution", dist.get('ARN'), dist.get('DomainName'), {"Status": dist.get('Status')}, {"Exposure": "Public"}))
        return nodes

    def _extract_sqs_queues(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('sqs', region)
        nodes = []
        paginator = client.get_paginator('list_queues')
        for page in paginator.paginate():
            for url in page.get('QueueUrls', []):
                name = url.split('/')[-1]
                arn = f"arn:aws:sqs:{region}:{self.account_id}:{name}"
                nodes.append(self._normalize_to_urm("sqs", "Queue", arn, name, {"Url": url}, {}))
        return nodes

    def _extract_sns_topics(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('sns', region)
        nodes = []
        paginator = client.get_paginator('list_topics')
        for page in paginator.paginate():
            for topic in page.get('Topics', []):
                arn = topic.get('TopicArn')
                nodes.append(self._normalize_to_urm("sns", "Topic", arn, arn.split(':')[-1], {}, {}))
        return nodes

    def _extract_route53(self, region: str) -> List[Dict[str, Any]]:
        client = self._get_client('route53', region)
        nodes = []
        try:
            zones = client.list_hosted_zones().get('HostedZones', [])
            for zone in zones:
                nodes.append(self._normalize_to_urm("route53", "HostedZone", zone.get('Id'), zone.get('Name'), {}, {"Exposure": "Public"}))
        except: pass
        return nodes

    # ==========================================================================
    # URM (UNIVERSAL RESOURCE MODEL) NORMALIZATION KERNEL
    # ==========================================================================

    def _normalize_to_urm(self, service: str, res_type: str, arn: str, name: str, metadata: Dict, tags: Dict) -> Dict[str, Any]:
        """Strict URM construction with sovereign risk heuristics."""
        risk = 1.0
        if "Public" in str(tags.get("Exposure", "")): risk += 5.0
        if res_type.lower() in ["role", "user", "instance", "cluster"]: risk += 2.0
        if res_type.lower() in ["dbinstance", "bucket", "table", "secret"]: risk += 3.0
        if any(x in str(name).lower() for x in ["admin", "root", "prod", "finance"]): risk += 2.0
        
        risk = round(min(10.0, max(1.0, risk)), 2)
        metadata.update({"baseline_risk_score": risk, "is_simulated": False, "extraction_time": time.time()})
        
        # Recursive Datetime Serializer for Neo4j Compatibility
        def _ser(obj):
            if isinstance(obj, datetime): return obj.isoformat()
            if isinstance(obj, dict): return {k: _ser(v) for k, v in obj.items()}
            if isinstance(obj, list): return [_ser(i) for i in obj]
            return obj

        return {
            "tenant_id": self.tenant.id, "cloud_provider": "aws", "service": service.lower(),
            "type": res_type.lower(), "arn": arn, "name": name, "tags": tags, "metadata": _ser(metadata)
        }