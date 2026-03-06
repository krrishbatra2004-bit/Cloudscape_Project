import asyncio
import logging
import traceback
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from engines.base_engine import BaseDiscoveryEngine
from core.config import config, TenantConfig

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - ENTERPRISE AWS DISCOVERY ENGINE (TITAN FULL)
# ==============================================================================
# The absolute un-truncated extraction engine. 
# Implements strict Session Partition Locking, Active Tag Probing for LocalStack,
# D2H (Direct-to-Hardware) native extraction, registry force-loading, and the 
# complete suite of deep vulnerability heuristics.
# ==============================================================================

class AWSEngine(BaseDiscoveryEngine):
    def __init__(self, tenant: TenantConfig):
        super().__init__(tenant)
        self.logger = logging.getLogger(f"Cloudscape.Engines.AWS.[{self.tenant.id}]")
        
        # Configuration-Driven Regionality
        aws_config = getattr(config.settings, 'aws', None)
        self.target_regions = getattr(aws_config, 'target_regions', ["ap-south-1"])
        
        # SDK-level adaptive retries with maximum connection pooling for high concurrency
        self.boto_config = Config(
            retries={'max_attempts': 5, 'mode': 'adaptive'},
            max_pool_connections=100
        )

    # --------------------------------------------------------------------------
    # ISOLATION & GATEWAY MECHANISMS
    # --------------------------------------------------------------------------

    def _get_isolated_client(self, service_name: str, region: str) -> Any:
        """
        The Session Partition Anchor.
        Forces a dedicated boto3.Session for every thread to prevent LocalStack 
        identity shadowing during asynchronous task delegation.
        """
        kwargs = self.get_aws_client_kwargs()
        
        # Lock session to the specific partition credentials to cure shadowing
        session = boto3.Session(
            aws_access_key_id=kwargs.get("aws_access_key_id", "testing"),
            aws_secret_access_key=kwargs.get("aws_secret_access_key", "testing"),
            region_name=region
        )
        
        endpoint = kwargs.get("endpoint_url")
        if endpoint:
            return session.client(service_name, endpoint_url=endpoint, config=self.boto_config)
        return session.client(service_name, config=self.boto_config)

    async def _verify_tenant_ownership(self, client: Any, resource_type: str, resource_id: str, resource_arn: str, initial_tags: List[Dict]) -> bool:
        """
        Active Tag Probe & Tenant Isolation Filter.
        Systematically fetches tags if they are missing from the primary List call.
        Crucial for bypassing LocalStack's metadata omission in List APIs.
        """
        if self.mode != "MOCK":
            # In production, IAM scoping strictly handles isolation
            return True 

        tags = initial_tags or []
        
        # 1. Active Probing for tag-blind services if the initial array is empty
        if not tags:
            try:
                if resource_type == 's3':
                    tag_resp = await self.execute_with_backoff(asyncio.to_thread, client.get_bucket_tagging, Bucket=resource_id)
                    tags = tag_resp.get('TagSet', [])
                elif resource_type == 'iam':
                    tag_resp = await self.execute_with_backoff(asyncio.to_thread, client.list_role_tags, RoleName=resource_id)
                    tags = tag_resp.get('Tags', [])
                elif resource_type in ['ec2_vpc', 'ec2_subnet', 'ec2_sg', 'ec2_instance']:
                    tag_resp = await self.execute_with_backoff(asyncio.to_thread, client.describe_tags, Filters=[{'Name': 'resource-id', 'Values': [resource_id]}])
                    tags = tag_resp.get('Tags', [])
                elif resource_type == 'rds':
                    tag_resp = await self.execute_with_backoff(asyncio.to_thread, client.list_tags_for_resource, ResourceName=resource_arn)
                    tags = tag_resp.get('TagList', [])
            except ClientError as e:
                # Expected if the resource genuinely has no tags or API is unsupported in mock
                self.logger.debug(f"Active Tag Probe yielded no results for {resource_type}/{resource_id}: {e.response['Error']['Code']}")
            except Exception:
                pass
                
        # 2. Case-Insensitive Ownership Validation
        for tag in tags:
            k = str(tag.get('Key', tag.get('key', ''))).lower()
            v = str(tag.get('Value', tag.get('value', ''))).lower()
            if k == 'cloudscapetenantid' and v == self.tenant.id.lower():
                return True
                
        # 3. Semantic Name Matching (Last Resort Fallback)
        if self.tenant.id.lower() in resource_id.lower():
            return True
            
        return False

    # --------------------------------------------------------------------------
    # CORE DISCOVERY ORCHESTRATION
    # --------------------------------------------------------------------------

    async def test_connection(self) -> bool:
        """Validates identity via STS using the isolated partition anchor."""
        primary_region = self.target_regions[0]
        self.logger.info(f"Testing AWS STS Connectivity for account partition in {primary_region}...")
        
        try:
            sts_client = await asyncio.to_thread(self._get_isolated_client, 'sts', primary_region)
            identity = await self.execute_with_backoff(asyncio.to_thread, sts_client.get_caller_identity)
            
            if not identity:
                return False
                
            self.tenant.credentials.aws_account_id = identity.get('Account')
            self.logger.info(f"STS Handshake Verified. Target Partition resolved to Account: {identity.get('Account')}")
            return True
        except Exception as e:
            self.logger.error(f"AWS STS Handshake Collapsed: {e}")
            return False

    async def discover(self) -> List[Dict[str, Any]]:
        """
        The Master Extraction Orchestrator.
        Forces the Titan Baseline registry if configuration is empty to prevent scan starvation.
        """
        self.logger.info(f"[{self.tenant.id}] Engaging AWS Deep Discovery across {len(self.target_regions)} regions...")
        total_payloads = []
        
        # Registry Hard-Coding (Forces baseline if settings.yaml is missing or empty)
        reg = getattr(config, 'service_registry', {}).get("aws", {})
        if not reg:
            self.logger.debug(f"[{self.tenant.id}] Registry starvation detected. Injecting Titan Baseline.")
            reg = {
                "iam_role": {"baseline_risk_score": 0.5},
                "s3_bucket": {"baseline_risk_score": 0.3},
                "vpc": {"baseline_risk_score": 0.1},
                "subnet": {"baseline_risk_score": 0.1},
                "security_group": {"baseline_risk_score": 0.2},
                "ec2_instance": {"baseline_risk_score": 0.6},
                "rds_instance": {"baseline_risk_score": 0.8}
            }

        tasks = []
        primary_region = self.target_regions[0]
        
        # 1. Global Service Allocation (IAM, S3)
        if "iam_role" in reg: tasks.append(self._extract_iam_roles(primary_region, reg["iam_role"]["baseline_risk_score"]))
        if "s3_bucket" in reg: tasks.append(self._extract_s3_buckets(primary_region, reg["s3_bucket"]["baseline_risk_score"]))

        # 2. Regional Service Allocation (VPC, EC2, SG, Subnet, RDS)
        for region in self.target_regions:
            if "vpc" in reg: tasks.append(self._extract_vpcs(region, reg["vpc"]["baseline_risk_score"]))
            if "subnet" in reg: tasks.append(self._extract_subnets(region, reg["subnet"]["baseline_risk_score"]))
            if "security_group" in reg: tasks.append(self._extract_security_groups(region, reg["security_group"]["baseline_risk_score"]))
            if "ec2_instance" in reg: tasks.append(self._extract_ec2_instances(region, reg["ec2_instance"]["baseline_risk_score"]))
            if "rds_instance" in reg: tasks.append(self._extract_rds_instances(region, reg["rds_instance"]["baseline_risk_score"]))

        # 3. Parallel Execution Matrix
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"AWS Service Extraction Failure: {result}")
                self.logger.debug(traceback.format_exc())
            elif result:
                total_payloads.extend(result)

        self.logger.info(f"[{self.tenant.id}] AWS Discovery Cycle Complete. Extracted {len(total_payloads)} Nodes.")
        return total_payloads

    # ==========================================================================
    # D2H EXTRACTION MATRICES & DEEP HEURISTICS
    # ==========================================================================

    async def _execute_aws_list_api(self, client: Any, method_name: str, key_name: str, **kwargs) -> List[Dict]:
        """
        D2H (Direct-to-Hardware) Raw Executor.
        Bypasses boto3 paginators to ensure full retrieval from LocalStack memory,
        handling native 'NextToken' and 'Marker' iteration deterministically.
        """
        def fetch_all():
            results = []
            method = getattr(client, method_name)
            
            response = method(**kwargs)
            results.extend(response.get(key_name, []))
            
            token = response.get('NextToken') or response.get('Marker')
            while token:
                page_kwargs = {**kwargs, ('NextToken' if 'NextToken' in response else 'Marker'): token}
                response = method(**page_kwargs)
                results.extend(response.get(key_name, []))
                token = response.get('NextToken') or response.get('Marker')
                
            return results

        try:
            return await self.execute_with_backoff(asyncio.to_thread, fetch_all)
        except Exception as e:
            self.logger.error(f"D2H API Fail ({method_name}): {e}")
            return []

    async def _extract_iam_roles(self, region: str, risk: float) -> List[Dict]:
        """Extracts IAM Roles and evaluates administrative privilege structures."""
        try:
            client = await asyncio.to_thread(self._get_isolated_client, 'iam', region)
            roles = await self._execute_aws_list_api(client, 'list_roles', 'Roles')
            payloads = []
            
            for r in roles:
                role_name = r.get("RoleName", "")
                arn = r.get("Arn", "")
                
                # Tenant Isolation check
                is_owner = await self._verify_tenant_ownership(client, 'iam', role_name, arn, r.get("Tags", []))
                if not is_owner:
                    continue
                    
                # Evaluate Trust Policy Exposure Heuristics
                trust_doc = str(r.get("AssumeRolePolicyDocument", ""))
                if '"*" ' in trust_doc or '"*"}' in trust_doc:
                    r.setdefault("Tags", []).append({'Key': 'Exposure', 'Value': 'OverpermissiveTrust'})
                    risk = min(risk + 0.4, 1.0)
                    
                has_changed, state_hash = await self.check_state_differential(arn, r)
                if has_changed:
                    r["_state_hash"] = state_hash
                    payload = self.format_urm_payload("iam", "Role", arn, r, risk)
                    payload["cloud_provider"] = "aws"
                    payloads.append(payload)
                    
            return payloads
        except Exception as e:
            self.logger.error(f"IAM Role extraction failed: {e}")
            return []

    async def _extract_s3_buckets(self, region: str, risk: float) -> List[Dict]:
        """Extracts S3 Buckets and explicitly probes for Public Access Block configurations."""
        try:
            client = await asyncio.to_thread(self._get_isolated_client, 's3', region)
            response = await self.execute_with_backoff(asyncio.to_thread, client.list_buckets)
            buckets = response.get('Buckets', []) if response else []
            payloads = []
            account_id = self.tenant.credentials.aws_account_id or "unknown"
            
            for b in buckets:
                name = b.get("Name", "")
                arn = f"arn:aws:s3:::{name}"
                b["AccountId"] = account_id
                
                # Tenant Isolation check
                is_owner = await self._verify_tenant_ownership(client, 's3', name, arn, [])
                if not is_owner:
                    continue
                
                # Deep Exposure Heuristics: Public Access Block
                bucket_risk = risk
                try:
                    pab = await self.execute_with_backoff(asyncio.to_thread, client.get_public_access_block, Bucket=name)
                    b["PublicAccessBlock"] = pab.get('PublicAccessBlockConfiguration', {})
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        b.setdefault("tags", []).append({'Key': 'Exposure', 'Value': 'PublicAccessBlockMissing'})
                        bucket_risk = min(bucket_risk + 0.3, 1.0)
                    
                has_changed, state_hash = await self.check_state_differential(arn, b)
                if has_changed:
                    b["_state_hash"] = state_hash
                    payload = self.format_urm_payload("s3", "Bucket", arn, b, bucket_risk)
                    payload["cloud_provider"] = "aws"
                    payloads.append(payload)
                    
            return payloads
        except Exception as e:
            self.logger.error(f"S3 Bucket extraction failed: {e}")
            return []

    async def _extract_vpcs(self, region: str, risk: float) -> List[Dict]:
        """Extracts Virtual Private Clouds and base network architecture."""
        try:
            client = await asyncio.to_thread(self._get_isolated_client, 'ec2', region)
            vpcs = await self._execute_aws_list_api(client, 'describe_vpcs', 'Vpcs')
            payloads = []
            account_id = self.tenant.credentials.aws_account_id or "unknown"
            
            for v in vpcs:
                vid = v.get("VpcId", "")
                arn = f"arn:aws:ec2:{region}:{account_id}:vpc/{vid}"
                
                is_owner = await self._verify_tenant_ownership(client, 'ec2_vpc', vid, arn, v.get('Tags', []))
                if not is_owner:
                    continue
                    
                has_changed, state_hash = await self.check_state_differential(arn, v)
                if has_changed:
                    v["_state_hash"] = state_hash
                    payload = self.format_urm_payload("ec2", "Vpc", arn, v, risk)
                    payload["cloud_provider"] = "aws"
                    payloads.append(payload)
                    
            return payloads
        except Exception as e:
            self.logger.error(f"VPC extraction failed in {region}: {e}")
            return []

    async def _extract_subnets(self, region: str, risk: float) -> List[Dict]:
        """Extracts Subnets and maps automatic Public IP generation exposure."""
        try:
            client = await asyncio.to_thread(self._get_isolated_client, 'ec2', region)
            subnets = await self._execute_aws_list_api(client, 'describe_subnets', 'Subnets')
            payloads = []
            account_id = self.tenant.credentials.aws_account_id or "unknown"
            
            for s in subnets:
                sid = s.get("SubnetId", "")
                arn = f"arn:aws:ec2:{region}:{account_id}:subnet/{sid}"
                
                is_owner = await self._verify_tenant_ownership(client, 'ec2_subnet', sid, arn, s.get('Tags', []))
                if not is_owner:
                    continue
                    
                # Exposure mapping heuristics
                subnet_risk = risk
                if s.get("MapPublicIpOnLaunch"):
                    s.setdefault("tags", []).append({'Key': 'Exposure', 'Value': 'Public'})
                    subnet_risk = min(subnet_risk + 0.1, 1.0)
                    
                has_changed, state_hash = await self.check_state_differential(arn, s)
                if has_changed:
                    s["_state_hash"] = state_hash
                    payload = self.format_urm_payload("ec2", "Subnet", arn, s, subnet_risk)
                    payload["cloud_provider"] = "aws"
                    payloads.append(payload)
                    
            return payloads
        except Exception as e:
            self.logger.error(f"Subnet extraction failed in {region}: {e}")
            return []

    async def _extract_security_groups(self, region: str, risk: float) -> List[Dict]:
        """Extracts Security Groups and evaluates deep inbound port exposure rules."""
        try:
            client = await asyncio.to_thread(self._get_isolated_client, 'ec2', region)
            sgs = await self._execute_aws_list_api(client, 'describe_security_groups', 'SecurityGroups')
            payloads = []
            account_id = self.tenant.credentials.aws_account_id or "unknown"
            
            for sg in sgs:
                sgid = sg.get("GroupId", "")
                arn = f"arn:aws:ec2:{region}:{account_id}:security-group/{sgid}"
                
                is_owner = await self._verify_tenant_ownership(client, 'ec2_sg', sgid, arn, sg.get('Tags', []))
                if not is_owner:
                    continue
                    
                # Deep Heuristic Analysis: Check for 0.0.0.0/0 on sensitive ports
                sg_risk = risk
                for permission in sg.get("IpPermissions", []):
                    from_port = permission.get("FromPort")
                    to_port = permission.get("ToPort")
                    for ip_range in permission.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            if from_port in [22, 3389, None]:  # None implies all ports
                                sg.setdefault("tags", []).append({'Key': 'Exposure', 'Value': 'CriticalPortOpen'})
                                sg_risk = min(sg_risk + 0.4, 1.0)
                                break
                                
                has_changed, state_hash = await self.check_state_differential(arn, sg)
                if has_changed:
                    sg["_state_hash"] = state_hash
                    payload = self.format_urm_payload("ec2", "SecurityGroup", arn, sg, sg_risk)
                    payload["cloud_provider"] = "aws"
                    payloads.append(payload)
                    
            return payloads
        except Exception as e:
            self.logger.error(f"Security Group extraction failed in {region}: {e}")
            return []
            
    async def _extract_ec2_instances(self, region: str, risk: float) -> List[Dict]:
        """Extracts EC2 Compute Instances and evaluates physical public exposure."""
        try:
            client = await asyncio.to_thread(self._get_isolated_client, 'ec2', region)
            reservations = await self._execute_aws_list_api(client, 'describe_instances', 'Reservations')
            payloads = []
            account_id = self.tenant.credentials.aws_account_id or "unknown"
            
            for res in reservations:
                for inst in res.get("Instances", []):
                    iid = inst.get("InstanceId", "")
                    arn = f"arn:aws:ec2:{region}:{account_id}:instance/{iid}"
                    
                    is_owner = await self._verify_tenant_ownership(client, 'ec2_instance', iid, arn, inst.get('Tags', []))
                    if not is_owner:
                        continue
                        
                    # Exposure mapping heuristics
                    inst_risk = risk
                    if inst.get("PublicIpAddress"):
                        inst.setdefault("tags", []).append({'Key': 'Exposure', 'Value': 'Public'})
                        inst_risk = min(inst_risk + 0.2, 1.0)
                        
                    has_changed, state_hash = await self.check_state_differential(arn, inst)
                    if has_changed:
                        inst["_state_hash"] = state_hash
                        payload = self.format_urm_payload("ec2", "Instance", arn, inst, inst_risk)
                        payload["cloud_provider"] = "aws"
                        payloads.append(payload)
                        
            return payloads
        except Exception as e:
            self.logger.error(f"EC2 Instance extraction failed in {region}: {e}")
            return []

    async def _extract_rds_instances(self, region: str, risk: float) -> List[Dict]:
        """Extracts RDS Databases and evaluates public exposure and encryption status."""
        try:
            client = await asyncio.to_thread(self._get_isolated_client, 'rds', region)
            instances = await self._execute_aws_list_api(client, 'describe_db_instances', 'DBInstances')
            payloads = []
            
            for db in instances:
                arn = db.get("DBInstanceArn", "")
                db_id = db.get("DBInstanceIdentifier", "")
                
                is_owner = await self._verify_tenant_ownership(client, 'rds', db_id, arn, db.get('TagList', []))
                if not is_owner:
                    continue
                    
                # Exposure and Encryption Heuristics
                db_risk = risk
                if db.get("PubliclyAccessible"):
                    db.setdefault("tags", []).append({'Key': 'Exposure', 'Value': 'Public'})
                    db_risk = min(db_risk + 0.3, 1.0)
                if not db.get("StorageEncrypted"):
                    db.setdefault("tags", []).append({'Key': 'Encryption', 'Value': 'Disabled'})
                    db_risk = min(db_risk + 0.4, 1.0)
                    
                has_changed, state_hash = await self.check_state_differential(arn, db)
                if has_changed:
                    db["_state_hash"] = state_hash
                    payload = self.format_urm_payload("rds", "DBInstance", arn, db, db_risk)
                    payload["cloud_provider"] = "aws"
                    payloads.append(payload)
                    
            return payloads
        except Exception as e:
            # Expected fallback if RDS is not explicitly mocked or supported in local environment
            self.logger.debug(f"RDS extraction skipped or failed: {e}")
            return []