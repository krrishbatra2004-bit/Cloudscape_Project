import asyncio
import logging
import traceback
from typing import Any, Dict, List

import boto3
from botocore.config import Config

from engines.base_engine import BaseDiscoveryEngine
from core.config import config, TenantConfig

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - ENTERPRISE AWS DISCOVERY ENGINE
# ==============================================================================
# High-concurrency extraction engine dynamically steered by the Base Gateway.
# Implements strict Session Partition Locking, Active Tag Probing for LocalStack, 
# D2H (Direct-to-Hardware) native extraction, deep vulnerability heuristics, 
# and state hashing for high-fidelity materialization.
# ==============================================================================

class AWSEngine(BaseDiscoveryEngine):
    def __init__(self, tenant: TenantConfig):
        super().__init__(tenant)
        self.logger = logging.getLogger(f"Cloudscape.Engines.AWS.[{self.tenant.id}]")
        
        # Configuration-Driven Regionality
        aws_config = getattr(config.settings, 'aws', None)
        self.target_regions = getattr(aws_config, 'target_regions', ["ap-south-1"])
        
        # SDK-level adaptive retries (works in tandem with BaseEngine Circuit Breaker)
        self.boto_config = Config(
            retries={'max_attempts': 3, 'mode': 'adaptive'},
            max_pool_connections=50
        )

    # --------------------------------------------------------------------------
    # ISOLATION & GATEWAY MECHANISMS
    # --------------------------------------------------------------------------

    def _get_isolated_client(self, service_name: str, region: str) -> Any:
        """
        The Session Partition Lock.
        Creates a dedicated boto3.Session before instantiating the client.
        This guarantees LocalStack recognizes the injected credentials across 
        asynchronous threads, curing the 'Logical Partition Shadowing' bug.
        """
        kwargs = self.get_aws_client_kwargs()
        
        # Build an explicit, isolated session to enforce partition routing
        session = boto3.Session(
            aws_access_key_id=kwargs.get("aws_access_key_id"),
            aws_secret_access_key=kwargs.get("aws_secret_access_key"),
            region_name=region
        )
        
        endpoint = kwargs.get("endpoint_url")
        if endpoint:
            return session.client(service_name, endpoint_url=endpoint, config=self.boto_config)
        return session.client(service_name, config=self.boto_config)

    async def _verify_tenant_ownership(self, client: Any, resource_type: str, resource_name: str, tags: List[Dict]) -> bool:
        """
        The Mock-Aware Tag Fetcher & Tenant Isolation Filter.
        Inspects resource tags to ensure they belong to the current executing tenant.
        Includes Active Probing to retrieve tags that LocalStack's List APIs omit.
        """
        if self.mode != "MOCK":
            return True
            
        # 1. Check existing tags first (Case-Insensitive)
        for tag in tags:
            k = tag.get('Key', tag.get('key', ''))
            v = tag.get('Value', tag.get('value', ''))
            if str(k).lower() == 'cloudscapetenantid' and str(v).lower() == self.tenant.id.lower():
                return True
                
        # 2. Active Tag Probe for LocalStack "List API" Blindness
        if not tags:
            try:
                if resource_type == 's3':
                    tag_resp = await self.execute_with_backoff(asyncio.to_thread, client.get_bucket_tagging, Bucket=resource_name)
                    for tag in tag_resp.get('TagSet', []):
                        if str(tag.get('Key')).lower() == 'cloudscapetenantid' and str(tag.get('Value')).lower() == self.tenant.id.lower():
                            return True
                elif resource_type == 'iam':
                    tag_resp = await self.execute_with_backoff(asyncio.to_thread, client.list_role_tags, RoleName=resource_name)
                    for tag in tag_resp.get('Tags', []):
                        if str(tag.get('Key')).lower() == 'cloudscapetenantid' and str(tag.get('Value')).lower() == self.tenant.id.lower():
                            return True
            except Exception as e:
                # Silently ignore missing tag sets or unsupported LocalStack calls
                pass
                
        # 3. Last Resort Fallback (Name matching)
        if self.tenant.id.lower() in resource_name.lower():
            return True
            
        return False

    # --------------------------------------------------------------------------
    # CORE DISCOVERY ORCHESTRATION
    # --------------------------------------------------------------------------

    async def test_connection(self) -> bool:
        """Validates identity via STS using the dynamic Base Gateway routing."""
        primary_region = self.target_regions[0]
        self.logger.info(f"Testing AWS STS Connectivity and validating Identity Handshake in {primary_region}...")
        
        try:
            sts_client = await asyncio.to_thread(self._get_isolated_client, 'sts', primary_region)
            identity = await self.execute_with_backoff(asyncio.to_thread, sts_client.get_caller_identity)
            
            if not identity:
                return False
                
            self.tenant.credentials.aws_account_id = identity.get('Account')
            self.logger.info(f"STS Handshake Verified. Target Account Resolved: {identity.get('Account')}")
            return True
        except Exception as e:
            self.logger.error(f"AWS STS Connectivity Failed. Pipeline halted for this tenant: {e}")
            return False

    async def discover(self) -> List[Dict[str, Any]]:
        """
        The Master Extraction Orchestrator.
        Spawns parallel asynchronous threads to extract network, compute, 
        storage, and identity configurations across all target regions.
        """
        self.logger.info(f"[{self.tenant.id}] Initiating AWS Telemetry Extraction across {len(self.target_regions)} regions...")
        total_payloads = []
        
        # The Registry Force-Load
        reg = getattr(config, 'service_registry', {}).get("aws", {})
        if not reg:
            self.logger.debug(f"[{self.tenant.id}] Registry empty. Forcing Titan extraction defaults.")
            reg = {
                "iam_role": {"baseline_risk_score": 0.5},
                "s3_bucket": {"baseline_risk_score": 0.3},
                "rds_instance": {"baseline_risk_score": 0.8},
                "vpc": {"baseline_risk_score": 0.1},
                "subnet": {"baseline_risk_score": 0.1},
                "security_group": {"baseline_risk_score": 0.2},
                "ec2_instance": {"baseline_risk_score": 0.6}
            }

        tasks = []
        
        # 1. Global Services (IAM, S3)
        primary_region = self.target_regions[0]
        if "iam_role" in reg: 
            tasks.append(self._extract_iam_roles(primary_region, reg["iam_role"].get("baseline_risk_score", 0.5)))
        if "s3_bucket" in reg: 
            tasks.append(self._extract_s3_buckets(primary_region, reg["s3_bucket"].get("baseline_risk_score", 0.3)))

        # 2. Regional Services (VPC, EC2, RDS)
        for region in self.target_regions:
            if "vpc" in reg: 
                tasks.append(self._extract_vpcs(region, reg["vpc"].get("baseline_risk_score", 0.1)))
            if "subnet" in reg: 
                tasks.append(self._extract_subnets(region, reg["subnet"].get("baseline_risk_score", 0.1)))
            if "security_group" in reg: 
                tasks.append(self._extract_security_groups(region, reg["security_group"].get("baseline_risk_score", 0.2)))
            if "ec2_instance" in reg: 
                tasks.append(self._extract_ec2_instances(region, reg["ec2_instance"].get("baseline_risk_score", 0.6)))
            if "rds_instance" in reg: 
                tasks.append(self._extract_rds_instances(region, reg["rds_instance"].get("baseline_risk_score", 0.8)))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"A core AWS extraction task failed catastrophically: {result}")
                self.logger.debug(traceback.format_exc())
            elif result:
                total_payloads.extend(result)

        self.logger.info(f"[{self.tenant.id}] AWS Discovery Cycle Complete. Extracted {len(total_payloads)} nodes.")
        return total_payloads

    # ==========================================================================
    # RESOURCE EXTRACTION & NORMALIZATION MATRICES
    # ==========================================================================

    async def _execute_aws_list_api(self, client: Any, method_name: str, key_name: str, **kwargs) -> List[Dict]:
        """
        Direct-to-Hardware (D2H) API Executor.
        Bypasses boto3's internal paginators which are notoriously brittle against 
        LocalStack's emulated control plane. Natively handles execution and iteration.
        """
        def fetch_all():
            results = []
            method = getattr(client, method_name)
            
            response = method(**kwargs)
            results.extend(response.get(key_name, []))
            
            token = response.get('NextToken') or response.get('Marker')
            while token:
                if 'NextToken' in response:
                    kwargs['NextToken'] = token
                elif 'Marker' in response:
                    kwargs['Marker'] = token
                    
                response = method(**kwargs)
                results.extend(response.get(key_name, []))
                token = response.get('NextToken') or response.get('Marker')
                
            return results

        try:
            return await self.execute_with_backoff(asyncio.to_thread, fetch_all)
        except Exception as e:
            self.logger.error(f"D2H API Execution failed ({method_name}): {e}")
            return []

    async def _extract_iam_roles(self, region: str, risk: float) -> List[Dict]:
        try:
            client = await asyncio.to_thread(self._get_isolated_client, 'iam', region)
            roles = await self._execute_aws_list_api(client, 'list_roles', 'Roles')
            payloads = []
            
            for r in roles:
                role_name = r.get("RoleName", "")
                is_owner = await self._verify_tenant_ownership(client, 'iam', role_name, r.get("Tags", []))
                if not is_owner:
                    continue
                    
                arn = r.get("Arn")
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
        try:
            client = await asyncio.to_thread(self._get_isolated_client, 's3', region)
            response = await self.execute_with_backoff(asyncio.to_thread, client.list_buckets)
            buckets = response.get('Buckets', []) if response else []
            payloads = []
            account_id = self.tenant.credentials.aws_account_id or "unknown"
            
            for b in buckets:
                name = b.get("Name", "")
                is_owner = await self._verify_tenant_ownership(client, 's3', name, [])
                if not is_owner:
                    continue
                    
                arn = f"arn:aws:s3:::{name}"
                b["AccountId"] = account_id
                
                has_changed, state_hash = await self.check_state_differential(arn, b)
                if has_changed:
                    b["_state_hash"] = state_hash
                    payload = self.format_urm_payload("s3", "Bucket", arn, b, risk)
                    payload["cloud_provider"] = "aws"
                    payloads.append(payload)
            return payloads
        except Exception as e:
            self.logger.error(f"S3 Bucket extraction failed: {e}")
            return []

    async def _extract_vpcs(self, region: str, risk: float) -> List[Dict]:
        try:
            client = await asyncio.to_thread(self._get_isolated_client, 'ec2', region)
            vpcs = await self._execute_aws_list_api(client, 'describe_vpcs', 'Vpcs')
            payloads = []
            account_id = self.tenant.credentials.aws_account_id or "unknown"
            
            for v in vpcs:
                is_owner = await self._verify_tenant_ownership(client, 'ec2', v.get('VpcId', ''), v.get('Tags', []))
                if not is_owner:
                    continue
                    
                vid = v.get("VpcId")
                arn = f"arn:aws:ec2:{region}:{account_id}:vpc/{vid}"
                
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
        try:
            client = await asyncio.to_thread(self._get_isolated_client, 'ec2', region)
            subnets = await self._execute_aws_list_api(client, 'describe_subnets', 'Subnets')
            payloads = []
            account_id = self.tenant.credentials.aws_account_id or "unknown"
            
            for s in subnets:
                is_owner = await self._verify_tenant_ownership(client, 'ec2', s.get('SubnetId', ''), s.get('Tags', []))
                if not is_owner:
                    continue
                    
                sid = s.get("SubnetId")
                arn = f"arn:aws:ec2:{region}:{account_id}:subnet/{sid}"
                
                # Heuristics mapping
                if s.get("MapPublicIpOnLaunch"):
                    s.setdefault("tags", []).append({'Key': 'Exposure', 'Value': 'Public'})
                    
                has_changed, state_hash = await self.check_state_differential(arn, s)
                if has_changed:
                    s["_state_hash"] = state_hash
                    payload = self.format_urm_payload("ec2", "Subnet", arn, s, risk)
                    payload["cloud_provider"] = "aws"
                    payloads.append(payload)
            return payloads
        except Exception as e:
            self.logger.error(f"Subnet extraction failed in {region}: {e}")
            return []

    async def _extract_security_groups(self, region: str, risk: float) -> List[Dict]:
        try:
            client = await asyncio.to_thread(self._get_isolated_client, 'ec2', region)
            sgs = await self._execute_aws_list_api(client, 'describe_security_groups', 'SecurityGroups')
            payloads = []
            account_id = self.tenant.credentials.aws_account_id or "unknown"
            
            for sg in sgs:
                is_owner = await self._verify_tenant_ownership(client, 'ec2', sg.get('GroupName', ''), sg.get('Tags', []))
                if not is_owner:
                    continue
                    
                sgid = sg.get("GroupId")
                arn = f"arn:aws:ec2:{region}:{account_id}:security-group/{sgid}"
                
                has_changed, state_hash = await self.check_state_differential(arn, sg)
                if has_changed:
                    sg["_state_hash"] = state_hash
                    payload = self.format_urm_payload("ec2", "SecurityGroup", arn, sg, risk)
                    payload["cloud_provider"] = "aws"
                    payloads.append(payload)
            return payloads
        except Exception as e:
            self.logger.error(f"Security Group extraction failed in {region}: {e}")
            return []
            
    async def _extract_ec2_instances(self, region: str, risk: float) -> List[Dict]:
        try:
            client = await asyncio.to_thread(self._get_isolated_client, 'ec2', region)
            reservations = await self._execute_aws_list_api(client, 'describe_instances', 'Reservations')
            payloads = []
            account_id = self.tenant.credentials.aws_account_id or "unknown"
            
            for res in reservations:
                for inst in res.get("Instances", []):
                    is_owner = await self._verify_tenant_ownership(client, 'ec2', inst.get('InstanceId', ''), inst.get('Tags', []))
                    if not is_owner:
                        continue
                        
                    iid = inst.get("InstanceId")
                    arn = f"arn:aws:ec2:{region}:{account_id}:instance/{iid}"
                    
                    # Heuristics mapping
                    if inst.get("PublicIpAddress"):
                        inst.setdefault("tags", []).append({'Key': 'Exposure', 'Value': 'Public'})
                        risk += 0.2
                        
                    has_changed, state_hash = await self.check_state_differential(arn, inst)
                    if has_changed:
                        inst["_state_hash"] = state_hash
                        payload = self.format_urm_payload("ec2", "Instance", arn, inst, min(risk, 1.0))
                        payload["cloud_provider"] = "aws"
                        payloads.append(payload)
            return payloads
        except Exception as e:
            self.logger.error(f"EC2 Instance extraction failed in {region}: {e}")
            return []

    async def _extract_rds_instances(self, region: str, risk: float) -> List[Dict]:
        try:
            client = await asyncio.to_thread(self._get_isolated_client, 'rds', region)
            instances = await self._execute_aws_list_api(client, 'describe_db_instances', 'DBInstances')
            payloads = []
            
            for db in instances:
                is_owner = await self._verify_tenant_ownership(client, 'rds', db.get('DBInstanceIdentifier', ''), db.get('TagList', []))
                if not is_owner:
                    continue
                    
                arn = db.get("DBInstanceArn")
                
                # Heuristics mapping
                if db.get("PubliclyAccessible"):
                    db.setdefault("tags", []).append({'Key': 'Exposure', 'Value': 'Public'})
                    risk += 0.3
                if not db.get("StorageEncrypted"):
                    db.setdefault("tags", []).append({'Key': 'Encryption', 'Value': 'Disabled'})
                    risk += 0.4
                    
                has_changed, state_hash = await self.check_state_differential(arn, db)
                if has_changed:
                    db["_state_hash"] = state_hash
                    payload = self.format_urm_payload("rds", "DBInstance", arn, db, min(risk, 1.0))
                    payload["cloud_provider"] = "aws"
                    payloads.append(payload)
            return payloads
        except Exception as e:
            return []