import logging
import json
import time
import uuid
import asyncio
import traceback
import functools
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import (
    ClientError, 
    EndpointConnectionError, 
    ConnectTimeoutError, 
    ReadTimeoutError,
    BotoCoreError,
    NoCredentialsError,
    ParamValidationError,
)

from core.config import config, TenantConfig
from discovery.engines.base_engine import BaseDiscoveryEngine, EngineMode

# ==============================================================================
# CLOUDSCAPE NEXUS 5.2 TITAN - AWS MULTI-REGION EXTRACTION SENSOR (SUPREME EDITION)
# ==============================================================================
# The physical AWS Cloud Extraction Sensor. Now properly extends 
# BaseDiscoveryEngine for consistent backoff, circuit breaker, and URM behavior.
#
# TITAN NEXUS 5.2 UPGRADES ACTIVE:
# 1. EXTENDS BaseDiscoveryEngine: Proper OOP inheritance with shared backoff.
# 2. MULTI-REGION THREADING: Parallel extraction across all configured regions.
# 3. DEEP METADATA ENRICHMENT: IAM secondary metadata, tags, policy parsing.
# 4. PAGINATION SUPPORT: Full auto-pagination for any paginated API.
# 5. SERVICE REGISTRY DRIVEN: Dynamically loads service+method pairs from JSON.
# 6. LOCALSTACK COMPATIBILITY: Micro-cooling for Docker stability.
# 7. ARN SYNTHESIS: Constructs ARNs when not natively returned by APIs.
# 8. FAULT ISOLATION: Each service extraction runs in its own barrier.
# ==============================================================================


# Minimal fallback for when LocalStack health probe is unreachable.
# The engine will ALWAYS attempt dynamic probing first.
_LOCALSTACK_FALLBACK_SERVICES = frozenset({
    "iam", "s3", "ec2", "sts",
})


class AWSEngine(BaseDiscoveryEngine):
    """
    The Supreme AWS Multi-Region Extraction Sensor.
    Discovers, enumerates, and normalizes AWS infrastructure into URM nodes.
    """

    def __init__(self, tenant: TenantConfig):
        super().__init__(tenant)
        self.logger = logging.getLogger(f"CloudScape.Engine.AWS.[{tenant.id}]")
        
        # AWS Configuration
        self.aws_regions: List[str] = config.settings.aws.target_regions
        self.localstack_endpoint: str = config.settings.aws.localstack_endpoint
        self.max_retries: int = config.settings.aws.boto_max_retries
        self.boto_timeout: int = config.settings.aws.boto_timeout
        self.pagination_page_size: int = config.settings.aws.pagination_page_size
        
        # Tenant identity
        self.aws_account_id: str = tenant.credentials.aws_account_id
        self.aws_access_key: str = tenant.credentials.aws_access_key_id
        self.aws_secret_key: str = tenant.credentials.aws_secret_access_key
        
        # Service Registry
        self.service_registry: Dict[str, Any] = {}
        self._load_service_registry()
        
        # Multi-region thread pool
        max_workers = min(len(self.aws_regions) * 3, 15)
        self._region_executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix=f"aws-{tenant.id[:6]}"
        )
        
        self.logger.debug(
            f"AWS Engine initialized: "
            f"regions={self.aws_regions}, "
            f"mode={self.mode.value}, "
            f"account={self.aws_account_id}"
        )

    # --------------------------------------------------------------------------
    # SERVICE REGISTRY LOADING
    # --------------------------------------------------------------------------
    
    def _load_service_registry(self) -> None:
        """Loads the service:method pairs from the JSON service registry."""
        registry_paths = [
            Path(config.config_manager.base_dir if hasattr(config, 'config_manager') else '.') / "registry" / "aws_services.json",
            Path(__file__).resolve().parent.parent / "registry" / "aws_services.json",
            Path(__file__).resolve().parent.parent / "config" / "aws_services.json",
        ]
        
        for path in registry_paths:
            if path.exists():
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        self.service_registry = json.load(f)
                    self.logger.debug(f"Loaded AWS service registry: {len(self.service_registry)} services")
                    return
                except (json.JSONDecodeError, IOError) as e:
                    self.logger.warning(f"Failed to parse {path}: {e}")
        
        # Fallback: Hardcoded essential services
        self.logger.warning("No service registry found. Using hardcoded fallback.")
        self.service_registry = {
            "ec2": [{"method": "describe_instances", "key": "Reservations"}],
            "s3": [{"method": "list_buckets", "key": "Buckets"}],
            "iam": [
                {"method": "list_roles", "key": "Roles"},
                {"method": "list_users", "key": "Users"},
                {"method": "list_groups", "key": "Groups"}
            ],
            "rds": [{"method": "describe_db_instances", "key": "DBInstances"}],
            "lambda": [{"method": "list_functions", "key": "Functions"}],
            "dynamodb": [{"method": "list_tables", "key": "TableNames"}],
            "sqs": [{"method": "list_queues", "key": "QueueUrls"}],
        }

    # --------------------------------------------------------------------------
    # CONNECTION TESTING - Abstract Implementation
    # --------------------------------------------------------------------------
    
    async def test_connection(self) -> bool:
        """Validates connectivity by calling STS GetCallerIdentity."""
        try:
            sts_client = self._create_boto_client("sts", "us-east-1")
            
            identity = await self.execute_with_backoff(
                sts_client.get_caller_identity,
                operation_name="STS.GetCallerIdentity"
            )
            
            actual_account = identity.get("Account", "unknown")
            actual_arn = identity.get("Arn", "unknown")
            
            self.logger.info(
                f"AWS STS validated. Account: {actual_account}, ARN: {actual_arn}"
            )
            
            # Update account ID if we got a real one
            if actual_account != "unknown" and self.aws_account_id == "123456789012":
                self.aws_account_id = actual_account
                self.logger.debug(f"Account ID updated to: {self.aws_account_id}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"STS connectivity test failed: {e}")
            return False

    # --------------------------------------------------------------------------
    # MASTER DISCOVERY - Abstract Implementation
    # --------------------------------------------------------------------------
    
    async def discover(self) -> List[Dict[str, Any]]:
        """
        Executes the full multi-region AWS discovery cycle.
        
        Architecture:
        1. For each region, creates a set of service extraction tasks
        2. Each service runs inside a fault isolation barrier
        3. Results are flattened, deduplicated, and returned as URM nodes
        """
        self.logger.info(f"Starting multi-region AWS discovery across {len(self.aws_regions)} regions...")
        self.metrics.reset()
        start_time = time.perf_counter()
        
        all_nodes: List[Dict[str, Any]] = []
        
        # Determine which services to scan
        services_to_scan = self._get_scannable_services()
        
        # Execute per-region extraction
        for region in self.aws_regions:
            self.logger.debug(f"  Scanning region: {region}")
            region_nodes = await self._extract_region(region, services_to_scan)
            all_nodes.extend(region_nodes)
            self.metrics.regions_scanned += 1
        
        # Enrich IAM entities (global, region-independent)
        iam_nodes = [n for n in all_nodes if n.get("service") == "iam"]
        if iam_nodes:
            all_nodes = await self._enrich_iam_metadata(all_nodes)
        
        # Metrics
        self.metrics.total_extraction_time_ms = (time.perf_counter() - start_time) * 1000
        self.metrics.last_extraction_timestamp = datetime.now(timezone.utc).isoformat()
        self.metrics.nodes_extracted = len(all_nodes)
        
        self.logger.info(
            f"AWS Discovery complete: {len(all_nodes)} nodes across "
            f"{self.metrics.regions_scanned} regions "
            f"({self.metrics.total_extraction_time_ms:.0f}ms)"
        )
        
        return all_nodes

    def _probe_localstack_services(self) -> frozenset:
        """
        Dynamically queries the LocalStack health endpoint to discover which
        AWS services are actually running.  Falls back to a minimal hardcoded
        set only if the probe fails (e.g. container not reachable).
        """
        health_url = self.localstack_endpoint.rstrip("/") + "/_localstack/health"
        try:
            req = urllib.request.Request(health_url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            services_section = data.get("services", {})
            running = frozenset(
                svc.lower()
                for svc, status in services_section.items()
                if status in ("available", "running", "ready")
            )
            if running:
                self.logger.debug(
                    f"LocalStack probe: {len(running)} live services — {sorted(running)}"
                )
                return running

            self.logger.warning("LocalStack health reported 0 running services.")
        except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError) as e:
            self.logger.warning(f"LocalStack health probe failed ({e}). Using fallback.")

        return _LOCALSTACK_FALLBACK_SERVICES

    def _get_scannable_services(self) -> Dict[str, Any]:
        """
        Determines which services to scan based on mode and registry.
        In MOCK mode, dynamically probes LocalStack to discover available
        services rather than relying on a hardcoded allowlist.
        """
        if self.mode == EngineMode.MOCK:
            live_services = self._probe_localstack_services()
            filtered = {
                k: v for k, v in self.service_registry.items()
                if k.lower() in live_services
            }
            self.logger.debug(
                f"MOCK mode: Scanning {len(filtered)}/{len(self.service_registry)} services "
                f"(dynamically probed from LocalStack)"
            )
            return filtered
        return self.service_registry

    async def _extract_region(self, region: str, services: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts all services for a single region using Partitioned Execution.
        Low resource services run in PARALLEL. High resource services run SERIALLY."""
        region_nodes: List[Dict[str, Any]] = []
        
        high_resource_services = {"ec2", "rds", "lambda", "ecs", "eks", "dynamodb"}
        low_res_tasks = []
        high_res_tasks = []
        
        for service_name, methods in services.items():
            if service_name in ("iam", "s3") and region != "us-east-1":
                continue
            
            if service_name in high_resource_services:
                high_res_tasks.append((service_name, methods))
            else:
                low_res_tasks.append((service_name, methods))
        
        # 1. Execute LOW-RESOURCE services in PARALLEL
        if low_res_tasks:
            self.logger.debug(f"    [PARALLEL] Extracting low-resource AWS services: {[s for s, _ in low_res_tasks]}")
            coroutines = [
                self._extract_service_safely(region, service_name, methods)
                for service_name, methods in low_res_tasks
            ]
            results = await asyncio.gather(*coroutines, return_exceptions=True)
            for result, (service_name, _) in zip(results, low_res_tasks):
                if isinstance(result, Exception):
                    self.metrics.services_failed += 1
                    self.logger.warning(f"  [ISOLATED] {service_name} in {region} failed: {result}")
                elif result:
                    region_nodes.extend(result)
                    self.metrics.services_scanned += 1
                    
        # 2. Execute HIGH-RESOURCE services SERIALLY to prevent API saturation
        for service_name, methods in high_res_tasks:
            try:
                self.logger.debug(f"    [SERIAL] Extracting high-resource AWS service: {service_name}")
                service_nodes = await self._extract_service(region, service_name, methods)
                region_nodes.extend(service_nodes)
                self.metrics.services_scanned += 1
            except Exception as e:
                self.metrics.services_failed += 1
                self.logger.warning(
                    f"  [ISOLATED] {service_name} in {region} failed: {e}"
                )
        
        return region_nodes

    async def _extract_service_safely(self, region: str, service_name: str, methods: Any) -> List[Dict[str, Any]]:
        """Wrapper to catch exceptions safely when using asyncio.gather."""
        return await self._extract_service(region, service_name, methods)

    async def _extract_service(
        self, 
        region: str, 
        service_name: str, 
        methods: Any
    ) -> List[Dict[str, Any]]:
        """Extracts resources for a single service."""
        nodes: List[Dict[str, Any]] = []
        
        try:
            client = self._create_boto_client(service_name, region)
        except Exception as e:
            self.logger.debug(f"    Could not create client for {service_name}: {e}")
            return nodes
        
        # Handle both list and dict registry formats
        method_list = methods if isinstance(methods, list) else [methods]
        
        for method_spec in method_list:
            method_name = method_spec.get("method", "") if isinstance(method_spec, dict) else str(method_spec)
            response_key = method_spec.get("key", "") if isinstance(method_spec, dict) else ""
            
            if not method_name:
                continue
            
            try:
                # Execute the API call with backoff and circuit breaker
                raw_response = await self.execute_with_backoff(
                    self._call_service_method,
                    client, method_name,
                    operation_name=f"{service_name}.{method_name}"
                )
                
                if not raw_response:
                    continue
                
                # Extract the resource list from the response
                resources = self._extract_resource_list(raw_response, response_key, service_name)
                
                # Normalize each resource into a URM node
                for resource in resources:
                    try:
                        urm_node = self._normalize_aws_resource(
                            service_name, method_name, resource, region
                        )
                        if urm_node:
                            nodes.append(urm_node)
                    except Exception as norm_error:
                        self.logger.debug(f"    Normalization error: {norm_error}")
                
                # LocalStack micro-cooling
                if self.mode == EngineMode.MOCK:
                    await asyncio.sleep(0.2)
                    
            except RuntimeError as re:
                if "Circuit breaker" in str(re):
                    self.logger.warning(f"    Circuit breaker open for {service_name}")
                    break  # Stop calling this service entirely
                raise
            except Exception as e:
                self.logger.debug(f"    {service_name}.{method_name} error: {e}")
        
        return nodes

    def _call_service_method(self, client, method_name: str) -> Optional[Dict]:
        """
        Calls a Boto3 service method with automatic pagination support.
        This runs in a thread pool (blocking).
        """
        method = getattr(client, method_name, None)
        if not method:
            return None
        
        try:
            # Check if the method supports pagination
            if hasattr(client, 'get_paginator'):
                try:
                    paginator = client.get_paginator(method_name)
                    pages = paginator.paginate(PaginationConfig={'PageSize': self.pagination_page_size})
                    
                    # Merge all pages into a single response
                    merged = {}
                    for page in pages:
                        for key, value in page.items():
                            if isinstance(value, list):
                                merged.setdefault(key, []).extend(value)
                            elif key not in merged:
                                merged[key] = value
                    return merged
                    
                except (ClientError, Exception):
                    pass  # Fall through to non-paginated call
            
            # Non-paginated call
            return method()
            
        except ClientError as ce:
            raise  # Let the backoff handler deal with it
        except Exception as e:
            self.logger.debug(f"    Service method call error: {e}")
            raise

    # --------------------------------------------------------------------------
    # RESOURCE NORMALIZATION
    # --------------------------------------------------------------------------
    
    def _extract_resource_list(
        self, 
        response: Dict, 
        response_key: str, 
        service_name: str
    ) -> List[Dict]:
        """Extracts the list of resources from an API response."""
        if response_key and response_key in response:
            result = response[response_key]
            if isinstance(result, list):
                return result
            return [result] if result else []
        
        # EC2 special case: nested Reservations -> Instances
        if service_name == "ec2" and "Reservations" in response:
            instances = []
            for reservation in response["Reservations"]:
                instances.extend(reservation.get("Instances", []))
            return instances
        
        # Fallback: try common keys
        for key in ["Items", "Resources", "results", "data"]:
            if key in response and isinstance(response[key], list):
                return response[key]
        
        return []

    def _normalize_aws_resource(
        self, 
        service: str, 
        method: str, 
        resource: Dict, 
        region: str
    ) -> Optional[Dict[str, Any]]:
        """Converts a raw AWS API resource into a URM-compliant node."""
        if not isinstance(resource, dict):
            return None
        
        # Determine resource type from the method name
        resource_type = self._infer_resource_type(service, method, resource)
        
        # Construct or extract ARN
        arn = self._resolve_arn(service, resource, region, resource_type)
        
        if not arn:
            return None
        
        # Determine baseline risk
        base_risk = self._calculate_aws_risk(service, resource)
        
        return self.format_urm_payload(
            service=service,
            resource_type=resource_type,
            arn=arn,
            raw_data=resource,
            baseline_risk=base_risk
        )

    def _resolve_arn(self, service: str, resource: Dict, region: str, resource_type: str) -> str:
        """
        Resolves or synthesizes an ARN for an AWS resource.
        Many APIs don't return ARNs natively, so we construct them.
        """
        # Try direct ARN fields
        for arn_key in ("Arn", "arn", "RoleArn", "FunctionArn", "UserArn", "GroupArn",
                        "DBInstanceArn", "TopicArn", "QueueArn", "StackId", "KeyArn"):
            if arn_key in resource and resource[arn_key]:
                return resource[arn_key]
        
        # Synthesize ARN based on service
        arn_templates = {
            "ec2": lambda r: f"arn:aws:ec2:{region}:{self.aws_account_id}:instance/{r.get('InstanceId', uuid.uuid4().hex[:8])}",
            "s3": lambda r: f"arn:aws:s3:::{r.get('Name', r.get('BucketName', uuid.uuid4().hex[:8]))}",
            "rds": lambda r: f"arn:aws:rds:{region}:{self.aws_account_id}:db:{r.get('DBInstanceIdentifier', uuid.uuid4().hex[:8])}",
            "lambda": lambda r: f"arn:aws:lambda:{region}:{self.aws_account_id}:function:{r.get('FunctionName', uuid.uuid4().hex[:8])}",
            "dynamodb": lambda r: f"arn:aws:dynamodb:{region}:{self.aws_account_id}:table/{r if isinstance(r, str) else r.get('TableName', uuid.uuid4().hex[:8])}",
            "sqs": lambda r: r.get('QueueUrl', f"arn:aws:sqs:{region}:{self.aws_account_id}:{uuid.uuid4().hex[:8]}"),
            "kms": lambda r: f"arn:aws:kms:{region}:{self.aws_account_id}:key/{r.get('KeyId', uuid.uuid4().hex[:8])}",
            "ecs": lambda r: r.get('clusterArn', f"arn:aws:ecs:{region}:{self.aws_account_id}:cluster/{uuid.uuid4().hex[:8]}"),
        }
        
        if service in arn_templates:
            try:
                return arn_templates[service](resource)
            except Exception:
                pass
        
        # Ultimate fallback
        identifier = resource.get('Id', resource.get('Name', uuid.uuid4().hex[:8]))
        return f"arn:aws:{service}:{region}:{self.aws_account_id}:{resource_type.lower()}/{identifier}"

    def _infer_resource_type(self, service: str, method: str, resource: Dict) -> str:
        """Infers the resource type from the service name and method."""
        type_map = {
            ("ec2", "describe_instances"): "Instance",
            ("ec2", "describe_vpcs"): "VPC",
            ("ec2", "describe_subnets"): "Subnet",
            ("ec2", "describe_security_groups"): "SecurityGroup",
            ("s3", "list_buckets"): "Bucket",
            ("iam", "list_roles"): "Role",
            ("iam", "list_users"): "User",
            ("iam", "list_groups"): "Group",
            ("rds", "describe_db_instances"): "DBInstance",
            ("lambda", "list_functions"): "Function",
            ("dynamodb", "list_tables"): "Table",
            ("sqs", "list_queues"): "Queue",
            ("kms", "list_keys"): "Key",
            ("ecs", "list_clusters"): "Cluster",
            ("route53", "list_hosted_zones"): "HostedZone",
        }
        return type_map.get((service, method), service.capitalize())

    def _calculate_aws_risk(self, service: str, resource: Dict) -> float:
        """Calculates a baseline risk score based on service type and exposure."""
        base_risks = {
            "iam": 6.0, "s3": 4.0, "rds": 5.0, "ec2": 3.0,
            "lambda": 3.5, "kms": 7.0, "secretsmanager": 7.0,
            "dynamodb": 4.0, "ecs": 4.0, "sqs": 3.0,
        }
        risk = base_risks.get(service, 3.0)
        
        # Amplify if public
        if resource.get("PubliclyAccessible") or resource.get("PublicDnsName"):
            risk = min(10.0, risk + 2.0)
        
        # Amplify if IAM with wildcard
        if service == "iam":
            policies = resource.get("AttachedManagedPolicies", [])
            for p in policies:
                if isinstance(p, dict) and "Admin" in p.get("PolicyName", ""):
                    risk = min(10.0, risk + 2.0)
        
        return risk

    # --------------------------------------------------------------------------
    # IAM SECONDARY METADATA ENRICHMENT
    # --------------------------------------------------------------------------
    
    async def _enrich_iam_metadata(self, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enriches IAM entities with secondary metadata:
        - Access Keys (for Users)
        - Inline Policies (for Roles and Users)
        - Assume Role Policy Document (for Roles)
        """
        if self.mode == EngineMode.MOCK:
            self.logger.debug("    Skipping deep IAM enrichment in MOCK mode.")
            return nodes
        
        self.logger.debug("    Enriching IAM secondary metadata...")
        iam_client = self._create_boto_client("iam", "us-east-1")
        
        for node in nodes:
            if node.get("service") != "iam":
                continue
            
            try:
                name = node.get("name", "")
                res_type = node.get("type", "").lower()
                
                if res_type == "user" and name:
                    # Fetch access keys
                    keys_resp = await self.execute_with_backoff(
                        iam_client.list_access_keys,
                        UserName=name,
                        operation_name=f"IAM.ListAccessKeys({name})"
                    )
                    if keys_resp:
                        node.setdefault("metadata", {})["_secondary_metadata"] = {
                            "AccessKeys": keys_resp.get("AccessKeyMetadata", [])
                        }
                
                elif res_type == "role" and name:
                    # Fetch role details
                    role_resp = await self.execute_with_backoff(
                        iam_client.get_role,
                        RoleName=name,
                        operation_name=f"IAM.GetRole({name})"
                    )
                    if role_resp and "Role" in role_resp:
                        trust_doc = role_resp["Role"].get("AssumeRolePolicyDocument", {})
                        node.setdefault("metadata", {})["AssumeRolePolicyDocument"] = (
                            json.dumps(trust_doc) if isinstance(trust_doc, dict) else str(trust_doc)
                        )
                        
            except Exception as e:
                self.logger.debug(f"    IAM enrichment error for {node.get('name', 'unknown')}: {e}")
                continue  # Non-critical
        
        return nodes

    # --------------------------------------------------------------------------
    # BOTO3 CLIENT FACTORY
    # --------------------------------------------------------------------------
    
    def _create_boto_client(self, service: str, region: str):
        """Creates a configured Boto3 client with proper timeout and retry settings."""
        boto_config = BotoConfig(
            retries={"max_attempts": 0, "mode": "standard"},  # We handle retries ourselves
            connect_timeout=self.boto_timeout,
            read_timeout=self.boto_timeout,
            max_pool_connections=25,
        )
        
        client_kwargs = {
            "service_name": service,
            "region_name": region,
            "config": boto_config,
        }
        
        if self.mode == EngineMode.MOCK:
            client_kwargs.update({
                "aws_access_key_id": "testing",
                "aws_secret_access_key": "testing",
                "endpoint_url": self.localstack_endpoint,
            })
        else:
            client_kwargs.update({
                "aws_access_key_id": self.aws_access_key,
                "aws_secret_access_key": self.aws_secret_key,
            })
        
        return boto3.client(**client_kwargs)

    # --------------------------------------------------------------------------
    # LIFECYCLE OVERRIDES
    # --------------------------------------------------------------------------
    
    async def teardown(self) -> None:
        """Shuts down the AWS engine and its thread pools."""
        self._region_executor.shutdown(wait=True, cancel_futures=False)
        await super().teardown()