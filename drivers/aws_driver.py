import asyncio
import logging
import json
import os
import boto3
import traceback
from typing import List, Dict, Any
from botocore.config import Config

from engines.base_engine import BaseDiscoveryEngine
from core.config import config

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - AWS DISCOVERY ENGINE (TITAN EDITION)
# ==============================================================================
# Enterprise AWS telemetry extraction sensor. 
# Features Service-Level Fault Isolation, Heavy-Service Deferral, Dynamic 
# Pagination mapping, and LocalStack emulator cooling protocols.
# ==============================================================================

class AWSEngine(BaseDiscoveryEngine):
    def __init__(self, tenant):
        super().__init__(tenant)
        self.logger = logging.getLogger(f"Cloudscape.Engines.AWS.[{self.tenant.id}]")
        self.account_id = "UNKNOWN"
        self.registry = {}
        
        # Deep Boto3 connection parameters. 
        # Retries are stripped here because they are handled strictly by the 
        # Titan BaseEngine's exponential backoff & jitter circuit breaker.
        self.boto_config = Config(
            retries={'max_attempts': 0},
            connect_timeout=15,
            read_timeout=45,
            max_pool_connections=config.settings.crawling.concurrency
        )
        
        self._load_service_registry()

    def _load_service_registry(self):
        """
        Loads the universal service blueprint that maps physical AWS APIs.
        Safely resolves the path regardless of the execution directory.
        """
        registry_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'service_registry.json')
        try:
            with open(registry_path, 'r') as f:
                full_registry = json.load(f)
                self.registry = full_registry.get("aws", {})
        except Exception as e:
            self.logger.critical(f"FATAL: Failed to mount AWS Service Registry: {e}")
            self.registry = {}

    async def test_connection(self) -> bool:
        """
        Validates the AWS partition handshake and resolves the exact Account ID 
        used for deterministic ARN synthesis later in the pipeline.
        """
        try:
            client_kwargs = self.get_aws_client_kwargs()
            # STS validation must operate in a globally stable boundary
            client_kwargs["region_name"] = "us-east-1"
            
            sts_client = boto3.client('sts', config=self.boto_config, **client_kwargs)
            
            # Utilize the Titan resilient backoff to verify connectivity
            response = await self.execute_with_backoff(sts_client.get_caller_identity)
            
            self.account_id = response.get('Account', '000000000000')
            self.logger.info(f"STS Handshake Verified. Target Partition resolved to Account: {self.account_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"AWS STS Handshake Rejected: {e}")
            return False

    async def discover(self) -> List[Dict[str, Any]]:
        """
        The Master Extraction Loop.
        Iterates over target regions and services, protected by a strict fault 
        isolation barrier to ensure partial data survival during infrastructure outages.
        """
        self.logger.info(f"[{self.tenant.id}] Engaging AWS Deep Discovery across {len(config.settings.aws.target_regions)} regions...")
        discovered_nodes = []
        
        # 1. Establish initial identity trust
        connection_valid = await self.test_connection()
        if not connection_valid and not config.settings.crawling.fail_open_on_access_denied:
            self.logger.warning("Aborting discovery due to STS validation failure.")
            return discovered_nodes

        # 2. Smart-Sort the Registry (Heavy Service Deferral)
        # Push 'rds' and 'redshift' to the back of the queue. This extracts VPCs/IAMs 
        # first, giving LocalStack time to stabilize before hitting heavy database emulators.
        heavy_services = ['rds', 'redshift', 'elasticache', 'neptune']
        sorted_registry = sorted(
            self.registry.items(), 
            key=lambda x: 1 if any(h in x[0].lower() for h in heavy_services) else 0
        )

        # 3. Sweep across physical geographic boundaries
        for region in config.settings.aws.target_regions:
            client_kwargs = self.get_aws_client_kwargs()
            client_kwargs["region_name"] = region
            
            for service_key, meta in sorted_registry:
                # ==============================================================
                # TITAN FAULT ISOLATION BARRIER
                # ==============================================================
                # This try/except prevents a single service crash (e.g. LocalStack 
                # RDS HTTP 500 Deadlock) from discarding the successfully extracted 
                # nodes of sibling services (VPC, S3, IAM).
                try:
                    boto_client_name = meta['boto_client']
                    client = boto3.client(boto_client_name, config=self.boto_config, **client_kwargs)
                    
                    service_nodes = await self._extract_service(client, region, service_key, meta)
                    if service_nodes:
                        discovered_nodes.extend(service_nodes)
                        
                except Exception as e:
                    self.logger.error(f"[{service_key}] Service Extraction Terminated: {e}")
                    self.logger.warning(f"Blast Radius Contained. Preserving {len(discovered_nodes)} sibling nodes for {self.tenant.id}.")
                    continue  # The Magic Bullet: Safely move to the next service.
                    
        self.logger.info(f"[{self.tenant.id}] AWS Discovery Cycle Complete. Extracted {len(discovered_nodes)} Nodes.")
        return discovered_nodes

    async def _extract_service(self, client, region: str, service_key: str, meta: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Dynamically executes the AWS API call based on the JSON registry definition.
        Handles dynamic pagination, ARN synthesis, and LocalStack emulator micro-cooling.
        """
        extracted_data = []
        list_func_name = meta['list_function']
        result_key = meta['result_key']
        resource_type = meta['resource_type']
        baseline_risk = meta.get('baseline_risk_score', 0.5)
        
        # [ TITAN MICRO-COOLING INJECTOR ]
        # Give the Docker daemon a physical CPU breather before firing heavy forks.
        if self.mode == "MOCK" and "rds" in service_key.lower():
            self.logger.debug(f"Injecting micro-cooling delay before heavy execution: {service_key}")
            await asyncio.sleep(2.5)

        # 1. Dynamic Pagination Resolution
        if client.can_paginate(list_func_name):
            paginator = client.get_paginator(list_func_name)
            
            # Define a blocking wrapper to exhaust the paginator inside the thread pool
            def fetch_all_pages():
                results = []
                for page in paginator.paginate():
                    results.extend(page.get(result_key, []))
                return results
                
            items = await self.execute_with_backoff(fetch_all_pages)
        else:
            # Single-call resolution
            list_func = getattr(client, list_func_name)
            response = await self.execute_with_backoff(list_func)
            items = response.get(result_key, [])

        # 2. URM Transformation & ARN Synthesis
        for item in items:
            # Physical ARN resolution vs Synthetic Generation
            arn = item.get("Arn") or item.get("DBInstanceArn") or item.get("RoleArn") or item.get("GroupArn") or item.get("VpcId")
            
            if not arn:
                # Synthesize a globally unique identifier if the API omits it natively
                resource_id = item.get("Id") or item.get("Name") or item.get("InstanceId") or "unknown"
                arn = f"arn:aws:{meta['boto_client']}:{region}:{self.account_id}:{resource_type.lower()}/{resource_id}"
            
            # Normalize into the Cloudscape Universal Resource Model (URM)
            formatted_node = self.format_urm_payload(
                service="aws",
                resource_type=resource_type,
                arn=arn,
                raw_data=item,
                baseline_risk=baseline_risk
            )
            extracted_data.append(formatted_node)
            
        return extracted_data