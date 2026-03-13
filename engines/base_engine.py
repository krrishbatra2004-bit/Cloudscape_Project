import abc
import asyncio
import hashlib
import json
import logging
import os
import time
import traceback
import random
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Tuple, Optional, Union

# Cloud Provider Exceptions for Circuit Breaker
try:
    from botocore.exceptions import ClientError, BotoCoreError, EndpointConnectionError
except ImportError:
    ClientError = BotoCoreError = EndpointConnectionError = Exception

try:
    from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
except ImportError:
    HttpResponseError = ResourceNotFoundError = Exception

from core.config import config, TenantConfig

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - BASE DISCOVERY ENGINE (TITAN EDITION)
# ==============================================================================
# The Enterprise Abstract Gateway.
# Manages execution modes (MOCK vs LIVE), dynamic endpoint routing, resilient 
# jitter-backed network backoffs, concurrency limiting, URM normalization, and 
# recursive differential state hashing for high-performance convergence.
#
# TITAN UPGRADES ACTIVE: 
# - Adaptive Contextual Fast-Fail (Auth drops instantly, bypassing 9m loops)
# - Pre-Emptive Stagger (Mathematical desynchronization of Docker threads)
# - Universal Tag Normalizer (Cross-vendor flattening)
# - Asynchronous Thread-Pool Isolation for blocking SDKs
# ==============================================================================

class BaseDiscoveryEngine(abc.ABC):
    def __init__(self, tenant: TenantConfig):
        """
        Initializes the Core Discovery primitives, setting up isolated logging, 
        forensic metrics, and the environment-aware execution mode.
        """
        self.tenant = tenant
        self.logger = logging.getLogger(f"Cloudscape.Engines.Base.[{self.tenant.id}]")
        
        # ----------------------------------------------------------------------
        # MODE ROUTER: Path A (MOCK) vs Path B (LIVE)
        # ----------------------------------------------------------------------
        self.mode = config.settings.execution_mode.upper()
        
        # ----------------------------------------------------------------------
        # RESILIENCE & CONCURRENCY TUNING
        # ----------------------------------------------------------------------
        self.max_retries = getattr(config.settings.crawling, "api_retry_max_attempts", 6)
        self.base_delay = getattr(config.settings.crawling, "api_retry_backoff_factor", 2.0)
        self.cap_delay = 60.0 # Maximum physical wait time per retry
        
        # Pull strict concurrency caps from the Pydantic configuration model
        self.max_concurrent_tasks = getattr(config.settings.system, "max_concurrency_per_engine", 5)
        self._semaphore = asyncio.Semaphore(self.max_concurrent_tasks)
        
        # ----------------------------------------------------------------------
        # FORENSIC METRICS MATRIX
        # ----------------------------------------------------------------------
        self.metrics = {
            "api_calls_attempted": 0,
            "api_calls_successful": 0,
            "circuit_breaker_triggers": 0,
            "fast_fails_executed": 0,
            "state_hashes_calculated": 0,
            "state_hashes_unchanged": 0,
            "nodes_formatted": 0,
            "execution_time_ms": 0.0
        }
        
        self._log_initialization_state()

    def _log_initialization_state(self) -> None:
        """Outputs the operational parameters to the forensic log."""
        if self.mode == "MOCK":
            self.logger.info("Engine initialized in MOCK Mode. Traffic routed to Local Sandbox Gateways.")
        else:
            self.logger.info("Engine initialized in LIVE Mode. Engaging physical cloud partitions.")

    # ==========================================================================
    # DYNAMIC CONNECTION GATEWAYS (THE "HOT SWAP" ROUTERS)
    # ==========================================================================

    def get_aws_client_kwargs(self) -> Dict[str, Any]:
        """
        The Universal AWS Connection Gateway.
        Dynamically steers SDK traffic based on the execution mode. In MOCK mode,
        it intercepts all endpoints and forces them into the LocalStack container.
        """
        kwargs = {}
        if self.mode == "MOCK":
            # Force traffic to the LocalStack Docker mesh (Port 4566)
            kwargs["endpoint_url"] = getattr(config.settings.aws, "localstack_endpoint", "http://localhost:4566")
            # Prevent Identity Shadowing by forcing the partition testing keys
            kwargs["aws_access_key_id"] = "test_titan_key"
            kwargs["aws_secret_access_key"] = "test_titan_secret"
            # Disable SSL verification for local docker execution
            kwargs["verify"] = False
        else:
            # Physical production environment binding
            kwargs["aws_access_key_id"] = getattr(self.tenant.credentials, 'aws_access_key_id', None)
            kwargs["aws_secret_access_key"] = getattr(self.tenant.credentials, 'aws_secret_access_key', None)
            
        return kwargs

    def get_azure_connection_parameters(self) -> Dict[str, Any]:
        """
        The Universal Azure Connection Gateway.
        Provides connectivity logic for Azurite (MOCK) or ARM/Graph APIs (LIVE).
        """
        if self.mode == "MOCK":
            azurite_endpoint = getattr(config.settings.azure, "azurite_endpoint", "http://127.0.0.1:10000")
            return {
                "connection_string": (
                    f"DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
                    f"AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
                    f"BlobEndpoint={azurite_endpoint}/devstoreaccount1;"
                ),
                "is_mock": True
            }
        else:
            return {
                "is_mock": False
            }

    # ==========================================================================
    # NETWORK RESILIENCE (CIRCUIT BREAKER & ISOLATION)
    # ==========================================================================

    async def execute_with_backoff(self, func: Callable, *args, **kwargs) -> Any:
        """
        The Titan Adaptive Resilience Gateway.
        1. Thread Isolation: Offloads blocking synchronous SDKs to background workers.
        2. Pre-Emptive Stagger: Prevents Thundering Herd lockups on LocalStack.
        3. Contextual Interceptor: Analyzes physical tracebacks to either fast-fail or deep-backoff.
        """
        # [ TITAN PRE-EMPTIVE STAGGER ]
        if self.mode == "MOCK":
            stagger_delay = random.uniform(0.1, 2.5)
            await asyncio.sleep(stagger_delay)

        async with self._semaphore:
            self.metrics["api_calls_attempted"] += 1
            retries = 0
            
            while retries <= self.max_retries:
                try:
                    start_time = time.perf_counter()
                    
                    # Thread Isolation: Prevent synchronous SDKs (boto3/azure) from blocking the async event loop
                    if asyncio.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        result = await asyncio.to_thread(func, *args, **kwargs)
                        
                    self.metrics["execution_time_ms"] += (time.perf_counter() - start_time) * 1000
                    self.metrics["api_calls_successful"] += 1
                    return result
                    
                except (ClientError, BotoCoreError, EndpointConnectionError) as e:
                    # AWS Exception Interception & Context Extraction
                    error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', 'Unknown')
                    if error_code == 'Unknown' and 'InternalFailure' in str(e):
                        error_code = 'InternalFailure'
                    
                    # 1. Fast-Fail Protocol: Do not retry physical authorization failures
                    fatal_flags = ['AccessDenied', 'UnauthorizedOperation', 'InvalidClientTokenId', 'AuthFailure', 'OptInRequired']
                    if error_code in fatal_flags or any(f.lower() in str(e).lower() for f in fatal_flags):
                        self.metrics["fast_fails_executed"] += 1
                        self.logger.error(f"Deterministic Authorization Fault ({error_code}). Fast-Failing bypass triggered: {e}")
                        raise e
                        
                    await self._handle_retry_logic(retries, error_code, getattr(func, '__name__', 'api_call'))
                    retries += 1
                    
                except (HttpResponseError, ResourceNotFoundError) as e:
                    # Azure Exception Interception
                    error_code = getattr(e, 'error', {}).get('code', 'Unknown') if hasattr(e, 'error') else 'HttpError'
                    
                    if hasattr(e, 'status_code') and e.status_code in [401, 403]:
                        self.metrics["fast_fails_executed"] += 1
                        self.logger.error(f"Azure Authorization Failure ({error_code}). Fast-Failing bypass triggered.")
                        raise e
                        
                    await self._handle_retry_logic(retries, error_code, getattr(func, '__name__', 'api_call'))
                    retries += 1
                    
                except Exception as e:
                    # Catastrophic unhandled exception (e.g. memory allocation, physical network drop)
                    self.logger.error(f"Unhandled catastrophic exception in execution matrix: {e}")
                    self.logger.debug(traceback.format_exc())
                    raise

    async def _handle_retry_logic(self, current_retry: int, error_code: str, func_name: str) -> None:
        """
        Internal backoff calculator using exponential decay + randomized jitter.
        Applies a 'Deep Backoff' penalty if emulator CPU saturation is detected.
        """
        self.metrics["circuit_breaker_triggers"] += 1
        
        if current_retry >= self.max_retries:
            self.logger.error(f"Maximum backoff reached ({self.max_retries}). Target rejected connection. Code: {error_code}")
            raise Exception(f"Max retries exceeded for {func_name}. Final Code: {error_code}")
            
        # [ DEEP BACKOFF PROTOCOL ]
        # If LocalStack throws an HTTP 500/502 InternalFailure, its CPU is saturated.
        # We multiply the backoff exponent and force a massive jitter to let it breathe.
        if error_code in ['InternalFailure', 'ServiceUnavailable', 'BadGateway'] and self.mode == "MOCK":
            exp_delay = (self.base_delay ** current_retry) * 1.5
            jitter = random.uniform(1.0, 4.0)
            if current_retry == 0:
                self.logger.warning(f"Emulator CPU Saturation Detected ({error_code}). Engaging Deep Backoff...")
        else:
            exp_delay = (self.base_delay ** current_retry)
            jitter = random.uniform(0.1, 1.0)
            
        # Cap the exponential curve to prevent infinite blocking
        sleep_time = min(self.cap_delay, exp_delay) + jitter
        
        self.logger.warning(f"Transient fault on {func_name}. Retrying in {sleep_time:.2f}s (Attempt {current_retry + 1}/{self.max_retries})")
        await asyncio.sleep(sleep_time)

    # ==========================================================================
    # UNIVERSAL RESOURCE MODEL (URM) & STATE HASHING
    # ==========================================================================

    def _sanitize_for_hashing(self, payload: Any) -> Any:
        """
        The "Dirty Read" Cache Cure.
        Recursively traverses the extraction payload and strips out volatile API 
        networking keys to guarantee mathematically pure State Hashes.
        """
        volatile_keys = {
            'ResponseMetadata', 'RequestId', 'HTTPHeaders', 'RetryAttempts',
            'HostId', 'Owner', 'Date', 'date', 'LastModified', 'last_modified',
            'client_request_id', 'request_id', 'x-ms-request-id', 
            'x-ms-client-request-id', 'ETag', 'etag', 'version', 'last_seen', 'Metrics'
        }

        if isinstance(payload, dict):
            return {k: self._sanitize_for_hashing(v) for k, v in payload.items() if k not in volatile_keys}
        elif isinstance(payload, list):
            return [self._sanitize_for_hashing(item) for item in payload]
        else:
            return payload

    async def check_state_differential(self, arn: str, current_state: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Calculates a mathematically pure SHA-256 hash of the sanitized resource payload.
        Returns a tuple: (Has_Changed, SHA256_Hash)
        """
        self.metrics["state_hashes_calculated"] += 1
        try:
            clean_state = self._sanitize_for_hashing(current_state)
            state_string = json.dumps(clean_state, sort_keys=True, default=str)
            state_hash = hashlib.sha256(state_string.encode('utf-8')).hexdigest()
            
            # Note: In a live enterprise environment, this would hit the Redis cache 
            # to verify if the hash exists. For the Titan Pipeline, we default to 
            # True to ensure the graph is fully populated on every run.
            return True, state_hash
            
        except Exception as e:
            self.logger.debug(f"State differential calculation failed for {arn}, defaulting to physical overwrite. {e}")
            fallback_hash = hashlib.sha256(str(random.random()).encode('utf-8')).hexdigest()
            return True, fallback_hash

    def format_urm_payload(self, service: str, resource_type: str, arn: str, raw_data: Dict[str, Any], baseline_risk: float) -> Dict[str, Any]:
        """
        The URM Standardization Contract.
        Ensures that output from AWS, Azure, and Synthetic engines are absolutely 
        structurally identical before arriving at the HybridBridge or Ingestor.
        """
        self.metrics["nodes_formatted"] += 1
        
        # Intelligent Name Extraction Fallback Matrix
        resource_name = "Unknown_Resource"
        name_keys = ["Name", "InstanceId", "RoleName", "GroupId", "DBInstanceIdentifier", "BucketName", "name", "id"]
        
        for name_key in name_keys:
            if name_key in raw_data and raw_data[name_key]:
                resource_name = str(raw_data[name_key])
                break
                
        # If all explicit name keys fail, extract the terminal string from the ARN
        if resource_name == "Unknown_Resource" and arn:
            resource_name = arn.split(":")[-1].split("/")[-1]
                
        # Resolve Cloud Provider dynamically based on service signatures
        aws_services = ["ec2", "iam", "s3", "rds", "lambda", "dynamodb", "ecs", "eks"]
        cloud_prov = "aws" if service.lower() in aws_services else "azure"
        
        return {
            "tenant_id": self.tenant.id,
            "cloud_provider": cloud_prov,
            "service": service.lower(),
            "type": resource_type.lower(),
            "arn": arn,
            "name": resource_name,
            "tags": self._extract_tags(raw_data),
            "risk_score": float(baseline_risk),
            "_state_hash": raw_data.get("_state_hash", "UNKNOWN_STATE"),
            "metadata": {
                **raw_data,
                "arn": arn,
                "resource_type": resource_type.lower(),
                "baseline_risk_score": float(baseline_risk),
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "is_simulated": False
            }
        }
        
    def _extract_tags(self, raw_data: Dict) -> Dict[str, str]:
        """
        Universal Tag Normalizer.
        Squashes differing vendor tag formats (AWS Arrays vs Azure Dicts vs Legacy Sets) 
        into a standardized flat dictionary for O(1) querying downstream.
        """
        tags_map = {}
        
        # Format 1: AWS Standard Array -> [{"Key": "Env", "Value": "Prod"}]
        if "Tags" in raw_data and isinstance(raw_data["Tags"], list):
            for t in raw_data["Tags"]:
                key = t.get("Key")
                if key:
                    tags_map[str(key)] = str(t.get("Value", ""))
                    
        # Format 2: Azure/Modern Dict -> {"Env": "Prod"}
        elif "tags" in raw_data and isinstance(raw_data["tags"], dict):
            for k, v in raw_data["tags"].items():
                tags_map[str(k)] = str(v)
                
        # Format 3: AWS Legacy (TagSet) -> {"TagSet": [{"Key": "Env", "Value": "Prod"}]}
        elif "TagSet" in raw_data and isinstance(raw_data["TagSet"], list):
            for t in raw_data["TagSet"]:
                key = t.get("Key")
                if key:
                    tags_map[str(key)] = str(t.get("Value", ""))
                    
        # Format 4: Stringified JSON (Edge case in some mock infrastructures)
        elif "tags" in raw_data and isinstance(raw_data["tags"], str):
            try:
                parsed_tags = json.loads(raw_data["tags"])
                if isinstance(parsed_tags, dict):
                    for k, v in parsed_tags.items():
                        tags_map[str(k)] = str(v)
            except json.JSONDecodeError:
                pass
                
        return tags_map

    def get_execution_metrics(self) -> Dict[str, Any]:
        """Exposes internal forensic telemetry to the Orchestrator."""
        return self.metrics

    # ==========================================================================
    # ABSTRACT CONTRACTS (CHILD OBLIGATIONS)
    # ==========================================================================

    @abc.abstractmethod
    async def test_connection(self) -> bool:
        """Verifies STS/Azure AD handshake before commencing heavy extraction."""
        raise NotImplementedError("Child discovery engines must implement test_connection().")

    @abc.abstractmethod
    async def discover(self) -> List[Dict[str, Any]]:
        """The Master Extraction Loop. Must yield a list of URM-compliant nodes."""
        raise NotImplementedError("Child discovery engines must implement discover().")