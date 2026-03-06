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
from typing import Any, Callable, Dict, List, Tuple, Optional

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
# Manages execution modes (MOCK vs PROPER), dynamic endpoint routing, resilient 
# jitter-backed network backoffs, concurrency limiting, URM normalization, and 
# recursive differential state hashing for high-performance convergence.
#
# TITAN UPGRADE: Integrates the "Pre-Emptive Stagger" to mathematically 
# desynchronize thread collisions against local Docker emulators.
# ==============================================================================

class BaseDiscoveryEngine(abc.ABC):
    def __init__(self, tenant: TenantConfig):
        """
        Initializes the Core Discovery primitives, setting up logging, metrics,
        and the environment-aware execution mode.
        """
        self.tenant = tenant
        self.logger = logging.getLogger(f"Cloudscape.Engines.Base.[{self.tenant.id}]")
        
        # ----------------------------------------------------------------------
        # MODE ROUTER: Path A (MOCK) vs Path B (PROPER)
        # ----------------------------------------------------------------------
        self.mode = config.settings.execution_mode.upper()
        
        # ----------------------------------------------------------------------
        # RESILIENCE & CONCURRENCY TUNING
        # ----------------------------------------------------------------------
        self.max_retries = getattr(config.settings.crawling, "api_retry_max_attempts", 5)
        self.base_delay = getattr(config.settings.crawling, "api_retry_backoff_factor", 2.0)
        
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
            "state_hashes_calculated": 0,
            "state_hashes_unchanged": 0,
            "nodes_formatted": 0,
            "execution_time_ms": 0.0
        }
        
        self._log_initialization_state()

    def _log_initialization_state(self):
        """Outputs the operational parameters to the forensic log."""
        if self.mode == "MOCK":
            self.logger.info("Engine initialized in MOCK Mode. Traffic routed to Local Sandbox Gateways.")
        else:
            self.logger.info("Engine initialized in PROPER Mode. Traffic routed to Global Cloud APIs.")

    # ==========================================================================
    # DYNAMIC CONNECTION GATEWAYS (THE "HOT SWAP" ROUTERS)
    # ==========================================================================

    def get_aws_client_kwargs(self) -> Dict[str, Any]:
        """
        The Universal AWS Connection Gateway.
        Dynamically steers SDK traffic based on the execution mode.
        """
        kwargs = {}
        if self.mode == "MOCK":
            # Force traffic to the LocalStack Docker mesh
            kwargs["endpoint_url"] = "http://localhost:4566"
            # Prevent Identity Shadowing by forcing the partition testing key
            kwargs["aws_access_key_id"] = "testing"
            kwargs["aws_secret_access_key"] = "testing"
            
        return kwargs

    def get_azure_connection_parameters(self) -> Dict[str, Any]:
        """
        The Universal Azure Connection Gateway.
        Provides connectivity logic for Azurite (MOCK) or ARM/Graph APIs (PROPER).
        """
        if self.mode == "MOCK":
            return {
                "connection_string": (
                    "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
                    "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
                    "BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"
                ),
                "is_mock": True
            }
        else:
            return {
                "is_mock": False
            }

    # ==========================================================================
    # NETWORK RESILIENCE (CIRCUIT BREAKER & STAGGER METRICS)
    # ==========================================================================

    async def execute_with_backoff(self, func: Callable, *args, **kwargs) -> Any:
        """
        Adaptive Jitter Backoff Algorithm wrapped in a Concurrency Semaphore.
        Shields the extraction pipeline from rate limits and LocalStack CPU starvation.
        """
        # [ TITAN PRE-EMPTIVE STAGGER ]
        # In MOCK mode, if 10 engines launch simultaneously, LocalStack is hit with a 
        # 'Thundering Herd' of requests before the semaphores can even meter them.
        # This randomized sleep desynchronizes the execution timelines globally.
        if self.mode == "MOCK":
            stagger_delay = random.uniform(0.1, 2.5)
            await asyncio.sleep(stagger_delay)

        async with self._semaphore:
            self.metrics["api_calls_attempted"] += 1
            retries = 0
            
            while retries <= self.max_retries:
                try:
                    start_time = time.perf_counter()
                    
                    if asyncio.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        result = await asyncio.to_thread(func, *args, **kwargs)
                        
                    self.metrics["execution_time_ms"] += (time.perf_counter() - start_time) * 1000
                    self.metrics["api_calls_successful"] += 1
                    return result
                    
                except (ClientError, BotoCoreError, EndpointConnectionError) as e:
                    # AWS Exception Extraction
                    error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', 'Unknown')
                    if error_code == 'Unknown' and 'InternalFailure' in str(e):
                        error_code = 'InternalFailure'
                    
                    if error_code in ['AccessDenied', 'UnauthorizedOperation', 'InvalidClientTokenId', 'AuthFailure']:
                        self.logger.error(f"Circuit Breaker Triggered: Hard Authorization Failure ({error_code}).")
                        raise
                        
                    await self._handle_retry_logic(retries, error_code, func.__name__)
                    retries += 1
                    
                except (HttpResponseError, ResourceNotFoundError) as e:
                    # Azure Exception Extraction
                    error_code = getattr(e, 'error', {}).get('code', 'Unknown') if hasattr(e, 'error') else 'HttpError'
                    
                    if hasattr(e, 'status_code') and e.status_code in [401, 403]:
                        self.logger.error(f"Circuit Breaker Triggered: Azure Authorization Failure ({error_code}).")
                        raise
                        
                    await self._handle_retry_logic(retries, error_code, func.__name__)
                    retries += 1
                    
                except Exception as e:
                    self.logger.error(f"Unhandled catastrophic exception in execution matrix: {e}")
                    self.logger.debug(traceback.format_exc())
                    raise

    async def _handle_retry_logic(self, current_retry: int, error_code: str, func_name: str):
        """Internal backoff calculator using exponential decay + randomized jitter."""
        self.metrics["circuit_breaker_triggers"] += 1
        if current_retry >= self.max_retries:
            self.logger.error(f"Maximum backoff reached ({self.max_retries}). Function {func_name} failed. Code: {error_code}")
            raise Exception(f"Max retries exceeded for {func_name}")
            
        # [ DEEP BACKOFF PROTOCOL ]
        # If LocalStack throws an HTTP 500 InternalFailure, its CPU is saturated.
        # We multiply the backoff exponent and force a massive jitter.
        if error_code == 'InternalFailure' and self.mode == "MOCK":
            exp_delay = (self.base_delay ** current_retry) * 1.5
            jitter = random.uniform(1.0, 3.5)
            self.logger.warning(f"Emulator CPU Saturation Detected ({error_code}). Engaging Deep Backoff...")
        else:
            exp_delay = (self.base_delay ** current_retry)
            jitter = random.uniform(0.1, 1.0)
            
        sleep_time = exp_delay + jitter
        
        self.logger.warning(f"Transient fault. Retrying {func_name} in {sleep_time:.2f}s (Attempt {current_retry + 1}/{self.max_retries})")
        await asyncio.sleep(sleep_time)

    # ==========================================================================
    # URM STANDARDIZATION & STATE MANAGEMENT
    # ==========================================================================

    def _sanitize_for_hashing(self, payload: Any) -> Any:
        """
        The "Dirty Read" Cache Cure.
        Recursively traverses the extraction payload and strips out volatile API 
        networking injection keys to guarantee perfect State Hashes.
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
        """
        self.metrics["state_hashes_calculated"] += 1
        try:
            clean_state = self._sanitize_for_hashing(current_state)
            state_string = json.dumps(clean_state, sort_keys=True, default=str)
            state_hash = hashlib.sha256(state_string.encode('utf-8')).hexdigest()
            return True, state_hash
        except Exception as e:
            self.logger.debug(f"State differential calculation failed for {arn}, defaulting to physical overwrite. {e}")
            fallback_hash = hashlib.sha256(str(random.random()).encode('utf-8')).hexdigest()
            return True, fallback_hash

    def format_urm_payload(self, service: str, resource_type: str, arn: str, raw_data: Dict[str, Any], baseline_risk: float) -> Dict[str, Any]:
        """
        Transforms raw, vendor-specific JSON into the Universal Resource Model (URM).
        """
        self.metrics["nodes_formatted"] += 1
        
        name = (
            raw_data.get("Name") or 
            raw_data.get("InstanceId") or 
            raw_data.get("RoleName") or 
            raw_data.get("GroupId") or 
            raw_data.get("DBInstanceIdentifier") or 
            raw_data.get("name") or 
            arn.split(":")[-1].split("/")[-1]
        )
        
        normalized_tags = {}
        raw_tags = raw_data.get("Tags") or raw_data.get("tags") or raw_data.get("TagList") or []
        
        if isinstance(raw_tags, list):
            for t in raw_tags:
                if isinstance(t, dict):
                    k = t.get("Key", t.get("key"))
                    v = t.get("Value", t.get("value"))
                    if k is not None:
                        normalized_tags[str(k)] = str(v)
        elif isinstance(raw_tags, dict):
            for k, v in raw_tags.items():
                normalized_tags[str(k)] = str(v)
            
        return {
            "tenant_id": self.tenant.id,
            "cloud_provider": "unknown",
            "service": service.lower(),
            "type": resource_type,
            "arn": arn,
            "name": name,
            "tags": normalized_tags,
            "risk_score": float(baseline_risk),
            "_state_hash": raw_data.get("_state_hash", "UNKNOWN_STATE"),
            "raw_data": {
                **raw_data,
                "arn": arn,
                "resource_type": resource_type,
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "is_simulated": False
            }
        }

    def get_execution_metrics(self) -> Dict[str, Any]:
        return self.metrics

    # ==========================================================================
    # ABSTRACT CONTRACTS (CHILD OBLIGATIONS)
    # ==========================================================================

    @abc.abstractmethod
    async def test_connection(self) -> bool:
        raise NotImplementedError("Child discovery engines must implement test_connection().")

    @abc.abstractmethod
    async def discover(self) -> List[Dict[str, Any]]:
        raise NotImplementedError("Child discovery engines must implement discover().")