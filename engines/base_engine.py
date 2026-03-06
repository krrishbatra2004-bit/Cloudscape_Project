import asyncio
import hashlib
import json
import logging
import os
import time
import traceback
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

from core.config import TenantConfig

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - BASE DISCOVERY ENGINE
# ==============================================================================
# The Enterprise Abstract Gateway.
# Manages execution modes (MOCK vs PROPER), dynamic endpoint routing, resilient 
# network backoffs, concurrency limiting, URM normalization, and differential 
# state hashing for high-performance convergence.
# ==============================================================================

class BaseDiscoveryEngine:
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
        self.mode = os.getenv("NEXUS_EXECUTION_MODE", "MOCK").upper()
        
        # ----------------------------------------------------------------------
        # RESILIENCE & CONCURRENCY TUNING
        # ----------------------------------------------------------------------
        self.max_retries = 4
        self.base_delay = 1.5
        # Prevent socket exhaustion during massive parallel sweeps
        self.max_concurrent_tasks = 50 
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
        self.logger.debug(f"Concurrency capped at {self.max_concurrent_tasks} parallel threads.")

    # ==========================================================================
    # DYNAMIC CONNECTION GATEWAYS (THE "HOT SWAP" ROUTERS)
    # ==========================================================================

    def get_aws_client_kwargs(self) -> Dict[str, Any]:
        """
        The Universal AWS Connection Gateway.
        Dynamically steers SDK traffic based on the execution mode.
        Child classes (AWSEngine) must pass this dictionary to boto3 client initializations.
        """
        kwargs = {}
        if self.mode == "MOCK":
            # Path A: Force traffic to the LocalStack Docker mesh
            kwargs["endpoint_url"] = "http://localhost:4566"
            # CRITICAL FIX: Prevent Identity Shadowing by forcing the testing partition
            kwargs["aws_access_key_id"] = "testing"
            kwargs["aws_secret_access_key"] = "testing"
            
        # Path B (PROPER): Returns empty dict. 
        # boto3 will automatically use standard AWS endpoints and rely on IAM.
        return kwargs

    def get_azure_connection_parameters(self) -> Dict[str, Any]:
        """
        The Universal Azure Connection Gateway.
        Provides connectivity logic for Azurite (MOCK) or ARM/Graph APIs (PROPER).
        """
        if self.mode == "MOCK":
            # Path A: Explicitly target the Azurite container
            return {
                "connection_string": (
                    "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
                    "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
                    "BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"
                ),
                "is_mock": True
            }
        else:
            # Path B (PROPER): Signal engine to use DefaultAzureCredential
            return {
                "is_mock": False
            }

    # ==========================================================================
    # NETWORK RESILIENCE (CIRCUIT BREAKER & SEMAPHORES)
    # ==========================================================================

    async def execute_with_backoff(self, func: Callable, *args, **kwargs) -> Any:
        """
        Adaptive Jitter Backoff Algorithm wrapped in a Concurrency Semaphore.
        Shields the extraction pipeline from rate limits (429s) and transient faults.
        """
        async with self._semaphore:
            self.metrics["api_calls_attempted"] += 1
            retries = 0
            
            while retries <= self.max_retries:
                try:
                    start_time = time.perf_counter()
                    result = await func(*args, **kwargs)
                    self.metrics["execution_time_ms"] += (time.perf_counter() - start_time) * 1000
                    self.metrics["api_calls_successful"] += 1
                    return result
                    
                except (ClientError, BotoCoreError, EndpointConnectionError) as e:
                    # AWS Exception Handling
                    error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', 'Unknown')
                    
                    if error_code in ['AccessDenied', 'UnauthorizedOperation', 'InvalidClientTokenId', 'AuthFailure']:
                        self.logger.error(f"Circuit Breaker Triggered: Hard Authorization Failure ({error_code}).")
                        raise
                        
                    self._handle_retry_logic(retries, error_code, func.__name__)
                    retries += 1
                    
                except (HttpResponseError, ResourceNotFoundError) as e:
                    # Azure Exception Handling
                    error_code = getattr(e, 'error', {}).get('code', 'Unknown') if hasattr(e, 'error') else 'HttpError'
                    
                    if e.status_code in [401, 403]:
                        self.logger.error(f"Circuit Breaker Triggered: Azure Authorization Failure ({error_code}).")
                        raise
                        
                    self._handle_retry_logic(retries, error_code, func.__name__)
                    retries += 1
                    
                except Exception as e:
                    # Catch-all for SDK bugs, payload parsing faults, or memory issues
                    self.logger.error(f"Unhandled catastrophic exception in execution matrix: {e}")
                    self.logger.debug(traceback.format_exc())
                    raise

    async def _handle_retry_logic(self, current_retry: int, error_code: str, func_name: str):
        """Internal backoff calculator using exponential jitter."""
        self.metrics["circuit_breaker_triggers"] += 1
        if current_retry >= self.max_retries:
            self.logger.error(f"Maximum backoff reached ({self.max_retries}). Function {func_name} failed. Code: {error_code}")
            raise Exception(f"Max retries exceeded for {func_name}")
            
        sleep_time = (self.base_delay ** current_retry) * 0.5
        self.logger.warning(f"Transient fault detected ({error_code}). Retrying {func_name} in {sleep_time:.2f}s (Attempt {current_retry + 1}/{self.max_retries})")
        await asyncio.sleep(sleep_time)

    # ==========================================================================
    # URM STANDARDIZATION & STATE MANAGEMENT
    # ==========================================================================

    def format_urm_payload(self, service: str, resource_type: str, arn: str, raw_data: Dict[str, Any], baseline_risk: float) -> Dict[str, Any]:
        """
        Transforms raw, vendor-specific JSON into the Universal Resource Model (URM)
        required by the Cloudscape Hybrid Bridge and Identity Fabric.
        Flattens tags and extracts deeply nested names safely.
        """
        self.metrics["nodes_formatted"] += 1
        
        # Deep Name Extraction Matrix
        name = (
            raw_data.get("Name") or 
            raw_data.get("InstanceId") or 
            raw_data.get("RoleName") or 
            raw_data.get("GroupId") or 
            raw_data.get("DBInstanceIdentifier") or 
            raw_data.get("name") or 
            arn.split(":")[-1].split("/")[-1]
        )
        
        # Tag Normalization (AWS standardizes to 'Tags' list of dicts, Azure to 'tags' dict)
        normalized_tags = {}
        raw_tags = raw_data.get("Tags") or raw_data.get("tags") or []
        if isinstance(raw_tags, list):
            for t in raw_tags:
                if isinstance(t, dict) and "Key" in t and "Value" in t:
                    normalized_tags[t["Key"]] = t["Value"]
        elif isinstance(raw_tags, dict):
            normalized_tags = raw_tags
            
        return {
            "tenant_id": self.tenant.id,
            "cloud_provider": "unknown", # Must be overridden by child class (e.g., 'aws', 'azure')
            "service": service.lower(),
            "type": resource_type,
            "arn": arn,
            "name": name,
            "tags": normalized_tags,
            "metadata": {
                **raw_data,
                "arn": arn,
                "resource_type": resource_type,
                "baseline_risk_score": float(baseline_risk),
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "is_simulated": False
            }
        }

    async def check_state_differential(self, arn: str, current_state: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Advanced performance optimization.
        Calculates a SHA-256 hash of the incoming resource payload. 
        If the hash matches the cache, the engine drops the payload early,
        saving the Neo4j database massive write-I/O during Convergence.
        """
        self.metrics["state_hashes_calculated"] += 1
        try:
            # Strip highly volatile fields before hashing to prevent false positives
            clean_state = {k: v for k, v in current_state.items() if k not in ["last_seen", "ResponseMetadata", "Metrics"]}
            
            # Sort keys to ensure deterministic hashing across different Python processes
            state_string = json.dumps(clean_state, sort_keys=True, default=str)
            state_hash = hashlib.sha256(state_string.encode('utf-8')).hexdigest()
            
            # FUTURE: Integrate Redis check here: 
            # if await redis.get(f"state:{arn}") == state_hash: return False, state_hash
            
            # Currently defaulting to True (force write) until Redis caching is enabled in Path B
            return True, state_hash
            
        except Exception as e:
            self.logger.debug(f"State differential calculation failed for {arn}, defaulting to physical overwrite. {e}")
            return True, "hash_error"

    def get_execution_metrics(self) -> Dict[str, Any]:
        """Exposes internal forensic metrics to the Orchestrator for terminal reporting."""
        return self.metrics

    # ==========================================================================
    # ABSTRACT CONTRACTS (CHILD OBLIGATIONS)
    # ==========================================================================

    async def test_connection(self) -> bool:
        """
        Contract: Child classes must implement identity validation logic.
        Validates STS / ARM connectivity before global sweeps begin.
        """
        raise NotImplementedError("Child discovery engines must implement test_connection().")

    async def discover(self) -> List[Dict[str, Any]]:
        """
        Contract: Child classes must implement resource extraction logic.
        Must return a flat List of URM-compliant payload dictionaries.
        """
        raise NotImplementedError("Child discovery engines must implement discover().")