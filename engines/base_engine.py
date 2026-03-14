import asyncio
import logging
import time
import hashlib
import json
import uuid
import traceback
import functools
import random
import platform
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from concurrent.futures import ThreadPoolExecutor

from core.config import config

# ==============================================================================
# CLOUDSCAPE NEXUS 5.2 TITAN - BASE DISCOVERY ENGINE (SUPREME EDITION)
# ==============================================================================
# The abstract foundation for all Cloud Extraction Sensors. Implements:
#
# 1. ADAPTIVE EXPONENTIAL BACKOFF: Intelligent retry with jitter, fast-fail 
#    detection, and emulator CPU saturation awareness.
# 2. UNIVERSAL RESOURCE MODEL (URM): Strict schema enforcement for normalized 
#    data across AWS, Azure, GCP, and synthetic topologies.
# 3. STATE DIFFERENTIAL ENGINE: SHA-256 fingerprinting for change detection 
#    across consecutive scan cycles.
# 4. ENGINE TELEMETRY: High-fidelity metrics collection for forensic reporting.
# 5. CONCURRENCY GOVERNOR: Semaphore-based rate limiting and circuit breaker 
#    patterns to protect cloud API endpoints.
# 6. THREAD POOL MANAGER: Managed executor for offloading blocking SDK calls 
#    without starving the asyncio event loop.
# ==============================================================================


# ------------------------------------------------------------------------------
# ENUMS & DATACLASSES
# ------------------------------------------------------------------------------

class EngineMode(Enum):
    """Operational mode for discovery engines."""
    MOCK = "MOCK"
    LIVE = "LIVE"
    HYBRID = "HYBRID"
    DRY_RUN = "DRY_RUN"


class RetryOutcome(Enum):
    """Outcome of a retry attempt."""
    SUCCESS = "SUCCESS"
    RETRIED = "RETRIED"
    EXHAUSTED = "EXHAUSTED"
    FAST_FAILED = "FAST_FAILED"
    CIRCUIT_OPEN = "CIRCUIT_OPEN"


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "CLOSED"        # Normal operation
    OPEN = "OPEN"            # Failures exceeded threshold, rejecting calls
    HALF_OPEN = "HALF_OPEN"  # Testing if service recovered


@dataclass
class EngineMetrics:
    """High-fidelity telemetry for engine performance tracking."""
    api_calls_total: int = 0
    api_calls_succeeded: int = 0
    api_calls_failed: int = 0
    api_calls_retried: int = 0
    api_calls_fast_failed: int = 0
    nodes_extracted: int = 0
    state_changes_detected: int = 0
    state_unchanged_count: int = 0
    total_extraction_time_ms: float = 0.0
    last_extraction_timestamp: Optional[str] = None
    regions_scanned: int = 0
    services_scanned: int = 0
    services_failed: int = 0
    circuit_breaker_trips: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Serializes metrics for forensic reporting."""
        return {
            "api_calls": {
                "total": self.api_calls_total,
                "succeeded": self.api_calls_succeeded,
                "failed": self.api_calls_failed,
                "retried": self.api_calls_retried,
                "fast_failed": self.api_calls_fast_failed
            },
            "extraction": {
                "nodes_extracted": self.nodes_extracted,
                "state_changes": self.state_changes_detected,
                "state_unchanged": self.state_unchanged_count,
                "total_time_ms": round(self.total_extraction_time_ms, 2),
                "last_timestamp": self.last_extraction_timestamp
            },
            "coverage": {
                "regions_scanned": self.regions_scanned,
                "services_scanned": self.services_scanned,
                "services_failed": self.services_failed
            },
            "resilience": {
                "circuit_breaker_trips": self.circuit_breaker_trips
            }
        }

    def reset(self) -> None:
        """Resets all metrics for a new scan cycle."""
        self.api_calls_total = 0
        self.api_calls_succeeded = 0
        self.api_calls_failed = 0
        self.api_calls_retried = 0
        self.api_calls_fast_failed = 0
        self.nodes_extracted = 0
        self.state_changes_detected = 0
        self.state_unchanged_count = 0
        self.total_extraction_time_ms = 0.0
        self.regions_scanned = 0
        self.services_scanned = 0
        self.services_failed = 0
        # Don't reset circuit_breaker_trips — that's cumulative


@dataclass
class CircuitBreaker:
    """
    Circuit breaker for protecting cloud API endpoints from cascading failures.
    
    When failure_count exceeds failure_threshold, the circuit opens and rejects
    all calls for recovery_timeout_sec seconds. After the timeout, a single 
    probe call is allowed (half-open state). If it succeeds, circuit closes.
    """
    failure_threshold: int = 5
    recovery_timeout_sec: float = 60.0
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    last_failure_time: float = 0.0
    consecutive_successes: int = 0
    success_threshold: int = 2  # Successes needed in half-open to close circuit
    
    def record_success(self) -> None:
        """Records a successful call and potentially closes the circuit."""
        if self.state == CircuitState.HALF_OPEN:
            self.consecutive_successes += 1
            if self.consecutive_successes >= self.success_threshold:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.consecutive_successes = 0
        elif self.state == CircuitState.CLOSED:
            self.failure_count = max(0, self.failure_count - 1)  # Slow decay
    
    def record_failure(self) -> None:
        """Records a failed call and potentially opens the circuit."""
        self.failure_count += 1
        self.last_failure_time = time.monotonic()
        self.consecutive_successes = 0
        
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
    
    def can_execute(self) -> bool:
        """Checks if a call is allowed under the current circuit state."""
        if self.state == CircuitState.CLOSED:
            return True
        elif self.state == CircuitState.OPEN:
            # Check if recovery timeout has elapsed
            if time.monotonic() - self.last_failure_time >= self.recovery_timeout_sec:
                self.state = CircuitState.HALF_OPEN
                self.consecutive_successes = 0
                return True
            return False
        elif self.state == CircuitState.HALF_OPEN:
            return True
        return False

    def reset(self) -> None:
        """Resets the circuit breaker to closed state."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.consecutive_successes = 0


# ------------------------------------------------------------------------------
# FAST-FAIL ERROR CLASSIFICATION
# ------------------------------------------------------------------------------

# Errors that should NOT be retried — they indicate permanent failures
FAST_FAIL_ERRORS = frozenset({
    "AuthorizationError",
    "UnauthorizedOperation",
    "AccessDenied",
    "AccessDeniedException",
    "InvalidParameterException",
    "InvalidParameterValue",
    "MalformedPolicyDocument",
    "InvalidClientTokenId",
    "SignatureDoesNotMatch",
    "SubscriptionNotFound",
    "AuthenticationFailed",
    "InvalidAuthenticationToken",
    "AuthorizationFailed",
    "ResourceNotFound",
    "NoSuchEntity",
    "NoSuchBucket",
    "InvalidAction",
    "UnsupportedOperation",
    "OperationNotPermittedException",
    "ValidationException",
    "ValidationError",
})

# Errors that indicate transient issues and SHOULD be retried
TRANSIENT_ERRORS = frozenset({
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "BandwidthLimitExceeded",
    "ServiceUnavailable",
    "InternalFailure",
    "InternalServerError",
    "InternalError",
    "RequestTimeout",
    "RequestTimeoutException",
    "ProvisionedThroughputExceededException",
    "SlowDown",
    "ConnectionError",
    "EndpointConnectionError",
    "ConnectTimeoutError",
    "ReadTimeoutError",
    "TooManyRequests",
    "ServerBusy",
    "ResourceInUseException",
})


# ------------------------------------------------------------------------------
# THE SUPREME BASE DISCOVERY ENGINE
# ------------------------------------------------------------------------------

class BaseDiscoveryEngine(ABC):
    """
    The abstract base class for all Cloudscape Cloud Discovery Engines.
    
    Provides:
    - Adaptive exponential backoff with jitter
    - Circuit breaker pattern for cascading failure prevention
    - URM (Universal Resource Model) normalization
    - State differential hashing
    - Concurrency governance via semaphore
    - Thread pool management for blocking SDK calls
    - Comprehensive engine telemetry
    """
    
    def __init__(self, tenant):
        # Core Identity
        self.tenant = tenant
        self.engine_id = f"{self.__class__.__name__}-{tenant.id}-{uuid.uuid4().hex[:6]}"
        self.logger = logging.getLogger(f"Cloudscape.Engine.{self.__class__.__name__}.[{tenant.id}]")
        
        # Mode Resolution
        self.mode = self._resolve_engine_mode()
        
        # Retry & Resilience Configuration
        self.max_retries = getattr(config.settings.crawling, 'api_retry_max_attempts', 5)
        self.backoff_factor = getattr(config.settings.crawling, 'api_retry_backoff_factor', 2.0)
        self.base_timeout = getattr(config.settings.crawling, 'timeout_seconds', 30)
        
        # Concurrency Governance
        self._semaphore = asyncio.Semaphore(
            getattr(config.settings.crawling, 'concurrency', 10)
        )
        
        # Thread Pool for blocking SDK calls
        max_workers = getattr(config.settings.crawling, 'max_worker_threads', 5)
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix=f"engine-{tenant.id[:8]}"
        )
        
        # Circuit Breaker
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=max(3, self.max_retries),
            recovery_timeout_sec=60.0
        )
        
        # Telemetry
        self.metrics = EngineMetrics()
        
        # State Differential Cache (in-memory for this process lifecycle)
        self._state_cache: Dict[str, str] = {}
        
        self.logger.debug(
            f"Engine initialized: mode={self.mode.value}, "
            f"max_retries={self.max_retries}, "
            f"backoff={self.backoff_factor}, "
            f"concurrency={self._semaphore._value}"
        )

    def _resolve_engine_mode(self) -> EngineMode:
        """Resolves the execution mode from configuration with safe fallback."""
        try:
            mode_str = config.settings.execution_mode.upper().strip()
            return EngineMode(mode_str)
        except (ValueError, AttributeError):
            self.logger = logging.getLogger(f"Cloudscape.Engine.{self.__class__.__name__}")
            self.logger.warning("Could not resolve execution mode, defaulting to MOCK.")
            return EngineMode.MOCK

    # --------------------------------------------------------------------------
    # AWS CLIENT FACTORY
    # --------------------------------------------------------------------------
    
    def get_aws_client_kwargs(self) -> Dict[str, Any]:
        """
        Resolves AWS client connection parameters based on execution mode.
        MOCK mode routes through LocalStack, LIVE uses real AWS credentials.
        """
        if self.mode == EngineMode.MOCK:
            return {
                "aws_access_key_id": "testing",
                "aws_secret_access_key": "testing",
                "endpoint_url": config.settings.aws.localstack_endpoint,
            }
        elif self.mode == EngineMode.LIVE:
            creds = self.tenant.credentials
            kwargs = {
                "aws_access_key_id": creds.aws_access_key_id,
                "aws_secret_access_key": creds.aws_secret_access_key,
            }
            # Support STS AssumeRole for cross-account federation
            if creds.aws_assume_role_arn:
                kwargs["role_arn"] = creds.aws_assume_role_arn
            return kwargs
        else:
            # HYBRID or DRY_RUN: use mock credentials
            return {
                "aws_access_key_id": "testing",
                "aws_secret_access_key": "testing",
                "endpoint_url": config.settings.aws.localstack_endpoint,
            }

    def get_azure_credentials(self) -> Dict[str, str]:
        """
        Resolves Azure credential parameters based on execution mode.
        MOCK mode uses dummy credentials, LIVE uses real Azure identity.
        """
        creds = self.tenant.credentials
        if self.mode == EngineMode.MOCK:
            return {
                "tenant_id": creds.azure_tenant_id,
                "client_id": creds.azure_client_id,
                "client_secret": creds.azure_client_secret,
                "subscription_id": creds.azure_subscription_id,
            }
        else:
            return {
                "tenant_id": creds.azure_tenant_id,
                "client_id": creds.azure_client_id,
                "client_secret": creds.azure_client_secret,
                "subscription_id": creds.azure_subscription_id,
            }

    # --------------------------------------------------------------------------
    # ADAPTIVE EXPONENTIAL BACKOFF WITH CIRCUIT BREAKER
    # --------------------------------------------------------------------------
    
    async def execute_with_backoff(
        self, 
        func: Callable, 
        *args, 
        operation_name: str = "",
        fast_fail_on: Optional[Set[str]] = None,
        **kwargs
    ) -> Any:
        """
        Executes a blocking function with adaptive exponential backoff, jitter,
        circuit breaker protection, and intelligent error classification.
        
        The function is offloaded to a thread pool to prevent blocking the 
        asyncio event loop, which is critical for Boto3/Azure SDK calls.
        
        Args:
            func: The callable to execute (typically a blocking SDK call)
            *args: Positional arguments for the callable
            operation_name: Human-readable name for logging
            fast_fail_on: Additional error codes to fast-fail on
            **kwargs: Keyword arguments for the callable
            
        Returns:
            The result of the callable
            
        Raises:
            RuntimeError: If the circuit breaker is open
            Exception: The original exception after all retries are exhausted
        """
        op_name = operation_name or getattr(func, '__name__', 'unknown_operation')
        combined_fast_fail = FAST_FAIL_ERRORS | (fast_fail_on or set())
        
        # Circuit Breaker Gate
        if not self._circuit_breaker.can_execute():
            self.metrics.api_calls_fast_failed += 1
            self.logger.warning(
                f"[CIRCUIT OPEN] Rejecting call to '{op_name}'. "
                f"Will recover in {self._circuit_breaker.recovery_timeout_sec}s."
            )
            raise RuntimeError(
                f"Circuit breaker OPEN for engine {self.engine_id}. "
                f"Too many consecutive failures ({self._circuit_breaker.failure_count})."
            )
        
        last_exception: Optional[Exception] = None
        
        for attempt in range(1, self.max_retries + 1):
            self.metrics.api_calls_total += 1
            
            try:
                # Acquire the concurrency semaphore
                async with self._semaphore:
                    # Offload blocking function to thread pool
                    result = await asyncio.get_event_loop().run_in_executor(
                        self._executor, functools.partial(func, *args, **kwargs)
                    )
                
                # Success path
                self.metrics.api_calls_succeeded += 1
                self._circuit_breaker.record_success()
                return result
                
            except Exception as e:
                last_exception = e
                error_code = self._extract_error_code(e)
                error_message = str(e)
                
                # MESSAGE-LEVEL FAST-FAIL: Detect permanent failures hidden
                # behind transient error codes (e.g., LocalStack license gates
                # return InternalFailure but the message reveals it's permanent)
                message_fast_fail_patterns = (
                    "not included within your LocalStack license",
                    "not included in your license",
                    "available in an upgraded license",
                    "upgrade your subscription",
                    "not supported in this region",
                    "service is not available",
                )
                is_message_fast_fail = any(
                    pattern in error_message for pattern in message_fast_fail_patterns
                )
                
                # FAST-FAIL: Non-retryable errors (by code OR by message)
                if error_code in combined_fast_fail or is_message_fast_fail:
                    self.metrics.api_calls_failed += 1
                    self.metrics.api_calls_fast_failed += 1
                    self._circuit_breaker.record_failure()
                    self.logger.warning(
                        f"[FAST-FAIL] '{op_name}' rejected with non-retryable error: "
                        f"{error_code} — {error_message[:150]}"
                    )
                    raise  # Propagate immediately, no retry
                
                # TRANSIENT: Retryable errors
                if attempt < self.max_retries:
                    self.metrics.api_calls_retried += 1
                    
                    # Calculate backoff with decorrelated jitter (AWS best practice)
                    base_delay = self.backoff_factor ** attempt
                    jitter = random.uniform(0, base_delay * 0.5)
                    delay = min(base_delay + jitter, 120.0)  # Cap at 2 minutes
                    
                    # Check for explicit Retry-After header (Azure 429s)
                    retry_after = self._extract_retry_after(e)
                    if retry_after:
                        delay = max(delay, retry_after)
                    
                    # Emulator saturation detection (MOCK mode)
                    if self.mode == EngineMode.MOCK and attempt > 2:
                        delay += random.uniform(2.0, 5.0)  # Extra cooling for Docker
                    
                    self.logger.warning(
                        f"[RETRY {attempt}/{self.max_retries}] '{op_name}' failed with {error_code}. "
                        f"Backoff: {delay:.1f}s. Error: {error_message[:100]}"
                    )
                    await asyncio.sleep(delay)
                else:
                    # All retries exhausted
                    self.metrics.api_calls_failed += 1
                    self._circuit_breaker.record_failure()
                    
                    if self._circuit_breaker.state == CircuitState.OPEN:
                        self.metrics.circuit_breaker_trips += 1
                        self.logger.critical(
                            f"[CIRCUIT BREAKER TRIPPED] Engine {self.engine_id}: "
                            f"'{op_name}' failed {self._circuit_breaker.failure_count} times. "
                            f"Circuit OPEN for {self._circuit_breaker.recovery_timeout_sec}s."
                        )
                    
                    self.logger.error(
                        f"[EXHAUSTED] '{op_name}' failed after {self.max_retries} attempts. "
                        f"Final error: {error_code} — {error_message}"
                    )
                    raise  # Propagate the last exception

        # Safety net (should never reach here due to raise above, but explicit is better)
        if last_exception:
            raise last_exception
        raise RuntimeError(f"execute_with_backoff for '{op_name}' exited without result or exception.")

    def _extract_error_code(self, error: Exception) -> str:
        """
        Extracts the canonical error code from various cloud SDK exception types.
        Supports Boto3 ClientError, Azure HttpResponseError, and generic exceptions.
        """
        # Boto3 ClientError
        if hasattr(error, 'response'):
            try:
                return error.response.get('Error', {}).get('Code', type(error).__name__)
            except (AttributeError, TypeError):
                pass
        
        # Azure HttpResponseError
        if hasattr(error, 'error_code'):
            return error.error_code or type(error).__name__
        
        # Azure specific status code
        if hasattr(error, 'status_code'):
            status = getattr(error, 'status_code', 0)
            if status == 429:
                return "TooManyRequests"
            elif status >= 500:
                return "InternalServerError"
        
        # Boto3 specific exception names
        error_type = type(error).__name__
        if error_type in ('EndpointConnectionError', 'ConnectTimeoutError', 'ReadTimeoutError'):
            return error_type
        
        return error_type

    def _extract_retry_after(self, error: Exception) -> Optional[float]:
        """
        Extracts the Retry-After header value from Azure 429 responses.
        Returns the wait time in seconds, or None if not present.
        """
        # Azure HttpResponseError
        if hasattr(error, 'response') and hasattr(error.response, 'headers'):
            try:
                retry_after = error.response.headers.get('Retry-After')
                if retry_after:
                    return float(retry_after)
            except (AttributeError, ValueError, TypeError):
                pass
        return None

    # --------------------------------------------------------------------------
    # URM (UNIVERSAL RESOURCE MODEL) NORMALIZATION
    # --------------------------------------------------------------------------
    
    def format_urm_payload(
        self,
        service: str,
        resource_type: str,
        arn: str,
        raw_data: Dict[str, Any],
        baseline_risk: float = 0.5,
        extra_metadata: Optional[Dict[str, Any]] = None,
        extra_tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Transforms raw cloud API responses into the strict Cloudscape
        Universal Resource Model (URM) schema.
        
        Ensures all nodes have:
        - Deterministic fingerprint (for state differential)
        - Normalized tenant and provider identifiers
        - Sanitized metadata (no None values, no circular refs)
        - Risk score baseline for the intelligence engine
        
        Args:
            service: Cloud service identifier (e.g., "ec2", "compute")
            resource_type: Resource type (e.g., "Instance", "VirtualMachine")
            arn: Amazon Resource Name or Azure Resource Manager ID
            raw_data: Raw API response dictionary
            baseline_risk: Base risk score (0.0 to 10.0)
            extra_metadata: Additional metadata to merge
            extra_tags: Additional tags to apply
            
        Returns:
            URM-compliant dictionary
        """
        # Sanitize the raw data — remove None values and circular references
        sanitized_data = self._deep_sanitize(raw_data)
        
        # Calculate deterministic state hash for this resource
        state_hash = self._compute_state_hash(arn, sanitized_data)
        
        # Extract human-readable name
        name = self._extract_resource_name(sanitized_data, resource_type, arn)
        
        # Build the tag matrix
        tags = {
            "Environment": config.settings.execution_mode,
            "ManagedBy": "Cloudscape-Discovery",
            "Tenant": self.tenant.id,
        }
        if extra_tags:
            tags.update(extra_tags)
        
        # Inject resource-specific tags from raw data
        raw_tags = sanitized_data.get("Tags", sanitized_data.get("tags", []))
        if isinstance(raw_tags, list):
            for tag in raw_tags:
                if isinstance(tag, dict):
                    key = tag.get("Key", tag.get("key", ""))
                    value = tag.get("Value", tag.get("value", ""))
                    if key:
                        tags[str(key)] = str(value)
        elif isinstance(raw_tags, dict):
            tags.update({str(k): str(v) for k, v in raw_tags.items()})
        
        # Build the URM node
        urm_node = {
            "tenant_id": self.tenant.id,
            "cloud_provider": service.upper() if service.upper() in ("AWS", "AZURE", "GCP") else "AWS",
            "service": service.lower(),
            "type": resource_type.lower(),
            "arn": arn,
            "name": name,
            "tags": tags,
            "metadata": {
                "arn": arn,
                "resource_type": resource_type.lower(),
                "baseline_risk_score": round(max(0.0, min(10.0, baseline_risk)), 2),
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "is_simulated": (self.mode == EngineMode.MOCK),
                "_state_hash": state_hash,
                "_engine_id": self.engine_id,
                **(extra_metadata or {})
            },
            "properties": sanitized_data,
            "risk_score": round(max(0.0, min(10.0, baseline_risk)), 2),
            "_state_hash": state_hash,
        }
        
        self.metrics.nodes_extracted += 1
        return urm_node

    def _extract_resource_name(self, data: Dict[str, Any], resource_type: str, arn: str) -> str:
        """
        Extracts a human-readable name from the raw data using a priority cascade.
        Falls back to the ARN basename if no name field is found.
        """
        # Priority order for name resolution
        name_keys = [
            "Name", "name", "DBInstanceIdentifier", "InstanceId",
            "BucketName", "RoleName", "GroupName", "UserName",
            "FunctionName", "ClusterName", "KeyId", "SecretName",
            "HostedZoneId", "DomainName", "TableName", "VpcId",
            "SubnetId", "SecurityGroupId", "Id", "id",
        ]
        
        for key in name_keys:
            value = data.get(key)
            if value and isinstance(value, str):
                return value
        
        # Fallback: extract basename from ARN
        if arn:
            parts = arn.split("/")
            if len(parts) > 1:
                return parts[-1]
            parts = arn.split(":")
            if len(parts) > 1:
                return parts[-1]
        
        return f"{resource_type}-{uuid.uuid4().hex[:8]}"

    # --------------------------------------------------------------------------
    # STATE DIFFERENTIAL ENGINE
    # --------------------------------------------------------------------------
    
    def _compute_state_hash(self, arn: str, data: Dict[str, Any]) -> str:
        """
        Computes a deterministic SHA-256 fingerprint of a resource's current state.
        Used for detecting changes between consecutive scan cycles.
        """
        try:
            # Create a canonical JSON representation (sorted keys, no whitespace)
            canonical = json.dumps(data, sort_keys=True, default=str, separators=(',', ':'))
            hash_input = f"{arn}:{canonical}"
            return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
        except (TypeError, ValueError) as e:
            self.logger.debug(f"State hash computation failed for {arn}: {e}")
            return hashlib.sha256(arn.encode('utf-8')).hexdigest()

    def check_state_differential(self, arn: str, current_hash: str) -> bool:
        """
        Checks if a resource has changed since the last scan cycle.
        
        Returns True if the resource is new or has changed, False if unchanged.
        Updates the internal cache with the new hash.
        """
        is_state_diff_enabled = getattr(
            config.settings.orchestrator, 'enable_state_differential', True
        )
        
        if not is_state_diff_enabled:
            return True  # Always treat as changed when differential is disabled
        
        previous_hash = self._state_cache.get(arn)
        self._state_cache[arn] = current_hash
        
        if previous_hash is None:
            # New resource — first time seen
            self.metrics.state_changes_detected += 1
            return True
        elif previous_hash != current_hash:
            # Resource has changed
            self.metrics.state_changes_detected += 1
            return True
        else:
            # Resource unchanged
            self.metrics.state_unchanged_count += 1
            return False

    # --------------------------------------------------------------------------
    # DATA SANITIZATION UTILITIES
    # --------------------------------------------------------------------------
    
    def _deep_sanitize(self, data: Any, depth: int = 0, max_depth: int = 20) -> Any:
        """
        Recursively sanitizes API response data for safe storage.
        
        Handles:
        - None values (replaced with empty strings or appropriate defaults)
        - datetime objects (converted to ISO format strings)
        - bytes objects (converted to hex strings)
        - Circular references (depth-limited)
        - Non-serializable objects (converted to string representation)
        """
        if depth > max_depth:
            return "<DEPTH_LIMIT_EXCEEDED>"
        
        if data is None:
            return ""
        elif isinstance(data, (str, int, float, bool)):
            return data
        elif isinstance(data, bytes):
            try:
                return data.decode('utf-8', errors='replace')
            except Exception:
                return data.hex()
        elif isinstance(data, datetime):
            return data.isoformat()
        elif isinstance(data, dict):
            return {
                str(k): self._deep_sanitize(v, depth + 1, max_depth) 
                for k, v in data.items()
            }
        elif isinstance(data, (list, tuple, set)):
            return [self._deep_sanitize(item, depth + 1, max_depth) for item in data]
        elif hasattr(data, '__dict__'):
            # Handle SDK model objects (Azure, Boto3)
            try:
                return self._deep_sanitize(vars(data), depth + 1, max_depth)
            except Exception:
                return str(data)
        else:
            return str(data)

    def _flatten_tags(self, tags: Any) -> Dict[str, str]:
        """
        Normalizes tags from various cloud provider formats into a flat dictionary.
        
        Handles:
        - AWS format: [{"Key": "k", "Value": "v"}, ...]
        - Azure format: {"k": "v", ...}
        - Null/missing tags
        """
        if not tags:
            return {}
        
        if isinstance(tags, dict):
            return {str(k): str(v) for k, v in tags.items()}
        
        if isinstance(tags, list):
            result = {}
            for tag in tags:
                if isinstance(tag, dict):
                    key = tag.get("Key", tag.get("key", ""))
                    value = tag.get("Value", tag.get("value", ""))
                    if key:
                        result[str(key)] = str(value)
            return result
        
        return {}

    # --------------------------------------------------------------------------
    # THREAD POOL & RESOURCE MANAGEMENT
    # --------------------------------------------------------------------------
    
    def shutdown_executor(self, wait: bool = True, cancel_futures: bool = False) -> None:
        """
        Gracefully terminates the internal thread pool executor.
        Should be called during engine teardown.
        """
        try:
            self._executor.shutdown(wait=wait, cancel_futures=cancel_futures)
            self.logger.debug(f"Thread pool executor shut down for engine {self.engine_id}.")
        except Exception as e:
            self.logger.warning(f"Error during executor shutdown: {e}")

    async def run_in_thread(self, func: Callable, *args, **kwargs) -> Any:
        """
        Convenience wrapper: runs a blocking function in the thread pool.
        Simpler than execute_with_backoff for non-retryable operations.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor, functools.partial(func, *args, **kwargs)
        )

    # --------------------------------------------------------------------------
    # TELEMETRY & DIAGNOSTICS
    # --------------------------------------------------------------------------
    
    def get_metrics(self) -> Dict[str, Any]:
        """Returns the current engine metrics as a serializable dictionary."""
        return {
            "engine_id": self.engine_id,
            "engine_type": self.__class__.__name__,
            "tenant_id": self.tenant.id,
            "mode": self.mode.value,
            "circuit_state": self._circuit_breaker.state.value,
            **self.metrics.to_dict()
        }

    def reset_metrics(self) -> None:
        """Resets engine metrics for a new scan cycle."""
        self.metrics.reset()
        self.logger.debug(f"Metrics reset for engine {self.engine_id}.")

    def get_circuit_state(self) -> str:
        """Returns the current circuit breaker state as a string."""
        return self._circuit_breaker.state.value

    def reset_circuit_breaker(self) -> None:
        """Manually resets the circuit breaker to CLOSED state."""
        self._circuit_breaker.reset()
        self.logger.info(f"Circuit breaker manually reset for engine {self.engine_id}.")

    # --------------------------------------------------------------------------
    # ABSTRACT INTERFACE — CHILD ENGINES MUST IMPLEMENT
    # --------------------------------------------------------------------------
    
    @abstractmethod
    async def test_connection(self) -> bool:
        """
        Validates connectivity to the target cloud partition.
        Returns True if the engine can successfully authenticate and communicate.
        """
        pass

    @abstractmethod
    async def discover(self) -> List[Dict[str, Any]]:
        """
        Executes the full discovery cycle for this engine's cloud provider.
        Returns a list of URM-compliant node dictionaries.
        """
        pass

    # --------------------------------------------------------------------------
    # LIFECYCLE MANAGEMENT
    # --------------------------------------------------------------------------
    
    async def initialize(self) -> bool:
        """
        Full engine initialization lifecycle.
        Tests connection and sets up any required state.
        Returns True if the engine is ready for discovery.
        """
        self.logger.info(f"Initializing engine {self.engine_id} in {self.mode.value} mode...")
        self.metrics.reset()
        
        try:
            is_connected = await self.test_connection()
            if is_connected:
                self.logger.info(f"Engine {self.engine_id} initialized successfully.")
            else:
                self.logger.warning(f"Engine {self.engine_id} connection test failed.")
            return is_connected
        except Exception as e:
            self.logger.error(f"Engine initialization failed: {e}")
            self.logger.debug(traceback.format_exc())
            return False

    async def teardown(self) -> None:
        """
        Graceful engine teardown.
        Shuts down thread pools and releases held resources.
        """
        self.logger.info(f"Tearing down engine {self.engine_id}...")
        self.shutdown_executor(wait=True)
        self.metrics.last_extraction_timestamp = datetime.now(timezone.utc).isoformat()
        self.logger.info(
            f"Engine {self.engine_id} teardown complete. "
            f"Final metrics: {self.metrics.nodes_extracted} nodes, "
            f"{self.metrics.api_calls_total} API calls "
            f"({self.metrics.api_calls_succeeded} OK, "
            f"{self.metrics.api_calls_failed} failed)."
        )

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"engine_id={self.engine_id} "
            f"tenant={self.tenant.id} "
            f"mode={self.mode.value} "
            f"circuit={self._circuit_breaker.state.value}>"
        )