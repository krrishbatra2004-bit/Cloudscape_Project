import os
import yaml
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any

from pydantic import BaseModel, Field, ValidationError

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - CONFIGURATION MANAGER
# ==============================================================================
# The strict Type-Safe configuration gateway powered by Pydantic V2.
# Maps the YAML state into immutable Python memory structures. Guarantees that
# the system never executes with corrupted, missing, or mismatched parameters.
# ==============================================================================

# ------------------------------------------------------------------------------
# NESTED SYSTEM MODELS
# ------------------------------------------------------------------------------

class AppMetadata(BaseModel):
    name: str
    version: str
    author: Optional[str] = "Aether-Titan"
    description: Optional[str] = ""
    environment: str = "MOCK"

class SystemConfig(BaseModel):
    log_level: str = "INFO"
    ingestion_chunk_size: int = Field(ge=100, le=20000, default=500)
    max_concurrency_per_engine: int = 50
    telemetry_enabled: bool = True

class AWSConfig(BaseModel):
    target_regions: List[str] = ["us-east-1"]

class AzureConfig(BaseModel):
    target_subscription: str = "mock-azure-sub-0001"

class DatabaseIngestion(BaseModel):
    batch_size: int = Field(ge=100, le=20000, default=1000)
    retries: int = 5
    backoff_factor: float = 1.5

class DatabaseConfig(BaseModel):
    uri: str
    user: str
    password: str
    redis_uri: str
    connection_pool_size: int = 100
    connection_timeout_sec: int = 15
    transaction_retry_time_sec: int = 30
    ingestion: DatabaseIngestion

class OrchestratorConfig(BaseModel):
    max_concurrent_tenants: int = 10
    max_workers: int = 20
    timeout: int = 300
    hybrid_merge_strategy: str = "deep_merge"
    enable_state_differential: bool = True
    worker_timeout_sec: int = 300

class ForensicsConfig(BaseModel):
    log_path: str = "forensics/logs"
    report_path: str = "forensics/reports"
    output_directory: str = "forensics/reports"
    retention_days: int = 7
    generate_json_evidence: bool = True
    compress_reports: bool = True
    slack_alerts_enabled: bool = False

class RiskScoringConfig(BaseModel):
    enabled: bool = True
    public_exposure_penalty: float = 25.0
    admin_privilege_penalty: float = 50.0

class PermissionResolverConfig(BaseModel):
    enabled: bool = True
    flag_wildcard_actions: bool = True

class IdentityFabricConfig(BaseModel):
    enabled: bool = True
    flag_shadow_admins: bool = True
    cross_cloud_mapping: bool = True

class AttackPathConfig(BaseModel):
    enabled: bool = True
    max_path_cost: float = 20.0
    target_tags: List[str] = ["critical", "high"]

class LogicEngineConfig(BaseModel):
    risk_threshold: float = 0.7
    max_depth: int = 5
    risk_scoring: RiskScoringConfig
    effective_permission_resolver: PermissionResolverConfig
    identity_fabric: IdentityFabricConfig
    attack_path_detection: AttackPathConfig

class SimulationConfig(BaseModel):
    enabled: bool = True
    synthetic_node_count: int = 200
    vulnerability_density: float = 0.4
    vulnerability_injection_rate: float = 0.05
    base_node_multiplier: int = 50

class CrawlingConfig(BaseModel):
    depth: int = 3
    concurrency: int = 10
    rate_limit: int = 100
    api_retry_max_attempts: int = 5
    api_retry_backoff_factor: float = 2.0
    timeout_seconds: int = 30
    max_pagination_depth: int = 100
    concurrency_limit: int = 50
    fail_open_on_access_denied: bool = False
    rate_limit_calls_per_sec: float = 20.0
    verify_ssl: bool = True
    max_worker_threads: int = 50
    user_agent: str = "Cloudscape-Nexus-Titan/5.0"

# ------------------------------------------------------------------------------
# TENANT & IDENTITY MODELS
# ------------------------------------------------------------------------------

class TenantCredentials(BaseModel):
    aws_access_key_id: str = "testing"
    aws_secret_access_key: str = "testing"
    aws_account_id: Optional[str] = None
    azure_subscription_id: Optional[str] = None
    azure_tenant_id: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None

class TenantConfig(BaseModel):
    id: str
    name: str
    # Expanded regex to permit MOCK and TESTING environments without failure
    environment_type: str = Field(..., pattern=r"^(?i)(production|development|sandbox|dr|finance|shared-services|testing|staging|mock)$")
    credentials: TenantCredentials

# ------------------------------------------------------------------------------
# ROOT SETTINGS MODEL
# ------------------------------------------------------------------------------

class Settings(BaseModel):
    app_metadata: AppMetadata
    execution_mode: str = "MOCK"
    system: SystemConfig
    aws: AWSConfig
    azure: AzureConfig
    database: DatabaseConfig
    orchestrator: OrchestratorConfig
    forensics: ForensicsConfig
    logic_engine: LogicEngineConfig
    simulation: SimulationConfig
    crawling: CrawlingConfig
    service_registry: Dict[str, Any] = {}

# ------------------------------------------------------------------------------
# CONFIGURATION MANAGER (THE SINGLETON)
# ------------------------------------------------------------------------------

class ConfigurationManager:
    def __init__(self):
        # Establish absolute paths dynamically regardless of execution directory
        self.base_dir = Path(__file__).parent.parent
        self.config_dir = self.base_dir / "config"
        self.registry_dir = self.base_dir / "registry"
        
        # Logging initialization
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s"
        )
        self.logger = logging.getLogger("Cloudscape.Config")
        
        # State Containers
        self.settings: Settings = None
        self.tenants: List[TenantConfig] = []
        
        # Ignition Sequence
        self._load_settings()
        self._load_tenants()
        self.logger.info("Configuration Manager Initialized. Aether Features Loaded successfully.")

    def _load_settings(self):
        """Loads and validates the main configuration matrix."""
        settings_path = self.config_dir / "settings.yaml"
        if not settings_path.exists():
            self.logger.critical(f"FATAL: Master configuration missing at {settings_path}")
            sys.exit(1)
            
        try:
            with open(settings_path, 'r', encoding='utf-8') as file:
                raw_settings = yaml.safe_load(file) or {}
                
            # Attempt to overlay the legacy service_registry.json if present
            registry_path = self.config_dir / "service_registry.json"
            if registry_path.exists() and "service_registry" not in raw_settings:
                with open(registry_path, 'r', encoding='utf-8') as reg_file:
                    raw_settings["service_registry"] = json.load(reg_file)

            # Engage Pydantic Validation Matrix
            self.settings = Settings(**raw_settings)
            
        except ValidationError as ve:
            self.logger.critical("FATAL: Schema validation failed for settings.yaml:")
            self.logger.critical(ve.json(indent=2))
            sys.exit(1)
        except Exception as e:
            self.logger.critical(f"FATAL: Unhandled configuration read error: {e}")
            sys.exit(1)

    def _load_tenants(self):
        """Loads and validates the multi-tenant physical environments."""
        # Check both config/ and registry/ directories for flexibility
        tenant_path = self.config_dir / "tenants.yaml"
        if not tenant_path.exists():
            tenant_path = self.registry_dir / "tenants.yaml"
            
        if not tenant_path.exists():
            self.logger.critical("FATAL: Multi-tenant map (tenants.yaml) is missing.")
            sys.exit(1)
            
        try:
            with open(tenant_path, 'r', encoding='utf-8') as file:
                raw_tenants = yaml.safe_load(file)
                
            tenant_list = raw_tenants.get("tenants", []) if isinstance(raw_tenants, dict) else raw_tenants
            self.tenants = [TenantConfig(**t) for t in tenant_list]
            
        except ValidationError as ve:
            self.logger.critical("FATAL: Schema validation failed for tenants.yaml:")
            self.logger.critical(ve.json(indent=2))
            sys.exit(1)
        except Exception as e:
            self.logger.critical(f"FATAL: Failed to map tenants: {e}")
            sys.exit(1)

# Export the singleton instance
config = ConfigurationManager()