import os
import yaml
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any

from pydantic import BaseModel, Field, ValidationError, AliasChoices

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - CONFIGURATION MANAGER (ZERO-G EDITION)
# ==============================================================================
# The strict Type-Safe configuration gateway powered by Pydantic V2.
# Maps the YAML state into immutable Python memory structures. 
# 
# TITAN UPGRADES:
# - Physical Alias Bridging: Utilizes AliasChoices to natively bind legacy YAML 
#   keys (e.g., 'uri') directly to strictly required engine attributes ('neo4j_uri')
#   ensuring 100% memory availability during Graceful Teardown operations.
# - Absolute Environment Validation.
# ==============================================================================

# ------------------------------------------------------------------------------
# NESTED SYSTEM MODELS
# ------------------------------------------------------------------------------

class AppMetadata(BaseModel):
    name: str = Field(default="Cloudscape-Nexus")
    version: str = Field(default="5.0.1")
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
    localstack_endpoint: str = "http://localhost:4566"

class AzureConfig(BaseModel):
    target_subscription: str = "mock-azure-sub-0001"
    azurite_endpoint: str = "http://127.0.0.1:10000"

class DatabaseIngestion(BaseModel):
    batch_size: int = Field(ge=100, le=20000, default=1000)
    retries: int = 5
    backoff_factor: float = 1.5

class DatabaseConfig(BaseModel):
    # --- TITAN PHYSICAL ALIAS MAPPING ---
    # AliasChoices allows the YAML to use 'uri' while physically storing it 
    # in memory as 'neo4j_uri'. This permanently prevents the Teardown crash.
    neo4j_uri: str = Field(default="bolt://127.0.0.1:7687", validation_alias=AliasChoices('uri', 'neo4j_uri'))
    neo4j_user: str = Field(default="neo4j", validation_alias=AliasChoices('user', 'neo4j_user'))
    neo4j_password: str = Field(default="password", validation_alias=AliasChoices('password', 'neo4j_password'))
    
    redis_uri: str = Field(default="redis://127.0.0.1:6379", validation_alias=AliasChoices('redis_uri', 'cache_uri'))
    connection_pool_size: int = 100
    connection_timeout_sec: int = 15
    transaction_retry_time_sec: int = 30
    ingestion: DatabaseIngestion = Field(default_factory=lambda: DatabaseIngestion())

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
    risk_scoring: RiskScoringConfig = Field(default_factory=RiskScoringConfig)
    effective_permission_resolver: PermissionResolverConfig = Field(default_factory=PermissionResolverConfig)
    identity_fabric: IdentityFabricConfig = Field(default_factory=IdentityFabricConfig)
    attack_path_detection: AttackPathConfig = Field(default_factory=AttackPathConfig)

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
    # Expanded regex to permit MOCK and TESTING environments without validation failure
    environment_type: str = Field(..., pattern=r"^(?i)(production|development|sandbox|dr|finance|shared-services|testing|staging|mock)$")
    credentials: TenantCredentials = Field(default_factory=TenantCredentials)

# ------------------------------------------------------------------------------
# ROOT SETTINGS MODEL
# ------------------------------------------------------------------------------

class Settings(BaseModel):
    app_metadata: AppMetadata = Field(default_factory=AppMetadata)
    execution_mode: str = "MOCK"
    system: SystemConfig = Field(default_factory=SystemConfig)
    aws: AWSConfig = Field(default_factory=AWSConfig)
    azure: AzureConfig = Field(default_factory=AzureConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    orchestrator: OrchestratorConfig = Field(default_factory=OrchestratorConfig)
    forensics: ForensicsConfig = Field(default_factory=ForensicsConfig)
    logic_engine: LogicEngineConfig = Field(default_factory=LogicEngineConfig)
    simulation: SimulationConfig = Field(default_factory=SimulationConfig)
    crawling: CrawlingConfig = Field(default_factory=CrawlingConfig)
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
        
        try:
            raw_settings = {}
            if settings_path.exists():
                with open(settings_path, 'r', encoding='utf-8') as file:
                    raw_settings = yaml.safe_load(file) or {}
            else:
                self.logger.warning(f"Master configuration missing at {settings_path}. Booting with Titan Defaults.")
                
            # Attempt to overlay the legacy service_registry.json if present
            registry_path = self.config_dir / "service_registry.json"
            if registry_path.exists() and "service_registry" not in raw_settings:
                with open(registry_path, 'r', encoding='utf-8') as reg_file:
                    raw_settings["service_registry"] = json.load(reg_file)

            # Engage Pydantic Validation Matrix (AliasChoices will auto-map 'uri' to 'neo4j_uri')
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
            self.logger.warning("Multi-tenant map (tenants.yaml) is missing. Injecting Mock Tenants.")
            self.tenants = self._generate_mock_tenants()
            return
            
        try:
            with open(tenant_path, 'r', encoding='utf-8') as file:
                raw_tenants = yaml.safe_load(file) or {}
                
            tenant_list = raw_tenants.get("tenants", []) if isinstance(raw_tenants, dict) else raw_tenants
            
            if not tenant_list:
                self.logger.warning("Tenant array is empty. Injecting Mock Tenants.")
                self.tenants = self._generate_mock_tenants()
            else:
                self.tenants = [TenantConfig(**t) for t in tenant_list]
            
        except ValidationError as ve:
            self.logger.critical("FATAL: Schema validation failed for tenants.yaml:")
            self.logger.critical(ve.json(indent=2))
            sys.exit(1)
        except Exception as e:
            self.logger.critical(f"FATAL: Failed to map tenants: {e}")
            sys.exit(1)

    def _generate_mock_tenants(self) -> List[TenantConfig]:
        """Generates a fallback physical tenant matrix if the configuration is missing."""
        return [
            TenantConfig(id="PROJ-FIN-01", name="Finance Subsystem", environment_type="MOCK"),
            TenantConfig(id="PROJ-WEB-02", name="Public Web Gateway", environment_type="MOCK")
        ]

# Export the absolute singleton instance
config = ConfigurationManager()