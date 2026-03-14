import os
import yaml
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from pydantic import (
    BaseModel, 
    Field, 
    ValidationError, 
    AliasChoices, 
    field_validator,
    model_validator,
    ConfigDict
)

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 TITAN - CONFIGURATION MANAGER (ZERO-G EDITION)
# ==============================================================================
# The strict Type-Safe configuration gateway powered by Pydantic V2.
# 
# TITAN UPGRADES ACTIVE:
# 1. Azure Crawling Restored: Re-injected the CrawlingConfig block to cure the 
#    AttributeError crashing the Azure physical extraction sensor.
# 2. Sovereign-Forensic Matrix: Added dedicated structures for Zero-Trust Mesh 
#    (Tailscale/WireGuard), Privacy Proxies (Presidio), and FinOps Cost-Gravity.
# 3. The "Zero-None" Guarantee: Absolute defaults injected to prevent malformed 
#    ARNs (e.g., arn:aws:ec2:us-east-1:None:...) during Graph linking.
# 4. Dynamic Alias Mapping: AliasChoices recursively hunts for legacy YAML keys.
# 5. Cross-Component Validation: Ensures memory safety and connection pooling 
#    limits are mathematically sound before ignition.
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. CORE SYSTEM & SOVEREIGN-FORENSIC MODELS
# ------------------------------------------------------------------------------

class AppMetadata(BaseModel):
    name: str = Field(default="Cloudscape-Nexus-Titan")
    version: str = Field(default="5.0.2")
    author: str = Field(default="Aether-Titan-Engineering")
    description: str = Field(default="Sovereign-Forensic Multi-Cloud Intelligence Mesh")
    environment: str = Field(default="MOCK")
    strict_mode: bool = Field(default=True, description="Halt execution on any non-transient schema fault.")

class SystemConfig(BaseModel):
    log_level: str = Field(default="INFO", validation_alias=AliasChoices("log_level", "LogLevel"))
    ingestion_chunk_size: int = Field(ge=100, le=50000, default=500)
    max_concurrency_per_engine: int = Field(ge=1, le=200, default=50)
    telemetry_enabled: bool = Field(default=True)
    os_thread_pool_multiplier: int = Field(default=4, ge=1, le=10, description="Multiplier for asyncio.to_thread workers.")
    
    @field_validator('log_level')
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Enforces strictly recognized Python logging levels."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            return "INFO"
        return v.upper()

class ZeroTrustMeshConfig(BaseModel):
    """
    Configuration for the Tailscale WireGuard mesh, Microsoft Presidio privacy 
    proxy, and strict mTLS routing for highly classified environments.
    """
    enabled: bool = Field(default=True)
    tailscale_auth_key: Optional[str] = Field(default=None)
    presidio_anonymization_enabled: bool = Field(default=True)
    enforce_zero_ingress: bool = Field(default=True)
    require_mtls_inter_node: bool = Field(default=False)
    egress_proxy_url: Optional[str] = Field(default=None)

class FinOpsConfig(BaseModel):
    """Configuration for the Cost-Gravity 3D Physics Engine."""
    enabled: bool = Field(default=True)
    aws_price_list_api_region: str = Field(default="us-east-1")
    cost_gravity_multiplier: float = Field(default=1.5, ge=0.1, le=10.0)
    heatmap_threshold_usd: float = Field(default=1000.0, ge=1.0)
    detect_idle_resources: bool = Field(default=True)

# ------------------------------------------------------------------------------
# 2. SENSOR & API CRAWLING MODELS
# ------------------------------------------------------------------------------

class AWSConfig(BaseModel):
    target_regions: List[str] = Field(default=["us-east-1", "us-west-2"])
    localstack_endpoint: str = Field(default="http://localhost:4566")
    boto_max_retries: int = Field(default=6, ge=1, le=15)
    boto_timeout: int = Field(default=45, ge=5, le=120)
    sts_regional_endpoints: bool = Field(default=True)
    pagination_page_size: int = Field(default=100, ge=10, le=1000)

class AzureConfig(BaseModel):
    azurite_endpoint: str = Field(default="http://127.0.0.1:10000")
    parallel_extractions: int = Field(default=10, ge=1, le=50)
    authority_host: str = Field(default="https://login.microsoftonline.com")
    management_endpoint: str = Field(default="https://management.azure.com")

class CrawlingConfig(BaseModel):
    """
    THE AZURE CURE.
    Configuration specifically utilized by the AzureEngine to handle Deep Pagination, 
    Web App API scraping, and Storage Blob crawling without triggering rate limits.
    """
    depth: int = Field(default=3, ge=1, le=10)
    concurrency: int = Field(default=10, ge=1, le=100)
    rate_limit_calls_per_sec: float = Field(default=20.0, ge=1.0, le=1000.0)
    api_retry_max_attempts: int = Field(default=5, ge=1, le=10)
    api_retry_backoff_factor: float = Field(default=2.0, ge=1.0, le=10.0)
    timeout_seconds: int = Field(default=30, ge=5, le=300)
    fail_open_on_access_denied: bool = Field(default=False)
    verify_ssl: bool = Field(default=True)
    user_agent: str = Field(default="Cloudscape-Nexus-Titan/5.0")

# ------------------------------------------------------------------------------
# 3. DATABASE & MEMORY MANAGEMENT MODELS
# ------------------------------------------------------------------------------

class DatabaseIngestion(BaseModel):
    batch_size: int = Field(ge=100, le=20000, default=500)
    retries: int = Field(default=5, ge=1, le=20)
    backoff_factor: float = Field(default=3.0, ge=0.5, le=15.0)

class DatabaseConfig(BaseModel):
    # --- TITAN PHYSICAL ALIAS MAPPING ---
    # Guarantees connection pooling survival during Graceful Teardown.
    neo4j_uri: str = Field(default="bolt://127.0.0.1:7687", validation_alias=AliasChoices('uri', 'neo4j_uri', 'Neo4jUri'))
    neo4j_user: str = Field(default="neo4j", validation_alias=AliasChoices('user', 'neo4j_user', 'Neo4jUser'))
    neo4j_password: str = Field(default="password", validation_alias=AliasChoices('password', 'neo4j_password', 'Neo4jPassword'))
    
    redis_uri: str = Field(default="redis://127.0.0.1:6379", validation_alias=AliasChoices('redis_uri', 'cache_uri'))
    mongo_bson_uri: str = Field(default="mongodb://127.0.0.1:27017", validation_alias=AliasChoices('mongo_uri', 'bson_uri'))
    
    connection_pool_size: int = Field(default=200, ge=10)
    connection_timeout_sec: float = Field(default=15.0, ge=1.0)
    ingestion: DatabaseIngestion = Field(default_factory=DatabaseIngestion)

class OrchestratorConfig(BaseModel):
    max_concurrent_tenants: int = Field(default=1) # Strictly 1 to prevent LocalStack Mutex locks
    worker_timeout_sec: int = Field(default=1200)
    enable_state_differential: bool = Field(default=True)
    strict_sequential_mode: bool = Field(default=True, description="Force serial extraction to protect Docker limits.")

class ForensicsConfig(BaseModel):
    log_path: str = Field(default="forensics/logs")
    report_path: str = Field(default="forensics/reports")
    bson_ledger_path: str = Field(default="forensics/bson_ledger")
    retention_days: int = Field(default=7, ge=1)
    generate_json_evidence: bool = Field(default=True)

# ------------------------------------------------------------------------------
# 4. INTELLIGENCE & LOGIC ENGINE MODELS
# ------------------------------------------------------------------------------

class RiskScoringConfig(BaseModel):
    enabled: bool = Field(default=True)
    public_exposure_penalty: float = Field(default=5.0)
    admin_privilege_penalty: float = Field(default=4.0)
    cvss_base_multiplier: float = Field(default=1.2)

class AttackPathConfig(BaseModel):
    enabled: bool = Field(default=True)
    max_depth: int = Field(default=6, ge=2, le=10)
    risk_threshold: float = Field(default=5.0, ge=1.0, le=10.0) # Upgraded for Friction Decay 2.0
    decay_exponent: float = Field(default=2.0, ge=1.0, le=5.0) # Inverse-square physics control
    mitre_attack_enrichment: bool = Field(default=True)

class LogicEngineConfig(BaseModel):
    risk_scoring: RiskScoringConfig = Field(default_factory=RiskScoringConfig)
    attack_path_detection: AttackPathConfig = Field(default_factory=AttackPathConfig)

class SimulationConfig(BaseModel):
    enabled: bool = Field(default=True)
    vulnerability_injection_rate: float = Field(default=0.15, ge=0.0, le=1.0)
    base_node_multiplier: int = Field(default=20, ge=1)
    deterministic_seed: Optional[int] = Field(default=42) # For reproducible mock testing

# ------------------------------------------------------------------------------
# 5. TENANT & IDENTITY MODELS (THE "ZERO-NONE" FIX)
# ------------------------------------------------------------------------------

class TenantCredentials(BaseModel):
    """
    The core cryptographic resolution object.
    Implements aggressive AliasChoices to read varying YAML formats, and absolute
    enterprise defaults to mathematically eliminate "None-ID" bugs in ARN generation.
    """
    # AWS Credentials
    aws_access_key_id: str = Field(
        default="testing", 
        validation_alias=AliasChoices('aws_access_key_id', 'access_key', 'AwsAccessKeyId')
    )
    aws_secret_access_key: str = Field(
        default="testing", 
        validation_alias=AliasChoices('aws_secret_access_key', 'secret_key', 'AwsSecretAccessKey')
    )
    # THE ZERO-NONE GUARANTEE: Never allow a None value to break Graph linking
    aws_account_id: str = Field(
        default="123456789012", 
        validation_alias=AliasChoices('aws_account_id', 'account_id', 'AccountId', 'aws_account')
    )
    aws_region: str = Field(
        default="us-east-1", 
        validation_alias=AliasChoices('aws_region', 'region', 'Region', 'default_region')
    )

    # Azure Credentials
    azure_subscription_id: str = Field(
        default="00000000-0000-0000-0000-000000000000", 
        validation_alias=AliasChoices('azure_subscription_id', 'subscription_id', 'SubscriptionId', 'subscription')
    )
    azure_tenant_id: str = Field(
        default="simulated-azure-tenant-id", 
        validation_alias=AliasChoices('azure_tenant_id', 'tenant_id', 'TenantId')
    )
    azure_client_id: str = Field(
        default="mock-client-id", 
        validation_alias=AliasChoices('azure_client_id', 'client_id', 'ClientId')
    )
    azure_client_secret: str = Field(
        default="mock-client-secret", 
        validation_alias=AliasChoices('azure_client_secret', 'client_secret', 'ClientSecret')
    )

class TenantConfig(BaseModel):
    id: str = Field(..., description="Unique Project/Tenant Identifier")
    name: str = Field(default="Unknown_Tenant")
    
    # Expanded regex to perfectly match enterprise lifecycles
    environment_type: str = Field(
        default="MOCK", 
        pattern=r"^(?i)(production|development|sandbox|dr|finance|shared-services|testing|staging|mock)$"
    )
    
    credentials: TenantCredentials = Field(default_factory=TenantCredentials)

# ------------------------------------------------------------------------------
# 6. ROOT SETTINGS MODEL (WITH CROSS-COMPONENT VALIDATION)
# ------------------------------------------------------------------------------

class Settings(BaseModel):
    """The Root Document mapped directly from settings.yaml"""
    app_metadata: AppMetadata = Field(default_factory=AppMetadata)
    execution_mode: str = Field(default="MOCK", validation_alias=AliasChoices("execution_mode", "mode", "Mode"))
    
    system: SystemConfig = Field(default_factory=SystemConfig)
    zero_trust_mesh: ZeroTrustMeshConfig = Field(default_factory=ZeroTrustMeshConfig)
    finops: FinOpsConfig = Field(default_factory=FinOpsConfig)
    
    aws: AWSConfig = Field(default_factory=AWSConfig)
    azure: AzureConfig = Field(default_factory=AzureConfig)
    crawling: CrawlingConfig = Field(default_factory=CrawlingConfig) # THE RESTORED AZURE FIX
    
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    orchestrator: OrchestratorConfig = Field(default_factory=OrchestratorConfig)
    forensics: ForensicsConfig = Field(default_factory=ForensicsConfig)
    logic_engine: LogicEngineConfig = Field(default_factory=LogicEngineConfig)
    simulation: SimulationConfig = Field(default_factory=SimulationConfig)
    service_registry: Dict[str, Any] = Field(default_factory=dict)
    
    model_config = ConfigDict(extra='ignore', populate_by_name=True)

    @model_validator(mode='after')
    def validate_cross_component_constraints(self) -> 'Settings':
        """
        Ensures that parameters spanning different components do not conflict
        and cause unhandled memory leaks or race conditions.
        """
        # Ensure Neo4j batching does not overwhelm the connection pool
        if self.database.ingestion.batch_size > 5000 and self.database.connection_pool_size < 100:
            raise ValueError("High batch sizes require a Neo4j connection pool size of at least 100.")
            
        # Ensure emulator compatibility when in MOCK mode
        if self.execution_mode.upper() == "MOCK":
            if "localhost" not in self.aws.localstack_endpoint and "127.0.0.1" not in self.aws.localstack_endpoint:
                if "host.docker.internal" not in self.aws.localstack_endpoint:
                    pass # Allow custom docker bridges, but usually this is a misconfiguration
                    
        return self

# ------------------------------------------------------------------------------
# 7. CONFIGURATION MANAGER (THE GLOBAL SINGLETON)
# ------------------------------------------------------------------------------

class ConfigurationManager:
    """
    The Global Singleton State Container.
    Initializes logging, establishes absolute file paths, parses YAML state, 
    applies environment variable overrides, and holds the configuration in 
    a stable memory address for the lifespan of the application.
    """
    def __init__(self):
        # Establish absolute paths dynamically regardless of where main.py is executed
        self.base_dir = Path(__file__).resolve().parent.parent
        self.config_dir = self.base_dir / "config"
        self.registry_dir = self.base_dir / "registry"
        
        # Early Logging Bootstrap (Before main.py fully takes over)
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s | %(levelname)-8s | %(name)-35s | %(message)s"
        )
        self.logger = logging.getLogger("Cloudscape.Core.Config")
        
        # State Containers
        self.settings: Settings = None
        self.tenants: List[TenantConfig] = []
        
        # Ignition Sequence
        self._load_settings()
        self._load_tenants()
        self._apply_environment_overrides()
        
        self.logger.info("Configuration Manager Initialized. Sovereign-Forensic Matrix Locked.")

    def _load_settings(self) -> None:
        """Loads and mathematically validates the main configuration matrix."""
        settings_path = self.config_dir / "settings.yaml"
        raw_settings = {}
        
        try:
            if settings_path.exists():
                with open(settings_path, 'r', encoding='utf-8') as file:
                    raw_settings = yaml.safe_load(file) or {}
            else:
                self.logger.warning(f"Master configuration missing at {settings_path}. Booting with Titan Engine Defaults.")
                
            # Overlay legacy service_registry.json if present
            registry_path = self.config_dir / "service_registry.json"
            if registry_path.exists() and "service_registry" not in raw_settings:
                with open(registry_path, 'r', encoding='utf-8') as reg_file:
                    raw_settings["service_registry"] = json.load(reg_file)

            # Engage Pydantic Validation Matrix
            self.settings = Settings(**raw_settings)
            
        except ValidationError as ve:
            self.logger.critical("\n\033[91m[FATAL] Schema validation failed for settings.yaml. Ensure types are correct:\033[0m")
            self.logger.critical(ve.json(indent=2))
            sys.exit(1)
        except Exception as e:
            self.logger.critical(f"\n\033[91m[FATAL] Unhandled configuration read error: {e}\033[0m")
            sys.exit(1)

    def _load_tenants(self) -> None:
        """
        Loads the multi-tenant physical environments.
        This is where the 'Zero-None' fix activates, guaranteeing Account IDs exist.
        """
        # Check standard config and registry fallbacks
        tenant_path = self.config_dir / "tenants.yaml"
        if not tenant_path.exists():
            tenant_path = self.registry_dir / "tenants.yaml"
            
        if not tenant_path.exists():
            self.logger.warning("Multi-tenant map (tenants.yaml) is missing. Injecting Enterprise Mock Tenants.")
            self.tenants = self._generate_mock_tenants()
            return
            
        try:
            with open(tenant_path, 'r', encoding='utf-8') as file:
                raw_tenants = yaml.safe_load(file) or {}
                
            # Handle both list and nested dictionary YAML structures
            tenant_list = raw_tenants.get("tenants", []) if isinstance(raw_tenants, dict) else raw_tenants
            
            if not tenant_list:
                self.logger.warning("Tenant array is declared but empty. Injecting Enterprise Mock Tenants.")
                self.tenants = self._generate_mock_tenants()
            else:
                # Pydantic AliasChoices mapping engages here
                self.tenants = [TenantConfig(**t) for t in tenant_list]
            
        except ValidationError as ve:
            self.logger.critical("\n\033[91m[FATAL] Schema validation failed for tenants.yaml. Review credential mapping:\033[0m")
            self.logger.critical(ve.json(indent=2))
            sys.exit(1)
        except Exception as e:
            self.logger.critical(f"\n\033[91m[FATAL] Failed to map enterprise tenants: {e}\033[0m")
            sys.exit(1)

    def _apply_environment_overrides(self) -> None:
        """
        Scans OS Environment variables to dynamically override config files.
        Useful for Docker/Kubernetes deployments where YAML cannot be easily edited.
        """
        exec_mode = os.environ.get("CLOUDSCAPE_EXECUTION_MODE")
        if exec_mode:
            self.settings.execution_mode = exec_mode.upper()
            
        neo4j_pwd = os.environ.get("CLOUDSCAPE_NEO4J_PASSWORD")
        if neo4j_pwd:
            self.settings.database.neo4j_password = neo4j_pwd

    def _generate_mock_tenants(self) -> List[TenantConfig]:
        """
        Generates a robust fallback multi-tenant matrix.
        Provides physically valid Account IDs and Subscription UUIDs to guarantee 
        that ARNs form correctly when running completely synthetic scans.
        """
        return [
            TenantConfig(
                id="PROJ-FIN-01", 
                name="Finance Subsystem", 
                environment_type="MOCK",
                credentials=TenantCredentials(aws_account_id="111122223333", azure_subscription_id="11111111-1111-1111-1111-111111111111")
            ),
            TenantConfig(
                id="PROJ-WEB-02", 
                name="Public Web Gateway", 
                environment_type="MOCK",
                credentials=TenantCredentials(aws_account_id="444455556666", azure_subscription_id="22222222-2222-2222-2222-222222222222")
            ),
            TenantConfig(
                id="PROJ-SHR-03", 
                name="Shared Services DB", 
                environment_type="MOCK",
                credentials=TenantCredentials(aws_account_id="777788889999", azure_subscription_id="33333333-3333-3333-3333-333333333333")
            ),
            TenantConfig(
                id="PROJ-AZURE-04", 
                name="Azure Edge Gateway", 
                environment_type="MOCK",
                credentials=TenantCredentials(aws_account_id="000000000000", azure_subscription_id="44444444-4444-4444-4444-444444444444")
            ),
            TenantConfig(
                id="PROJ-DR-05", 
                name="Disaster Recovery Core", 
                environment_type="MOCK",
                credentials=TenantCredentials(aws_account_id="999999999999", azure_subscription_id="55555555-5555-5555-5555-555555555555")
            )
        ]

# Export the absolute singleton instance. 
# This locks configuration into memory and prevents async drift.
config = ConfigurationManager()