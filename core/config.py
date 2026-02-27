import os
import yaml
from typing import List, Optional, Dict
from pydantic import BaseModel, Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

# ==============================================================================
# PROJECT CLOUDSCAPE: ADVANCED MULTI-TENANT CONFIGURATION ENGINE
# ==============================================================================

class TenantAuth(BaseModel):
    """Schema for dynamic authentication credentials per tenant."""
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None

class TenantConfig(BaseModel):
    """Schema for individual cloud project/tenant definition."""
    id: str
    name: str
    provider: str
    account_id: Optional[str] = None
    tenant_id: Optional[str] = None
    region: str
    endpoint_url: str  # Critical for LocalStack/Azurite redirection
    risk_weight: float = Field(ge=0.0, le=1.0)
    tags: List[str] = []
    auth: TenantAuth

class GlobalSettings(BaseSettings):
    """Global system settings loaded from Environment Variables."""
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Graph Database Configuration
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "Cloudscape2026!"

    # System Paths
    VAULT_ROOT: str = "E:/Cloudscape_Vault"
    REGISTRY_PATH: str = "registry/tenants.yaml"

    # Orchestration Settings
    MAX_WORKERS: int = 5
    SCAN_INTERVAL_SECONDS: int = 3600
    LOG_LEVEL: str = "INFO"

def load_tenant_registry(file_path: str) -> List[TenantConfig]:
    """
    Parses the YAML registry and validates it against the Pydantic schema.
    This ensures malformed project definitions never enter the pipeline.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"[-] Registry file not found at: {file_path}")

    with open(file_path, 'r') as f:
        raw_data = yaml.safe_load(f)

    if not raw_data or "tenants" not in raw_data:
        raise ValueError("[-] Invalid registry format: 'tenants' key missing.")

    return [TenantConfig(**t) for t in raw_data["tenants"]]

# Global Instances for use across the framework
settings = GlobalSettings()
try:
    tenants = load_tenant_registry(settings.REGISTRY_PATH)
except Exception as e:
    print(f"[FATAL] Configuration Error: {e}")
    exit(1)

# Ensure Vault structure exists on E: Drive
if not os.path.exists(settings.VAULT_ROOT):
    os.makedirs(settings.VAULT_ROOT, exist_ok=True)