import os
from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings
from pydantic import Field

class CloudscapeConfig(BaseSettings):
    """
    Advanced Configuration Management for Project Cloudscape.
    Centralizes all pathing for the D:/E: Drive split.
    """
    # --- DRIVE ARCHITECTURE ---
    PROJECT_NAME: str = "Cloudscape_Enterprise"
    BASE_DIR: Path = Path("D:/Cloudscape_Project")
    
    # Vault (E: Drive) Persistence Root
    VAULT_ROOT: Path = Path("E:/Cloudscape_Data")
    VAULT_DIR: Path = VAULT_ROOT / "DockerDesktopWSL"
    MANIFEST_DIR: Path = VAULT_DIR / "manifests"
    LOG_DIR: Path = VAULT_DIR / "logs"
    
    # --- INFRASTRUCTURE ENDPOINTS ---
    AWS_ENDPOINT_URL: str = Field(default="http://localhost:4566")
    AWS_REGION: str = "us-east-1"
    
    # --- GRAPH DATABASE (NEO4J) ---
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASS: str = "password"

    # --- DISCOVERY SETTINGS ---
    ENABLED_SERVICES: List[str] = [
        'ec2', 's3', 'rds', 'lambda', 'elbv2', 
        'ecs', 'dynamodb', 'apigateway', 'kinesis'
    ]

    class Config:
        env_file = ".env"
        case_sensitive = True

    def setup_vault(self):
        """Creates the physical directory structure on the E: Drive."""
        directories = [self.VAULT_ROOT, self.VAULT_DIR, self.MANIFEST_DIR, self.LOG_DIR]
        for directory in directories:
            # exist_ok=True prevents errors if the folder already exists
            os.makedirs(directory, exist_ok=True)
        return True

# Global Singleton Instance
settings = CloudscapeConfig()