$ErrorActionPreference = "Stop"
$root = "d:\Cloudscape_Project"
Set-Location $root

# Create base structure
$dirs = @(
    "frontend/public",
    "frontend/src",
    "backend/config",
    "backend/forensics/logs",
    "backend/forensics/reports",
    "backend/forensics/bson_ledger",
    "backend/scripts",
    "backend/src/core/processor",
    "backend/src/core/correlation",
    "backend/src/discovery/engines",
    "backend/src/discovery/drivers",
    "backend/src/intelligence",
    "backend/src/simulation",
    "backend/src/utils",
    "backend/tests"
)

foreach ($dir in $dirs) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# Move root files
if (Test-Path "main.py") { Move-Item -Force "main.py" "backend/" }

# Move config
if (Test-Path "config/settings.yaml") { Move-Item -Force "config/settings.yaml" "backend/config/" }
if (Test-Path "config/tenants.yaml") { Move-Item -Force "config/tenants.yaml" "backend/config/" }
if (Test-Path "registry/aws_services.json") { Move-Item -Force "registry/aws_services.json" "backend/config/service_registry.json" }

# Move scripts
if (Test-Path "utils/soft_reset.py") { Move-Item -Force "utils/soft_reset.py" "backend/scripts/" }
if (Test-Path "scripts/titan_preflight.py") { Move-Item -Force "scripts/titan_preflight.py" "backend/scripts/" -ErrorAction SilentlyContinue }
if (Test-Path "scripts/check_mesh.py") { Move-Item -Force "scripts/check_mesh.py" "backend/scripts/" -ErrorAction SilentlyContinue }
if (Test-Path "scripts/audit.py") { Move-Item -Force "scripts/audit.py" "backend/scripts/" -ErrorAction SilentlyContinue }

# Move core
if (Test-Path "core/config.py") { Move-Item -Force "core/config.py" "backend/src/core/" }
if (Test-Path "core/orchestrator.py") { Move-Item -Force "core/orchestrator.py" "backend/src/core/" }
if (Test-Path "core/processor/ingestor.py") { Move-Item -Force "core/processor/ingestor.py" "backend/src/core/processor/" }
if (Test-Path "core/processor/transformer.py") { Move-Item -Force "core/processor/transformer.py" "backend/src/core/processor/" }
if (Test-Path "core/correlation/trust_resolver.py") { Move-Item -Force "core/correlation/trust_resolver.py" "backend/src/core/correlation/" }

# Move discovery
if (Test-Path "engines/aws_engine.py") { Move-Item -Force "engines/aws_engine.py" "backend/src/discovery/engines/" }
if (Test-Path "engines/azure_engine.py") { Move-Item -Force "engines/azure_engine.py" "backend/src/discovery/engines/" }
if (Test-Path "engines/base_engine.py") { Move-Item -Force "engines/base_engine.py" "backend/src/discovery/engines/" }
if (Test-Path "engines/hybrid_bridge.py") { Move-Item -Force "engines/hybrid_bridge.py" "backend/src/discovery/engines/" }

if (Test-Path "drivers/aws_driver.py") { Move-Item -Force "drivers/aws_driver.py" "backend/src/discovery/drivers/" }
if (Test-Path "drivers/azure_driver.py") { Move-Item -Force "drivers/azure_driver.py" "backend/src/discovery/drivers/" }
if (Test-Path "drivers/base_driver.py") { Move-Item -Force "drivers/base_driver.py" "backend/src/discovery/drivers/" }

# Move intelligence
if (Test-Path "core/intelligence/attack_path.py") { Move-Item -Force "core/intelligence/attack_path.py" "backend/src/intelligence/" }
if (Test-Path "core/intelligence/identity_fabric.py") { Move-Item -Force "core/intelligence/identity_fabric.py" "backend/src/intelligence/" }
if (Test-Path "core/logic/policy_engine.py") { Move-Item -Force "core/logic/policy_engine.py" "backend/src/intelligence/" }
if (Test-Path "core/logic/risk_scorer.py") { Move-Item -Force "core/logic/risk_scorer.py" "backend/src/intelligence/" }

# Move simulation
if (Test-Path "simulation/state_factory.py") { Move-Item -Force "simulation/state_factory.py" "backend/src/simulation/" }
if (Test-Path "utils/mesh_seeder.py") { Move-Item -Force "utils/mesh_seeder.py" "backend/src/simulation/" }
if (Test-Path "core/simulation/enterprise_seeder.py") { Move-Item -Force "core/simulation/enterprise_seeder.py" "backend/src/simulation/" }

# Move utils
if (Test-Path "utils/logger.py") { Move-Item -Force "utils/logger.py" "backend/src/utils/" }
if (Test-Path "utils/db_tools.py") { Move-Item -Force "utils/db_tools.py" "backend/src/utils/" }
if (Test-Path "utils/config_loader.py") { Move-Item -Force "utils/config_loader.py" "backend/src/utils/" }
if (Test-Path "utils/visibility_debugger.py") { Move-Item -Force "utils/visibility_debugger.py" "backend/src/utils/" }

# Tests
if (Test-Path "tests") { Move-Item -Force "tests/*" "backend/tests/" -ErrorAction SilentlyContinue }
if (Test-Path "dashboard/app.py") { Move-Item -Force "dashboard/app.py" "frontend/src/" -ErrorAction SilentlyContinue }

# Clean old roots
Remove-Item -Recurse -Force core, config, dashboard, drivers, engines, registry, simulation, utils, tests, scripts -ErrorAction SilentlyContinue
Write-Output "File structure reorganized."
