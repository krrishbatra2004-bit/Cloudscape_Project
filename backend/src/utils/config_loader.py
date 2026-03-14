import os
import sys
import logging
import platform
from pathlib import Path
from typing import Optional


# ==============================================================================
# CLOUDSCAPE NEXUS 5.2 TITAN - PORTABLE ENVIRONMENT VALIDATOR
# ==============================================================================
# Platform-agnostic workspace validation utility. Ensures the runtime
# environment is correctly configured before pipeline ignition.
#
# TITAN 5.2 UPGRADES:
# 1. REMOVED HARDCODED DRIVE LETTERS: No longer assumes D:/E: Windows layout.
# 2. PLATFORM DETECTION: Auto-detects OS and adjusts validation accordingly.
# 3. GRACEFUL FALLBACK: Uses logging instead of hard sys.exit on non-critical.
# 4. OPTIONAL RICH: Falls back to standard print if 'rich' is not installed.
# ==============================================================================

# Optional rich import with graceful fallback
try:
    from rich.console import Console
    console = Console()
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False
    console = None


logger = logging.getLogger("CloudScape.Utils.ConfigLoader")


def _print(message: str, style: str = "") -> None:
    """Prints a message using rich if available, otherwise uses standard print."""
    if _HAS_RICH and console:
        console.print(message)
    else:
        # Strip rich markup for plain output
        import re
        clean = re.sub(r'\[.*?\]', '', message)
        print(clean)


def verify_setup(
    require_project_dir: bool = True,
    expected_project_name: str = "CloudScape_Project",
) -> bool:
    """
    Validates that the runtime environment is sane for CloudScape execution.
    
    Checks performed:
    1. Cloud credential environment variables point to valid paths (if set).
    2. Current working directory is within the expected project folder.
    3. Python version meets minimum requirements.
    
    Args:
        require_project_dir: If True, validates CWD is inside the project.
        expected_project_name: Expected project folder name for CWD validation.
    
    Returns:
        True if all checks pass.
    
    Raises:
        SystemExit only on critical failures when require_project_dir is True.
    """
    all_ok = True
    
    # ── Check 1: Python version ──────────────────────────────────────────
    py_version = sys.version_info
    if py_version < (3, 10):
        _print(f"[bold red]!! PYTHON VERSION TOO OLD !![/bold red]")
        _print(f"Required: Python 3.10+, Found: {py_version.major}.{py_version.minor}")
        logger.error(f"Python version {py_version.major}.{py_version.minor} is below minimum 3.10")
        all_ok = False
    else:
        logger.debug(f"Python version OK: {py_version.major}.{py_version.minor}.{py_version.micro}")
    
    # ── Check 2: Cloud credential path validation (non-fatal) ────────────
    azure_path = os.getenv('AZURE_CONFIG_DIR', '')
    aws_path = os.getenv('AWS_SHARED_CREDENTIALS_FILE', '')
    
    if azure_path and not Path(azure_path).exists():
        _print(f"[yellow]⚠ AZURE_CONFIG_DIR points to non-existent path: {azure_path}[/yellow]")
        logger.warning(f"AZURE_CONFIG_DIR path does not exist: {azure_path}")
    
    if aws_path and not Path(aws_path).exists():
        _print(f"[yellow]⚠ AWS_SHARED_CREDENTIALS_FILE points to non-existent path: {aws_path}[/yellow]")
        logger.warning(f"AWS_SHARED_CREDENTIALS_FILE path does not exist: {aws_path}")
    
    # ── Check 3: Working directory validation ────────────────────────────
    if require_project_dir:
        current_dir = Path.cwd()
        project_found = (
            current_dir.name == expected_project_name or
            expected_project_name in str(current_dir)
        )
        
        if not project_found:
            _print(f"[bold red]!! WRONG WORKSPACE !![/bold red]")
            _print(f"Expected project directory containing '{expected_project_name}', got: {current_dir}")
            logger.error(f"CWD mismatch: expected '{expected_project_name}' in path, got '{current_dir}'")
            all_ok = False
        else:
            logger.debug(f"Working directory OK: {current_dir}")
    
    # ── Check 4: Platform info logging ───────────────────────────────────
    logger.debug(
        f"Platform: {platform.system()} {platform.release()} | "
        f"Architecture: {platform.machine()}"
    )
    
    if all_ok:
        logger.info("Environment validation passed.")
    
    return all_ok