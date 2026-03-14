import os
import sys
import json
import logging
import logging.handlers
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timezone

# ==============================================================================
# CLOUDSCAPE NEXUS 5.2 TITAN - ENTERPRISE LOGGING MODULE
# ==============================================================================
# Centralized logging configuration for the entire CloudScape pipeline.
# Provides colored console output, rotating file handlers, and structured
# JSON logging for forensic analysis and SIEM integration.
#
# FEATURES:
# 1. COLORED CONSOLE: Level-aware ANSI coloring for terminal readability.
# 2. ROTATING FILE HANDLER: Automatic log rotation to prevent disk exhaustion.
# 3. JSON STRUCTURED LOGS: Machine-parseable log format for Splunk/ELK.
# 4. CORRELATION IDS: Thread-local request tracing for async pipelines.
# 5. CONFIGURABLE LEVELS: Per-module log level overrides.
# ==============================================================================


from rich.logging import RichHandler
from rich.console import Console

# Shared console for consistent output
console = Console()


# ──────────────────────────────────────────────────────────────────────────────
# JSON STRUCTURED FORMATTER (FOR SIEM / ELK / SPLUNK)
# ──────────────────────────────────────────────────────────────────────────────

class JSONFormatter(logging.Formatter):
    """
    Outputs log records as single-line JSON objects.
    Ideal for ingestion into Splunk, ELK, or cloud-native log aggregators.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Include exception info if present
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info),
            }

        # Include extra fields if any
        standard_keys = {
            'name', 'msg', 'args', 'created', 'relativeCreated', 'exc_info',
            'exc_text', 'stack_info', 'lineno', 'funcName', 'pathname',
            'filename', 'module', 'levelno', 'levelname', 'thread',
            'threadName', 'process', 'processName', 'message', 'msecs',
            'taskName',
        }
        extras = {k: v for k, v in record.__dict__.items() if k not in standard_keys}
        if extras:
            log_entry["extra"] = extras

        return json.dumps(log_entry, default=str, ensure_ascii=False)


# ──────────────────────────────────────────────────────────────────────────────
# LOGGING CONFIGURATOR
# ──────────────────────────────────────────────────────────────────────────────

def configure_logging(
    level: str = "INFO",
    log_dir: Optional[str] = None,
    enable_json: bool = False,
    enable_file: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
    module_overrides: Optional[Dict[str, str]] = None,
) -> None:
    """
    Configures the root logger with console and optional file/JSON handlers.
    
    Args:
        level: Root log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_dir: Directory for log files. If None, file logging is disabled.
        enable_json: If True, file logs use JSON format instead of plain text.
        enable_file: Whether to enable file logging at all.
        max_bytes: Maximum size of each log file before rotation.
        backup_count: Number of rotated log files to keep.
        module_overrides: Dict of logger_name -> level for per-module control.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Clear existing handlers to prevent duplicates on re-init
    root_logger.handlers.clear()

    # ── Console Handler (Rich handler for stylish, "glassy" output) ──────
    console_handler = RichHandler(
        console=console,
        show_time=True,
        omit_repeated_times=False,
        show_level=True,
        show_path=False,  # Path is noisy for this use case
        enable_link_path=False,
        markup=True,      # Enables Rich markup like [bold] in log messages
        rich_tracebacks=True, # Beautiful stack traces
        log_time_format="[%Y-%m-%d %H:%M:%S]"
    )
    
    # Minimal formatting for Rich since it handles alignments natively
    console_format = logging.Formatter("%(name)s | %(message)s")
    console_handler.setFormatter(console_format)
    console_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    root_logger.addHandler(console_handler)

    # ── File Handler (if directory provided) ─────────────────────────────
    if enable_file and log_dir:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)

        log_file = log_path / "cloudscape_nexus.log"
        file_formatter = JSONFormatter() if enable_json else logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )

        file_handler = logging.handlers.RotatingFileHandler(
            str(log_file),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8',
        )
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.DEBUG)  # File captures everything
        root_logger.addHandler(file_handler)

    # ── Per-Module Overrides ─────────────────────────────────────────────
    if module_overrides:
        for module_name, module_level in module_overrides.items():
            mod_logger = logging.getLogger(module_name)
            mod_logger.setLevel(getattr(logging, module_level.upper(), logging.INFO))

    # Suppress noisy third-party loggers
    for noisy_logger in ['urllib3', 'azure', 'botocore', 'boto3', 'neo4j']:
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Returns a named logger instance.
    Convenience wrapper to centralize logger creation.
    """
    return logging.getLogger(name)
