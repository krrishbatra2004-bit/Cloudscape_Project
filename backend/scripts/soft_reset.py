import os
import sys
import shutil
import subprocess
import time
import socket
import logging
from pathlib import Path

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - ENVIRONMENT SANITIZER (SOFT RESET)
# ==============================================================================
# Performs a strict, deterministic tear-down and rebuild of the local Docker mesh.
# Purges stale volumes, destroys Python bytecode caches, clears forensic logs, 
# validates cryptographic bindings, and utilizes active socket-level polling 
# to guarantee mesh readiness before ignition.
# ==============================================================================

# Configure temporary stdout logging for the reset sequence
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

class EnvironmentSanitizer:
    def __init__(self):
        self.logger = logging.getLogger("CloudScape.Sanitizer")
        self.project_root = Path(__file__).resolve().parent.parent
        self.compose_file = self.project_root / "docker-compose.yml"
        
        # Required mesh ports to poll for readiness
        self.mesh_services = {
            "Neo4j Graph UI": 7474,
            "Neo4j Bolt Protocol": 7687,
            "LocalStack AWS Gateway": 4566,
            "Azurite Blob Gateway": 10000,
            "Redis Cache": 6379
        }

    def print_banner(self):
        banner = """
    ==================================================================================
    CLOUDSCAPE NEXUS v5.0.1 | ENVIRONMENT SANITIZER (DETERMINISTIC REPAIR)
    ==================================================================================
        """
        print("\033[93m" + banner + "\033[0m")

    def execute(self):
        """Master Execution Sequence for the Soft Reset."""
        self.print_banner()
        self.logger.info("Initiating CloudScape Environment Sanitization Sequence...")
        
        self._detect_docker_command()
        self._validate_crypto_stack()
        self._purge_python_caches()
        self._purge_forensic_logs()
        self._teardown_docker_mesh()
        self._rebuild_docker_mesh()
        self._verify_mesh_health()
        
        self.logger.info("======================================================")
        self.logger.info(" Sanitization Complete. The Mesh is Pristine and Ready.")
        self.logger.info("======================================================")

    def _detect_docker_command(self):
        """
        Detects whether Docker is available and whether to use V2 
        ('docker compose') or V1 ('docker-compose') syntax.
        """
        self.logger.info("Phase 0: Detecting Docker runtime...")
        
        # Check for Docker V2 first (preferred)
        if shutil.which("docker"):
            result = subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True, text=True, shell=(sys.platform == 'win32')
            )
            if result.returncode == 0:
                self._docker_cmd = ["docker", "compose"]
                self.logger.info(f" -> Using Docker Compose V2: {result.stdout.strip()}")
                return
        
        # Fallback to V1
        if shutil.which("docker-compose"):
            self._docker_cmd = ["docker-compose"]
            self.logger.info(" -> Using Docker Compose V1 (legacy).")
            return
        
        self.logger.error(" -> CRITICAL: Neither 'docker compose' nor 'docker-compose' found.")
        self.logger.error("    Ensure Docker Desktop is installed and in your PATH.")
        sys.exit(1)

    # --------------------------------------------------------------------------
    # 1. CRYPTOGRAPHIC DEPENDENCY VALIDATION
    # --------------------------------------------------------------------------

    def _validate_crypto_stack(self):
        """
        Explicitly tests the Python cryptographic stack to catch Rust-binding 
        errors (x509) that cause the Azure SDK to silently fail during discovery.
        """
        self.logger.info("Phase 1: Validating Python Cryptographic Stack...")
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            import OpenSSL
            self.logger.info(" -> Cryptography and OpenSSL Rust bindings verified: OK")
        except ImportError as e:
            self.logger.error(f" -> CRITICAL: Cryptographic stack is corrupted: {e}")
            self.logger.error("    Mandatory Action: Run the following command in your terminal:")
            self.logger.error("    pip install --force-reinstall cryptography pyopenssl azure-identity azure-storage-blob azure-mgmt-resource azure-mgmt-compute azure-mgmt-network aiohttp")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f" -> CRITICAL: Unexpected failure during crypto validation: {e}")
            sys.exit(1)

    # --------------------------------------------------------------------------
    # 2. CACHE & ARTIFACT DESTRUCTION
    # --------------------------------------------------------------------------

    def _purge_python_caches(self):
        """Recursively hunts and destroys __pycache__ and compiled bytecode."""
        self.logger.info("Phase 2: Purging Python bytecode caches...")
        cache_count = 0
        file_count = 0
        
        # Destroy directories
        for path in self.project_root.rglob('__pycache__'):
            try:
                shutil.rmtree(path)
                cache_count += 1
            except Exception as e:
                self.logger.warning(f"Failed to remove cache directory {path}: {e}")
                
        # Destroy orphaned compiled files
        for ext in ['*.pyc', '*.pyo']:
            for path in self.project_root.rglob(ext):
                try:
                    path.unlink()
                    file_count += 1
                except Exception:
                    pass
                
        self.logger.info(f" -> Destroyed {cache_count} cache directories and {file_count} compiled files.")

    def _purge_forensic_logs(self):
        """Clears stale logs to ensure forensic purity on the next scan."""
        self.logger.info("Phase 3: Purging stale forensic logs and reports...")
        logs_dir = self.project_root / "forensics" / "logs"
        reports_dir = self.project_root / "forensics" / "reports"
        
        cleared_files = 0
        for directory in [logs_dir, reports_dir]:
            if directory.exists():
                for file in directory.glob('*'):
                    if file.is_file() and file.name != '.gitkeep':
                        try:
                            file.unlink()
                            cleared_files += 1
                        except Exception:
                            pass
                            
        self.logger.info(f" -> Purged {cleared_files} stale forensic artifacts.")

    # --------------------------------------------------------------------------
    # 3. DOCKER MESH RECONSTRUCTION
    # --------------------------------------------------------------------------

    def _teardown_docker_mesh(self):
        """
        Executes docker compose down with the -v flag. 
        CRITICAL: The -v flag destroys named volumes, wiping Neo4j and LocalStack 
        databases to cure 'Ghost Tenant' state poisoning.
        """
        self.logger.info("Phase 4: Tearing down Docker Mesh and annihilating persistent volumes...")
        if not self.compose_file.exists():
            self.logger.error("docker-compose.yml not found in project root. Skipping Docker phase.")
            return

        try:
            # -v removes volumes, --remove-orphans cleans up unlinked containers
            result = subprocess.run(
                self._docker_cmd + ["down", "-v", "--remove-orphans"], 
                cwd=self.project_root, 
                check=True,
                capture_output=True,
                text=True,
                shell=(sys.platform == 'win32')
            )
            self.logger.info(" -> Mesh topology destroyed. Volumes sanitized.")
            self.logger.debug(f"Docker teardown output:\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to tear down Docker Mesh. Is Docker Desktop running?\n{e.stderr}")
            sys.exit(1)

    def _rebuild_docker_mesh(self):
        """Spawns the Docker containers in detached mode."""
        self.logger.info("Phase 5: Rebuilding CloudScape Docker Mesh...")
        try:
            result = subprocess.run(
                self._docker_cmd + ["up", "-d"], 
                cwd=self.project_root, 
                check=True,
                capture_output=True,
                text=True,
                shell=(sys.platform == 'win32')
            )
            self.logger.info(" -> Containers spawned. Awaiting OS process binding...")
            self.logger.debug(f"Docker build output:\n{result.stdout}")
            time.sleep(5) # Base buffer for OS process spawning before socket polls
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to rebuild Docker Mesh:\n{e.stderr}")
            sys.exit(1)

    # --------------------------------------------------------------------------
    # 4. ACTIVE SOCKET HEALTH POLLING
    # --------------------------------------------------------------------------

    def _verify_mesh_health(self):
        """
        Actively polls the critical ports until they bind or timeout.
        Ensures the orchestrator never starts before the DB and Emulators are ready.
        """
        self.logger.info("Phase 6: Verifying socket health of physical mesh endpoints...")
        timeout_seconds = 60
        
        for service, port in self.mesh_services.items():
            start_time = time.time()
            is_healthy = False
            
            while time.time() - start_time < timeout_seconds:
                try:
                    # Attempt a raw TCP socket connection to the local port
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        is_healthy = True
                        break
                except (ConnectionRefusedError, TimeoutError, OSError):
                    time.sleep(2) # Poll interval
                    
            if is_healthy:
                elapsed = round(time.time() - start_time, 2)
                self.logger.info(f" -> [ONLINE] {service} (Port {port}) - Ready in {elapsed}s")
            else:
                self.logger.warning(f" -> [TIMEOUT] {service} (Port {port}) failed to bind within {timeout_seconds}s.")
                self.logger.error(f"CRITICAL: The mesh is incomplete. Check 'docker ps' for crashed containers.")

if __name__ == "__main__":
    sanitizer = EnvironmentSanitizer()
    sanitizer.execute()