import asyncio
import importlib
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Type

from core.config import settings, tenants, TenantConfig
from core.processor.ingestor import GraphIngestor
from core.correlation.trust_resolver import EnterpriseCorrelationEngine

# Configure Enterprise-Grade Logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
)
logger = logging.getLogger("Cloudscape.Orchestrator")

# ==============================================================================
# PROJECT CLOUDSCAPE: INTEGRATED MULTI-TENANT ORCHESTRATOR (FINAL)
# ==============================================================================

class DiscoveryEngineError(Exception):
    """Custom exception for Discovery Engine failures."""
    pass

class DiscoveryOrchestrator:
    """
    Advanced event-driven orchestrator. Implements a multi-threaded producer
    mesh and a transactional consumer to bridge Cloud APIs to Neo4j.
    """

    def __init__(self, tenant_list: List[TenantConfig]):
        self.tenants = tenant_list
        # The Queue buffers data between the Crawlers (Producers) and Ingestor (Consumer)
        self.ingestion_queue: asyncio.Queue = asyncio.Queue()
        self.active_tasks = 0

    def _dynamically_load_engine(self, provider: str) -> Type:
        """DYNAMIC FACTORY: Resolves engine classes at runtime based on provider string."""
        engine_map = {
            "aws": "engines.aws_engine.AWSEngine",
            "azure": "engines.azure_engine.AzureEngine"
        }

        if provider not in engine_map:
            raise ValueError(f"Unsupported cloud provider: {provider}")

        module_path, class_name = engine_map[provider].rsplit(".", 1)
        
        try:
            module = importlib.import_module(module_path)
            engine_class = getattr(module, class_name)
            return engine_class
        except (ImportError, AttributeError) as e:
            logger.error(f"Failed to dynamically load engine for {provider}: {e}")
            raise DiscoveryEngineError(f"Engine resolution failed for {provider}")

    async def _scan_tenant_task(self, tenant: TenantConfig) -> None:
        """THE PRODUCER: Executes the cloud API crawl and queues the forensic state."""
        logger.info(f"Initiating Discovery Mesh for Tenant: {tenant.name} [{tenant.id}]")
        
        try:
            # Resolve engine and run in separate thread to keep asyncio loop responsive
            engine_class = self._dynamically_load_engine(tenant.provider)
            engine_instance = engine_class(tenant)

            loop = asyncio.get_running_loop()
            with ThreadPoolExecutor(max_workers=5) as pool:
                raw_state: Dict[str, Any] = await loop.run_in_executor(
                    pool, engine_instance.run_full_discovery
                )

            # Bundle data with metadata for the correlation logic
            payload = {
                "tenant_metadata": tenant.model_dump(),
                "raw_state": raw_state
            }

            await self.ingestion_queue.put(payload)
            logger.info(f"Scan complete for {tenant.name}. Data queued for Graph Ingestion.")

        except Exception as e:
            logger.error(f"Discovery failed for Tenant {tenant.name} [{tenant.id}]: {str(e)}")
        finally:
            self.active_tasks -= 1

    async def _graph_ingestor_consumer(self) -> None:
        """
        THE CONSUMER: Translates raw JSON into Correlated Graph Edges.
        Includes graceful handling for asyncio cancellation.
        """
        logger.info("Graph Ingestor Consumer started. Waiting for payloads...")
        
        # Initialize the heavy-duty components
        ingestor = GraphIngestor()
        correlator = EnterpriseCorrelationEngine(self.tenants)
        
        while True:
            try:
                # Await a payload from the queue
                payload = await self.ingestion_queue.get()
                
                tenant_meta = TenantConfig(**payload['tenant_metadata'])
                raw_state = payload['raw_state']
                
                logger.info(f"Processing Graph State for {tenant_meta.name}...")

                # 1. RUN CORRELATION ENGINE (Finding Cross-Account Links)
                cross_edges = correlator.extract_mesh_edges(tenant_meta, raw_state)

                # 2. EXECUTE GRAPH INGESTION (Neo4j Write)
                ingestor.ingest_tenant_state(tenant_meta, raw_state, cross_edges)
                
                # 3. Mark the task as done successfully
                self.ingestion_queue.task_done()
                logger.info(f"Successfully committed {tenant_meta.name} to Enterprise Graph.")
                
            except asyncio.CancelledError:
                # Handle the shutdown signal from execute_mesh_scan
                logger.debug("Consumer task received shutdown signal.")
                break
            except Exception as e:
                logger.error(f"Ingestion pipeline failure: {e}")
                # We still mark as done so the queue doesn't hang on failure
                self.ingestion_queue.task_done()

    async def execute_mesh_scan(self):
        """Main entry point. Manages the lifecycle of producers and consumers."""
        logger.info(f"Starting Multi-Tenant Orchestrator. Targets: {len(self.tenants)}")
        
        self.active_tasks = len(self.tenants)
        
        # Start background consumer
        consumer_task = asyncio.create_task(self._graph_ingestor_consumer())

        # Launch parallel scans
        scan_tasks = [
            asyncio.create_task(self._scan_tenant_task(tenant)) 
            for tenant in self.tenants
        ]

        # Wait for all producers to finish their API crawls
        await asyncio.gather(*scan_tasks)

        # Wait for the consumer to finish processing all queued items
        await self.ingestion_queue.join()

        # Shutdown consumer gracefully
        consumer_task.cancel()
        try:
            await consumer_task
        except asyncio.CancelledError:
            pass
            
        logger.info("Enterprise Mesh Discovery and Graph Correlation Complete.")

if __name__ == "__main__":
    orchestrator = DiscoveryOrchestrator(tenants)
    asyncio.run(orchestrator.execute_mesh_scan())