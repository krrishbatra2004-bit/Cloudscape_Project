import asyncio
import logging
import traceback
from typing import Any, Dict, List

# ==============================================================================
# SPLIT-PLANE DEPENDENCY INJECTION
# Isolates the Data Plane (Storage) from the Control Plane (ARM Management).
# Prevents total engine failure in MOCK mode if ARM SDKs are corrupted.
# ==============================================================================

# 1. Data Plane SDKs (Required for MOCK / Azurite)
try:
    from azure.storage.blob.aio import BlobServiceClient
    from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
except ImportError:
    BlobServiceClient = None

# 2. Control Plane SDKs (Required for PROPER / ARM)
try:
    from azure.identity.aio import DefaultAzureCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.core.exceptions import ClientAuthenticationError
except ImportError:
    DefaultAzureCredential = None
    ResourceManagementClient = ComputeManagementClient = NetworkManagementClient = None

from engines.base_engine import BaseDiscoveryEngine
from core.config import config, TenantConfig

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - ENTERPRISE AZURE DISCOVERY ENGINE (TITAN FULL)
# ==============================================================================
# Dual-Mode extraction engine. Natively routes to Azurite in MOCK mode or 
# Global ARM endpoints in PROPER mode. Implements deterministic async consumption, 
# Tenant Isolation Filtering, vulnerability heuristics, and state hashing.
# ==============================================================================

class AzureEngine(BaseDiscoveryEngine):
    def __init__(self, tenant: TenantConfig):
        super().__init__(tenant)
        self.logger = logging.getLogger(f"Cloudscape.Engines.Azure.[{self.tenant.id}]")
        
        # Fetch the abstracted connection parameters from the parent Gateway
        self.conn_params = self.get_azure_connection_parameters()
        self.is_mock = self.conn_params.get("is_mock", False)
        self.credential = None

    # --------------------------------------------------------------------------
    # ISOLATION & GATEWAY MECHANISMS
    # --------------------------------------------------------------------------

    async def _verify_tenant_ownership(self, resource_name: str, metadata: Dict[str, Any]) -> bool:
        """
        The Tenant Isolation Filter (Case-Insensitive).
        Inspects resource metadata to ensure they belong to the current executing tenant.
        Shields the graph from stale emulator state and cross-tenant contamination.
        """
        if not self.is_mock:
            # In proper mode, Subscription RBAC inherently provides isolation
            return True
            
        # 1. Check Metadata (Azure metadata dictionaries are usually flat string:string)
        if metadata:
            for k, v in metadata.items():
                if str(k).lower() == 'cloudscapetenantid' and str(v).lower() == self.tenant.id.lower():
                    return True
                    
        # 2. Last Resort Fallback (Semantic Name matching)
        if self.tenant.id.lower() in resource_name.lower():
            return True
            
        return False

    async def test_connection(self) -> bool:
        """Validates Authentication & Access using the dynamic Base Gateway routing."""
        self.logger.info("Testing Azure Authentication & Access Gateway...")
        
        try:
            if self.is_mock:
                if BlobServiceClient is None:
                    self.logger.error("Azure Storage SDK missing. Azurite mock extraction cannot proceed.")
                    return False
                    
                self.logger.debug("MOCK Mode: Validating Azurite local endpoints.")
                conn_str = self.conn_params.get("connection_string")
                blob_service_client = BlobServiceClient.from_connection_string(conn_str)
                
                # Test connectivity by initiating an HTTP session to the gateway
                async with blob_service_client:
                    container_iter = blob_service_client.list_containers(results_per_page=1)
                    await self.execute_with_backoff(container_iter.__anext__)
                    
                self.tenant.credentials.azure_subscription_id = "mock-azure-sub-0001"
                self.logger.info("Azurite Gateway Handshake Verified.")
                return True
                
            else:
                if DefaultAzureCredential is None:
                    self.logger.error("Azure ARM SDKs missing. PROPER mode extraction cannot proceed.")
                    return False
                    
                self.logger.debug("PROPER Mode: Validating Azure Resource Manager (ARM) via DefaultAzureCredential.")
                self.credential = DefaultAzureCredential()
                
                async with self.credential:
                    token = await self.execute_with_backoff(self.credential.get_token, "https://management.azure.com/.default")
                    if not token:
                        return False
                
                if not self.tenant.credentials.azure_subscription_id:
                    self.logger.info("No explicit Subscription ID provided. Resolving via ARM...")
                    sub_client = ResourceManagementClient(credential=self.credential, subscription_id="00000000-0000-0000-0000-000000000000")
                    subs = await asyncio.to_thread(list, sub_client.subscriptions.list())
                    if subs:
                        self.tenant.credentials.azure_subscription_id = subs[0].subscription_id
                        self.logger.info(f"Target Azure Subscription Resolved: {self.tenant.credentials.azure_subscription_id}")
                    else:
                        self.logger.error("No Azure Subscriptions found for this identity.")
                        return False

                self.logger.info("ARM Gateway Handshake Verified.")
                return True
                
        except StopAsyncIteration:
            # Expected if Azurite is genuinely empty but connectivity is proven
            self.tenant.credentials.azure_subscription_id = "mock-azure-sub-0001"
            self.logger.info("Azurite Gateway Handshake Verified (Empty Mesh).")
            return True
        except ClientAuthenticationError as auth_err:
            self.logger.error(f"Azure ARM Authentication Failed: {auth_err}")
            return False
        except Exception as e:
            self.logger.error(f"Azure Connectivity Failed. Pipeline halted for this tenant: {e}")
            return False

    # --------------------------------------------------------------------------
    # CORE DISCOVERY ORCHESTRATION
    # --------------------------------------------------------------------------

    async def discover(self) -> List[Dict[str, Any]]:
        """
        The Master Extraction Orchestrator.
        Forces the Titan Baseline registry if configuration is empty to prevent scan starvation.
        """
        self.logger.info(f"[{self.tenant.id}] Initiating Azure Telemetry Extraction...")
        total_payloads = []
        
        # Registry Hard-Coding (Forces baseline if settings.yaml is missing or empty)
        reg = getattr(config, 'service_registry', {}).get("azure", {})
        if not reg:
            self.logger.debug(f"[{self.tenant.id}] Registry starvation detected. Injecting Titan Baseline.")
            reg = {
                "storage_container": {"baseline_risk_score": 0.3},
                "storage_blob": {"baseline_risk_score": 0.5},
                "virtual_machine": {"baseline_risk_score": 0.6},
                "virtual_network": {"baseline_risk_score": 0.1},
                "network_security_group": {"baseline_risk_score": 0.2}
            }

        tasks = []
        
        if self.is_mock:
            self.logger.debug("MOCK Mode active: Engaging Local Azurite deep extraction sequence.")
            if "storage_container" in reg and BlobServiceClient is not None:
                tasks.append(self._extract_azurite_storage(
                    container_risk=reg["storage_container"].get("baseline_risk_score", 0.3),
                    blob_risk=reg["storage_blob"].get("baseline_risk_score", 0.5)
                ))
        else:
            self.logger.debug("PROPER Mode active: Engaging Global ARM telemetry extraction.")
            sub_id = self.tenant.credentials.azure_subscription_id
            
            if DefaultAzureCredential is not None:
                if "virtual_machine" in reg:
                    tasks.append(self._extract_virtual_machines(sub_id, reg["virtual_machine"].get("baseline_risk_score", 0.6)))
                if "virtual_network" in reg:
                    tasks.append(self._extract_virtual_networks(sub_id, reg["virtual_network"].get("baseline_risk_score", 0.1)))
                if "network_security_group" in reg:
                    tasks.append(self._extract_network_security_groups(sub_id, reg["network_security_group"].get("baseline_risk_score", 0.2)))

        # Parallel Execution Matrix
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"A core Azure extraction task failed catastrophically: {result}")
                self.logger.debug(traceback.format_exc())
            elif result:
                total_payloads.extend(result)

        self.logger.info(f"[{self.tenant.id}] Azure Discovery Cycle Complete. Extracted {len(total_payloads)} nodes.")
        return total_payloads

    # ==========================================================================
    # AZURITE DEEP EXTRACTION (PATH A)
    # ==========================================================================

    async def _extract_azurite_storage(self, container_risk: float, blob_risk: float) -> List[Dict]:
        """
        Recursively traverses Azurite to extract Storage Containers and physical Blobs.
        Implements Deterministic Async Consumption to prevent silent iterator exhaustion.
        """
        payloads = []
        conn_str = self.conn_params.get("connection_string")
        sub_id = self.tenant.credentials.azure_subscription_id or "unknown"
        
        try:
            blob_service_client = BlobServiceClient.from_connection_string(conn_str)
            
            async with blob_service_client:
                # 1. Deterministic Extraction of Containers
                container_iter = blob_service_client.list_containers(include_metadata=True)
                containers = []
                async for c in container_iter:
                    containers.append(c)
                
                for container in containers:
                    c_name = container.name
                    c_metadata = container.metadata or {}
                    
                    is_owner = await self._verify_tenant_ownership(c_name, c_metadata)
                    if not is_owner:
                        continue
                        
                    c_arn = f"/subscriptions/{sub_id}/resourceGroups/mock-rg/providers/Microsoft.Storage/storageAccounts/devstoreaccount1/blobServices/default/containers/{c_name}"
                    
                    # Container Vulnerability Heuristics
                    c_risk = container_risk
                    c_tags = []
                    if container.public_access:
                        c_tags.append({"Key": "Exposure", "Value": f"Public-{container.public_access}"})
                        c_risk += 0.3
                        
                    c_data = {"Name": c_name, "Tags": c_tags, "Metadata": c_metadata}
                    has_changed, state_hash = await self.check_state_differential(c_arn, c_data)
                    
                    if has_changed:
                        c_data["_state_hash"] = state_hash
                        payload = self.format_urm_payload("storage", "StorageContainer", c_arn, c_data, c_risk)
                        payload["cloud_provider"] = "azure"
                        payloads.append(payload)
                        
                    # 2. Deterministic Extraction of Blobs within the Container
                    container_client = blob_service_client.get_container_client(c_name)
                    blob_iter = container_client.list_blobs(include=['metadata'])
                    blobs = []
                    async for b in blob_iter:
                        blobs.append(b)
                    
                    for blob in blobs:
                        b_name = blob.name
                        b_arn = f"{c_arn}/blobs/{b_name}"
                        b_metadata = blob.metadata or {}
                        
                        b_tags = []
                        b_risk = blob_risk
                        
                        # Blob Payload Heuristics
                        if "pci" in b_name.lower() or "billing" in b_name.lower():
                            b_tags.append({"Key": "DataClassification", "Value": "Restricted"})
                            b_risk += 0.4
                        if "tfstate" in b_name.lower():
                            b_tags.append({"Key": "Infrastructure", "Value": "StateFile"})
                            b_risk += 0.4
                            
                        b_data = {
                            "Name": b_name, 
                            "Tags": b_tags, 
                            "Metadata": b_metadata,
                            "Size": blob.size,
                            "ContentType": blob.content_settings.content_type if blob.content_settings else "unknown"
                        }
                        
                        b_has_changed, b_state_hash = await self.check_state_differential(b_arn, b_data)
                        if b_has_changed:
                            b_data["_state_hash"] = b_state_hash
                            b_payload = self.format_urm_payload("storage", "StorageBlob", b_arn, b_data, min(b_risk, 1.0))
                            b_payload["cloud_provider"] = "azure"
                            payloads.append(b_payload)

            return payloads
            
        except Exception as e:
            self.logger.error(f"Azure Azurite Storage extraction failed: {e}")
            self.logger.debug(traceback.format_exc())
            return []

    # ==========================================================================
    # GLOBAL ARM DEEP EXTRACTION (PATH B)
    # ==========================================================================

    async def _extract_virtual_machines(self, subscription_id: str, risk: float) -> List[Dict]:
        """Extracts Azure Virtual Machines via ARM compute client."""
        payloads = []
        try:
            client = ComputeManagementClient(credential=self.credential, subscription_id=subscription_id)
            
            def fetch_vms():
                return list(client.virtual_machines.list_all())
                
            vms = await self.execute_with_backoff(asyncio.to_thread, fetch_vms)
            
            for vm in vms:
                arn = vm.id
                vm_dict = vm.as_dict()
                
                vm_risk = risk
                if not vm_dict.get('network_profile', {}).get('network_interfaces'):
                    vm_dict.setdefault("tags", {})["NetworkState"] = "Orphaned"
                
                has_changed, state_hash = await self.check_state_differential(arn, vm_dict)
                if has_changed:
                    vm_dict["_state_hash"] = state_hash
                    payload = self.format_urm_payload("compute", "VirtualMachine", arn, vm_dict, min(vm_risk, 1.0))
                    payload["cloud_provider"] = "azure"
                    payloads.append(payload)
                    
            return payloads
        except Exception as e:
            self.logger.error(f"ARM Virtual Machine extraction failed: {e}")
            return []

    async def _extract_virtual_networks(self, subscription_id: str, risk: float) -> List[Dict]:
        """Extracts Azure VNets and Subnets via ARM network client."""
        payloads = []
        try:
            client = NetworkManagementClient(credential=self.credential, subscription_id=subscription_id)
            
            def fetch_vnets():
                return list(client.virtual_networks.list_all())
                
            vnets = await self.execute_with_backoff(asyncio.to_thread, fetch_vnets)
            
            for vnet in vnets:
                arn = vnet.id
                vnet_dict = vnet.as_dict()
                
                has_changed, state_hash = await self.check_state_differential(arn, vnet_dict)
                if has_changed:
                    vnet_dict["_state_hash"] = state_hash
                    payload = self.format_urm_payload("network", "VirtualNetwork", arn, vnet_dict, risk)
                    payload["cloud_provider"] = "azure"
                    payloads.append(payload)
                    
                for subnet in vnet_dict.get('subnets', []):
                    sub_arn = subnet.get('id')
                    sub_risk = risk
                    
                    if not subnet.get('network_security_group'):
                        subnet.setdefault("tags", {})["Security"] = "Unprotected"
                        sub_risk += 0.3
                        
                    s_has_changed, s_state_hash = await self.check_state_differential(sub_arn, subnet)
                    if s_has_changed:
                        subnet["_state_hash"] = s_state_hash
                        s_payload = self.format_urm_payload("network", "Subnet", sub_arn, subnet, min(sub_risk, 1.0))
                        s_payload["cloud_provider"] = "azure"
                        payloads.append(s_payload)
                        
            return payloads
        except Exception as e:
            self.logger.error(f"ARM Virtual Network extraction failed: {e}")
            return []

    async def _extract_network_security_groups(self, subscription_id: str, risk: float) -> List[Dict]:
        """Extracts Azure NSGs and evaluates deep inbound port exposure rules."""
        payloads = []
        try:
            client = NetworkManagementClient(credential=self.credential, subscription_id=subscription_id)
            
            def fetch_nsgs():
                return list(client.network_security_groups.list_all())
                
            nsgs = await self.execute_with_backoff(asyncio.to_thread, fetch_nsgs)
            
            for nsg in nsgs:
                arn = nsg.id
                nsg_dict = nsg.as_dict()
                nsg_risk = risk
                
                for rule in nsg_dict.get('security_rules', []):
                    if rule.get('direction') == 'Inbound' and rule.get('access') == 'Allow':
                        port = rule.get('destination_port_range')
                        if port in ['22', '3389', 'Any', '*']:
                            nsg_dict.setdefault("tags", {})["Exposure"] = "CriticalPortOpen"
                            nsg_risk += 0.5
                            break
                            
                has_changed, state_hash = await self.check_state_differential(arn, nsg_dict)
                if has_changed:
                    nsg_dict["_state_hash"] = state_hash
                    payload = self.format_urm_payload("network", "NetworkSecurityGroup", arn, nsg_dict, min(nsg_risk, 1.0))
                    payload["cloud_provider"] = "azure"
                    payloads.append(payload)
                    
            return payloads
        except Exception as e:
            self.logger.error(f"ARM NSG extraction failed: {e}")
            return []