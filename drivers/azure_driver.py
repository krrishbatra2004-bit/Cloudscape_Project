import os
import json
from azure.identity import DefaultAzureCredential, AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from rich.console import Console

console = Console()

class AzureScraper:
    def __init__(self):
        self.persistence_path = "E:/Cloudscape_Data/manifests"
        os.makedirs(self.persistence_path, exist_ok=True)
        
        # Identity Logic: Use CLI first for Student Accounts
        try:
            self.credential = AzureCliCredential()
            # Subscription ID from your 'az login' output
            self.subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "dd674fe3-337c-4cae-871b-9d6774f91a25")
            
            # Clients for Resource Groups and VMs
            self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
            self.compute_client = ComputeManagementClient(self.credential, self.subscription_id)
        except Exception as e:
            console.print(f"[bold red]Critical Auth Failure:[/bold red] {str(e)}")
            raise

    def fetch_all_resources(self):
        inventory = {
            "resource_groups": [],
            "virtual_machines": []
        }

        try:
            console.print("[cyan]→ Scanning Azure Resource Groups...[/cyan]")
            for rg in self.resource_client.resource_groups.list():
                inventory["resource_groups"].append({
                    "name": rg.name,
                    "id": rg.id,
                    "location": rg.location,
                    "tags": rg.tags or {}
                })

            console.print("[cyan]→ Scanning Azure Virtual Machines...[/cyan]")
            for vm in self.compute_client.virtual_machines.list_all():
                inventory["virtual_machines"].append({
                    "name": vm.name,
                    "id": vm.id,
                    "location": vm.location,
                    "size": vm.hardware_profile.vm_size,
                    "os": vm.storage_profile.os_disk.os_type.value
                })

            # Save full advanced manifest to E: Drive
            output_file = f"{self.persistence_path}/azure_inventory.json"
            with open(output_file, "w") as f:
                json.dump(inventory, f, indent=4)
            
            console.print(f"[bold green]✔ Azure Scan Complete.[/bold green] Saved {len(inventory['resource_groups'])} RGs and {len(inventory['virtual_machines'])} VMs.")
            
        except Exception as e:
            console.print(f"[bold red]Azure Ingestion Error:[/bold red] {str(e)}")

if __name__ == "__main__":
    # Unit test for the driver
    scraper = AzureScraper()
    scraper.fetch_all_resources()