import os
import sys
from rich.console import Console

console = Console()

def verify_setup():
    """Forces the project to stay isolated on D and E."""
    # Check Persistence (E:)
    azure_path = os.getenv('AZURE_CONFIG_DIR', '')
    aws_path = os.getenv('AWS_SHARED_CREDENTIALS_FILE', '')
    
    if not (azure_path.startswith('E:') and aws_path.startswith('E:')):
        console.print("[bold red]!! DATA LEAK PREVENTED !![/bold red]")
        console.print(f"Azure Config: {azure_path}")
        console.print(f"AWS Config: {aws_path}")
        console.print("[yellow]Ensure environment variables point to E: drive before proceeding.[/yellow]")
        sys.exit(1)
        
    # Check Logic (D:)
    current_dir = os.getcwd()
    if not current_dir.startswith('D:'):
        console.print("[bold red]!! WRONG WORKSPACE !![/bold red]")
        console.print("Scripts must be executed from the D: drive project folder.")
        sys.exit(1)
        
    return True