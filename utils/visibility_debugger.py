import sys
import os
import json
import logging
import asyncio
import boto3
from pathlib import Path

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - VISIBILITY DEBUGGER (D2H PROBE)
# ==============================================================================
# Bypasses the Orchestrator to perform direct-to-emulator telemetry probing.
# Used to isolate environment-level blindspots from logic-level filters.
# ==============================================================================

logging.basicConfig(level=logging.INFO, format="%(levelname)-8s | %(message)s")
logger = logging.getLogger("Cloudscape.Debugger")

async def debug_environment():
    print("\n" + "="*80)
    print(" CLOUDSCAPE VISIBILITY DEBUGGER | D2H PROBE SEQUENCE")
    print("="*80 + "\n")

    # --------------------------------------------------------------------------
    # 1. PYTHON ENVIRONMENT DIAGNOSTICS
    # --------------------------------------------------------------------------
    logger.info("PHASE 1: Python Environment & Path Audit")
    logger.info(f"Python Executable: {sys.executable}")
    logger.info(f"Current Venv: {os.getenv('VIRTUAL_ENV', 'NONE')}")
    
    # Check for Azure SDKs
    azure_status = "MISSING"
    try:
        from azure.identity.aio import DefaultAzureCredential
        from azure.storage.blob.aio import BlobServiceClient
        from azure.mgmt.compute import ComputeManagementClient
        azure_status = "INSTALLED & REACHABLE"
    except ImportError as e:
        azure_status = f"FAILED: {e}"
    
    logger.info(f"Azure SDK Status: {azure_status}")
    if "FAILED" in azure_status:
        logger.warning("CRITICAL: Azure discovery will always return 0 until libraries are in the Venv.")

    # --------------------------------------------------------------------------
    # 2. AWS LOCALSTACK PARTITION PROBE
    # --------------------------------------------------------------------------
    logger.info("\nPHASE 2: AWS LocalStack Raw Partition Probe")
    aws_endpoint = "http://localhost:4566"
    
    try:
        # Force the 'testing' credentials used by the MeshSeeder
        session = boto3.Session(
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            region_name="ap-south-1"
        )
        
        sts = session.client('sts', endpoint_url=aws_endpoint)
        identity = sts.get_caller_identity()
        logger.info(f" -> Identity Verified: Account {identity['Account']} | ARN {identity['Arn']}")

        ec2 = session.client('ec2', endpoint_url=aws_endpoint)
        vpcs = ec2.describe_vpcs()['Vpcs']
        logger.info(f" -> Raw VPC Count: {len(vpcs)}")
        for v in vpcs:
            name = next((t['Value'] for t in v.get('Tags', []) if t['Key'] == 'Name'), 'Unnamed')
            tenant = next((t['Value'] for t in v.get('Tags', []) if t['Key'] == 'CloudscapeTenantID'), 'NONE')
            logger.info(f"    [VPC] {v['VpcId']} | Name: {name} | Tenant: {tenant}")

        s3 = session.client('s3', endpoint_url=aws_endpoint)
        buckets = s3.list_buckets()['Buckets']
        logger.info(f" -> Raw S3 Bucket Count: {len(buckets)}")
        for b in buckets:
            logger.info(f"    [S3]  {b['Name']}")

    except Exception as e:
        logger.error(f"AWS Probe Collapsed: {e}")

    # --------------------------------------------------------------------------
    # 3. AZURE AZURITE GATEWAY PROBE
    # --------------------------------------------------------------------------
    logger.info("\nPHASE 3: Azure Azurite Direct Gateway Probe")
    conn_str = (
        "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
        "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
        "BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"
    )

    if "INSTALLED" in azure_status:
        try:
            from azure.storage.blob.aio import BlobServiceClient
            client = BlobServiceClient.from_connection_string(conn_str)
            async with client:
                containers = []
                async for c in client.list_containers():
                    containers.append(c.name)
                logger.info(f" -> Raw Container Count: {len(containers)}")
                for c in containers:
                    logger.info(f"    [CONT] {c}")
        except Exception as e:
            logger.error(f"Azure Probe Collapsed: {e}")
    else:
        logger.warning("Skipping Azure probe due to missing SDKs.")

    print("\n" + "="*80)
    logger.info("D2H Probe Sequence Concluded.")
    print("="*80 + "\n")

if __name__ == "__main__":
    # Handle Windows-specific Proactor event loop errors
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(debug_environment())