import boto3
import json
from rich.console import Console

console = Console()

def get_client(service):
    """Helper to get a boto3 client pointing to LocalStack"""
    return boto3.client(
        service,
        endpoint_url="http://localhost:4566",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1"
    )

def seed_network_and_compute():
    console.print("[cyan]→ Provisioning Network & Compute...[/cyan]")
    try:
        ec2 = get_client('ec2')
        elb = get_client('elbv2')
        r53 = get_client('route53')
        apigw = get_client('apigateway')

        # VPC & Subnets
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']
        vpc_id = vpc['VpcId']
        subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock='10.0.1.0/24')['Subnet']
        subnet_id = subnet['SubnetId']
        
        # EC2 Instances
        ec2.run_instances(ImageId='ami-12345', MinCount=3, MaxCount=3, InstanceType='t3.micro', SubnetId=subnet_id)
        
        # Load Balancer
        elb.create_load_balancer(Name='Cloudscape-ALB', Subnets=[subnet_id])
        
        # Route53 Zone
        r53.create_hosted_zone(Name='cloudscape.local', CallerReference='midsem-demo')
        
        # API Gateway
        apigw.create_rest_api(name='Cloudscape-Core-API', description='Main ingress API')
        console.print("[green]✔ Network & Compute (VPC, EC2, ELB, Route53, API GW) seeded.[/green]")
    except Exception as e:
        console.print(f"[red]✘ Network/Compute Error: {e}[/red]")

def seed_storage_and_containers():
    console.print("[cyan]→ Provisioning Storage & Containers...[/cyan]")
    try:
        s3 = get_client('s3')
        ecr = get_client('ecr')
        ecs = get_client('ecs')

        # S3 Buckets (Simulating standard and Glacier classes)
        s3.create_bucket(Bucket="cloudscape-data-lake")
        s3.create_bucket(Bucket="cloudscape-glacier-archive")
        
        # ECR Registry
        ecr.create_repository(repositoryName='cloudscape-microservices')
        
        # ECS Cluster
        ecs.create_cluster(clusterName='Cloudscape-Fargate-Cluster')
        console.print("[green]✔ Storage & Containers (S3, ECR, ECS) seeded.[/green]")
    except Exception as e:
        console.print(f"[red]✘ Storage/Containers Error: {e}[/red]")

def seed_databases():
    console.print("[cyan]→ Provisioning Databases...[/cyan]")
    try:
        ddb = get_client('dynamodb')
        rds = get_client('rds')
        elasticache = get_client('elasticache')

        # DynamoDB
        ddb.create_table(
            TableName='Cloudscape-AppSync-Data',
            KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST'
        )
        
        # RDS (Mocking an Aurora cluster creation)
        rds.create_db_cluster(
            DBClusterIdentifier='cloudscape-aurora-cluster',
            Engine='aurora-postgresql',
            MasterUsername='admin',
            MasterUserPassword='supersecretpassword'
        )

        # ElastiCache (Redis)
        elasticache.create_cache_cluster(
            CacheClusterId='cloudscape-redis',
            Engine='redis',
            NumCacheNodes=1,
            CacheNodeType='cache.t2.micro'
        )
        console.print("[green]✔ Databases (DynamoDB, RDS Aurora, ElastiCache) seeded.[/green]")
    except Exception as e:
        console.print(f"[red]✘ Database Error: {e}[/red]")

def seed_integration_and_analytics():
    console.print("[cyan]→ Provisioning App Integration & Analytics...[/cyan]")
    try:
        sqs = get_client('sqs')
        sns = get_client('sns')
        kinesis = get_client('kinesis')
        events = get_client('events') # EventBridge
        lmb = get_client('lambda')

        # SQS & SNS
        sqs.create_queue(QueueName='Analytics-Processing-Queue')
        sns.create_topic(Name='Cloudscape-Alerts')
        
        # Kinesis Data Stream
        kinesis.create_stream(StreamName='Cloudscape-Clickstream', ShardCount=1)
        
        # EventBridge Bus
        events.create_event_bus(Name='Cloudscape-Enterprise-Bus')

        console.print("[green]✔ Integration & Analytics (SQS, SNS, Kinesis, EventBridge) seeded.[/green]")
    except Exception as e:
        console.print(f"[red]✘ Integration/Analytics Error: {e}[/red]")

def run_mega_seed():
    console.print("[bold yellow]--- INITIATING PROJECT CLOUDSCAPE MEGA-SEED ---[/bold yellow]")
    seed_network_and_compute()
    seed_storage_and_containers()
    seed_databases()
    seed_integration_and_analytics()
    console.print("[bold green]--- MEGA-SEED COMPLETE: CLOUDSCAPE IS ALIVE ---[/bold green]")

if __name__ == "__main__":
    run_mega_seed()