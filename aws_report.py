#!/usr/bin/env python3
"""
-----------------------------------------------------------------------
Scans ALL AWS services 
- Resource Name
- Resource Type
- Essential Details
- Monthly Cost (aggregated in a separate sheet)


"""

import pandas as pd
import boto3
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError
import sys

# ----------- CONFIG ---------------------------------------------------

REGION = "us-east-2"
# -----------------------------------------------------------------------------

class ComprehensiveAWSScanner:
    """Comprehensive AWS scanner - ALL services, essential info only"""

    def __init__(self, access_key: str, secret_key: str, session_token: str = None):
        try:
            self.session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
                region_name=REGION
            )
            self.region = REGION
            self.all_resources = []
            self.costs_data = []
            self.account_id = self._get_account_id()
            print(f"✅ Scanning AWS Account ID: {self.account_id}")
            print(f"✅ Scanning ALL AWS services in: {self.region}")
        except Exception as e:
            print(f"❌ Failed to initialize: {e}")
            raise

    def _get_account_id(self):
        """Retrieves the AWS account ID using STS get_caller_identity."""
        try:
            # Added verify=False to bypass SSL check for STS client
            sts = self.session.client('sts', verify=False)
            identity = sts.get_caller_identity()
            return identity.get('Account', 'Unknown')
        except Exception as e:
            print(f"❌ Credential issue: {e}")
            raise

    def _add_resource(self, service_name, resource_type, name, details=""):
        """Add resource to the list"""
        self.all_resources.append({
            'Service': service_name,
            'Type': resource_type,
            'Name': name,
            'Details': details,
            'Region': self.region
        })

    def _get_tag_name(self, resource, default_name="Unnamed"):
        """Extract Name tag"""
        tags = resource.get('Tags', [])
        for tag in tags:
            if tag.get('Key') == 'Name':
                return tag.get('Value', default_name)
        return default_name

    def get_aws_monthly_costs(self):
        """
        Retrieves aggregated AWS costs for the previous month using Cost Explorer.
        This function should be run from a region where Cost Explorer is enabled (e.g., us-east-1).
        It's not designed to give per-resource costs.
        """
        print("💰 Fetching monthly cost data...")
        costs = []
        try:
            # Added verify=False to bypass SSL check for Cost Explorer client
            ce_client = self.session.client('ce', region_name='us-east-1', verify=False)

            # Define time period for the last full month
            end_date = datetime.now().replace(day=1).strftime('%Y-%m-%d')
            start_date = (datetime.now().replace(day=1) - timedelta(days=1)).replace(day=1).strftime('%Y-%m-%d')

            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date,
                    'End': end_date
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {'Type': 'DIMENSION', 'Key': 'SERVICE'},
                    {'Type': 'DIMENSION', 'Key': 'REGION'}
                ]
            )

            for result_by_time in response.get('ResultsByTime', []):
                for group in result_by_time.get('Groups', []):
                    service = group['Keys'][0]
                    region = group['Keys'][1]
                    amount = float(group['Metrics']['UnblendedCost']['Amount'])
                    unit = group['Metrics']['UnblendedCost']['Unit']
                    
                    
                    if region == self.region:
                         costs.append({
                             'Service': service,
                             'Region': region,
                             'Cost': amount,
                             'Unit': unit,
                             'TimePeriod': f"{result_by_time['TimePeriod']['Start']} to {result_by_time['TimePeriod']['End']}"
                         })

            print(f"✅ Collected cost data for period {start_date} to {end_date}.")
            self.costs_data = costs

        except ClientError as e:
            if "AccessDenied" in str(e):
                print(f"   ❌ Access denied for Cost Explorer. Please add 'ce:GetCostAndUsage' permission.")
            else:
                print(f"   ❌ Error collecting cost data: {e.response.get('Error', {}).get('Code', 'Unknown')}")
        except Exception as e:
            print(f"   ❌ Unexpected error collecting cost data: {e}")

    def scan_all_services(self):
        """Scan all AWS services"""
        print(f"\n🚀 Scanning ALL AWS services in {self.region}...")
        
        # 1. COMPUTE SERVICES
        self._scan_ec2()
        self._scan_ecr()
        self._scan_lambda()
        self._scan_ecs()
        self._scan_eks()
        self._scan_batch()
        
        # 2. STORAGE SERVICES
        self._scan_s3()
        self._scan_efs()
        self._scan_fsx()
        
        # 3. DATABASE SERVICES
        self._scan_rds()
        self._scan_dynamodb()
        self._scan_elasticache()
        self._scan_redshift()
        self._scan_documentdb()
        self._scan_neptune()
        
        # 4. NETWORKING SERVICES
        self._scan_load_balancers()
        self._scan_api_gateway()
        self._scan_cloudfront()
        self._scan_route53()
        
        # 5. MESSAGING SERVICES
        self._scan_sns()
        self._scan_sqs()
        self._scan_mq()
        
        # 6. ANALYTICS SERVICES
        self._scan_kinesis()
        self._scan_emr()
        self._scan_glue()
        self._scan_athena()
        
        # 7. MACHINE LEARNING
        self._scan_sagemaker()
        
        # 8. SECURITY SERVICES
        self._scan_iam()
        self._scan_kms()
        self._scan_secrets_manager()
        self._scan_acm()
        
        # 9. MANAGEMENT SERVICES
        self._scan_cloudwatch()
        self._scan_cloudformation()
        self._scan_systems_manager()
        self._scan_config()
        
        # 10. DEVELOPER SERVICES
        self._scan_codecommit()
        self._scan_codebuild()
        self._scan_codedeploy()
        self._scan_codepipeline()
        
        # 11. IOT SERVICES
        self._scan_iot()
        
        print(f"✅ Completed scanning all services!")

    def _scan_ec2(self):
        """EC2 - Only instances and volumes"""
        try:
            print("📊 Scanning EC2...")
            # Added verify=False
            ec2 = self.session.client('ec2', region_name=self.region, verify=False)
            
            # EC2 Instances only
            response = ec2.describe_instances()
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    name = self._get_tag_name(instance)
                    self._add_resource('EC2', 'Instance', 
                                       f"{name} ({instance.get('InstanceId', 'Unknown')})",
                                       f"{instance.get('InstanceType', 'Unknown')} - {instance.get('State', {}).get('Name', 'Unknown')}")
            
            # EBS Volumes only
            response = ec2.describe_volumes()
            for volume in response.get('Volumes', []):
                name = self._get_tag_name(volume)
                self._add_resource('EC2', 'Volume',
                                   f"{name} ({volume.get('VolumeId', 'Unknown')})",
                                   f"{volume.get('Size', 0)}GB - {volume.get('State', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ EC2 error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_ecr(self):
        """ECR - Repositories"""
        try:
            print("📊 Scanning ECR...")
            # Added verify=False
            ecr = self.session.client('ecr', region_name=self.region, verify=False)
            
            # Repositories
            response = ecr.describe_repositories()
            for repo in response.get('repositories', []):
                self._add_resource('ECR', 'Repository',
                                   repo.get('repositoryName', 'Unknown'),
                                   f"Scan: {repo.get('imageScanningConfiguration', {}).get('scanOnPush', False)}, Tag: {repo.get('imageTagMutability', 'N/A')}")
                                   
        except ClientError as e:
            print(f"   ❌ ECR error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_lambda(self):
        """Lambda Functions"""
        try:
            print("📊 Scanning Lambda...")
            # Added verify=False
            lambda_client = self.session.client('lambda', region_name=self.region, verify=False)
            
            response = lambda_client.list_functions()
            for func in response.get('Functions', []):
                self._add_resource('Lambda', 'Function',
                                   func.get('FunctionName', 'Unknown'),
                                   f"{func.get('Runtime', 'Unknown')} - {func.get('MemorySize', 0)}MB")
                                   
        except ClientError as e:
            print(f"   ❌ Lambda error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_ecs(self):
        """ECS Clusters and Services"""
        try:
            print("📊 Scanning ECS...")
            # Added verify=False
            ecs = self.session.client('ecs', region_name=self.region, verify=False)
            
            # Clusters
            response = ecs.list_clusters()
            for cluster_arn in response.get('clusterArns', []):
                cluster_name = cluster_arn.split('/')[-1]
                self._add_resource('ECS', 'Cluster', cluster_name, 'ECS Cluster')
                
                # Services in cluster
                try:
                    services_resp = ecs.list_services(cluster=cluster_arn)
                    for service_arn in services_resp.get('serviceArns', []):
                        service_name = service_arn.split('/')[-1]
                        self._add_resource('ECS', 'Service', service_name, f'Service in {cluster_name}')
                except:
                    pass
                    
        except ClientError as e:
            print(f"   ❌ ECS error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_eks(self):
        """EKS Clusters"""
        try:
            print("📊 Scanning EKS...")
            # Added verify=False
            eks = self.session.client('eks', region_name=self.region, verify=False)
            
            response = eks.list_clusters()
            for cluster_name in response.get('clusters', []):
                self._add_resource('EKS', 'Cluster', cluster_name, 'Kubernetes Cluster')
                
        except ClientError as e:
            print(f"   ❌ EKS error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_batch(self):
        """AWS Batch"""
        try:
            print("📊 Scanning Batch...")
            # Added verify=False
            batch = self.session.client('batch', region_name=self.region, verify=False)
            
            # Job Queues
            response = batch.describe_job_queues()
            for queue in response.get('jobQueues', []):
                self._add_resource('Batch', 'Job Queue', queue.get('jobQueueName', 'Unknown'),
                                   queue.get('state', 'Unknown'))
                                   
        except ClientError as e:
            print(f"   ❌ Batch error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_s3(self):
        """S3 Buckets"""
        try:
            print("📊 Scanning S3...")
            # Added verify=False
            s3 = self.session.client('s3', region_name='us-east-1', verify=False)  # S3 is global
            
            response = s3.list_buckets()
            for bucket in response.get('Buckets', []):
                self._add_resource('S3', 'Bucket', bucket.get('Name', 'Unknown'),
                                   f"Created: {str(bucket.get('CreationDate', ''))[:10]}")
                                   
        except ClientError as e:
            print(f"   ❌ S3 error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_efs(self):
        """EFS File Systems"""
        try:
            print("📊 Scanning EFS...")
            # Added verify=False
            efs = self.session.client('efs', region_name=self.region, verify=False)
            
            response = efs.describe_file_systems()
            for fs in response.get('FileSystems', []):
                name = fs.get('Name', self._get_tag_name(fs))
                self._add_resource('EFS', 'File System', 
                                   f"{name} ({fs.get('FileSystemId', 'Unknown')})",
                                   f"{fs.get('PerformanceMode', 'Unknown')} - {fs.get('LifeCycleState', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ EFS error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_fsx(self):
        """FSx File Systems"""
        try:
            print("📊 Scanning FSx...")
            # Added verify=False
            fsx = self.session.client('fsx', region_name=self.region, verify=False)
            
            response = fsx.describe_file_systems()
            for fs in response.get('FileSystems', []):
                name = self._get_tag_name(fs)
                self._add_resource('FSx', 'File System',
                                   f"{name} ({fs.get('FileSystemId', 'Unknown')})",
                                   f"{fs.get('FileSystemType', 'Unknown')} - {fs.get('Lifecycle', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ FSx error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_rds(self):
        """RDS Instances and Clusters"""
        try:
            print("📊 Scanning RDS...")
            # Added verify=False
            rds = self.session.client('rds', region_name=self.region, verify=False)
            
            # RDS Instances
            response = rds.describe_db_instances()
            for db in response.get('DBInstances', []):
                self._add_resource('RDS', 'Instance',
                                   db.get('DBInstanceIdentifier', 'Unknown'),
                                   f"{db.get('DBInstanceClass', 'Unknown')} - {db.get('Engine', 'Unknown')}")
            
            # RDS Clusters
            response = rds.describe_db_clusters()
            for cluster in response.get('DBClusters', []):
                self._add_resource('RDS', 'Cluster',
                                   cluster.get('DBClusterIdentifier', 'Unknown'),
                                   f"{cluster.get('Engine', 'Unknown')} - {cluster.get('Status', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ RDS error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_dynamodb(self):
        """DynamoDB Tables"""
        try:
            print("📊 Scanning DynamoDB...")
            # Added verify=False
            dynamodb = self.session.client('dynamodb', region_name=self.region, verify=False)
            
            response = dynamodb.list_tables()
            for table_name in response.get('TableNames', []):
                try:
                    table_info = dynamodb.describe_table(TableName=table_name)
                    table = table_info['Table']
                    billing_mode = table.get('BillingModeSummary', {}).get('BillingMode', 'Unknown')
                    self._add_resource('DynamoDB', 'Table', table_name,
                                       f"{table.get('TableStatus', 'Unknown')} - {billing_mode}")
                except:
                    self._add_resource('DynamoDB', 'Table', table_name, 'Table')
                    
        except ClientError as e:
            print(f"   ❌ DynamoDB error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_elasticache(self):
        """ElastiCache Clusters"""
        try:
            print("📊 Scanning ElastiCache...")
            # Added verify=False
            elasticache = self.session.client('elasticache', region_name=self.region, verify=False)
            
            # Cache Clusters
            response = elasticache.describe_cache_clusters()
            for cluster in response.get('CacheClusters', []):
                self._add_resource('ElastiCache', 'Cache Cluster',
                                   cluster.get('CacheClusterId', 'Unknown'),
                                   f"{cluster.get('Engine', 'Unknown')} - {cluster.get('CacheNodeType', 'Unknown')}")
            
            # Replication Groups
            response = elasticache.describe_replication_groups()
            for group in response.get('ReplicationGroups', []):
                self._add_resource('ElastiCache', 'Replication Group',
                                   group.get('ReplicationGroupId', 'Unknown'),
                                   f"Redis - {group.get('Status', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ ElastiCache error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_redshift(self):
        """Redshift Clusters"""
        try:
            print("📊 Scanning Redshift...")
            # Added verify=False
            redshift = self.session.client('redshift', region_name=self.region, verify=False)
            
            response = redshift.describe_clusters()
            for cluster in response.get('Clusters', []):
                self._add_resource('Redshift', 'Cluster',
                                   cluster.get('ClusterIdentifier', 'Unknown'),
                                   f"{cluster.get('NodeType', 'Unknown')} - {cluster.get('ClusterStatus', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ Redshift error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_documentdb(self):
        """DocumentDB Clusters"""
        try:
            print("📊 Scanning DocumentDB...")
            # Added verify=False
            docdb = self.session.client('docdb', region_name=self.region, verify=False)
            
            response = docdb.describe_db_clusters()
            for cluster in response.get('DBClusters', []):
                self._add_resource('DocumentDB', 'Cluster',
                                   cluster.get('DBClusterIdentifier', 'Unknown'),
                                   f"{cluster.get('Engine', 'Unknown')} - {cluster.get('Status', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ DocumentDB error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_neptune(self):
        """Neptune Clusters"""
        try:
            print("📊 Scanning Neptune...")
            # Added verify=False
            neptune = self.session.client('neptune', region_name=self.region, verify=False)
            
            response = neptune.describe_db_clusters()
            for cluster in response.get('DBClusters', []):
                self._add_resource('Neptune', 'Cluster',
                                   cluster.get('DBClusterIdentifier', 'Unknown'),
                                   f"{cluster.get('Engine', 'Unknown')} - {cluster.get('Status', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ Neptune error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_load_balancers(self):
        """Load Balancers"""
        try:
            print("📊 Scanning Load Balancers...")
            # Added verify=False
            elbv2 = self.session.client('elbv2', region_name=self.region, verify=False)
            
            response = elbv2.describe_load_balancers()
            for lb in response.get('LoadBalancers', []):
                self._add_resource('ELB', 'Load Balancer',
                                   lb.get('LoadBalancerName', 'Unknown'),
                                   f"{lb.get('Type', 'Unknown')} - {lb.get('State', {}).get('Code', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ ELB error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_api_gateway(self):
        """API Gateway"""
        try:
            print("📊 Scanning API Gateway...")
            # Added verify=False
            apigateway = self.session.client('apigateway', region_name=self.region, verify=False)
            
            response = apigateway.get_rest_apis()
            for api in response.get('items', []):
                self._add_resource('API Gateway', 'REST API',
                                   api.get('name', 'Unknown'),
                                   f"ID: {api.get('id', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ API Gateway error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_cloudfront(self):
        """CloudFront Distributions"""
        try:
            print("📊 Scanning CloudFront...")
            # Added verify=False
            cloudfront = self.session.client('cloudfront', region_name='us-east-1', verify=False)
            
            response = cloudfront.list_distributions()
            distributions = response.get('DistributionList', {}).get('Items', [])
            for dist in distributions:
                self._add_resource('CloudFront', 'Distribution',
                                   dist.get('Id', 'Unknown'),
                                   f"{dist.get('Status', 'Unknown')} - {dist.get('DomainName', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ CloudFront error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_route53(self):
        """Route53 Hosted Zones"""
        try:
            print("📊 Scanning Route53...")
            # Added verify=False
            route53 = self.session.client('route53', region_name='us-east-1', verify=False)
            
            response = route53.list_hosted_zones()
            for zone in response.get('HostedZones', []):
                self._add_resource('Route53', 'Hosted Zone',
                                   zone.get('Name', 'Unknown'),
                                   f"{zone.get('ResourceRecordSetCount', 0)} records")
                                   
        except ClientError as e:
            print(f"   ❌ Route53 error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_sns(self):
        """SNS Topics"""
        try:
            print("📊 Scanning SNS...")
            # Added verify=False
            sns = self.session.client('sns', region_name=self.region, verify=False)
            
            response = sns.list_topics()
            for topic in response.get('Topics', []):
                topic_name = topic.get('TopicArn', 'Unknown').split(':')[-1]
                self._add_resource('SNS', 'Topic', topic_name, 'SNS Topic')
                
        except ClientError as e:
            print(f"   ❌ SNS error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_sqs(self):
        """SQS Queues"""
        try:
            print("📊 Scanning SQS...")
            # Added verify=False
            sqs = self.session.client('sqs', region_name=self.region, verify=False)
            
            response = sqs.list_queues()
            for queue_url in response.get('QueueUrls', []):
                queue_name = queue_url.split('/')[-1]
                self._add_resource('SQS', 'Queue', queue_name, 'SQS Queue')
                
        except ClientError as e:
            print(f"   ❌ SQS error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_mq(self):
        """Amazon MQ Brokers"""
        try:
            print("📊 Scanning MQ...")
            # Added verify=False
            mq = self.session.client('mq', region_name=self.region, verify=False)
            
            response = mq.list_brokers()
            for broker in response.get('BrokerSummaries', []):
                self._add_resource('MQ', 'Broker',
                                   broker.get('BrokerName', 'Unknown'),
                                   f"{broker.get('EngineType', 'Unknown')} - {broker.get('BrokerState', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ MQ error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_kinesis(self):
        """Kinesis Streams"""
        try:
            print("📊 Scanning Kinesis...")
            # Added verify=False
            kinesis = self.session.client('kinesis', region_name=self.region, verify=False)
            
            response = kinesis.list_streams()
            for stream_name in response.get('StreamNames', []):
                self._add_resource('Kinesis', 'Stream', stream_name, 'Data Stream')
                
        except ClientError as e:
            print(f"   ❌ Kinesis error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_emr(self):
        """EMR Clusters"""
        try:
            print("📊 Scanning EMR...")
            # Added verify=False
            emr = self.session.client('emr', region_name=self.region, verify=False)
            
            response = emr.list_clusters()
            for cluster in response.get('Clusters', []):
                self._add_resource('EMR', 'Cluster',
                                   cluster.get('Name', 'Unknown'),
                                   f"ID: {cluster.get('Id', 'Unknown')} - {cluster.get('Status', {}).get('State', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ EMR error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_glue(self):
        """AWS Glue"""
        try:
            print("📊 Scanning Glue...")
            # Added verify=False
            glue = self.session.client('glue', region_name=self.region, verify=False)
            
            # Databases
            response = glue.get_databases()
            for db in response.get('DatabaseList', []):
                self._add_resource('Glue', 'Database',
                                   db.get('Name', 'Unknown'),
                                   f"Description: {db.get('Description', 'No description')[:30]}")
                                   
        except ClientError as e:
            print(f"   ❌ Glue error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_athena(self):
        """Athena Workgroups"""
        try:
            print("📊 Scanning Athena...")
            # Added verify=False
            athena = self.session.client('athena', region_name=self.region, verify=False)
            
            response = athena.list_work_groups()
            for wg in response.get('WorkGroups', []):
                self._add_resource('Athena', 'Work Group',
                                   wg.get('Name', 'Unknown'),
                                   f"State: {wg.get('State', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ Athena error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_sagemaker(self):
        """SageMaker"""
        try:
            print("📊 Scanning SageMaker...")
            # Added verify=False
            sagemaker = self.session.client('sagemaker', region_name=self.region, verify=False)
            
            # Notebook Instances
            response = sagemaker.list_notebook_instances()
            for notebook in response.get('NotebookInstances', []):
                self._add_resource('SageMaker', 'Notebook',
                                   notebook.get('NotebookInstanceName', 'Unknown'),
                                   f"{notebook.get('InstanceType', 'Unknown')} - {notebook.get('NotebookInstanceStatus', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ SageMaker error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_iam(self):
        """IAM Resources"""
        try:
            print("📊 Scanning IAM...")
            # Added verify=False
            iam = self.session.client('iam', region_name='us-east-1', verify=False)
            
            # Users (limited to first 10)
            response = iam.list_users(MaxItems=10)
            for user in response.get('Users', []):
                self._add_resource('IAM', 'User',
                                   user.get('UserName', 'Unknown'),
                                   f"Created: {str(user.get('CreateDate', ''))[:10]}")
                                   
        except ClientError as e:
            print(f"   ❌ IAM error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_kms(self):
        """KMS Keys"""
        try:
            print("📊 Scanning KMS...")
            # Added verify=False
            kms = self.session.client('kms', region_name=self.region, verify=False)
            
            response = kms.list_keys()
            for key in response.get('Keys', []):
                key_id = key.get('KeyId', 'Unknown')
                try:
                    key_info = kms.describe_key(KeyId=key_id)
                    key_metadata = key_info.get('KeyMetadata', {})
                    self._add_resource('KMS', 'Key',
                                       key_metadata.get('Description', f'Key-{key_id[:8]}'),
                                       f"Usage: {key_metadata.get('KeyUsage', 'Unknown')}")
                except:
                    self._add_resource('KMS', 'Key', f'Key-{key_id[:8]}', 'KMS Key')
                    
        except ClientError as e:
            print(f"   ❌ KMS error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_secrets_manager(self):
        """Secrets Manager"""
        try:
            print("📊 Scanning Secrets Manager...")
            # Added verify=False
            secretsmanager = self.session.client('secretsmanager', region_name=self.region, verify=False)
            
            response = secretsmanager.list_secrets()
            for secret in response.get('SecretList', []):
                self._add_resource('Secrets Manager', 'Secret',
                                   secret.get('Name', 'Unknown'),
                                   f"Description: {secret.get('Description', 'No description')[:30]}")
                                   
        except ClientError as e:
            print(f"   ❌ Secrets Manager error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_acm(self):
        """ACM Certificates"""
        try:
            print("📊 Scanning ACM...")
            # Added verify=False
            acm = self.session.client('acm', region_name=self.region, verify=False)
            
            response = acm.list_certificates()
            for cert in response.get('CertificateSummaryList', []):
                self._add_resource('ACM', 'Certificate',
                                   cert.get('DomainName', 'Unknown'),
                                   f"Status: {cert.get('Status', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ ACM error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_cloudwatch(self):
        """CloudWatch"""
        try:
            print("📊 Scanning CloudWatch...")
            # Added verify=False
            cloudwatch = self.session.client('cloudwatch', region_name=self.region, verify=False)
            logs = self.session.client('logs', region_name=self.region, verify=False)
            
            # Alarms
            response = cloudwatch.describe_alarms()
            for alarm in response.get('MetricAlarms', [])[:10]:  # First 10
                self._add_resource('CloudWatch', 'Alarm',
                                   alarm.get('AlarmName', 'Unknown'),
                                   f"{alarm.get('StateValue', 'Unknown')} - {alarm.get('MetricName', 'Unknown')}")
            
            # Log Groups (first 10)
            response = logs.describe_log_groups()
            for log_group in response.get('logGroups', [])[:10]:
                self._add_resource('CloudWatch', 'Log Group',
                                   log_group.get('logGroupName', 'Unknown'),
                                   f"Retention: {log_group.get('retentionInDays', 'Never')} days")
                                   
        except ClientError as e:
            print(f"   ❌ CloudWatch error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_cloudformation(self):
        """CloudFormation Stacks"""
        try:
            print("📊 Scanning CloudFormation...")
            # Added verify=False
            cf = self.session.client('cloudformation', region_name=self.region, verify=False)
            
            response = cf.list_stacks()
            for stack in response.get('StackSummaries', []):
                if stack.get('StackStatus') != 'DELETE_COMPLETE':  # Skip deleted stacks
                    self._add_resource('CloudFormation', 'Stack',
                                       stack.get('StackName', 'Unknown'),
                                       f"{stack.get('StackStatus', 'Unknown')}")
                                       
        except ClientError as e:
            print(f"   ❌ CloudFormation error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_systems_manager(self):
        """Systems Manager"""
        try:
            print("📊 Scanning Systems Manager...")
            # Added verify=False
            ssm = self.session.client('ssm', region_name=self.region, verify=False)
            
            # Parameters (first 20)
            response = ssm.describe_parameters(MaxResults=20)
            for param in response.get('Parameters', []):
                self._add_resource('SSM', 'Parameter',
                                   param.get('Name', 'Unknown'),
                                   f"Type: {param.get('Type', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ SSM error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_config(self):
        """AWS Config"""
        try:
            print("📊 Scanning Config...")
            # Added verify=False
            config = self.session.client('config', region_name=self.region, verify=False)
            
            response = config.describe_configuration_recorders()
            for recorder in response.get('ConfigurationRecorders', []):
                self._add_resource('Config', 'Recorder',
                                   recorder.get('name', 'Unknown'),
                                   f"Recording: {recorder.get('recordingGroup', {}).get('allSupported', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ Config error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_codecommit(self):
        """CodeCommit Repositories"""
        try:
            print("📊 Scanning CodeCommit...")
            # Added verify=False
            codecommit = self.session.client('codecommit', region_name=self.region, verify=False)
            
            response = codecommit.list_repositories()
            for repo in response.get('repositories', []):
                self._add_resource('CodeCommit', 'Repository',
                                   repo.get('repositoryName', 'Unknown'),
                                   f"ID: {repo.get('repositoryId', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ CodeCommit error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_codebuild(self):
        """CodeBuild Projects"""
        try:
            print("📊 Scanning CodeBuild...")
            # Added verify=False
            codebuild = self.session.client('codebuild', region_name=self.region, verify=False)
            
            response = codebuild.list_projects()
            for project_name in response.get('projects', []):
                self._add_resource('CodeBuild', 'Project', project_name, 'Build Project')
                
        except ClientError as e:
            print(f"   ❌ CodeBuild error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_codedeploy(self):
        """CodeDeploy Applications"""
        try:
            print("📊 Scanning CodeDeploy...")
            # Added verify=False
            codedeploy = self.session.client('codedeploy', region_name=self.region, verify=False)
            
            response = codedeploy.list_applications()
            for app_name in response.get('applications', []):
                self._add_resource('CodeDeploy', 'Application', app_name, 'Deployment Application')
                
        except ClientError as e:
            print(f"   ❌ CodeDeploy error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_codepipeline(self):
        """CodePipeline Pipelines"""
        try:
            print("📊 Scanning CodePipeline...")
            # Added verify=False
            codepipeline = self.session.client('codepipeline', region_name=self.region, verify=False)
            
            response = codepipeline.list_pipelines()
            for pipeline in response.get('pipelines', []):
                self._add_resource('CodePipeline', 'Pipeline',
                                   pipeline.get('name', 'Unknown'),
                                   f"Version: {pipeline.get('version', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ CodePipeline error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def _scan_iot(self):
        """IoT Things"""
        try:
            print("📊 Scanning IoT...")
            # Added verify=False
            iot = self.session.client('iot', region_name=self.region, verify=False)
            
            response = iot.list_things()
            for thing in response.get('things', []):
                self._add_resource('IoT', 'Thing',
                                   thing.get('thingName', 'Unknown'),
                                   f"Type: {thing.get('thingTypeName', 'Unknown')}")
                                   
        except ClientError as e:
            print(f"   ❌ IoT error: {e.response.get('Error', {}).get('Code', 'Unknown')}")

    def print_summary(self):
        """Print comprehensive summary"""
        print("\n" + "="*80)
        print("🎯 COMPREHENSIVE AWS  INVENTORY - ALL SERVICES")
        print("="*80)

        if not self.all_resources:
            print("⚠ No resources found")
            return

        # Group by service
        service_groups = {}
        for resource in self.all_resources:
            service = resource['Service']
            service_groups.setdefault(service, []).append(resource)

        total_resources = len(self.all_resources)
        
        for service, resources in sorted(service_groups.items()):
            print(f"\n📋 {service}: {len(resources)} resources")
            print("-" * 50)
            for i, resource in enumerate(resources[:5], 1):  # Show first 5
                print(f"   {i:2}. [{resource['Type']}] {resource['Name']}")
                if resource['Details']:
                    print(f"       {resource['Details']}")
                print()
            if len(resources) > 5:
                print(f"      ... and {len(resources) - 5} more")
                print()
        
        # Print a summary of costs if available
        if self.costs_data:
            print("\n💰 MONTHLY COST SUMMARY (Last Full Month)")
            print("-" * 50)
            for cost_item in self.costs_data:
                print(f"   - {cost_item['Service']}: {cost_item['Cost']:.2f} {cost_item['Unit']} in {cost_item['Region']}")

        print("="*80)
        print(f"🎯 TOTAL: {total_resources} resources across ALL AWS services")
        print("="*80)

    def export_to_excel(self):
        """Export to Excel"""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"aws_all_services_{self.account_id}_{timestamp}.xlsx"

        try:
            df = pd.DataFrame(self.all_resources)
            
            with pd.ExcelWriter(filename, engine="openpyxl") as writer:
                # All resources
                df.to_excel(writer, sheet_name="All_Resources", index=False)
                
                # Summary by service
                summary = df.groupby('Service').size().reset_index(name='Count')
                summary.to_excel(writer, sheet_name="Summary", index=False)

                # Export costs if available
                if self.costs_data:
                    costs_df = pd.DataFrame(self.costs_data)
                    costs_df.to_excel(writer, sheet_name="Monthly Costs", index=False)

            print(f"✅ Excel file created: {filename}")
            return filename

        except Exception as e:
            print(f"❌ Excel export failed: {e}")
            return None

# --------------------------- ENTRY POINT -------------------------------------
if __name__ == "__main__":
    print("🎯 COMPREHENSIVE AWS INVENTORY - ALL SERVICES, ESSENTIAL INFO")
    print("=" * 70)
    
    try:
        # Prompt user for credentials
        access_key = input("Enter your AWS Access Key ID: ")
        secret_key = input("Enter your AWS Secret Access Key: ")
        session_token = input("Enter your AWS Session Token (if applicable, otherwise press Enter): ")
        
        if not access_key or not secret_key:
            print("❌ Access Key ID and Secret Access Key are required.")
            sys.exit(1)

        scanner = ComprehensiveAWSScanner(access_key, secret_key, session_token or None)
        
        # Scan all services and then fetch costs
        scanner.scan_all_services()
        scanner.get_aws_monthly_costs()
        
        # Print summary
        scanner.print_summary()
        
        # Export to Excel
        excel_file = scanner.export_to_excel()
        
        print(f"\n🎉 SUCCESS!")
        print(f"📊 Total resources: {len(scanner.all_resources)}")
        print(f"📁 Excel file: {excel_file}")
       
        print(f"🔍 Coverage: ALL AWS services, essential info only")
        
    except KeyboardInterrupt:
        print("\n⚠ Scan interrupted")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
