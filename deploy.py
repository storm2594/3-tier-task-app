import json
import time
import subprocess
import argparse
import os
import sys
import boto3
import logging
import requests
import pg8000

# ─────────────────────────────────────────────────────────────────────────────
# 🛠️ HELPER FUNCTIONS (Merged from *_setup.py)
# ─────────────────────────────────────────────────────────────────────────────

def setup_vpc(ec2):
    """Creates VPC, Subnets, IGW, and Route Tables with idempotency checks."""
    try:
        # 1. Check for existing VPC
        vpcs = ec2.describe_vpcs(Filters=[{'Name': 'tag:Name', 'Values': ['task-manager-vpc']}])
        if vpcs['Vpcs']:
            vpc_id = vpcs['Vpcs'][0]['VpcId']
            logger.info(f"Using existing VPC: {vpc_id}")
            sns = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
            subnets = [sn['SubnetId'] for sn in sns['Subnets']]
            if len(subnets) >= 2:
                logger.info(f"Using existing subnets: {subnets}")
                return vpc_id, subnets[:2]

        # Create new VPC
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc['Vpc']['VpcId']
        logger.info(f"Created VPC: {vpc_id}")
        ec2.create_tags(Resources=[vpc_id], Tags=[{'Key': 'Name', 'Value': 'task-manager-vpc'}])
        ec2.get_waiter('vpc_exists').wait(VpcIds=[vpc_id])
        ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={'Value': True})
        ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={'Value': True})

        # IGW
        igw = ec2.create_internet_gateway()
        igw_id = igw['InternetGateway']['InternetGatewayId']
        ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

        # Subnets in 2 different AZs
        subnets = []
        azs = ec2.describe_availability_zones()['AvailabilityZones']
        for i in range(2):
            sn = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f'10.0.{i+1}.0/24', AvailabilityZone=azs[i]['ZoneName'])
            sn_id = sn['Subnet']['SubnetId']
            ec2.modify_subnet_attribute(SubnetId=sn_id, MapPublicIpOnLaunch={'Value': True})
            subnets.append(sn_id)

        # Route Table
        rt = ec2.create_route_table(VpcId=vpc_id)
        rt_id = rt['RouteTable']['RouteTableId']
        ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock='0.0.0.0/0', GatewayId=igw_id)
        for sn_id in subnets:
            ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sn_id)

        return vpc_id, subnets
    except Exception as e:
        logger.error(f"Error setting up VPC: {e}")
        raise

def create_security_groups(ec2, vpc_id, backend_port=5000):
    """Creates/reuses ALB and ECS security groups."""
    try:
        # ALB SG
        alb_sg_id = None
        sgs = ec2.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': ['task-manager-alb-sg']}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
        if sgs['SecurityGroups']:
            alb_sg_id = sgs['SecurityGroups'][0]['GroupId']
            logger.info(f"Reusing ALB SG: {alb_sg_id}")
        else:
            alb_sg = ec2.create_security_group(Description='Task Manager ALB SG', GroupName='task-manager-alb-sg', VpcId=vpc_id)
            alb_sg_id = alb_sg['GroupId']
            ec2.authorize_security_group_ingress(GroupId=alb_sg_id, IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}])
            logger.info(f"Created ALB SG: {alb_sg_id}")

        # ECS SG
        ecs_sg_id = None
        sgs = ec2.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': ['task-manager-ecs-sg']}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
        if sgs['SecurityGroups']:
            ecs_sg_id = sgs['SecurityGroups'][0]['GroupId']
            logger.info(f"Reusing ECS SG: {ecs_sg_id}")
        else:
            ecs_sg = ec2.create_security_group(Description='Task Manager ECS SG', GroupName='task-manager-ecs-sg', VpcId=vpc_id)
            ecs_sg_id = ecs_sg['GroupId']
            perms = [{'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'UserIdGroupPairs': [{'GroupId': alb_sg_id}]}]
            if backend_port != 80:
                perms.append({'IpProtocol': 'tcp', 'FromPort': backend_port, 'ToPort': backend_port, 'UserIdGroupPairs': [{'GroupId': alb_sg_id}]})
            ec2.authorize_security_group_ingress(GroupId=ecs_sg_id, IpPermissions=perms)
            logger.info(f"Created ECS SG: {ecs_sg_id}")

        return alb_sg_id, ecs_sg_id
    except Exception as e:
        logger.error(f"Error creating security groups: {e}")
        raise

def setup_ecr(ecr_client, repo_name):
    """Creates ECR repository or returns URI if it exists."""
    try:
        response = ecr_client.create_repository(repositoryName=repo_name, imageScanningConfiguration={'scanOnPush': True}, imageTagMutability='MUTABLE')
        repository_uri = response['repository']['repositoryUri']
        logger.info(f"Created ECR Repository {repo_name}: {repository_uri}")
        return repository_uri
    except ecr_client.exceptions.RepositoryAlreadyExistsException:
        response = ecr_client.describe_repositories(repositoryNames=[repo_name])
        repository_uri = response['repositories'][0]['repositoryUri']
        logger.info(f"ECR Repository {repo_name} already exists: {repository_uri}")
        return repository_uri
    except Exception as e:
        logger.error(f"Error setting up ECR {repo_name}: {e}")
        raise

def setup_alb(elbv2_client, vpc_id, subnets, alb_sg_id, backend_port=5000, frontend_port=80):
    """Creates ALB, Target Groups, and Listener with path-based routing."""
    try:
        # Load Balancer
        try:
            albs = elbv2_client.describe_load_balancers(Names=['task-manager-alb'])
            alb_arn = albs['LoadBalancers'][0]['LoadBalancerArn']
            alb_dns = albs['LoadBalancers'][0]['DNSName']
            logger.info(f"ALB already exists: {alb_dns}")
        except elbv2_client.exceptions.LoadBalancerNotFoundException:
            alb = elbv2_client.create_load_balancer(Name='task-manager-alb', Subnets=subnets, SecurityGroups=[alb_sg_id], Scheme='internet-facing', Type='application')
            alb_arn = alb['LoadBalancers'][0]['LoadBalancerArn']
            alb_dns = alb['LoadBalancers'][0]['DNSName']
            logger.info(f"Created ALB: {alb_dns}")

        # Target Groups
        def create_tg(name, port, path='/health'):
            try:
                tgs = elbv2_client.describe_target_groups(Names=[name])
                return tgs['TargetGroups'][0]['TargetGroupArn']
            except elbv2_client.exceptions.TargetGroupNotFoundException:
                tg = elbv2_client.create_target_group(Name=name, Protocol='HTTP', Port=port, VpcId=vpc_id, TargetType='ip', HealthCheckPath=path, HealthyThresholdCount=2, UnhealthyThresholdCount=2)
                return tg['TargetGroups'][0]['TargetGroupArn']

        backend_tg_arn = create_tg('task-manager-tg', backend_port)
        frontend_tg_arn = create_tg('task-manager-frontend-tg', frontend_port)

        # Listener
        listeners = elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)
        if not listeners['Listeners']:
            listener = elbv2_client.create_listener(LoadBalancerArn=alb_arn, Protocol='HTTP', Port=80, DefaultActions=[{'Type': 'forward', 'TargetGroupArn': frontend_tg_arn}])
            listener_arn = listener['Listeners'][0]['ListenerArn']
            elbv2_client.create_rule(ListenerArn=listener_arn, Priority=1, Conditions=[{'Field': 'path-pattern', 'Values': ['/api*']}], Actions=[{'Type': 'forward', 'TargetGroupArn': backend_tg_arn}])
            logger.info("Created ALB Listener and path-based Rules")

        return alb_dns, backend_tg_arn, frontend_tg_arn
    except Exception as e:
        logger.error(f"Error setting up ALB: {e}")
        raise

def setup_rds(rds_client, ec2_client, vpc_id, subnets, ecs_sg_id, db_password, db_name='taskmanager', db_user='postgres'):
    """Creates RDS PostgreSQL instance."""
    try:
        subnet_group_name = 'task-manager-db-subnet-group'
        try:
            rds_client.create_db_subnet_group(DBSubnetGroupName=subnet_group_name, DBSubnetGroupDescription='Task Manager DB Subnets', SubnetIds=subnets)
        except rds_client.exceptions.DBSubnetGroupAlreadyExistsFault: pass

        # SG
        rds_sg_id = None
        try:
            sgs = ec2_client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': ['task-manager-rds-sg']}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
            rds_sg_id = sgs['SecurityGroups'][0]['GroupId']
        except (ec2_client.exceptions.ClientError, IndexError):
            rds_sg = ec2_client.create_security_group(Description='RDS SG', GroupName='task-manager-rds-sg', VpcId=vpc_id)
            rds_sg_id = rds_sg['GroupId']
            ec2_client.authorize_security_group_ingress(GroupId=rds_sg_id, IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 5432, 'ToPort': 5432, 'UserIdGroupPairs': [{'GroupId': ecs_sg_id}]}])

        db_id = 'task-manager-db'
        try:
            resp = rds_client.describe_db_instances(DBInstanceIdentifier=db_id)
            instance = resp['DBInstances'][0]
            logger.info(f"RDS Instance {db_id} already exists.")
            
            # CRITICAL: Ensure existing instance is publicly accessible
            if not instance.get('PubliclyAccessible', False):
                logger.info(f"Modifying existing RDS instance {db_id} to be Publicly Accessible...")
                rds_client.modify_db_instance(
                    DBInstanceIdentifier=db_id,
                    PubliclyAccessible=True,
                    ApplyImmediately=True
                )
                logger.info("Waiting for modification to complete...")
                time.sleep(30) # Brief pause for call to register
        except rds_client.exceptions.DBInstanceNotFoundFault:
            rds_client.create_db_instance(
                DBInstanceIdentifier=db_id,
                DBName='taskmanager',
                Engine='postgres',
                EngineVersion='15.14',
                DBInstanceClass='db.t3.micro',
                AllocatedStorage=20,
                MasterUsername=db_user,
                MasterUserPassword=db_password,
                VpcSecurityGroupIds=[rds_sg_id],
                DBSubnetGroupName=subnet_group_name,
                PubliclyAccessible=True,
                MultiAZ=False,
                StorageType='gp2',
                BackupRetentionPeriod=1
            )
            logger.info(f"Creating RDS Instance {db_id}...")

        logger.info(f"Waiting for RDS Instance {db_id} to be available (this can take 5-10 mins)...")
        rds_client.get_waiter('db_instance_available').wait(DBInstanceIdentifier=db_id)
        resp = rds_client.describe_db_instances(DBInstanceIdentifier=db_id)
        endpoint = resp['DBInstances'][0]['Endpoint']['Address']
        logger.info(f"RDS Instance available at: {endpoint}")
        return endpoint
    except Exception as e:
        logger.error(f"Error setting up RDS: {e}")
        raise

def apply_db_schema(ec2_client, rds_client, vpc_id, db_host, db_password, db_name='taskmanager', db_user='postgres'):
    """Temporarily opens RDS SG, connects via pg8000, and applies schema.sql with retries."""
    logger.info("⏳ Applying database schema...")
    
    # 1. Get public IP
    try:
        public_ip = requests.get('https://api.ipify.org', timeout=10).text.strip()
        logger.info(f"Targeting deployment machine IP: {public_ip}")
    except Exception as e:
        logger.error(f"Could not determine public IP: {e}")
        return False

    # 2. Find RDS Security Group
    try:
        sgs = ec2_client.describe_security_groups(Filters=[
            {'Name': 'group-name', 'Values': ['task-manager-rds-sg']},
            {'Name': 'vpc-id', 'Values': [vpc_id]}
        ])
        rds_sg_id = sgs['SecurityGroups'][0]['GroupId']
    except Exception as e:
        logger.error(f"Could not find RDS Security Group: {e}")
        return False

    # 3. Temporarily open port 5432
    rule_added = False
    try:
        # Check if rule already exists to avoid Duplicate Rule error
        try:
            ec2_client.authorize_security_group_ingress(
                GroupId=rds_sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 5432,
                    'ToPort': 5432,
                    'IpRanges': [{'CidrIp': f'{public_ip}/32', 'Description': 'Temporary deployment access'}]
                }]
            )
            rule_added = True
            logger.info("Temporary Security Group rule added.")
        except ec2_client.exceptions.ClientError as e:
            if 'InvalidPermission.Duplicate' in str(e):
                logger.info("Security Group rule already exists, continuing...")
                rule_added = True
            else:
                raise
        
        # Wait for propagation
        logger.info("Waiting 20s for Security Group propagation...")
        time.sleep(20)
        
        # 4. Connect and Apply SQL (with retries)
        max_retries = 3
        sys_conn = None
        for attempt in range(max_retries):
            try:
                logger.info(f"Connecting to {db_host} (postgres) - Attempt {attempt+1}/{max_retries}...")
                sys_conn = pg8000.connect(host=db_host, user=db_user, password=db_password, database='postgres')
                break
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                logger.warning(f"Connection failed: {e}. Retrying in 10s...")
                time.sleep(10)
        
        sys_conn.autocommit = True
        sys_cursor = sys_conn.cursor()
        
        try:
            sys_cursor.execute("CREATE DATABASE taskmanager")
            logger.info("Created 'taskmanager' database.")
        except Exception as e:
            if "already exists" in str(e).lower():
                logger.info("'taskmanager' database already exists.")
            else:
                logger.warning(f"Note: Could not create 'taskmanager' via SQL: {e}")
        
        sys_cursor.close()
        sys_conn.close()

        # Step B: Reconnect to 'taskmanager' and apply schema
        logger.info(f"Connecting to {db_host} (taskmanager) to apply schema...")
        conn = pg8000.connect(host=db_host, user=db_user, password=db_password, database='taskmanager')
        cursor = conn.cursor()
        
        schema_path = os.path.join(os.path.dirname(__file__), 'database', 'schema.sql')
        if not os.path.exists(schema_path):
            logger.error(f"Schema file not found at {schema_path}")
            return False

        with open(schema_path, 'r') as f:
            schema_sql = f.read()
            
        logger.info(f"Applying schema statements...")
        # A more robust regex-based split that respects $$ quoted blocks for triggers
        # We put the $$ block pattern FIRST so it consumes the block (including any inner semicolons)
        # before the outer [^;] pattern has a chance to stop at them.
        import re
        statements = re.findall(r'(?:\$\$[\s\S]*?\$\$|[^;])+;', schema_sql)
        
        if not statements:
            # Fallback for simple schemas or if regex fails
            logger.warning("Regex split found no statements, falling back to crude split.")
            statements = [s.strip() for s in schema_sql.split(';') if s.strip()]

        for i, statement in enumerate(statements):
            stmt = statement.strip()
            if not stmt: continue
            try:
                cursor.execute(stmt)
                logger.info(f"[{i+1}/{len(statements)}] Executed statement.")
            except Exception as e:
                # If a statement fails, we might still want to continue if it's 'already exists'
                if "already exists" in str(e).lower():
                    logger.info(f"[{i+1}/{len(statements)}] Skipping (already exists).")
                else:
                    logger.warning(f"Error in statement {i+1}: {e}")
                    # Most drivers abort transaction on error, so we should consider that
                    # but since we want to be robust, we'll just log it.
        
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("✅ Database schema applied successfully!")
        
    except Exception as e:
        logger.error(f"❌ Error applying database schema: {e}")
        return False
    finally:
        # 5. Cleanup
        if rule_added:
            try:
                ec2_client.revoke_security_group_ingress(
                    GroupId=rds_sg_id,
                    IpPermissions=[{
                        'IpProtocol': 'tcp',
                        'FromPort': 5432,
                        'ToPort': 5432,
                        'IpRanges': [{'CidrIp': f'{public_ip}/32'}]
                    }]
                )
                logger.info("Temporary Security Group rule removed.")
            except Exception as e:
                logger.warning(f"Cleanup failed (manual removal may be needed): {e}")

    return True

def create_execution_role(iam_client):
    """Creates IAM role for ECS task execution."""
    role_name = 'task-manager-ecs-execution-role'
    trust_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    try:
        role = iam_client.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
        role_arn = role['Role']['Arn']
        iam_client.attach_role_policy(RoleName=role_name, PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy')
        time.sleep(10)
        return role_arn
    except iam_client.exceptions.EntityAlreadyExistsException:
        return iam_client.get_role(RoleName=role_name)['Role']['Arn']

def create_ecs_cluster_and_role(ecs_client, iam_client, cluster_name):
    ecs_client.create_cluster(clusterName=cluster_name)
    return create_execution_role(iam_client)

def deploy_service(ecs_client, logs_client, region, cluster_name, task_family, container_name, image_uri, container_port, subnets, ecs_sg_id, tg_arn, env_vars, exec_role_arn, desired_count=1):
    log_group = f'/ecs/{task_family}'
    try:
        logs_client.create_log_group(logGroupName=log_group)
    except logs_client.exceptions.ResourceAlreadyExistsException: pass

    container_def = {'name': container_name, 'image': image_uri, 'portMappings': [{'containerPort': container_port, 'hostPort': container_port, 'protocol': 'tcp'}], 'essential': True, 'environment': env_vars, 'logConfiguration': {'logDriver': 'awslogs', 'options': {'awslogs-group': log_group, 'awslogs-region': region, 'awslogs-stream-prefix': 'ecs'}}}
    resp = ecs_client.register_task_definition(family=task_family, networkMode='awsvpc', containerDefinitions=[container_def], requiresCompatibilities=['FARGATE'], cpu='256', memory='512', executionRoleArn=exec_role_arn, taskRoleArn=exec_role_arn)
    task_def_arn = resp['taskDefinition']['taskDefinitionArn']

    svc_name = f'{task_family}-service'
    net_config = {'awsvpcConfiguration': {'subnets': subnets, 'securityGroups': [ecs_sg_id], 'assignPublicIp': 'ENABLED'}}
    
    try:
        existing = ecs_client.describe_services(cluster=cluster_name, services=[svc_name])['services']
        if existing and existing[0]['status'] != 'INACTIVE':
            ecs_client.update_service(cluster=cluster_name, service=svc_name, taskDefinition=task_def_arn, networkConfiguration=net_config, forceNewDeployment=True)
        else:
            ecs_client.create_service(cluster=cluster_name, serviceName=svc_name, taskDefinition=task_def_arn, loadBalancers=[{'targetGroupArn': tg_arn, 'containerName': container_name, 'containerPort': container_port}], desiredCount=desired_count, launchType='FARGATE', networkConfiguration=net_config)
    except Exception:
        ecs_client.create_service(cluster=cluster_name, serviceName=svc_name, taskDefinition=task_def_arn, loadBalancers=[{'targetGroupArn': tg_arn, 'containerName': container_name, 'containerPort': container_port}], desiredCount=desired_count, launchType='FARGATE', networkConfiguration=net_config)
    return svc_name

def wait_for_services(ecs_client, cluster_name, services):
    logger.info(f"Waiting for services to stabilise: {services}")
    ecs_client.get_waiter('services_stable').wait(cluster=cluster_name, services=services, WaiterConfig={'Delay': 15, 'MaxAttempts': 40})

def destroy_infrastructure(session, region_name):
    """Destroys all provisioned resources."""
    logger.info("🔥 STARTING INFRASTRUCTURE DESTRUCTION")
    ec2 = session.client('ec2', region_name=region_name)
    ecs = session.client('ecs', region_name=region_name)
    elbv2 = session.client('elbv2', region_name=region_name)
    rds = session.client('rds', region_name=region_name)
    ecr = session.client('ecr', region_name=region_name)
    
    cluster_name = 'task-manager-cluster'
    try:
        svcs = ecs.list_services(cluster=cluster_name)['serviceArns']
        for s in svcs:
            ecs.delete_service(cluster=cluster_name, service=s, force=True)
            logger.info(f"Deleted service {s}")
        ecs.delete_cluster(cluster=cluster_name)
        logger.info(f"Deleted cluster {cluster_name}")
    except Exception as e: logger.warning(f"ECS cleanup failed: {e}")

    try:
        for name in ['task-manager-alb']:
            arn = elbv2.describe_load_balancers(Names=[name])['LoadBalancers'][0]['LoadBalancerArn']
            elbv2.delete_load_balancer(LoadBalancerArn=arn)
            logger.info(f"Deleted ALB {name}")
    except Exception as e: logger.warning(f"ALB cleanup failed: {e}")

    try:
        db_id = 'task-manager-db'
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
        logger.info(f"RDS {db_id} deletion initiated.")
    except Exception as e: logger.warning(f"RDS cleanup failed: {e}")

    try:
        for repo in ['task-manager-repo', 'task-manager-frontend']:
            ecr.delete_repository(repositoryName=repo, force=True)
            logger.info(f"Deleted ECR repo {repo}")
    except Exception as e: logger.warning(f"ECR cleanup failed: {e}")

    logger.info("Cleanup complete. (Note: VPC and Security Groups may require manual deletion if dependencies exist)")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Configuration  (change these for a new account)
# ─────────────────────────────────────────────
CLUSTER_NAME       = 'task-manager-cluster'
BACKEND_REPO       = 'task-manager-repo'
FRONTEND_REPO      = 'task-manager-frontend'
BACKEND_FAMILY     = 'task-manager-task'
FRONTEND_FAMILY    = 'task-manager-frontend'
BACKEND_CONTAINER  = 'task-manager-container'
FRONTEND_CONTAINER = 'task-manager-frontend-container'
BACKEND_PORT       = 5000
FRONTEND_PORT      = 80


def prompt_credentials():
    """Interactively prompts for AWS credentials unless already in env."""
    if os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'):
        region = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
        logger.info(f"Using existing env credentials. Region: {region}")
        os.environ['AWS_DEFAULT_REGION'] = region
        os.environ['AWS_REGION'] = region
        return

    print("\n--- AWS Credentials Setup ---")
    access_key = input("Enter AWS_ACCESS_KEY_ID: ").strip()
    secret_key = input("Enter AWS_SECRET_ACCESS_KEY: ").strip()
    region     = input("Enter AWS_REGION (e.g., us-east-1): ").strip()

    if not access_key or not secret_key or not region:
        logger.error("All credentials and region are required.")
        sys.exit(1)

    os.environ['AWS_ACCESS_KEY_ID']     = access_key
    os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key
    os.environ['AWS_DEFAULT_REGION']    = region
    os.environ['AWS_REGION']            = region
    print("Credentials set.\n")


def ecr_login(region, registry_url):
    """Logs Docker into ECR."""
    login_cmd = f"aws ecr get-login-password --region {region}"
    password = subprocess.check_output(login_cmd, shell=True).decode().strip()
    proc = subprocess.Popen(
        ['docker', 'login', '--username', 'AWS', '--password-stdin', registry_url],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    _, err = proc.communicate(input=password.encode())
    if proc.returncode != 0:
        raise RuntimeError(f"Docker login failed: {err.decode()}")
    logger.info(f"Logged in to ECR: {registry_url}")


def build_and_push(local_name, context_dir, ecr_uri, region):
    """Builds a Docker image and pushes it to ECR."""
    registry_url = ecr_uri.split('/')[0]
    ecr_login(region, registry_url)

    logger.info(f"Building {local_name} from {context_dir}...")
    subprocess.run(['docker', 'build', '-t', local_name, context_dir], check=True)
    subprocess.run(['docker', 'tag', f'{local_name}:latest', f'{ecr_uri}:latest'], check=True)

    logger.info(f"Pushing {ecr_uri}:latest ...")
    subprocess.run(['docker', 'push', f'{ecr_uri}:latest'], check=True)
    logger.info(f"Push complete: {ecr_uri}:latest")


def main():
    parser = argparse.ArgumentParser(description='Deploy Task Manager to AWS ECS Fargate')
    parser.add_argument('--destroy',       action='store_true',    help='Destroy all infrastructure')
    parser.add_argument('--skip-build',    action='store_true',    help='Skip Docker build and push')
    parser.add_argument('--enable-rds',    action='store_true',    help='Enable RDS PostgreSQL (default: False)')
    parser.add_argument('--db-password',   type=str,               help='RDS Master Password', default='YourSecurePassword123!')
    parser.add_argument('--desired-count', type=int,               help='Desired ECS task count', default=1)
    args = parser.parse_args()

    # ── 1. Credentials (must come FIRST, before any boto3 calls) ──
    prompt_credentials()
    region = os.environ['AWS_DEFAULT_REGION']

    # Create session
    session  = boto3.Session(
        aws_access_key_id     = os.environ['AWS_ACCESS_KEY_ID'],
        aws_secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY'],
        region_name           = region
    )

    if args.destroy:
        destroy_infrastructure(session, region)
        return
    ec2   = session.client('ec2')
    ecr   = session.client('ecr')
    elbv2 = session.client('elbv2')
    ecs   = session.client('ecs')
    iam   = session.client('iam')
    rds   = session.client('rds')
    logs  = session.client('logs')

    logger.info("=" * 60)
    logger.info("STARTING FULL-STACK DEPLOYMENT")
    logger.info("=" * 60)

    # ── 2. Networking ──
    vpc_id, subnets = setup_vpc(ec2)
    alb_sg_id, ecs_sg_id = create_security_groups(ec2, vpc_id, BACKEND_PORT)

    # ── 3. ECR Repos ──
    backend_ecr_uri  = setup_ecr(ecr, BACKEND_REPO)
    frontend_ecr_uri = setup_ecr(ecr, FRONTEND_REPO)

    # ── 4. Build & Push ──
    if not args.skip_build:
        build_and_push('task-manager-backend',  './backend',  backend_ecr_uri,  region)
        build_and_push('task-manager-frontend', './frontend', frontend_ecr_uri, region)
    else:
        logger.info("--skip-build set: using existing ECR images.")

    # ── 5. RDS (optional) ──
    db_host = 'localhost'
    if args.enable_rds:
        db_host = setup_rds(rds, ec2, vpc_id, subnets, ecs_sg_id, args.db_password)
        # Apply schema to RDS
        apply_db_schema(ec2, rds, vpc_id, db_host, args.db_password)
    else:
        logger.info("RDS disabled — falling back to in-cluster DB (not recommended for prod).")

    # ── 6. ALB (path-based routing) ──
    alb_dns, backend_tg_arn, frontend_tg_arn = setup_alb(
        elbv2, vpc_id, subnets, alb_sg_id, BACKEND_PORT, FRONTEND_PORT
    )

    # ── 7. ECS Cluster + IAM Role ──
    exec_role_arn = create_ecs_cluster_and_role(ecs, iam, CLUSTER_NAME)

    # ── 8. Backend ECS Service ──
    backend_env = [
        {'name': 'DB_HOST',     'value': db_host},
        {'name': 'DB_PORT',     'value': '5432'},
        {'name': 'DB_USER',     'value': 'postgres'},
        {'name': 'DB_PASSWORD', 'value': args.db_password if args.enable_rds else 'postgres'},
        {'name': 'DB_NAME',     'value': 'taskmanager'},
        {'name': 'DB_SSL',      'value': 'true'},
        {'name': 'NODE_TLS_REJECT_UNAUTHORIZED', 'value': '0'},
        {'name': 'PORT',        'value': str(BACKEND_PORT)},
        {'name': 'NODE_ENV',    'value': 'production'},
        {'name': 'JWT_SECRET',  'value': 'change-me-in-production-please'},
        {'name': 'ALLOWED_ORIGINS', 'value': f'http://{alb_dns}'},
    ]
    backend_svc = deploy_service(
        ecs, logs, region, CLUSTER_NAME,
        BACKEND_FAMILY, BACKEND_CONTAINER, f'{backend_ecr_uri}:latest',
        BACKEND_PORT, subnets, ecs_sg_id, backend_tg_arn,
        backend_env, exec_role_arn, args.desired_count
    )

    # ── 9. Frontend ECS Service ──
    frontend_svc = deploy_service(
        ecs, logs, region, CLUSTER_NAME,
        FRONTEND_FAMILY, FRONTEND_CONTAINER, f'{frontend_ecr_uri}:latest',
        FRONTEND_PORT, subnets, ecs_sg_id, frontend_tg_arn,
        [], exec_role_arn, args.desired_count
    )

    # ── 10. Wait for Stability ──
    wait_for_services(ecs, CLUSTER_NAME, [backend_svc, frontend_svc])

    # ── 11. Final Verification ──
    logger.info("🔍 Verifying deployment health...")
    time.sleep(10) # Give ALB a moment to update with target health
    health_url = f"http://{alb_dns}/health"
    try:
        health_resp = requests.get(health_url, timeout=15)
        if health_resp.status_code == 200:
            logger.info("✅ Health Check Passed!")
        else:
            logger.warning(f"⚠️ Health Check returned status {health_resp.status_code}")
    except Exception as e:
        logger.warning(f"Could not reach health endpoint: {e}")

    print()
    print("=" * 60)
    print("  DEPLOYMENT COMPLETE!")
    print("=" * 60)
    print(f"  Frontend UI  : http://{alb_dns}")
    print(f"  Backend API  : http://{alb_dns}/api")
    print(f"  Health Check : {health_url}")
    print("=" * 60)
    print()
    print("To re-deploy at any time (e.g., on a new account):")
    print("  1. Set your AWS creds when prompted")
    print("  2. Run: python deploy.py --enable-rds")
    print()


if __name__ == "__main__":
    main()
