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
import re

# ─────────────────────────────────────────────────────────────────────────────
# 🛠️ HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def setup_vpc(ec2):
    """Creates VPC, 2 Public/2 Private Subnets, IGW, NAT, and Route Tables with idempotency checks."""
    try:
        # 1. Check for existing VPC
        vpcs = ec2.describe_vpcs(Filters=[{'Name': 'tag:Name', 'Values': ['task-manager-vpc']}])
        if vpcs['Vpcs']:
            vpc_id = vpcs['Vpcs'][0]['VpcId']
            logger.info(f"Using existing VPC: {vpc_id}")
            sns = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
            pub_subs = []
            priv_subs = []
            for sn in sns['Subnets']:
                tags = {t['Key']: t['Value'] for t in sn.get('Tags', [])}
                if 'public' in tags.get('Name', '').lower():
                    pub_subs.append(sn['SubnetId'])
                elif 'private' in tags.get('Name', '').lower():
                    priv_subs.append(sn['SubnetId'])
            if len(pub_subs) >= 2 and len(priv_subs) >= 2:
                logger.info(f"Using existing subnets. Public: {pub_subs[:2]}, Private: {priv_subs[:2]}")
                return vpc_id, pub_subs[:2], priv_subs[:2]

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
        ec2.create_tags(Resources=[igw_id], Tags=[{'Key': 'Name', 'Value': 'task-manager-igw'}])
        ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        logger.info(f"Created & Attached IGW: {igw_id}")

        # Subnets in 2 different AZs
        pub_subs = []
        priv_subs = []
        azs = ec2.describe_availability_zones()['AvailabilityZones'][:2]
        
        for i, az in enumerate(azs):
            # Public Subnet
            sn_pub = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f'10.0.{i+1}.0/24', AvailabilityZone=az['ZoneName'])
            sn_pub_id = sn_pub['Subnet']['SubnetId']
            ec2.modify_subnet_attribute(SubnetId=sn_pub_id, MapPublicIpOnLaunch={'Value': True})
            ec2.create_tags(Resources=[sn_pub_id], Tags=[{'Key': 'Name', 'Value': f'task-manager-subnet-public-{i+1}'}])
            pub_subs.append(sn_pub_id)

            # Private Subnet
            sn_priv = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f'10.0.{i+3}.0/24', AvailabilityZone=az['ZoneName'])
            sn_priv_id = sn_priv['Subnet']['SubnetId']
            ec2.create_tags(Resources=[sn_priv_id], Tags=[{'Key': 'Name', 'Value': f'task-manager-subnet-private-{i+1}'}])
            priv_subs.append(sn_priv_id)

        # NAT Gateway and EIP
        logger.info("Setting up NAT Gateway... This takes ~2-3 minutes.")
        eip = ec2.allocate_address(Domain='vpc')
        ec2.create_tags(Resources=[eip['AllocationId']], Tags=[{'Key': 'Name', 'Value': 'task-manager-eip'}])
        
        nat = ec2.create_nat_gateway(SubnetId=pub_subs[0], AllocationId=eip['AllocationId'])
        nat_id = nat['NatGateway']['NatGatewayId']
        ec2.create_tags(Resources=[nat_id], Tags=[{'Key': 'Name', 'Value': 'task-manager-nat'}])
        ec2.get_waiter('nat_gateway_available').wait(NatGatewayIds=[nat_id])
        logger.info(f"✅ NAT Gateway Provisioned: {nat_id}")

        # Public Route Table
        rt_pub = ec2.create_route_table(VpcId=vpc_id)
        rt_pub_id = rt_pub['RouteTable']['RouteTableId']
        ec2.create_tags(Resources=[rt_pub_id], Tags=[{'Key': 'Name', 'Value': 'task-manager-rt-public'}])
        ec2.create_route(RouteTableId=rt_pub_id, DestinationCidrBlock='0.0.0.0/0', GatewayId=igw_id)
        for sn_id in pub_subs:
            ec2.associate_route_table(RouteTableId=rt_pub_id, SubnetId=sn_id)

        # Private Route Table
        rt_priv = ec2.create_route_table(VpcId=vpc_id)
        rt_priv_id = rt_priv['RouteTable']['RouteTableId']
        ec2.create_tags(Resources=[rt_priv_id], Tags=[{'Key': 'Name', 'Value': 'task-manager-rt-private'}])
        ec2.create_route(RouteTableId=rt_priv_id, DestinationCidrBlock='0.0.0.0/0', NatGatewayId=nat_id)
        for sn_id in priv_subs:
            ec2.associate_route_table(RouteTableId=rt_priv_id, SubnetId=sn_id)

        return vpc_id, pub_subs, priv_subs
    except Exception as e:
        logger.error(f"Error setting up VPC: {e}")
        raise

def create_security_groups(ec2, vpc_id, backend_port=5000):
    """Creates ALB, ECS, and partial RDS security groups with strict boundaries."""
    try:
        # ALB SG: Allows 80 from anywhere
        alb_sg_id = None
        sgs = ec2.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': ['task-manager-alb-sg']}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
        if sgs['SecurityGroups']:
            alb_sg_id = sgs['SecurityGroups'][0]['GroupId']
            logger.info(f"Reusing ALB SG: {alb_sg_id}")
        else:
            alb_sg = ec2.create_security_group(
                Description='Task Manager ALB SG', GroupName='task-manager-alb-sg', VpcId=vpc_id,
                TagSpecifications=[{'ResourceType': 'security-group', 'Tags': [{'Key': 'Name', 'Value': 'task-manager-alb-sg'}]}]
            )
            alb_sg_id = alb_sg['GroupId']
            ec2.authorize_security_group_ingress(GroupId=alb_sg_id, IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}])
            logger.info(f"Created ALB SG: {alb_sg_id}")

        # ECS SG: Allows 80 & 5000 only from ALB SG
        ecs_sg_id = None
        sgs = ec2.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': ['task-manager-ecs-sg']}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
        if sgs['SecurityGroups']:
            ecs_sg_id = sgs['SecurityGroups'][0]['GroupId']
            logger.info(f"Reusing ECS SG: {ecs_sg_id}")
        else:
            ecs_sg = ec2.create_security_group(
                Description='Task Manager ECS SG', GroupName='task-manager-ecs-sg', VpcId=vpc_id,
                TagSpecifications=[{'ResourceType': 'security-group', 'Tags': [{'Key': 'Name', 'Value': 'task-manager-ecs-sg'}]}]
            )
            ecs_sg_id = ecs_sg['GroupId']
            logger.info(f"Created ECS SG: {ecs_sg_id}")

        perms = [{'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'UserIdGroupPairs': [{'GroupId': alb_sg_id}]}]
        if backend_port != 80:
            perms.append({'IpProtocol': 'tcp', 'FromPort': backend_port, 'ToPort': backend_port, 'UserIdGroupPairs': [{'GroupId': alb_sg_id}]})
        
        try:
            ec2.authorize_security_group_ingress(GroupId=ecs_sg_id, IpPermissions=perms)
        except ec2.exceptions.ClientError as e:
            if 'InvalidPermission.Duplicate' not in str(e):
                logger.warning(f"Failed to add ECS SG ingress rules: {e}")

        return alb_sg_id, ecs_sg_id
    except Exception as e:
        logger.error(f"Error creating security groups: {e}")
        raise

def setup_ecr(ecr_client, repo_name):
    """Creates ECR repository or returns URI if it exists."""
    try:
        response = ecr_client.create_repository(
            repositoryName=repo_name, 
            imageScanningConfiguration={'scanOnPush': True}, 
            imageTagMutability='MUTABLE',
            tags=[{'Key': 'Name', 'Value': repo_name}]
        )
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

def setup_alb(elbv2_client, vpc_id, pub_subs, alb_sg_id, backend_port=5000, frontend_port=80):
    """Creates ALB in PUBLIC subnets, Target Groups, and Listener with path-based routing."""
    try:
        try:
            albs = elbv2_client.describe_load_balancers(Names=['task-manager-alb'])
            alb_arn = albs['LoadBalancers'][0]['LoadBalancerArn']
            alb_dns = albs['LoadBalancers'][0]['DNSName']
            logger.info(f"ALB already exists: {alb_dns}")
        except elbv2_client.exceptions.LoadBalancerNotFoundException:
            alb = elbv2_client.create_load_balancer(
                Name='task-manager-alb', 
                Subnets=pub_subs, 
                SecurityGroups=[alb_sg_id], 
                Scheme='internet-facing', 
                Type='application',
                Tags=[{'Key': 'Name', 'Value': 'task-manager-alb'}]
            )
            alb_arn = alb['LoadBalancers'][0]['LoadBalancerArn']
            alb_dns = alb['LoadBalancers'][0]['DNSName']
            logger.info(f"Created ALB: {alb_dns}")

        def create_tg(name, port, path='/health'):
            try:
                tgs = elbv2_client.describe_target_groups(Names=[name])
                return tgs['TargetGroups'][0]['TargetGroupArn']
            except elbv2_client.exceptions.TargetGroupNotFoundException:
                tg = elbv2_client.create_target_group(
                    Name=name, Protocol='HTTP', Port=port, VpcId=vpc_id, TargetType='ip', 
                    HealthCheckPath=path, HealthyThresholdCount=2, UnhealthyThresholdCount=2,
                    Tags=[{'Key': 'Name', 'Value': name}]
                )
                return tg['TargetGroups'][0]['TargetGroupArn']

        backend_tg_arn = create_tg('task-manager-tg', backend_port)
        frontend_tg_arn = create_tg('task-manager-frontend-tg', frontend_port)

        listeners = elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)
        if not listeners['Listeners']:
            listener = elbv2_client.create_listener(
                LoadBalancerArn=alb_arn, Protocol='HTTP', Port=80, 
                DefaultActions=[{'Type': 'forward', 'TargetGroupArn': frontend_tg_arn}],
                Tags=[{'Key': 'Name', 'Value': 'task-manager-alb-listener'}]
            )
            listener_arn = listener['Listeners'][0]['ListenerArn']
            elbv2_client.create_rule(
                ListenerArn=listener_arn, Priority=1, Conditions=[{'Field': 'path-pattern', 'Values': ['/api*']}], 
                Actions=[{'Type': 'forward', 'TargetGroupArn': backend_tg_arn}],
                Tags=[{'Key': 'Name', 'Value': 'task-manager-alb-api-rule'}]
            )
            logger.info("Created ALB Listener and path-based Rules")

        return alb_dns, backend_tg_arn, frontend_tg_arn
    except Exception as e:
        logger.error(f"Error setting up ALB: {e}")
        raise

def setup_rds(rds_client, ec2_client, vpc_id, priv_subs, ecs_sg_id, db_password, db_name='taskmanager', db_user='postgres'):
    """Creates RDS PostgreSQL Primary and Read Replica in PRIVATE subnets."""
    try:
        subnet_group_name = 'task-manager-db-subnet-group'
        try:
            rds_client.create_db_subnet_group(
                DBSubnetGroupName=subnet_group_name, 
                DBSubnetGroupDescription='Task Manager Private DB Subnets', 
                SubnetIds=priv_subs,
                Tags=[{'Key': 'Name', 'Value': subnet_group_name}]
            )
        except rds_client.exceptions.DBSubnetGroupAlreadyExistsFault: pass

        # RDS SG: Allow 5432 from ECS SG
        rds_sg_id = None
        try:
            sgs = ec2_client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': ['task-manager-rds-sg']}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
            rds_sg_id = sgs['SecurityGroups'][0]['GroupId']
        except (ec2_client.exceptions.ClientError, IndexError):
            pass
            
        if not rds_sg_id:
            rds_sg = ec2_client.create_security_group(
                Description='RDS SG', GroupName='task-manager-rds-sg', VpcId=vpc_id,
                TagSpecifications=[{'ResourceType': 'security-group', 'Tags': [{'Key': 'Name', 'Value': 'task-manager-rds-sg'}]}]
            )
            rds_sg_id = rds_sg['GroupId']
            
        try:
            ec2_client.authorize_security_group_ingress(GroupId=rds_sg_id, IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 5432, 'ToPort': 5432, 'UserIdGroupPairs': [{'GroupId': ecs_sg_id}]}])
        except ec2_client.exceptions.ClientError as e:
            if 'InvalidPermission.Duplicate' not in str(e):
                logger.warning(f"Failed to add RDS SG ingress rule: {e}")

        db_id = 'task-manager-db'
        replica_id = 'task-manager-db-replica'

        # 1. Primary Instance
        try:
            resp = rds_client.describe_db_instances(DBInstanceIdentifier=db_id)
            logger.info(f"RDS Primary {db_id} already exists.")
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
                PubliclyAccessible=False,
                MultiAZ=False,
                StorageType='gp2',
                BackupRetentionPeriod=1,
                Tags=[{'Key': 'Name', 'Value': db_id}]
            )
            logger.info(f"Creating RDS Primary {db_id} (this takes ~5-10 mins)...")

        rds_client.get_waiter('db_instance_available').wait(DBInstanceIdentifier=db_id)
        resp = rds_client.describe_db_instances(DBInstanceIdentifier=db_id)
        primary_endpoint = resp['DBInstances'][0]['Endpoint']['Address']
        logger.info(f"RDS Primary available at: {primary_endpoint}")

        # 2. Read Replica
        try:
            resp = rds_client.describe_db_instances(DBInstanceIdentifier=replica_id)
            logger.info(f"RDS Replica {replica_id} already exists.")
            replica_endpoint = resp['DBInstances'][0]['Endpoint']['Address']
        except rds_client.exceptions.DBInstanceNotFoundFault:
            rds_client.create_db_instance_read_replica(
                DBInstanceIdentifier=replica_id,
                SourceDBInstanceIdentifier=db_id,
                DBInstanceClass='db.t3.micro',
                PubliclyAccessible=False,
                VpcSecurityGroupIds=[rds_sg_id],
                Tags=[{'Key': 'Name', 'Value': replica_id}]
            )
            logger.info(f"Creating RDS Read Replica {replica_id} (this takes ~5-10 mins)...")

        rds_client.get_waiter('db_instance_available').wait(DBInstanceIdentifier=replica_id)
        resp = rds_client.describe_db_instances(DBInstanceIdentifier=replica_id)
        replica_endpoint = resp['DBInstances'][0]['Endpoint']['Address']
        logger.info(f"RDS Replica available at: {replica_endpoint}")

        return primary_endpoint, replica_endpoint, rds_sg_id
    except Exception as e:
        logger.error(f"Error setting up RDS: {e}")
        raise



def create_execution_role(iam_client):
    """Creates IAM role for ECS task execution."""
    role_name = 'task-manager-ecs-execution-role'
    trust_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    try:
        role = iam_client.create_role(
            RoleName=role_name, 
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Tags=[{'Key': 'Name', 'Value': role_name}]
        )
        role_arn = role['Role']['Arn']
        iam_client.attach_role_policy(RoleName=role_name, PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy')
        time.sleep(10)
        return role_arn
    except iam_client.exceptions.EntityAlreadyExistsException:
        return iam_client.get_role(RoleName=role_name)['Role']['Arn']

def create_ecs_cluster_and_role(ecs_client, iam_client, cluster_name):
    # Idempotency for cluster
    try:
        logger.info(f"Checking for existing ECS Cluster [{cluster_name}]...")
        clusters = ecs_client.describe_clusters(clusters=[cluster_name])
        if clusters['clusters'] and clusters['clusters'][0]['status'] == 'ACTIVE':
            logger.info(f"✅ ECS Cluster [{cluster_name}] already exists.")
            try:
                ecs_client.update_cluster_settings(
                    cluster=cluster_name,
                    settings=[{'name': 'containerInsights', 'value': 'enabled'}]
                )
            except Exception as e:
                logger.warning(f"Could not update container insights: {e}")
        else:
            ecs_client.create_cluster(
                clusterName=cluster_name,
                settings=[{'name': 'containerInsights', 'value': 'enabled'}],
                tags=[{'key': 'Name', 'value': cluster_name}]
            )
            logger.info(f"✅ Created new ECS Cluster [{cluster_name}] with Container Insights enabled.")
    except Exception as e:
        logger.warning(f"Error checking/creating cluster: {e}")
        
    return create_execution_role(iam_client)

def deploy_service(ecs_client, logs_client, region, cluster_name, task_family, container_name, image_uri, container_port, priv_subs, ecs_sg_id, tg_arn, env_vars, exec_role_arn, desired_count=1):
    """Deploys ECS Service directly into PRIVATE Subnets."""
    log_group = f'/ecs/{task_family}'
    try:
        logs_client.create_log_group(logGroupName=log_group, tags={'Name': log_group})
    except logs_client.exceptions.ResourceAlreadyExistsException: pass

    # Setup Metric Filters for Log Groups
    for level in ['ERROR', 'FATAL']:
        try:
            logs_client.put_metric_filter(
                logGroupName=log_group,
                filterName=f'{task_family}-{level.lower()}-count',
                filterPattern=f'"{level}"',
                metricTransformations=[{
                    'metricName': f'{task_family}-{level.capitalize()}Count',
                    'metricNamespace': 'TaskApp/Logs',
                    'metricValue': '1',
                    'defaultValue': 0.0
                }]
            )
        except Exception as e:
            logger.warning(f"Failed to create metric filter {level} for {log_group}: {e}")

    container_def = {'name': container_name, 'image': image_uri, 'portMappings': [{'containerPort': container_port, 'hostPort': container_port, 'protocol': 'tcp'}], 'essential': True, 'environment': env_vars, 'logConfiguration': {'logDriver': 'awslogs', 'options': {'awslogs-group': log_group, 'awslogs-region': region, 'awslogs-stream-prefix': 'ecs'}}}
    resp = ecs_client.register_task_definition(
        family=task_family, networkMode='awsvpc', containerDefinitions=[container_def], 
        requiresCompatibilities=['FARGATE'], cpu='256', memory='512', 
        executionRoleArn=exec_role_arn, taskRoleArn=exec_role_arn,
        tags=[{'key': 'Name', 'value': task_family}]
    )
    task_def_arn = resp['taskDefinition']['taskDefinitionArn']

    svc_name = f'{task_family}-service'
    net_config = {'awsvpcConfiguration': {'subnets': priv_subs, 'securityGroups': [ecs_sg_id], 'assignPublicIp': 'DISABLED'}}
    
    try:
        existing = ecs_client.describe_services(cluster=cluster_name, services=[svc_name])['services']
        if existing and existing[0]['status'] != 'INACTIVE':
            ecs_client.update_service(cluster=cluster_name, service=svc_name, taskDefinition=task_def_arn, networkConfiguration=net_config, forceNewDeployment=True, desiredCount=desired_count)
            logger.info(f"Updated existing ECS Service: {svc_name} with desired count {desired_count}")
        else:
            ecs_client.create_service(
                cluster=cluster_name, serviceName=svc_name, taskDefinition=task_def_arn, 
                loadBalancers=[{'targetGroupArn': tg_arn, 'containerName': container_name, 'containerPort': container_port}], 
                desiredCount=desired_count, launchType='FARGATE', networkConfiguration=net_config,
                tags=[{'key': 'Name', 'value': svc_name}]
            )
            logger.info(f"Created new ECS Service: {svc_name}")
    except Exception:
        ecs_client.create_service(
            cluster=cluster_name, serviceName=svc_name, taskDefinition=task_def_arn, 
            loadBalancers=[{'targetGroupArn': tg_arn, 'containerName': container_name, 'containerPort': container_port}], 
            desiredCount=desired_count, launchType='FARGATE', networkConfiguration=net_config,
            tags=[{'key': 'Name', 'value': svc_name}]
        )
        logger.info(f"Created new ECS Service (Exception fallback): {svc_name}")
        
    return svc_name

def wait_for_services(ecs_client, cluster_name, services):
    logger.info(f"Waiting for ECS services to stabilise: {services}...")
    try:
        ecs_client.get_waiter('services_stable').wait(cluster=cluster_name, services=services, WaiterConfig={'Delay': 15, 'MaxAttempts': 40})
        logger.info(f"✅ Services {services} successfully stabilized.")
    except Exception as e:
        logger.warning(f"⚠️ Service stabilizing waiter failed, checking logs: {e}")

def destroy_infrastructure(session, region_name):
    """Destroys all provisioned resources including Replicas, NAT, and EIP correctly."""
    logger.info("🔥 STARTING SECURE INFRASTRUCTURE DESTRUCTION")
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
            logger.info(f"Deleted ECS Service {s}")
        ecs.delete_cluster(cluster=cluster_name)
        logger.info(f"Deleted ECS Cluster {cluster_name}")
    except Exception: pass

    try:
        for name in ['task-manager-alb']:
            arn = elbv2.describe_load_balancers(Names=[name])['LoadBalancers'][0]['LoadBalancerArn']
            elbv2.delete_load_balancer(LoadBalancerArn=arn)
            logger.info(f"Deleted ALB {name}")
    except Exception: pass

    # Delete RDS Replica and Primary
    try:
        rds.delete_db_instance(DBInstanceIdentifier='task-manager-db-replica', SkipFinalSnapshot=True)
        logger.info("Deleted RDS Replica - Note: Depending on snapshot settings, this might require manual waiting.")
    except Exception: pass

    try:
        rds.delete_db_instance(DBInstanceIdentifier='task-manager-db', SkipFinalSnapshot=True)
        logger.info("Deleted RDS Primary.")
    except Exception: pass

    try:
        for repo in ['task-manager-repo', 'task-manager-frontend']:
            ecr.delete_repository(repositoryName=repo, force=True)
            logger.info(f"Deleted repository {repo}")
    except Exception: pass

    # Clean up NAT and EIP
    try:
        nats = ec2.describe_nat_gateways(Filters=[{'Name': 'state', 'Values': ['available', 'pending', 'deleting']}])
        nat_ids = []
        for nat in nats.get('NatGateways', []):
            if any(t['Value'] == 'task-manager-nat' for t in nat.get('Tags', [])):
                if nat['State'] != 'deleting':
                    ec2.delete_nat_gateway(NatGatewayId=nat['NatGatewayId'])
                    logger.info(f"Initiated NAT Gateway deletion: {nat['NatGatewayId']}")
                nat_ids.append(nat['NatGatewayId'])
        
        if nat_ids:
            logger.info(f"Waiting for NAT Gateway(s) {nat_ids} to be fully deleted... (Takes up to 5 mins)")
            ec2.get_waiter('nat_gateway_deleted').wait(NatGatewayIds=nat_ids)
            logger.info("NAT Gateway(s) fully deleted.")

        # Release EIPs
        eips = ec2.describe_addresses()
        for eip in eips.get('Addresses', []):
            if any(t['Value'] == 'task-manager-eip' for t in eip.get('Tags', [])):
                if 'AssociationId' in eip:
                    try: ec2.disassociate_address(AssociationId=eip['AssociationId'])
                    except Exception: pass
                ec2.release_address(AllocationId=eip['AllocationId'])
                logger.info(f"Released Elastic IP: {eip['PublicIp']}")

    except Exception as e: 
        logger.warning(f"NAT/EIP Cleanup error. Check manually if needed: {e}")

    logger.info("Cleanup iteration complete. (Note: VPC, final NAT Gateway stragglers, EIPs, and Security Groups may require manual final deletion)")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Configuration
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
    if os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'):
        return
    print("\n--- AWS Credentials Setup ---")
    access_key = input("Enter AWS_ACCESS_KEY_ID: ").strip()
    secret_key = input("Enter AWS_SECRET_ACCESS_KEY: ").strip()
    region     = input("Enter AWS_REGION (e.g., us-east-1): ").strip()
    if not access_key or not secret_key or not region:
        sys.exit(1)
    os.environ['AWS_ACCESS_KEY_ID'] = access_key
    os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key
    os.environ['AWS_DEFAULT_REGION'] = region
    os.environ['AWS_REGION'] = region

def ecr_login(region, registry_url):
    login_cmd = f"aws ecr get-login-password --region {region}"
    password = subprocess.check_output(login_cmd, shell=True).decode().strip()
    proc = subprocess.Popen(['docker', 'login', '--username', 'AWS', '--password-stdin', registry_url], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, err = proc.communicate(input=password.encode())
    if proc.returncode != 0: raise RuntimeError(f"Docker login failed: {err.decode()}")

def build_and_push(local_name, context_dir, ecr_uri, region):
    registry_url = ecr_uri.split('/')[0]
    ecr_login(region, registry_url)
    subprocess.run(['docker', 'build', '-t', local_name, context_dir], check=True)
    subprocess.run(['docker', 'tag', f'{local_name}:latest', f'{ecr_uri}:latest'], check=True)
    subprocess.run(['docker', 'push', f'{ecr_uri}:latest'], check=True)

def main():
    parser = argparse.ArgumentParser(description='Deploy 3-Tier Task Manager to AWS ECS Fargate')
    parser.add_argument('--destroy',       action='store_true',    help='Destroy all infrastructure')
    parser.add_argument('--skip-build',    action='store_true',    help='Skip Docker build and push')
    parser.add_argument('--enable-rds',    action='store_true',    help='Enable RDS PostgreSQL')
    parser.add_argument('--db-password',   type=str,               help='RDS Master Password', default='YourSecurePassword123!')
    parser.add_argument('--desired-count', type=int,               help='Desired ECS task count', default=2)
    parser.add_argument('--jwt-secret',    type=str,               help='JWT Secret Key', default='supersecretjwtkey123prod')
    args = parser.parse_args()

    prompt_credentials()
    region = os.environ['AWS_DEFAULT_REGION']

    session  = boto3.Session(
        aws_access_key_id     = os.environ['AWS_ACCESS_KEY_ID'],
        aws_secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY'],
        region_name           = region
    )

    if args.destroy:
        destroy_infrastructure(session, region)
        return

    ec2, ecr, elbv2, ecs, iam, rds, logs = (session.client(c) for c in ['ec2', 'ecr', 'elbv2', 'ecs', 'iam', 'rds', 'logs'])

    logger.info("=" * 60)
    logger.info("STARTING FULL 3-TIER ARCHITECTURE DEPLOYMENT")
    logger.info("=" * 60)

    # 1. Networking (2 Public Subnets, 2 Private Subnets, NAT, IGW)
    vpc_id, pub_subs, priv_subs = setup_vpc(ec2)
    alb_sg_id, ecs_sg_id = create_security_groups(ec2, vpc_id, BACKEND_PORT)

    # 2. ECR
    backend_ecr_uri  = setup_ecr(ecr, BACKEND_REPO)
    frontend_ecr_uri = setup_ecr(ecr, FRONTEND_REPO)

    # 3. Build/Push
    if not args.skip_build:
        build_and_push('task-manager-backend',  './backend',  backend_ecr_uri,  region)
        build_and_push('task-manager-frontend', './frontend', frontend_ecr_uri, region)

    # 4. RDS
    primary_db = 'localhost'
    replica_db = 'localhost'
    if args.enable_rds:
        primary_db, replica_db, rds_sg_id = setup_rds(rds, ec2, vpc_id, priv_subs, ecs_sg_id, args.db_password)

    # 5. ALB (Public Subnets)
    alb_dns, backend_tg_arn, frontend_tg_arn = setup_alb(elbv2, vpc_id, pub_subs, alb_sg_id, BACKEND_PORT, FRONTEND_PORT)

    # 6. ECS (Private Subnets)
    exec_role_arn = create_ecs_cluster_and_role(ecs, iam, CLUSTER_NAME)

    backend_env = [
        {'name': 'DB_HOST',     'value': primary_db},
        {'name': 'DB_REPLICA_HOST', 'value': replica_db},
        {'name': 'DB_PORT',     'value': '5432'},
        {'name': 'DB_USER',     'value': 'postgres'},
        {'name': 'DB_PASSWORD', 'value': args.db_password if args.enable_rds else 'postgres'},
        {'name': 'DB_NAME',     'value': 'taskmanager'},
        {'name': 'DB_SSL',      'value': 'true'},
        {'name': 'NODE_TLS_REJECT_UNAUTHORIZED', 'value': '0'},
        {'name': 'PORT',        'value': str(BACKEND_PORT)},
        {'name': 'NODE_ENV',    'value': 'production'},
        {'name': 'ALLOWED_ORIGINS', 'value': f'http://{alb_dns}'},
        {'name': 'JWT_SECRET',  'value': args.jwt_secret},
    ]

    backend_svc = deploy_service(
        ecs, logs, region, CLUSTER_NAME,
        BACKEND_FAMILY, BACKEND_CONTAINER, f'{backend_ecr_uri}:latest',
        BACKEND_PORT, priv_subs, ecs_sg_id, backend_tg_arn, backend_env, exec_role_arn, args.desired_count
    )

    frontend_svc = deploy_service(
        ecs, logs, region, CLUSTER_NAME,
        FRONTEND_FAMILY, FRONTEND_CONTAINER, f'{frontend_ecr_uri}:latest',
        FRONTEND_PORT, priv_subs, ecs_sg_id, frontend_tg_arn, [], exec_role_arn, args.desired_count
    )

    wait_for_services(ecs, CLUSTER_NAME, [backend_svc, frontend_svc])

    # 7. Multi-Retry Health Checks
    logger.info("🔍 Verifying deployment health over 5 retry cycles...")
    health_url = f"http://{alb_dns}/health"
    health_passed = False
    
    for i in range(5):
        try:
            health_resp = requests.get(health_url, timeout=15)
            if health_resp.status_code == 200:
                logger.info("✅ Health Check Passed! The 3-Tier Architecture is Live!")
                health_passed = True
                break
            else:
                logger.warning(f"⚠️ Health Check returned status {health_resp.status_code}. Retrying... ({i+1}/5)")
        except Exception as e:
            logger.warning(f"Could not reach health endpoint. Services may still be spinning up. Error: {e}. Retrying... ({i+1}/5)")
        
        if i < 4:
            time.sleep(10)
            
    if not health_passed:
        logger.error("❌ High Severity: Health Checks failed all 5 retries. Investigate ECS or LoadBalancer target logs.")

    logger.info("=" * 60)
    logger.info("🎉 DEPLOYMENT FINISHED 🎉")
    logger.info("=" * 60)
    logger.info(f"Frontend Interface: http://{alb_dns}")
    logger.info(f"Backend API Node:   http://{alb_dns}/api")

if __name__ == "__main__":
    main()
