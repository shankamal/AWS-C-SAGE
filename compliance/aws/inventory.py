import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from .types import InventoryData

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CollectorSpec:
    service: str
    client: str
    operation: str
    result_keys: tuple[str, ...]
    resource_type: str
    id_fields: tuple[str, ...]
    name_fields: tuple[str, ...] = ()
    arn_fields: tuple[str, ...] = ()
    status_fields: tuple[str, ...] = ()
    creation_fields: tuple[str, ...] = ()
    kwargs: dict[str, Any] = field(default_factory=dict)
    global_service: bool = False


def _json_safe(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return value


def _first(data, fields, default=""):
    if not isinstance(data, dict):
        return default
    for field_name in fields:
        value = data.get(field_name)
        if value not in (None, "", [], {}):
            return value
    return default


def _tags(raw):
    if not isinstance(raw, dict):
        return {}
    value = _first(raw, ("Tags", "tags", "TagList", "tagList"), {})
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    if isinstance(value, list):
        out = {}
        for item in value:
            if not isinstance(item, dict):
                continue
            key = item.get("Key") or item.get("key") or item.get("TagKey")
            val = item.get("Value") or item.get("value") or item.get("TagValue") or ""
            if key:
                out[str(key)] = str(val)
        return out
    return {}


def _resource_name(raw, tags, fields):
    value = _first(raw, fields)
    if value:
        return str(value)
    for key in ("Name", "name", "aws:cloudformation:stack-name"):
        if tags.get(key):
            return str(tags[key])
    return ""


def _extract_category(raw, keywords):
    if not isinstance(raw, dict):
        return {}
    selected = {}
    for key, value in raw.items():
        lower = key.lower()
        if any(token in lower for token in keywords):
            selected[key] = _json_safe(value)
    return selected


def _status_from_error(exc):
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        if any(x in code.lower() for x in ("accessdenied", "unauthorized", "forbidden")):
            return "ACCESS_DENIED", code
        if any(x in code.lower() for x in ("notfound", "unsupported", "invalidaction")):
            return "UNAVAILABLE", code
        return "ERROR", code or exc.__class__.__name__
    return "ERROR", exc.__class__.__name__


def _pages(client, operation, kwargs=None):
    kwargs = kwargs or {}
    if client.can_paginate(operation):
        yield from client.get_paginator(operation).paginate(**kwargs)
    else:
        yield getattr(client, operation)(**kwargs)


def _items(page, keys):
    for key in keys:
        value = page.get(key, []) if isinstance(page, dict) else []
        if isinstance(value, list):
            for item in value:
                yield item


def make_resource_key(account_id, region, service, resource_type, resource_id, resource_arn=""):
    basis = "|".join([
        str(account_id), str(region), str(service), str(resource_type), str(resource_arn or resource_id)
    ])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


class InventoryBuilder:
    def __init__(self, target):
        self.target = target
        self.rows: list[InventoryData] = []
        self.coverage: list[dict[str, Any]] = []
        self._index: dict[str, InventoryData] = {}

    def add(self, *, region, service, resource_type, resource_id, resource_name="", resource_arn="",
            status="", creation_time="", tags=None, configuration=None, networking=None, security=None,
            relationships=None, raw_attributes=None, source="service-api"):
        if not resource_id and not resource_arn:
            return None
        resource_id = str(resource_id or resource_arn)
        resource_arn = str(resource_arn or "")
        key = make_resource_key(
            self.target.account_id, region or "global", service, resource_type, resource_id, resource_arn
        )
        raw = _json_safe(raw_attributes or configuration or {})
        tags = _json_safe(tags or {})
        configuration = _json_safe(configuration or {})
        networking = _json_safe(networking or {})
        security = _json_safe(security or {})
        relationships = _json_safe(relationships or {})
        creation_time = _json_safe(creation_time) if creation_time else ""

        if key in self._index:
            existing = self._index[key]
            # Prefer richer service-specific data over broad Config/Tagging discovery.
            if len(json.dumps(raw, default=str)) > len(json.dumps(existing.raw_attributes, default=str)):
                existing.resource_name = resource_name or existing.resource_name
                existing.status = status or existing.status
                existing.creation_time = creation_time or existing.creation_time
                existing.tags = tags or existing.tags
                existing.configuration = configuration or existing.configuration
                existing.networking = networking or existing.networking
                existing.security = security or existing.security
                existing.relationships = relationships or existing.relationships
                existing.raw_attributes = raw
                existing.discovery_source = source
            return existing

        row = InventoryData(
            account_id=self.target.account_id,
            account_name=self.target.account_name,
            region=region or "global",
            service=service,
            resource_type=resource_type,
            resource_name=str(resource_name or ""),
            resource_id=resource_id,
            resource_arn=resource_arn,
            status=str(status or ""),
            creation_time=creation_time,
            tags=tags,
            configuration=configuration,
            networking=networking,
            security=security,
            relationships=relationships,
            raw_attributes=raw,
            discovery_source=source,
            resource_key=key,
        )
        self.rows.append(row)
        self._index[key] = row
        return row

    def add_raw(self, region, spec, raw, source="service-api"):
        if isinstance(raw, str):
            raw = {"Value": raw}
        if not isinstance(raw, dict):
            raw = {"Value": str(raw)}
        tags = _tags(raw)
        resource_id = _first(raw, spec.id_fields)
        resource_name = _resource_name(raw, tags, spec.name_fields)
        resource_arn = _first(raw, spec.arn_fields)
        status = _first(raw, spec.status_fields)
        creation = _first(raw, spec.creation_fields)
        networking = _extract_category(raw, ("vpc", "subnet", "network", "route", "endpoint", "ipaddress", "dns"))
        security = _extract_category(raw, ("security", "iam", "role", "policy", "kms", "encrypt", "public", "acl", "certificate"))
        relationships = _extract_category(raw, ("attach", "target", "member", "parent", "dependency", "association", "gateway", "cluster", "instance"))
        return self.add(
            region=region,
            service=spec.service,
            resource_type=spec.resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            resource_arn=resource_arn,
            status=status,
            creation_time=creation,
            tags=tags,
            configuration=raw,
            networking=networking,
            security=security,
            relationships=relationships,
            raw_attributes=raw,
            source=source,
        )

    def covered(self, *, region, service, resource_type, count, status="COMPLETE", message="", source="service-api"):
        self.coverage.append({
            "account_id": self.target.account_id,
            "account_name": self.target.account_name,
            "region": region or "global",
            "service": service,
            "resource_type": resource_type,
            "resource_count": int(count or 0),
            "scan_status": status,
            "message": str(message or ""),
            "source": source,
        })


REGIONAL_SPECS = [
    CollectorSpec("EC2", "ec2", "describe_volumes", ("Volumes",), "EBS Volume", ("VolumeId",), ("VolumeId",), (), ("State",), ("CreateTime",)),
    CollectorSpec("EC2", "ec2", "describe_snapshots", ("Snapshots",), "EBS Snapshot", ("SnapshotId",), ("Description",), (), ("State",), ("StartTime",), {"OwnerIds": ["self"]}),
    CollectorSpec("EC2", "ec2", "describe_images", ("Images",), "AMI", ("ImageId",), ("Name",), (), ("State",), ("CreationDate",), {"Owners": ["self"]}),
    CollectorSpec("EC2", "ec2", "describe_vpcs", ("Vpcs",), "VPC", ("VpcId",), ("VpcId",), (), ("State",)),
    CollectorSpec("EC2", "ec2", "describe_subnets", ("Subnets",), "Subnet", ("SubnetId",), ("SubnetId",), (), ("State",)),
    CollectorSpec("EC2", "ec2", "describe_route_tables", ("RouteTables",), "Route Table", ("RouteTableId",), ("RouteTableId",)),
    CollectorSpec("EC2", "ec2", "describe_internet_gateways", ("InternetGateways",), "Internet Gateway", ("InternetGatewayId",), ("InternetGatewayId",)),
    CollectorSpec("EC2", "ec2", "describe_nat_gateways", ("NatGateways",), "NAT Gateway", ("NatGatewayId",), ("NatGatewayId",), (), ("State",), ("CreateTime",)),
    CollectorSpec("EC2", "ec2", "describe_transit_gateways", ("TransitGateways",), "Transit Gateway", ("TransitGatewayId",), ("Description",), ("TransitGatewayArn",), ("State",), ("CreationTime",)),
    CollectorSpec("EC2", "ec2", "describe_vpc_endpoints", ("VpcEndpoints",), "VPC Endpoint", ("VpcEndpointId",), ("ServiceName",), (), ("State",), ("CreationTimestamp",)),
    CollectorSpec("EC2", "ec2", "describe_security_groups", ("SecurityGroups",), "Security Group", ("GroupId",), ("GroupName",)),
    CollectorSpec("EC2", "ec2", "describe_network_acls", ("NetworkAcls",), "Network ACL", ("NetworkAclId",), ("NetworkAclId",)),
    CollectorSpec("EC2", "ec2", "describe_addresses", ("Addresses",), "Elastic IP", ("AllocationId", "PublicIp"), ("PublicIp",)),
    CollectorSpec("EC2", "ec2", "describe_launch_templates", ("LaunchTemplates",), "Launch Template", ("LaunchTemplateId",), ("LaunchTemplateName",), (), (), ("CreateTime",)),
    CollectorSpec("EC2", "ec2", "describe_vpn_connections", ("VpnConnections",), "VPN Connection", ("VpnConnectionId",), ("VpnConnectionId",), (), ("State",)),
    CollectorSpec("EC2", "ec2", "describe_client_vpn_endpoints", ("ClientVpnEndpoints",), "Client VPN Endpoint", ("ClientVpnEndpointId",), ("Description",), (), ("Status",), ("CreationTime",)),
    CollectorSpec("ELBv2", "elbv2", "describe_load_balancers", ("LoadBalancers",), "Application/Network/Gateway Load Balancer", ("LoadBalancerArn",), ("LoadBalancerName",), ("LoadBalancerArn",), ("State",), ("CreatedTime",)),
    CollectorSpec("ELBv2", "elbv2", "describe_target_groups", ("TargetGroups",), "Target Group", ("TargetGroupArn",), ("TargetGroupName",), ("TargetGroupArn",)),
    CollectorSpec("ELB", "elb", "describe_load_balancers", ("LoadBalancerDescriptions",), "Classic Load Balancer", ("LoadBalancerName",), ("LoadBalancerName",), (), (), ("CreatedTime",)),
    CollectorSpec("Auto Scaling", "autoscaling", "describe_auto_scaling_groups", ("AutoScalingGroups",), "Auto Scaling Group", ("AutoScalingGroupARN", "AutoScalingGroupName"), ("AutoScalingGroupName",), ("AutoScalingGroupARN",), (), ("CreatedTime",)),
    CollectorSpec("Lambda", "lambda", "list_functions", ("Functions",), "Lambda Function", ("FunctionArn", "FunctionName"), ("FunctionName",), ("FunctionArn",), ("State",), ("LastModified",)),
    CollectorSpec("API Gateway", "apigateway", "get_rest_apis", ("items",), "REST API", ("id",), ("name",), (), (), ("createdDate",)),
    CollectorSpec("API Gateway v2", "apigatewayv2", "get_apis", ("Items",), "HTTP/WebSocket API", ("ApiId",), ("Name",), (), (), ("CreatedDate",)),
    CollectorSpec("CloudFormation", "cloudformation", "describe_stacks", ("Stacks",), "CloudFormation Stack", ("StackId",), ("StackName",), ("StackId",), ("StackStatus",), ("CreationTime",)),
    CollectorSpec("Systems Manager", "ssm", "describe_instance_information", ("InstanceInformationList",), "SSM Managed Node", ("InstanceId",), ("ComputerName", "Name"), (), ("PingStatus",), ("LastPingDateTime",)),
    CollectorSpec("Systems Manager", "ssm", "list_associations", ("Associations",), "SSM Association", ("AssociationId", "Name"), ("AssociationName", "Name"), (), ("AssociationVersion",)),
    CollectorSpec("Systems Manager", "ssm", "describe_maintenance_windows", ("WindowIdentities",), "SSM Maintenance Window", ("WindowId",), ("Name",), (), ("Enabled",), ("CreatedDate",)),
    CollectorSpec("RDS", "rds", "describe_db_instances", ("DBInstances",), "RDS Database", ("DBInstanceArn", "DBInstanceIdentifier"), ("DBInstanceIdentifier",), ("DBInstanceArn",), ("DBInstanceStatus",), ("InstanceCreateTime",)),
    CollectorSpec("RDS", "rds", "describe_db_clusters", ("DBClusters",), "Aurora/DB Cluster", ("DBClusterArn", "DBClusterIdentifier"), ("DBClusterIdentifier",), ("DBClusterArn",), ("Status",), ("ClusterCreateTime",)),
    CollectorSpec("ElastiCache", "elasticache", "describe_cache_clusters", ("CacheClusters",), "ElastiCache Cluster", ("ARN", "CacheClusterId"), ("CacheClusterId",), ("ARN",), ("CacheClusterStatus",), ("CacheClusterCreateTime",)),
    CollectorSpec("Redshift", "redshift", "describe_clusters", ("Clusters",), "Redshift Cluster", ("ClusterIdentifier",), ("ClusterIdentifier",), (), ("ClusterStatus",), ("ClusterCreateTime",)),
    CollectorSpec("EFS", "efs", "describe_file_systems", ("FileSystems",), "EFS File System", ("FileSystemId",), ("Name",), ("FileSystemArn",), ("LifeCycleState",), ("CreationTime",)),
    CollectorSpec("FSx", "fsx", "describe_file_systems", ("FileSystems",), "FSx File System", ("FileSystemId",), ("FileSystemId",), ("ResourceARN",), ("Lifecycle",), ("CreationTime",)),
    CollectorSpec("Backup", "backup", "list_backup_vaults", ("BackupVaultList",), "Backup Vault", ("BackupVaultArn", "BackupVaultName"), ("BackupVaultName",), ("BackupVaultArn",), (), ("CreationDate",)),
    CollectorSpec("CloudWatch", "cloudwatch", "describe_alarms", ("MetricAlarms",), "CloudWatch Metric Alarm", ("AlarmArn", "AlarmName"), ("AlarmName",), ("AlarmArn",), ("StateValue",), ("AlarmConfigurationUpdatedTimestamp",)),
    CollectorSpec("CloudWatch", "cloudwatch", "describe_alarms", ("CompositeAlarms",), "CloudWatch Composite Alarm", ("AlarmArn", "AlarmName"), ("AlarmName",), ("AlarmArn",), ("StateValue",), ("AlarmConfigurationUpdatedTimestamp",)),
    CollectorSpec("CloudWatch Logs", "logs", "describe_log_groups", ("logGroups",), "CloudWatch Log Group", ("arn", "logGroupName"), ("logGroupName",), ("arn",), (), ("creationTime",)),
    CollectorSpec("EventBridge", "events", "list_rules", ("Rules",), "EventBridge Rule", ("Arn", "Name"), ("Name",), ("Arn",), ("State",)),
    CollectorSpec("SNS", "sns", "list_topics", ("Topics",), "SNS Topic", ("TopicArn",), ("TopicArn",), ("TopicArn",)),
    CollectorSpec("Step Functions", "stepfunctions", "list_state_machines", ("stateMachines",), "Step Functions State Machine", ("stateMachineArn",), ("name",), ("stateMachineArn",), (), ("creationDate",)),
    CollectorSpec("Glue", "glue", "get_jobs", ("Jobs",), "Glue Job", ("Name",), ("Name",), (), (), ("CreatedOn",)),
    CollectorSpec("Glue", "glue", "get_crawlers", ("Crawlers",), "Glue Crawler", ("Name",), ("Name",), (), ("State",), ("CreationTime",)),
    CollectorSpec("Glue", "glue", "get_databases", ("DatabaseList",), "Glue Database", ("Name",), ("Name",), (), (), ("CreateTime",)),
    CollectorSpec("EMR", "emr", "list_clusters", ("Clusters",), "EMR Cluster", ("Id",), ("Name",), (), ("Status",), ("Status",)),
    CollectorSpec("SageMaker", "sagemaker", "list_endpoints", ("Endpoints",), "SageMaker Endpoint", ("EndpointArn", "EndpointName"), ("EndpointName",), ("EndpointArn",), ("EndpointStatus",), ("CreationTime",)),
    CollectorSpec("SageMaker", "sagemaker", "list_models", ("Models",), "SageMaker Model", ("ModelArn", "ModelName"), ("ModelName",), ("ModelArn",), (), ("CreationTime",)),
    CollectorSpec("SageMaker", "sagemaker", "list_notebook_instances", ("NotebookInstances",), "SageMaker Notebook Instance", ("NotebookInstanceArn", "NotebookInstanceName"), ("NotebookInstanceName",), ("NotebookInstanceArn",), ("NotebookInstanceStatus",), ("CreationTime",)),
    CollectorSpec("SageMaker", "sagemaker", "list_training_jobs", ("TrainingJobSummaries",), "SageMaker Training Job", ("TrainingJobArn", "TrainingJobName"), ("TrainingJobName",), ("TrainingJobArn",), ("TrainingJobStatus",), ("CreationTime",)),
    CollectorSpec("ECR", "ecr", "describe_repositories", ("repositories",), "ECR Repository", ("repositoryArn", "repositoryName"), ("repositoryName",), ("repositoryArn",), (), ("createdAt",)),
    CollectorSpec("MQ", "mq", "list_brokers", ("BrokerSummaries",), "Amazon MQ Broker", ("BrokerArn", "BrokerId"), ("BrokerName",), ("BrokerArn",), ("BrokerState",), ("Created",)),
    CollectorSpec("MSK", "kafka", "list_clusters_v2", ("ClusterInfoList",), "MSK Cluster", ("ClusterArn",), ("ClusterName",), ("ClusterArn",), ("State",), ("CreationTime",)),
    CollectorSpec("MemoryDB", "memorydb", "describe_clusters", ("Clusters",), "MemoryDB Cluster", ("ARN", "Name"), ("Name",), ("ARN",), ("Status",), ("CreateTime",)),
    CollectorSpec("DMS", "dms", "describe_replication_instances", ("ReplicationInstances",), "DMS Replication Instance", ("ReplicationInstanceArn",), ("ReplicationInstanceIdentifier",), ("ReplicationInstanceArn",), ("ReplicationInstanceStatus",), ("InstanceCreateTime",)),
    CollectorSpec("DMS", "dms", "describe_replication_tasks", ("ReplicationTasks",), "DMS Replication Task", ("ReplicationTaskArn",), ("ReplicationTaskIdentifier",), ("ReplicationTaskArn",), ("Status",), ("ReplicationTaskCreationDate",)),
    CollectorSpec("Transfer Family", "transfer", "list_servers", ("Servers",), "Transfer Family Server", ("Arn", "ServerId"), ("ServerId",), ("Arn",), ("State",)),
    CollectorSpec("Network Firewall", "network-firewall", "list_firewalls", ("Firewalls",), "Network Firewall", ("FirewallArn",), ("FirewallName",), ("FirewallArn",)),
    CollectorSpec("AppSync", "appsync", "list_graphql_apis", ("graphqlApis",), "AppSync GraphQL API", ("arn", "apiId"), ("name",), ("arn",), ("visibility",)),
    CollectorSpec("CloudTrail", "cloudtrail", "describe_trails", ("trailList",), "CloudTrail Trail", ("TrailARN", "Name"), ("Name",), ("TrailARN",)),
]


GLOBAL_SPECS = [
    CollectorSpec("IAM", "iam", "list_users", ("Users",), "IAM User", ("Arn", "UserId"), ("UserName",), ("Arn",), (), ("CreateDate",), global_service=True),
    CollectorSpec("IAM", "iam", "list_roles", ("Roles",), "IAM Role", ("Arn", "RoleId"), ("RoleName",), ("Arn",), (), ("CreateDate",), global_service=True),
    CollectorSpec("IAM", "iam", "list_groups", ("Groups",), "IAM Group", ("Arn", "GroupId"), ("GroupName",), ("Arn",), (), ("CreateDate",), global_service=True),
    CollectorSpec("IAM", "iam", "list_policies", ("Policies",), "IAM Customer Managed Policy", ("Arn", "PolicyId"), ("PolicyName",), ("Arn",), (), ("CreateDate",), {"Scope": "Local"}, True),
    CollectorSpec("Route53", "route53", "list_hosted_zones", ("HostedZones",), "Route53 Hosted Zone", ("Id",), ("Name",), (), (), (), {}, True),
    CollectorSpec("Route53", "route53", "list_health_checks", ("HealthChecks",), "Route53 Health Check", ("Id",), ("Id",), (), (), (), {}, True),
    CollectorSpec("CloudFront", "cloudfront", "list_distributions", ("DistributionList.Items",), "CloudFront Distribution", ("ARN", "Id"), ("DomainName",), ("ARN",), ("Status",), ("LastModifiedTime",), {}, True),
    CollectorSpec("Organizations", "organizations", "list_accounts", ("Accounts",), "AWS Organization Account", ("Arn", "Id"), ("Name",), ("Arn",), ("Status",), ("JoinedTimestamp",), {}, True),
    CollectorSpec("Control Tower", "controltower", "list_landing_zones", ("landingZones",), "Control Tower Landing Zone", ("arn",), ("arn",), ("arn",), (), (), {}, True),
    CollectorSpec("Direct Connect", "directconnect", "describe_connections", ("connections",), "Direct Connect Connection", ("connectionId",), ("connectionName",), (), ("connectionState",), (), {}, True),
    CollectorSpec("Direct Connect", "directconnect", "describe_virtual_interfaces", ("virtualInterfaces",), "Direct Connect Virtual Interface", ("virtualInterfaceId",), ("virtualInterfaceName",), (), ("virtualInterfaceState",), (), {}, True),
    CollectorSpec("Direct Connect", "directconnect", "describe_direct_connect_gateways", ("directConnectGateways",), "Direct Connect Gateway", ("directConnectGatewayId",), ("directConnectGatewayName",), (), ("directConnectGatewayState",), (), {}, True),
    CollectorSpec("Shield", "shield", "list_protections", ("Protections",), "Shield Protection", ("ProtectionArn", "Id"), ("Name",), ("ProtectionArn",), (), (), {}, True),
]


def _collect_spec(session, builder, region, spec):
    count = 0
    try:
        client = session.client(spec.client, region_name=region)
        if not hasattr(client, spec.operation):
            builder.covered(region=region, service=spec.service, resource_type=spec.resource_type, count=0,
                            status="UNAVAILABLE", message=f"Boto3 client does not expose {spec.operation}")
            return
        for page in _pages(client, spec.operation, dict(spec.kwargs)):
            # Handle CloudFront's nested DistributionList.Items shape.
            if spec.result_keys == ("DistributionList.Items",):
                items = ((page.get("DistributionList") or {}).get("Items") or [])
            else:
                items = list(_items(page, spec.result_keys))
            for raw in items:
                if builder.add_raw(region, spec, raw):
                    count += 1
        builder.covered(region=region, service=spec.service, resource_type=spec.resource_type, count=count)
    except (ClientError, BotoCoreError, Exception) as exc:
        status, code = _status_from_error(exc)
        logger.info("Inventory collector %s/%s failed in %s: %s", spec.service, spec.resource_type, region, exc)
        builder.covered(region=region, service=spec.service, resource_type=spec.resource_type, count=count,
                        status=status, message=code)


def _collect_ec2_instances(session, builder, region):
    count = 0
    try:
        ec2 = session.client("ec2", region_name=region)
        for page in _pages(ec2, "describe_instances"):
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    tags = _tags(instance)
                    name = tags.get("Name", "")
                    builder.add(
                        region=region, service="EC2", resource_type="EC2 Instance",
                        resource_id=instance.get("InstanceId", ""), resource_name=name,
                        status=((instance.get("State") or {}).get("Name", "")),
                        creation_time=instance.get("LaunchTime", ""), tags=tags,
                        configuration=instance,
                        networking=_extract_category(instance, ("vpc", "subnet", "network", "ipaddress", "dns", "securitygroup")),
                        security={"SecurityGroups": instance.get("SecurityGroups", []), "IamInstanceProfile": instance.get("IamInstanceProfile")},
                        relationships={"BlockDeviceMappings": instance.get("BlockDeviceMappings", []), "NetworkInterfaces": instance.get("NetworkInterfaces", [])},
                        raw_attributes=instance,
                    )
                    count += 1
        builder.covered(region=region, service="EC2", resource_type="EC2 Instance", count=count)
    except Exception as exc:
        status, code = _status_from_error(exc)
        builder.covered(region=region, service="EC2", resource_type="EC2 Instance", count=count, status=status, message=code)


def _collect_ecs(session, builder, region):
    cluster_count = service_count = task_count = fargate_count = 0
    try:
        ecs = session.client("ecs", region_name=region)
        cluster_arns = []
        for page in _pages(ecs, "list_clusters"):
            cluster_arns.extend(page.get("clusterArns", []))
        for start in range(0, len(cluster_arns), 100):
            for cluster in ecs.describe_clusters(clusters=cluster_arns[start:start + 100], include=["TAGS", "SETTINGS", "CONFIGURATIONS"]).get("clusters", []):
                builder.add(region=region, service="ECS", resource_type="ECS Cluster",
                            resource_id=cluster.get("clusterArn", ""), resource_name=cluster.get("clusterName", ""),
                            resource_arn=cluster.get("clusterArn", ""), status=cluster.get("status", ""), tags=_tags(cluster),
                            configuration=cluster, relationships=_extract_category(cluster, ("service", "task", "capacityprovider")),
                            raw_attributes=cluster)
                cluster_count += 1

        for cluster_arn in cluster_arns:
            services = []
            for page in _pages(ecs, "list_services", {"cluster": cluster_arn}):
                services.extend(page.get("serviceArns", []))
            for start in range(0, len(services), 10):
                response = ecs.describe_services(cluster=cluster_arn, services=services[start:start + 10], include=["TAGS"])
                for service in response.get("services", []):
                    launch = service.get("launchType", "")
                    cps = [x.get("capacityProvider", "") for x in service.get("capacityProviderStrategy", [])]
                    is_fargate = launch == "FARGATE" or any("FARGATE" in x for x in cps)
                    rtype = "ECS Fargate Service" if is_fargate else "ECS Service"
                    builder.add(region=region, service="ECS", resource_type=rtype,
                                resource_id=service.get("serviceArn", ""), resource_name=service.get("serviceName", ""),
                                resource_arn=service.get("serviceArn", ""), status=service.get("status", ""),
                                creation_time=service.get("createdAt", ""), tags=_tags(service), configuration=service,
                                networking={"networkConfiguration": service.get("networkConfiguration")},
                                security={"roleArn": service.get("roleArn")},
                                relationships={"clusterArn": service.get("clusterArn"), "loadBalancers": service.get("loadBalancers", []), "taskDefinition": service.get("taskDefinition")},
                                raw_attributes=service)
                    service_count += 1
                    if is_fargate:
                        fargate_count += 1

            tasks = []
            for page in _pages(ecs, "list_tasks", {"cluster": cluster_arn}):
                tasks.extend(page.get("taskArns", []))
            for start in range(0, len(tasks), 100):
                for task in ecs.describe_tasks(cluster=cluster_arn, tasks=tasks[start:start + 100], include=["TAGS"]).get("tasks", []):
                    launch = task.get("launchType", "")
                    rtype = "ECS Fargate Task" if launch == "FARGATE" else "ECS Task"
                    builder.add(region=region, service="ECS", resource_type=rtype,
                                resource_id=task.get("taskArn", ""), resource_name=task.get("group", ""),
                                resource_arn=task.get("taskArn", ""), status=task.get("lastStatus", ""),
                                creation_time=task.get("createdAt", ""), tags=_tags(task), configuration=task,
                                networking={"attachments": task.get("attachments", [])},
                                security={"taskRoleArn": task.get("taskRoleArn"), "executionRoleArn": task.get("executionRoleArn")},
                                relationships={"clusterArn": task.get("clusterArn"), "taskDefinitionArn": task.get("taskDefinitionArn"), "containers": task.get("containers", [])},
                                raw_attributes=task)
                    task_count += 1
        builder.covered(region=region, service="ECS", resource_type="ECS Cluster", count=cluster_count)
        builder.covered(region=region, service="ECS", resource_type="ECS Service", count=service_count)
        builder.covered(region=region, service="ECS", resource_type="ECS Task", count=task_count)
        builder.covered(region=region, service="ECS", resource_type="Fargate Service/Task", count=fargate_count)
    except Exception as exc:
        status, code = _status_from_error(exc)
        for rtype, count in (("ECS Cluster", cluster_count), ("ECS Service", service_count), ("ECS Task", task_count), ("Fargate Service/Task", fargate_count)):
            builder.covered(region=region, service="ECS", resource_type=rtype, count=count, status=status, message=code)


def _collect_eks(session, builder, region):
    cluster_count = node_count = fargate_count = 0
    try:
        eks = session.client("eks", region_name=region)
        clusters = []
        for page in _pages(eks, "list_clusters"):
            clusters.extend(page.get("clusters", []))
        for name in clusters:
            cluster = eks.describe_cluster(name=name).get("cluster", {})
            builder.add(region=region, service="EKS", resource_type="EKS Cluster",
                        resource_id=cluster.get("arn", name), resource_name=name, resource_arn=cluster.get("arn", ""),
                        status=cluster.get("status", ""), creation_time=cluster.get("createdAt", ""), tags=cluster.get("tags", {}),
                        configuration=cluster,
                        networking={"resourcesVpcConfig": cluster.get("resourcesVpcConfig"), "kubernetesNetworkConfig": cluster.get("kubernetesNetworkConfig")},
                        security={"roleArn": cluster.get("roleArn"), "encryptionConfig": cluster.get("encryptionConfig")},
                        raw_attributes=cluster)
            cluster_count += 1
            nodegroups = []
            for page in _pages(eks, "list_nodegroups", {"clusterName": name}):
                nodegroups.extend(page.get("nodegroups", []))
            for node_name in nodegroups:
                node = eks.describe_nodegroup(clusterName=name, nodegroupName=node_name).get("nodegroup", {})
                builder.add(region=region, service="EKS", resource_type="EKS Node Group",
                            resource_id=node.get("nodegroupArn", node_name), resource_name=node_name, resource_arn=node.get("nodegroupArn", ""),
                            status=node.get("status", ""), creation_time=node.get("createdAt", ""), tags=node.get("tags", {}),
                            configuration=node, networking={"subnets": node.get("subnets", []), "remoteAccess": node.get("remoteAccess")},
                            security={"nodeRole": node.get("nodeRole")}, relationships={"clusterName": name, "resources": node.get("resources")},
                            raw_attributes=node)
                node_count += 1
            profiles = []
            for page in _pages(eks, "list_fargate_profiles", {"clusterName": name}):
                profiles.extend(page.get("fargateProfileNames", []))
            for profile_name in profiles:
                profile = eks.describe_fargate_profile(clusterName=name, fargateProfileName=profile_name).get("fargateProfile", {})
                builder.add(region=region, service="EKS", resource_type="EKS Fargate Profile",
                            resource_id=profile.get("fargateProfileArn", profile_name), resource_name=profile_name,
                            resource_arn=profile.get("fargateProfileArn", ""), status=profile.get("status", ""),
                            creation_time=profile.get("createdAt", ""), tags=profile.get("tags", {}), configuration=profile,
                            networking={"subnets": profile.get("subnets", [])}, security={"podExecutionRoleArn": profile.get("podExecutionRoleArn")},
                            relationships={"clusterName": name, "selectors": profile.get("selectors", [])}, raw_attributes=profile)
                fargate_count += 1
        builder.covered(region=region, service="EKS", resource_type="EKS Cluster", count=cluster_count)
        builder.covered(region=region, service="EKS", resource_type="EKS Node Group", count=node_count)
        builder.covered(region=region, service="EKS", resource_type="EKS Fargate Profile", count=fargate_count)
    except Exception as exc:
        status, code = _status_from_error(exc)
        for rtype, count in (("EKS Cluster", cluster_count), ("EKS Node Group", node_count), ("EKS Fargate Profile", fargate_count)):
            builder.covered(region=region, service="EKS", resource_type=rtype, count=count, status=status, message=code)


def _collect_dynamodb(session, builder, region):
    count = 0
    try:
        client = session.client("dynamodb", region_name=region)
        names = []
        for page in _pages(client, "list_tables"):
            names.extend(page.get("TableNames", []))
        for name in names:
            table = client.describe_table(TableName=name).get("Table", {})
            arn = table.get("TableArn", "")
            try:
                tags = {x.get("Key"): x.get("Value", "") for x in client.list_tags_of_resource(ResourceArn=arn).get("Tags", [])} if arn else {}
            except Exception:
                tags = {}
            builder.add(region=region, service="DynamoDB", resource_type="DynamoDB Table",
                        resource_id=arn or name, resource_name=name, resource_arn=arn, status=table.get("TableStatus", ""),
                        creation_time=table.get("CreationDateTime", ""), tags=tags, configuration=table,
                        security={"SSEDescription": table.get("SSEDescription")}, relationships={"GlobalSecondaryIndexes": table.get("GlobalSecondaryIndexes", []), "Replicas": table.get("Replicas", [])},
                        raw_attributes=table)
            count += 1
        builder.covered(region=region, service="DynamoDB", resource_type="DynamoDB Table", count=count)
    except Exception as exc:
        status, code = _status_from_error(exc)
        builder.covered(region=region, service="DynamoDB", resource_type="DynamoDB Table", count=count, status=status, message=code)


def _collect_opensearch(session, builder, region):
    count = 0
    try:
        client = session.client("opensearch", region_name=region)
        names = []
        for page in _pages(client, "list_domain_names"):
            names.extend([x.get("DomainName") for x in page.get("DomainNames", []) if x.get("DomainName")])
        for name in names:
            domain = client.describe_domain(DomainName=name).get("DomainStatus", {})
            builder.add(region=region, service="OpenSearch", resource_type="OpenSearch Domain",
                        resource_id=domain.get("ARN", name), resource_name=name, resource_arn=domain.get("ARN", ""),
                        status="Processing" if domain.get("Processing") else "Active", tags={}, configuration=domain,
                        networking={"VPCOptions": domain.get("VPCOptions"), "Endpoints": domain.get("Endpoints")},
                        security={"EncryptionAtRestOptions": domain.get("EncryptionAtRestOptions"), "NodeToNodeEncryptionOptions": domain.get("NodeToNodeEncryptionOptions"), "DomainEndpointOptions": domain.get("DomainEndpointOptions"), "AdvancedSecurityOptions": domain.get("AdvancedSecurityOptions")},
                        raw_attributes=domain)
            count += 1
        builder.covered(region=region, service="OpenSearch", resource_type="OpenSearch Domain", count=count)
    except Exception as exc:
        status, code = _status_from_error(exc)
        builder.covered(region=region, service="OpenSearch", resource_type="OpenSearch Domain", count=count, status=status, message=code)


def _collect_kms(session, builder, region):
    count = 0
    try:
        kms = session.client("kms", region_name=region)
        keys = []
        for page in _pages(kms, "list_keys"):
            keys.extend(page.get("Keys", []))
        for key in keys:
            key_id = key.get("KeyId", "")
            meta = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
            try:
                tags = {x.get("TagKey"): x.get("TagValue", "") for x in kms.list_resource_tags(KeyId=key_id).get("Tags", [])}
            except Exception:
                tags = {}
            builder.add(region=region, service="KMS", resource_type="KMS Key",
                        resource_id=meta.get("Arn", key_id), resource_name=meta.get("Description", ""), resource_arn=meta.get("Arn", ""),
                        status=meta.get("KeyState", ""), creation_time=meta.get("CreationDate", ""), tags=tags, configuration=meta,
                        security={"KeyManager": meta.get("KeyManager"), "KeySpec": meta.get("KeySpec"), "KeyUsage": meta.get("KeyUsage"), "Origin": meta.get("Origin")},
                        raw_attributes=meta)
            count += 1
        builder.covered(region=region, service="KMS", resource_type="KMS Key", count=count)
    except Exception as exc:
        status, code = _status_from_error(exc)
        builder.covered(region=region, service="KMS", resource_type="KMS Key", count=count, status=status, message=code)


def _collect_secrets(session, builder, region):
    count = 0
    try:
        client = session.client("secretsmanager", region_name=region)
        for page in _pages(client, "list_secrets", {"IncludePlannedDeletion": True}):
            for secret in page.get("SecretList", []):
                builder.add(region=region, service="Secrets Manager", resource_type="Secrets Manager Secret",
                            resource_id=secret.get("ARN", secret.get("Name", "")), resource_name=secret.get("Name", ""),
                            resource_arn=secret.get("ARN", ""), status="PendingDeletion" if secret.get("DeletedDate") else "Active",
                            creation_time=secret.get("CreatedDate", ""), tags=_tags(secret), configuration=secret,
                            security={"KmsKeyId": secret.get("KmsKeyId")}, raw_attributes=secret)
                count += 1
        builder.covered(region=region, service="Secrets Manager", resource_type="Secrets Manager Secret", count=count)
    except Exception as exc:
        status, code = _status_from_error(exc)
        builder.covered(region=region, service="Secrets Manager", resource_type="Secrets Manager Secret", count=count, status=status, message=code)


def _collect_acm(session, builder, region):
    count = 0
    try:
        acm = session.client("acm", region_name=region)
        arns = []
        for page in _pages(acm, "list_certificates"):
            arns.extend([x.get("CertificateArn") for x in page.get("CertificateSummaryList", []) if x.get("CertificateArn")])
        for arn in arns:
            cert = acm.describe_certificate(CertificateArn=arn).get("Certificate", {})
            builder.add(region=region, service="ACM", resource_type="ACM Certificate",
                        resource_id=arn, resource_name=cert.get("DomainName", ""), resource_arn=arn, status=cert.get("Status", ""),
                        creation_time=cert.get("CreatedAt", ""), tags={}, configuration=cert,
                        security={"KeyAlgorithm": cert.get("KeyAlgorithm"), "SignatureAlgorithm": cert.get("SignatureAlgorithm"), "Type": cert.get("Type")},
                        relationships={"InUseBy": cert.get("InUseBy", []), "SubjectAlternativeNames": cert.get("SubjectAlternativeNames", [])}, raw_attributes=cert)
            count += 1
        builder.covered(region=region, service="ACM", resource_type="ACM Certificate", count=count)
    except Exception as exc:
        status, code = _status_from_error(exc)
        builder.covered(region=region, service="ACM", resource_type="ACM Certificate", count=count, status=status, message=code)


def _collect_sqs(session, builder, region):
    count = 0
    try:
        sqs = session.client("sqs", region_name=region)
        urls = []
        for page in _pages(sqs, "list_queues"):
            urls.extend(page.get("QueueUrls", []))
        for url in urls:
            attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"]).get("Attributes", {})
            try:
                tags = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
            except Exception:
                tags = {}
            arn = attrs.get("QueueArn", "")
            name = url.rsplit("/", 1)[-1]
            raw = {"QueueUrl": url, **attrs}
            builder.add(region=region, service="SQS", resource_type="SQS Queue", resource_id=arn or url,
                        resource_name=name, resource_arn=arn, status="Active", creation_time=attrs.get("CreatedTimestamp", ""),
                        tags=tags, configuration=raw, security={"KmsMasterKeyId": attrs.get("KmsMasterKeyId"), "Policy": attrs.get("Policy")},
                        relationships={"DeadLetterTarget": attrs.get("RedrivePolicy")}, raw_attributes=raw)
            count += 1
        builder.covered(region=region, service="SQS", resource_type="SQS Queue", count=count)
    except Exception as exc:
        status, code = _status_from_error(exc)
        builder.covered(region=region, service="SQS", resource_type="SQS Queue", count=count, status=status, message=code)


def _collect_backup_recovery_points(session, builder, region):
    count = 0
    try:
        backup = session.client("backup", region_name=region)
        vaults = []
        for page in _pages(backup, "list_backup_vaults"):
            vaults.extend([x.get("BackupVaultName") for x in page.get("BackupVaultList", []) if x.get("BackupVaultName")])
        for vault in vaults:
            for page in _pages(backup, "list_recovery_points_by_backup_vault", {"BackupVaultName": vault}):
                for rp in page.get("RecoveryPoints", []):
                    arn = rp.get("RecoveryPointArn", "")
                    builder.add(region=region, service="Backup", resource_type="Backup Recovery Point",
                                resource_id=arn, resource_name=rp.get("ResourceName", ""), resource_arn=arn,
                                status=rp.get("Status", ""), creation_time=rp.get("CreationDate", ""), tags={}, configuration=rp,
                                security={"EncryptionKeyArn": rp.get("EncryptionKeyArn"), "IsEncrypted": rp.get("IsEncrypted")},
                                relationships={"BackupVaultName": vault, "ResourceArn": rp.get("ResourceArn")}, raw_attributes=rp)
                    count += 1
        builder.covered(region=region, service="Backup", resource_type="Backup Recovery Point", count=count)
    except Exception as exc:
        status, code = _status_from_error(exc)
        builder.covered(region=region, service="Backup", resource_type="Backup Recovery Point", count=count, status=status, message=code)


def _collect_glue_tables(session, builder, region):
    count = 0
    try:
        glue = session.client("glue", region_name=region)
        dbs = []
        for page in _pages(glue, "get_databases"):
            dbs.extend([x.get("Name") for x in page.get("DatabaseList", []) if x.get("Name")])
        for db in dbs:
            for page in _pages(glue, "get_tables", {"DatabaseName": db}):
                for table in page.get("TableList", []):
                    name = table.get("Name", "")
                    builder.add(region=region, service="Glue", resource_type="Glue Table",
                                resource_id=f"{db}/{name}", resource_name=name, status="Available",
                                creation_time=table.get("CreateTime", ""), tags={}, configuration=table,
                                relationships={"DatabaseName": db}, raw_attributes=table)
                    count += 1
        builder.covered(region=region, service="Glue", resource_type="Glue Table", count=count)
    except Exception as exc:
        status, code = _status_from_error(exc)
        builder.covered(region=region, service="Glue", resource_type="Glue Table", count=count, status=status, message=code)


def _collect_s3(session, builder, home_region):
    count = 0
    try:
        s3 = session.client("s3", region_name=home_region)
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket.get("Name", "")
            raw = dict(bucket)
            tags = {}
            security = {}
            relationships = {}
            region = "global"
            try:
                loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
                region = "us-east-1" if not loc else ("eu-west-1" if loc == "EU" else loc)
                raw["LocationConstraint"] = region
            except Exception as exc:
                raw["LocationError"] = str(exc)
            for key, operation in (
                ("Versioning", "get_bucket_versioning"),
                ("Encryption", "get_bucket_encryption"),
                ("PublicAccessBlock", "get_public_access_block"),
                ("PolicyStatus", "get_bucket_policy_status"),
                ("OwnershipControls", "get_bucket_ownership_controls"),
                ("Lifecycle", "get_bucket_lifecycle_configuration"),
                ("Replication", "get_bucket_replication"),
            ):
                try:
                    value = getattr(s3, operation)(Bucket=name)
                    value.pop("ResponseMetadata", None)
                    raw[key] = value
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code not in ("NoSuchTagSet", "NoSuchLifecycleConfiguration", "ReplicationConfigurationNotFoundError", "ServerSideEncryptionConfigurationNotFoundError", "NoSuchPublicAccessBlockConfiguration"):
                        raw[f"{key}Error"] = code
                except Exception as exc:
                    raw[f"{key}Error"] = str(exc)
            try:
                tags = {x.get("Key"): x.get("Value", "") for x in s3.get_bucket_tagging(Bucket=name).get("TagSet", [])}
            except Exception:
                tags = {}
            security = {k: raw.get(k) for k in ("Encryption", "PublicAccessBlock", "PolicyStatus", "OwnershipControls") if k in raw}
            relationships = {k: raw.get(k) for k in ("Replication",) if k in raw}
            builder.add(region=region, service="S3", resource_type="S3 Bucket", resource_id=name,
                        resource_name=name, resource_arn=f"arn:aws:s3:::{name}", status="Available",
                        creation_time=bucket.get("CreationDate", ""), tags=tags, configuration=raw,
                        security=security, relationships=relationships, raw_attributes=raw)
            count += 1
        builder.covered(region="global", service="S3", resource_type="S3 Bucket", count=count)
    except Exception as exc:
        status, code = _status_from_error(exc)
        builder.covered(region="global", service="S3", resource_type="S3 Bucket", count=count, status=status, message=code)


def _collect_waf(session, builder, region, scope):
    suffix = "CloudFront" if scope == "CLOUDFRONT" else "Regional"
    count = 0
    client_region = "us-east-1" if scope == "CLOUDFRONT" else region
    try:
        waf = session.client("wafv2", region_name=client_region)
        for kind, op, key, rtype in (
            ("webacl", "list_web_acls", "WebACLs", f"WAF {suffix} Web ACL"),
            ("rulegroup", "list_rule_groups", "RuleGroups", f"WAF {suffix} Rule Group"),
            ("ipset", "list_ip_sets", "IPSets", f"WAF {suffix} IP Set"),
            ("regexpattern", "list_regex_pattern_sets", "RegexPatternSets", f"WAF {suffix} Regex Pattern Set"),
        ):
            local = 0
            for page in _pages(waf, op, {"Scope": scope}):
                for item in page.get(key, []):
                    builder.add(region="global" if scope == "CLOUDFRONT" else region, service="WAFv2", resource_type=rtype,
                                resource_id=item.get("ARN", item.get("Id", "")), resource_name=item.get("Name", ""),
                                resource_arn=item.get("ARN", ""), status="Available", configuration=item, raw_attributes=item)
                    local += 1
                    count += 1
            builder.covered(region="global" if scope == "CLOUDFRONT" else region, service="WAFv2", resource_type=rtype, count=local)
    except Exception as exc:
        status, code = _status_from_error(exc)
        builder.covered(region="global" if scope == "CLOUDFRONT" else region, service="WAFv2", resource_type=f"WAF {suffix} Resources", count=count, status=status, message=code)


def _collect_config_fallback(session, builder, region):
    """Broad fallback. AWS Config can surface supported resource types not yet covered by an explicit collector."""
    count = 0
    try:
        cfg = session.client("config", region_name=region)
        token = None
        while True:
            kwargs = {"Expression": "SELECT accountId, awsRegion, resourceType, resourceId, resourceName, arn"}
            if token:
                kwargs["NextToken"] = token
            page = cfg.select_resource_config(**kwargs)
            keys = []
            summaries = []
            for result in page.get("Results", []):
                item = json.loads(result)
                rid = item.get("resourceId", "")
                rtype = item.get("resourceType", "AWS::Unknown::Resource")
                summaries.append(item)
                if rid and rtype:
                    keys.append({"resourceType": rtype, "resourceId": rid})
            details = {}
            for start in range(0, len(keys), 100):
                response = cfg.batch_get_resource_config(resourceKeys=keys[start:start + 100])
                for item in response.get("baseConfigurationItems", []):
                    details[(item.get("resourceType"), item.get("resourceId"))] = item
            for summary in summaries:
                rtype = summary.get("resourceType", "AWS::Unknown::Resource")
                rid = summary.get("resourceId", "")
                detail = details.get((rtype, rid), summary)
                config = detail.get("configuration")
                if isinstance(config, str):
                    try:
                        config = json.loads(config)
                    except Exception:
                        config = {"configuration": config}
                raw = dict(detail)
                raw["configuration"] = config or {}
                service = rtype.split("::")[1] if "::" in rtype else "AWS Config"
                builder.add(region=summary.get("awsRegion") or region, service=service, resource_type=rtype,
                            resource_id=rid, resource_name=summary.get("resourceName", ""), resource_arn=summary.get("arn", ""),
                            status=detail.get("configurationItemStatus", ""), creation_time=detail.get("resourceCreationTime", ""),
                            tags=detail.get("tags", {}), configuration=config or {}, raw_attributes=raw, source="aws-config")
                count += 1
            token = page.get("NextToken")
            if not token:
                break
        builder.covered(region=region, service="AWS Config", resource_type="All Config-supported resources", count=count, source="aws-config")
    except Exception as exc:
        status, code = _status_from_error(exc)
        builder.covered(region=region, service="AWS Config", resource_type="All Config-supported resources", count=count,
                        status=status, message=code, source="aws-config")


def _collect_tagging_fallback(session, builder, region):
    count = 0
    try:
        tag = session.client("resourcegroupstaggingapi", region_name=region)
        for page in _pages(tag, "get_resources"):
            for item in page.get("ResourceTagMappingList", []):
                arn = item.get("ResourceARN", "")
                if not arn:
                    continue
                service = arn.split(":")[2].upper() if arn.startswith("arn:") else "AWS"
                rid = arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
                builder.add(region=region, service=service, resource_type="Tagged AWS Resource",
                            resource_id=rid, resource_arn=arn, tags=_tags(item), configuration=item,
                            raw_attributes=item, source="resource-groups-tagging-api")
                count += 1
        builder.covered(region=region, service="Tagging API", resource_type="Tagged resources fallback", count=count,
                        source="resource-groups-tagging-api")
    except Exception as exc:
        status, code = _status_from_error(exc)
        builder.covered(region=region, service="Tagging API", resource_type="Tagged resources fallback", count=count,
                        status=status, message=code, source="resource-groups-tagging-api")


def discover_inventory(session, target, regions, home_region="ap-south-1"):
    """
    Discover inventory without silently hiding empty or inaccessible services.

    Explicit collectors capture rich service data for common enterprise services. AWS Config and
    Resource Groups Tagging API are used as breadth fallbacks for resource types not explicitly
    modelled. Every collector emits a coverage row even when zero resources are returned.
    """
    builder = InventoryBuilder(target)
    scan_regions = list(dict.fromkeys(regions or [home_region]))

    for region in scan_regions:
        _collect_ec2_instances(session, builder, region)
        for spec in REGIONAL_SPECS:
            _collect_spec(session, builder, region, spec)
        _collect_ecs(session, builder, region)
        _collect_eks(session, builder, region)
        _collect_dynamodb(session, builder, region)
        _collect_opensearch(session, builder, region)
        _collect_kms(session, builder, region)
        _collect_secrets(session, builder, region)
        _collect_acm(session, builder, region)
        _collect_sqs(session, builder, region)
        _collect_backup_recovery_points(session, builder, region)
        _collect_glue_tables(session, builder, region)
        _collect_waf(session, builder, region, "REGIONAL")
        _collect_config_fallback(session, builder, region)
        _collect_tagging_fallback(session, builder, region)

    _collect_s3(session, builder, home_region)
    _collect_waf(session, builder, home_region, "CLOUDFRONT")
    for spec in GLOBAL_SPECS:
        _collect_spec(session, builder, home_region, spec)

    return builder.rows, builder.coverage
