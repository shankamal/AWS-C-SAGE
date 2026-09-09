import logging
import os
import re
from datetime import date, timedelta
from botocore.exceptions import BotoCoreError, ClientError
from compliance.models import LifecycleRule
from .helpers import cidr_is_broad, days_old, pagination, sensitive_ports, utcnow
from .types import FindingData, InventoryData

logger = logging.getLogger(__name__)


def _finding(module, rule, target, region, service, resource_id, resource_type, compliant, title, details="", severity="MEDIUM", evidence=None):
    return FindingData(module, rule, target.account_id, target.account_name, region or "global", service, resource_id, resource_type, compliant, title, details, severity, evidence or {})


def _safe_tags(tags):
    return {t.get("Key", ""): t.get("Value", "") for t in (tags or [])}


def scan_inventory(session, target, regions):
    """Build a broad inventory using AWS Config/Tagging API plus audited core resources."""
    out = []
    seen = set()

    def add(region, service, rtype, rid, arn="", metadata=None):
        key = (region or "global", rtype or service, rid or arn)
        if not (rid or arn) or key in seen:
            return
        seen.add(key)
        out.append(InventoryData(target.account_id, target.account_name, region or "global", service, rtype, rid or arn, arn or "", metadata or {}))

    for region in regions:
        # Prefer AWS Config because it can enumerate tagged and untagged supported resource types.
        try:
            cfg = session.client("config", region_name=region)
            token = None
            while True:
                kwargs = {"Expression": "SELECT resourceId, resourceType, arn, resourceName"}
                if token:
                    kwargs["NextToken"] = token
                page = cfg.select_resource_config(**kwargs)
                for row in page.get("Results", []):
                    import json
                    item = json.loads(row)
                    rtype = item.get("resourceType", "AWS::Unknown::Resource")
                    service = rtype.split("::")[1] if "::" in rtype else "AWS"
                    add(region, service, rtype, item.get("resourceId") or item.get("resourceName") or item.get("arn", ""), item.get("arn", ""))
                token = page.get("NextToken")
                if not token:
                    break
        except Exception as exc:
            logger.info("AWS Config inventory unavailable for %s/%s: %s", target.account_id, region, exc)

        # Resource Groups Tagging API expands coverage where Config is not enabled.
        try:
            tag = session.client("resourcegroupstaggingapi", region_name=region)
            for item in pagination(tag, "get_resources", "ResourceTagMappingList"):
                arn = item.get("ResourceARN", "")
                service = arn.split(":")[2].upper() if arn.startswith("arn:") else "AWS"
                add(region, service, "Tagged AWS Resource", arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1], arn, {"tags": item.get("Tags", [])})
        except Exception as exc:
            logger.info("Tagging API inventory unavailable for %s/%s: %s", target.account_id, region, exc)

        # Explicitly enumerate core services used by compliance controls so important untagged resources are included.
        explicit = [
            ("ec2", "describe_instances", "Reservations", "EC2 Instance"),
            ("ec2", "describe_volumes", "Volumes", "EBS Volume"),
            ("rds", "describe_db_instances", "DBInstances", "RDS DB Instance"),
            ("lambda", "list_functions", "Functions", "Lambda Function"),
            ("eks", "list_clusters", "clusters", "EKS Cluster"),
            ("efs", "describe_file_systems", "FileSystems", "EFS File System"),
        ]
        for service, op, key, rtype in explicit:
            try:
                client = session.client(service, region_name=region)
                for page in client.get_paginator(op).paginate() if client.can_paginate(op) else [getattr(client, op)()]:
                    items = page.get(key, [])
                    if service == "ec2" and op == "describe_instances":
                        items = [i for r in items for i in r.get("Instances", [])]
                    for item in items:
                        if isinstance(item, str):
                            rid, arn = item, ""
                        else:
                            rid = item.get("InstanceId") or item.get("VolumeId") or item.get("DBInstanceIdentifier") or item.get("FunctionName") or item.get("FileSystemId") or ""
                            arn = item.get("DBInstanceArn") or item.get("FunctionArn") or ""
                        add(region, service.upper(), rtype, rid, arn)
            except (ClientError, BotoCoreError) as exc:
                logger.warning("Inventory %s failed for %s/%s: %s", service, target.account_id, region, exc)

    try:
        s3 = session.client("s3")
        for bucket in s3.list_buckets().get("Buckets", []):
            add("global", "S3", "S3 Bucket", bucket["Name"], f"arn:aws:s3:::{bucket['Name']}")
    except (ClientError, BotoCoreError) as exc:
        logger.warning("Inventory S3 failed for %s: %s", target.account_id, exc)
    return out


def scan_eol(session, target, regions):
    findings = []
    warn_days = int(os.getenv("CSAGE_EOL_WARNING_DAYS", "30"))
    cutoff = date.today() + timedelta(days=warn_days)
    rules = {(r.service.lower(), r.engine.lower(), r.version): r for r in LifecycleRule.objects.filter(active=True)}
    for region in regions:
        checks = []
        try:
            for db in pagination(session.client("rds", region_name=region), "describe_db_instances", "DBInstances"):
                checks.append(("rds", db.get("Engine", ""), db.get("EngineVersion", ""), db.get("DBInstanceIdentifier", ""), "RDS DB Instance"))
        except Exception as exc:
            logger.warning("RDS EOL scan failed: %s", exc)
        try:
            for dom in pagination(session.client("opensearch", region_name=region), "list_domain_names", "DomainNames"):
                name = dom.get("DomainName", "")
                info = session.client("opensearch", region_name=region).describe_domain(DomainName=name).get("DomainStatus", {})
                version = info.get("EngineVersion", "")
                checks.append(("opensearch", "opensearch", version, name, "OpenSearch Domain"))
        except Exception as exc:
            logger.warning("OpenSearch EOL scan failed: %s", exc)
        try:
            for c in pagination(session.client("elasticache", region_name=region), "describe_cache_clusters", "CacheClusters"):
                checks.append(("elasticache", c.get("Engine", ""), c.get("EngineVersion", ""), c.get("CacheClusterId", ""), "ElastiCache Cluster"))
        except Exception as exc:
            logger.warning("ElastiCache EOL scan failed: %s", exc)
        try:
            eks = session.client("eks", region_name=region)
            for name in pagination(eks, "list_clusters", "clusters"):
                info = eks.describe_cluster(name=name).get("cluster", {})
                checks.append(("eks", "kubernetes", info.get("version", ""), name, "EKS Cluster"))
        except Exception as exc:
            logger.warning("EKS EOL scan failed: %s", exc)

        for service, engine, version, rid, rtype in checks:
            rule = rules.get((service.lower(), engine.lower(), version))
            compliant = True if not rule else rule.eol_date > cutoff
            details = "No active lifecycle rule matched; maintain LifecycleRule catalog." if not rule else f"EOL/EOS date: {rule.eol_date}; warning window: {warn_days} days."
            findings.append(_finding("PaaS EOL / EOS", "CSAGE-EOL-001", target, region, service, rid, rtype, compliant, "PaaS version must remain within vendor support", details, "HIGH" if not compliant else "INFO", {"engine": engine, "version": version, "eol_date": str(rule.eol_date) if rule else None}))
    return findings


def scan_certificates(session, target, regions):
    findings = []
    for region in regions:
        try:
            acm = session.client("acm", region_name=region)
            for cert in pagination(acm, "list_certificates", "CertificateSummaryList"):
                arn = cert.get("CertificateArn", "")
                d = acm.describe_certificate(CertificateArn=arn).get("Certificate", {})
                not_after = d.get("NotAfter")
                remaining = (not_after - utcnow()).days if not_after else 99999
                compliant = d.get("Status") != "EXPIRED" and remaining > 30
                findings.append(_finding("Certificates", "CSAGE-CERT-001", target, region, "ACM", arn, "ACM Certificate", compliant, "Certificate must be valid for more than 30 days", f"Status={d.get('Status')}; days_remaining={remaining}", "HIGH", {"domain": d.get("DomainName"), "not_after": str(not_after)}))
        except Exception as exc:
            logger.warning("ACM scan failed: %s", exc)
    try:
        iam = session.client("iam")
        for cert in pagination(iam, "list_server_certificates", "ServerCertificateMetadataList"):
            expiry = cert.get("Expiration")
            remaining = (expiry - utcnow()).days if expiry else 99999
            compliant = remaining > 30
            findings.append(_finding("Certificates", "CSAGE-CERT-002", target, "global", "IAM", cert.get("ServerCertificateName", ""), "IAM Server Certificate", compliant, "IAM server certificate must be valid for more than 30 days", f"days_remaining={remaining}", "HIGH", {"expiration": str(expiry)}))
    except Exception as exc:
        logger.warning("IAM certificate scan failed: %s", exc)
    return findings


def scan_iam_keys(session, target, regions):
    findings = []
    max_age = int(os.getenv("CSAGE_ACCESS_KEY_MAX_AGE_DAYS", "90"))
    try:
        iam = session.client("iam")
        for user in pagination(iam, "list_users", "Users"):
            username = user.get("UserName", "")
            for key in iam.list_access_keys(UserName=username).get("AccessKeyMetadata", []):
                if key.get("Status") != "Active":
                    continue
                age = days_old(key.get("CreateDate"))
                compliant = age <= max_age
                findings.append(_finding("IAM Access Keys", "CSAGE-IAM-KEY-001", target, "global", "IAM", key.get("AccessKeyId", ""), "IAM Access Key", compliant, f"Active IAM access key age must not exceed {max_age} days", f"User={username}; age_days={age}", "HIGH", {"user": username, "age_days": age}))
    except Exception as exc:
        logger.warning("IAM key scan failed: %s", exc)
    return findings


def _is_customer_managed_kms(key_id):
    return bool(key_id) and "/aws/" not in key_id and not str(key_id).startswith("alias/aws/")


def scan_storage_encryption(session, target, regions):
    findings = []
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            for v in pagination(ec2, "describe_volumes", "Volumes"):
                kms = v.get("KmsKeyId", "")
                compliant = bool(v.get("Encrypted")) and _is_customer_managed_kms(kms)
                findings.append(_finding("Storage Encryption", "CSAGE-STG-ENC-001", target, region, "EBS", v.get("VolumeId", ""), "EBS Volume", compliant, "EBS volume must use customer-managed KMS encryption", f"Encrypted={v.get('Encrypted')}; KmsKeyId={kms or 'None'}", "HIGH", {"kms_key_id": kms}))
        except Exception as exc:
            logger.warning("EBS encryption scan failed: %s", exc)
        try:
            efs = session.client("efs", region_name=region)
            for fs in pagination(efs, "describe_file_systems", "FileSystems"):
                kms = fs.get("KmsKeyId", "")
                compliant = bool(fs.get("Encrypted")) and _is_customer_managed_kms(kms)
                findings.append(_finding("Storage Encryption", "CSAGE-STG-ENC-002", target, region, "EFS", fs.get("FileSystemId", ""), "EFS File System", compliant, "EFS must use customer-managed KMS encryption", f"Encrypted={fs.get('Encrypted')}; KmsKeyId={kms or 'None'}", "HIGH", {"kms_key_id": kms}))
        except Exception as exc:
            logger.warning("EFS encryption scan failed: %s", exc)
    return findings


def scan_backup(session, target, regions):
    findings = []
    max_age_hours = int(os.getenv("CSAGE_BACKUP_MAX_AGE_HOURS", "24"))
    min_retention_days = int(os.getenv("CSAGE_BACKUP_MIN_RETENTION_DAYS", "7"))
    cutoff = utcnow() - timedelta(hours=max_age_hours)

    for region in regions:
        latest_backup = {}
        try:
            backup = session.client("backup", region_name=region)
            for vault in pagination(backup, "list_backup_vaults", "BackupVaultList"):
                name = vault.get("BackupVaultName")
                for rp in pagination(backup, "list_recovery_points_by_backup_vault", "RecoveryPoints", BackupVaultName=name):
                    arn = rp.get("ResourceArn")
                    created = rp.get("CreationDate")
                    if arn and created and (arn not in latest_backup or created > latest_backup[arn]):
                        latest_backup[arn] = created
        except Exception as exc:
            logger.warning("AWS Backup inventory failed: %s", exc)

        def recent_backup_for(identifier):
            matches = [dt for arn, dt in latest_backup.items() if identifier and identifier in arn]
            return max(matches) if matches else None

        try:
            ec2 = session.client("ec2", region_name=region)
            latest_snapshot = {}
            for snap in pagination(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"]):
                vid, started = snap.get("VolumeId"), snap.get("StartTime")
                if vid and started and (vid not in latest_snapshot or started > latest_snapshot[vid]):
                    latest_snapshot[vid] = started
            for v in pagination(ec2, "describe_volumes", "Volumes"):
                vid = v.get("VolumeId", "")
                snap_dt = latest_snapshot.get(vid)
                backup_dt = recent_backup_for(vid)
                newest = max([x for x in [snap_dt, backup_dt] if x], default=None)
                compliant = bool(newest and newest >= cutoff)
                findings.append(_finding("Storage Backup", "CSAGE-BACKUP-001", target, region, "EBS", vid, "EBS Volume", compliant, "EBS must have a recent snapshot or AWS Backup recovery point", f"latest_backup={newest}; required_within_hours={max_age_hours}. S3 is exempt from this rule.", "HIGH", {"latest_backup": str(newest) if newest else None, "max_age_hours": max_age_hours}))
        except Exception as exc:
            logger.warning("EBS backup scan failed: %s", exc)

        try:
            rds = session.client("rds", region_name=region)
            for db in pagination(rds, "describe_db_instances", "DBInstances"):
                retention = int(db.get("BackupRetentionPeriod", 0) or 0)
                rid = db.get("DBInstanceIdentifier", "")
                backup_dt = recent_backup_for(rid)
                compliant = retention >= min_retention_days or bool(backup_dt and backup_dt >= cutoff)
                findings.append(_finding("Storage Backup", "CSAGE-BACKUP-002", target, region, "RDS", rid, "RDS DB Instance", compliant, "RDS must meet automated backup retention or have a recent AWS Backup recovery point", f"BackupRetentionPeriod={retention}; required_retention_days={min_retention_days}; latest_aws_backup={backup_dt}", "HIGH", {"retention_days": retention, "latest_backup": str(backup_dt) if backup_dt else None}))
        except Exception as exc:
            logger.warning("RDS backup scan failed: %s", exc)

        try:
            efs = session.client("efs", region_name=region)
            for fs in pagination(efs, "describe_file_systems", "FileSystems"):
                rid = fs.get("FileSystemId", "")
                backup_dt = recent_backup_for(rid)
                compliant = bool(backup_dt and backup_dt >= cutoff)
                findings.append(_finding("Storage Backup", "CSAGE-BACKUP-003", target, region, "EFS", rid, "EFS File System", compliant, "EFS must have a recent AWS Backup recovery point", f"latest_aws_backup={backup_dt}; required_within_hours={max_age_hours}", "HIGH"))
        except Exception as exc:
            logger.warning("EFS backup scan failed: %s", exc)

        try:
            ddb = session.client("dynamodb", region_name=region)
            for table in pagination(ddb, "list_tables", "TableNames"):
                info = ddb.describe_table(TableName=table).get("Table", {})
                arn = info.get("TableArn", "")
                pitr = ddb.describe_continuous_backups(TableName=table).get("ContinuousBackupsDescription", {}).get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus")
                backup_dt = latest_backup.get(arn) or recent_backup_for(table)
                compliant = pitr == "ENABLED" or bool(backup_dt and backup_dt >= cutoff)
                findings.append(_finding("Storage Backup", "CSAGE-BACKUP-004", target, region, "DynamoDB", table, "DynamoDB Table", compliant, "DynamoDB must have PITR or a recent AWS Backup recovery point", f"PITR={pitr}; latest_aws_backup={backup_dt}", "HIGH"))
        except Exception as exc:
            logger.warning("DynamoDB backup scan failed: %s", exc)
    return findings


def scan_s3(session, target, regions):
    findings = []
    try:
        s3 = session.client("s3")
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            public = False
            evidence = {}
            try:
                bpa = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
                public = not all(bpa.get(k, False) for k in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"])
                evidence["public_access_block"] = bpa
            except ClientError:
                public = True
            try:
                status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
                public = public or bool(status.get("IsPublic"))
                evidence["policy_public"] = status.get("IsPublic", False)
            except ClientError:
                pass
            findings.append(_finding("Object Storage", "CSAGE-S3-001", target, "global", "S3", name, "S3 Bucket", not public, "S3 bucket must not be publicly accessible", "", "CRITICAL", evidence))
            try:
                rules = s3.get_bucket_encryption(Bucket=name).get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                by_default = (rules[0].get("ApplyServerSideEncryptionByDefault", {}) if rules else {})
                algo = by_default.get("SSEAlgorithm")
                key = by_default.get("KMSMasterKeyID", "")
                compliant = algo == "aws:kms" and _is_customer_managed_kms(key)
            except ClientError:
                algo, key, compliant = None, "", False
            findings.append(_finding("Object Storage", "CSAGE-S3-002", target, "global", "S3", name, "S3 Bucket", compliant, "S3 bucket must use customer-managed KMS encryption", f"algorithm={algo}; kms_key={key or 'None'}", "HIGH", {"algorithm": algo, "kms_key_id": key}))
    except Exception as exc:
        logger.warning("S3 scan failed: %s", exc)
    return findings


def scan_lambda(session, target, regions):
    findings = []
    deprecated = {x.strip() for x in os.getenv("CSAGE_DEPRECATED_LAMBDA_RUNTIMES", "python3.7,python3.8,nodejs14.x,nodejs16.x").split(",") if x.strip()}
    for region in regions:
        try:
            client = session.client("lambda", region_name=region)
            for fn in pagination(client, "list_functions", "Functions"):
                name = fn.get("FunctionName", "")
                vpc = fn.get("VpcConfig") or {}
                in_vpc = bool(vpc.get("SubnetIds")) and bool(vpc.get("VpcId"))
                findings.append(_finding("Lambda", "CSAGE-LAMBDA-001", target, region, "Lambda", name, "Lambda Function", in_vpc, "Lambda function must be attached to a VPC", f"VpcId={vpc.get('VpcId') or 'None'}", "HIGH"))
                runtime = fn.get("Runtime")
                compliant = not runtime or runtime not in deprecated
                findings.append(_finding("Lambda", "CSAGE-LAMBDA-002", target, region, "Lambda", name, "Lambda Function", compliant, "Lambda runtime must not be deprecated/EOS", f"Runtime={runtime or 'Custom/Container'}", "HIGH", {"runtime": runtime}))
        except Exception as exc:
            logger.warning("Lambda scan failed: %s", exc)
    return findings


def scan_security_groups(session, target, regions):
    findings = []
    ritm = re.compile(r"\bRITM\d{6,12}\b", re.I)
    ports = sensitive_ports()
    for region in regions:
        redirect_sgs = set()
        try:
            elbv2 = session.client("elbv2", region_name=region)
            for lb in pagination(elbv2, "describe_load_balancers", "LoadBalancers"):
                arn = lb.get("LoadBalancerArn")
                if not arn:
                    continue
                listeners = elbv2.describe_listeners(LoadBalancerArn=arn).get("Listeners", [])
                has_redirect = any(
                    l.get("Port") == 80 and any(
                        a.get("Type") == "redirect" and (a.get("RedirectConfig") or {}).get("Protocol", "").upper() == "HTTPS"
                        for a in l.get("DefaultActions", [])
                    ) for l in listeners
                )
                if has_redirect:
                    redirect_sgs.update(lb.get("SecurityGroups", []))
        except Exception as exc:
            logger.info("ALB HTTPS redirect discovery unavailable for %s/%s: %s", target.account_id, region, exc)
        try:
            ec2 = session.client("ec2", region_name=region)
            for sg in pagination(ec2, "describe_security_groups", "SecurityGroups"):
                gid = sg.get("GroupId", "")
                desc = (sg.get("Description") or "").strip()
                findings.append(_finding("Security Groups", "CSAGE-SG-001", target, region, "EC2/VPC", gid, "Security Group", bool(desc), "Security Group must have a description", desc or "Missing description", "MEDIUM"))
                findings.append(_finding("Security Groups", "CSAGE-SG-002", target, region, "EC2/VPC", gid, "Security Group", bool(ritm.search(desc)), "Security Group description must contain a valid RITM ticket", desc or "Missing description", "MEDIUM"))
                broad_sensitive = []
                http_open = False
                for perm in sg.get("IpPermissions", []):
                    fp, tp = perm.get("FromPort"), perm.get("ToPort")
                    cidrs = [x.get("CidrIp") for x in perm.get("IpRanges", []) if x.get("CidrIp")]
                    for cidr in cidrs:
                        if cidr == "0.0.0.0/0" and fp is not None and tp is not None and fp <= 80 <= tp:
                            http_open = True
                        if cidr_is_broad(cidr) and fp is not None and tp is not None and any(fp <= p <= tp for p in ports):
                            broad_sensitive.append({"cidr": cidr, "from": fp, "to": tp})
                findings.append(_finding("Security Groups", "CSAGE-SG-003", target, region, "EC2/VPC", gid, "Security Group", not broad_sensitive, "Sensitive ports must not be exposed to broad CIDR ranges", f"Broad sensitive rules={broad_sensitive}", "CRITICAL", {"violations": broad_sensitive}))
                http_compliant = not http_open or gid in redirect_sgs
                findings.append(_finding("Security Groups", "CSAGE-SG-004", target, region, "EC2/VPC", gid, "Security Group", http_compliant, "Internet-exposed HTTP/80 must redirect to HTTPS", f"internet_http_open={http_open}; verified_alb_https_redirect={gid in redirect_sgs}", "HIGH", {"internet_http_open": http_open, "verified_alb_https_redirect": gid in redirect_sgs}))
        except Exception as exc:
            logger.warning("Security group scan failed: %s", exc)
    return findings


def scan_kms(session, target, regions):
    findings = []
    max_age = int(os.getenv("CSAGE_KMS_MAX_AGE_DAYS", "365"))
    for region in regions:
        try:
            kms = session.client("kms", region_name=region)
            for entry in pagination(kms, "list_keys", "Keys"):
                key_id = entry.get("KeyId", "")
                meta = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                if meta.get("KeyManager") != "CUSTOMER":
                    continue
                age = days_old(meta.get("CreationDate"))
                try:
                    rotation = kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled", False)
                except ClientError:
                    rotation = False
                compliant = age <= max_age and rotation
                findings.append(_finding("KMS", "CSAGE-KMS-001", target, region, "KMS", key_id, "Customer Managed KMS Key", compliant, "Customer-managed KMS key must be <= 365 days old and rotation enabled", f"age_days={age}; rotation_enabled={rotation}", "HIGH", {"age_days": age, "rotation_enabled": rotation, "arn": meta.get("Arn")}))
        except Exception as exc:
            logger.warning("KMS scan failed: %s", exc)
    return findings


def scan_notifications(session, target, regions):
    findings = []
    allowed = os.getenv("CSAGE_ALLOWED_EMAIL_DOMAIN", "icicibank.com").lower()
    for region in regions:
        try:
            sns = session.client("sns", region_name=region)
            for sub in pagination(sns, "list_subscriptions", "Subscriptions"):
                if sub.get("Protocol") not in {"email", "email-json"}:
                    continue
                endpoint = (sub.get("Endpoint") or "").lower()
                compliant = endpoint.endswith("@" + allowed)
                findings.append(_finding("Notification Domains", "CSAGE-NOTIFY-001", target, region, "SNS", sub.get("SubscriptionArn", endpoint), "SNS Email Subscription", compliant, f"SNS email endpoint must use @{allowed}", endpoint, "HIGH", {"endpoint": endpoint}))
        except Exception as exc:
            logger.warning("SNS scan failed: %s", exc)
    try:
        budgets = session.client("budgets", region_name="us-east-1")
        for budget in pagination(budgets, "describe_budgets", "Budgets", AccountId=target.account_id):
            name = budget.get("BudgetName", "")
            for n in budgets.describe_notifications_for_budget(AccountId=target.account_id, BudgetName=name).get("Notifications", []):
                subs = budgets.describe_subscribers_for_notification(AccountId=target.account_id, BudgetName=name, Notification=n).get("Subscribers", [])
                for s in subs:
                    if s.get("SubscriptionType") != "EMAIL":
                        continue
                    endpoint = (s.get("Address") or "").lower()
                    compliant = endpoint.endswith("@" + allowed)
                    findings.append(_finding("Notification Domains", "CSAGE-NOTIFY-002", target, "global", "Budgets", f"{name}:{endpoint}", "Budget Email Subscriber", compliant, f"Budget alert email must use @{allowed}", endpoint, "HIGH", {"endpoint": endpoint, "budget": name}))
    except Exception as exc:
        logger.warning("Budgets scan failed: %s", exc)
    return findings

SCANNERS = [scan_eol, scan_certificates, scan_iam_keys, scan_storage_encryption, scan_backup, scan_s3, scan_lambda, scan_security_groups, scan_kms, scan_notifications]
