import logging
import os
from datetime import datetime, timedelta, timezone

from botocore.exceptions import BotoCoreError, ClientError

from .helpers import pagination
from .types import FindingData

logger = logging.getLogger(__name__)


def _finding(target, region, service, resource_id, resource_type, compliant, title, details, severity="INFO", evidence=None, rule_id="CSAGE-EOL-001"):
    return FindingData(
        "PaaS EOL / EOS",
        rule_id,
        target.account_id,
        target.account_name,
        region or "global",
        service,
        resource_id,
        resource_type,
        compliant,
        title,
        details,
        severity,
        evidence or {},
    )


def _within_window(value, warning_days):
    if not value:
        return False
    now = datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value <= now + timedelta(days=warning_days)


def _rds_major_version(rds, engine, engine_version):
    try:
        response = rds.describe_db_engine_versions(Engine=engine, EngineVersion=engine_version, IncludeAll=True)
        versions = response.get("DBEngineVersions", [])
        if versions:
            return versions[0].get("MajorEngineVersion") or engine_version
    except Exception:
        pass
    parts = str(engine_version).split(".")
    if engine in {"postgres", "aurora-postgresql"}:
        return parts[0]
    return ".".join(parts[:2]) if len(parts) >= 2 else str(engine_version)


def scan_rds_lifecycle(session, target, regions, warning_days):
    findings = []
    for region in regions:
        try:
            rds = session.client("rds", region_name=region)
            lifecycle_cache = {}
            for db in pagination(rds, "describe_db_instances", "DBInstances"):
                engine = db.get("Engine", "")
                engine_version = db.get("EngineVersion", "")
                resource_id = db.get("DBInstanceIdentifier", "")
                major = _rds_major_version(rds, engine, engine_version)
                cache_key = (engine, major)
                if cache_key not in lifecycle_cache:
                    try:
                        response = rds.describe_db_major_engine_versions(Engine=engine, MajorEngineVersion=major)
                        rows = response.get("DBMajorEngineVersions", [])
                        lifecycle_cache[cache_key] = rows[0].get("SupportedEngineLifecycles", []) if rows else []
                    except Exception as exc:
                        logger.info("RDS lifecycle metadata unavailable for %s %s in %s: %s", engine, major, region, exc)
                        lifecycle_cache[cache_key] = []

                lifecycles = lifecycle_cache[cache_key]
                if not lifecycles:
                    findings.append(_finding(
                        target, region, "RDS", resource_id, "RDS DB Instance", True,
                        "RDS lifecycle metadata is sourced directly from AWS",
                        f"Engine={engine}; version={engine_version}; AWS did not return lifecycle dates for this engine/version. Commercial engines may rely on AWS Health notices.",
                        "INFO",
                        {"source": "RDS DescribeDBMajorEngineVersions", "engine": engine, "engine_version": engine_version, "major_engine_version": major},
                    ))
                    continue

                standard = next((x for x in lifecycles if x.get("LifecycleSupportName") == "open-source-rds-standard-support"), None)
                extended = next((x for x in lifecycles if x.get("LifecycleSupportName") == "open-source-rds-extended-support"), None)
                standard_end = standard.get("LifecycleSupportEndDate") if standard else None
                extended_end = extended.get("LifecycleSupportEndDate") if extended else None
                deadline = standard_end or extended_end
                non_compliant = _within_window(standard_end, warning_days) if standard_end else _within_window(extended_end, warning_days)
                status_label = "standard support" if standard_end else "extended support"
                details = (
                    f"Engine={engine}; version={engine_version}; major={major}; "
                    f"standard_support_end={standard_end}; extended_support_end={extended_end}; "
                    f"warning_window={warning_days} days. Source: RDS service API."
                )
                findings.append(_finding(
                    target, region, "RDS", resource_id, "RDS DB Instance", not non_compliant,
                    f"RDS engine version must remain outside the {status_label} EOL/EOS warning window",
                    details,
                    "HIGH" if non_compliant else "INFO",
                    {"source": "RDS DescribeDBMajorEngineVersions", "engine": engine, "engine_version": engine_version, "major_engine_version": major,
                     "standard_support_end": str(standard_end) if standard_end else None, "extended_support_end": str(extended_end) if extended_end else None,
                     "evaluated_deadline": str(deadline) if deadline else None},
                ))
        except Exception as exc:
            logger.warning("RDS lifecycle scan failed for %s/%s: %s", target.account_id, region, exc)
    return findings


def scan_eks_lifecycle(session, target, regions, warning_days):
    findings = []
    for region in regions:
        try:
            eks = session.client("eks", region_name=region)
            cache = {}
            for name in pagination(eks, "list_clusters", "clusters"):
                cluster = eks.describe_cluster(name=name).get("cluster", {})
                version = cluster.get("version", "")
                if version not in cache:
                    try:
                        response = eks.describe_cluster_versions(clusterVersions=[version], includeAll=True)
                        rows = response.get("clusterVersions", [])
                        cache[version] = rows[0] if rows else {}
                    except Exception as exc:
                        logger.info("EKS lifecycle metadata unavailable for %s in %s: %s", version, region, exc)
                        cache[version] = {}
                meta = cache[version]
                standard_end = meta.get("endOfStandardSupportDate")
                extended_end = meta.get("endOfExtendedSupportDate")
                version_status = meta.get("versionStatus") or meta.get("status") or "UNKNOWN"
                non_compliant = _within_window(standard_end, warning_days) if standard_end else version_status in {"EXTENDED_SUPPORT", "UNSUPPORTED", "extended-support", "unsupported"}
                details = (
                    f"Kubernetes={version}; version_status={version_status}; standard_support_end={standard_end}; "
                    f"extended_support_end={extended_end}; warning_window={warning_days} days. Source: EKS service API."
                )
                findings.append(_finding(
                    target, region, "EKS", name, "EKS Cluster", not non_compliant,
                    "EKS Kubernetes version must remain in standard support outside the EOL warning window",
                    details,
                    "HIGH" if non_compliant else "INFO",
                    {"source": "EKS DescribeClusterVersions", "cluster_version": version, "version_status": version_status,
                     "standard_support_end": str(standard_end) if standard_end else None,
                     "extended_support_end": str(extended_end) if extended_end else None},
                ))
        except Exception as exc:
            logger.warning("EKS lifecycle scan failed for %s/%s: %s", target.account_id, region, exc)
    return findings


def scan_health_lifecycle(session, target, warning_days):
    """Read AWS Health scheduled-change lifecycle notices for services without a native lifecycle-date API."""
    findings = []
    try:
        health = session.client("health", region_name="us-east-1")
        events = []
        token = None
        while True:
            kwargs = {
                "filter": {
                    "eventTypeCategories": ["scheduledChange"],
                    "eventStatusCodes": ["open", "upcoming"],
                }
            }
            if token:
                kwargs["nextToken"] = token
            page = health.describe_events(**kwargs)
            events.extend(page.get("events", []))
            token = page.get("nextToken")
            if not token:
                break

        for event in events:
            arn = event.get("arn", "")
            if not arn:
                continue
            event_type = event.get("eventTypeCode", "")
            service = event.get("service", "AWS Health")
            deadline = event.get("endTime") or event.get("startTime")
            # Keep the lifecycle scanner focused on deprecation, upgrade, retirement and support-ending notices.
            marker = event_type.lower()
            if not any(term in marker for term in ("deprecat", "retire", "end", "support", "upgrade", "version", "runtime")):
                continue
            affected = []
            try:
                entity_token = None
                while True:
                    entity_kwargs = {"filter": {"eventArns": [arn]}}
                    if entity_token:
                        entity_kwargs["nextToken"] = entity_token
                    entity_page = health.describe_affected_entities(**entity_kwargs)
                    affected.extend(entity_page.get("entities", []))
                    entity_token = entity_page.get("nextToken")
                    if not entity_token:
                        break
            except Exception as exc:
                logger.info("AWS Health affected-entity lookup failed for %s: %s", arn, exc)

            non_compliant = _within_window(deadline, warning_days)
            entities = affected or [{"entityValue": event_type}]
            for entity in entities:
                resource_id = entity.get("entityValue") or entity.get("entityArn") or event_type
                findings.append(_finding(
                    target, event.get("region") or "global", service, resource_id, "AWS Health Affected Entity",
                    not non_compliant,
                    "AWS Health scheduled lifecycle event must remain outside the EOL/EOS warning window",
                    f"event_type={event_type}; start={event.get('startTime')}; end={event.get('endTime')}; warning_window={warning_days} days. Source: AWS Health Dashboard/API.",
                    "HIGH" if non_compliant else "INFO",
                    {"source": "AWS Health", "event_arn": arn, "event_type_code": event_type,
                     "start_time": str(event.get("startTime")) if event.get("startTime") else None,
                     "end_time": str(event.get("endTime")) if event.get("endTime") else None,
                     "entity_arn": entity.get("entityArn"), "entity_value": entity.get("entityValue")},
                    rule_id="CSAGE-EOL-HEALTH-001",
                ))
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "SubscriptionRequiredException":
            logger.warning("AWS Health API unavailable for %s because the account support plan does not include Health API access", target.account_id)
            findings.append(_finding(
                target, "global", "AWS Health", "health-api", "Lifecycle Data Source", True,
                "AWS Health lifecycle source is unavailable for this account",
                "AWS Health Dashboard is available in the console, but API access requires an eligible AWS Support plan. EKS and supported RDS lifecycle dates continue to be evaluated directly from their service APIs.",
                "INFO",
                {"source": "AWS Health", "status": "SubscriptionRequiredException"},
                rule_id="CSAGE-EOL-SOURCE-001",
            ))
        else:
            logger.warning("AWS Health lifecycle scan failed for %s: %s", target.account_id, exc)
    except (BotoCoreError, Exception) as exc:
        logger.warning("AWS Health lifecycle scan failed for %s: %s", target.account_id, exc)
    return findings


def scan_dynamic_lifecycle(session, target, regions):
    warning_days = int(os.getenv("CSAGE_EOL_WARNING_DAYS", "30"))
    findings = []
    findings.extend(scan_rds_lifecycle(session, target, regions, warning_days))
    findings.extend(scan_eks_lifecycle(session, target, regions, warning_days))
    findings.extend(scan_health_lifecycle(session, target, warning_days))
    return findings


def scan_lambda_dynamic(session, target, regions):
    """Lambda VPC compliance plus runtime lifecycle notices sourced from AWS Health, never a maintained runtime list."""
    findings = []
    for region in regions:
        try:
            client = session.client("lambda", region_name=region)
            for function in pagination(client, "list_functions", "Functions"):
                name = function.get("FunctionName", "")
                arn = function.get("FunctionArn", name)
                runtime = function.get("Runtime", "")
                vpc = function.get("VpcConfig", {}) or {}
                attached = bool(vpc.get("VpcId") and vpc.get("SubnetIds"))
                findings.append(FindingData(
                    "AWS Lambda Functions", "CSAGE-LAMBDA-001", target.account_id, target.account_name, region,
                    "Lambda", arn, "Lambda Function", attached,
                    "Lambda function must be attached to a VPC",
                    f"VpcId={vpc.get('VpcId') or 'None'}", "HIGH" if not attached else "INFO",
                    {"vpc_id": vpc.get("VpcId"), "subnets": vpc.get("SubnetIds", []), "runtime": runtime},
                ))
        except Exception as exc:
            logger.warning("Lambda scan failed for %s/%s: %s", target.account_id, region, exc)
    # Runtime deprecation/EOS is intentionally not inferred from a hard-coded list. Relevant notices are emitted by scan_dynamic_lifecycle via AWS Health.
    return findings
