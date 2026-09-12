import hashlib
import logging
from collections import Counter

from botocore.exceptions import BotoCoreError, ClientError

from .types import InventoryData

logger = logging.getLogger(__name__)


def _key(account_id, region, service, resource_type, resource_id, arn=""):
    basis = "|".join([str(account_id), str(region), str(service), str(resource_type), str(arn or resource_id)])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _status(exc):
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        if any(term in code.lower() for term in ("accessdenied", "unauthorized", "forbidden")):
            return "ACCESS_DENIED", code
        if any(term in code.lower() for term in ("notfound", "defaultview", "validation")):
            return "UNAVAILABLE", code
        return "ERROR", code or exc.__class__.__name__
    return "ERROR", exc.__class__.__name__


def _pages(client, operation, kwargs=None):
    kwargs = kwargs or {}
    if client.can_paginate(operation):
        yield from client.get_paginator(operation).paginate(**kwargs)
    else:
        yield getattr(client, operation)(**kwargs)


def discover_resource_explorer(session, target, regions):
    """
    Broad inventory fallback using AWS Resource Explorer 2.

    Resource Explorer is used to discover supported services/resource types that are not yet
    covered by an explicit service collector. It also emits per-service coverage rows, including
    supported services with zero resources. Results depend on Resource Explorer indexes/views
    configured in the target account and Region; lack of access is recorded as coverage status.
    """
    rows = []
    coverage = []
    seen = set()

    for region in regions:
        counts = Counter()
        supported_services = set()
        try:
            client = session.client("resource-explorer-2", region_name=region)
            try:
                for page in _pages(client, "list_supported_resource_types"):
                    for item in page.get("ResourceTypes", []):
                        service = item.get("Service")
                        if service:
                            supported_services.add(service)
            except Exception as exc:
                logger.info("Resource Explorer supported-type listing unavailable in %s: %s", region, exc)

            for page in _pages(client, "list_resources"):
                for item in page.get("Resources", []):
                    arn = item.get("Arn", "")
                    rtype = item.get("ResourceType", "Resource Explorer Resource")
                    service = item.get("Service") or (arn.split(":")[2] if arn.startswith("arn:") else "AWS")
                    resource_region = item.get("Region") or region
                    rid = arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1] if arn else rtype
                    key = _key(target.account_id, resource_region, service, rtype, rid, arn)
                    if key in seen:
                        continue
                    seen.add(key)
                    counts[service] += 1
                    supported_services.add(service)
                    rows.append(InventoryData(
                        account_id=target.account_id,
                        account_name=target.account_name,
                        region=resource_region,
                        service=service,
                        resource_type=rtype,
                        resource_name=rid,
                        resource_id=rid,
                        resource_arn=arn,
                        status="",
                        creation_time=item.get("LastReportedAt", ""),
                        tags={},
                        configuration=item,
                        networking={},
                        security={},
                        relationships={},
                        raw_attributes=item,
                        discovery_source="resource-explorer-2",
                        resource_key=key,
                    ))

            for service in sorted(supported_services):
                coverage.append({
                    "account_id": target.account_id,
                    "account_name": target.account_name,
                    "region": region,
                    "service": service,
                    "resource_type": "Resource Explorer supported resources",
                    "resource_count": counts.get(service, 0),
                    "scan_status": "COMPLETE",
                    "message": "",
                    "source": "resource-explorer-2",
                })
            coverage.append({
                "account_id": target.account_id,
                "account_name": target.account_name,
                "region": region,
                "service": "AWS Resource Explorer",
                "resource_type": "Broad discovery fallback",
                "resource_count": sum(counts.values()),
                "scan_status": "COMPLETE",
                "message": "Default Resource Explorer view queried with pagination.",
                "source": "resource-explorer-2",
            })
        except (ClientError, BotoCoreError, Exception) as exc:
            scan_status, message = _status(exc)
            logger.info("Resource Explorer inventory unavailable for %s/%s: %s", target.account_id, region, exc)
            coverage.append({
                "account_id": target.account_id,
                "account_name": target.account_name,
                "region": region,
                "service": "AWS Resource Explorer",
                "resource_type": "Broad discovery fallback",
                "resource_count": 0,
                "scan_status": scan_status,
                "message": message,
                "source": "resource-explorer-2",
            })

    return rows, coverage
