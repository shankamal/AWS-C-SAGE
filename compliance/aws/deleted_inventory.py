import logging
from datetime import timedelta

from botocore.exceptions import BotoCoreError, ClientError

from .inventory import _json_safe, _status_from_error, make_resource_key
from .types import InventoryData

logger = logging.getLogger(__name__)


def _pages(client, operation, kwargs):
    if client.can_paginate(operation):
        yield from client.get_paginator(operation).paginate(**kwargs)
    else:
        token = None
        while True:
            call = dict(kwargs)
            if token:
                call["nextToken"] = token
            page = getattr(client, operation)(**call)
            yield page
            token = page.get("nextToken")
            if not token:
                break


def _supported_config_resource_types(config_client):
    """Use botocore's current service model instead of maintaining a local AWS Config type catalog."""
    try:
        operation = config_client.meta.service_model.operation_model("ListDiscoveredResources")
        resource_type_shape = operation.input_shape.members["resourceType"]
        return list(resource_type_shape.enum or [])
    except Exception as exc:
        logger.warning("Unable to inspect AWS Config supported resource-type enum: %s", exc)
        return []


def _latest_history_item(config_client, resource_type, resource_id, deletion_time):
    """Return the last Config item at/before deletion when AWS still retains it."""
    try:
        kwargs = {
            "resourceType": resource_type,
            "resourceId": resource_id,
            "chronologicalOrder": "Reverse",
            "limit": 1,
        }
        if deletion_time:
            # Give Config a small margin so a deletion CI recorded just after the identifier's
            # deletion timestamp is still eligible for the reverse-history lookup.
            kwargs["laterTime"] = deletion_time + timedelta(minutes=5)
        response = config_client.get_resource_config_history(**kwargs)
        items = response.get("configurationItems", [])
        return items[0] if items else {}
    except Exception as exc:
        return {"HistoryLookupError": str(exc)}


def discover_deleted_inventory(session, target, regions):
    """
    Discover deleted resources only when AWS Config still exposes deletion metadata/history.

    This deliberately does not infer deletion from absence. Each emitted row has an AWS-provided
    resourceDeletionTime from ListDiscoveredResources(includeDeletedResources=True).
    """
    rows = []
    coverage = []

    for region in regions:
        count = 0
        try:
            config = session.client("config", region_name=region)
            recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
            if not recorders:
                coverage.append({
                    "account_id": target.account_id,
                    "account_name": target.account_name,
                    "region": region,
                    "service": "AWS Config History",
                    "resource_type": "Deleted resources",
                    "resource_count": 0,
                    "scan_status": "UNAVAILABLE",
                    "message": "No AWS Config configuration recorder is available in this Region.",
                    "source": "aws-config-history",
                })
                continue

            resource_types = _supported_config_resource_types(config)
            if not resource_types:
                coverage.append({
                    "account_id": target.account_id,
                    "account_name": target.account_name,
                    "region": region,
                    "service": "AWS Config History",
                    "resource_type": "Deleted resources",
                    "resource_count": 0,
                    "scan_status": "UNAVAILABLE",
                    "message": "AWS Config resource-type catalog could not be resolved from the SDK service model.",
                    "source": "aws-config-history",
                })
                continue

            for resource_type in resource_types:
                try:
                    for page in _pages(config, "list_discovered_resources", {
                        "resourceType": resource_type,
                        "includeDeletedResources": True,
                    }):
                        for item in page.get("resourceIdentifiers", []):
                            deletion_time = item.get("resourceDeletionTime")
                            if not deletion_time:
                                continue
                            resource_id = item.get("resourceId", "")
                            if not resource_id:
                                continue
                            history = _latest_history_item(
                                config, resource_type, resource_id, deletion_time
                            )
                            configuration = history.get("configuration", {}) if isinstance(history, dict) else {}
                            if isinstance(configuration, str):
                                import json
                                try:
                                    configuration = json.loads(configuration)
                                except Exception:
                                    configuration = {"configuration": configuration}
                            tags = history.get("tags", {}) if isinstance(history, dict) else {}
                            relationships = history.get("relationships", []) if isinstance(history, dict) else []
                            original_service = resource_type.split("::")[1] if "::" in resource_type else "AWS"
                            raw = {
                                "discoveredResourceIdentifier": _json_safe(item),
                                "lastConfigurationItem": _json_safe(history),
                                "originalService": original_service,
                            }
                            historical_type = f"{resource_type} (Deleted)"
                            key = make_resource_key(
                                target.account_id,
                                region,
                                "AWS Config History",
                                historical_type,
                                f"{resource_id}@{_json_safe(deletion_time)}",
                                "",
                            )
                            rows.append(InventoryData(
                                account_id=target.account_id,
                                account_name=target.account_name,
                                region=region,
                                service="AWS Config History",
                                resource_type=historical_type,
                                resource_name=item.get("resourceName", ""),
                                resource_id=resource_id,
                                resource_arn=history.get("arn", "") if isinstance(history, dict) else "",
                                status="DELETED",
                                creation_time=history.get("resourceCreationTime", "") if isinstance(history, dict) else "",
                                tags=_json_safe(tags or {}),
                                configuration=_json_safe(configuration or {}),
                                networking={},
                                security={},
                                relationships={
                                    "original_service": original_service,
                                    "config_relationships": _json_safe(relationships or []),
                                    "resource_deletion_time": _json_safe(deletion_time),
                                },
                                raw_attributes=raw,
                                discovery_source="aws-config-history",
                                resource_key=key,
                            ))
                            count += 1
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    # Some Config resource types are not valid/available in every Region. Skip the
                    # type and continue; region-level discovery remains valid for other types.
                    if code in {
                        "ValidationException",
                        "InvalidResourceTypeException",
                        "NoAvailableConfigurationRecorderException",
                    }:
                        continue
                    raise

            coverage.append({
                "account_id": target.account_id,
                "account_name": target.account_name,
                "region": region,
                "service": "AWS Config History",
                "resource_type": "Deleted resources",
                "resource_count": count,
                "scan_status": "COMPLETE",
                "message": "Only AWS Config-discovered resources with AWS-provided deletion timestamps are included.",
                "source": "aws-config-history",
            })
        except (ClientError, BotoCoreError, Exception) as exc:
            status, message = _status_from_error(exc)
            logger.info("Deleted-resource inventory unavailable for %s/%s: %s", target.account_id, region, exc)
            coverage.append({
                "account_id": target.account_id,
                "account_name": target.account_name,
                "region": region,
                "service": "AWS Config History",
                "resource_type": "Deleted resources",
                "resource_count": count,
                "scan_status": status,
                "message": message,
                "source": "aws-config-history",
            })

    return rows, coverage
