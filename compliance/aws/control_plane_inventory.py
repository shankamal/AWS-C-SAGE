import logging

from botocore.exceptions import BotoCoreError, ClientError

from .inventory import InventoryBuilder, _pages, _status_from_error

logger = logging.getLogger(__name__)


def _dx_tags(client, arns):
    if not arns:
        return {}
    result = {}
    try:
        for start in range(0, len(arns), 100):
            response = client.describe_tags(resourceArns=arns[start:start + 100])
            for resource in response.get("resourceTags", []):
                arn = resource.get("resourceArn", "")
                result[arn] = {
                    tag.get("key", ""): tag.get("value", "")
                    for tag in resource.get("tags", [])
                    if tag.get("key")
                }
    except Exception as exc:
        logger.info("Direct Connect tag discovery failed: %s", exc)
    return result


def _collect_direct_connect(session, builder, region):
    try:
        client = session.client("directconnect", region_name=region)
        resources = []

        for page in _pages(client, "describe_connections"):
            resources.extend(("Direct Connect Connection", item) for item in page.get("connections", []))
        for page in _pages(client, "describe_virtual_interfaces"):
            resources.extend(("Direct Connect Virtual Interface", item) for item in page.get("virtualInterfaces", []))
        for page in _pages(client, "describe_direct_connect_gateways"):
            resources.extend(("Direct Connect Gateway", item) for item in page.get("directConnectGateways", []))

        arns = []
        for _, item in resources:
            arn = item.get("connectionArn") or item.get("virtualInterfaceArn") or item.get("directConnectGatewayArn")
            if arn:
                arns.append(arn)
        tags_by_arn = _dx_tags(client, arns)

        counts = {
            "Direct Connect Connection": 0,
            "Direct Connect Virtual Interface": 0,
            "Direct Connect Gateway": 0,
        }
        for rtype, item in resources:
            if rtype == "Direct Connect Connection":
                rid = item.get("connectionId", "")
                name = item.get("connectionName", "")
                arn = item.get("connectionArn", "")
                status = item.get("connectionState", "")
            elif rtype == "Direct Connect Virtual Interface":
                rid = item.get("virtualInterfaceId", "")
                name = item.get("virtualInterfaceName", "")
                arn = item.get("virtualInterfaceArn", "")
                status = item.get("virtualInterfaceState", "")
            else:
                rid = item.get("directConnectGatewayId", "")
                name = item.get("directConnectGatewayName", "")
                arn = item.get("directConnectGatewayArn", "")
                status = item.get("directConnectGatewayState", "")

            builder.add(
                region=region,
                service="Direct Connect",
                resource_type=rtype,
                resource_id=arn or rid,
                resource_name=name,
                resource_arn=arn,
                status=status,
                tags=tags_by_arn.get(arn, {}),
                configuration=item,
                networking=item,
                security={},
                relationships=item,
                raw_attributes=item,
                source="service-api",
            )
            counts[rtype] += 1

        for rtype, count in counts.items():
            builder.covered(region=region, service="Direct Connect", resource_type=rtype, count=count)
    except (ClientError, BotoCoreError, Exception) as exc:
        status, message = _status_from_error(exc)
        for rtype in ("Direct Connect Connection", "Direct Connect Virtual Interface", "Direct Connect Gateway"):
            builder.covered(region=region, service="Direct Connect", resource_type=rtype, count=0, status=status, message=message)


def _collect_control_tower(session, builder, region):
    count = 0
    try:
        client = session.client("controltower", region_name=region)
        summaries = []
        for page in _pages(client, "list_landing_zones"):
            summaries.extend(page.get("landingZones", []))
        for summary in summaries:
            arn = summary.get("arn", "")
            detail = dict(summary)
            if arn:
                try:
                    detail = client.get_landing_zone(landingZoneIdentifier=arn).get("landingZone", summary)
                except Exception as exc:
                    detail = dict(summary)
                    detail["GetLandingZoneError"] = str(exc)
            builder.add(
                region=region,
                service="Control Tower",
                resource_type="Control Tower Landing Zone",
                resource_id=arn or summary.get("version", "landing-zone"),
                resource_name=detail.get("arn", arn),
                resource_arn=arn,
                status=detail.get("status", ""),
                configuration=detail,
                security=detail,
                relationships=detail,
                raw_attributes=detail,
                source="service-api",
            )
            count += 1
        builder.covered(region=region, service="Control Tower", resource_type="Control Tower Landing Zone", count=count)
    except (ClientError, BotoCoreError, Exception) as exc:
        status, message = _status_from_error(exc)
        builder.covered(region=region, service="Control Tower", resource_type="Control Tower Landing Zone", count=count, status=status, message=message)


def _collect_shield(session, builder):
    count = 0
    try:
        client = session.client("shield", region_name="us-east-1")
        protections = []
        for page in _pages(client, "list_protections"):
            protections.extend(page.get("Protections", []))
        for protection in protections:
            protection_id = protection.get("Id", "")
            detail = dict(protection)
            if protection_id:
                try:
                    detail = client.describe_protection(ProtectionId=protection_id).get("Protection", protection)
                except Exception as exc:
                    detail["DescribeProtectionError"] = str(exc)
            arn = detail.get("ProtectionArn", protection.get("ProtectionArn", ""))
            tags = {}
            if arn:
                try:
                    tags = {
                        item.get("Key", ""): item.get("Value", "")
                        for item in client.list_tags_for_resource(ResourceARN=arn).get("Tags", [])
                        if item.get("Key")
                    }
                except Exception:
                    tags = {}
            builder.add(
                region="global",
                service="Shield",
                resource_type="Shield Protection",
                resource_id=arn or protection_id,
                resource_name=detail.get("Name", ""),
                resource_arn=arn,
                status="Protected",
                tags=tags,
                configuration=detail,
                security=detail,
                relationships={"ResourceArn": detail.get("ResourceArn")},
                raw_attributes=detail,
                source="service-api",
            )
            count += 1
        builder.covered(region="global", service="Shield", resource_type="Shield Protection", count=count)
    except (ClientError, BotoCoreError, Exception) as exc:
        status, message = _status_from_error(exc)
        builder.covered(region="global", service="Shield", resource_type="Shield Protection", count=count, status=status, message=message)


def discover_control_plane_inventory(session, target, regions):
    builder = InventoryBuilder(target)
    for region in regions:
        _collect_direct_connect(session, builder, region)
        _collect_control_tower(session, builder, region)
    _collect_shield(session, builder)
    return builder.rows, builder.coverage
