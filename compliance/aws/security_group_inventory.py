import logging

from botocore.exceptions import ClientError

from .types import InventoryData

logger = logging.getLogger(__name__)


def _pages(client, operation, **kwargs):
    if client.can_paginate(operation):
        yield from client.get_paginator(operation).paginate(**kwargs)
    else:
        yield getattr(client, operation)(**kwargs)


def _coverage(target, region, count, status="COMPLETE", message=""):
    return {
        "account_id": target.account_id,
        "account_name": target.account_name,
        "region": region,
        "service": "EC2",
        "resource_type": "Security Group Rule",
        "resource_count": int(count or 0),
        "scan_status": status,
        "message": str(message or ""),
        "source": "ec2-describe-security-group-rules",
    }


def _error_status(exc):
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        lower = code.lower()
        if any(token in lower for token in ("accessdenied", "unauthorized", "forbidden")):
            return "ACCESS_DENIED", code
        if any(token in lower for token in ("unsupported", "invalidaction", "notfound")):
            return "UNAVAILABLE", code
        return "ERROR", code or exc.__class__.__name__
    return "ERROR", exc.__class__.__name__


def _tags(raw):
    result = {}
    for item in raw.get("Tags", []) or []:
        if isinstance(item, dict) and item.get("Key"):
            result[str(item["Key"])] = str(item.get("Value", ""))
    return result


def _endpoint(rule):
    for key in ("CidrIpv4", "CidrIpv6", "PrefixListId"):
        if rule.get(key):
            return str(rule[key])
    referenced = rule.get("ReferencedGroupInfo") or {}
    if referenced.get("GroupId"):
        owner = referenced.get("UserId")
        return f"{referenced['GroupId']} ({owner})" if owner else str(referenced["GroupId"])
    return "All"


def _port_range(rule):
    protocol = str(rule.get("IpProtocol", "") or "")
    if protocol == "-1":
        return "All"
    start = rule.get("FromPort")
    end = rule.get("ToPort")
    if start is None and end is None:
        return "All"
    if start == end:
        return str(start)
    return f"{start}-{end}"


def _protocol(rule):
    value = str(rule.get("IpProtocol", "") or "")
    return "ALL" if value == "-1" else value.upper()


def _partition(target):
    role_arn = str(getattr(target, "role_arn", "") or "")
    parts = role_arn.split(":")
    if len(parts) > 1 and parts[0] == "arn" and parts[1]:
        return parts[1]
    return "aws"


def discover_security_group_rule_inventory(session, target, regions):
    """Return one Master Inventory row for every EC2 security-group ingress/egress rule."""
    rows = []
    coverage = []

    for region in regions:
        count = 0
        try:
            ec2 = session.client("ec2", region_name=region)

            # Enrich each rule with its parent Security Group name and VPC when available.
            groups = {}
            try:
                for page in _pages(ec2, "describe_security_groups"):
                    for group in page.get("SecurityGroups", []) or []:
                        group_id = group.get("GroupId")
                        if group_id:
                            groups[group_id] = {
                                "GroupName": group.get("GroupName", ""),
                                "VpcId": group.get("VpcId", ""),
                                "Description": group.get("Description", ""),
                            }
            except Exception as exc:
                logger.info("Security Group metadata enrichment failed for %s/%s: %s", target.account_id, region, exc)

            for page in _pages(ec2, "describe_security_group_rules"):
                for rule in page.get("SecurityGroupRules", []) or []:
                    rule_id = str(rule.get("SecurityGroupRuleId", "") or "")
                    if not rule_id:
                        # DescribeSecurityGroupRules normally always returns sgr-*; skip malformed records
                        # rather than creating an unstable inventory identity.
                        continue

                    group_id = str(rule.get("GroupId", "") or "")
                    group = groups.get(group_id, {})
                    direction = "EGRESS" if rule.get("IsEgress") else "INGRESS"
                    endpoint = _endpoint(rule)
                    ports = _port_range(rule)
                    protocol = _protocol(rule)
                    group_label = group.get("GroupName") or group_id or "Security Group"
                    rule_name = f"{group_label} | {direction.title()} {protocol} {ports} | {endpoint}"
                    referenced = rule.get("ReferencedGroupInfo") or {}

                    configuration = dict(rule)
                    configuration.update({
                        "Direction": direction,
                        "ProtocolDisplay": protocol,
                        "PortRange": ports,
                        "SourceOrDestination": endpoint,
                    })
                    networking = {
                        "SecurityGroupId": group_id,
                        "VpcId": group.get("VpcId", ""),
                        "CidrIpv4": rule.get("CidrIpv4"),
                        "CidrIpv6": rule.get("CidrIpv6"),
                        "PrefixListId": rule.get("PrefixListId"),
                        "ReferencedGroupInfo": referenced,
                    }
                    security = {
                        "Direction": direction,
                        "IpProtocol": rule.get("IpProtocol"),
                        "FromPort": rule.get("FromPort"),
                        "ToPort": rule.get("ToPort"),
                        "PortRange": ports,
                        "SourceOrDestination": endpoint,
                        "Description": rule.get("Description", ""),
                    }
                    relationships = {
                        "SecurityGroupId": group_id,
                        "SecurityGroupName": group.get("GroupName", ""),
                        "SecurityGroupDescription": group.get("Description", ""),
                        "VpcId": group.get("VpcId", ""),
                        "ReferencedGroupInfo": referenced,
                    }
                    arn = f"arn:{_partition(target)}:ec2:{region}:{target.account_id}:security-group-rule/{rule_id}"

                    rows.append(InventoryData(
                        account_id=target.account_id,
                        account_name=target.account_name,
                        region=region,
                        service="EC2",
                        resource_type="Security Group Rule",
                        resource_id=rule_id,
                        resource_name=rule_name,
                        resource_arn=arn,
                        status=direction,
                        tags=_tags(rule),
                        configuration=configuration,
                        networking=networking,
                        security=security,
                        relationships=relationships,
                        raw_attributes=dict(rule),
                        discovery_source="ec2-describe-security-group-rules",
                    ))
                    count += 1

            coverage.append(_coverage(target, region, count))
        except Exception as exc:
            status, message = _error_status(exc)
            logger.info("Security Group Rule inventory failed for %s/%s: %s", target.account_id, region, exc)
            coverage.append(_coverage(target, region, count, status=status, message=message))

    return rows, coverage
