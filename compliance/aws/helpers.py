import ipaddress
import os
from datetime import datetime, timezone


def utcnow():
    return datetime.now(timezone.utc)


def days_old(dt):
    if not dt:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (utcnow() - dt).days


def pagination(client, operation, result_key, **kwargs):
    if client.can_paginate(operation):
        paginator = client.get_paginator(operation)
        for page in paginator.paginate(**kwargs):
            yield from page.get(result_key, [])
    else:
        page = getattr(client, operation)(**kwargs)
        yield from page.get(result_key, [])


def cidr_is_broad(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return net.prefixlen <= 16
    except ValueError:
        return False


def sensitive_ports():
    raw = os.getenv("CSAGE_SENSITIVE_PORTS", "22,3389,1433,1521,3306,5432,6379,9200,27017")
    return {int(x.strip()) for x in raw.split(",") if x.strip().isdigit()}
