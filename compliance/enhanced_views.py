from collections import Counter

from django.core.paginator import Paginator
from django.http import HttpResponse
from django.shortcuts import render

from .inventory_export import build_inventory_workbook
from .models import Finding, ResourceInventory, ScanRun
from .storage import store


def _latest():
    return ScanRun.objects.first()


def _inventory_filters(request, rows):
    account = request.GET.get("account", "")
    service = request.GET.get("service", "")
    resource_type = request.GET.get("resource_type", "")
    region = request.GET.get("region", "")
    status = request.GET.get("status", "")
    keyword = request.GET.get("q", "").strip().lower()

    result = rows
    if account:
        result = [r for r in result if r.account_id == account]
    if service:
        result = [r for r in result if r.service == service]
    if resource_type:
        result = [r for r in result if r.resource_type == resource_type]
    if region:
        result = [r for r in result if r.region == region]
    if status:
        result = [r for r in result if r.status == status]
    if keyword:
        result = [
            r for r in result
            if any(
                keyword in str(value).lower()
                for value in (
                    r.resource_name,
                    r.resource_id,
                    r.resource_arn,
                    r.service,
                    r.resource_type,
                    r.account_name,
                    r.account_id,
                )
            )
        ]

    return result, {
        "account": account,
        "service": service,
        "resource_type": resource_type,
        "region": region,
        "status": status,
        "q": request.GET.get("q", ""),
    }


def dashboard(request):
    scan = _latest()
    findings = Finding.objects.for_scan(scan)
    inventory = ResourceInventory.objects.for_scan(scan)

    modules = []
    for name in sorted({f.module for f in findings}):
        module_findings = [f for f in findings if f.module == name]
        modules.append({
            "name": name,
            "total": len(module_findings),
            "non_compliant": sum(1 for f in module_findings if f.status == Finding.Status.NON_COMPLIANT),
            "suppressed": sum(1 for f in module_findings if f.status == Finding.Status.SUPPRESSED),
        })
    modules.sort(key=lambda item: (-item["non_compliant"], item["name"].lower()))

    recent = [f for f in findings if f.status != Finding.Status.COMPLIANT][:12]

    service_counts = Counter((r.service or "Unknown") for r in inventory)
    service_max = max(service_counts.values(), default=1)
    service_chart = [
        {"name": name, "count": count, "pct": round((count / service_max) * 100, 1)}
        for name, count in service_counts.most_common(8)
    ]

    severity_counts = Counter((f.severity or "INFO").upper() for f in findings)
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    severity_max = max((severity_counts.get(name, 0) for name in severity_order), default=1) or 1
    severity_chart = [
        {
            "name": name.title(),
            "slug": name.lower(),
            "count": severity_counts.get(name, 0),
            "pct": round((severity_counts.get(name, 0) / severity_max) * 100, 1),
        }
        for name in severity_order
        if severity_counts.get(name, 0)
    ]

    compliant = scan.compliant_count if scan else 0
    non_compliant = scan.non_compliant_count if scan else 0
    suppressed = scan.suppressed_count if scan else 0
    posture_total = compliant + non_compliant + suppressed
    if posture_total:
        compliant_pct = round((compliant / posture_total) * 100, 1)
        non_compliant_pct = round((non_compliant / posture_total) * 100, 1)
        suppressed_pct = round((suppressed / posture_total) * 100, 1)
    else:
        compliant_pct = non_compliant_pct = suppressed_pct = 0

    posture = {
        "compliant": compliant,
        "non_compliant": non_compliant,
        "suppressed": suppressed,
        "compliant_pct": compliant_pct,
        "non_compliant_pct": non_compliant_pct,
        "suppressed_pct": suppressed_pct,
        "non_compliant_end": round(compliant_pct + non_compliant_pct, 1),
        "score": compliant_pct,
    }

    return render(request, "compliance/dashboard.html", {
        "scan": scan,
        "recent_findings": recent,
        "modules": modules,
        "service_chart": service_chart,
        "severity_chart": severity_chart,
        "posture": posture,
    })


def inventory_view(request):
    scan = _latest()
    base = ResourceInventory.objects.for_scan(scan)
    filtered, filters = _inventory_filters(request, base)
    filtered.sort(
        key=lambda r: (
            r.account_name.lower(),
            r.service.lower(),
            r.resource_type.lower(),
            r.resource_name.lower(),
            r.resource_id.lower(),
        )
    )

    coverage = [
        row for row in store.read_inventory_coverage()
        if scan and row.get("scan_run_id") == scan.id
    ]
    coverage_summary = {}
    for row in coverage:
        key = (row.get("service", "Unknown"), row.get("resource_type", "Unknown"))
        item = coverage_summary.setdefault(key, {
            "service": key[0],
            "resource_type": key[1],
            "resource_count": 0,
            "complete": 0,
            "access_denied": 0,
            "errors": 0,
            "regions": set(),
            "accounts": set(),
        })
        item["resource_count"] += int(row.get("resource_count", 0) or 0)
        scan_status = row.get("scan_status", "")
        if scan_status == "COMPLETE":
            item["complete"] += 1
        elif scan_status == "ACCESS_DENIED":
            item["access_denied"] += 1
        else:
            item["errors"] += 1
        item["regions"].add(row.get("region", ""))
        item["accounts"].add(row.get("account_id", ""))

    coverage_rows = []
    for item in coverage_summary.values():
        item["regions"] = len(item["regions"])
        item["accounts"] = len(item["accounts"])
        coverage_rows.append(item)
    coverage_rows.sort(key=lambda item: (item["service"].lower(), item["resource_type"].lower()))

    accounts = sorted({(r.account_id, r.account_name) for r in base}, key=lambda item: item[1].lower())
    services = sorted({r.service for r in base} | {r.get("service", "") for r in coverage if r.get("service")})

    service_resource_types = {}
    for resource in base:
        if resource.service and resource.resource_type:
            service_resource_types.setdefault(resource.service, set()).add(resource.resource_type)
    for row in coverage:
        service = row.get("service", "")
        resource_type = row.get("resource_type", "")
        if service and resource_type:
            service_resource_types.setdefault(service, set()).add(resource_type)

    service_resource_types = {
        service: sorted(resource_types)
        for service, resource_types in sorted(service_resource_types.items(), key=lambda item: item[0].lower())
    }
    all_resource_types = sorted({resource_type for values in service_resource_types.values() for resource_type in values})
    resource_types = service_resource_types.get(filters["service"], []) if filters["service"] else all_resource_types

    regions = sorted({r.region for r in base} | {r.get("region", "") for r in coverage if r.get("region")})
    statuses = sorted({r.status for r in base if r.status})

    paginator = Paginator(filtered, 200)
    page = paginator.get_page(request.GET.get("page", 1))
    query_without_page = request.GET.copy()
    query_without_page.pop("page", None)

    return render(request, "compliance/inventory.html", {
        "scan": scan,
        "page": page,
        "filtered_count": len(filtered),
        "total_count": len(base),
        "coverage": coverage_rows,
        "coverage_count": len(coverage_rows),
        "zero_resource_count": sum(1 for item in coverage_rows if item["resource_count"] == 0),
        "coverage_issue_count": sum(1 for item in coverage_rows if item["access_denied"] or item["errors"]),
        "accounts": accounts,
        "services": services,
        "resource_types": resource_types,
        "service_resource_types": service_resource_types,
        "regions": regions,
        "statuses": statuses,
        "filters": filters,
        "query_without_page": query_without_page.urlencode(),
        "export_query": request.GET.urlencode(),
    })


def export_inventory_xlsx(request):
    scan = _latest()
    rows = ResourceInventory.objects.for_scan(scan)
    rows, filters = _inventory_filters(request, rows)
    rows.sort(
        key=lambda r: (
            r.account_name.lower(),
            r.service.lower(),
            r.resource_type.lower(),
            r.resource_name.lower(),
            r.resource_id.lower(),
        )
    )
    coverage = [
        row for row in store.read_inventory_coverage()
        if scan and row.get("scan_run_id") == scan.id
    ]
    workbook_bytes = build_inventory_workbook(scan, rows, coverage, filters)
    response = HttpResponse(
        workbook_bytes,
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    response["Content-Disposition"] = 'attachment; filename="c-sage-filtered-aws-inventory.xlsx"'
    return response
