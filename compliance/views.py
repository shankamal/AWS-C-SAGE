import csv
import io

from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST
from openpyxl import Workbook

from .aws.orchestrator import ComplianceOrchestrator
from .aws.suppressions import SuppressionStore
from .models import Finding, ResourceInventory, ScanRun
from .storage import store


def healthz(request):
    return JsonResponse({"status": "ok", "service": "C-SAGE", "storage": "flat-file"})


def _latest():
    return ScanRun.objects.first()


def dashboard(request):
    scan = _latest()
    findings = Finding.objects.for_scan(scan)
    modules = []
    for name in sorted({f.module for f in findings}):
        module_findings = [f for f in findings if f.module == name]
        modules.append({
            "name": name,
            "total": len(module_findings),
            "non_compliant": sum(1 for f in module_findings if f.status == Finding.Status.NON_COMPLIANT),
            "suppressed": sum(1 for f in module_findings if f.status == Finding.Status.SUPPRESSED),
        })
    recent = [f for f in findings if f.status != Finding.Status.COMPLIANT][:12]
    return render(request, "compliance/dashboard.html", {"scan": scan, "recent_findings": recent, "modules": modules})


def findings_view(request):
    scan = _latest()
    base = Finding.objects.for_scan(scan)
    account = request.GET.get("account", "")
    module = request.GET.get("module", "")
    status = request.GET.get("status", "")
    keyword = request.GET.get("q", "").strip().lower()

    findings = base
    if account:
        findings = [f for f in findings if f.account_id == account]
    if module:
        findings = [f for f in findings if f.module == module]
    if status:
        findings = [f for f in findings if f.status == status]
    if keyword:
        findings = [
            f for f in findings
            if keyword in f.resource_id.lower()
            or keyword in f.title.lower()
            or keyword in f.rule_id.lower()
            or keyword in f.details.lower()
        ]

    accounts = sorted({(f.account_id, f.account_name) for f in base}, key=lambda item: item[1])
    module_names = sorted({f.module for f in base})
    ctx = {
        "scan": scan,
        "findings": findings[:1000],
        "accounts": accounts,
        "module_names": module_names,
        "filters": {"account": account, "module": module, "status": status, "q": request.GET.get("q", "")},
    }
    return render(request, "compliance/findings.html", ctx)


@require_POST
def run_scan(request):
    try:
        actor = request.user.get_username() if getattr(request, "user", None) else "system"
        scan = ComplianceOrchestrator().run(actor or "system")
        messages.success(request, f"Audit scan #{scan.id} completed.")
    except Exception as exc:
        messages.error(request, f"Audit scan failed: {exc}")
    return redirect("dashboard")


@require_POST
def toggle_suppression(request, finding_id):
    scan = _latest()
    findings = Finding.objects.for_scan(scan)
    finding = next((item for item in findings if item.id == finding_id), None)
    if not finding:
        messages.error(request, "Finding not found in the latest flat-file scan results.")
        return redirect("findings")

    suppressions = SuppressionStore()
    try:
        actor = request.user.get_username() if getattr(request, "user", None) else "system"
        if finding.status == Finding.Status.SUPPRESSED:
            suppressions.unsuppress(finding.finding_key, actor)
            finding.status = Finding.Status.NON_COMPLIANT
            messages.success(request, "Finding unsuppressed.")
        else:
            reason = request.POST.get("reason", "Suppressed through C-SAGE UI")[:500]
            suppressions.suppress(finding.finding_key, actor, reason)
            finding.status = Finding.Status.SUPPRESSED
            messages.success(request, "Finding suppressed and persisted to the local flat-file store.")

        store.write_findings([item.to_dict() for item in findings])
        if scan:
            scan.compliant_count = sum(1 for item in findings if item.status == Finding.Status.COMPLIANT)
            scan.non_compliant_count = sum(1 for item in findings if item.status == Finding.Status.NON_COMPLIANT)
            scan.suppressed_count = sum(1 for item in findings if item.status == Finding.Status.SUPPRESSED)
            scan.save()
    except Exception as exc:
        messages.error(request, f"Suppression update failed: {exc}")
    return redirect(request.META.get("HTTP_REFERER", "/findings/"))


def export_inventory_csv(request):
    scan = _latest()
    rows = ResourceInventory.objects.for_scan(scan)
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="c-sage-master-inventory.csv"'
    writer = csv.writer(response)
    writer.writerow(["Account ID", "Account Name", "Region", "Service", "Resource Type", "Resource ID", "Resource ARN"])
    for r in rows:
        writer.writerow([r.account_id, r.account_name, r.region, r.service, r.resource_type, r.resource_id, r.resource_arn])
    return response


def export_inventory_xlsx(request):
    scan = _latest()
    rows = ResourceInventory.objects.for_scan(scan)
    wb = Workbook(write_only=True)
    ws = wb.create_sheet("Master Inventory")
    ws.append(["Account ID", "Account Name", "Region", "Service", "Resource Type", "Resource ID", "Resource ARN"])
    for r in rows:
        ws.append([r.account_id, r.account_name, r.region, r.service, r.resource_type, r.resource_id, r.resource_arn])
    buf = io.BytesIO()
    wb.save(buf)
    response = HttpResponse(buf.getvalue(), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    response["Content-Disposition"] = 'attachment; filename="c-sage-master-inventory.xlsx"'
    return response


def export_findings_csv(request):
    scan = _latest()
    rows = Finding.objects.for_scan(scan)
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="c-sage-compliance-findings.csv"'
    writer = csv.writer(response)
    writer.writerow(["Rule", "Module", "Account ID", "Account Name", "Region", "Service", "Resource ID", "Status", "Severity", "Title", "Details"])
    for f in rows:
        writer.writerow([f.rule_id, f.module, f.account_id, f.account_name, f.region, f.service, f.resource_id, f.status, f.severity, f.title, f.details])
    return response
