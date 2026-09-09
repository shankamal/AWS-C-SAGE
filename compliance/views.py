import csv
import io
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from openpyxl import Workbook
from .aws.orchestrator import ComplianceOrchestrator
from .aws.suppressions import SuppressionStore
from .models import Finding, ResourceInventory, ScanRun


def healthz(request):
    return JsonResponse({"status": "ok", "service": "C-SAGE"})


def _latest():
    return ScanRun.objects.first()


@login_required
def dashboard(request):
    scan = _latest()
    findings = Finding.objects.filter(scan_run=scan) if scan else Finding.objects.none()
    modules = []
    if scan:
        for name in findings.values_list("module", flat=True).distinct().order_by("module"):
            q = findings.filter(module=name)
            modules.append({"name": name, "total": q.count(), "non_compliant": q.filter(status=Finding.Status.NON_COMPLIANT).count(), "suppressed": q.filter(status=Finding.Status.SUPPRESSED).count()})
    return render(request, "compliance/dashboard.html", {"scan": scan, "recent_findings": findings.exclude(status=Finding.Status.COMPLIANT)[:12], "modules": modules})


@login_required
def findings_view(request):
    scan = _latest()
    qs = Finding.objects.filter(scan_run=scan) if scan else Finding.objects.none()
    account = request.GET.get("account", "")
    module = request.GET.get("module", "")
    status = request.GET.get("status", "")
    keyword = request.GET.get("q", "")
    if account:
        qs = qs.filter(account_id=account)
    if module:
        qs = qs.filter(module=module)
    if status:
        qs = qs.filter(status=status)
    if keyword:
        qs = qs.filter(Q(resource_id__icontains=keyword) | Q(title__icontains=keyword) | Q(rule_id__icontains=keyword) | Q(details__icontains=keyword))
    base = Finding.objects.filter(scan_run=scan) if scan else Finding.objects.none()
    ctx = {
        "scan": scan,
        "findings": qs[:1000],
        "accounts": base.values_list("account_id", "account_name").distinct().order_by("account_name"),
        "module_names": base.values_list("module", flat=True).distinct().order_by("module"),
        "filters": {"account": account, "module": module, "status": status, "q": keyword},
    }
    return render(request, "compliance/findings.html", ctx)

@require_POST
@login_required
def run_scan(request):
    try:
        scan = ComplianceOrchestrator().run(request.user.get_username() or "authenticated-user")
        messages.success(request, f"Audit scan #{scan.id} completed.")
    except Exception as exc:
        messages.error(request, f"Audit scan failed: {exc}")
    return redirect("dashboard")

@require_POST
@login_required
def toggle_suppression(request, finding_id):
    finding = get_object_or_404(Finding, pk=finding_id)
    store = SuppressionStore()
    try:
        actor = request.user.get_username() or "authenticated-user"
        if finding.status == Finding.Status.SUPPRESSED:
            store.unsuppress(finding.finding_key, actor)
            finding.status = Finding.Status.NON_COMPLIANT
            delta = -1
            messages.success(request, "Finding unsuppressed.")
        else:
            reason = request.POST.get("reason", "Suppressed through C-SAGE UI")[:500]
            store.suppress(finding.finding_key, actor, reason)
            finding.status = Finding.Status.SUPPRESSED
            delta = 1
            messages.success(request, "Finding suppressed and persisted to S3.")
        finding.save(update_fields=["status"])
        scan = finding.scan_run
        scan.suppressed_count = max(0, scan.suppressed_count + delta)
        scan.non_compliant_count = max(0, scan.non_compliant_count - delta)
        scan.save(update_fields=["suppressed_count", "non_compliant_count"])
    except Exception as exc:
        messages.error(request, f"Suppression update failed: {exc}")
    return redirect(request.META.get("HTTP_REFERER", "/findings/"))


@login_required
def export_inventory_csv(request):
    scan = _latest()
    qs = ResourceInventory.objects.filter(scan_run=scan) if scan else ResourceInventory.objects.none()
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="c-sage-master-inventory.csv"'
    writer = csv.writer(response)
    writer.writerow(["Account ID", "Account Name", "Region", "Service", "Resource Type", "Resource ID", "Resource ARN"])
    for r in qs.iterator(chunk_size=1000):
        writer.writerow([r.account_id, r.account_name, r.region, r.service, r.resource_type, r.resource_id, r.resource_arn])
    return response


@login_required
def export_inventory_xlsx(request):
    scan = _latest()
    qs = ResourceInventory.objects.filter(scan_run=scan) if scan else ResourceInventory.objects.none()
    wb = Workbook(write_only=True)
    ws = wb.create_sheet("Master Inventory")
    ws.append(["Account ID", "Account Name", "Region", "Service", "Resource Type", "Resource ID", "Resource ARN"])
    for r in qs.iterator(chunk_size=1000):
        ws.append([r.account_id, r.account_name, r.region, r.service, r.resource_type, r.resource_id, r.resource_arn])
    buf = io.BytesIO()
    wb.save(buf)
    response = HttpResponse(buf.getvalue(), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    response["Content-Disposition"] = 'attachment; filename="c-sage-master-inventory.xlsx"'
    return response


@login_required
def export_findings_csv(request):
    scan = _latest()
    qs = Finding.objects.filter(scan_run=scan) if scan else Finding.objects.none()
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="c-sage-compliance-findings.csv"'
    writer = csv.writer(response)
    writer.writerow(["Rule", "Module", "Account ID", "Account Name", "Region", "Service", "Resource ID", "Status", "Severity", "Title", "Details"])
    for f in qs.iterator(chunk_size=1000):
        writer.writerow([f.rule_id, f.module, f.account_id, f.account_name, f.region, f.service, f.resource_id, f.status, f.severity, f.title, f.details])
    return response
