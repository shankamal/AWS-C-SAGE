from .models import Finding, ScanRun
from django.shortcuts import render


def _latest():
    return ScanRun.objects.first()


def _matches_keyword(finding, keyword):
    return any(
        keyword in str(value or "").lower()
        for value in (
            finding.resource_id,
            finding.title,
            finding.rule_id,
            finding.details,
            finding.module,
            finding.service,
            finding.account_name,
            finding.account_id,
        )
    )


def _compliance_posture(rows):
    compliant = sum(1 for finding in rows if finding.status == Finding.Status.COMPLIANT)
    non_compliant = sum(1 for finding in rows if finding.status == Finding.Status.NON_COMPLIANT)
    suppressed = sum(1 for finding in rows if finding.status == Finding.Status.SUPPRESSED)
    total = compliant + non_compliant + suppressed

    if total:
        compliant_pct = round((compliant / total) * 100, 1)
        non_compliant_pct = round((non_compliant / total) * 100, 1)
        suppressed_pct = round((suppressed / total) * 100, 1)
    else:
        compliant_pct = non_compliant_pct = suppressed_pct = 0

    return {
        "compliant": compliant,
        "non_compliant": non_compliant,
        "suppressed": suppressed,
        "total": total,
        "compliant_pct": compliant_pct,
        "non_compliant_pct": non_compliant_pct,
        "suppressed_pct": suppressed_pct,
        "non_compliant_end": round(compliant_pct + non_compliant_pct, 1),
        "score": compliant_pct,
    }


def findings_view(request):
    scan = _latest()
    base = Finding.objects.for_scan(scan)

    account = request.GET.get("account", "")
    module = request.GET.get("module", "")
    policy = request.GET.get("policy", "")
    status = request.GET.get("status", "")
    raw_keyword = request.GET.get("q", "")
    keyword = raw_keyword.strip().lower()

    # Build the score scope from business filters. The Status filter is intentionally
    # applied only to the table so that selecting NON-COMPLIANT does not turn a policy's
    # compliance score into 0%. The pie always represents the full posture of the
    # selected account/module/policy/search scope.
    score_findings = base
    if account:
        score_findings = [finding for finding in score_findings if finding.account_id == account]
    if module:
        score_findings = [finding for finding in score_findings if finding.module == module]
    if policy:
        score_findings = [finding for finding in score_findings if finding.rule_id == policy]
    if keyword:
        score_findings = [finding for finding in score_findings if _matches_keyword(finding, keyword)]

    findings = score_findings
    if status:
        findings = [finding for finding in findings if finding.status == status]

    accounts = sorted({(finding.account_id, finding.account_name) for finding in base}, key=lambda item: item[1])
    module_names = sorted({finding.module for finding in base})

    policy_map = {}
    for finding in base:
        if not finding.rule_id:
            continue
        policy_map.setdefault(finding.rule_id, {
            "rule_id": finding.rule_id,
            "title": finding.title or finding.rule_id,
            "module": finding.module,
        })
    policies = sorted(policy_map.values(), key=lambda item: (item["module"].lower(), item["rule_id"].lower()))

    ctx = {
        "scan": scan,
        "findings": findings[:1000],
        "filtered_count": len(findings),
        "score_scope_count": len(score_findings),
        "accounts": accounts,
        "module_names": module_names,
        "policies": policies,
        "posture": _compliance_posture(score_findings),
        "filters": {
            "account": account,
            "module": module,
            "policy": policy,
            "status": status,
            "q": raw_keyword,
        },
    }
    return render(request, "compliance/findings.html", ctx)
