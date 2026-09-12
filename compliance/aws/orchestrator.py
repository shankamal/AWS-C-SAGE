import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from django.utils import timezone

from compliance.models import Finding, ResourceInventory, ScanRun
from .config import AccountResolver
from .lifecycle import scan_dynamic_lifecycle, scan_lambda_dynamic
from .session import session_for
from .scanners import SCANNERS, scan_inventory
from .suppressions import SuppressionStore, make_finding_key

logger = logging.getLogger(__name__)

# Replace the legacy rule-file EOL scanner and hard-coded Lambda runtime scanner
# with AWS-native lifecycle discovery. All other existing compliance scanners stay unchanged.
ACTIVE_SCANNERS = [
    scanner for scanner in SCANNERS
    if scanner.__name__ not in {"scan_eol", "scan_lambda"}
] + [scan_dynamic_lifecycle, scan_lambda_dynamic]


class ComplianceOrchestrator:
    def __init__(self):
        self.base_session = boto3.Session()
        self.max_workers = int(os.getenv("CSAGE_MAX_WORKERS", "8"))

    def _regions(self, session, target):
        if target.regions:
            return list(target.regions)
        region = self.base_session.region_name or os.getenv("AWS_DEFAULT_REGION", "ap-south-1")
        try:
            ec2 = session.client("ec2", region_name=region)
            return sorted(r["RegionName"] for r in ec2.describe_regions(AllRegions=False).get("Regions", []))
        except Exception:
            return [region]

    def _scan_account(self, target):
        session = session_for(target, self.base_session)
        regions = self._regions(session, target)
        inventory = scan_inventory(session, target, regions)
        findings = []
        for scanner in ACTIVE_SCANNERS:
            try:
                findings.extend(scanner(session, target, regions))
            except Exception as exc:
                logger.exception("Scanner %s failed for %s", scanner.__name__, target.account_id)
                findings.append(type("ErrFinding", (), {
                    "module": scanner.__name__, "rule_id": "CSAGE-SCAN-ERROR", "account_id": target.account_id,
                    "account_name": target.account_name, "region": "global", "service": "Scanner", "resource_id": scanner.__name__,
                    "resource_type": "Scanner Module", "compliant": False, "title": "Scanner execution error", "details": str(exc),
                    "severity": "HIGH", "evidence": {"exception": exc.__class__.__name__}
                })())
        return inventory, findings

    def run(self, initiated_by="system"):
        scan = ScanRun.objects.create(status=ScanRun.Status.RUNNING, initiated_by=initiated_by)
        try:
            targets = AccountResolver(self.base_session).resolve()
            suppressions = SuppressionStore(self.base_session).load()
            all_inventory, all_findings = [], []
            with ThreadPoolExecutor(max_workers=min(self.max_workers, max(1, len(targets)))) as pool:
                futures = {pool.submit(self._scan_account, target): target for target in targets}
                for future in as_completed(futures):
                    inv, findings = future.result()
                    all_inventory.extend(inv)
                    all_findings.extend(findings)

            inv_rows = [ResourceInventory(
                scan_run=scan, account_id=i.account_id, account_name=i.account_name, region=i.region,
                service=i.service, resource_type=i.resource_type, resource_id=i.resource_id,
                resource_arn=i.resource_arn, metadata=i.metadata,
            ) for i in all_inventory]
            ResourceInventory.objects.bulk_create(inv_rows, batch_size=500)

            finding_rows = []
            for f in all_findings:
                key = make_finding_key(f.rule_id, f.account_id, f.region, f.resource_id)
                suppressed = bool(suppressions.get(key, {}).get("suppressed"))
                status = Finding.Status.SUPPRESSED if suppressed and not f.compliant else (Finding.Status.COMPLIANT if f.compliant else Finding.Status.NON_COMPLIANT)
                finding_rows.append(Finding(
                    scan_run=scan, finding_key=key, module=f.module, rule_id=f.rule_id,
                    account_id=f.account_id, account_name=f.account_name, region=f.region, service=f.service,
                    resource_id=f.resource_id, resource_type=f.resource_type, status=status, severity=f.severity,
                    title=f.title, details=f.details, evidence=f.evidence,
                ))
            Finding.objects.bulk_create(finding_rows, batch_size=500)

            scan.account_count = len(targets)
            scan.resource_count = len(inv_rows)
            scan.compliant_count = sum(1 for f in finding_rows if f.status == Finding.Status.COMPLIANT)
            scan.non_compliant_count = sum(1 for f in finding_rows if f.status == Finding.Status.NON_COMPLIANT)
            scan.suppressed_count = sum(1 for f in finding_rows if f.status == Finding.Status.SUPPRESSED)
            scan.status = ScanRun.Status.COMPLETED
            scan.completed_at = timezone.now()
            scan.save()
            return scan
        except Exception as exc:
            logger.exception("C-SAGE scan failed")
            scan.status = ScanRun.Status.FAILED
            scan.error_message = str(exc)
            scan.completed_at = timezone.now()
            scan.save(update_fields=["status", "error_message", "completed_at"])
            raise
