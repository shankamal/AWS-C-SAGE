import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from django.utils import timezone

from compliance.models import Finding, ResourceInventory, ScanRun
from compliance.storage import store
from .config import AccountResolver
from .inventory import discover_inventory
from .lifecycle import scan_dynamic_lifecycle, scan_lambda_dynamic
from .resource_explorer_inventory import discover_resource_explorer
from .session import session_for
from .scanners import SCANNERS
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
        self.home_region = self.base_session.region_name or os.getenv("AWS_DEFAULT_REGION", "ap-south-1")

    def _regions(self, session, target):
        if target.regions:
            return list(target.regions)
        try:
            ec2 = session.client("ec2", region_name=self.home_region)
            return sorted(r["RegionName"] for r in ec2.describe_regions(AllRegions=False).get("Regions", []))
        except Exception:
            return [self.home_region]

    @staticmethod
    def _identity_keys(item):
        """Return identities that can correlate service, Config, Tagging and Resource Explorer records."""
        keys = []
        arn = str(getattr(item, "resource_arn", "") or "").strip().lower()
        region = str(getattr(item, "region", "") or "global").strip().lower()
        service = str(getattr(item, "service", "") or "aws").strip().lower()
        resource_id = str(getattr(item, "resource_id", "") or "").strip().lower()
        if arn:
            # ARN is globally unique within an account for the same provisioned resource.
            keys.append(("arn", arn))
            arn_tail = arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
            if arn_tail:
                keys.append(("simple", region, service, arn_tail))
        if resource_id:
            keys.append(("simple", region, service, resource_id))
        return keys

    @staticmethod
    def _merge_dict(target, source):
        if not isinstance(target, dict):
            target = {}
        if isinstance(source, dict):
            for key, value in source.items():
                if key not in target or target[key] in (None, "", [], {}):
                    target[key] = value
        return target

    @classmethod
    def _consolidate_inventory(cls, *groups):
        """
        Produce one row per resource while retaining evidence from every discovery source.

        Service-specific API rows are added first and therefore remain canonical. AWS Config,
        Resource Groups Tagging API and Resource Explorer records enrich those rows instead of
        creating duplicate resources. Tags are merged even when the fallback record is smaller.
        """
        merged = []
        identity_map = {}

        for group in groups:
            for item in group:
                existing = None
                for identity in cls._identity_keys(item):
                    if identity in identity_map:
                        existing = identity_map[identity]
                        break

                if existing is None:
                    merged.append(item)
                    for identity in cls._identity_keys(item):
                        identity_map[identity] = item
                    continue

                # Merge common fields without replacing richer service-specific values.
                if not getattr(existing, "resource_name", "") and getattr(item, "resource_name", ""):
                    existing.resource_name = item.resource_name
                if not getattr(existing, "resource_arn", "") and getattr(item, "resource_arn", ""):
                    existing.resource_arn = item.resource_arn
                if not getattr(existing, "status", "") and getattr(item, "status", ""):
                    existing.status = item.status
                if not getattr(existing, "creation_time", "") and getattr(item, "creation_time", ""):
                    existing.creation_time = item.creation_time

                existing.tags = cls._merge_dict(getattr(existing, "tags", {}), getattr(item, "tags", {}))
                existing.networking = cls._merge_dict(getattr(existing, "networking", {}), getattr(item, "networking", {}))
                existing.security = cls._merge_dict(getattr(existing, "security", {}), getattr(item, "security", {}))
                existing.relationships = cls._merge_dict(getattr(existing, "relationships", {}), getattr(item, "relationships", {}))

                incoming_source = str(getattr(item, "discovery_source", "") or "unknown")
                incoming_raw = getattr(item, "raw_attributes", {}) or {}
                existing_raw = getattr(existing, "raw_attributes", {}) or {}
                if isinstance(existing_raw, dict) and incoming_raw:
                    supplemental = existing_raw.setdefault("_supplemental_discovery", {})
                    source_payloads = supplemental.setdefault(incoming_source, [])
                    if incoming_raw not in source_payloads:
                        source_payloads.append(incoming_raw)
                    existing.raw_attributes = existing_raw

                # Config can fill gaps in the normalized configuration while the original raw
                # payload remains preserved under _supplemental_discovery.
                existing.configuration = cls._merge_dict(
                    getattr(existing, "configuration", {}), getattr(item, "configuration", {})
                )

                # Register identities learned from the enrichment record (for example an ARN
                # discovered by Config/Tagging when the service API only returned an ID).
                for identity in cls._identity_keys(existing) + cls._identity_keys(item):
                    identity_map[identity] = existing

        return merged

    def _scan_account(self, target):
        session = session_for(target, self.base_session)
        regions = self._regions(session, target)

        # Master Inventory is independent from compliance findings. It deliberately records
        # zero-resource and access-denied coverage instead of silently omitting services.
        inventory, coverage = discover_inventory(session, target, regions, self.home_region)
        explorer_inventory, explorer_coverage = discover_resource_explorer(session, target, regions)
        inventory = self._consolidate_inventory(inventory, explorer_inventory)
        coverage.extend(explorer_coverage)

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
        return inventory, coverage, findings

    def run(self, initiated_by="system"):
        scan = ScanRun.objects.create(status=ScanRun.Status.RUNNING, initiated_by=initiated_by)
        try:
            targets = AccountResolver(self.base_session).resolve()
            suppressions = SuppressionStore(self.base_session).load()
            all_inventory, all_coverage, all_findings = [], [], []

            with ThreadPoolExecutor(max_workers=min(self.max_workers, max(1, len(targets)))) as pool:
                futures = {pool.submit(self._scan_account, target): target for target in targets}
                for future in as_completed(futures):
                    inv, coverage, findings = future.result()
                    all_inventory.extend(inv)
                    all_coverage.extend(coverage)
                    all_findings.extend(findings)

            inv_rows = [ResourceInventory(scan_run=scan, **i.__dict__) for i in all_inventory]
            ResourceInventory.objects.bulk_create(inv_rows, batch_size=500)

            coverage_rows = []
            for row in all_coverage:
                item = dict(row)
                item["scan_run_id"] = scan.id
                coverage_rows.append(item)
            store.write_inventory_coverage(coverage_rows)

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
