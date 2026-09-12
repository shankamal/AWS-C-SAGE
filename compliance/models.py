from datetime import datetime, timezone
import uuid

from .storage import store


def _parse_datetime(value):
    if isinstance(value, datetime) or value is None:
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


class ScanRun:
    class Status:
        RUNNING = "RUNNING"
        COMPLETED = "COMPLETED"
        FAILED = "FAILED"

    def __init__(self, id=None, started_at=None, completed_at=None, status="RUNNING", initiated_by="", account_count=0,
                 resource_count=0, compliant_count=0, non_compliant_count=0, suppressed_count=0, error_message=""):
        self.id = id or f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
        self.started_at = _parse_datetime(started_at) or datetime.now(timezone.utc)
        self.completed_at = _parse_datetime(completed_at)
        self.status = status
        self.initiated_by = initiated_by
        self.account_count = int(account_count or 0)
        self.resource_count = int(resource_count or 0)
        self.compliant_count = int(compliant_count or 0)
        self.non_compliant_count = int(non_compliant_count or 0)
        self.suppressed_count = int(suppressed_count or 0)
        self.error_message = error_message or ""

    def to_dict(self):
        return {
            "id": self.id,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "initiated_by": self.initiated_by,
            "account_count": self.account_count,
            "resource_count": self.resource_count,
            "compliant_count": self.compliant_count,
            "non_compliant_count": self.non_compliant_count,
            "suppressed_count": self.suppressed_count,
            "error_message": self.error_message,
        }

    def save(self, update_fields=None):
        store.upsert_scan(self.to_dict())


class ScanRunManager:
    def create(self, **kwargs):
        scan = ScanRun(**kwargs)
        scan.save()
        return scan

    def first(self):
        history = store.scan_history()
        return ScanRun(**history[0]) if history else None


ScanRun.objects = ScanRunManager()


class Finding:
    class Status:
        COMPLIANT = "COMPLIANT"
        NON_COMPLIANT = "NON_COMPLIANT"
        SUPPRESSED = "SUPPRESSED"
        ERROR = "ERROR"

    def __init__(self, scan_run=None, scan_run_id=None, id=None, finding_key="", module="", rule_id="", account_id="",
                 account_name="", region="", service="", resource_id="", resource_type="", status="COMPLIANT",
                 severity="MEDIUM", title="", details="", evidence=None, detected_at=None):
        self.scan_run = scan_run
        self.scan_run_id = scan_run_id or getattr(scan_run, "id", "")
        self.finding_key = finding_key
        self.id = id or finding_key
        self.module = module
        self.rule_id = rule_id
        self.account_id = account_id
        self.account_name = account_name
        self.region = region
        self.service = service
        self.resource_id = resource_id
        self.resource_type = resource_type
        self.status = status
        self.severity = severity
        self.title = title
        self.details = details
        self.evidence = evidence or {}
        self.detected_at = _parse_datetime(detected_at) or datetime.now(timezone.utc)

    def get_status_display(self):
        return {
            self.Status.COMPLIANT: "Compliant",
            self.Status.NON_COMPLIANT: "Non-Compliant",
            self.Status.SUPPRESSED: "Suppressed",
            self.Status.ERROR: "Error",
        }.get(self.status, self.status)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_run_id": self.scan_run_id,
            "finding_key": self.finding_key,
            "module": self.module,
            "rule_id": self.rule_id,
            "account_id": self.account_id,
            "account_name": self.account_name,
            "region": self.region,
            "service": self.service,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "status": self.status,
            "severity": self.severity,
            "title": self.title,
            "details": self.details,
            "evidence": self.evidence,
            "detected_at": self.detected_at.isoformat(),
        }

    def save(self, update_fields=None):
        rows = store.read_findings()
        replaced = False
        for index, row in enumerate(rows):
            if row.get("id") == self.id:
                rows[index] = self.to_dict()
                replaced = True
                break
        if not replaced:
            rows.append(self.to_dict())
        store.write_findings(rows)


class FindingManager:
    def bulk_create(self, rows, batch_size=None):
        store.write_findings([row.to_dict() for row in rows])
        return rows

    def for_scan(self, scan):
        if not scan:
            return []
        return [Finding(scan_run=scan, **row) for row in store.read_findings() if row.get("scan_run_id") == scan.id]

    def all_latest(self):
        scan = ScanRun.objects.first()
        return self.for_scan(scan)


Finding.objects = FindingManager()


class ResourceInventory:
    def __init__(self, scan_run=None, scan_run_id=None, account_id="", account_name="", region="", service="",
                 resource_type="", resource_id="", resource_arn="", metadata=None):
        self.scan_run = scan_run
        self.scan_run_id = scan_run_id or getattr(scan_run, "id", "")
        self.account_id = account_id
        self.account_name = account_name
        self.region = region
        self.service = service
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.resource_arn = resource_arn
        self.metadata = metadata or {}

    def to_dict(self):
        return {
            "scan_run_id": self.scan_run_id,
            "account_id": self.account_id,
            "account_name": self.account_name,
            "region": self.region,
            "service": self.service,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_arn": self.resource_arn,
            "metadata": self.metadata,
        }


class ResourceInventoryManager:
    def bulk_create(self, rows, batch_size=None):
        store.write_inventory([row.to_dict() for row in rows])
        return rows

    def for_scan(self, scan):
        if not scan:
            return []
        return [ResourceInventory(scan_run=scan, **row) for row in store.read_inventory() if row.get("scan_run_id") == scan.id]


ResourceInventory.objects = ResourceInventoryManager()


class _InactiveLifecycleRuleManager:
    """Compatibility only for the legacy scanner module; no lifecycle data is stored or loaded locally."""

    def filter(self, active=True):
        return []


class LifecycleRule:
    objects = _InactiveLifecycleRuleManager()
