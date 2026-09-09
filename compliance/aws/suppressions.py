import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from compliance.storage import store


def make_finding_key(rule_id: str, account_id: str, region: str, resource_id: str) -> str:
    raw = "|".join([rule_id or "", account_id or "", region or "", resource_id or ""])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class SuppressionStore:
    """Persist resource suppression details as an auditable JSON flat file.

    No S3 dependency is used. By default the file is
    /data/suppressed_findings.json on the container, backed by the EC2 host
    bind mount.
    """

    def __init__(self, session=None):
        configured = os.getenv("CSAGE_SUPPRESSION_FILE", "").strip()
        self.path = Path(configured) if configured else store.path("suppressed_findings.json")
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def configured(self):
        return True

    def load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            return payload.get("suppressions", payload) if isinstance(payload, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def save(self, data: dict):
        payload = {"version": 2, "suppressions": data}
        if self.path.parent.resolve() == store.data_dir.resolve():
            store.write_json(self.path.name, payload)
            return
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        with temp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, default=str)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, self.path)

    def suppress(self, finding_key: str, actor: str, reason: str = "", finding=None):
        data = self.load()
        now = datetime.now(timezone.utc).isoformat()
        existing = data.get(finding_key, {})
        record = {
            **existing,
            "suppressed": True,
            "actor": actor,
            "reason": reason,
            "updated_at": now,
            "suppressed_at": existing.get("suppressed_at") or now,
        }
        if finding is not None:
            record.update({
                "finding_key": finding_key,
                "rule_id": getattr(finding, "rule_id", ""),
                "module": getattr(finding, "module", ""),
                "account_id": getattr(finding, "account_id", ""),
                "account_name": getattr(finding, "account_name", ""),
                "region": getattr(finding, "region", ""),
                "service": getattr(finding, "service", ""),
                "resource_id": getattr(finding, "resource_id", ""),
                "resource_type": getattr(finding, "resource_type", ""),
                "severity": getattr(finding, "severity", ""),
                "title": getattr(finding, "title", ""),
                "details": getattr(finding, "details", ""),
            })
        data[finding_key] = record
        self.save(data)

    def unsuppress(self, finding_key: str, actor: str):
        data = self.load()
        if finding_key in data:
            data[finding_key]["suppressed"] = False
            data[finding_key]["actor"] = actor
            data[finding_key]["updated_at"] = datetime.now(timezone.utc).isoformat()
            data[finding_key]["unsuppressed_at"] = datetime.now(timezone.utc).isoformat()
        self.save(data)
