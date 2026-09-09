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
    """Persist finding suppressions as an auditable JSON flat file on the EC2 host volume."""

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
        payload = {"version": 1, "suppressions": data}
        if self.path.parent.resolve() == store.data_dir.resolve():
            store.write_json(self.path.name, payload)
            return
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        with temp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, default=str)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, self.path)

    def suppress(self, finding_key: str, actor: str, reason: str = ""):
        data = self.load()
        data[finding_key] = {
            "suppressed": True,
            "actor": actor,
            "reason": reason,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self.save(data)

    def unsuppress(self, finding_key: str, actor: str):
        data = self.load()
        if finding_key in data:
            data[finding_key]["suppressed"] = False
            data[finding_key]["actor"] = actor
            data[finding_key]["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.save(data)
