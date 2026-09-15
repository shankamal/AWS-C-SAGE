from datetime import datetime, timezone

from .storage import store


POLICY_CONFIG_FILE = "policy_config.json"


class PolicyConfigStore:
    """Persist enabled/disabled C-SAGE policy state in the flat-file data directory."""

    def __init__(self, backing_store=None):
        self.store = backing_store or store

    def read(self):
        payload = self.store.read_json(POLICY_CONFIG_FILE, {"version": 1, "policies": {}})
        if not isinstance(payload, dict):
            payload = {"version": 1, "policies": {}}
        policies = payload.get("policies")
        if not isinstance(policies, dict):
            policies = {}
        return {"version": 1, "policies": policies}

    def disabled_rule_ids(self):
        payload = self.read()
        return {
            rule_id
            for rule_id, item in payload["policies"].items()
            if isinstance(item, dict) and item.get("enabled", True) is False
        }

    def remember_findings(self, findings):
        payload = self.read()
        policies = payload["policies"]
        now = datetime.now(timezone.utc).isoformat()
        changed = False
        for finding in findings:
            rule_id = str(getattr(finding, "rule_id", "") or "").strip()
            if not rule_id or rule_id == "CSAGE-SCAN-ERROR":
                continue
            current = policies.get(rule_id, {}) if isinstance(policies.get(rule_id), dict) else {}
            updated = {
                "enabled": current.get("enabled", True),
                "rule_id": rule_id,
                "module": str(getattr(finding, "module", "") or current.get("module", "")),
                "title": str(getattr(finding, "title", "") or current.get("title", "")),
                "service": str(getattr(finding, "service", "") or current.get("service", "")),
                "severity": str(getattr(finding, "severity", "") or current.get("severity", "")),
                "last_seen": now,
            }
            if updated != current:
                policies[rule_id] = updated
                changed = True
        if changed:
            self.store.write_json(POLICY_CONFIG_FILE, payload)

    def set_enabled(self, rule_id, enabled, metadata=None):
        rule_id = str(rule_id or "").strip()
        if not rule_id:
            raise ValueError("Rule ID is required")
        payload = self.read()
        policies = payload["policies"]
        current = policies.get(rule_id, {}) if isinstance(policies.get(rule_id), dict) else {}
        metadata = metadata or {}
        current.update({
            "rule_id": rule_id,
            "enabled": bool(enabled),
            "module": metadata.get("module", current.get("module", "")),
            "title": metadata.get("title", current.get("title", "")),
            "service": metadata.get("service", current.get("service", "")),
            "severity": metadata.get("severity", current.get("severity", "")),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        policies[rule_id] = current
        self.store.write_json(POLICY_CONFIG_FILE, payload)

    def catalog(self):
        payload = self.read()
        rows = list(payload["policies"].values())
        rows.sort(key=lambda item: (str(item.get("module", "")).lower(), str(item.get("rule_id", "")).lower()))
        return rows
