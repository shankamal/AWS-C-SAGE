import json
import os
import tempfile
from contextlib import contextmanager
from datetime import date, datetime
from pathlib import Path

import fcntl


class FlatFileStore:
    """Atomic JSON flat-file persistence for the single-host C-SAGE deployment."""

    def __init__(self, data_dir=None):
        self.data_dir = Path(data_dir or os.getenv("CSAGE_DATA_DIR", "/data"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.lock_path = self.data_dir / ".csage.lock"

    @contextmanager
    def locked(self):
        self.lock_path.touch(exist_ok=True)
        with self.lock_path.open("r+") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _json_default(value):
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        return str(value)

    def path(self, filename):
        return self.data_dir / filename

    def read_json(self, filename, default):
        path = self.path(filename)
        if not path.exists():
            return default
        try:
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError):
            return default

    def write_json(self, filename, payload):
        path = self.path(filename)
        with self.locked():
            fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(self.data_dir))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2, default=self._json_default)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_name, path)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)

    def scan_history(self):
        payload = self.read_json("scan_runs.json", {"scan_runs": []})
        return payload.get("scan_runs", []) if isinstance(payload, dict) else []

    def upsert_scan(self, scan):
        history = self.scan_history()
        record = dict(scan)
        replaced = False
        for index, item in enumerate(history):
            if item.get("id") == record.get("id"):
                history[index] = record
                replaced = True
                break
        if not replaced:
            history.append(record)
        history.sort(key=lambda item: item.get("started_at", ""), reverse=True)
        limit = max(1, int(os.getenv("CSAGE_SCAN_HISTORY_LIMIT", "50")))
        self.write_json("scan_runs.json", {"version": 1, "scan_runs": history[:limit]})

    def write_findings(self, rows):
        self.write_json("findings.json", {"version": 1, "findings": rows})

    def read_findings(self):
        payload = self.read_json("findings.json", {"findings": []})
        return payload.get("findings", []) if isinstance(payload, dict) else []

    def write_inventory(self, rows):
        self.write_json("inventory.json", {"version": 1, "inventory": rows})

    def read_inventory(self):
        payload = self.read_json("inventory.json", {"inventory": []})
        return payload.get("inventory", []) if isinstance(payload, dict) else []


store = FlatFileStore()
