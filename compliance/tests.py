import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from .aws.config import AccountResolver
from .aws.helpers import cidr_is_broad
from .aws.suppressions import SuppressionStore, make_finding_key
from .storage import FlatFileStore


class ComplianceUtilityTests(TestCase):
    def test_finding_key_is_stable(self):
        a = make_finding_key("RULE", "111122223333", "ap-south-1", "resource-1")
        b = make_finding_key("RULE", "111122223333", "ap-south-1", "resource-1")
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_broad_cidr_detection(self):
        self.assertTrue(cidr_is_broad("0.0.0.0/0"))
        self.assertTrue(cidr_is_broad("10.0.0.0/8"))
        self.assertTrue(cidr_is_broad("172.16.0.0/16"))
        self.assertFalse(cidr_is_broad("10.10.10.0/24"))

    def test_flat_file_store_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = FlatFileStore(tmp)
            store.write_json("sample.json", {"value": 1})
            self.assertEqual(store.read_json("sample.json", {}), {"value": 1})
            self.assertTrue((Path(tmp) / "sample.json").exists())

    def test_account_flat_file_parses_assume_role_metadata(self):
        target = AccountResolver._targets({
            "accounts": [{
                "account_id": "111122223333",
                "account_name": "Production",
                "role_arn": "arn:aws:iam::111122223333:role/ComplianceAuditRole",
                "external_id": "external-123",
                "role_session_name": "CSAGEAudit",
                "duration_seconds": 7200,
                "regions": ["ap-south-1", "ap-south-2"],
            }]
        })[0]
        self.assertEqual(target.role_arn, "arn:aws:iam::111122223333:role/ComplianceAuditRole")
        self.assertEqual(target.external_id, "external-123")
        self.assertEqual(target.role_session_name, "CSAGEAudit")
        self.assertEqual(target.duration_seconds, 7200)
        self.assertEqual(target.regions, ("ap-south-1", "ap-south-2"))

    def test_suppression_flat_file_contains_resource_details(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "suppressed_findings.json"
            finding = SimpleNamespace(
                rule_id="CSAGE-SG-003",
                module="Security Groups",
                account_id="111122223333",
                account_name="Production",
                region="ap-south-1",
                service="EC2",
                resource_id="sg-123",
                resource_type="Security Group",
                severity="HIGH",
                title="Broad ingress",
                details="Port 22 open to 0.0.0.0/0",
            )
            key = make_finding_key(finding.rule_id, finding.account_id, finding.region, finding.resource_id)
            with patch.dict(os.environ, {"CSAGE_SUPPRESSION_FILE": str(path)}):
                suppressions = SuppressionStore()
                suppressions.suppress(key, "tester", "Approved RITM1234567", finding=finding)
            payload = json.loads(path.read_text(encoding="utf-8"))
            record = payload["suppressions"][key]
            self.assertTrue(record["suppressed"])
            self.assertEqual(record["resource_id"], "sg-123")
            self.assertEqual(record["reason"], "Approved RITM1234567")
