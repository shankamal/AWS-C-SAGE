import tempfile
from types import SimpleNamespace
from unittest import TestCase

from .policy_config import PolicyConfigStore
from .storage import FlatFileStore


class PolicyConfigStoreTests(TestCase):
    def test_policy_catalog_and_enablement_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = FlatFileStore(tmp)
            policies = PolicyConfigStore(store)
            findings = [
                SimpleNamespace(
                    rule_id="CSAGE-TEST-001",
                    module="Test Module",
                    title="Test control",
                    service="EC2",
                    severity="HIGH",
                ),
                SimpleNamespace(
                    rule_id="CSAGE-TEST-002",
                    module="Test Module",
                    title="Second control",
                    service="S3",
                    severity="MEDIUM",
                ),
            ]
            policies.remember_findings(findings)
            self.assertEqual(len(policies.catalog()), 2)
            self.assertEqual(policies.disabled_rule_ids(), set())

            policies.set_enabled("CSAGE-TEST-001", False)
            self.assertEqual(policies.disabled_rule_ids(), {"CSAGE-TEST-001"})
            first = next(item for item in policies.catalog() if item["rule_id"] == "CSAGE-TEST-001")
            self.assertFalse(first["enabled"])

            policies.set_enabled("CSAGE-TEST-001", True)
            self.assertEqual(policies.disabled_rule_ids(), set())

    def test_scanner_error_is_not_added_to_policy_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = FlatFileStore(tmp)
            policies = PolicyConfigStore(store)
            policies.remember_findings([
                SimpleNamespace(
                    rule_id="CSAGE-SCAN-ERROR",
                    module="scan_example",
                    title="Scanner execution error",
                    service="Scanner",
                    severity="HIGH",
                )
            ])
            self.assertEqual(policies.catalog(), [])
