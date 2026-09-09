import tempfile
from pathlib import Path
from unittest import TestCase

from .aws.helpers import cidr_is_broad
from .aws.suppressions import make_finding_key
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
