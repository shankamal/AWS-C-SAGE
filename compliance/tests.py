import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from .aws.config import AccountResolver
from .aws.helpers import cidr_is_broad
from .aws.orchestrator import ComplianceOrchestrator
from .aws.suppressions import SuppressionStore, make_finding_key
from .aws.types import InventoryData
from .models import ResourceInventory
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

    def test_inventory_coverage_round_trip_including_zero_resources(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = FlatFileStore(tmp)
            rows = [{
                "scan_run_id": "scan-1",
                "account_id": "111122223333",
                "account_name": "Production",
                "region": "ap-south-1",
                "service": "Redshift",
                "resource_type": "Redshift Cluster",
                "resource_count": 0,
                "scan_status": "COMPLETE",
                "message": "",
                "source": "service-api",
            }]
            store.write_inventory_coverage(rows)
            payload = store.read_inventory_coverage()
            self.assertEqual(payload, rows)
            self.assertEqual(payload[0]["resource_count"], 0)
            self.assertEqual(payload[0]["scan_status"], "COMPLETE")

    def test_rich_inventory_resource_serializes_all_sections(self):
        resource = ResourceInventory(
            scan_run_id="scan-1",
            account_id="111122223333",
            account_name="Production",
            region="ap-south-1",
            service="EC2",
            resource_type="EC2 Instance",
            resource_name="web-01",
            resource_id="i-0123456789abcdef0",
            resource_arn="arn:aws:ec2:ap-south-1:111122223333:instance/i-0123456789abcdef0",
            status="running",
            creation_time="2026-09-12T10:00:00+00:00",
            tags={"Name": "web-01", "Environment": "Production"},
            configuration={"InstanceType": "m6i.large"},
            networking={"VpcId": "vpc-123", "SubnetId": "subnet-123"},
            security={"SecurityGroups": [{"GroupId": "sg-123"}]},
            relationships={"BlockDeviceMappings": [{"DeviceName": "/dev/xvda"}]},
            raw_attributes={"InstanceId": "i-0123456789abcdef0", "Architecture": "x86_64"},
            discovery_source="service-api",
        )
        row = resource.to_dict()
        self.assertEqual(row["resource_name"], "web-01")
        self.assertEqual(row["tags"]["Environment"], "Production")
        self.assertEqual(row["configuration"]["InstanceType"], "m6i.large")
        self.assertEqual(row["networking"]["VpcId"], "vpc-123")
        self.assertEqual(row["security"]["SecurityGroups"][0]["GroupId"], "sg-123")
        self.assertEqual(row["raw_attributes"]["Architecture"], "x86_64")
        self.assertEqual(len(row["resource_key"]), 64)

    def test_inventory_consolidation_merges_tagging_fallback(self):
        arn = "arn:aws:ec2:ap-south-1:111122223333:volume/vol-123"
        service_row = InventoryData(
            account_id="111122223333",
            account_name="Production",
            region="ap-south-1",
            service="EC2",
            resource_type="EBS Volume",
            resource_id="vol-123",
            resource_arn=arn,
            status="in-use",
            configuration={"VolumeId": "vol-123", "Size": 100},
            raw_attributes={"VolumeId": "vol-123", "Size": 100},
            discovery_source="service-api",
        )
        tagging_row = InventoryData(
            account_id="111122223333",
            account_name="Production",
            region="ap-south-1",
            service="EC2",
            resource_type="Tagged AWS Resource",
            resource_id="vol-123",
            resource_arn=arn,
            tags={"Name": "data-volume", "Application": "Payments"},
            configuration={"ResourceARN": arn},
            raw_attributes={"ResourceARN": arn, "Tags": [{"Key": "Application", "Value": "Payments"}]},
            discovery_source="resource-groups-tagging-api",
        )
        result = ComplianceOrchestrator._consolidate_inventory([service_row, tagging_row])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].resource_type, "EBS Volume")
        self.assertEqual(result[0].tags["Application"], "Payments")
        self.assertIn("_supplemental_discovery", result[0].raw_attributes)

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
