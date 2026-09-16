from types import SimpleNamespace

from django.test import SimpleTestCase

from .aws.security_group_inventory import discover_security_group_rule_inventory


class _Paginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kwargs):
        return iter(self.pages)


class _EC2Client:
    def __init__(self):
        self.pages = {
            "describe_security_groups": [{
                "SecurityGroups": [{
                    "GroupId": "sg-0123456789abcdef0",
                    "GroupName": "web-prod-sg",
                    "VpcId": "vpc-0123456789abcdef0",
                    "Description": "Production web security group",
                }]
            }],
            "describe_security_group_rules": [{
                "SecurityGroupRules": [
                    {
                        "SecurityGroupRuleId": "sgr-00000000000000001",
                        "GroupId": "sg-0123456789abcdef0",
                        "GroupOwnerId": "111122223333",
                        "IsEgress": False,
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "CidrIpv4": "10.0.0.0/8",
                        "Description": "HTTPS from corporate network",
                        "Tags": [{"Key": "ManagedBy", "Value": "C-SAGE"}],
                    },
                    {
                        "SecurityGroupRuleId": "sgr-00000000000000002",
                        "GroupId": "sg-0123456789abcdef0",
                        "GroupOwnerId": "111122223333",
                        "IsEgress": True,
                        "IpProtocol": "-1",
                        "ReferencedGroupInfo": {
                            "GroupId": "sg-0fedcba9876543210",
                            "UserId": "111122223333",
                        },
                        "Description": "All traffic to application SG",
                    },
                ]
            }],
        }

    def can_paginate(self, operation):
        return True

    def get_paginator(self, operation):
        return _Paginator(self.pages[operation])


class _Session:
    def __init__(self):
        self.ec2 = _EC2Client()

    def client(self, service, region_name=None):
        if service != "ec2":
            raise AssertionError(f"Unexpected service: {service}")
        return self.ec2


class SecurityGroupRuleInventoryTests(SimpleTestCase):
    def test_inventory_contains_one_row_per_security_group_rule(self):
        target = SimpleNamespace(
            account_id="111122223333",
            account_name="Production",
            role_arn="arn:aws:iam::111122223333:role/ComplianceAuditRole",
        )

        rows, coverage = discover_security_group_rule_inventory(
            _Session(), target, ["ap-south-1"]
        )

        self.assertEqual(len(rows), 2)
        self.assertEqual(len(coverage), 1)
        self.assertEqual(coverage[0]["resource_type"], "Security Group Rule")
        self.assertEqual(coverage[0]["resource_count"], 2)
        self.assertEqual(coverage[0]["scan_status"], "COMPLETE")

        ingress = next(row for row in rows if row.resource_id == "sgr-00000000000000001")
        self.assertEqual(ingress.service, "EC2")
        self.assertEqual(ingress.resource_type, "Security Group Rule")
        self.assertEqual(ingress.status, "INGRESS")
        self.assertEqual(ingress.security["PortRange"], "443")
        self.assertEqual(ingress.security["SourceOrDestination"], "10.0.0.0/8")
        self.assertEqual(ingress.relationships["SecurityGroupName"], "web-prod-sg")
        self.assertEqual(ingress.relationships["VpcId"], "vpc-0123456789abcdef0")
        self.assertEqual(ingress.tags["ManagedBy"], "C-SAGE")
        self.assertIn("Ingress TCP 443", ingress.resource_name)
        self.assertEqual(
            ingress.resource_arn,
            "arn:aws:ec2:ap-south-1:111122223333:security-group-rule/sgr-00000000000000001",
        )

        egress = next(row for row in rows if row.resource_id == "sgr-00000000000000002")
        self.assertEqual(egress.status, "EGRESS")
        self.assertEqual(egress.security["PortRange"], "All")
        self.assertEqual(
            egress.security["SourceOrDestination"],
            "sg-0fedcba9876543210 (111122223333)",
        )
        self.assertEqual(
            egress.relationships["ReferencedGroupInfo"]["GroupId"],
            "sg-0fedcba9876543210",
        )
