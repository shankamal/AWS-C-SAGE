# C-SAGE

**Cloud Security, Audit, Governance & Enforcement**

C-SAGE is an AWS multi-account cloud compliance and governance application built with Django and Boto3. It provides complete-inventory discovery, compliance findings, suppression workflows, lifecycle evidence, and exportable audit evidence through an ICICI Bank-aligned enterprise UI.

## Key capabilities

- Local flat-file AWS multi-account configuration with STS `AssumeRole`
- Optional AssumeRole External ID, session name, duration, and per-account regions
- Fallback to the EC2 instance profile / default AWS credential chain for the current account
- Concurrent account scans with regional and global AWS discovery
- **Master Inventory** with resource-level browse, search, filters, drill-down, JSON export and individual Excel export
- Layered inventory discovery using service-native AWS APIs, AWS Config, Resource Groups Tagging API and AWS Resource Explorer 2
- Explicit inventory coverage evidence, including zero-resource service/type checks and access-denied/unavailable/error states
- Raw AWS API attributes retained with normalized resource identity, status, creation time, tags, configuration, networking, security and dependencies
- Formatted full-workbook Excel export with Inventory Summary, Master Inventory, Service Coverage and flattened Resource Attributes sheets
- 11 compliance audit modules covering lifecycle, certificates, IAM keys, encryption, backup, S3, Lambda, security groups, KMS and notification domains
- AWS-native lifecycle discovery: EKS support dates from EKS APIs, RDS support dates from RDS APIs, and lifecycle/deprecation notices from AWS Health
- No maintained EOL/EOS rule file and no hard-coded deprecated Lambda runtime list
- Database-free runtime: no SQLite, PostgreSQL, RDS, migrations or Django DB sessions
- JSON flat-file persistence under `/data`
- Detailed flat-file resource suppressions with actor, reason, account, region, service, resource, rule and timestamps
- ICICI Bank-aligned enterprise UI with accessibility controls
- Single Docker container using Gunicorn

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Compliance Control Catalog](docs/CONTROL_CATALOG.md)
- [Deployment Guide](docs/DEPLOYMENT.md)

## Runtime data files

By default C-SAGE stores state in `/data` inside the container. Mount that directory from the EC2 host.

```text
/data/accounts.json
/data/scan_runs.json
/data/findings.json
/data/inventory.json
/data/inventory_coverage.json
/data/suppressed_findings.json
```

`inventory.json` contains the latest resource-level Master Inventory snapshot. `inventory_coverage.json` records what C-SAGE attempted to discover for every account/Region/service/resource type, including successful checks returning zero resources and checks that failed because of permissions or API availability.

There is no S3 dependency for application configuration or suppression persistence, and lifecycle dates are not maintained locally.

## Complete AWS Master Inventory

The **Master Inventory** tab is populated during every audit scan.

C-SAGE uses a layered discovery strategy because AWS does not provide one API that returns every provisioned resource with every service-specific attribute:

1. **Service-native APIs** — explicit paginated collectors for the major infrastructure, networking, compute, container, database, storage, security, integration, analytics, management and global services.
2. **AWS Config** — Advanced Query plus `BatchGetResourceConfig` broadens coverage and supplies configuration for supported resource types when Config is available.
3. **Resource Groups Tagging API** — supplies broad tagged-resource discovery and tag enrichment.
4. **AWS Resource Explorer 2** — dynamically discovers additional supported AWS resource types and services not explicitly modelled by a service collector. Supported service coverage is recorded even when the resource count is zero.

The service-native collectors include, among others:

- EC2 instances, EBS volumes/snapshots, AMIs, VPCs, subnets, route tables, IGWs, NAT gateways, transit gateways, endpoints, security groups, NACLs, EIPs, launch templates, VPN and Client VPN
- ALB/NLB/GWLB, Classic ELB, target groups and Auto Scaling groups
- Lambda, API Gateway, ECS clusters/services/tasks/Fargate, EKS clusters/node groups/Fargate profiles
- CloudFormation and Systems Manager resources
- RDS databases, Aurora/DB clusters, DynamoDB, ElastiCache, Redshift, OpenSearch and MemoryDB
- S3, EFS, FSx, Backup vaults and recovery points
- IAM users/roles/groups/customer-managed policies, KMS keys, Secrets Manager metadata and ACM certificates
- Route 53, CloudFront, CloudWatch alarms/log groups, EventBridge, SNS, SQS and Step Functions
- Glue, EMR and SageMaker
- Organizations, Control Tower, Direct Connect, WAF and Shield
- ECR, MSK, Amazon MQ, DMS, Transfer Family, Network Firewall, AppSync, CloudTrail and additional Resource Explorer-supported types

For each discovered resource C-SAGE retains, when AWS exposes it:

- Resource name, ID and ARN
- Account ID/name and Region/global scope
- AWS service and resource type
- Status and creation/last-reported time
- Tags
- Configuration details
- Networking details
- Security/encryption/IAM details
- Attached/dependent resources and relationships
- Raw API-returned attributes used during discovery
- Discovery source and deterministic resource key

### Empty services are retained

C-SAGE does **not** treat a missing row as proof that a service is empty. Every collector writes a separate coverage record with one of these states:

- `COMPLETE` with `resource_count=0` — AWS was queried successfully and returned no resources
- `COMPLETE` with a positive count — resources were found
- `ACCESS_DENIED` — the role could not query the service
- `UNAVAILABLE` — the API/resource type is not available in that account/Region or the broad-discovery source is not configured
- `ERROR` — another API failure occurred

The Master Inventory UI and the Excel **Service Coverage** sheet make these states visible to auditors and platform engineers.

### Inventory exports

The Master Inventory supports:

- filtered CSV export
- formatted full Excel export
- individual resource Excel export
- individual resource JSON export
- browser drill-down showing tags, networking, security, relationships, normalized configuration and raw AWS API attributes

The full Excel workbook contains:

1. `Inventory Summary`
2. `Master Inventory`
3. `Service Coverage`
4. one or more `Resource Attributes` sheets containing flattened attribute path/value rows so nested API payloads are retained without summarization

Deleted-resource information is included only when an AWS API still exposes that metadata. C-SAGE does not synthesize deleted resources.

## Quick start on Linux / EC2

```bash
git clone https://github.com/shankamal/AWS-C-SAGE.git
cd AWS-C-SAGE
cp .env.example .env
mkdir -p data
cp accounts.example.json data/accounts.json

docker build -t c-sage:latest .

docker run -d \
  --name c-sage \
  --restart unless-stopped \
  -p 8000:8000 \
  --env-file .env \
  -v "$(pwd)/data:/data" \
  c-sage:latest
```

Open `http://<EC2-IP>:8000`. C-SAGE uses HTTP Basic authentication configured through `CSAGE_AUTH_USERNAME` and `CSAGE_AUTH_PASSWORD`. `/healthz/` is unauthenticated for health checks.

## AWS account and AssumeRole configuration

C-SAGE reads cross-account configuration only from the flat file defined by `CSAGE_ACCOUNTS_FILE` (default `/data/accounts.json`).

Example:

```json
{
  "accounts": [
    {
      "account_id": "111122223333",
      "account_name": "Production",
      "role_arn": "arn:aws:iam::111122223333:role/ComplianceAuditRole",
      "external_id": "",
      "role_session_name": "CSAGEComplianceAudit",
      "duration_seconds": 3600,
      "regions": ["ap-south-1", "ap-south-2"]
    }
  ]
}
```

If the file is missing, empty or unreadable, C-SAGE falls back to the EC2 instance profile/default Boto3 credential chain and audits the current AWS account.

## Cross-account inventory permissions

The EC2 `CSAGEApplicationRole` needs only permission to assume the approved target `ComplianceAuditRole` roles. Each target account's `ComplianceAuditRole` requires the read/list/describe permissions in:

```text
iam/ComplianceAuditRolePolicy.json
```

That policy intentionally does not grant secret-value retrieval such as `secretsmanager:GetSecretValue`; inventory captures secret metadata, not secret contents.

Some global/control-plane APIs such as Organizations and Control Tower are meaningful only from accounts that are authorized to call them. C-SAGE records `ACCESS_DENIED` or `UNAVAILABLE` coverage rather than reporting those services as empty.

AWS Resource Explorer broad coverage depends on Resource Explorer indexes/views being available in the account/Region. AWS Config enrichment depends on AWS Config coverage. If either source is unavailable, the service-native collectors still run and the limitation appears in `inventory_coverage.json` and the Master Inventory Coverage table.

## Resource suppressions

Suppressions are persisted only in the flat file defined by `CSAGE_SUPPRESSION_FILE` (default `/data/suppressed_findings.json`). Suppressed findings remain visible but are excluded from the open non-compliant count.

## Lifecycle / EOL / EOS discovery

C-SAGE does not maintain lifecycle dates in a local file.

The scanner obtains lifecycle information from AWS itself:

- **Amazon EKS**: `DescribeClusterVersions` provides version status plus end-of-standard-support and end-of-extended-support dates.
- **Amazon RDS / Aurora open-source engines**: `DescribeDBMajorEngineVersions` provides supported lifecycle periods and support end dates.
- **AWS Health**: scheduled-change events are queried for AWS-published deprecation, retirement, version, runtime, upgrade and end-of-support notices affecting account resources.
- **AWS Lambda runtime lifecycle**: no hard-coded deprecated runtime list is maintained. C-SAGE relies on AWS Health notices for runtime deprecation/EOS while continuing to enforce Lambda VPC compliance directly from the Lambda API.

`CSAGE_EOL_WARNING_DAYS` controls how far ahead C-SAGE flags an AWS-published support deadline; it does not contain lifecycle dates or versions.

## Security notes

- Attach a dedicated IAM role to the EC2 instance.
- Allow that role to `sts:AssumeRole` only into approved target `ComplianceAuditRole` roles.
- Use dedicated read-only `ComplianceAuditRole` roles in target accounts.
- Protect `/opt/csage/data` because it contains account role mappings, inventory evidence, scan findings and suppression history.
- Use encrypted EBS and restrict Linux permissions on the data directory.
- Restrict inbound access to the EC2 security group or place C-SAGE behind an internal ALB/reverse proxy.
- Set strong `DJANGO_SECRET_KEY`, `CSAGE_AUTH_USERNAME` and `CSAGE_AUTH_PASSWORD` values.
- Back up `/opt/csage/data` or the chosen host data directory.

## Local checks

```bash
python -m compileall .
python manage.py check
python manage.py test
```
