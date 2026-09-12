# C-SAGE

**Cloud Security, Audit, Governance & Enforcement**

C-SAGE is an AWS multi-account cloud compliance and governance application built with Django and Boto3. It provides inventory, audit findings, suppression workflows, and exportable evidence through an ICICI Bank-aligned enterprise UI.

## Key capabilities

- Local flat-file AWS multi-account configuration with STS `AssumeRole`
- Optional AssumeRole External ID, session name, duration, and per-account regions
- Fallback to the EC2 instance profile / default AWS credential chain for the current account
- Concurrent account and regional scans
- 11 compliance audit modules covering inventory, lifecycle, certificates, IAM keys, encryption, backup, S3, Lambda, security groups, KMS, and notification domains
- AWS-native lifecycle discovery: EKS support dates from EKS APIs, RDS support dates from RDS APIs, and lifecycle/deprecation notices from AWS Health
- No maintained EOL/EOS rule file and no hard-coded deprecated Lambda runtime list
- Database-free runtime: no SQLite, PostgreSQL, RDS, migrations, or Django DB sessions
- JSON flat-file persistence under `/data`
- Detailed flat-file resource suppressions with actor, reason, account, region, service, resource, rule, and timestamps
- CSV and Excel exports
- ICICI Bank UI design tokens with accessibility font scaling
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
/data/suppressed_findings.json
```

There is no S3 dependency for account configuration or suppression persistence, and lifecycle dates are not maintained locally.

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

If the file is missing, empty, or unreadable, C-SAGE falls back to the EC2 instance profile / default Boto3 credential chain and audits the current AWS account.

## Resource suppressions

Suppressions are persisted only in the flat file defined by `CSAGE_SUPPRESSION_FILE` (default `/data/suppressed_findings.json`). Suppressed findings remain visible but are excluded from the open non-compliant count.

## Lifecycle / EOL / EOS discovery

C-SAGE does not maintain lifecycle dates in a local file.

The scanner obtains lifecycle information from AWS itself:

- **Amazon EKS**: `DescribeClusterVersions` provides the current version status plus end-of-standard-support and end-of-extended-support dates.
- **Amazon RDS / Aurora open-source engines**: `DescribeDBMajorEngineVersions` provides supported lifecycle periods and support end dates.
- **AWS Health**: scheduled-change events are queried for AWS-published deprecation, retirement, version, runtime, upgrade, and end-of-support notices affecting account resources.
- **AWS Lambda runtime lifecycle**: no hard-coded deprecated runtime list is maintained. C-SAGE relies on AWS Health notices for runtime deprecation/EOS while continuing to enforce Lambda VPC compliance directly from the Lambda API.

`CSAGE_EOL_WARNING_DAYS` controls how far ahead C-SAGE flags an AWS-published support deadline; it does not contain lifecycle dates or versions.

AWS Health Dashboard is available in the AWS console to all customers. Programmatic AWS Health API access requires an eligible AWS Support plan. If Health API access is unavailable, C-SAGE still evaluates lifecycle dates exposed directly by EKS and RDS APIs and records the Health API limitation as informational evidence.

## Security notes

- Attach a dedicated IAM role to the EC2 instance.
- Allow that role to `sts:AssumeRole` only into approved target `ComplianceAuditRole` roles.
- Use dedicated read-only `ComplianceAuditRole` roles in target accounts.
- Grant the target audit role read-only lifecycle permissions for EKS, RDS, and AWS Health.
- Protect `/opt/csage/data` because it contains account role mappings, scan evidence, and suppression history.
- Use encrypted EBS and restrict Linux permissions on the data directory.
- Restrict inbound access to the EC2 security group or place C-SAGE behind an internal ALB/reverse proxy.
- Set strong `DJANGO_SECRET_KEY`, `CSAGE_AUTH_USERNAME`, and `CSAGE_AUTH_PASSWORD` values.
- Back up `/opt/csage/data` or the chosen host data directory.

## Local checks

```bash
python -m compileall .
python manage.py check
python manage.py test
```
