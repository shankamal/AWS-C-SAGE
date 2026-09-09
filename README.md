# C-SAGE

**Cloud Security, Audit, Governance & Enforcement**

C-SAGE is an AWS multi-account cloud compliance and governance application built with Django and Boto3. It provides inventory, audit findings, suppression workflows, and exportable evidence through an ICICI Bank-aligned enterprise UI.

## Key capabilities

- Local flat-file AWS multi-account configuration with STS `AssumeRole`
- Optional AssumeRole External ID, session name, duration, and per-account regions
- Fallback to the EC2 instance profile / default AWS credential chain for the current account
- Concurrent account and regional scans
- 11 compliance audit modules covering inventory, lifecycle, certificates, IAM keys, encryption, backup, S3, Lambda, security groups, KMS, and notification domains
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
/data/lifecycle_rules.json
/data/scan_runs.json
/data/findings.json
/data/inventory.json
/data/suppressed_findings.json
```

There is no S3 dependency for account configuration or suppression persistence.

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

Suppressions are persisted only in the flat file defined by `CSAGE_SUPPRESSION_FILE` (default `/data/suppressed_findings.json`).

Each suppression record contains the finding key plus auditable details including:

- rule and module
- account ID and account name
- region and AWS service
- resource ID and resource type
- severity, title, and finding details
- suppression actor and reason
- suppression/update timestamps

See `suppressed_findings.example.json` for an example. Suppressed findings remain visible but are excluded from the open non-compliant count.

## Lifecycle/EOL rules

Maintain lifecycle data in `/data/lifecycle_rules.json`:

```json
{
  "rules": [
    {
      "service": "eks",
      "engine": "kubernetes",
      "version": "1.30",
      "eol_date": "2026-11-26",
      "active": true,
      "source_reference": "https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html"
    }
  ]
}
```

## Security notes

- Attach a dedicated IAM role to the EC2 instance.
- Allow that role to `sts:AssumeRole` only into approved target `ComplianceAuditRole` roles.
- Use dedicated read-only `ComplianceAuditRole` roles in target accounts.
- Protect `/opt/csage/data` because it contains account role mappings, scan evidence, lifecycle rules, and suppression history.
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
