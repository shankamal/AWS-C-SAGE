# C-SAGE

**Cloud Security, Audit, Governance & Enforcement**

C-SAGE is an AWS multi-account cloud compliance and governance application built with Django and Boto3. It provides inventory, audit findings, suppression workflows, and exportable evidence through an ICICI Bank-aligned enterprise UI.

## Key capabilities

- S3-driven or local flat-file AWS multi-account configuration with STS `AssumeRole`
- Fallback to the EC2 instance profile / default AWS credential chain
- Concurrent account and regional scans
- 11 compliance audit modules covering inventory, lifecycle, certificates, IAM keys, encryption, backup, S3, Lambda, security groups, KMS, and notification domains
- Database-free runtime: no SQLite, PostgreSQL, RDS, migrations, or Django DB sessions
- JSON flat-file persistence under `/data`
- Flat-file finding suppressions
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

## AWS account configuration

C-SAGE checks configuration in this order:

1. S3 when `COMPLIANCE_CONFIG_S3_BUCKET` is configured.
2. Local flat file defined by `CSAGE_ACCOUNTS_FILE` (default `/data/accounts.json`).
3. EC2 instance profile / default Boto3 credential chain for the current AWS account.

Example:

```json
{
  "accounts": [
    {
      "account_id": "111122223333",
      "account_name": "Production",
      "role_arn": "arn:aws:iam::111122223333:role/ComplianceAuditRole",
      "regions": ["ap-south-1", "ap-south-2"]
    }
  ]
}
```

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
- Use dedicated read-only `ComplianceAuditRole` roles in target accounts.
- Restrict inbound access to the EC2 security group or place C-SAGE behind an internal ALB/reverse proxy.
- Set a strong `DJANGO_SECRET_KEY`, `CSAGE_AUTH_USERNAME`, and `CSAGE_AUTH_PASSWORD`.
- Back up `/opt/csage/data` or the chosen host data directory because it contains C-SAGE state and audit history.

## Local checks

```bash
python -m compileall .
python manage.py check
python manage.py test
```
