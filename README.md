# C-SAGE

**Cloud Security, Audit, Governance & Enforcement**

C-SAGE is an AWS multi-account cloud compliance and governance application built with Django and Boto3. It provides inventory, audit findings, suppression workflows, and exportable evidence through an ICICI Bank-aligned enterprise UI.

## Key capabilities

- S3-driven AWS multi-account configuration with STS `AssumeRole`
- Fallback to the workload IAM role / default AWS credential chain
- Concurrent account and regional scans
- Broad resource inventory using AWS Config and Resource Groups Tagging API, with explicit discovery for core audited resources
- 11 compliance audit modules covering inventory, lifecycle, certificates, IAM keys, encryption, backup, S3, Lambda, security groups, KMS, and notification domains
- S3-persisted finding suppressions
- Cached scan runs and findings in SQLite or PostgreSQL
- CSV and Excel exports
- ICICI Bank UI design tokens with accessibility font scaling
- Single Docker container using Gunicorn

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Compliance Control Catalog](docs/CONTROL_CATALOG.md)
- [Deployment Guide](docs/DEPLOYMENT.md)

## Quick start

```bash
cp .env.example .env
docker build -t c-sage .
docker run --rm -p 8000:8000 --env-file .env c-sage
```

Create an administrator before first use (`python manage.py createsuperuser` when running locally, or execute the equivalent command in the container), then open `http://localhost:8000`. All dashboard, scan, suppression, and export views require authentication; `/healthz/` remains unauthenticated for platform health checks.

For a production AWS deployment using Amazon ECR, ECS Fargate, ALB/ACM, Amazon RDS PostgreSQL, S3 configuration, cross-account IAM roles, Secrets Manager/SSM, and CloudWatch, follow [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## AWS account configuration

Set:

```text
COMPLIANCE_CONFIG_S3_BUCKET=my-governance-bucket
COMPLIANCE_CONFIG_S3_KEY=aws-compliance-config/accounts.json
```

Example configuration:

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

If the S3 configuration is unavailable, C-SAGE scans with the default Boto3 credential provider chain.

## Suppressions

Configure:

```text
SUPPRESSION_S3_BUCKET=my-governance-bucket
SUPPRESSION_S3_KEY=suppressed_findings.json
```

Suppressions remain visible and auditable, but are excluded from the non-compliant summary count.

## Lifecycle/EOL rules

PaaS lifecycle rules are stored in the `LifecycleRule` table. Populate or maintain them through Django Admin. C-SAGE evaluates a matching service/engine/version as non-compliant when its EOL/EOS date is in the past or within the configured warning window (default 30 days).

## Security notes

- Use a dedicated read-only audit role in each target account.
- Restrict the C-SAGE execution role to only the required S3 objects and `sts:AssumeRole` target roles.
- Put the application behind enterprise SSO / reverse-proxy authentication before production exposure.
- Store `DJANGO_SECRET_KEY` in AWS Secrets Manager, SSM Parameter Store, or the deployment platform's secret facility.

## Local checks

```bash
python -m compileall .
python manage.py check
python manage.py test
```
