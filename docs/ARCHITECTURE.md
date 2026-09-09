# C-SAGE Architecture

## Purpose

C-SAGE (Cloud Security, Audit, Governance & Enforcement) is a single-container Django application for AWS multi-account compliance auditing, evidence generation and governed suppressions.

## Runtime flow

1. An authenticated operator starts an audit scan.
2. `AccountResolver` reads `/data/accounts.json` (or the path defined by `CSAGE_ACCOUNTS_FILE`).
3. Each configured account can define its Account ID, Account Name, IAM Role ARN, optional External ID, role session name, session duration, and target regions.
4. For configured member accounts, C-SAGE calls AWS STS `AssumeRole` using the role metadata from the local flat file.
5. If no valid account file is available, C-SAGE falls back to the EC2 instance profile/default AWS credential provider chain and scans the current account.
6. Accounts are scanned concurrently. Within each account C-SAGE resolves configured/enabled regions and executes the compliance modules.
7. Inventory, findings, scan history, lifecycle rules and suppressions are persisted as JSON flat files in `/data`.
8. Resource suppression records contain the original finding metadata, suppression actor, reason and timestamps.
9. Dashboard counters exclude suppressed findings from the open non-compliant count while preserving the records as auditable evidence.
10. Operators export inventory and findings as CSV/XLSX evidence.

## Components

- `csage/`: Django project configuration and WSGI entry point.
- `compliance/models.py`: lightweight record classes backed by flat-file persistence; no Django ORM models.
- `compliance/storage.py`: atomic JSON persistence and Linux file locking.
- `compliance/middleware.py`: database-free HTTP Basic authentication.
- `compliance/aws/config.py`: local flat-file account and AssumeRole configuration plus EC2 credential fallback.
- `compliance/aws/session.py`: STS role assumption using local role metadata.
- `compliance/aws/scanners.py`: compliance scanner implementations.
- `compliance/aws/orchestrator.py`: concurrent scan execution and persistence.
- `compliance/aws/suppressions.py`: local JSON resource suppression catalog.
- `templates/` + `static/`: C-SAGE ICICI-aligned enterprise UI.

## Persistence model

C-SAGE has no application database. `DATABASES = {}` is configured in Django and the container does not run migrations.

The persistent host directory is mounted into the container at `/data`. Typical files are:

```text
/data/accounts.json
/data/lifecycle_rules.json
/data/scan_runs.json
/data/findings.json
/data/inventory.json
/data/suppressed_findings.json
```

There is no S3 dependency for runtime configuration or suppression state.

Writes use atomic file replacement and a Linux file lock to reduce corruption risk on the single-host deployment.

## Account and AssumeRole flat file

`/data/accounts.json` is the source of truth for cross-account role information. Example fields:

```json
{
  "account_id": "111122223333",
  "account_name": "Production",
  "role_arn": "arn:aws:iam::111122223333:role/ComplianceAuditRole",
  "external_id": "",
  "role_session_name": "CSAGEComplianceAudit",
  "duration_seconds": 3600,
  "regions": ["ap-south-1", "ap-south-2"]
}
```

The EC2 instance profile requires only the permissions necessary to assume the approved target audit roles, plus direct read permissions only when the hosting account itself is scanned without role assumption.

## Suppression flat file

`/data/suppressed_findings.json` is the source of truth for resource exceptions. Each entry is keyed by the deterministic finding SHA-256 key and records:

- suppression status
- actor and reason
- suppression/update timestamps
- rule ID and compliance module
- account ID/name
- region and AWS service
- resource ID/type
- severity, title and finding detail

This makes suppression decisions auditable without a database or object store.

## Production deployment

The target deployment is a Linux EC2 instance running the C-SAGE Docker container with a bind mount such as:

```text
/opt/csage/data:/data
```

The EC2 instance should use encrypted EBS storage, an instance profile with least-privilege AWS permissions, restricted security-group ingress, and regular backup/snapshot protection for `/opt/csage/data`.

An internal ALB or enterprise reverse proxy can be added in front of the EC2 instance for HTTPS and enterprise access control.

The container runs as a non-root Linux user. Static assets are served by WhiteNoise. Gunicorn concurrency and timeout values are configurable through environment variables.

## Security boundary

The C-SAGE EC2 execution role should have only:

- `sts:AssumeRole` to the approved target audit role ARNs.
- Required read/list permissions when scanning the hosting account directly.

Target audit roles should be read-only and trusted only by the approved C-SAGE EC2 execution role. Do not attach administrative policies to the scanner role.

Protect the local data directory with Linux permissions, encrypted EBS, restricted administrative access, and backups because it contains account/role mappings and auditable suppression history.

## Lifecycle catalog

PaaS EOL/EOS dates are data-driven because vendor lifecycle dates change. Rules are maintained in `/data/lifecycle_rules.json` and evaluated using the configured warning window. This avoids hard-coding lifecycle dates into scanner code and avoids any database dependency.
