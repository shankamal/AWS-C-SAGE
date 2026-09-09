# C-SAGE Architecture

## Purpose

C-SAGE (Cloud Security, Audit, Governance & Enforcement) is a single-container Django application for AWS multi-account compliance auditing, evidence generation and governed suppressions.

## Runtime flow

1. Authenticated operator starts an audit scan.
2. `AccountResolver` first reads account configuration from the configured S3 object when enabled.
3. If S3 is not configured or unavailable, C-SAGE reads `/data/accounts.json` (or `CSAGE_ACCOUNTS_FILE`).
4. If no account file is available, C-SAGE falls back to the EC2 instance profile/default AWS credential provider chain and scans the current account.
5. For configured member accounts, C-SAGE calls STS `AssumeRole` using each target `ComplianceAuditRole`.
6. Accounts are scanned concurrently. Within each account C-SAGE resolves enabled regions and executes the compliance modules.
7. Inventory, findings, scan history and suppressions are persisted as JSON flat files in `/data`.
8. Dashboard counters exclude suppressed findings from the open non-compliant count while preserving the findings as auditable records.
9. Operators export inventory and findings as CSV/XLSX evidence.

## Components

- `csage/`: Django project configuration and WSGI entry point.
- `compliance/models.py`: lightweight record classes backed by flat-file persistence; no Django ORM models.
- `compliance/storage.py`: atomic JSON persistence and Linux file locking.
- `compliance/middleware.py`: database-free HTTP Basic authentication.
- `compliance/aws/config.py`: S3/local account configuration and EC2 credential fallback.
- `compliance/aws/session.py`: STS role assumption.
- `compliance/aws/scanners.py`: compliance scanner implementations.
- `compliance/aws/orchestrator.py`: concurrent scan execution and persistence.
- `compliance/aws/suppressions.py`: local JSON suppression catalog.
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

Writes use atomic file replacement and a Linux file lock to reduce corruption risk on the single-host deployment.

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

- Read access to the exact configuration S3 object when S3 configuration is used.
- `sts:AssumeRole` to the approved target audit role ARNs.
- Required read/list permissions when scanning the hosting account directly.

Target audit roles should be read-only and trusted only by the approved C-SAGE execution role. Do not attach administrative policies to the scanner role.

## Lifecycle catalog

PaaS EOL/EOS dates are data-driven because vendor lifecycle dates change. Rules are maintained in `/data/lifecycle_rules.json` and evaluated using the configured warning window. This avoids hard-coding lifecycle dates into scanner code and avoids any database dependency.
