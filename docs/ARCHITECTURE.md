# C-SAGE Architecture

## Purpose

C-SAGE (Cloud Security, Audit, Governance & Enforcement) is a single-container Django application for AWS multi-account compliance auditing, evidence generation and governed suppressions.

## Runtime flow

1. Authenticated operator starts an audit scan.
2. `AccountResolver` reads `accounts.json` from the configured S3 object.
3. If the S3 object cannot be used, C-SAGE falls back to the default AWS credential provider chain and scans the current account.
4. For configured member accounts, C-SAGE calls STS `AssumeRole` using each target `ComplianceAuditRole`.
5. Accounts are scanned concurrently. Within each account C-SAGE resolves enabled regions and executes the compliance modules.
6. Inventory and findings are written through Django ORM to SQLite (development) or PostgreSQL (recommended production database).
7. The suppression catalog is read from S3 and applied by deterministic finding key.
8. Dashboard counters exclude suppressed findings from the open non-compliant count while preserving the findings as auditable records.
9. Operators export inventory and findings as CSV/XLSX evidence.

## Components

- `csage/`: Django project configuration and WSGI entry point.
- `compliance/models.py`: scan, finding, inventory and lifecycle catalog persistence.
- `compliance/aws/config.py`: S3 account configuration and fallback logic.
- `compliance/aws/session.py`: STS role assumption.
- `compliance/aws/scanners.py`: compliance scanner implementations.
- `compliance/aws/orchestrator.py`: concurrent scan execution and persistence.
- `compliance/aws/suppressions.py`: S3 suppression catalog.
- `templates/` + `static/`: C-SAGE ICICI-aligned enterprise UI.

## Production deployment

Recommended AWS deployment is an internal ALB in front of ECS/Fargate or EC2, with PostgreSQL/RDS for persistence and S3/KMS for configuration and suppression evidence. Use enterprise SSO at the reverse proxy or integrate Django with the bank-approved identity provider before broad production use.

The container runs as a non-root Linux user. Static assets are served by WhiteNoise. Gunicorn concurrency and timeout values are configurable through environment variables.

## Security boundary

The C-SAGE execution role should have only:

- Read/write access to the exact configuration/suppression S3 objects required.
- `sts:AssumeRole` to the approved target audit role ARNs.

Target audit roles should be read-only and trusted only by the C-SAGE execution role. Do not attach administrative policies to the scanner role.

## Lifecycle catalog

PaaS EOL/EOS dates are deliberately data-driven because vendor lifecycle dates change. `LifecycleRule` records are maintained in Django Admin and evaluated using the configured warning window. This avoids hard-coding lifecycle dates into scanner code.
