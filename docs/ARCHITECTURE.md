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
7. Lifecycle data is queried dynamically from AWS service APIs and AWS Health; C-SAGE does not maintain an EOL/EOS rule catalog.
8. Inventory, findings, scan history and suppressions are persisted as JSON flat files in `/data`.
9. Resource suppression records contain the original finding metadata, suppression actor, reason and timestamps.
10. Dashboard counters exclude suppressed findings from the open non-compliant count while preserving the records as auditable evidence.
11. Operators export inventory and findings as CSV/XLSX evidence.

## Components

- `csage/`: Django project configuration and WSGI entry point.
- `compliance/models.py`: lightweight record classes backed by flat-file persistence; no Django ORM models.
- `compliance/storage.py`: atomic JSON persistence and Linux file locking.
- `compliance/middleware.py`: database-free HTTP Basic authentication.
- `compliance/aws/config.py`: local flat-file account and AssumeRole configuration plus EC2 credential fallback.
- `compliance/aws/session.py`: STS role assumption using local role metadata.
- `compliance/aws/scanners.py`: core compliance scanner implementations.
- `compliance/aws/lifecycle.py`: AWS-native lifecycle discovery using EKS, RDS and AWS Health APIs.
- `compliance/aws/orchestrator.py`: concurrent scan execution and persistence.
- `compliance/aws/suppressions.py`: local JSON resource suppression catalog.
- `templates/` + `static/`: C-SAGE ICICI-aligned enterprise UI.

## Persistence model

C-SAGE has no application database. `DATABASES = {}` is configured in Django and the container does not run migrations.

The persistent host directory is mounted into the container at `/data`. Typical files are:

```text
/data/accounts.json
/data/scan_runs.json
/data/findings.json
/data/inventory.json
/data/suppressed_findings.json
```

There is no S3 dependency for runtime configuration or suppression state, and no lifecycle rule file is maintained.

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

`/data/suppressed_findings.json` is the source of truth for resource exceptions. Each entry is keyed by the deterministic finding SHA-256 key and records suppression status, actor/reason, timestamps, rule/module, account, region, service, resource and severity details.

## AWS-native lifecycle discovery

C-SAGE deliberately does not maintain EOL/EOS dates or deprecated runtime versions locally.

### Amazon EKS

C-SAGE queries `DescribeClusterVersions` for the Kubernetes version used by each cluster. AWS returns version status, end of standard support and end of extended support dates. A cluster is flagged when standard support has ended or is within the configured warning window.

### Amazon RDS / Aurora

For open-source RDS/Aurora engines, C-SAGE queries `DescribeDBMajorEngineVersions`. AWS returns standard and, where available, extended-support lifecycle periods. C-SAGE evaluates the AWS-provided support dates against the warning window.

### AWS Health

C-SAGE queries AWS Health scheduled-change events for AWS-published deprecation, retirement, runtime, version, upgrade and end-of-support notifications, including affected entities. This provides lifecycle coverage for services that do not expose a dedicated support-date API.

AWS Health Dashboard is visible in the console for AWS customers, while programmatic Health API access requires an eligible AWS Support plan. If Health API access returns `SubscriptionRequiredException`, C-SAGE records this as informational evidence and continues with service-native EKS/RDS lifecycle checks.

### Lambda runtime lifecycle

C-SAGE does not contain a hard-coded Lambda deprecated-runtime list. Lambda VPC compliance is still evaluated from the Lambda API, while runtime deprecation/EOS is derived from AWS Health scheduled-change events.

`CSAGE_EOL_WARNING_DAYS` is only a policy threshold for how far ahead to alert; it contains no vendor lifecycle dates or version mappings.

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

Target audit roles should be read-only and trusted only by the approved C-SAGE EC2 execution role. The lifecycle scanner needs read-only `eks:DescribeClusterVersions`, `rds:DescribeDBEngineVersions`, `rds:DescribeDBMajorEngineVersions`, and AWS Health describe permissions in addition to the existing service inventory permissions.

Protect the local data directory with Linux permissions, encrypted EBS, restricted administrative access, and backups because it contains account/role mappings and auditable suppression history.
