# C-SAGE Architecture

## Purpose

C-SAGE (Cloud Security, Audit, Governance & Enforcement) is a single-container Django application for AWS multi-account inventory discovery, compliance auditing, evidence generation and governed suppressions.

## Runtime flow

1. An authenticated operator starts an audit scan.
2. `AccountResolver` reads `/data/accounts.json` (or the path defined by `CSAGE_ACCOUNTS_FILE`).
3. Each configured account defines its Account ID/name, IAM Role ARN, optional External ID, role session settings and target regions.
4. C-SAGE uses AWS STS `AssumeRole` for configured member accounts.
5. If no valid account file is available, C-SAGE falls back to the EC2 instance profile/default AWS credential chain and scans the current account.
6. Accounts are scanned concurrently. Regions are either explicitly configured or discovered from EC2 `DescribeRegions`.
7. The **Master Inventory engine** runs layered discovery across service-native APIs, AWS Config, Resource Groups Tagging API and AWS Resource Explorer 2.
8. Inventory collectors always emit coverage evidence, including successful zero-resource checks, access-denied results and unavailable/error states.
9. Service/API discovery records are consolidated into one canonical resource row while supplementary tag/config/resource-explorer payloads are retained as evidence.
10. Lifecycle data is queried dynamically from AWS service APIs and AWS Health; C-SAGE does not maintain an EOL/EOS rule catalog.
11. Inventory, inventory coverage, findings, scan history and suppressions are persisted as JSON flat files under `/data`.
12. Operators browse the Master Inventory, drill into individual resources, and export filtered/full Excel/CSV/JSON evidence.

## Components

- `csage/`: Django project configuration and WSGI entry point.
- `compliance/models.py`: lightweight record classes backed by flat-file persistence; no Django ORM models.
- `compliance/storage.py`: atomic JSON persistence and Linux file locking.
- `compliance/middleware.py`: database-free HTTP Basic authentication.
- `compliance/aws/config.py`: local flat-file account and AssumeRole configuration plus EC2 credential fallback.
- `compliance/aws/session.py`: STS role assumption using local role metadata.
- `compliance/aws/inventory.py`: service-native inventory collectors, AWS Config enrichment, Tagging API discovery and coverage tracking.
- `compliance/aws/resource_explorer_inventory.py`: dynamic Resource Explorer 2 fallback for additional AWS resource types and zero-resource supported-service coverage.
- `compliance/aws/scanners.py`: core compliance scanner implementations.
- `compliance/aws/lifecycle.py`: AWS-native lifecycle discovery using EKS, RDS and AWS Health APIs.
- `compliance/aws/orchestrator.py`: concurrent account execution, inventory consolidation, compliance execution and persistence.
- `compliance/aws/suppressions.py`: local JSON resource suppression catalog.
- `templates/compliance/inventory.html`: Master Inventory grid and coverage UI.
- `templates/compliance/resource_detail.html`: per-resource drill-down and export UI.
- `templates/` + `static/`: C-SAGE ICICI-aligned enterprise UI.

## Complete Master Inventory architecture

There is no single AWS API that can return every AWS resource together with all service-specific configuration. C-SAGE therefore uses complementary discovery layers.

### Layer 1 — service-native APIs

C-SAGE calls paginated list/describe APIs for major enterprise AWS services. These collectors provide the richest normalized fields such as resource name/ID/ARN, status, creation time, networking, security settings and relationships. The complete API item used for discovery is retained under `raw_attributes`.

Coverage includes compute, EC2 networking, ELB, Auto Scaling, Lambda, API Gateway, ECS/EKS/Fargate, CloudFormation, SSM, databases, storage, Backup, IAM/KMS/Secrets/ACM, Route 53/CloudFront, monitoring/integration, analytics, Organizations, Control Tower, Direct Connect, WAF/Shield and other commonly provisioned AWS services.

### Layer 2 — AWS Config

Where AWS Config is available, C-SAGE uses Advanced Query (`SelectResourceConfig`) to enumerate Config-supported resources and `BatchGetResourceConfig` to enrich individual resources. Config discoveries that correspond to an existing service-native row are merged as supplemental evidence rather than emitted as duplicates.

### Layer 3 — Resource Groups Tagging API

`tag:GetResources` broadens coverage for taggable resources and provides tag enrichment. Tagged fallback records are consolidated into the canonical service-native/Config resource whenever the ARN or resource identity matches.

### Layer 4 — AWS Resource Explorer 2

Resource Explorer 2 provides dynamic breadth for supported AWS resource types not explicitly modelled by a collector. C-SAGE records supported-service coverage even when zero resources are returned. If Resource Explorer is not configured or the audit role lacks access, C-SAGE records that state rather than treating the service as empty.

### Resource consolidation

Inventory records are correlated primarily by ARN and secondarily by account/region/service/resource ID. Service-native API records are canonical. Supplemental discovery sources merge tags and missing normalized fields while their original payloads are retained in `_supplemental_discovery` under `raw_attributes`.

This avoids separate duplicate rows for the same provisioned resource while preserving the evidence returned by multiple AWS discovery sources.

## Inventory resource model

Every persisted resource contains:

```text
resource_key
account_id
account_name
region
service
resource_type
resource_name
resource_id
resource_arn
status
creation_time
tags
configuration
networking
security
relationships
raw_attributes
discovery_source
```

`resource_key` is deterministic and is used for individual resource drill-down and exports.

### No summarization of API evidence

The UI displays normalized categories for usability, but the discovery payload is also retained as structured JSON. The Excel export contains flattened attribute path/value sheets so nested AWS API responses can be exported without forcing an entire resource payload into a single Excel cell.

Deleted-resource metadata is stored only when an AWS API still returns it. C-SAGE does not infer or synthesize deleted resources.

## Empty-resource and completeness evidence

`/data/inventory_coverage.json` records every collector attempt with:

```text
scan_run_id
account_id
account_name
region
service
resource_type
resource_count
scan_status
message
source
```

`scan_status` distinguishes:

- `COMPLETE` with count `0`: queried successfully and no resources exist for that check.
- `COMPLETE` with count `>0`: resources were returned.
- `ACCESS_DENIED`: IAM prevented discovery.
- `UNAVAILABLE`: the API, view or resource type is unavailable/not configured.
- `ERROR`: another discovery failure occurred.

The Master Inventory Coverage table and the Excel `Service Coverage` sheet expose this evidence directly.

## Persistence model

C-SAGE has no application database. `DATABASES = {}` is configured in Django and the container does not run migrations.

The persistent host directory is mounted into the container at `/data`:

```text
/data/accounts.json
/data/scan_runs.json
/data/findings.json
/data/inventory.json
/data/inventory_coverage.json
/data/suppressed_findings.json
```

There is no S3 dependency for runtime configuration or suppression state, and no lifecycle rule file is maintained.

Writes use atomic file replacement and a Linux file lock. The deployment is intentionally a single-host/single-state design; horizontal multi-host scaling would require a shared persistence redesign.

## Inventory exports

The full Excel workbook contains:

1. `Inventory Summary`
2. `Master Inventory`
3. `Service Coverage`
4. one or more `Resource Attributes N` sheets

The Resource Attributes sheets flatten every retained Tags, Configuration, Networking, Security, Relationships and Raw API Attributes payload into section/path/value rows. Large attribute sheets are split before Excel's worksheet row limit.

Every individual resource also supports browser drill-down, JSON export and dedicated Excel export.

## Account and AssumeRole boundary

`/data/accounts.json` is the source of truth for cross-account role information. The EC2 `CSAGEApplicationRole` should have only `sts:AssumeRole` to approved target `ComplianceAuditRole` ARNs.

Target `ComplianceAuditRole` roles are read-only. `iam/ComplianceAuditRolePolicy.json` contains the list/read/describe permissions needed by inventory and compliance collectors. Secret values are deliberately not retrieved.

Global/control-plane APIs such as Organizations and Control Tower may be callable only from specific authorized accounts. An unauthorized member account produces coverage evidence such as `ACCESS_DENIED`; it is not reported as an empty service.

## Suppression flat file

`/data/suppressed_findings.json` is the source of truth for compliance exceptions. Each entry records suppression status, actor/reason, timestamps, rule/module, account, region, service, resource and severity details.

## AWS-native lifecycle discovery

C-SAGE deliberately does not maintain EOL/EOS dates or deprecated runtime versions locally.

- **Amazon EKS** — `DescribeClusterVersions` supplies version status, end of standard support and end of extended support dates.
- **Amazon RDS/Aurora** — `DescribeDBMajorEngineVersions` supplies lifecycle periods for supported engines.
- **AWS Health** — scheduled-change events supply AWS-published deprecation, retirement, runtime, version, upgrade and end-of-support notifications.

AWS Health API access depends on the account's eligible Support plan. If it is unavailable, C-SAGE records the limitation and continues service-native lifecycle checks.

`CSAGE_EOL_WARNING_DAYS` is only a policy threshold against AWS-published dates.

## Production deployment

The target deployment is a Linux EC2 instance running the C-SAGE Docker container with an encrypted EBS-backed bind mount:

```text
/opt/csage/data:/data
```

The container runs as a non-root Linux user. The host directory must therefore be writable by the container's `csage` UID/GID. On SELinux-enabled hosts the bind mount may require `:Z` relabeling.

Use restricted security-group ingress, IMDSv2, an approved instance profile, encrypted EBS, regular backups and preferably an internal ALB/reverse proxy with HTTPS.
