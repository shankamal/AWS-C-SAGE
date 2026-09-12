# C-SAGE Control Catalog

| Module | Rule ID | Control |
|---|---|---|
| PaaS EOL / EOS | CSAGE-EOL-001 | EKS and supported RDS/Aurora versions must remain outside the configured warning window using support dates returned directly by AWS service APIs. |
| PaaS EOL / EOS | CSAGE-EOL-HEALTH-001 | AWS Health scheduled-change lifecycle events for affected resources must remain outside the configured EOL/EOS warning window. |
| PaaS EOL / EOS | CSAGE-EOL-SOURCE-001 | Informational evidence is recorded when AWS Health API access is unavailable because of the account support plan. |
| Certificates | CSAGE-CERT-001 | ACM certificate must not be expired or expire within 30 days. |
| Certificates | CSAGE-CERT-002 | IAM server certificate must not expire within 30 days. |
| IAM Access Keys | CSAGE-IAM-KEY-001 | Active IAM access key age must not exceed 90 days by default. |
| Storage Encryption | CSAGE-STG-ENC-001 | EBS must be encrypted with a customer-managed KMS key. |
| Storage Encryption | CSAGE-STG-ENC-002 | EFS must be encrypted with a customer-managed KMS key. |
| Storage Backup | CSAGE-BACKUP-001 | EBS must have a recent snapshot or AWS Backup recovery point. |
| Storage Backup | CSAGE-BACKUP-002 | RDS must meet backup retention or recent AWS Backup requirements. |
| Storage Backup | CSAGE-BACKUP-003 | EFS must have a recent AWS Backup recovery point. |
| Storage Backup | CSAGE-BACKUP-004 | DynamoDB must have PITR or a recent AWS Backup recovery point. |
| Object Storage | CSAGE-S3-001 | S3 public exposure and incomplete Block Public Access are prohibited. |
| Object Storage | CSAGE-S3-002 | S3 default encryption must use customer-managed KMS. |
| Lambda | CSAGE-LAMBDA-001 | Lambda must be attached to a VPC. Runtime deprecation/EOS is sourced from AWS Health rather than a maintained runtime list. |
| Security Groups | CSAGE-SG-001 | Security Group description is mandatory. |
| Security Groups | CSAGE-SG-002 | Security Group description must contain an RITM ticket. |
| Security Groups | CSAGE-SG-003 | Sensitive ports must not be exposed to broad CIDRs (`/0`, `/8`, `/16`, or broader). |
| Security Groups | CSAGE-SG-004 | Internet-exposed HTTP/80 is prohibited unless an application-layer HTTPS redirect can be established. |
| KMS | CSAGE-KMS-001 | Customer-managed KMS key must not exceed configured age and rotation must be enabled. |
| Notification Domains | CSAGE-NOTIFY-001 | SNS email subscriptions must use the approved domain. |
| Notification Domains | CSAGE-NOTIFY-002 | AWS Budget email subscribers must use the approved domain. |

## Tunable policy values

The following environment variables allow policy thresholds to be changed without code deployment:

- `CSAGE_EOL_WARNING_DAYS`
- `CSAGE_ACCESS_KEY_MAX_AGE_DAYS`
- `CSAGE_KMS_MAX_AGE_DAYS`
- `CSAGE_BACKUP_MAX_AGE_HOURS`
- `CSAGE_BACKUP_MIN_RETENTION_DAYS`
- `CSAGE_ALLOWED_EMAIL_DOMAIN`
- `CSAGE_SENSITIVE_PORTS`

`CSAGE_EOL_WARNING_DAYS` only controls how far ahead to alert against dates published by AWS. C-SAGE does not maintain EOL dates, version calendars, or deprecated Lambda runtime lists locally.
