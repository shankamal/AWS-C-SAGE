import json
import logging
import os
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from .types import AccountTarget

logger = logging.getLogger(__name__)

class AccountResolver:
    def __init__(self, base_session=None):
        self.base_session = base_session or boto3.Session()

    def resolve(self) -> list[AccountTarget]:
        bucket = os.getenv("COMPLIANCE_CONFIG_S3_BUCKET", "").strip()
        key = os.getenv("COMPLIANCE_CONFIG_S3_KEY", "aws-compliance-config/accounts.json").strip()
        if bucket:
            try:
                body = self.base_session.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read()
                payload = json.loads(body)
                raw_accounts = payload.get("accounts", payload if isinstance(payload, list) else [])
                targets = [
                    AccountTarget(
                        account_id=str(a["account_id"]),
                        account_name=a.get("account_name", str(a["account_id"])),
                        role_arn=a.get("role_arn") or f"arn:aws:iam::{a['account_id']}:role/ComplianceAuditRole",
                        regions=tuple(a.get("regions") or ()),
                    )
                    for a in raw_accounts
                ]
                if targets:
                    return targets
            except (ClientError, BotoCoreError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                logger.warning("Unable to load account config from s3://%s/%s; using local credentials: %s", bucket, key, exc)

        sts = self.base_session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity.get("Account", "")
        return [AccountTarget(account_id=account_id, account_name="Current AWS Account", role_arn=None)]
