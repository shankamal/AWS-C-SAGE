import json
import logging
import os
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .types import AccountTarget

logger = logging.getLogger(__name__)


class AccountResolver:
    def __init__(self, base_session=None):
        self.base_session = base_session or boto3.Session()

    @staticmethod
    def _targets(payload):
        raw_accounts = payload.get("accounts", payload if isinstance(payload, list) else [])
        return [
            AccountTarget(
                account_id=str(account["account_id"]),
                account_name=account.get("account_name", str(account["account_id"])),
                role_arn=account.get("role_arn") or f"arn:aws:iam::{account['account_id']}:role/ComplianceAuditRole",
                regions=tuple(account.get("regions") or ()),
            )
            for account in raw_accounts
        ]

    def resolve(self) -> list[AccountTarget]:
        bucket = os.getenv("COMPLIANCE_CONFIG_S3_BUCKET", "").strip()
        key = os.getenv("COMPLIANCE_CONFIG_S3_KEY", "aws-compliance-config/accounts.json").strip()
        if bucket:
            try:
                body = self.base_session.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read()
                targets = self._targets(json.loads(body))
                if targets:
                    return targets
            except (ClientError, BotoCoreError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                logger.warning("Unable to load account config from s3://%s/%s: %s", bucket, key, exc)

        local_path = Path(os.getenv("CSAGE_ACCOUNTS_FILE", "/data/accounts.json"))
        if local_path.exists():
            try:
                with local_path.open("r", encoding="utf-8") as handle:
                    targets = self._targets(json.load(handle))
                if targets:
                    return targets
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                logger.warning("Unable to load local account config %s: %s", local_path, exc)

        sts = self.base_session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity.get("Account", "")
        return [AccountTarget(account_id=account_id, account_name="Current AWS Account", role_arn=None)]
