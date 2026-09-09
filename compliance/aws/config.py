import json
import logging
import os
from pathlib import Path

import boto3

from .types import AccountTarget

logger = logging.getLogger(__name__)


class AccountResolver:
    """Resolve AWS account and AssumeRole configuration from a local JSON flat file.

    C-SAGE intentionally does not use S3 for account configuration. The default
    configuration file is /data/accounts.json, which should be backed by the EC2
    host bind mount.
    """

    def __init__(self, base_session=None):
        self.base_session = base_session or boto3.Session()

    @staticmethod
    def _targets(payload):
        raw_accounts = payload.get("accounts", payload if isinstance(payload, list) else [])
        targets = []
        for account in raw_accounts:
            duration = int(account.get("duration_seconds", 3600) or 3600)
            duration = max(900, min(duration, 43200))
            targets.append(
                AccountTarget(
                    account_id=str(account["account_id"]),
                    account_name=account.get("account_name", str(account["account_id"])),
                    role_arn=account.get("role_arn") or f"arn:aws:iam::{account['account_id']}:role/ComplianceAuditRole",
                    regions=tuple(account.get("regions") or ()),
                    external_id=account.get("external_id") or None,
                    role_session_name=account.get("role_session_name") or "CSAGEComplianceAudit",
                    duration_seconds=duration,
                )
            )
        return targets

    def resolve(self) -> list[AccountTarget]:
        local_path = Path(os.getenv("CSAGE_ACCOUNTS_FILE", "/data/accounts.json"))
        if local_path.exists():
            try:
                with local_path.open("r", encoding="utf-8") as handle:
                    targets = self._targets(json.load(handle))
                if targets:
                    return targets
                logger.warning("Account configuration %s contains no accounts; using EC2 instance profile for current account", local_path)
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                logger.warning("Unable to load local account configuration %s; using EC2 instance profile for current account: %s", local_path, exc)

        sts = self.base_session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity.get("Account", "")
        return [AccountTarget(account_id=account_id, account_name="Current AWS Account", role_arn=None)]
