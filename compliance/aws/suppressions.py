import hashlib
import json
import os
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError


def make_finding_key(rule_id: str, account_id: str, region: str, resource_id: str) -> str:
    raw = "|".join([rule_id or "", account_id or "", region or "", resource_id or ""])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

class SuppressionStore:
    def __init__(self, session=None):
        self.session = session or boto3.Session()
        self.bucket = os.getenv("SUPPRESSION_S3_BUCKET", "").strip()
        self.key = os.getenv("SUPPRESSION_S3_KEY", "suppressed_findings.json").strip()

    @property
    def configured(self):
        return bool(self.bucket)

    def load(self) -> dict:
        if not self.bucket:
            return {}
        try:
            obj = self.session.client("s3").get_object(Bucket=self.bucket, Key=self.key)
            payload = json.loads(obj["Body"].read())
            return payload.get("suppressions", payload) if isinstance(payload, dict) else {}
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in {"NoSuchKey", "404"}:
                return {}
            raise

    def save(self, data: dict):
        if not self.bucket:
            raise RuntimeError("SUPPRESSION_S3_BUCKET is not configured")
        self.session.client("s3").put_object(
            Bucket=self.bucket,
            Key=self.key,
            Body=json.dumps({"version": 1, "suppressions": data}, indent=2, default=str).encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="aws:kms" if os.getenv("SUPPRESSION_S3_KMS_KEY_ID") else "AES256",
            **({"SSEKMSKeyId": os.getenv("SUPPRESSION_S3_KMS_KEY_ID")} if os.getenv("SUPPRESSION_S3_KMS_KEY_ID") else {}),
        )

    def suppress(self, finding_key: str, actor: str, reason: str = ""):
        data = self.load()
        data[finding_key] = {"suppressed": True, "actor": actor, "reason": reason, "updated_at": datetime.now(timezone.utc).isoformat()}
        self.save(data)

    def unsuppress(self, finding_key: str, actor: str):
        data = self.load()
        if finding_key in data:
            data[finding_key]["suppressed"] = False
            data[finding_key]["actor"] = actor
            data[finding_key]["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.save(data)
