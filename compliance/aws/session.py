import boto3
from .types import AccountTarget


def session_for(target: AccountTarget, base_session=None):
    base = base_session or boto3.Session()
    if not target.role_arn:
        return base
    sts = base.client("sts")
    response = sts.assume_role(
        RoleArn=target.role_arn,
        RoleSessionName="CSAGEComplianceAudit",
        DurationSeconds=3600,
    )
    c = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"],
        region_name=base.region_name,
    )
