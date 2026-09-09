import boto3

from .types import AccountTarget


def session_for(target: AccountTarget, base_session=None):
    base = base_session or boto3.Session()
    if not target.role_arn:
        return base

    sts = base.client("sts")
    assume_args = {
        "RoleArn": target.role_arn,
        "RoleSessionName": target.role_session_name,
        "DurationSeconds": target.duration_seconds,
    }
    if target.external_id:
        assume_args["ExternalId"] = target.external_id

    response = sts.assume_role(**assume_args)
    credentials = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=base.region_name,
    )
