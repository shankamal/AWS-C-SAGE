import hashlib
import hmac
import json
import os
import re
import tempfile
from pathlib import Path

from django.contrib import messages
from django.core import signing
from django.shortcuts import redirect, render

from .policy_config import PolicyConfigStore
from .storage import store


ADMIN_USERNAME = "csage"
# SHA-256 of the fixed administrator password requested for this deployment.
# The clear-text password is intentionally not committed to source control.
ADMIN_PASSWORD_SHA256 = "0da920a12885fb97acacb1fdc34496a1b8258c1ed78337e582b60fa064229656"
ADMIN_COOKIE = "csage_admin"
ADMIN_COOKIE_SALT = "csage-admin-v1"
ADMIN_SESSION_SECONDS = 8 * 60 * 60


def _admin_authenticated(request):
    token = request.COOKIES.get(ADMIN_COOKIE, "")
    if not token:
        return False
    try:
        value = signing.loads(token, salt=ADMIN_COOKIE_SALT, max_age=ADMIN_SESSION_SECONDS)
    except signing.BadSignature:
        return False
    return isinstance(value, dict) and value.get("username") == ADMIN_USERNAME


def _password_matches(password):
    supplied = hashlib.sha256((password or "").encode("utf-8")).hexdigest()
    return hmac.compare_digest(supplied, ADMIN_PASSWORD_SHA256)


def _accounts_path():
    return Path(os.getenv("CSAGE_ACCOUNTS_FILE", "/data/accounts.json"))


def _read_accounts():
    path = _accounts_path()
    if not path.exists():
        return {"accounts": []}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"accounts": []}
    if isinstance(payload, list):
        return {"accounts": payload}
    if not isinstance(payload, dict):
        return {"accounts": []}
    accounts = payload.get("accounts", [])
    return {"accounts": accounts if isinstance(accounts, list) else []}


def _write_accounts(payload):
    path = _accounts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with store.locked():
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)


def _normalize_regions(raw):
    regions = []
    for item in re.split(r"[,\s]+", raw or ""):
        region = item.strip()
        if region and region not in regions:
            regions.append(region)
    return regions


def _add_account(request):
    account_id = request.POST.get("account_id", "").strip()
    account_name = request.POST.get("account_name", "").strip()
    role_arn = request.POST.get("role_arn", "").strip()
    external_id = request.POST.get("external_id", "").strip()
    regions = _normalize_regions(request.POST.get("regions", ""))

    if not re.fullmatch(r"\d{12}", account_id):
        raise ValueError("AWS Account ID must contain exactly 12 digits.")
    if not account_name:
        raise ValueError("Account name is required.")
    if not role_arn:
        role_arn = f"arn:aws:iam::{account_id}:role/ComplianceAuditRole"
    expected_prefix = f"arn:aws:iam::{account_id}:role/"
    if not role_arn.startswith(expected_prefix):
        raise ValueError("Role ARN must be an IAM role ARN from the AWS account being added.")

    payload = _read_accounts()
    accounts = payload["accounts"]
    if any(str(item.get("account_id", "")) == account_id for item in accounts if isinstance(item, dict)):
        raise ValueError(f"AWS account {account_id} already exists in accounts.json.")

    accounts.append({
        "account_id": account_id,
        "account_name": account_name,
        "role_arn": role_arn,
        "external_id": external_id,
        "role_session_name": "CSAGEComplianceAudit",
        "duration_seconds": 3600,
        "regions": regions,
    })
    _write_accounts(payload)


def _remove_account(request):
    account_id = request.POST.get("account_id", "").strip()
    payload = _read_accounts()
    before = len(payload["accounts"])
    payload["accounts"] = [
        item for item in payload["accounts"]
        if not isinstance(item, dict) or str(item.get("account_id", "")) != account_id
    ]
    if len(payload["accounts"]) == before:
        raise ValueError(f"AWS account {account_id} was not found.")
    _write_accounts(payload)


def admin_console(request):
    authenticated = _admin_authenticated(request)

    if request.method == "POST" and request.POST.get("action") == "login":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        if hmac.compare_digest(username, ADMIN_USERNAME) and _password_matches(password):
            token = signing.dumps({"username": ADMIN_USERNAME}, salt=ADMIN_COOKIE_SALT)
            response = redirect("csage_admin")
            response.set_cookie(
                ADMIN_COOKIE,
                token,
                max_age=ADMIN_SESSION_SECONDS,
                httponly=True,
                secure=request.is_secure(),
                samesite="Strict",
                path="/admin/",
            )
            return response
        return render(request, "compliance/admin.html", {
            "admin_authenticated": False,
            "login_error": "Invalid administrator username or password.",
        }, status=401)

    if request.method == "POST" and request.POST.get("action") == "logout":
        response = redirect("csage_admin")
        response.delete_cookie(ADMIN_COOKIE, path="/admin/")
        return response

    if not authenticated:
        return render(request, "compliance/admin.html", {"admin_authenticated": False})

    if request.method == "POST":
        action = request.POST.get("action", "")
        try:
            if action == "toggle_policy":
                rule_id = request.POST.get("rule_id", "").strip()
                enabled = request.POST.get("enabled") == "true"
                PolicyConfigStore().set_enabled(rule_id, enabled, {
                    "module": request.POST.get("module", ""),
                    "title": request.POST.get("title", ""),
                    "service": request.POST.get("service", ""),
                    "severity": request.POST.get("severity", ""),
                })
                messages.success(request, f"Policy {rule_id} {'enabled' if enabled else 'disabled'}. The setting applies to the next audit scan.")
            elif action == "add_account":
                _add_account(request)
                messages.success(request, "AWS account added to accounts.json.")
            elif action == "remove_account":
                _remove_account(request)
                messages.success(request, "AWS account removed from accounts.json.")
        except (OSError, ValueError) as exc:
            messages.error(request, str(exc))
        return redirect("csage_admin")

    policies = PolicyConfigStore().catalog()
    accounts = _read_accounts()["accounts"]
    accounts.sort(key=lambda item: (str(item.get("account_name", "")).lower(), str(item.get("account_id", ""))))
    return render(request, "compliance/admin.html", {
        "admin_authenticated": True,
        "admin_username": ADMIN_USERNAME,
        "policies": policies,
        "accounts": accounts,
        "accounts_path": str(_accounts_path()),
        "policy_file": str(store.path("policy_config.json")),
    })
