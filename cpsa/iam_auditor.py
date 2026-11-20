"""IAM auditor: checks the account password policy, users, MFA and access keys.

Plain boto3 calls. The same code runs against real AWS if you drop the mock
(it needs iam:GetAccountPasswordPolicy, iam:GenerateCredentialReport and
iam:GetCredentialReport). Everything comes back as Finding objects.
"""
import csv
import io
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from . import config
from .models import Finding


def _now(now):
    return now or datetime.now(timezone.utc)


def _parse_date(value):
    """Credential-report dates look like 2026-01-02T03:04:05+00:00; others are N/A etc."""
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


# ------------------------------------------------------------------ password policy
def audit_password_policy(iam) -> list:
    res = "AccountPasswordPolicy"
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return [Finding("PWD-000", res, "No custom password policy; AWS defaults apply.", "password_policy")]
        raise

    out = []
    length = policy.get("MinimumPasswordLength", 0)
    if length < config.MIN_LENGTH_NIST:
        out.append(Finding("PWD-001", res, f"MinimumPasswordLength is {length} (NIST floor is {config.MIN_LENGTH_NIST}).",
                           "password_policy", {"minimum_length": length}))
    elif length < config.MIN_LENGTH_RECOMMENDED:
        out.append(Finding("PWD-002", res, f"MinimumPasswordLength is {length} (recommended {config.MIN_LENGTH_RECOMMENDED}+).",
                           "password_policy", {"minimum_length": length}))

    reuse = policy.get("PasswordReusePrevention", 0)
    if reuse < config.REUSE_PREVENTION_MIN:
        shown = f"{reuse}" if reuse else "not set"
        out.append(Finding("PWD-003", res, f"PasswordReusePrevention is {shown} (recommended {config.REUSE_PREVENTION_MIN}).",
                           "password_policy", {"reuse_prevention": reuse}))

    max_age = policy.get("MaxPasswordAge", 0)
    if policy.get("ExpirePasswords") and 0 < max_age <= config.FORCED_EXPIRY_DAYS:
        out.append(Finding("PWD-004", res, f"Passwords are forced to expire every {max_age} days; NIST advises against arbitrary rotation.",
                           "password_policy", {"max_password_age": max_age}))

    # IAM has no setting to block common/breached passwords, so we always note it (INFO).
    out.append(Finding("PWD-005", res, "IAM cannot screen passwords against a breached-password list; use the strength engine.",
                       "password_policy"))
    return out


# ------------------------------------------------------------------ credential report
def fetch_credential_report(iam, timeout: int = 30) -> list:
    """Generate and download the credential report; return one dict per row."""
    deadline = time.time() + timeout
    while True:
        state = iam.generate_credential_report()["State"]
        if state == "COMPLETE":
            break
        if time.time() > deadline:
            raise TimeoutError("credential report not ready")
        time.sleep(1)
    content = iam.get_credential_report()["Content"].decode("utf-8")
    return list(csv.DictReader(io.StringIO(content)))


def audit_credential_report(rows: list, now=None) -> list:
    now = _now(now)
    out = []
    for r in rows:
        user = r["user"]
        days = lambda d: (now - d).days
        evidence_base = {"user": user}

        if user == "<root_account>":
            if r.get("access_key_1_active") == "true" or r.get("access_key_2_active") == "true":
                out.append(Finding("IAM-004", user, "Root account has an active access key.", "iam_user", evidence_base))
            if r.get("mfa_active") != "true":
                out.append(Finding("IAM-005", user, "Root account has no MFA device.", "iam_user", evidence_base))
            continue

        console = r.get("password_enabled") == "true"

        if console and r.get("mfa_active") != "true":
            out.append(Finding("IAM-001", user, "Has a console password but no MFA device.", "iam_user", evidence_base))

        if console:                                           # idle console password
            created = _parse_date(r.get("user_creation_time"))
            last = _parse_date(r.get("password_last_used")) or _parse_date(r.get("password_last_changed")) or created
            if last and days(last) >= config.UNUSED_CREDENTIAL_DAYS:
                never = _parse_date(r.get("password_last_used")) is None
                out.append(Finding("IAM-003", user,
                                   f"Console password {'never used' if never else 'unused'} for {days(last)} days.",
                                   "iam_user", {**evidence_base, "kind": "console", "idle_days": days(last)}))

        for n in (1, 2):                                      # access keys 1 and 2
            if r.get(f"access_key_{n}_active") != "true":
                continue
            rotated = _parse_date(r.get(f"access_key_{n}_last_rotated"))
            used = _parse_date(r.get(f"access_key_{n}_last_used_date"))
            if rotated and days(rotated) > config.KEY_MAX_AGE_DAYS:
                out.append(Finding("IAM-002", user, f"Access key {n} is {days(rotated)} days old (limit {config.KEY_MAX_AGE_DAYS}).",
                                   "iam_user", {**evidence_base, "key_index": n, "age_days": days(rotated)}))
            last_key = used or rotated
            if last_key and days(last_key) >= config.UNUSED_CREDENTIAL_DAYS:
                out.append(Finding("IAM-003", user,
                                   f"Access key {n} {'never used' if used is None else 'unused'} for {days(last_key)} days.",
                                   "iam_user", {**evidence_base, "kind": "key", "key_index": n, "idle_days": days(last_key)}))
    return out


def audit_iam(iam, now=None) -> list:
    """Full IAM audit: password policy + credential report."""
    return audit_password_policy(iam) + audit_credential_report(fetch_credential_report(iam), now)
