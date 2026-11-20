"""Application-layer role checks, modelled on least-privilege IAM policies.

Roles map to allowed actions; every action maps to the AWS API calls it would
need, so `iam_policy_document(role)` can print the equivalent IAM policy (the
"IAM policy as a design artifact" from the project plan). Real AWS enforcement
is not available in the emulator, so the checks happen here, in the app.
"""
import json


class AccessDenied(PermissionError):
    """Raised when a role is not allowed to perform an action."""


ROLE_PERMISSIONS = {
    "admin":   {"run_audit", "analyze_password", "scan_secrets", "store_record",
                "read_records", "read_pepper", "view_report", "view_audit_log"},
    "analyst": {"run_audit", "analyze_password", "scan_secrets", "store_record",
                "read_pepper", "view_report"},
    "viewer":  {"view_report"},
}

ACTION_TO_AWS_APIS = {
    "run_audit": ["iam:GetAccountPasswordPolicy", "iam:GenerateCredentialReport", "iam:GetCredentialReport"],
    "store_record": ["dynamodb:PutItem"],
    "read_records": ["dynamodb:GetItem", "dynamodb:Scan"],
    "read_pepper": ["secretsmanager:GetSecretValue"],
    "view_audit_log": ["logs:GetLogEvents"],
    "analyze_password": [], "scan_secrets": [], "view_report": [],
}


def is_allowed(role: str, action: str) -> bool:
    return action in ROLE_PERMISSIONS.get(role, set())


def check_access(role: str, action: str, actor: str = "unknown", logger=None) -> None:
    """Allow silently or raise AccessDenied. Both outcomes go to the audit log if one is given."""
    allowed = is_allowed(role, action)
    if logger is not None:
        logger.log("access_check", actor=actor, role=role, outcome="ALLOWED" if allowed else "DENIED",
                   action=action)
    if not allowed:
        raise AccessDenied(f"role '{role}' is not allowed to '{action}'")


def iam_policy_document(role: str) -> dict:
    """Equivalent least-privilege IAM policy for a role (documentation artifact)."""
    apis = sorted({api for a in ROLE_PERMISSIONS.get(role, set()) for api in ACTION_TO_AWS_APIS.get(a, [])})
    return {
        "Version": "2012-10-17",
        "Statement": [{"Sid": f"cpsa{role.capitalize()}", "Effect": "Allow", "Action": apis, "Resource": "*"}]
        if apis else [],
    }


def policy_json(role: str) -> str:
    return json.dumps(iam_policy_document(role), indent=2)
