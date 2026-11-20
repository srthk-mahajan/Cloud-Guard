"""Read-only boto3 collectors with bounded retry and explicit UNKNOWN errors."""
import time
from typing import Callable

from botocore.exceptions import ClientError, BotoCoreError

from cpsa.models import Finding

from .catalogue import load_catalogue


def _call(client, method: str, service: str, faults=None, retries: int = 2, **kwargs):
    for attempt in range(retries + 1):
        try:
            if faults:
                faults.check(service)
            return getattr(client, method)(**kwargs)
        except (ClientError, BotoCoreError) as exc:
            code = exc.response.get("Error", {}).get("Code", type(exc).__name__) if isinstance(exc, ClientError) else type(exc).__name__
            retryable = code in {"Throttling", "ThrottlingException", "RequestTimeout", "InternalError"}
            if retryable and attempt < retries:
                time.sleep(0.02 * (2 ** attempt))
                continue
            raise RuntimeError(f"{type(exc).__name__}:{code}") from exc


def _unknown(rule_id, resource, category, service, error) -> Finding:
    return Finding(rule_id, resource, f"Unable to evaluate {rule_id}; collection failed.", category,
                   {"error_class": str(error).split(":", 1)[0]}, "UNKNOWN", service)


def _finding(rule_id, resource, passed, detail, category, service, evidence=None) -> Finding:
    return Finding(rule_id, resource, detail, category, evidence or {}, "PASS" if passed else "FAIL", service)


def collect_s3(s3, faults=None) -> list[Finding]:
    rules = load_catalogue()
    try:
        buckets = _call(s3, "list_buckets", "s3", faults).get("Buckets", [])
    except RuntimeError as exc:
        return [_unknown(rid, "s3", "s3", "s3", exc) for rid in ("S3-001", "S3-002", "S3-003")]
    out = []
    for bucket in buckets:
        name = bucket["Name"]
        try:
            try:
                pab = _call(s3, "get_public_access_block", "s3", faults, Bucket=name)["PublicAccessBlockConfiguration"]
            except RuntimeError as exc:
                if "NoSuchConfiguration" in str(exc) or "NoSuchPublicAccessBlockConfiguration" in str(exc):
                    pab = {}
                else:
                    raise
            acl = _call(s3, "get_bucket_acl", "s3", faults, Bucket=name)
            public_acl = any(g.get("Grantee", {}).get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers"
                             and g.get("Permission") in {"READ", "FULL_CONTROL"} for g in acl.get("Grants", []))
            blocked = all(pab.get(k, False) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
            safe_public = blocked or not public_acl
            out.append(_finding("S3-001", name, safe_public,
                                "Public access is blocked." if safe_public else "Bucket can be publicly accessed.",
                                "s3", "s3", {"public_access_block": blocked, "public_acl": public_acl}))
            try:
                _call(s3, "get_bucket_encryption", "s3", faults, Bucket=name)
                encrypted = True
            except RuntimeError as exc:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(exc):
                    encrypted = False
                else:
                    raise
            out.append(_finding("S3-002", name, encrypted, "Default encryption is enabled." if encrypted else "Default encryption is not enabled.",
                                "s3", "s3", {"encrypted": encrypted}))
            versioning = _call(s3, "get_bucket_versioning", "s3", faults, Bucket=name).get("Status") == "Enabled"
            out.append(_finding("S3-003", name, versioning, "Versioning is enabled." if versioning else "Versioning is disabled.",
                                "s3", "s3", {"versioning": versioning}))
        except RuntimeError as exc:
            out.append(_unknown("S3-001", name, "s3", "s3", exc))
    return out


def collect_ec2(ec2, iam, faults=None) -> list[Finding]:
    out = []
    try:
        groups = _call(ec2, "describe_security_groups", "ec2", faults).get("SecurityGroups", [])
    except RuntimeError as exc:
        return [_unknown("EC2-001", "security-groups", "ec2", "ec2", exc)]
    for group in groups:
        exposed = []
        for permission in group.get("IpPermissions", []):
            if permission.get("FromPort") in {22, 3389} and any(ip.get("CidrIp") == "0.0.0.0/0" for ip in permission.get("IpRanges", [])):
                exposed.append(permission.get("FromPort"))
        out.append(_finding("EC2-001", group["GroupId"], not exposed,
                            "No SSH/RDP rule is open to the internet." if not exposed else "SSH/RDP is open to 0.0.0.0/0.",
                            "ec2", "ec2", {"open_ports": exposed}))
    try:
        instances = _call(ec2, "describe_instances", "ec2", faults).get("Reservations", [])
        for reservation in instances:
            for instance in reservation.get("Instances", []):
                profile_arn = instance.get("IamInstanceProfile", {}).get("Arn", "")
                profile_name = profile_arn.rsplit("/", 1)[-1] if profile_arn else ""
                if not profile_name:
                    continue
                profile = _call(iam, "get_instance_profile", "iam", faults, InstanceProfileName=profile_name)
                roles = profile.get("InstanceProfile", {}).get("Roles", [])
                role_name = roles[0]["RoleName"] if roles else ""
                if not role_name:
                    out.append(_finding("EC2-002", instance["InstanceId"], True, "Instance profile has no attached role.",
                                        "ec2", "ec2", {"role": None, "wildcard": False}))
                    continue
                policies = _call(iam, "list_role_policies", "iam", faults, RoleName=role_name).get("PolicyNames", [])
                wildcard = False
                for policy_name in policies:
                    doc = _call(iam, "get_role_policy", "iam", faults, RoleName=role_name, PolicyName=policy_name).get("PolicyDocument", {})
                    statements = doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    wildcard = wildcard or any(s.get("Effect") == "Allow" and
                                               ("*" in ([s.get("Action")] if isinstance(s.get("Action"), str) else s.get("Action", [])) or
                                                "*" in ([s.get("Resource")] if isinstance(s.get("Resource"), str) else s.get("Resource", [])))
                                               for s in statements)
                out.append(_finding("EC2-002", instance["InstanceId"], not wildcard,
                                    "Instance role is scoped." if not wildcard else "Instance role contains wildcard permissions.",
                                    "ec2", "ec2", {"role": role_name, "wildcard": wildcard,
                                                   "security_groups": [group["GroupId"] for group in instance.get("SecurityGroups", [])]}))
    except RuntimeError as exc:
        out.append(_unknown("EC2-002", "instances", "ec2", "ec2", exc))
    return out


def collect_rds(rds, faults=None) -> list[Finding]:
    try:
        dbs = _call(rds, "describe_db_instances", "rds", faults).get("DBInstances", [])
    except RuntimeError as exc:
        return [_unknown("RDS-001", "rds", "rds", "rds", exc), _unknown("RDS-002", "rds", "rds", "rds", exc)]
    out = []
    for db in dbs:
        rid = db["DBInstanceIdentifier"]
        public = bool(db.get("PubliclyAccessible"))
        encrypted = bool(db.get("StorageEncrypted"))
        out.append(_finding("RDS-001", rid, not public, "Database is private." if not public else "Database is publicly accessible.",
                            "rds", "rds", {"publicly_accessible": public}))
        out.append(_finding("RDS-002", rid, encrypted, "Storage is encrypted." if encrypted else "Storage encryption is disabled.",
                            "rds", "rds", {"storage_encrypted": encrypted}))
    return out


ESCALATION_ACTIONS = {
    "iam:PassRole",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:CreateRole",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
}

SERVICE_CREATION_ACTIONS = {
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "cloudformation:CreateStack",
    "glue:CreateDevEndpoint",
    "iam:CreateLoginProfile",
}


def _escalation_patterns(doc) -> list[str]:
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    patterns = set()
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        actions = set(actions)
        resources = statement.get("Resource", [])
        resources = [resources] if isinstance(resources, str) else resources
        if "*" in actions:
            patterns.add("wildcard action")
        if "*" in resources:
            patterns.add("wildcard resource")
        patterns.update(f"action:{action}" for action in ESCALATION_ACTIONS.intersection(actions))
        patterns.update(f"service-creation:{action}" for action in SERVICE_CREATION_ACTIONS.intersection(actions))
    return sorted(patterns)


def collect_iam_escalation(iam, faults=None) -> list[Finding]:
    try:
        users = _call(iam, "list_users", "iam", faults).get("Users", [])
    except RuntimeError as exc:
        return [_unknown("IAM-ESC-001", "iam-users", "iam", "iam", exc)]
    out = []
    for user in users:
        name = user["UserName"]
        try:
            policies = _call(iam, "list_user_policies", "iam", faults, UserName=name).get("PolicyNames", [])
            patterns = set()
            for policy_name in policies:
                document = _call(iam, "get_user_policy", "iam", faults, UserName=name, PolicyName=policy_name).get("PolicyDocument", {})
                patterns.update(_escalation_patterns(document))
            risky = bool(patterns)
            out.append(_finding("IAM-ESC-001", name, not risky,
                                "No known privilege-escalation pattern found." if not risky else "User policy permits a privilege-escalation pattern.",
                                "iam", "iam", {"escalation": risky, "patterns": sorted(patterns)}))
        except RuntimeError as exc:
            out.append(_unknown("IAM-ESC-001", name, "iam", "iam", exc))
    return out
