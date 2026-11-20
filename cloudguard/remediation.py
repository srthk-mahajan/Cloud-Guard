"""Verified, moto-sandbox-only remediation actions."""
import json

from .engine import scan_account


def _action(rule_id, resource, status, detail):
    return {"rule_id": rule_id, "resource": resource, "status": status, "detail": detail}


def apply_remediation(sim, findings=None) -> dict:
    """Apply safe configuration fixes, rescan, and verify each requested finding."""
    before = scan_account(sim) if findings is None else {"findings": findings}
    actions = []
    s3 = sim.client("s3")
    ec2 = sim.client("ec2")
    iam = sim.client("iam")
    rds = sim.client("rds")
    seen = set()
    for finding in before["findings"]:
        if finding.status != "FAIL" or (finding.rule_id, finding.resource) in seen:
            continue
        seen.add((finding.rule_id, finding.resource))
        try:
            if finding.rule_id == "S3-001":
                s3.put_public_access_block(
                    Bucket=finding.resource,
                    PublicAccessBlockConfiguration={"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                                    "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
                )
                actions.append(_action(finding.rule_id, finding.resource, "APPLIED", "Enabled S3 public access block."))
            elif finding.rule_id == "S3-002":
                s3.put_bucket_encryption(
                    Bucket=finding.resource,
                    ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
                )
                actions.append(_action(finding.rule_id, finding.resource, "APPLIED", "Enabled AES256 default encryption."))
            elif finding.rule_id == "S3-003":
                s3.put_bucket_versioning(Bucket=finding.resource, VersioningConfiguration={"Status": "Enabled"})
                actions.append(_action(finding.rule_id, finding.resource, "APPLIED", "Enabled versioning."))
            elif finding.rule_id == "EC2-001":
                group = ec2.describe_security_groups(GroupIds=[finding.resource])["SecurityGroups"][0]
                for permission in group.get("IpPermissions", []):
                    if permission.get("FromPort") in {22, 3389}:
                        ec2.revoke_security_group_ingress(GroupId=finding.resource, IpPermissions=[permission])
                actions.append(_action(finding.rule_id, finding.resource, "APPLIED", "Removed public SSH/RDP ingress."))
            elif finding.rule_id == "EC2-002":
                role = finding.evidence.get("role")
                if role:
                    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::cloudguard-private/*"}]}
                    iam.put_role_policy(RoleName=role, PolicyName="CloudGuardRolePolicy", PolicyDocument=json.dumps(policy))
                    actions.append(_action(finding.rule_id, finding.resource, "APPLIED", "Replaced wildcard role policy."))
            elif finding.rule_id == "RDS-001":
                rds.modify_db_instance(DBInstanceIdentifier=finding.resource, PubliclyAccessible=False, ApplyImmediately=True)
                actions.append(_action(finding.rule_id, finding.resource, "APPLIED", "Disabled public RDS access."))
            elif finding.rule_id == "RDS-002":
                actions.append(_action(finding.rule_id, finding.resource, "UNSUPPORTED", "Moto cannot enable storage encryption on an existing RDS instance; replace and migrate it."))
            elif finding.rule_id == "IAM-ESC-001" and finding.resource == "cloudguard-escalator":
                iam.delete_user_policy(UserName=finding.resource, PolicyName="PassRole")
                actions.append(_action(finding.rule_id, finding.resource, "APPLIED", "Removed the escalation-prone inline policy."))
        except Exception as exc:
            actions.append(_action(finding.rule_id, finding.resource, "ERROR", type(exc).__name__))
    after = scan_account(sim)
    before_keys = {(f.rule_id, f.resource): f for f in before["findings"]}
    after_keys = {(f.rule_id, f.resource): f for f in after["findings"]}
    verified = []
    for key, old in before_keys.items():
        new = after_keys.get(key)
        verified.append({
            "rule_id": key[0], "resource": key[1],
            "before": old.status, "after": new.status if new else "ABSENT",
            "fixed": old.status == "FAIL" and (new is None or new.status == "PASS"),
        })
    new_findings = [
        {"rule_id": key[0], "resource": key[1], "status": finding.status}
        for key, finding in after_keys.items()
        if key not in before_keys and finding.status == "FAIL"
    ]
    return {"actions": actions, "before": before, "after": after, "verified": verified,
            "fixed": sum(item["fixed"] for item in verified),
            "requested": sum(item["before"] == "FAIL" for item in verified),
            "new_findings": new_findings}
