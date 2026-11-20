"""Cloud simulation with moto.

moto intercepts boto3 calls and answers like AWS, in memory: no Docker, no account.
`CloudSimulation` keeps ONE mock alive for the whole run, so everything created
(users, table, secret) is still there when later steps read it.

`seed_insecure_account()` builds a deliberately badly-configured fake company so the
auditor has real problems to find. `harden_account()` fixes them for a before/after demo.
"""
import secrets
from datetime import datetime, timedelta, timezone

import boto3
from moto import mock_aws

from . import config
from .iam_auditor import audit_credential_report, fetch_credential_report

# name, has console password, MFA, access keys as (age_days, last_used_days_ago or None), last console login (days ago or None)
SEED_USERS = [
    dict(name="alice.admin",    console=True,  mfa=True,  keys=[(20, 1)],               login=1,    created=400),
    dict(name="bob.dev",        console=True,  mfa=False, keys=[(200, 3)],              login=2,    created=300),
    dict(name="carol.finance",  console=True,  mfa=False, keys=[],                      login=70,   created=500),
    dict(name="dave.contractor", console=True, mfa=False, keys=[],                      login=None, created=120),
    dict(name="svc-backup",     console=False, mfa=False, keys=[(30, 2), (400, None)],  login=None, created=450),
]


def _naive_utc(days_ago: int = 0) -> datetime:
    """moto stores naive UTC datetimes."""
    return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_ago)


class CloudSimulation:
    def __init__(self, region: str = config.REGION):
        self.region = region
        self._mock = None
        self.seeded = False
        self.backdating_ok = False

    # ---- lifecycle -------------------------------------------------------
    def start(self):
        if self._mock is None:
            self._mock = mock_aws()
            self._mock.start()
        return self

    def stop(self):
        if self._mock is not None:
            self._mock.stop()
            self._mock = None
            self.seeded = False

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    # ---- boto3 handles ---------------------------------------------------
    def client(self, service: str):
        return boto3.client(service, region_name=self.region)

    def resource(self, service: str):
        return boto3.resource(service, region_name=self.region)

    def table(self):
        return self.resource("dynamodb").Table(config.TABLE_NAME)

    # ---- seeding ---------------------------------------------------------
    def seed_insecure_account(self) -> dict:
        iam = self.client("iam")

        # Weak password policy: short minimum, no reuse prevention.
        iam.update_account_password_policy(
            MinimumPasswordLength=6, RequireSymbols=False, RequireNumbers=False,
            RequireUppercaseCharacters=False, RequireLowercaseCharacters=False,
            AllowUsersToChangePassword=False)

        key_ids = {}
        for u in SEED_USERS:
            iam.create_user(UserName=u["name"])
            if u["console"]:
                iam.create_login_profile(UserName=u["name"], Password=secrets.token_urlsafe(18),
                                         PasswordResetRequired=False)
            if u["mfa"]:
                self._enable_mfa(iam, u["name"])
            key_ids[u["name"]] = [iam.create_access_key(UserName=u["name"])["AccessKey"]["AccessKeyId"]
                                  for _ in u["keys"]]

        self.backdating_ok = self._backdate(key_ids)

        # DynamoDB table for hash records + Secrets Manager secret for the pepper.
        self.client("dynamodb").create_table(
            TableName=config.TABLE_NAME,
            KeySchema=[{"AttributeName": "record_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "record_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST")
        self.client("secretsmanager").create_secret(Name=config.PEPPER_SECRET_NAME,
                                                    SecretString=secrets.token_hex(32))
        self.seeded = True
        return {"users": [u["name"] for u in SEED_USERS], "table": config.TABLE_NAME,
                "secret": config.PEPPER_SECRET_NAME, "backdated": self.backdating_ok}

    @staticmethod
    def _enable_mfa(iam, user: str):
        serial = iam.create_virtual_mfa_device(VirtualMFADeviceName=f"{user}-mfa")["VirtualMFADevice"]["SerialNumber"]
        iam.enable_mfa_device(UserName=user, SerialNumber=serial,
                              AuthenticationCode1="123456", AuthenticationCode2="654321")

    def _backdate(self, key_ids: dict) -> bool:
        """The public API cannot create old users/keys, so we set dates on moto's in-memory objects.
        Returns False (and the demo loses its 'old' findings) if a future moto changes these internals."""
        try:
            from moto.iam.models import iam_backends
            account = self.client("sts").get_caller_identity()["Account"]
            backend = iam_backends[account]["global"]
            for u in SEED_USERS:
                user = backend.users[u["name"]]
                user.create_date = _naive_utc(u["created"])
                if u["login"] is not None:
                    user.password_last_used = _naive_utc(u["login"])
                for key, (age, used) in zip(user.access_keys, u["keys"]):
                    key.create_date = _naive_utc(age)
                    key.last_used = _naive_utc(used) if used is not None else None
            return True
        except Exception:
            return False

    # ---- fixing it (before/after demo) -----------------------------------
    def harden_account(self) -> dict:
        iam = self.client("iam")
        iam.update_account_password_policy(
            MinimumPasswordLength=16, RequireSymbols=True, RequireNumbers=True,
            RequireUppercaseCharacters=True, RequireLowercaseCharacters=True,
            AllowUsersToChangePassword=True, PasswordReusePrevention=24)

        actions = {"mfa_enabled": [], "keys_deleted": [], "console_disabled": []}
        snapshot, deleted = {}, set()          # key ids captured once so deleting one key can't shift indexes
        for f in audit_credential_report(fetch_credential_report(iam)):
            user, ev = f.evidence.get("user"), f.evidence
            if f.rule_id == "IAM-001":
                self._enable_mfa(iam, user)
                actions["mfa_enabled"].append(user)
            elif f.rule_id in ("IAM-002", "IAM-003") and "key_index" in ev:
                if user not in snapshot:
                    snapshot[user] = [k["AccessKeyId"] for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]]
                idx = ev["key_index"] - 1
                if idx < len(snapshot[user]) and snapshot[user][idx] not in deleted:
                    iam.delete_access_key(UserName=user, AccessKeyId=snapshot[user][idx])
                    deleted.add(snapshot[user][idx])
                    actions["keys_deleted"].append(f"{user}#{ev['key_index']}")
            elif f.rule_id == "IAM-003" and ev.get("kind") == "console":
                iam.delete_login_profile(UserName=user)
                actions["console_disabled"].append(user)
        return actions
