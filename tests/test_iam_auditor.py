from cpsa.iam_auditor import audit_credential_report, audit_iam, audit_password_policy, fetch_credential_report


def ids(findings, rule, resource=None):
    return [f for f in findings if f.rule_id == rule and (resource is None or f.resource == resource)]


def test_seeded_backdating_worked(sim):
    assert sim.backdating_ok, "moto internals changed: seeded 'old' users/keys would be missing"


def test_policy_problems_found(sim):
    f = audit_password_policy(sim.client("iam"))
    assert ids(f, "PWD-001") and ids(f, "PWD-003") and ids(f, "PWD-005")


def test_missing_mfa_found_for_right_users(sim):
    f = audit_iam(sim.client("iam"))
    assert {x.resource for x in ids(f, "IAM-001")} == {"bob.dev", "carol.finance", "dave.contractor"}
    assert not ids(f, "IAM-001", "alice.admin")


def test_old_and_unused_credentials_found(sim):
    f = audit_iam(sim.client("iam"))
    assert ids(f, "IAM-002", "bob.dev") and ids(f, "IAM-002", "svc-backup")
    assert ids(f, "IAM-003", "carol.finance") and ids(f, "IAM-003", "dave.contractor")


def test_healthy_user_has_no_user_findings(sim):
    f = audit_iam(sim.client("iam"))
    assert not [x for x in f if x.resource == "alice.admin"]


def test_hardening_removes_all_serious_findings(sim):
    sim.harden_account()
    f = audit_iam(sim.client("iam"))
    assert {x.rule_id for x in f} <= {"PWD-005"}      # only the informational note remains


def test_root_account_rows_are_checked():
    rows = [{"user": "<root_account>", "access_key_1_active": "true", "access_key_2_active": "false", "mfa_active": "false"}]
    rules = {f.rule_id for f in audit_credential_report(rows)}
    assert rules == {"IAM-004", "IAM-005"}


def test_credential_report_is_parsed(sim):
    rows = fetch_credential_report(sim.client("iam"))
    assert {r["user"] for r in rows} >= {"alice.admin", "svc-backup"}
