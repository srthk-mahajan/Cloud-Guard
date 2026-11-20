import json

import pytest

from cpsa.access_control import AccessDenied, check_access, iam_policy_document, is_allowed
from cpsa.audit_logger import AuditLogger


def test_viewer_is_denied_and_logged():
    log = AuditLogger()
    with pytest.raises(AccessDenied):
        check_access("viewer", "run_audit", actor="eve", logger=log)
    assert log.entries[-1]["outcome"] == "DENIED" and log.entries[-1]["actor"] == "eve"


def test_admin_allowed_and_logged():
    log = AuditLogger()
    check_access("admin", "run_audit", actor="alice", logger=log)
    assert log.entries[-1]["outcome"] == "ALLOWED"


def test_unknown_role_gets_nothing():
    assert not is_allowed("hacker", "view_report")
    with pytest.raises(AccessDenied):
        check_access("hacker", "view_report")


def test_least_privilege_policy():
    assert iam_policy_document("viewer")["Statement"] == []
    actions = iam_policy_document("analyst")["Statement"][0]["Action"]
    assert "dynamodb:PutItem" in actions and "dynamodb:Scan" not in actions     # analyst can't read records back
    json.dumps(iam_policy_document("admin"))                                    # valid JSON
