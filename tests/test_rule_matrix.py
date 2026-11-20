import pytest

from cloudguard.engine import scan_account
from cloudguard.faults import FaultInjector
from cloudguard.simulation import CloudGuardSimulation


RULE_SERVICES = [
    ("S3-001", "s3"),
    ("S3-002", "s3"),
    ("S3-003", "s3"),
    ("EC2-001", "ec2"),
    ("EC2-002", "iam"),
    ("RDS-001", "rds"),
    ("RDS-002", "rds"),
    ("IAM-ESC-001", "iam"),
]


@pytest.mark.parametrize(("rule_id", "_service"), RULE_SERVICES)
def test_each_rule_has_insecure_positive_and_secure_negative_fixture(rule_id, _service):
    with CloudGuardSimulation() as insecure:
        insecure.seed_cloudguard_account()
        insecure_statuses = {f.status for f in scan_account(insecure)["findings"] if f.rule_id == rule_id}
    with CloudGuardSimulation() as secure:
        secure.seed_cloudguard_account(secure=True)
        secure_statuses = {f.status for f in scan_account(secure)["findings"] if f.rule_id == rule_id}
    assert "FAIL" in insecure_statuses
    assert "PASS" in secure_statuses


@pytest.mark.parametrize(("rule_id", "service"), RULE_SERVICES)
def test_each_rule_has_unknown_collection_edge_case(rule_id, service):
    with CloudGuardSimulation() as sim:
        sim.seed_cloudguard_account()
        findings = scan_account(sim, FaultInjector(kind="access_denied", service=service))["findings"]
    matching = [finding for finding in findings if finding.rule_id == rule_id]
    assert matching
    assert any(finding.status == "UNKNOWN" for finding in matching)
