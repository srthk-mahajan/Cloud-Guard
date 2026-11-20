import pytest

from cloudguard.collectors import _escalation_patterns, collect_s3
from cloudguard.engine import scan_account
from cloudguard.faults import FaultInjector
from cloudguard.simulation import CloudGuardSimulation
from cloudguard.scoring import score_findings


@pytest.fixture
def cloudguard_sim():
    with CloudGuardSimulation() as sim:
        sim.seed_cloudguard_account()
        yield sim


def test_insecure_fixture_has_findings_for_every_cloud_service(cloudguard_sim):
    result = scan_account(cloudguard_sim)
    ids = {finding.rule_id for finding in result["findings"] if finding.status == "FAIL"}
    assert {"S3-001", "S3-002", "S3-003", "EC2-001", "EC2-002", "RDS-001", "RDS-002", "IAM-ESC-001"} <= ids
    assert result["score"]["coverage"] == 100.0
    assert result["score"]["posture"] < 100.0


def test_secure_fixture_has_no_failures():
    with CloudGuardSimulation() as sim:
        sim.seed_cloudguard_account(secure=True)
        result = scan_account(sim)
    assert not [finding for finding in result["findings"] if finding.status == "FAIL"]
    assert result["score"]["posture"] == 100.0
    assert result["score"]["risk_score"] == 0


@pytest.mark.parametrize("kind", ["access_denied", "throttle", "timeout"])
def test_faults_produce_unknown_not_pass(cloudguard_sim, kind):
    result = scan_account(cloudguard_sim, FaultInjector(kind=kind, service="s3"))
    s3_findings = [finding for finding in result["findings"] if finding.service == "s3"]
    assert s3_findings
    assert any(finding.status == "UNKNOWN" for finding in s3_findings)
    assert not all(finding.status == "PASS" for finding in s3_findings)


def test_direct_collector_unknown_contains_error_class(cloudguard_sim):
    findings = collect_s3(cloudguard_sim.client("s3"), FaultInjector(kind="access_denied", service="s3", remaining=99))
    assert all(finding.status == "UNKNOWN" for finding in findings)
    assert all("error_class" in finding.evidence for finding in findings)


def test_score_empty_and_unknown_are_not_false_passes():
    assert score_findings([])["posture"] is None
    with CloudGuardSimulation() as sim:
        sim.seed_cloudguard_account()
        result = scan_account(sim, FaultInjector(kind="access_denied", service="s3", remaining=99))
    assert result["score"]["unknown"] > 0
    assert result["score"]["coverage"] < 100


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("iam:AttachUserPolicy", "action:iam:AttachUserPolicy"),
        ("iam:CreatePolicyVersion", "action:iam:CreatePolicyVersion"),
        ("lambda:CreateFunction", "service-creation:lambda:CreateFunction"),
    ],
)
def test_escalation_patterns_identify_known_actions(action, expected):
    patterns = _escalation_patterns({
        "Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}],
    })
    assert expected in patterns
    assert "wildcard resource" in patterns


def test_escalation_patterns_identify_wildcard_action():
    assert "wildcard action" in _escalation_patterns({
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    })
