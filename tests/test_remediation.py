from cloudguard.remediation import apply_remediation
from cloudguard.simulation import CloudGuardSimulation


def test_remediation_rescans_and_verifies_fixed_findings():
    with CloudGuardSimulation() as sim:
        sim.seed_cloudguard_account()
        result = apply_remediation(sim)
    assert result["requested"] > 0
    assert result["fixed"] >= 6
    assert any(action["status"] == "UNSUPPORTED" for action in result["actions"])
    assert result["after"]["score"]["failed"] < result["before"]["score"]["failed"]
    assert result["new_findings"] == []


def test_secure_fixture_can_simulate_drift():
    with CloudGuardSimulation() as sim:
        sim.seed_cloudguard_account(secure=True)
        sim.simulate_drift()
        result = apply_remediation(sim)
    assert result["before"]["score"]["failed"] >= 1
