import json

from cloudguard.engine import scan_account
from cloudguard.reporting import findings_table
from cloudguard.simulation import CloudGuardSimulation


def test_cloudguard_findings_and_exports_contain_metadata_only():
    marker = "not-used-by-scanner"
    with CloudGuardSimulation() as sim:
        sim.seed_cloudguard_account()
        result = scan_account(sim)
    text = json.dumps([f.to_dict() for f in result["findings"]], default=str)
    text += findings_table(result["findings"]).to_csv()
    assert marker not in text
    assert all(f.status in {"PASS", "FAIL", "UNKNOWN"} for f in result["findings"])
