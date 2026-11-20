from cloudguard.attack_paths import find_attack_paths, graphviz_dot, plotly_figure
from cloudguard.engine import scan_account
from cloudguard.simulation import CloudGuardSimulation


def test_insecure_account_has_ranked_attack_paths():
    with CloudGuardSimulation() as sim:
        sim.seed_cloudguard_account()
        result = scan_account(sim)
    paths = find_attack_paths(result["findings"])
    assert paths
    assert paths[0].rank == 1
    assert any("S3-001" in path.finding_ids or "RDS-001" in path.finding_ids for path in paths)
    assert "digraph CloudGuard" in graphviz_dot(result["findings"])
    assert len(plotly_figure(result["findings"]).data) == 2


def test_secure_account_has_no_chained_paths():
    with CloudGuardSimulation() as sim:
        sim.seed_cloudguard_account(secure=True)
        result = scan_account(sim)
    assert find_attack_paths(result["findings"]) == []
