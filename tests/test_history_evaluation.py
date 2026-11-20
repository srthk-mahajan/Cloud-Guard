from cloudguard.engine import scan_account
from cloudguard.evaluation import evaluate_fixtures
from cloudguard.history import ScanHistory
from cloudguard.prioritization import prioritize_findings
from cloudguard.simulation import CloudGuardSimulation


def test_history_diff_classifies_new_and_recurring(tmp_path):
    history = ScanHistory(tmp_path / "history.db")
    with CloudGuardSimulation() as sim:
        sim.seed_cloudguard_account()
        first = scan_account(sim)
        history.record(first["findings"], first["score"])
        second = scan_account(sim)
        history.record(second["findings"], second["score"])
    diff = history.diff_latest()
    assert diff["recurring"]
    assert not diff["new"]
    assert history.trend()


def test_priority_is_numeric_and_ranks_exposure():
    with CloudGuardSimulation() as sim:
        sim.seed_cloudguard_account()
        findings = scan_account(sim)["findings"]
    ordered = prioritize_findings(findings)
    assert all(isinstance(finding.priority, (int, float)) for finding in ordered)
    assert ordered[0].priority >= ordered[-1].priority


def test_evaluation_reports_confusion_metrics():
    evaluation = evaluate_fixtures()
    assert evaluation["metrics"]
    assert all({"tp", "fp", "tn", "fn", "precision", "recall", "f1"} <= set(row) for row in evaluation["metrics"].values())


def test_evaluation_can_run_after_dashboard_fixture_is_stopped():
    dashboard = CloudGuardSimulation().start()
    dashboard.seed_cloudguard_account()
    dashboard.stop()

    evaluation = evaluate_fixtures()

    assert evaluation["metrics"]
    dashboard.start()
    dashboard.seed_cloudguard_account()
    dashboard.stop()
