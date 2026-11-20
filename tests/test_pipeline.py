import pytest

from cpsa.access_control import AccessDenied
from cpsa.audit_logger import AuditLogger
from cpsa.cloud_sim import CloudSimulation
from cpsa.compliance_mapper import RULES
from cpsa.pipeline import run_full_audit
from cpsa.report import build_report
from cpsa.secure_store import list_records


def test_pipeline_runs_end_to_end_and_state_persists(sim):
    r = run_full_audit(sim, verbose=False)
    assert len(r["stored"]) == 3 and all(s["verified"] for s in r["stored"])
    assert len(list_records(sim.table())) == 3                       # records still there after the run
    assert r["report"]["risk_score"] > 0 and len(r["trace"]) >= 8


def test_pipeline_seeds_itself():
    with CloudSimulation() as s:
        assert run_full_audit(s, verbose=False)["findings"]


def test_viewer_cannot_run_pipeline(sim):
    log = AuditLogger()
    with pytest.raises(AccessDenied):
        run_full_audit(sim, actor="eve", role="viewer", logger=log, verbose=False)
    assert any(e["outcome"] == "DENIED" for e in log.entries)


def test_every_emitted_rule_is_mapped_to_a_clause(sim):
    r = run_full_audit(sim, verbose=False)
    assert {f.rule_id for f in r["findings"]} <= set(RULES)
    assert all(row.nist_800_63b not in ("", None) for row in r["report"]["table"].itertuples())


def test_report_score_and_empty_report():
    assert build_report([])["risk_score"] == 0
    assert build_report([])["risk_level"] == "LOW"
