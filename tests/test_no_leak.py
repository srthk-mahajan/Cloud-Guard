"""The key security test: no raw password or secret may appear in logs, reports, traces or the database."""
import json

from cpsa.audit_logger import AuditLogger, sanitize
from cpsa.pipeline import DEMO_PASSWORDS, run_full_audit
from cpsa.report import render_text, to_csv
from cpsa.secure_store import list_records

SECRETS_IN_SAMPLE = ["AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG", "Sup3rS3cretDbPass", "hunter2hunter2"]


def test_no_raw_password_anywhere(sim, tmp_path):
    logger = AuditLogger(path=str(tmp_path / "audit.jsonl"))
    result = run_full_audit(sim, logger=logger, verbose=False)
    csv_path = to_csv(result["report"], str(tmp_path / "report.csv"))

    haystacks = {
        "audit log (memory)": logger.as_text(),
        "audit log (file)": (tmp_path / "audit.jsonl").read_text(),
        "report text": render_text(result["report"], max_rows=999),
        "report csv": open(csv_path, encoding="utf-8").read(),
        "trace": "\n".join(result["trace"]),
        "findings": json.dumps([f.to_dict() for f in result["findings"]], default=str),
        "dynamodb": json.dumps(list_records(sim.table()), default=str),
    }
    for where, text in haystacks.items():
        for pw in list(DEMO_PASSWORDS.values()) + SECRETS_IN_SAMPLE:
            assert pw not in text, f"raw secret leaked into {where}"


def test_logger_redacts_sensitive_keys_and_values():
    log = AuditLogger()
    e = log.log("test", password="hunter2", note="token AKIAIOSFODNN7EXAMPLE here", nested={"api_key": "abc", "ok": 1})
    text = json.dumps(e)
    assert "hunter2" not in text and "AKIAIOSFODNN7EXAMPLE" not in text and "abc" not in text
    assert e["details"]["nested"]["ok"] == 1


def test_sanitize_handles_odd_types():
    assert sanitize({"x": object(), "y": None, "z": [1, "a"]})["y"] is None
