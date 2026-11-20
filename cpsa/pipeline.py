"""End-to-end pipeline: the data flow between all components in one call.

  access check -> IAM audit -> secrets scan -> per-password: strength -> hash (pepper from
  Secrets Manager) -> store in DynamoDB -> verify -> compliance mapping -> report -> audit log
"""
from importlib import resources

from . import config
from .access_control import check_access
from .audit_logger import AuditLogger
from .iam_auditor import audit_iam
from .report import build_report
from .secrets_scanner import scan_text
from .secure_store import get_pepper, hash_password, list_records, store_hash_record, verify_password
from .strength_engine import analyze_password

# Demo passwords are labelled so reports and logs refer to "demo-user-1", never to the value.
DEMO_PASSWORDS = {
    "demo-user-1": "password123",
    "demo-user-2": "Summer2024!",
    "demo-user-3": "vault-violet-lantern-92-orbit",
}


def sample_code() -> str:
    return (resources.files("cpsa") / "data" / "sample_app.txt").read_text(encoding="utf-8")


def run_full_audit(sim, actor="alice.admin", role="admin", passwords=None, code_text=None,
                   logger=None, algorithm="bcrypt", verbose=True) -> dict:
    logger = logger or AuditLogger()
    passwords = DEMO_PASSWORDS if passwords is None else passwords
    code_text = sample_code() if code_text is None else code_text
    trace = []

    def step(msg):
        trace.append(msg)
        if verbose:
            print(msg)

    if not sim.seeded:
        step("[0] Seeding the simulated (insecure) cloud account ...")
        sim.seed_insecure_account()

    # 1. Authorisation
    for action in ("run_audit", "analyze_password", "scan_secrets", "store_record", "read_pepper"):
        check_access(role, action, actor, logger)
    step(f"[1] Access check passed: {actor} ({role})")

    findings = []

    # 2. IAM audit
    iam_findings = audit_iam(sim.client("iam"))
    findings += iam_findings
    logger.log("iam_audit", actor, role, findings=len(iam_findings))
    step(f"[2] IAM audit: {len(iam_findings)} findings (password policy, MFA, access keys)")

    # 3. Secrets scan
    sec_findings = scan_text(code_text, source="sample_app.txt")
    findings += sec_findings
    logger.log("secrets_scan", actor, role, findings=len(sec_findings))
    step(f"[3] Secrets scan: {len(sec_findings)} hardcoded secrets found (values masked)")

    # 4. Passwords: strength -> hash -> store -> verify
    pepper = get_pepper(sim.client("secretsmanager"))
    table = sim.table()
    stored = []
    for label, pw in passwords.items():
        analysis = analyze_password(pw, label=label)
        findings += analysis["findings"]
        info = hash_password(pw, pepper, algorithm)
        rid = store_hash_record(table, label, info, analysis, actor)
        ok = verify_password(pw, info["hash"], pepper) and not verify_password(pw + "x", info["hash"], pepper)
        stored.append({"subject": label, "record_id": rid, "score": analysis["score"],
                       "rating": analysis["rating"], "algorithm": info["algorithm"], "verified": ok})
        logger.log("password_analyzed", actor, role, subject=label, score=analysis["score"],
                   rule_ids=[f.rule_id for f in analysis["findings"]], stored_record=rid)
        step(f"[4] {label}: {analysis['rating']} (score {analysis['score']}/4) -> hashed with {info['algorithm']} "
             f"-> stored {rid[:8]} -> verify {'OK' if ok else 'FAILED'}")

    # 5. Compliance mapping + report
    report = build_report(findings)
    logger.log("report_generated", actor, role, risk_score=report["risk_score"], findings=len(findings))
    step(f"[5] Report: risk {report['risk_score']}/100 ({report['risk_level']}), {len(findings)} findings mapped to NIST/CIS/ASVS")
    step(f"[6] Audit log: {len(logger.entries)} events recorded; DynamoDB holds {len(list_records(table))} hash records")

    return {"findings": findings, "report": report, "trace": trace, "stored": stored, "logger": logger}
