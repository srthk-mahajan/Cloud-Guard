"""CloudGuard Streamlit dashboard; all cloud calls are handled by moto."""
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from cpsa.access_control import AccessDenied, check_access, policy_json
from cpsa.audit_logger import AuditLogger
from cpsa.compliance_mapper import RULES
from cpsa.expected_cases import run_expected_vs_actual
from cpsa.iam_auditor import audit_iam
from cpsa.pipeline import run_full_audit
from cpsa.report import render_text
from cpsa.secrets_scanner import scan_text
from cpsa.strength_engine import analyze_password, engine_name

from cloudguard.engine import scan_account
from cloudguard.faults import FaultInjector
from cloudguard.attack_paths import find_attack_paths, plotly_figure
from cloudguard.reporting import finding_to_dict, findings_table
from cloudguard.catalogue import load_catalogue
from cloudguard.simulation import CloudGuardSimulation
from cloudguard.history import ScanHistory
from cloudguard.evaluation import evaluate_fixtures
from cloudguard.remediation import apply_remediation


st.set_page_config(page_title="CloudGuard AWS Scanner", layout="wide")
st.title("CloudGuard")
st.caption("Read-only AWS configuration scanner running entirely against a deterministic moto account")
with st.expander("Read-only scope and known limitations"):
    st.markdown(
        "- The scanner collects metadata only; it does not read S3 objects or database records.\n"
        "- It uses a moto in-memory account, not real AWS credentials or network calls.\n"
        "- Rules use the API calls listed in the catalogue. A collection failure is shown as "
        "`UNKNOWN`, never as `PASS`.\n"
        "- Attack paths are inferred configuration relationships, not proof of a reachable network route.\n"
        "- IAM escalation detection covers documented patterns, not every possible AWS policy technique.\n"
        "- Some moto APIs cannot model in-place RDS encryption changes; those remediation actions are "
        "reported as unsupported."
    )
    scope = pd.DataFrame(
        [
            {"Rule": rule["id"], "Service": rule["service"], "Metadata APIs": ", ".join(rule["api_calls"])}
            for rule in load_catalogue().values()
            if "id" in rule
        ]
    )
    st.dataframe(scope, use_container_width=True, hide_index=True)


def _new_simulation(secure=False):
    old = st.session_state.get("cloudguard_sim")
    if old is not None:
        old.stop()
    sim = CloudGuardSimulation().start()
    sim.seed_cloudguard_account(secure=secure)
    st.session_state["cloudguard_sim"] = sim
    for key in (
        "cloudguard_result", "cloudguard_diff", "cpsa_iam_findings",
        "cpsa_pipeline_result",
    ):
        st.session_state.pop(key, None)


def _get_simulation():
    if "cloudguard_sim" not in st.session_state:
        _new_simulation(False)
    return st.session_state["cloudguard_sim"]


with st.sidebar:
    st.header("Account controls")
    if st.button("Create insecure account", use_container_width=True):
        _new_simulation(False)
        st.success("Insecure CloudGuard fixture created.")
    if st.button("Create secure account", use_container_width=True):
        _new_simulation(True)
        st.success("Secure CloudGuard fixture created.")
    if st.button("Reset", use_container_width=True):
        old = st.session_state.pop("cloudguard_sim", None)
        if old is not None:
            old.stop()
        for key in (
            "cloudguard_result", "cloudguard_diff", "cpsa_iam_findings",
            "cpsa_pipeline_result",
        ):
            st.session_state.pop(key, None)
        st.rerun()

    st.header("Fault injection")
    fault_kind = st.selectbox("Collection fault", ["none", "access_denied", "throttle", "timeout"])
    fault_service = st.selectbox("Service", ["s3", "ec2", "rds", "iam"])

sim = _get_simulation()
st.write("**Fixture:**", "secure" if sim.secure_variant else "insecure", "| **Moto state:** active")

if st.button("Run read-only CloudGuard scan", type="primary", use_container_width=True):
    injector = None if fault_kind == "none" else FaultInjector(kind=fault_kind, service=fault_service)
    result = scan_account(sim, injector)
    st.session_state["cloudguard_result"] = result
    history = ScanHistory()
    history.record(result["findings"], result["score"])
    st.session_state["cloudguard_diff"] = history.diff_latest()

result = st.session_state.get("cloudguard_result")
if result:
    score = result["score"]
    metrics = st.columns(5)
    metrics[0].metric("Posture", "n/a" if score["posture"] is None else f"{score['posture']:.1f}%")
    metrics[1].metric("Coverage", f"{score['coverage']:.1f}%")
    metrics[2].metric("Failed", score["failed"])
    metrics[3].metric("Passed", score["passed"])
    metrics[4].metric("Unknown", score["unknown"])
    st.info(f"Risk score: {score['risk_score']}/100. {score['disclaimer']}")
    if st.session_state.get("cloudguard_diff"):
        st.caption("Latest drift: " + json.dumps(st.session_state["cloudguard_diff"]))
    history = ScanHistory()
    trend = history.trend()
    if trend:
        st.line_chart(trend, x="created_at", y="risk_score")
    drift_col, fix_col = st.columns(2)
    if drift_col.button("Simulate drift"):
        sim.simulate_drift()
        st.info("Opened SSH to the internet. Run a scan to record the drift.")
    if fix_col.button("Apply verified remediation"):
        remediation = apply_remediation(sim)
        st.session_state["cloudguard_result"] = remediation["after"]
        history.record(remediation["after"]["findings"], remediation["after"]["score"])
        st.success(
            f"Verified fixed {remediation['fixed']} of {remediation['requested']} requested findings; "
            f"{len(remediation['new_findings'])} new failures."
        )
        st.json(remediation["actions"])
        if remediation["new_findings"]:
            st.warning("Remediation introduced new failures.")
            st.dataframe(remediation["new_findings"], use_container_width=True, hide_index=True)

    table = findings_table(result["findings"])
    st.subheader("Findings")
    if table.empty:
        st.success("The scan returned no findings.")
    else:
        services = st.multiselect("Services", sorted(table["service"].unique()), default=sorted(table["service"].unique()))
        statuses = st.multiselect("Statuses", ["FAIL", "PASS", "UNKNOWN"], default=["FAIL", "UNKNOWN"])
        filtered = table[table["service"].isin(services) & table["status"].isin(statuses)]
        st.dataframe(filtered, use_container_width=True, hide_index=True)

        selected = st.selectbox("Finding detail", list(range(len(result["findings"]))),
                                format_func=lambda i: f"{result['findings'][i].status} | {result['findings'][i].rule_id} | {result['findings'][i].resource}")
        finding = result["findings"][selected]
        detail = finding_to_dict(finding)
        detail_payload = {
            "evidence": detail["evidence"],
            "explanation": detail["rationale"] or detail["detail"],
            "cis": detail["cis"],
            "gdpr_dpdp": detail["gdpr_dpdp"],
            "remediation": detail["remediation"],
        }
        if finding.status == "UNKNOWN":
            rule = load_catalogue().get(finding.rule_id, {})
            detail_payload["unknown_explanation"] = (
                "The scanner could not safely evaluate this rule because required metadata collection "
                "failed. Review the error class and confirm read-only access to the listed APIs."
            )
            detail_payload["required_metadata_apis"] = rule.get("api_calls", [])
            detail_payload["error_class"] = detail["evidence"].get("error_class", "unknown")
        st.json(detail_payload)

    st.download_button("Download CSV", table.to_csv(index=False), "cloudguard_findings.csv", "text/csv")
    st.download_button("Download JSON", json.dumps([finding_to_dict(f) for f in result["findings"]], indent=2),
                       "cloudguard_findings.json", "application/json")

    st.subheader("Rule coverage")
    catalogue_rules = {
        rule["id"]: rule for rule in load_catalogue().values() if "id" in rule
    }
    coverage_rows = []
    for rule_id, rule in catalogue_rules.items():
        matching = [finding for finding in result["findings"] if finding.rule_id == rule_id]
        statuses = sorted({finding.status for finding in matching})
        coverage_rows.append({
            "Rule": rule_id,
            "Service": rule["service"],
            "Evaluated": bool(matching),
            "Statuses": ", ".join(statuses) if statuses else "NOT RETURNED",
            "Metadata APIs": ", ".join(rule["api_calls"]),
        })
    st.dataframe(pd.DataFrame(coverage_rows), use_container_width=True, hide_index=True)

    st.subheader("Attack paths")
    paths = find_attack_paths(result["findings"])
    if paths:
        st.plotly_chart(plotly_figure(result["findings"]), use_container_width=True)
        for path in paths:
            st.write(f"**#{path.rank} {path.severity}: {path.title}**")
            st.caption(" -> ".join(path.nodes) + " | findings: " + ", ".join(path.finding_ids))
    else:
        st.success("No chained internet-to-data path was identified.")

st.subheader("Rule evaluation")
if st.button("Run labelled fixture evaluation"):
    try:
        dashboard_secure = sim.secure_variant
        sim.stop()
        evaluation = evaluate_fixtures()
        sim.start()
        sim.seed_cloudguard_account(secure=dashboard_secure)
        st.dataframe(evaluation["metrics"], use_container_width=True)
    except Exception as exc:
        st.error(f"Fixture evaluation failed: {type(exc).__name__}: {exc}")

st.subheader("Credential hygiene")
st.caption("CPSA modules remain available as the credential-hygiene layer of CloudGuard.")
credential_tabs = st.tabs(["IAM audit", "Password strength", "Secrets scanner", "Audit log"])

with credential_tabs[0]:
    st.markdown("Audit the simulated account's IAM password policy and credential report.")
    if st.button("Run CPSA IAM audit", key="cpsa_iam_audit"):
        try:
            iam_findings = audit_iam(sim.client("iam"))
            iam_report = run_full_audit(sim, verbose=False)["report"] if not sim.seeded else None
            table = pd.DataFrame([finding.to_dict() for finding in iam_findings])
            st.session_state["cpsa_iam_findings"] = iam_findings
            st.dataframe(table, use_container_width=True, hide_index=True)
            if iam_report:
                st.caption("The full credential pipeline report is available after running the pipeline below.")
        except Exception as exc:
            st.error(f"IAM audit failed: {type(exc).__name__}: {exc}")
    if st.button("Run full credential pipeline", key="cpsa_full_pipeline"):
        try:
            pipeline_result = run_full_audit(sim, verbose=False)
            st.session_state["cpsa_pipeline_result"] = pipeline_result
            report = pipeline_result["report"]
            st.metric("CPSA risk score", f"{report['risk_score']}/100")
            st.dataframe(report["table"], use_container_width=True, hide_index=True)
            st.download_button("Download CPSA CSV", report["table"].to_csv(index=False), "cpsa_report.csv", "text/csv")
            with st.expander("CPSA text report"):
                st.code(render_text(report))
        except (AccessDenied, RuntimeError) as exc:
            st.error(f"Credential pipeline failed: {exc}")
    st.expander("Equivalent least-privilege IAM policy").json(policy_json("analyst"))

with credential_tabs[1]:
    st.caption("The password is analyzed in memory and is never logged or stored.")
    password = st.text_input("Password to analyze", type="password", key="cpsa_password")
    context = st.text_input("Context words (optional, comma-separated)", key="cpsa_context")
    if st.button("Check password", key="cpsa_check_password"):
        if not password:
            st.warning("Enter a password to analyze.")
        else:
            context_words = [word.strip() for word in context.split(",") if word.strip()] or None
            analysis = analyze_password(password, label="interactive-input", user_inputs=context_words)
            st.write(f"**{analysis['rating']}** — score {analysis['score']}/4, engine {engine_name()}, length {analysis['length']}")
            st.write("Entropy:", analysis["entropy_bits"], "bits")
            st.write("Patterns:", ", ".join(analysis["patterns"]) or "none")
            for finding in analysis["findings"]:
                st.warning(f"{finding.rule_id}: {finding.detail}")
    with st.expander("Expected versus actual cases"):
        st.dataframe(run_expected_vs_actual(), use_container_width=True, hide_index=True)

with credential_tabs[2]:
    sample_path = Path(__file__).parent / "cpsa" / "data" / "sample_app.txt"
    source_text = st.text_area(
        "Code or configuration to scan",
        value=sample_path.read_text(encoding="utf-8", errors="ignore") if sample_path.exists() else "",
        height=220,
        key="cpsa_secret_text",
    )
    if st.button("Scan for secrets", key="cpsa_scan_secrets"):
        secret_findings = scan_text(source_text, source="cloudguard-ui")
        if secret_findings:
            st.warning(f"{len(secret_findings)} potential secret(s) found; values are masked.")
            st.dataframe(pd.DataFrame([finding.to_dict() for finding in secret_findings]),
                         use_container_width=True, hide_index=True)
        else:
            st.success("No hardcoded secrets detected.")

with credential_tabs[3]:
    pipeline_result = st.session_state.get("cpsa_pipeline_result")
    if pipeline_result is None:
        st.info("Run the full credential pipeline to populate the sanitized audit log.")
    else:
        logger = pipeline_result["logger"]
        st.dataframe(logger.to_dataframe(), use_container_width=True, hide_index=True)
        st.download_button("Download audit log", logger.as_text(), "cpsa_audit_log.jsonl", "application/jsonl")
