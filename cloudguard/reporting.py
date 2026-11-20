"""Safe presentation helpers for CloudGuard findings and exports."""
import json

import pandas as pd


def finding_to_dict(finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "status": finding.status,
        "service": finding.service,
        "severity": getattr(finding, "severity", "MEDIUM"),
        "priority": finding.priority,
        "resource": finding.resource,
        "detail": finding.detail,
        "evidence": finding.evidence,
        "title": getattr(finding, "title", finding.rule_id),
        "cis": getattr(finding, "cis", "Not mapped"),
        "gdpr_dpdp": getattr(finding, "gdpr_dpdp", "Informational only."),
        "rationale": getattr(finding, "rationale", ""),
        "remediation": getattr(finding, "remediation", ""),
    }


def findings_table(findings) -> pd.DataFrame:
    rows = [finding_to_dict(finding) for finding in findings]
    for row in rows:
        row["evidence"] = json.dumps(row["evidence"], sort_keys=True)
    return pd.DataFrame(rows, columns=[
        "status", "severity", "priority", "service", "rule_id", "resource",
        "title", "detail", "evidence", "cis", "gdpr_dpdp", "remediation",
    ])
