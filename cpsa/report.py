"""Report builder: findings -> risk score, summary tables, CSV and text output."""
from datetime import datetime, timezone

import pandas as pd

from . import config
from .compliance_mapper import enrich


def risk_level(score: int) -> str:
    return "LOW" if score < 20 else "MODERATE" if score < 50 else "HIGH" if score < 80 else "CRITICAL"


def build_report(findings: list, title: str = "Cloud Password Security Report") -> dict:
    rows = enrich(findings)
    cols = ["severity", "rule_id", "category", "resource", "finding", "detail",
            "nist_800_63b", "cis_aws", "owasp_asvs", "remediation"]
    table = pd.DataFrame(rows, columns=cols)
    counts = {s: int((table["severity"] == s).sum()) for s in config.SEVERITY_ORDER}
    score = min(100, sum(config.SEVERITY_WEIGHTS[s] * n for s, n in counts.items()))
    by_clause = (table.groupby("nist_800_63b").size().sort_values(ascending=False)
                 .rename("findings").reset_index()) if len(table) else pd.DataFrame(columns=["nist_800_63b", "findings"])
    return {
        "title": title,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "risk_score": score,
        "risk_level": risk_level(score),
        "counts": counts,
        "table": table,
        "by_clause": by_clause,
    }


def to_csv(report: dict, path: str) -> str:
    report["table"].to_csv(path, index=False)
    return path


def render_text(report: dict, max_rows: int = 40) -> str:
    lines = [report["title"], "=" * len(report["title"]),
             f"Generated : {report['generated_at']}",
             f"Risk score: {report['risk_score']}/100 ({report['risk_level']})",
             "Findings  : " + ", ".join(f"{s}={n}" for s, n in report["counts"].items()), ""]
    for _, r in report["table"].head(max_rows).iterrows():
        lines.append(f"[{r['severity']:<8}] {r['rule_id']}  {r['resource']}")
        lines.append(f"            {r['detail']}")
        lines.append(f"            NIST: {r['nist_800_63b']} | CIS: {r['cis_aws']} | ASVS: {r['owasp_asvs']}")
        lines.append(f"            Fix : {r['remediation']}")
    if len(report["table"]) > max_rows:
        lines.append(f"... {len(report['table']) - max_rows} more (see CSV)")
    return "\n".join(lines)
