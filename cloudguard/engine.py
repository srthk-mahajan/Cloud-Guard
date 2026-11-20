"""CloudGuard scan orchestration over read-only service collectors."""
from cpsa.models import Finding

from .catalogue import load_catalogue
from .collectors import collect_ec2, collect_iam_escalation, collect_rds, collect_s3
from .scoring import score_findings
from .prioritization import prioritize_findings


def _annotate(findings):
    catalogue = load_catalogue()
    for finding in findings:
        rule = catalogue.get(finding.rule_id, {})
        finding.severity = rule.get("severity", "MEDIUM")
        finding.title = rule.get("title", finding.rule_id)
        finding.cis = rule.get("cis", "Not mapped")
        finding.gdpr_dpdp = rule.get("gdpr_dpdp", "Informational only.")
        finding.remediation = rule.get("remediation", "Review the resource configuration.")
        finding.rationale = rule.get("rationale", "")
        finding.api_calls = rule.get("api_calls", [])
        finding.risk_weight = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}.get(finding.severity, 4)
    return prioritize_findings(findings)


def scan_account(sim, faults=None) -> dict:
    """Scan only metadata and return findings, score, and catalogue coverage."""
    findings = []
    findings.extend(collect_s3(sim.client("s3"), faults))
    findings.extend(collect_ec2(sim.client("ec2"), sim.client("iam"), faults))
    findings.extend(collect_rds(sim.client("rds"), faults))
    findings.extend(collect_iam_escalation(sim.client("iam"), faults))
    findings = _annotate(findings)
    return {"findings": findings, "score": score_findings(findings), "catalogue": load_catalogue()}
