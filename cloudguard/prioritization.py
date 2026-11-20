"""Published severity x exposure x blast-radius prioritization."""
SEVERITY = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def prioritize_findings(findings):
    for finding in findings:
        exposure = 2 if finding.rule_id in {"EC2-001", "S3-001", "RDS-001"} else 1
        blast_radius = 2 if finding.rule_id in {"EC2-002", "IAM-ESC-001", "S3-001", "RDS-001"} else 1
        finding.priority = SEVERITY.get(getattr(finding, "severity", "MEDIUM"), 2) * exposure * blast_radius
        finding.evidence = {**finding.evidence, "exposure_factor": exposure, "blast_radius_factor": blast_radius}
    return sorted(findings, key=lambda finding: (-finding.priority, finding.rule_id, finding.resource))
