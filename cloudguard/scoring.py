"""Coverage, posture and severity-weighted CloudGuard scoring."""
SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}


def score_findings(findings: list) -> dict:
    applicable = [f for f in findings if f.status in {"PASS", "FAIL"}]
    passed = sum(f.status == "PASS" for f in applicable)
    failed = sum(f.status == "FAIL" for f in applicable)
    unknown = sum(f.status == "UNKNOWN" for f in findings)
    severities = {f.rule_id: SEVERITY_WEIGHTS.get(getattr(f, "severity", "MEDIUM"), 4) for f in findings}
    # Rule metadata is attached by the engine; unknown severities are conservatively medium.
    risk = min(100, sum(getattr(f, "risk_weight", severities.get(f.rule_id, 4)) for f in findings if f.status == "FAIL"))
    return {
        "evaluated": len(applicable),
        "passed": passed,
        "failed": failed,
        "unknown": unknown,
        "coverage": 100 * len(applicable) / len(findings) if findings else 100.0,
        "posture": 100 * passed / (passed + failed) if passed + failed else None,
        "risk_score": risk,
        "formula": "posture=100*passed/(passed+failed); risk=sum(severity weight*exposure*blast radius), capped at 100",
        "disclaimer": "CloudGuard is an operational scanner, not a certification or legal compliance result.",
    }
