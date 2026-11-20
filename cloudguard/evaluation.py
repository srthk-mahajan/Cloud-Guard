"""Small labelled fixture evaluation with safe denominator handling."""
from .engine import scan_account
from .simulation import CloudGuardSimulation


def ground_truth(simulation_kind="insecure"):
    expected = "FAIL" if simulation_kind == "insecure" else "PASS"
    return {rule_id: expected for rule_id in ("S3-001", "S3-002", "S3-003", "EC2-001", "EC2-002", "RDS-001", "RDS-002", "IAM-ESC-001")}


def evaluate_fixtures():
    rows = []
    sim = CloudGuardSimulation()
    try:
        sim.start()
        for kind, secure in (("insecure", False), ("secure", True)):
            if secure:
                sim.stop()
                sim.start()
            sim.seed_cloudguard_account(secure=secure)
            result = scan_account(sim)
            truth = ground_truth(kind)
            predictions = {}
            for finding in result["findings"]:
                predictions.setdefault(finding.rule_id, finding.status)
                if finding.status == "FAIL":
                    predictions[finding.rule_id] = "FAIL"
            for rule_id, expected in truth.items():
                predicted = predictions.get(rule_id, "UNKNOWN")
                rows.append({"fixture": kind, "rule_id": rule_id, "expected": expected, "predicted": predicted})
    finally:
        sim.stop()
    metrics = {}
    for rule_id in sorted({row["rule_id"] for row in rows}):
        sample = [row for row in rows if row["rule_id"] == rule_id]
        tp = sum(row["expected"] == "FAIL" and row["predicted"] == "FAIL" for row in sample)
        fp = sum(row["expected"] == "PASS" and row["predicted"] == "FAIL" for row in sample)
        fn = sum(row["expected"] == "FAIL" and row["predicted"] != "FAIL" for row in sample)
        tn = sum(row["expected"] == "PASS" and row["predicted"] == "PASS" for row in sample)
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
        metrics[rule_id] = {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "f1": f1}
    return {"rows": rows, "metrics": metrics}
