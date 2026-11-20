"""Load the fixed CloudGuard rule catalogue without network or AI calls."""
import json
from pathlib import Path


REQUIRED_RULE_FIELDS = {
    "id",
    "service",
    "title",
    "severity",
    "api_calls",
    "check_reference",
    "cis",
    "gdpr_dpdp",
    "rationale",
    "remediation",
}


def load_catalogue() -> dict:
    data = json.loads((Path(__file__).parent / "catalogue.json").read_text(encoding="utf-8"))
    catalogue = {rule["id"]: rule for rule in data}
    catalogue["_legacy_cpsa"] = {
        "source": "cpsa.iam_auditor.audit_iam",
        "rules": ["PWD-000", "PWD-001", "PWD-002", "PWD-003", "PWD-004", "PWD-005", "IAM-001", "IAM-002", "IAM-003", "IAM-004", "IAM-005"],
        "note": "Existing CPSA IAM rules remain authoritative and are referenced, not duplicated.",
    }
    return catalogue


def validate_catalogue() -> list[str]:
    """Return catalogue errors without changing the scanner's runtime behavior."""
    data = json.loads((Path(__file__).parent / "catalogue.json").read_text(encoding="utf-8"))
    errors = []
    seen = set()
    for index, rule in enumerate(data):
        prefix = f"rule {index}"
        missing = sorted(REQUIRED_RULE_FIELDS - set(rule))
        if missing:
            errors.append(f"{prefix} is missing: {', '.join(missing)}")
        rule_id = rule.get("id")
        if not rule_id:
            errors.append(f"{prefix} has no id")
        elif rule_id in seen:
            errors.append(f"duplicate rule id: {rule_id}")
        else:
            seen.add(rule_id)
        if not isinstance(rule.get("api_calls"), list) or not rule.get("api_calls"):
            errors.append(f"{prefix} api_calls must be a non-empty list")
    return errors
