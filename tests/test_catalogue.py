from cloudguard.catalogue import load_catalogue, validate_catalogue


EXPECTED_CLOUDGUARD_RULES = {
    "S3-001", "S3-002", "S3-003",
    "EC2-001", "EC2-002",
    "RDS-001", "RDS-002",
    "IAM-ESC-001",
}


def test_catalogue_has_complete_unique_rule_metadata():
    assert validate_catalogue() == []
    catalogue = load_catalogue()
    rules = {rule_id: rule for rule_id, rule in catalogue.items() if not rule_id.startswith("_")}
    assert set(rules) == EXPECTED_CLOUDGUARD_RULES
    assert all(rule["api_calls"] for rule in rules.values())


def test_legacy_cpsa_rules_are_referenced_without_duplication():
    legacy = load_catalogue()["_legacy_cpsa"]
    assert legacy["source"] == "cpsa.iam_auditor.audit_iam"
    assert legacy["rules"]
