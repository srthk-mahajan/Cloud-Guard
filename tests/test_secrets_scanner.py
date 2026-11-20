from cpsa.pipeline import sample_code
from cpsa.secrets_scanner import redact_text, scan_text


def rules(text):
    return {f.rule_id for f in scan_text(text)}


def test_sample_app_secrets_all_found():
    assert rules(sample_code()) == {"SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006"}


def test_clean_code_has_no_findings():
    assert rules('import os\nregion = os.environ["AWS_REGION"]\npassword = os.getenv("DB_PASSWORD")\n') == set()


def test_placeholders_ignored():
    assert rules('password = "<your-password>"\npassword = "${DB_PASS}"') == set()


def test_findings_never_contain_the_secret():
    for f in scan_text(sample_code()):
        blob = repr(f)
        for secret in ("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI", "Sup3rS3cretDbPass", "hunter2hunter2", "9fA2kLmQ8xZpV3nT7wRb1YcD5eHjU0sG"):
            assert secret not in blob


def test_redact_text():
    out = redact_text("id=AKIAIOSFODNN7EXAMPLE pw: password = 'abcd1234'")
    assert "AKIAIOSFODNN7EXAMPLE" not in out and "abcd1234" not in out


def test_empty_input():
    assert scan_text("") == []
