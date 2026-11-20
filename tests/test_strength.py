import pytest

from cpsa.expected_cases import CASES, evaluate
from cpsa.strength_engine import analyze_password, charset_size, load_common_passwords


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_expected_vs_actual(case):
    result = evaluate(case)
    assert result["result"] == "PASS", result


def test_wordlist_loaded():
    assert len(load_common_passwords()) > 1000


def test_empty_and_non_string_inputs():
    assert analyze_password("")["score"] == 0
    for bad in (None, 123, b"bytes", ["a"]):
        with pytest.raises(TypeError):
            analyze_password(bad)


def test_very_long_password_is_fast_and_safe():
    r = analyze_password("Xy7!" * 5000)
    assert r["length"] == 20000


def test_unicode_counts_code_points():
    assert analyze_password("пароль")["length"] == 6
    assert charset_size("пароль") > 0


def test_context_word_flagged():
    r = analyze_password("Acmecorp-lantern-99", user_inputs=["acmecorp"])
    assert "contains context-specific word" in r["patterns"]


def test_result_never_contains_the_password():
    secret = "Tr0ub4dor&3-Unique-Marker"
    assert secret not in repr(analyze_password(secret, label="u1"))
