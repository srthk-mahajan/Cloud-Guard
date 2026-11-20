import pytest

from cpsa.secure_store import (get_pepper, get_record, hash_password, list_records,
                               store_hash_record, verify_password)
from cpsa.strength_engine import analyze_password

PEPPER = "unit-test-pepper"


@pytest.mark.parametrize("algo", ["bcrypt", "argon2"])
def test_hash_verify_roundtrip(algo):
    h = hash_password("correct horse", PEPPER, algo)
    assert verify_password("correct horse", h["hash"], PEPPER)
    assert not verify_password("wrong horse", h["hash"], PEPPER)
    assert not verify_password("correct horse", h["hash"], "other-pepper")


def test_salt_is_random_and_hash_is_not_plaintext():
    a, b = hash_password("same", PEPPER), hash_password("same", PEPPER)
    assert a["hash"] != b["hash"] and a["salt"] != b["salt"]
    assert "same" not in a["hash"]


def test_very_long_and_unicode_passwords_work():
    for pw in ("x" * 10000, "пароль-🔥-Ω", ""):
        h = hash_password(pw, PEPPER)
        assert verify_password(pw, h["hash"], PEPPER)
    # bcrypt alone would ignore everything after 72 bytes; the HMAC pre-hash prevents that
    h = hash_password("a" * 100, PEPPER)
    assert not verify_password("a" * 99 + "b", h["hash"], PEPPER)


def test_verify_never_raises_on_garbage():
    assert verify_password("x", "not-a-hash", PEPPER) is False


def test_bad_inputs_rejected():
    with pytest.raises(TypeError):
        hash_password(None, PEPPER)
    with pytest.raises(ValueError):
        hash_password("x", PEPPER, "md5")


def test_dynamodb_record_has_no_plaintext(sim):
    pepper = get_pepper(sim.client("secretsmanager"))
    table = sim.table()
    pw = "Plaintext-Marker-123!"
    info = hash_password(pw, pepper)
    rid = store_hash_record(table, "u1", info, analyze_password(pw, "u1"), actor="tester")
    item = get_record(table, rid)
    assert pw not in str(item) and item["hash"] == info["hash"]
    assert len(list_records(table)) == 1
