"""Secure storage: peppered + salted slow hashing, and the (mock) DynamoDB record store.

Flow:  password --HMAC-SHA256(pepper)--> fixed-size digest --bcrypt/Argon2 (random salt)--> hash
The pepper lives in Secrets Manager, never in source code. Pre-hashing with HMAC also
sidesteps bcrypt's 72-byte limit, so very long passwords are handled correctly.
Only the hash and metadata are stored. The plaintext is never written anywhere.
"""
import base64
import hashlib
import hmac
import uuid
from datetime import datetime, timezone
from decimal import Decimal

import bcrypt
from argon2 import PasswordHasher

from . import config


def get_pepper(secrets_client, secret_name: str = None) -> str:
    """Fetch the application pepper from Secrets Manager."""
    resp = secrets_client.get_secret_value(SecretId=secret_name or config.PEPPER_SECRET_NAME)
    return resp["SecretString"]


def _prehash(password: str, pepper: str) -> bytes:
    mac = hmac.new(pepper.encode(), password.encode("utf-8", "surrogatepass"), hashlib.sha256).digest()
    return base64.b64encode(mac)                      # 44 bytes, safely under bcrypt's 72-byte limit


def _argon2() -> PasswordHasher:
    return PasswordHasher(time_cost=config.ARGON2_TIME_COST, memory_cost=config.ARGON2_MEMORY_COST,
                          parallelism=config.ARGON2_PARALLELISM)


def hash_password(password: str, pepper: str, algorithm: str = "bcrypt") -> dict:
    """Return {'algorithm','hash','salt','params'}. Each call uses a fresh random salt."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    material = _prehash(password, pepper)
    if algorithm == "bcrypt":
        h = bcrypt.hashpw(material, bcrypt.gensalt(rounds=config.BCRYPT_ROUNDS)).decode()
        return {"algorithm": "bcrypt", "hash": h, "salt": h[7:29], "params": {"cost": config.BCRYPT_ROUNDS}}
    if algorithm == "argon2":
        h = _argon2().hash(material.decode())
        parts = h.split("$")                          # ['', 'argon2id', 'v=19', 'm=..,t=..,p=..', salt, digest]
        return {"algorithm": "argon2id", "hash": h, "salt": parts[4], "params": {"m,t,p": parts[3]}}
    raise ValueError("algorithm must be 'bcrypt' or 'argon2'")


def verify_password(password: str, stored_hash: str, pepper: str) -> bool:
    """True only if the password matches. Never raises on bad input; returns False."""
    try:
        material = _prehash(password, pepper)
        if stored_hash.startswith("$argon2"):
            return bool(_argon2().verify(stored_hash, material.decode()))
        return bcrypt.checkpw(material, stored_hash.encode())
    except Exception:
        return False


def _dec(x):
    return Decimal(str(x)) if isinstance(x, float) else x


def store_hash_record(table, subject: str, hash_info: dict, analysis: dict, actor: str = "system") -> str:
    """Write hash + metadata (no plaintext) to the DynamoDB table. Returns the record id."""
    record_id = uuid.uuid4().hex
    table.put_item(Item={
        "record_id": record_id,
        "subject": subject,                              # a label such as 'demo-user-1', not the password
        "algorithm": hash_info["algorithm"],
        "hash": hash_info["hash"],
        "salt": hash_info["salt"],
        "strength_score": analysis["score"],
        "strength_rating": analysis["rating"],
        "entropy_bits": _dec(analysis["effective_entropy_bits"]),
        "compliance_flags": [f.rule_id for f in analysis["findings"]],
        "stored_by": actor,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    return record_id


def get_record(table, record_id: str):
    return table.get_item(Key={"record_id": record_id}).get("Item")


def list_records(table) -> list:
    return table.scan().get("Items", [])
