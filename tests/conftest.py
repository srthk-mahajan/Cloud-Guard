import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cpsa import config                      # noqa: E402
from cpsa.cloud_sim import CloudSimulation   # noqa: E402


@pytest.fixture(autouse=True)
def fast_hashing(monkeypatch):
    """Cheap hash settings so the suite runs in seconds. (Production values live in config.py.)"""
    monkeypatch.setattr(config, "BCRYPT_ROUNDS", 4)
    monkeypatch.setattr(config, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(config, "ARGON2_MEMORY_COST", 8)
    monkeypatch.setattr(config, "ARGON2_PARALLELISM", 1)


@pytest.fixture
def sim():
    """One mock AWS account per test, already seeded with the insecure fake company."""
    with CloudSimulation() as s:
        s.seed_insecure_account()
        yield s
