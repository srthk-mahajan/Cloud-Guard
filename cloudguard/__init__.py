"""CloudGuard: deterministic, read-only AWS configuration scanning on moto."""

__version__ = "0.1.0"

from .engine import scan_account
from .scoring import score_findings

__all__ = ["scan_account", "score_findings"]
