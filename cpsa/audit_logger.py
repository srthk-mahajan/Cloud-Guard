"""Audit logger: one JSON record per security-relevant event, never a raw secret.

Defence in depth: (1) keys that look sensitive are replaced by [REDACTED],
(2) every string value is passed through the secrets scanner's redactor, and
(3) records are plain data, so the report/tests can inspect them.
"""
import json
import logging
import re
import uuid
from datetime import datetime, timezone

from .secrets_scanner import redact_text

_SENSITIVE_KEY = re.compile(
    r"(^|_)(password|passwd|pwd|secret|token|apikey|api_key|private_key|pepper|hash|secret_access_key)$", re.I)
_log = logging.getLogger("cpsa.audit")


def sanitize(value, key: str = ""):
    if key and _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [sanitize(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(str(value))


class AuditLogger:
    def __init__(self, path=None):
        self.path = path
        self.entries = []

    def log(self, event: str, actor: str = "system", role: str = "-", outcome: str = "OK", **details) -> dict:
        entry = {
            "event_id": uuid.uuid4().hex[:12],
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
            "actor": actor,
            "role": role,
            "outcome": outcome,
            "details": sanitize(details),
        }
        self.entries.append(entry)
        line = json.dumps(entry, default=str)
        _log.info(line)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return entry

    def as_text(self) -> str:
        return "\n".join(json.dumps(e, default=str) for e in self.entries)

    def to_dataframe(self):
        import pandas as pd
        return pd.DataFrame([{**{k: v for k, v in e.items() if k != "details"},
                              "details": json.dumps(e["details"])} for e in self.entries])
