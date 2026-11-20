"""Hardcoded-secret scanner (regex + entropy).

It never returns or prints the secret: findings carry only the line number, the
kind of secret and a masked preview. `redact_text` is reused by the audit logger
as a safety net so a secret can't slip into a log line.
"""
import math
import re
from collections import Counter
from pathlib import Path

from .models import Finding

# (rule_id, name, compiled regex, group holding the secret value or 0 for whole match)
PATTERNS = [
    ("SEC-001", "AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("SEC-002", "AWS secret access key",
     re.compile(r"(?i)aws_?secret_?(?:access_?)?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), 1),
    ("SEC-004", "Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), 0),
    ("SEC-006", "Password in connection string", re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:([^\s@/]+)@"), 1),
    ("SEC-003", "Hardcoded password",
     re.compile(r"(?i)\b(?:[a-z_]*pass(?:word|wd)?|pwd)\b\s*[:=]\s*['\"]([^'\"\s]{4,})['\"]"), 1),
]
_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
_PLACEHOLDER = re.compile(r"(?i)^(\$\{.*\}|<.*>|x{4,}|\*{4,}|changeme_?here|your[_-]?password|example)$")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def mask(value: str) -> str:
    """Show only the first 4 characters and the length, e.g. 'AKIA…(20 chars)'."""
    return f"{value[:4]}…({len(value)} chars)"


def _matches(line: str):
    """Yield (rule_id, name, start, end, secret_value) for every secret found in a line."""
    taken = []
    for rule_id, name, rx, grp in PATTERNS:
        for m in rx.finditer(line):
            value = m.group(grp)
            if _PLACEHOLDER.match(value):
                continue
            start, end = m.span(grp)
            if any(s < end and start < e for s, e in taken):    # already reported by an earlier rule
                continue
            taken.append((start, end))
            yield rule_id, name, start, end, value
    for m in _TOKEN.finditer(line):                              # generic high-entropy tokens
        value = m.group(0)
        if any(s < m.end() and m.start() < e for s, e in taken):
            continue
        if (shannon_entropy(value) >= 4.0 and re.search(r"[A-Za-z]", value)
                and re.search(r"\d", value) and "/" not in value[:1]):
            yield "SEC-005", "High-entropy token", m.start(), m.end(), value


def scan_text(text: str, source: str = "<text>") -> list:
    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule_id, name, _s, _e, value in _matches(line):
            findings.append(Finding(
                rule_id, f"{source}:{lineno}", f"{name} found (masked: {mask(value)}).", "secret",
                {"line": lineno, "kind": name}))
    return findings


def scan_file(path) -> list:
    p = Path(path)
    return scan_text(p.read_text(encoding="utf-8", errors="ignore"), source=p.name)


def scan_directory(root, extensions=(".py", ".txt", ".env", ".cfg", ".ini", ".json", ".yml", ".yaml")) -> list:
    findings = []
    for p in sorted(Path(root).rglob("*")):
        if p.is_file() and p.suffix.lower() in extensions and ".git" not in p.parts:
            findings.extend(scan_file(p))
    return findings


def redact_text(text: str) -> str:
    """Replace any detected secret in `text` with a marker. Safe to call on log lines."""
    out = text
    spans = []
    for _rid, name, s, e, _v in _matches(text):
        spans.append((s, e, name))
    for s, e, name in sorted(spans, reverse=True):
        out = out[:s] + f"[REDACTED:{name}]" + out[e:]
    return out
