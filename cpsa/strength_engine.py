"""Password strength engine.

Combines: length, character diversity, entropy, a common/breached-password list
(SecLists top 10k, bundled so it works offline), pattern detection (repeats,
sequences, keyboard walks, years, leetspeak, context words) and, when it is
installed, zxcvbn. If zxcvbn is missing the built-in estimator is used, so the
tool never hard-fails on a Python version zxcvbn cannot install on.

PRIVACY: the returned dict never contains the password or any slice of it.
"""
import math
import re
import string
from functools import lru_cache
from pathlib import Path

from . import config
from .models import Finding

try:                                    # optional dependency
    from zxcvbn import zxcvbn as _zxcvbn
except Exception:                       # ImportError or build problems
    _zxcvbn = None

LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
_WORDLIST = Path(__file__).parent / "data" / "common_passwords.txt"
_LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "5": "s", "$": "s", "7": "t"})
_KEY_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "qazwsxedc"]


def engine_name() -> str:
    return "zxcvbn" if _zxcvbn else "builtin"


@lru_cache(maxsize=1)
def load_common_passwords() -> frozenset:
    try:
        words = _WORDLIST.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        words = ["123456", "password", "qwerty", "letmein", "admin"]   # tiny fallback
    return frozenset(w.strip().lower() for w in words if w.strip())


def charset_size(pw: str) -> int:
    size = 0
    if any(c in string.ascii_lowercase for c in pw): size += 26
    if any(c in string.ascii_uppercase for c in pw): size += 26
    if any(c in string.digits for c in pw): size += 10
    if any(c in string.punctuation + " " for c in pw): size += 33
    if any(ord(c) > 127 for c in pw): size += 100      # rough allowance for non-ASCII
    return size


def naive_entropy_bits(pw: str) -> float:
    size = charset_size(pw)
    return len(pw) * math.log2(size) if size else 0.0


def _common_match(pw: str):
    """Return 'exact', 'variant' or None for a match against the common-password list."""
    common = load_common_passwords()
    low = pw.lower()
    if low in common:
        return "exact"
    leet = low.translate(_LEET)
    candidates = {
        re.sub(r"[\d\W_]+$", "", low),          # password!!! / password2024
        re.sub(r"[^a-z]+$", "", leet),          # p@ssw0rd1
        leet,
    }
    for c in candidates:
        if len(c) >= 3 and c in common:
            return "variant"
    return None


def _repeat_coverage(pw: str) -> float:
    """Fraction of the password made of a block repeated 3+ times (e.g. 'abcabcabc')."""
    if not pw:
        return 0.0
    return sum(len(m.group(0)) for m in re.finditer(r"(.{1,16}?)\1{2,}", pw)) / len(pw)


def detect_patterns(pw: str, user_inputs=None) -> list:
    """Names of weak patterns found (never the matched text)."""
    found = []
    low = pw.lower()
    if re.search(r"(.)\1{2,}", pw):
        found.append("repeated characters")
    if _repeat_coverage(pw) >= 0.5:
        found.append("repeated block")
    for i in range(len(pw) - 3):                           # 4+ ascending/descending run
        chunk = pw[i:i + 4]
        if all(c.isalnum() for c in chunk):
            d = [ord(chunk[j + 1]) - ord(chunk[j]) for j in range(3)]
            if d in ([1, 1, 1], [-1, -1, -1]):
                found.append("sequence (abcd / 1234)")
                break
    for row in _KEY_ROWS:
        for r in (row, row[::-1]):
            if any(r[i:i + 4] in low for i in range(len(r) - 3)):
                found.append("keyboard walk")
                break
        if "keyboard walk" in found:
            break
    if re.search(r"(19|20)\d{2}", pw):
        found.append("year / date")
    if user_inputs:
        for word in user_inputs:
            w = str(word).lower().strip()
            if len(w) >= 3 and w in low:
                found.append("contains context-specific word")
                break
    return found


def _builtin_score(effective_bits: float, patterns: list) -> int:
    score = 0 if effective_bits < 28 else 1 if effective_bits < 36 else 2 if effective_bits < 60 else 3 if effective_bits < 80 else 4
    return max(0, score - (1 if patterns else 0))


def analyze_password(password: str, label: str = "password", user_inputs=None) -> dict:
    """Analyse one password. `label` is how it is referred to in findings (never the value)."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    length = len(password)
    sample = password[:config.MAX_ANALYZED_CHARS]
    patterns = detect_patterns(sample, user_inputs)
    match = _common_match(sample) if length else None
    entropy = naive_entropy_bits(password)

    guess_bits, crack_time, engine = None, None, "builtin"
    if _zxcvbn and length:
        try:
            z = _zxcvbn(sample, user_inputs=[str(u) for u in (user_inputs or [])])
            guess_bits = round(z["guesses_log10"] * math.log2(10), 1)
            crack_time = z["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
            score, engine = int(z["score"]), "zxcvbn"
        except Exception:
            score = _builtin_score(entropy, patterns)
    else:
        score = _builtin_score(entropy, patterns)
    effective = guess_bits if guess_bits is not None else max(entropy - 12 * len(patterns), 0.0)
    if _repeat_coverage(sample) >= 0.5:      # mostly one repeated block: never better than "Weak"
        score = min(score, 1)
    if match or length == 0:
        score = 0

    findings = []

    def add(rule, detail):
        findings.append(Finding(rule, label, detail, "password_strength", {"score": score, "length": length}))

    if length == 0:
        add("PW-002", "Password is empty.")
    else:
        if match == "exact":
            add("PW-001", "Password appears in the common/breached password list.")
        elif match == "variant":
            add("PW-001", "Password is a trivial variation of a common password (suffix or character swaps).")
        if length < config.MIN_LENGTH_NIST:
            add("PW-002", f"Password is {length} characters; NIST minimum is {config.MIN_LENGTH_NIST}.")
        if score <= 1 and not match and length >= config.MIN_LENGTH_NIST:
            add("PW-003", "Password is easily guessable (low estimated guess count).")
        if patterns:
            add("PW-004", "Predictable patterns found: " + ", ".join(sorted(set(patterns))) + ".")

    return {
        "label": label,
        "length": length,
        "charset_size": charset_size(password),
        "entropy_bits": round(entropy, 1),
        "effective_entropy_bits": round(effective, 1),
        "score": score,
        "rating": LABELS[score],
        "in_common_list": match == "exact",
        "common_variant": match == "variant",
        "patterns": sorted(set(patterns)),
        "crack_time_estimate": crack_time,
        "engine": engine,
        "findings": findings,
    }
