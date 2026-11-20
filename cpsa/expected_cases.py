"""Expected-vs-actual test cases for the strength engine (used by pytest AND the notebook table)."""
import pandas as pd

from .strength_engine import analyze_password

# name, password, expectations
CASES = [
    ("empty password",          "",                              dict(max_score=0, must_flag=["PW-002"])),
    ("most common password",    "password",                      dict(max_score=0, must_flag=["PW-001"])),
    ("common + suffix",         "Password1!",                    dict(max_score=0, must_flag=["PW-001"])),
    ("leetspeak common",        "p@ssw0rd",                      dict(max_score=0, must_flag=["PW-001"])),
    ("too short",               "aB3$x",                         dict(max_score=1, must_flag=["PW-002"])),
    ("repeated characters",     "aaaaaaaaaaaa",                  dict(max_score=1, must_flag=["PW-004"])),
    ("keyboard walk",           "zxcvbnm,./",                    dict(max_score=1, must_flag=["PW-004"])),
    ("passphrase",              "correct horse battery staple",  dict(min_score=3, must_not_flag=["PW-001", "PW-002", "PW-003"])),
    ("random-looking strong",   "vault-violet-lantern-92-orbit", dict(min_score=3, must_not_flag=["PW-001", "PW-002", "PW-003"])),
    ("unicode strong",          "пароль-Ωmega-🔥-lantern-47",     dict(min_score=3, must_not_flag=["PW-001", "PW-002"])),
    ("very long repetitive",    "a1B2" * 500,                    dict(max_score=1)),
]


def evaluate(case) -> dict:
    name, pw, exp = case
    a = analyze_password(pw, label=name)
    flagged = {f.rule_id for f in a["findings"]}
    problems = []
    if "min_score" in exp and a["score"] < exp["min_score"]: problems.append(f"score {a['score']} < {exp['min_score']}")
    if "max_score" in exp and a["score"] > exp["max_score"]: problems.append(f"score {a['score']} > {exp['max_score']}")
    for r in exp.get("must_flag", []):
        if r not in flagged: problems.append(f"missing {r}")
    for r in exp.get("must_not_flag", []):
        if r in flagged: problems.append(f"unexpected {r}")
    expected = ", ".join(
        [f"score>={exp['min_score']}" if "min_score" in exp else "", f"score<={exp['max_score']}" if "max_score" in exp else "",
         *(f"flag {r}" for r in exp.get("must_flag", [])), *(f"no {r}" for r in exp.get("must_not_flag", []))]).strip(", ").replace(", ,", ",")
    return {"case": name, "length": a["length"], "expected": expected,
            "actual": f"score={a['score']} ({a['rating']}); flags={sorted(flagged) or 'none'}",
            "result": "PASS" if not problems else "FAIL: " + "; ".join(problems)}


def run_expected_vs_actual() -> pd.DataFrame:
    return pd.DataFrame([evaluate(c) for c in CASES])
