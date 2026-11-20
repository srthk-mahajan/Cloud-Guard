"""Shared data structure: every analyser module returns a list of Finding objects."""
from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    rule_id: str          # key into compliance_mapper.RULES, e.g. "IAM-001"
    resource: str         # what it is about: "bob.dev", "AccountPasswordPolicy", "sample_app.txt:7"
    detail: str           # human readable explanation (never contains a raw secret)
    category: str         # password_policy | iam_user | secret | password_strength
    evidence: dict = field(default_factory=dict)   # small facts such as {"age_days": 200}
    status: str = "FAIL"  # PASS, FAIL, or UNKNOWN; legacy findings remain FAIL
    service: str = "cpsa"
    priority: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)
