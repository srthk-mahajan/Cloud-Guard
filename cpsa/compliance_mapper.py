"""Compliance mapper: turns raw findings into audit-ready rows.

Every rule the tool can raise is declared once in RULES with a severity, the
NIST SP 800-63B clause it traces to, optional CIS / OWASP cross-references and a
remediation. This is the "each check maps to a clause" requirement.

NOTE: clause numbers follow NIST SP 800-63B (rev 3), CIS AWS Foundations v1.5
and OWASP ASVS 4.0.3. Newer revisions renumber/tighten some items, so check
them against the document versions you cite in your slides.
"""
from dataclasses import dataclass

from . import config
from .models import Finding


@dataclass(frozen=True)
class Rule:
    title: str
    severity: str
    nist: str          # primary framework for this project
    cis: str
    owasp: str
    remediation: str


RULES = {
    # ---- IAM account password policy ----
    "PWD-000": Rule("No custom IAM password policy", "HIGH",
                    "5.1.1.1 Memorized secret authenticators", "1.8", "V2.1.1",
                    "Create an account password policy with a minimum length of 14 or more."),
    "PWD-001": Rule("Minimum password length below NIST minimum (8)", "HIGH",
                    "5.1.1.1 Memorized secret authenticators", "1.8", "V2.1.1",
                    "Raise MinimumPasswordLength to at least 14 (NIST floor is 8)."),
    "PWD-002": Rule("Minimum password length below recommended (14)", "MEDIUM",
                    "5.1.1.1 Memorized secret authenticators", "1.8", "V2.1.1",
                    "Raise MinimumPasswordLength to 14 or more."),
    "PWD-003": Rule("Password reuse prevention missing or too short", "MEDIUM",
                    "5.1.1.2 Memorized secret verifiers (related)", "1.9", "V2.1.10",
                    "Set PasswordReusePrevention to 24."),
    "PWD-004": Rule("Forced periodic password expiry enabled", "LOW",
                    "5.1.1.2 Memorized secret verifiers (SHOULD NOT force periodic change)", "n/a", "V2.1.10",
                    "Drop arbitrary expiry; require a change only on evidence of compromise."),
    "PWD-005": Rule("IAM cannot block common / breached passwords", "INFO",
                    "5.1.1.2 Memorized secret verifiers (blocklist)", "n/a", "V2.1.7",
                    "Screen new passwords against a blocklist (this tool's strength engine) before they are set."),
    # ---- IAM users and keys ----
    "IAM-001": Rule("Console user without MFA", "HIGH",
                    "4.2 Authenticator Assurance Level 2 (two factors)", "1.10", "V2.8.1",
                    "Enable a virtual or hardware MFA device for the user."),
    "IAM-002": Rule("Access key not rotated within 90 days", "MEDIUM",
                    "5.1.1.2 Verifier compromise resistance (related)", "1.14", "V2.10.4",
                    "Create a new key, switch the application over, then delete the old key."),
    "IAM-003": Rule("Credential unused for 45+ days", "MEDIUM",
                    "5.1.1.2 Verifier compromise resistance (related)", "1.12", "V2.10.4",
                    "Disable or delete the unused password or access key."),
    "IAM-004": Rule("Root account has active access keys", "CRITICAL",
                    "4.2 Authenticator Assurance Level 2", "1.4", "V2.10.4",
                    "Delete root access keys; use IAM roles/users instead."),
    "IAM-005": Rule("Root account without MFA", "CRITICAL",
                    "4.2 Authenticator Assurance Level 2", "1.5", "V2.8.1",
                    "Enable MFA on the root account."),
    # ---- Hardcoded secrets ----
    "SEC-001": Rule("AWS access key ID in source", "CRITICAL",
                    "5.1.1.2 Secrets must not be exposed (related)", "1.4", "V2.10.4",
                    "Remove it, rotate the key, load credentials from a vault or environment."),
    "SEC-002": Rule("AWS secret access key in source", "CRITICAL",
                    "5.1.1.2 Secrets must not be exposed (related)", "1.4", "V2.10.4",
                    "Remove it, rotate the key, load credentials from a vault or environment."),
    "SEC-003": Rule("Hardcoded password in source", "HIGH",
                    "5.1.1.2 Secrets must not be exposed (related)", "n/a", "V2.10.4",
                    "Move the password to a secrets manager and rotate it."),
    "SEC-004": Rule("Private key in source", "CRITICAL",
                    "5.1.1.2 Secrets must not be exposed (related)", "n/a", "V2.10.4",
                    "Remove the key, revoke/replace the key pair, store it in a vault."),
    "SEC-005": Rule("High-entropy token or API key in source", "MEDIUM",
                    "5.1.1.2 Secrets must not be exposed (related)", "n/a", "V2.10.4",
                    "Confirm whether it is a live credential; if so move it to a vault and rotate it."),
    "SEC-006": Rule("Password embedded in connection string", "HIGH",
                    "5.1.1.2 Secrets must not be exposed (related)", "n/a", "V2.10.4",
                    "Build the connection string at runtime from a secrets manager."),
    # ---- Password strength ----
    "PW-001": Rule("Password is common / appears in breached-password list", "CRITICAL",
                   "5.1.1.2 Memorized secret verifiers (blocklist)", "n/a", "V2.1.7",
                   "Reject it and ask for a different password."),
    "PW-002": Rule("Password shorter than NIST minimum (8)", "HIGH",
                   "5.1.1.1 Memorized secret authenticators", "1.8", "V2.1.1",
                   "Require at least 8 characters (aim for 12+ or a passphrase)."),
    "PW-003": Rule("Password is easily guessable", "HIGH",
                   "5.1.1.2 Memorized secret verifiers", "n/a", "V2.1.7",
                   "Use a longer, unpredictable password or passphrase."),
    "PW-004": Rule("Password contains predictable patterns", "MEDIUM",
                   "5.1.1.2 Memorized secret verifiers (repetitive / sequential / context words)", "n/a", "V2.1.7",
                   "Avoid repeats, sequences, keyboard walks, dates and personal/context words."),
}

_UNMAPPED = Rule("Unmapped rule", "MEDIUM", "n/a", "n/a", "n/a", "Add this rule to RULES.")


def get_rule(rule_id: str) -> Rule:
    return RULES.get(rule_id, _UNMAPPED)


def enrich(findings: list) -> list:
    """Return one flat dict per finding with severity and compliance references added."""
    rows = []
    for f in findings:
        rule = get_rule(f.rule_id)
        rows.append({
            "severity": rule.severity,
            "rule_id": f.rule_id,
            "category": f.category,
            "resource": f.resource,
            "finding": rule.title,
            "detail": f.detail,
            "nist_800_63b": rule.nist,
            "cis_aws": rule.cis,
            "owasp_asvs": rule.owasp,
            "remediation": rule.remediation,
        })
    rows.sort(key=lambda r: (config.SEVERITY_ORDER.index(r["severity"]), r["rule_id"], r["resource"]))
    return rows
