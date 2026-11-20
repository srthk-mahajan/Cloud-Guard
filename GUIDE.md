# Guide: running, demoing and presenting CloudGuard

## 1. The idea in one paragraph
CloudGuard audits the *configuration and credential security of a cloud account*. It reads an AWS-style account
(password policy, users, MFA, access keys), scans code for hardcoded secrets, scores passwords, stores
hashes safely, and turns everything into a report where each finding names a NIST SP 800-63B clause.
The AWS account is a **moto simulation** seeded with deliberate mistakes, so the demo is identical every
time and cannot fail because of wifi or permissions.

## 2. Folder map
```
cloud_password_analyzer/
  CPSA_Demo.ipynb          Colab/Jupyter demo (Run all)
  README.md  GUIDE.md  requirements.txt
  cloudguard/                read-only S3, EC2, IAM and RDS scanner
    catalogue.json           fixed rule metadata and remediation templates
    collectors.py            boto3 metadata collectors and UNKNOWN handling
    engine.py                scan orchestration and annotations
    attack_paths.py          network graph and chained paths
    remediation.py           verified moto-only fixes
    history.py               SQLite scan history and drift
    evaluation.py            labelled fixture metrics
  cpsa/                      existing credential-hygiene modules
    config.py              thresholds and hash costs (change values here)
    models.py              Finding dataclass shared by all modules
    cloud_sim.py           moto mock account: start/stop, seed insecure, harden
    iam_auditor.py         password policy + credential-report checks
    secrets_scanner.py     regex + entropy secret scanner, redaction helper
    strength_engine.py     password scoring (zxcvbn if present, built-in otherwise)
    secure_store.py        pepper, bcrypt/Argon2, DynamoDB records
    compliance_mapper.py   rule -> severity + NIST/CIS/ASVS clause + fix
    access_control.py      roles, AccessDenied, equivalent IAM policy JSON
    audit_logger.py        sanitised JSON audit log
    report.py              risk score, tables, CSV, text report
    pipeline.py            run_full_audit(): the end-to-end data flow
    expected_cases.py      expected-vs-actual strength cases
    cli.py                 python -m cpsa.cli ...
    data/                  10k common passwords, insecure sample code
  tests/                   pytest suite (CloudGuard + CPSA)
```

## 3. Running it
**Colab:** (1) open colab.research.google.com, upload `CPSA_Demo.ipynb`; (2) drag `cloud_password_analyzer.zip`
into the file panel; (3) `Runtime > Run all`. The first cell unzips the project, the next install the packages and
verify them for real (no hardcoded "OK").
If the optional zxcvbn install fails, that is fine: the built-in estimator takes over and the notebook says so.

**Locally:** `pip install -r requirements.txt`, then `python -m pytest -q`,
`python -m cpsa.cli demo`, `python -m cloudguard.cli scan`, or
`python -m cloudguard.cli evaluate`.

## 4. Demo script (about 6 minutes)
1. **Setup cell**: "Packages are verified by importing them, not assumed."
2. **Strength engine** table: weak, patterned and strong passwords, with flags. "NIST says check a blocklist and
   patterns, not composition rules, so `Summer2024!` fails and a passphrase passes."
3. **Simulated cloud**: "moto fakes AWS in memory. We seeded a company with a weak policy, no MFA and stale keys."
4. **IAM audit**: findings table with NIST/CIS columns. Point at one finding per severity.
5. **Secure storage**: show salt, bcrypt vs Argon2, "same password, different hash", then the DynamoDB item with no plaintext.
6. **Secrets scanner**: leaked keys found, values masked.
7. **Access control + audit log**: viewer denied, log line, then the redaction demo.
8. **Pipeline**: the printed trace is the data flow between components.
9. **CloudGuard scan**: show S3 public access, open SSH/RDP, wildcard role, public/unencrypted RDS and IAM escalation. The escalation rule reports known policy-mutation, `PassRole`, service-creation, and wildcard action/resource patterns.
10. **Attack paths and remediation**: explore the interactive Plotly graph, inject an UNKNOWN fault, then verify supported fixes.
11. **Tests**: run the complete pytest suite and show secure/insecure evaluation metrics.

Record a screen capture of a full Run all as a backup in case Colab or wifi fails.

## 5. Rubric mapping (adjust to your sheet)
| Rubric item | Where |
|---|---|
| Module-wise implementation | notebook sections 1-6, one module each |
| Integration / data flow | section 7, `pipeline.run_full_audit` and its trace |
| Testing, expected vs actual | section 9, `tests/`, `expected_cases.py` |
| Final demo, repo, slides | notebook + GitHub repo + the screen recording |
| Cloud security aspects | IAM audit, Secrets Manager pepper, DynamoDB hash store, role checks, audit log, NIST mapping |

## 6. Honest limits (say them before someone asks)
- **Simulated cloud.** The data is fake; the audit logic is real boto3 and would work on a real account that allows
  `iam:GetAccountPasswordPolicy`, `iam:GenerateCredentialReport`, `iam:GetCredentialReport`. AWS Academy Learner Lab
  blocks IAM, which is why the demo uses moto.
- **Backdating.** The AWS API cannot create old users or keys, so `cloud_sim.py` sets dates on moto's internal objects.
  A test (`test_seeded_backdating_worked`) fails loudly if a future moto version breaks this.
- **Access control is app-layer.** The emulator does not enforce IAM; `iam_policy_document()` prints the equivalent policy.
- **Milestone 1 said LocalStack.** The plan changed to moto. State it in one line ("we used moto after confirming
  with our instructor") and get that confirmation in writing.
- **Risk score** is a simple weighted sum capped at 100, so it saturates on very bad accounts. It is a demo metric, not a standard.
- **UNKNOWN is not PASS.** AccessDenied, throttling, timeout, and unsupported operations reduce coverage and remain visible.
- **Moto limitations.** Existing RDS storage encryption cannot be enabled in place; CloudGuard reports this honestly instead of fabricating a fix.
- **Remediation verification.** The remediation result records fixed original findings, unsupported actions, errors, and any new FAIL findings introduced by the rescan.

## 7. Check before you present
- **Clause numbers.** Mappings use NIST SP 800-63B rev 3, CIS AWS Foundations v1.5 and OWASP ASVS 4.0.3. Newer
  revisions renumber and tighten items (NIST rev 4 raises minimum lengths), so open the documents you cite and confirm
  each number in `compliance_mapper.py`. Edit `RULES` there; nothing else needs to change.
- **Milestone 2 notebook.** It still claims a Docker/LocalStack setup, pinned versions that did not install, and a
  hardcoded OK checklist. Replace it with this notebook's setup section or delete those lines.
- **Thresholds** (8/14 characters, 90/45 days, 24 reuse) live in `config.py`. Justify them in the slides.

## 8. Adding a web UI later
All modules return plain data, so a UI is a thin layer. Streamlit sketch (`app.py`):
```python
import streamlit as st
from cpsa.cloud_sim import CloudSimulation
from cpsa.pipeline import run_full_audit
sim = st.session_state.setdefault("sim", CloudSimulation().start())   # keep ONE mock alive per session
if st.button("Run audit"):
    r = run_full_audit(sim, verbose=False)
    st.metric("Risk score", r["report"]["risk_score"]); st.dataframe(r["report"]["table"])
```
Gradio works the same way and runs natively inside Colab with `launch(share=True)`.

## 9. Suggested team split
Strength engine + tests | IAM auditor + cloud simulation | Secrets scanner + compliance mapping | Pipeline, CLI, notebook, slides.
