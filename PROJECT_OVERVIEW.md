# CloudGuard Project Overview

CloudGuard is an offline AWS security posture scanner built on top of the
original Cloud Password Security Analyzer (CPSA). It combines cloud
configuration auditing with credential-hygiene checks in one demo-friendly
Python project.

The project is designed for a Cloud Security and Compliance course. It
demonstrates how a security scanner can collect cloud metadata, evaluate
security rules, map findings to compliance references, prioritize risks, show
attack paths, apply verified fixes, and track drift over time.

## 1. What the project does

CloudGuard audits a deterministic simulated AWS account and identifies
configuration weaknesses across:

- S3
- EC2
- IAM
- RDS
- Password and credential hygiene
- Hardcoded secrets in source/configuration text

The project creates two account variants:

1. **Insecure account** - intentionally contains realistic security weaknesses.
2. **Secure account** - contains hardened settings for comparison and evaluation.

The scanner returns findings with:

- Rule ID
- Service
- Resource
- Severity
- PASS/FAIL/UNKNOWN status
- Evidence
- Compliance references
- Explanation
- Remediation guidance
- Numeric priority

## 2. What it does not do

CloudGuard is a controlled educational scanner, not a production AWS
assessment platform. It:

- Does not connect to a real AWS account.
- Does not require AWS credentials.
- Does not call real AWS services.
- Does not read S3 object contents.
- Does not read database records.
- Does not store raw passwords or secret keys in reports.
- Does not claim complete CIS, NIST, GDPR, DPDP, or OWASP coverage.
- Is not a legal compliance or certification tool.
- Is not a penetration-testing or exploit framework.
- Does not prove that a real network path is exploitable.
- Does not detect every possible IAM privilege-escalation technique.
- Does not use an LLM, AI service, or machine-learning model.
- Does not guarantee that every moto behavior matches production AWS.

## 3. Technology stack

| Technology | Purpose |
|---|---|
| Python | Main implementation language |
| boto3 | AWS-style API calls |
| moto | Offline in-memory AWS simulation |
| Streamlit | Interactive dashboard |
| pandas | Finding tables and report data |
| NetworkX | Attack-path graph analysis |
| SQLite | Scan history and drift persistence |
| bcrypt | Secure password hashing |
| Argon2 | Alternative secure password hashing |
| pytest | Automated tests |
| JSON | Declarative rule catalogue |
| Jupyter/Colab | Reproducible demonstration notebook |

Dependencies are intentionally installed without exact version pins so the
project remains easier to run on current Python and Colab versions.

## 4. Repository structure

```text
cloud_password_analyzer/
├── app.py
├── CloudGuard_Demo.ipynb
├── CPSA_Demo.ipynb
├── PROJECT_OVERVIEW.md
├── README.md
├── GUIDE.md
├── requirements.txt
├── cloudguard/
│   ├── __init__.py
│   ├── attack_paths.py
│   ├── catalogue.json
│   ├── catalogue.py
│   ├── cli.py
│   ├── collectors.py
│   ├── engine.py
│   ├── evaluation.py
│   ├── faults.py
│   ├── history.py
│   ├── prioritization.py
│   ├── remediation.py
│   ├── reporting.py
│   ├── scoring.py
│   ├── simulation.py
│   └── ...
├── cpsa/
│   ├── access_control.py
│   ├── audit_logger.py
│   ├── cloud_sim.py
│   ├── compliance_mapper.py
│   ├── iam_auditor.py
│   ├── models.py
│   ├── pipeline.py
│   ├── report.py
│   ├── secrets_scanner.py
│   ├── secure_store.py
│   ├── strength_engine.py
│   └── ...
└── tests/
```

## 5. Original CPSA layer

CloudGuard does not replace the original CPSA implementation. It imports and
extends it.

### `cpsa/models.py`

Defines the shared `Finding` dataclass. It originally contained:

- `rule_id`
- `resource`
- `detail`
- `category`
- `evidence`

It was extended backwards-compatibly with:

- `status` - `PASS`, `FAIL`, or `UNKNOWN`
- `service`
- `priority`

The new fields have defaults, so existing CPSA code and tests continue to work.

### `cpsa/cloud_sim.py`

Defines `CloudSimulation`, which:

- Starts and stops one `moto.mock_aws()` environment.
- Creates IAM users and credentials.
- Seeds a weak IAM password policy.
- Creates old access keys and stale accounts.
- Creates a mock DynamoDB table.
- Creates a mock Secrets Manager pepper.
- Provides an existing `harden_account()` demonstration.

The same mock environment can be kept alive while resources are audited,
modified, and audited again.

### `cpsa/iam_auditor.py`

Audits IAM password and credential hygiene through boto3-style calls:

- Minimum password length.
- Password reuse prevention.
- Forced password expiry.
- Console users without MFA.
- Unused console passwords.
- Old access keys.
- Unused access keys.
- Root-account MFA and access-key conditions.

These existing IAM rules remain authoritative. The CloudGuard catalogue
references them instead of duplicating their implementation.

### `cpsa/secrets_scanner.py`

Scans pasted text or files for:

- AWS access-key IDs.
- AWS secret access keys.
- Private-key blocks.
- Passwords in connection strings.
- Hardcoded passwords.
- High-entropy tokens.

Findings contain metadata and masked previews, never complete secret values.

### `cpsa/strength_engine.py`

Analyzes a password without returning the password itself. It checks:

- Length.
- Character-set diversity.
- Estimated entropy.
- Common-password list membership.
- Common-password variants.
- Repeated characters.
- Repeated blocks.
- Keyboard walks.
- Sequential patterns.
- Years and dates.
- Context-specific words.
- Optional `zxcvbn` scoring.

If `zxcvbn` is unavailable, the built-in estimator is used.

### `cpsa/secure_store.py`

Demonstrates safe password storage:

```text
password
  -> HMAC-SHA256 with pepper
  -> bcrypt or Argon2
  -> random salt
  -> hash and metadata stored in DynamoDB
```

The pepper is retrieved from mock Secrets Manager. Plaintext passwords are not
stored in DynamoDB.

### `cpsa/access_control.py`

Provides application-layer roles:

- `admin`
- `analyst`
- `viewer`

For example, a viewer can read reports but cannot run an audit. The module also
generates an equivalent IAM-policy-style document for demonstration.

### `cpsa/audit_logger.py`

Creates JSON audit events and sanitizes sensitive values. It:

- Redacts sensitive dictionary keys.
- Redacts secret-like strings.
- Avoids recording raw passwords and credential values.
- Supports in-memory and file-backed logging.

### `cpsa/compliance_mapper.py`

Maps CPSA rule IDs to:

- Severity.
- NIST SP 800-63B reference.
- CIS AWS reference.
- OWASP ASVS reference.
- Remediation guidance.

These references are traceability aids, not compliance certification.

### `cpsa/report.py`

Converts findings into:

- pandas DataFrames.
- Severity counts.
- Risk score.
- Risk level.
- Clause summaries.
- Text reports.
- CSV exports.

### `cpsa/pipeline.py`

Runs the original CPSA end-to-end flow:

1. Seed the mock account.
2. Check authorization.
3. Audit IAM.
4. Scan sample code for secrets.
5. Analyze demo passwords.
6. Hash and store password metadata.
7. Verify hashes.
8. Build the compliance report.
9. Record audit-log events.

## 6. CloudGuard layer

The new `cloudguard/` package adds broader AWS configuration scanning.

### `cloudguard/simulation.py`

Defines `CloudGuardSimulation`, a subclass of the existing
`CloudSimulation`.

The insecure fixture creates:

- Public S3 access.
- Missing S3 encryption.
- Disabled S3 versioning.
- Internet-open SSH/RDP.
- An EC2 instance with a wildcard role policy.
- A public RDS instance.
- An unencrypted RDS instance.
- An IAM user with an escalation-prone `iam:PassRole` policy.

The secure fixture creates the same general resource layout with hardened
settings.

It also provides `simulate_drift()`, which deliberately opens SSH to the
internet so drift can be demonstrated during a rescan.

### `cloudguard/catalogue.json`

Contains declarative rule definitions. Each rule includes:

- Rule ID.
- Service.
- Title.
- Severity.
- API calls needed.
- Check reference.
- CIS reference.
- GDPR/DPDP informational note.
- Rationale.
- Remediation template.

Current CloudGuard rule families include:

| Rule | Description |
|---|---|
| `S3-001` | Public S3 access |
| `S3-002` | Missing S3 encryption |
| `S3-003` | Disabled S3 versioning |
| `EC2-001` | SSH/RDP open to the internet |
| `EC2-002` | Over-permissive EC2 instance role |
| `RDS-001` | Public RDS instance |
| `RDS-002` | Unencrypted RDS storage |
| `IAM-ESC-001` | IAM privilege-escalation policy patterns (PassRole, policy mutation, service creation, wildcard action/resource) |

### `cloudguard/collectors.py`

Contains read-only service collectors.

The collectors call metadata APIs such as:

- `ListBuckets`
- `GetPublicAccessBlock`
- `GetBucketAcl`
- `GetBucketEncryption`
- `GetBucketVersioning`
- `DescribeSecurityGroups`
- `DescribeInstances`
- `GetInstanceProfile`
- `ListRolePolicies`
- `GetRolePolicy`
- `DescribeDBInstances`
- `ListUsers`
- `ListUserPolicies`
- `GetUserPolicy`

The collector layer also:

- Uses bounded retries.
- Applies exponential backoff for retryable failures.
- Handles AccessDenied.
- Handles throttling.
- Handles timeout-style errors.
- Emits `UNKNOWN` when evaluation is not possible.

### `cloudguard/faults.py`

Provides deterministic fault injection for demos and tests:

- Access denied.
- Throttling.
- Timeout.

This proves that the scanner does not incorrectly report PASS when collection
fails.

### `cloudguard/engine.py`

Orchestrates a complete CloudGuard scan:

1. Collect S3 findings.
2. Collect EC2 findings.
3. Collect RDS findings.
4. Collect IAM escalation findings.
5. Attach catalogue metadata.
6. Calculate finding priorities.
7. Return findings, score data, and the catalogue.

### `cloudguard/scoring.py`

Calculates:

```text
coverage = 100 * evaluated / total
posture  = 100 * passed / (passed + failed)
```

`UNKNOWN` findings are excluded from posture and shown separately. This avoids
the unsafe behavior of treating an unevaluated rule as a pass.

Risk is severity-weighted and capped at 100.

### `cloudguard/prioritization.py`

Calculates:

```text
priority = severity × exposure factor × blast-radius factor
```

Internet-exposed resources receive a larger exposure factor. Wildcard roles,
public buckets, public databases, and escalation policies receive larger
blast-radius factors.

### `cloudguard/attack_paths.py`

Builds a NetworkX resource graph such as:

```text
internet
   |
open security group
   |
EC2 instance
   |
instance role
  / \
S3  RDS
```

The module:

- Creates graph nodes and edges.
- Finds simple paths.
- Lists the finding IDs forming each path.
- Assigns a severity to each path.
- Ranks the paths for display.

This is a deterministic educational graph, not a full AWS reachability
analysis or exploit simulation.

### `cloudguard/remediation.py`

Applies supported fixes through boto3 and rescans the account.

Supported examples:

- Enable S3 public-access-block settings.
- Enable S3 default encryption.
- Enable S3 versioning.
- Remove public SSH/RDP ingress.
- Replace wildcard EC2 role policy.
- Disable public RDS access.
- Remove the demo escalation policy.

The result contains:

- Actions attempted.
- Before-scan result.
- After-scan result.
- Per-finding verification.
- Number fixed.
- Number requested.

RDS storage encryption is reported as `UNSUPPORTED` because moto cannot enable
encryption on an existing RDS instance. The correct real-world remediation is
to create an encrypted replacement and migrate the data.

### `cloudguard/history.py`

Stores scan snapshots in SQLite. Each scan records:

- Timestamp.
- Score.
- Finding statuses.
- Evidence.
- Resource identifiers.

The module classifies:

- New findings.
- Fixed findings.
- Recurring findings.
- Findings changed to UNKNOWN.

It also provides risk-score trend data for the dashboard.

### `cloudguard/evaluation.py`

Runs labelled evaluation against the insecure and secure fixtures. For each
rule, it calculates:

- True positives.
- False positives.
- True negatives.
- False negatives.
- Precision.
- Recall.
- F1 score.

Metrics use safe denominator handling and return `None` where a metric cannot
be calculated.

### `cloudguard/reporting.py`

Converts CloudGuard findings into:

- JSON-compatible dictionaries.
- pandas tables.
- CSV-ready output.

Only metadata, evidence, and remediation text are exported.

### `cloudguard/cli.py`

Provides CloudGuard commands:

```bash
python -m cloudguard.cli scan
python -m cloudguard.cli scan --secure
python -m cloudguard.cli scan --fault access_denied
python -m cloudguard.cli evaluate
```

## 7. Streamlit dashboard

The root [app.py](app.py) provides the UI.

It stores one CloudGuard simulation in `st.session_state` per browser session,
so resources remain available across Streamlit reruns.

The dashboard supports:

- Create insecure account.
- Create secure account.
- Reset the simulation.
- Run a scan.
- Inject service faults.
- Display posture and coverage.
- Display PASS, FAIL, and UNKNOWN counts.
- Filter findings by service and status.
- View evidence and remediation details.
- Download CSV findings.
- Download JSON findings.
- Display interactive Plotly attack-path graphs with hoverable resources.
- Simulate drift.
- Apply verified remediation.
- Display risk-score trends.
- Run fixture evaluation.
- Analyze a password using the CPSA strength engine.

Run it with:

```bash
streamlit run app.py
```

## 8. Complete runtime pipeline

The normal CloudGuard flow is:

1. The user starts the CLI, dashboard, or notebook.
2. `CloudGuardSimulation` starts moto.
3. The simulation seeds an insecure or secure account.
4. The engine obtains boto3 clients for S3, EC2, IAM, and RDS.
5. Read-only collectors request resource metadata.
6. Fault injection may interrupt one service.
7. Retryable errors are retried with bounded backoff.
8. Unrecoverable collection errors become `UNKNOWN`.
9. Successful checks become `PASS` or `FAIL`.
10. The catalogue adds severity, references, rationale, and remediation.
11. Prioritization adds exposure and blast-radius factors.
12. Scoring calculates coverage, posture, unknown count, and risk.
13. Reporting converts findings to tables and downloadable formats.
14. Attack-path analysis creates resource chains from failed findings.
15. History can persist the scan in SQLite.
16. A later scan can be compared for drift.
17. Remediation can change supported settings and rescan to verify fixes.
18. CPSA can separately scan source text, analyze passwords, and demonstrate
    secure hash storage.

## 9. Development history

### Phase 1: Rule engine and coverage

The first development phase focused on the core scanner:

- Extended `Finding` without breaking CPSA.
- Added the JSON rule catalogue.
- Added CloudGuard resource fixtures.
- Added read-only collectors.
- Added retry logic.
- Added explicit UNKNOWN behavior.
- Added fault injection.
- Added coverage, posture, and risk scoring.

The insecure and secure fixtures were tested before adding the UI.

### Phase 2: Dashboard shell

The existing CPSA Streamlit app was replaced with a CloudGuard dashboard that
reused CPSA credential-hygiene functions. The dashboard was tested by:

- Compiling the Python modules.
- Starting Streamlit.
- Requesting the local HTTP endpoint.
- Confirming an HTTP 200 response.

### Phase 3: Attack paths and escalation

NetworkX was added for:

- Security-group-to-instance relationships.
- Instance-to-role relationships.
- Role-to-S3/RDS relationships.
- Ranked internet-to-data paths.

IAM policy inspection was added for patterns such as:

- `iam:PassRole`
- Policy attachment and mutation.
- Access-key creation.
- Wildcard actions.
- Wildcard resources.

### Phase 4: Verified remediation

Remediation was implemented as a before/after workflow:

1. Scan the account.
2. Apply supported boto3 changes.
3. Scan again.
4. Compare finding statuses.
5. Report fixed, unsupported, or failed actions.

Unsupported moto behavior was surfaced instead of being hidden.

### Phase 5: History, drift, and evaluation

SQLite persistence and fixture evaluation were added:

- Scan snapshots.
- Risk trends.
- Recurring findings.
- New findings.
- Fixed findings.
- UNKNOWN transitions.
- Confusion-matrix metrics.

The CLI was then added so the scanner could run without Streamlit.

### Phase 6: Notebook and documentation

`CloudGuard_Demo.ipynb` was added with:

- Unpinned dependency installation.
- Real package import verification.
- Insecure and secure scans.
- Finding tables.
- Fault-injection demonstration.
- Attack-path demonstration.
- Remediation demonstration.
- Optional Streamlit/cloudflared instructions; the notebook launches the quick tunnel when cloudflared is installed.
- Full pytest execution.

The README, GUIDE, and this document describe the architecture, formulas,
limitations, and demo flow.

## 10. Testing strategy

The project uses pytest and retains all original CPSA tests.

The final suite contains 65 tests covering:

- Original CPSA behavior.
- IAM audit findings.
- Password strength edge cases.
- Secret-scanner detection.
- Secure hash storage.
- No-secret logging and reports.
- Secure and insecure CloudGuard fixtures.
- S3, EC2, RDS, and IAM findings.
- AccessDenied fault injection.
- Throttling fault injection.
- Timeout fault injection.
- UNKNOWN status behavior.
- Coverage and posture scoring.
- Priority ranking.
- Attack-path construction.
- IAM escalation detection.
- Verified remediation.
- Unsupported remediation.
- Drift and history.
- Risk trends.
- Ground-truth evaluation metrics.
- Dashboard-compatible reporting.

Tests are behavior-based. They create moto resources, call the actual project
functions, and assert observable states rather than merely checking hardcoded
strings.

The shared `tests/conftest.py` retains the original CPSA fixtures and lowers
hashing costs during tests so the suite completes quickly. Production hash
settings remain higher in `cpsa/config.py`.

Run all tests with:

```bash
python -m pytest -q
```

## 11. Final commands

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the original CPSA demo:

```bash
python -m cpsa.cli demo
```

Run CloudGuard:

```bash
python -m cloudguard.cli scan
python -m cloudguard.cli scan --secure
python -m cloudguard.cli scan --fault access_denied
python -m cloudguard.cli evaluate
```

Run the dashboard:

```bash
streamlit run app.py
```

Run the notebook:

```text
Open CloudGuard_Demo.ipynb and select Runtime > Run all.
```
