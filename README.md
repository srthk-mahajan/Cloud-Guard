# CloudGuard: offline AWS security posture scanner

CloudGuard is an educational, deterministic AWS configuration scanner built
on top of the original **Cloud Password Security Analyzer (CPSA)** project.
It demonstrates how a security tool can collect cloud metadata, evaluate
security rules, preserve `UNKNOWN` results when collection fails, prioritize
risks, visualize attack paths, verify remediation, track drift, and expose
credential-hygiene checks through one dashboard.

The project is intentionally offline:

- AWS is represented by [`moto`](https://github.com/getmoto/moto), an
  in-memory AWS API simulator.
- The scanner uses ordinary `boto3` calls against that simulator.
- No AWS account, AWS credentials, Docker, LocalStack, LLM, AI service, or
  paid service is required.
- The demo never reads S3 object contents or database records.

This is a course/capstone demonstration, not a production AWS assessment
platform or a legal compliance certification tool.

---

## 1. Quick verification first

Run these commands from the project directory:

```powershell
cd C:\Users\saart\Desktop\GroupNumber_6
python -m pip install -r requirements.txt
python -m pytest -q
python -m compileall -q app.py cloudguard cpsa
```

Expected result:

```text
87 passed
```

Then verify the two CloudGuard fixture variants:

```powershell
python -m cloudguard.cli scan --secure
python -m cloudguard.cli scan
```

The secure scan should report:

- 17 evaluated findings;
- 17 passed;
- 0 failed;
- 0 unknown;
- 100% coverage;
- 100% posture;
- risk score `0`.

The insecure scan should contain failures for S3, EC2, RDS, and IAM
privilege-escalation checks.

Run the labelled evaluation:

```powershell
python -m cloudguard.cli evaluate
```

The deterministic insecure/secure fixtures are expected to produce
precision, recall, and F1 values of `1.0` for the current rule set. These are
fixture metrics, not production detection accuracy.

Test explicit failure handling:

```powershell
python -m cloudguard.cli scan --fault access_denied
python -m cloudguard.cli scan --fault throttle
python -m cloudguard.cli scan --fault timeout
```

These commands demonstrate that collection failures become `UNKNOWN`, never
`PASS`.

The CLI creates `cloudguard_history.db` when a scan is run. It is a local
demo artifact and is ignored by Git. Delete it whenever a clean history
demonstration is needed:

```powershell
Remove-Item .\cloudguard_history.db -ErrorAction SilentlyContinue
```

### What the dashboard means by UNKNOWN

`UNKNOWN` is deliberately different from both `PASS` and `FAIL`. It means the
scanner could not collect the metadata needed to evaluate a rule, for example
because of an access-denied, throttling, timeout, or unsupported-API error.
CloudGuard never converts that situation into a pass. The finding detail panel
shows the error class and the catalogue's required metadata APIs so the result
can be investigated.

The dashboard's **Read-only scope and known limitations** panel lists the
metadata API calls used by every CloudGuard rule. These calls describe the
scanner's intended read-only scope; the current application still runs only
against moto. The panel also states the important simulation limitations,
including inferred attack paths, known IAM-pattern coverage, and unsupported
in-place RDS encryption remediation.

---

## 2. Install and environment setup

### Requirements

- Python 3.10 or newer;
- pip;
- Windows, macOS, Linux, or Google Colab;
- internet only for installing Python packages, not for scanning.

Create an optional virtual environment:

```powershell
cd C:\Users\saart\Desktop\GroupNumber_6
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

The important dependencies are:

| Package | Purpose |
|---|---|
| `boto3` | AWS-style client API used by collectors and CPSA |
| `moto` | In-memory AWS simulation |
| `pandas` | Finding tables, reports, and CSV data |
| `networkx` | Attack-path graph construction |
| `plotly` | Interactive dashboard graph |
| `streamlit` | Web dashboard |
| `bcrypt` | Password hashing option |
| `argon2-cffi` | Alternative password hashing option |
| `pytest` | Automated tests |
| `zxcvbn` | Optional password-strength engine enhancement |

Dependencies are intentionally not pinned to exact versions so the project
can run on current Python and Colab environments. If `zxcvbn` is unavailable,
CPSA automatically uses its built-in estimator.

---

## 3. What the project contains

```text
GroupNumber_6/
├── app.py                         Combined Streamlit dashboard
├── cloudguard/                    Cloud posture scanner
│   ├── attack_paths.py            NetworkX paths + Plotly figure
│   ├── catalogue.json             Declarative CloudGuard rules
│   ├── catalogue.py               Catalogue loader
│   ├── cli.py                     CloudGuard CLI
│   ├── collectors.py              S3/EC2/IAM/RDS metadata collectors
│   ├── engine.py                  Scan orchestration
│   ├── evaluation.py              Fixture evaluation metrics
│   ├── faults.py                  Deterministic failure injection
│   ├── history.py                 SQLite history and drift
│   ├── prioritization.py          Exposure/blast-radius ordering
│   ├── remediation.py             Verified moto-only fixes
│   ├── reporting.py               JSON/table conversion
│   ├── scoring.py                 Coverage/posture/risk calculations
│   └── simulation.py              CloudGuard moto fixture
├── cpsa/                          Credential-hygiene layer
│   ├── access_control.py          Application roles and policy artifact
│   ├── audit_logger.py            Sanitized JSON audit events
│   ├── cloud_sim.py               Shared moto account lifecycle
│   ├── compliance_mapper.py       CPSA compliance mappings
│   ├── iam_auditor.py             IAM policy and credential auditing
│   ├── pipeline.py                End-to-end CPSA pipeline
│   ├── report.py                  CPSA report and CSV output
│   ├── secrets_scanner.py         Hardcoded-secret detection
│   ├── secure_store.py            Pepper + bcrypt/Argon2 storage demo
│   └── strength_engine.py         Password analysis
├── tests/                         CloudGuard and CPSA tests
├── CloudGuard_Demo.ipynb          CloudGuard notebook
├── CPSA_Demo.ipynb                Original CPSA notebook
├── GUIDE.md                       Presentation and demo guide
├── HOW_TO_RUN.md                  Short operational guide
└── PROJECT_OVERVIEW.md            Detailed architecture and scope
```

---

## 3. Requirements coverage and honest scope

The current implementation intentionally targets the safe, deterministic
CloudGuard MVP rather than every feature proposed for a production platform.

| Capability | Status | Where to verify |
|---|---|---|
| S3, EC2, IAM, and RDS metadata scanning | Implemented | `cloudguard/collectors.py` |
| Declarative rules and fixed remediation text | Implemented | `cloudguard/catalogue.json` |
| PASS/FAIL/UNKNOWN handling | Implemented | `cloudguard/collectors.py`, fault tests |
| Bounded retries and fault injection | Implemented | `cloudguard/collectors.py`, `cloudguard/faults.py` |
| Coverage, posture, and severity-weighted risk | Implemented | `cloudguard/scoring.py` |
| Interactive attack-path graph | Implemented | `cloudguard/attack_paths.py`, dashboard |
| Moto-only verified remediation | Implemented | `cloudguard/remediation.py` |
| SQLite scan history and drift | Implemented | `cloudguard/history.py` |
| Fixture evaluation with classification metrics | Implemented | `cloudguard/evaluation.py` |
| CPSA credential-hygiene integration | Implemented | `cpsa/`, dashboard credential tabs |
| Real AWS scanning | Not in scope | The application is deliberately moto-only |
| AI/LLM remediation | Not in scope | Remediation uses fixed catalogue templates |
| Exhaustive IAM privilege-escalation analysis | Partial | Known patterns are documented; coverage is not exhaustive |
| Formal legal or CIS certification | Not provided | CIS/GDPR/DPDP mappings are informational |

The dashboard's Rule coverage table shows whether each catalogue rule was
returned by the current scan and which status it received. The catalogue
validation tests also ensure each current rule has the required descriptive
metadata and at least one declared read-only API call.

## 4. Run every major function

### 4.1 CloudGuard command line

Run the insecure fixture:

```powershell
python -m cloudguard.cli scan
```

Run the hardened comparison fixture:

```powershell
python -m cloudguard.cli scan --secure
```

Inject a collection fault into the S3 collector:

```powershell
python -m cloudguard.cli scan --fault access_denied
python -m cloudguard.cli scan --fault throttle
python -m cloudguard.cli scan --fault timeout
```

Use a custom history file:

```powershell
python -m cloudguard.cli scan --history .\demo_history.db
```

Evaluate the labelled fixtures:

```powershell
python -m cloudguard.cli evaluate
```

The CloudGuard CLI prints JSON containing the score and serialized findings.

### 4.2 CPSA command line

Run the original full credential pipeline:

```powershell
python -m cpsa.cli demo
```

Run the IAM audit and demonstrate hardening:

```powershell
python -m cpsa.cli audit
python -m cpsa.cli audit --harden
```

Analyze a password. Omitting `--password` is safer because it prompts without
echoing the value:

```powershell
python -m cpsa.cli strength
```

Scan a file for hardcoded secrets:

```powershell
python -m cpsa.cli scan cpsa/data/sample_app.txt
```

Write a CPSA report to CSV:

```powershell
python -m cpsa.cli scan cpsa/data/sample_app.txt --csv .\secrets_report.csv
```

Print the equivalent least-privilege policy for a role:

```powershell
python -m cpsa.cli policy --role analyst
python -m cpsa.cli policy --role viewer
```

Demonstrate application-layer authorization:

```powershell
python -m cpsa.cli audit --role viewer
```

The viewer role is denied operations it is not allowed to perform. This is
application-level authorization; it is not real AWS IAM enforcement.

### 4.3 Streamlit dashboard

Start the dashboard:

```powershell
streamlit run app.py
```

Open the displayed local URL, normally:

```text
http://localhost:8501
```

Use the dashboard in this order:

1. Select **Create insecure account**.
2. Select **Run read-only CloudGuard scan**.
3. Review posture, coverage, failed/passed/unknown counts, and risk.
4. Filter findings by service and status.
5. Select a finding to inspect evidence, rationale, compliance notes, and
   remediation.
6. Download JSON or CSV results.
7. Explore the interactive Plotly attack-path graph with hover and zoom.
8. Select **Simulate drift**, then scan again.
9. Select **Apply verified remediation** and inspect the before/after result.
10. Run **labelled fixture evaluation**.
11. Use the **Credential hygiene** tabs for CPSA IAM audit, password analysis,
    secret scanning, audit logs, and the full credential pipeline.
12. Repeat with **Create secure account** to compare the hardened fixture.

The dashboard keeps one moto account in `st.session_state` so its resources
survive Streamlit reruns during one browser session.

### 4.4 Notebooks

Run the CloudGuard notebook:

```powershell
jupyter notebook CloudGuard_Demo.ipynb
```

Use **Run All**. It verifies imports, creates fixtures, scans them, displays
findings, demonstrates faults, attack paths, remediation, and evaluation.

Run the original CPSA notebook:

```powershell
jupyter notebook CPSA_Demo.ipynb
```

The optional final CloudGuard notebook cell starts Streamlit and launches a
Cloudflare quick tunnel when the `cloudflared` executable is available. If it
is not available, the cell prints the official installation link instead of
silently failing.

---

## 5. Function-by-function verification

The automated suite is the authoritative verification path:

```powershell
python -m pytest -q
```

The tests cover:

| Functionality | Test coverage |
|---|---|
| S3 public access, encryption, versioning | insecure/secure/UNKNOWN matrix |
| EC2 open SSH/RDP and wildcard role | insecure/secure/UNKNOWN matrix |
| RDS public access and encryption | insecure/secure/UNKNOWN matrix |
| IAM escalation patterns | action-pattern tests and fixture matrix |
| Access denied, throttle, timeout | fault-injection tests |
| Score formulas and empty/unknown scans | scoring tests |
| Attack paths | ranked path and Plotly graph tests |
| Remediation | before/after verification and new-finding reporting |
| History and drift | SQLite history tests |
| Fixture evaluation | TP/FP/TN/FN and metric tests |
| Password strength | length, entropy, patterns, common passwords |
| Secret scanning | AWS keys, passwords, private keys, tokens |
| Secure storage | pepper, bcrypt, Argon2, verification |
| Access control | allowed/denied roles and policy documents |
| Secret leakage prevention | reports, logs, traces, and storage |

The explicit rule matrix tests each current CloudGuard rule against:

1. an insecure fixture where it should fail;
2. a secure fixture where it should pass;
3. a collection-failure case where it should become unknown.

For a complete local verification pass:

```powershell
python -m pytest -q
python -m compileall -q app.py cloudguard cpsa
python -m cloudguard.cli scan --secure
python -m cloudguard.cli scan
python -m cloudguard.cli evaluate
python -m cpsa.cli demo
```

---

## 6. How CloudGuard works internally

### 6.1 Simulation and seeding

`CloudGuardSimulation` extends CPSA's `CloudSimulation`. It starts one
`moto.mock_aws()` environment and seeds:

- two S3 buckets;
- an EC2 VPC, subnet, instance, security group, instance profile, and role;
- an RDS instance;
- an IAM escalation-test user;
- the original CPSA IAM users, access keys, DynamoDB table, and pepper secret.

The insecure fixture deliberately creates public or weak settings. The secure
fixture creates the same general resource layout with hardened settings.

Moto cannot create genuinely old AWS users or keys through normal public APIs,
so CPSA's existing simulator backdates moto's in-memory objects for the
credential-report demonstration. This is explicitly a test fixture technique,
not a real AWS operation.

### 6.2 Collection

`cloudguard.collectors` uses read-only metadata calls:

- S3: list buckets, public-access block, ACL, encryption, versioning;
- EC2: security groups, instances, instance profiles;
- IAM: role policies, user policies, escalation patterns;
- RDS: instance accessibility and storage encryption metadata.

Collectors do not read object contents or database records.

Calls are wrapped by bounded retry logic. Retryable throttling/timeouts use a
short exponential backoff. Access denied, exhausted retries, and unsupported
collection are represented as `UNKNOWN` findings with an error class in
evidence.

### 6.3 Rule evaluation

The rule definitions live in `cloudguard/catalogue.json`. Each rule includes:

- rule ID;
- service;
- title;
- severity;
- required API calls;
- check reference;
- CIS benchmark reference where applicable;
- GDPR/DPDP informational note;
- rationale;
- remediation template.

The current CloudGuard rule families are:

| Rule | Check |
|---|---|
| `S3-001` | Public S3 access |
| `S3-002` | Missing S3 default encryption |
| `S3-003` | Disabled S3 versioning |
| `EC2-001` | Internet-open SSH or RDP |
| `EC2-002` | Wildcard or over-permissive EC2 role |
| `RDS-001` | Public RDS instance |
| `RDS-002` | Unencrypted RDS storage |
| `IAM-ESC-001` | Known IAM privilege-escalation patterns |

`IAM-ESC-001` checks patterns including `iam:PassRole`, policy mutation,
policy attachment, role-policy changes, service creation, wildcard actions,
and wildcard resources. It is a known-pattern detector, not an exhaustive
proof of every possible AWS escalation chain.

### 6.4 Finding model

Every CloudGuard finding is a CPSA `Finding` object extended with:

- `status`: `PASS`, `FAIL`, or `UNKNOWN`;
- `service`: for example `s3`, `ec2`, `iam`, or `rds`;
- `priority`: numeric risk ordering;
- evidence: small metadata facts, never raw credentials.

Legacy CPSA findings remain backwards compatible and default to `FAIL`.

### 6.5 Scoring

CloudGuard reports:

```text
coverage = 100 * evaluated / total
posture  = 100 * passed / (passed + failed)
```

`UNKNOWN` findings are not passes. They remain visible, reduce coverage, and
are excluded from the posture denominator.

Risk is a separate severity-weighted score:

```text
risk = sum(severity weight × exposure factor × blast-radius factor)
risk = min(risk, 100)
```

Prioritization uses the same exposure and blast-radius concepts. Internet
reachable resources, public data stores, wildcard permissions, and escalation
policies receive higher priority.

### 6.6 Attack paths

`cloudguard.attack_paths` builds a directed NetworkX graph such as:

```text
internet
   ↓
open security group
   ↓
EC2 instance
   ↓
instance role
  ↙  ↘
 S3  RDS
```

Only failing findings contribute to paths. Paths with at least two linked
findings are ranked by severity and length. `plotly_figure()` turns the graph
into an interactive Plotly chart for Streamlit.

This is an educational configuration graph. It does not prove real network
reachability or exploitability.

### 6.7 Remediation

`cloudguard.remediation.apply_remediation()`:

1. scans the account before changes;
2. attempts supported boto3 fixes;
3. records `APPLIED`, `UNSUPPORTED`, or `ERROR` actions;
4. scans the account again;
5. verifies which original failures became PASS or disappeared;
6. reports newly introduced FAIL findings separately.

Supported examples include S3 public-access blocking, S3 encryption,
versioning, security-group ingress removal, role-policy narrowing, public RDS
disablement, and removal of the demo escalation policy.

Moto cannot enable encryption on an existing RDS instance. That action is
reported as `UNSUPPORTED`; the real remediation is an encrypted replacement
instance followed by migration.

### 6.8 History and drift

`ScanHistory` stores serialized scan snapshots in SQLite. It compares the
latest two scans and reports:

- new findings;
- fixed findings;
- recurring findings;
- findings changed to `UNKNOWN`;
- risk-score trend data.

The dashboard's **Simulate drift** action opens SSH to the internet, allowing a
rescan to demonstrate a newly introduced finding.

---

## 7. How CPSA works

CloudGuard keeps CPSA as the credential-hygiene layer rather than replacing
it.

### IAM auditing

`cpsa.iam_auditor.audit_iam()` checks:

- minimum password length;
- password reuse prevention;
- forced password expiry;
- console users without MFA;
- unused console passwords;
- old access keys;
- unused access keys;
- root-account MFA and access-key conditions.

### Secret scanning

`cpsa.secrets_scanner` scans text/files for:

- AWS access-key IDs;
- AWS secret access keys;
- private-key blocks;
- passwords in connection strings;
- hardcoded passwords;
- high-entropy tokens.

Findings contain locations and masked previews, not complete secret values.

### Password strength

`cpsa.strength_engine` evaluates:

- length and character diversity;
- estimated entropy;
- common-password membership and variants;
- repeated characters and blocks;
- keyboard walks;
- sequences, years, and dates;
- context words;
- optional zxcvbn scoring.

The password itself is not returned in analysis results.

### Secure storage

The secure-store demonstration uses:

```text
password
  → HMAC-SHA256 with pepper from Secrets Manager
  → bcrypt or Argon2 with a random salt
  → hash and metadata in DynamoDB
```

Plaintext passwords and the pepper are not stored in DynamoDB. HMAC
pre-hashing also avoids bcrypt's 72-byte input limit.

### Access control and logging

CPSA defines application roles:

- `admin`;
- `analyst`;
- `viewer`.

It checks allowed actions before pipeline operations and can emit an
equivalent IAM-policy-style JSON document. `AuditLogger` sanitizes sensitive
keys and secret-like strings before storing JSON events.

This is application-layer authorization for demonstration; moto does not
enforce AWS IAM permissions.

---

## 8. Security and privacy guarantees

The project tests that:

- raw passwords do not appear in reports;
- raw secrets do not appear in logs;
- secret findings are masked;
- passwords are not stored in DynamoDB;
- password analysis does not return password substrings;
- unknown collection failures do not become passes;
- unsupported remediation is reported honestly.

Do not paste real production credentials into the demo. Use the included fake
fixtures and sample data.

---

## 9. Scope and limitations

CloudGuard is deliberately limited:

- it runs against moto fixtures, not a real AWS account;
- it does not manage AWS credentials or multi-account inventory;
- it does not continuously schedule scans;
- it does not read S3 objects or database records;
- it does not prove actual network reachability;
- it is not a penetration-testing or exploit framework;
- IAM escalation detection covers documented patterns, not every chain;
- the rule catalogue is partial, not complete CIS/NIST/OWASP coverage;
- GDPR/DPDP references are informational only;
- risk scoring is a project-specific capped weighted score;
- moto behavior can differ from production AWS;
- RDS encryption remediation is unsupported in-place by moto;
- Graph paths are illustrative, not exploit proofs.

Never describe a clean fixture scan as an AWS certification or compliance
attestation.

---

## 10. Troubleshooting

### `ModuleNotFoundError`

Install from the project directory:

```powershell
python -m pip install -r requirements.txt
```

For the dashboard, confirm Streamlit and Plotly:

```powershell
python -c "import streamlit, plotly; print('UI dependencies available')"
```

### Tests fail after a previous run

Remove local generated state and rerun:

```powershell
Remove-Item .\cloudguard_history.db -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .\__pycache__, .\.pytest_cache -ErrorAction SilentlyContinue
python -m pytest -q
```

### Streamlit shows stale state

Use the dashboard's **Reset** action or stop and restart:

```powershell
streamlit run app.py
```

Each browser session owns its own moto simulation.

### `EntityAlreadyExistsException` for `alice.admin`

If Streamlit is interrupted during account creation, moto can temporarily
retain a partially seeded account. The CloudGuard seed routine now detects
this exact duplicate-resource condition, resets the moto backend, and retries
once. Use the dashboard's **Reset** button and run the scan again. If an old
process is still serving the page, stop it with `Ctrl+C` and restart:

```powershell
python -m streamlit run app.py
```

### Cloudflared is unavailable

The scanner itself does not need cloudflared. It is only needed for an
optional public Colab browser tunnel. Run the dashboard locally, or install
cloudflared from the official Cloudflare documentation before rerunning the
notebook cell.

---

## 11. Recommended presentation sequence

For a short demonstration:

1. Run the secure scan and show 100% posture.
2. Run the insecure scan and show failed S3, EC2, RDS, and IAM findings.
3. Open the dashboard and inspect one finding's evidence and remediation.
4. Hover through the interactive attack-path graph.
5. Inject an access-denied fault and show `UNKNOWN`.
6. Simulate drift and rescan.
7. Apply verified remediation and show fixed/new/unsupported results.
8. Run labelled evaluation.
9. Open the CPSA credential-hygiene tabs.
10. Demonstrate password analysis and masked secret scanning.
11. Finish with the full test suite:

```powershell
python -m pytest -q
```

The expected current result is **87 passed**.
"# Cloud-Guard" 
