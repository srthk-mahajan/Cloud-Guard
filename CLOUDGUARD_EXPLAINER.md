# CloudGuard and CPSA: complete project explainer

This document explains the project from the outside in:

1. what the project is for;
2. how its components are organized;
3. how the simulated AWS environment works;
4. what happens during every scan;
5. how findings, scores, history, drift, graphs, and remediation work;
6. what every major Streamlit control displays;
7. how the original CPSA credential-hygiene system fits into CloudGuard;
8. what the project does not claim to do.

The project is located at:

```text
C:\Users\saart\Desktop\GroupNumber_6
```

It is an educational security-scanning demonstration. It is not a production
AWS security product, penetration-testing framework, or legal compliance
certification tool.

---

## 1. One-sentence description

CloudGuard creates a deterministic fake AWS account in memory, scans its S3,
EC2, IAM, and RDS configuration using ordinary boto3 calls, reports security
findings and risk, visualizes configuration-based attack paths, demonstrates
verified remediation and drift, and combines this with CPSA's password,
credential, secret-scanning, secure-storage, and audit-log features.

---

## 2. The most important design fact: this is not real AWS

All cloud resources are simulated with `moto`.

The application does not:

- connect to an AWS account;
- read AWS credentials from your machine;
- call real AWS APIs;
- inspect a real company's resources;
- read S3 object contents;
- read database rows;
- exploit a host or network;
- use Docker or LocalStack.

The code still uses normal `boto3` clients:

```python
s3 = sim.client("s3")
iam = sim.client("iam")
rds = sim.client("rds")
```

Moto intercepts those calls and returns responses from an in-memory fake AWS
backend. This gives the project three advantages:

1. **Repeatability:** the same insecure and secure fixtures can be recreated.
2. **Safety:** there are no real cloud changes.
3. **Offline demonstration:** scanning does not require credentials or network
   access.

The trade-off is that moto does not implement every AWS behavior exactly like
production AWS. The project documents unsupported operations rather than
pretending that moto performed them.

---

## 3. High-level architecture

There are two layers.

```text
                         ┌──────────────────────────┐
                         │ Streamlit dashboard      │
                         │ app.py                   │
                         └────────────┬─────────────┘
                                      │
                 ┌────────────────────┴────────────────────┐
                 │                                         │
     ┌───────────▼───────────┐                 ┌───────────▼───────────┐
     │ CloudGuard layer      │                 │ CPSA layer             │
     │ cloudguard/            │                 │ cpsa/                  │
     │ AWS posture scanner    │                 │ credential hygiene     │
     └───────────┬───────────┘                 └───────────┬───────────┘
                 │                                         │
                 └────────────────────┬────────────────────┘
                                      │
                         ┌────────────▼─────────────┐
                         │ moto + boto3 simulation  │
                         │ in-memory fake AWS       │
                         └──────────────────────────┘
```

### CloudGuard layer

CloudGuard answers questions such as:

- Is an S3 bucket publicly accessible?
- Is S3 default encryption enabled?
- Is S3 versioning enabled?
- Is SSH or RDP open to the internet?
- Does an EC2 instance use wildcard role permissions?
- Is an RDS instance publicly accessible?
- Is RDS storage encrypted?
- Does an IAM policy contain known privilege-escalation patterns?

### CPSA layer

CPSA answers questions such as:

- Is the IAM password policy weak?
- Are users missing MFA?
- Are access keys old or unused?
- Are hardcoded secrets present in source text?
- Is a password common or predictable?
- Can a password be stored using a pepper and slow hash?
- Are operations authorized and logged without leaking secrets?

CloudGuard imports CPSA; it does not replace it.

---

## 4. File-by-file map

## 4.1 Root files

### `app.py`

The combined Streamlit user interface.

It:

- creates and stores a `CloudGuardSimulation`;
- provides insecure/secure/reset controls;
- runs CloudGuard scans;
- injects faults;
- displays metrics and findings;
- displays the Plotly attack-path graph;
- records scan history;
- simulates drift;
- applies remediation;
- runs labelled evaluation;
- exposes CPSA IAM audit;
- runs the CPSA full pipeline;
- analyzes passwords;
- scans pasted text for secrets;
- displays sanitized audit logs.

`app.py` is presentation/orchestration code. The actual scanning logic belongs
in the package modules.

### `requirements.txt`

Declares the Python packages:

- boto3;
- moto;
- bcrypt;
- argon2-cffi;
- pandas;
- pytest;
- Streamlit;
- NetworkX;
- Plotly;
- optional zxcvbn.

### `README.md`

The operational and technical project guide:

- installation;
- CLI commands;
- dashboard usage;
- architecture;
- testing;
- limitations;
- troubleshooting.

### `GUIDE.md`

The presentation and demonstration guide. It explains how to present the
project in several minutes and lists honest limitations.

### `HOW_TO_RUN.md`

A shorter operational guide for running the project.

### `PROJECT_OVERVIEW.md`

A detailed architecture and scope document describing the original CPSA
layer, CloudGuard layer, dashboard, scoring, rules, and limitations.

### `CloudGuard_Demo.ipynb`

The CloudGuard notebook demonstration. It verifies imports and demonstrates:

- fixture creation;
- scanning;
- findings;
- faults;
- attack paths;
- remediation;
- evaluation;
- optional Streamlit/cloudflared use.

### `CPSA_Demo.ipynb`

The original credential-hygiene notebook.

### `cloudguard_history.db`

This file is generated at runtime by `ScanHistory`. It stores local scan
snapshots. It is not a source file and is ignored by Git.

---

## 4.2 `cloudguard/` files

### `cloudguard/__init__.py`

Exposes the primary library functions:

```python
from cloudguard import scan_account, score_findings
```

### `cloudguard/simulation.py`

Defines `CloudGuardSimulation`, a subclass of CPSA's `CloudSimulation`.

It seeds:

- S3 buckets;
- EC2 networking and instance resources;
- IAM role and user policy resources;
- an RDS database instance;
- the original CPSA IAM resources inherited from `CloudSimulation`.

It supports:

- insecure fixture creation;
- secure fixture creation;
- drift simulation;
- lifecycle start/stop.

It is the bridge between the generic CPSA moto account and CloudGuard
resources.

### `cloudguard/collectors.py`

Contains read-only collectors:

- `collect_s3`;
- `collect_ec2`;
- `collect_rds`;
- `collect_iam_escalation`.

Collectors call boto3 metadata APIs and convert results into `Finding`
objects.

They do not:

- modify resources;
- read object contents;
- read database records;
- execute commands;
- exploit anything.

They include bounded retry behavior and convert collection failures into
`UNKNOWN` findings.

### `cloudguard/catalogue.json`

The declarative rule catalogue.

Each entry contains:

- rule ID;
- service;
- title;
- severity;
- API calls needed;
- check reference;
- CIS reference;
- GDPR/DPDP informational note;
- rationale;
- remediation text.

The catalogue separates fixed rule metadata from scanning code.

### `cloudguard/catalogue.py`

Loads and indexes `catalogue.json` so the engine can enrich findings with
titles, severities, compliance notes, and remediation.

### `cloudguard/engine.py`

The central CloudGuard orchestrator.

`scan_account(sim, faults=None)`:

1. calls S3 collection;
2. calls EC2 collection;
3. calls RDS collection;
4. calls IAM escalation collection;
5. enriches findings from the catalogue;
6. calculates priority;
7. calculates score;
8. returns findings, score, and catalogue.

The engine is used by both the CLI and dashboard.

### `cloudguard/scoring.py`

Calculates:

- evaluated count;
- passed count;
- failed count;
- unknown count;
- coverage;
- posture;
- risk score;
- score formula;
- disclaimer.

### `cloudguard/prioritization.py`

Calculates finding priority from:

```text
severity × exposure factor × blast-radius factor
```

Internet exposure and broad permissions increase priority.

### `cloudguard/attack_paths.py`

Builds the resource graph and finds chained paths.

It also creates the interactive Plotly figure used by Streamlit.

### `cloudguard/remediation.py`

Applies supported fixes in moto and rescans.

It returns:

- attempted actions;
- action status;
- before result;
- after result;
- verified original findings;
- number fixed;
- number requested;
- newly introduced failures.

### `cloudguard/history.py`

Uses SQLite to store scan snapshots and compare the latest two scans.

### `cloudguard/faults.py`

Provides deterministic access-denied, throttling, and timeout injection.

### `cloudguard/evaluation.py`

Runs secure and insecure fixtures against labelled expected results and
calculates TP, FP, TN, FN, precision, recall, and F1.

### `cloudguard/reporting.py`

Converts `Finding` objects into:

- JSON-compatible dictionaries;
- pandas tables;
- CSV-ready data.

### `cloudguard/cli.py`

Provides:

```powershell
python -m cloudguard.cli scan
python -m cloudguard.cli scan --secure
python -m cloudguard.cli scan --fault access_denied
python -m cloudguard.cli evaluate
```

---

## 4.3 `cpsa/` files

### `cpsa/models.py`

Defines the shared `Finding` dataclass.

Important fields:

```text
rule_id       rule identifier
resource      affected resource
detail        human-readable explanation
category      finding category
evidence      safe metadata
status        PASS, FAIL, or UNKNOWN
service       cpsa, s3, ec2, iam, or rds
priority      numeric priority
```

CloudGuard extends this existing model backwards-compatibly.

### `cpsa/cloud_sim.py`

Creates the shared moto account used by CPSA:

- IAM users;
- weak password policy;
- access keys;
- DynamoDB hash table;
- Secrets Manager pepper.

It also contains the existing hardening demonstration.

### `cpsa/iam_auditor.py`

Audits:

- IAM password policy;
- MFA;
- password use;
- access-key age;
- access-key use;
- root-account conditions.

CloudGuard keeps this logic authoritative instead of rewriting it.

### `cpsa/secrets_scanner.py`

Scans text and files for:

- AWS access-key IDs;
- AWS secret access keys;
- private-key blocks;
- passwords in connection strings;
- hardcoded passwords;
- high-entropy tokens.

It masks values in findings.

### `cpsa/strength_engine.py`

Checks:

- length;
- character sets;
- entropy;
- common-password lists;
- common variants;
- repeats;
- keyboard patterns;
- sequences;
- years and dates;
- context words;
- optional zxcvbn feedback.

### `cpsa/secure_store.py`

Demonstrates:

```text
password
  → HMAC-SHA256 with Secrets Manager pepper
  → bcrypt or Argon2
  → DynamoDB hash record
```

It never stores the plaintext password.

### `cpsa/access_control.py`

Defines application-level roles:

- admin;
- analyst;
- viewer.

It checks whether a role may perform an action and generates an equivalent
IAM-policy-style document.

It is not actual AWS IAM enforcement.

### `cpsa/audit_logger.py`

Creates sanitized JSON events and redacts secret-like content.

### `cpsa/compliance_mapper.py`

Maps CPSA finding IDs to:

- severity;
- NIST;
- CIS;
- OWASP;
- remediation.

### `cpsa/report.py`

Builds CPSA:

- pandas finding tables;
- severity counts;
- risk score;
- compliance clause summaries;
- CSV;
- text reports.

### `cpsa/pipeline.py`

Runs the full CPSA flow:

```text
authorization
  → IAM audit
  → secret scan
  → password analysis
  → password hashing
  → DynamoDB storage
  → verification
  → compliance report
  → audit log
```

### `cpsa/cli.py`

Provides:

```powershell
python -m cpsa.cli demo
python -m cpsa.cli audit --harden
python -m cpsa.cli strength
python -m cpsa.cli scan cpsa/data/sample_app.txt
python -m cpsa.cli policy --role analyst
```

---

## 5. What happens when the dashboard starts

Run:

```powershell
python -m streamlit run app.py
```

Streamlit executes `app.py` from top to bottom on the first page load and
again after many widget interactions.

The dashboard uses `st.session_state` so the moto simulation survives those
reruns.

The startup path is:

```text
app.py
  → _get_simulation()
  → _new_simulation(False)
  → CloudGuardSimulation().start()
  → seed_cloudguard_account(secure=False)
```

The default initial account is insecure.

The account is kept in:

```python
st.session_state["cloudguard_sim"]
```

This matters because a scan, drift action, and remediation action must all
operate on the same simulated account.

If the account were recreated from scratch on every widget click, a drift
change would disappear before the next scan.

---

## 6. What every dashboard control means

## 6.1 Sidebar: Create insecure account

This:

1. stops the previous simulation if present;
2. starts a new moto backend;
3. creates the CPSA resources;
4. creates intentionally weak CloudGuard resources;
5. stores the new simulation in Streamlit session state;
6. clears previous scan and CPSA result state.

The insecure fixture is for demonstrating failures.

Expected weak conditions:

- public S3 ACL;
- no S3 encryption;
- no versioning on one bucket;
- open SSH/RDP;
- wildcard EC2 role;
- public RDS;
- unencrypted RDS;
- escalation-prone IAM user policy.

## 6.2 Sidebar: Create secure account

This performs the same lifecycle but calls:

```python
sim.seed_cloudguard_account(secure=True)
```

It creates:

- blocked S3 public access;
- encryption;
- versioning;
- restricted SSH;
- scoped EC2 permissions;
- private RDS;
- encrypted RDS;
- no demo escalation user.

It is used to demonstrate expected PASS behavior.

## 6.3 Sidebar: Reset

Reset:

1. stops the current moto backend;
2. removes the simulation from session state;
3. clears scan result state;
4. clears history-diff display state;
5. clears CPSA findings and pipeline state;
6. reruns the page.

Reset is useful when:

- a demonstration has become confusing;
- you want a clean before/after;
- you clicked controls in the wrong order;
- a previous browser session retained state.

## 6.4 Collection fault

Options:

- none;
- access_denied;
- throttle;
- timeout.

The fault is passed to the collector layer through `FaultInjector`.

## 6.5 Service

The selected service determines where the fault is injected:

- S3;
- EC2;
- RDS;
- IAM.

Example:

```text
fault = access_denied
service = s3
```

The S3 collector cannot collect its data and emits `UNKNOWN`.

## 6.6 Run read-only CloudGuard scan

This is the main dashboard operation.

It:

1. constructs a fault injector if selected;
2. calls `scan_account(sim, injector)`;
3. collects S3 findings;
4. collects EC2 findings;
5. collects RDS findings;
6. collects IAM escalation findings;
7. enriches and prioritizes findings;
8. computes score;
9. stores the result in `st.session_state`;
10. records a snapshot in SQLite;
11. computes the difference from the previous snapshot.

It does not modify the simulated resources.

The result is stored in:

```python
st.session_state["cloudguard_result"]
```

---

## 7. Understanding the overview metrics

## 7.1 Evaluated

The number of rule/resource checks where the scanner had enough data to
produce PASS or FAIL.

## 7.2 Passed

The number of evaluated checks that met the rule.

Example:

```text
S3 encryption is enabled → PASS
```

## 7.3 Failed

The number of evaluated checks that violated the rule.

Example:

```text
SSH is open to 0.0.0.0/0 → FAIL
```

## 7.4 Unknown

The number of checks that could not be evaluated because of:

- access denied;
- throttling after retries;
- timeout;
- unsupported collection;
- another collection failure.

Unknown is not a pass.

## 7.5 Coverage

```text
coverage = evaluated / total × 100
```

If a scan has 17 total checks and 17 were evaluated:

```text
coverage = 100%
```

If S3 collection failed and some checks are unknown, coverage decreases.

## 7.6 Posture

```text
posture = passed / (passed + failed) × 100
```

Unknown checks are excluded from the posture denominator because the scanner
does not know whether they passed or failed.

This is why a scan can have:

```text
coverage: 75%
posture: 100%
```

The 100% posture only describes the checks that were successfully evaluated.

## 7.7 Risk score

Risk is a project-specific priority indicator:

```text
risk = severity weight × exposure factor × blast-radius factor
```

The sum is capped at 100.

It is not:

- CVSS;
- an AWS score;
- a compliance score;
- a legal risk assessment.

---

## 8. Understanding the findings table

The findings table shows one row per rule/resource result.

Important columns include:

- status;
- service;
- severity;
- priority;
- rule ID;
- resource;
- detail;
- evidence;
- remediation metadata.

A rule can produce multiple rows.

For example:

```text
S3-002 + cloudguard-public
S3-002 + cloudguard-private
```

This means the same rule was evaluated independently for two buckets.

## 8.1 Services filter

Filters rows by:

- S3;
- EC2;
- IAM;
- RDS.

## 8.2 Status filter

Filters rows by:

- FAIL;
- PASS;
- UNKNOWN.

## 8.3 Finding detail

The detail panel shows:

- raw safe evidence;
- rationale;
- CIS mapping;
- GDPR/DPDP note;
- remediation text.

Evidence is intended to explain what the collector observed. It does not
contain secrets or object contents.

## 8.4 CSV download

Exports the current finding table as CSV.

## 8.5 JSON download

Exports serialized finding objects and metadata as JSON.

---

## 9. What each CloudGuard rule means

## `S3-001`: public S3 access

The collector checks bucket ACL and public-access-block metadata.

FAIL means the bucket can be publicly accessed according to the simulated
metadata.

PASS means public access is blocked or no public ACL was found.

## `S3-002`: S3 default encryption

The collector calls the bucket encryption metadata API.

FAIL means no default encryption configuration was found.

This checks configuration, not the contents of existing objects.

## `S3-003`: S3 versioning

The collector checks bucket versioning status.

FAIL means versioning is not enabled.

Versioning helps recovery and investigation but is not itself encryption.

## `EC2-001`: public SSH/RDP

The collector checks security-group ingress rules.

FAIL means TCP port 22 or 3389 is allowed from:

```text
0.0.0.0/0
```

This is a configuration finding. The scanner does not connect to the host.

## `EC2-002`: over-permissive EC2 role

The collector follows:

```text
EC2 instance
  → instance profile
  → IAM role
  → inline policy
```

It checks for wildcard `Action` or `Resource`.

FAIL means a compromised workload could have broad permissions.

## `RDS-001`: public RDS

The collector checks `PubliclyAccessible`.

FAIL means the database instance is configured as publicly accessible.

The scanner does not connect to the database or read rows.

## `RDS-002`: RDS encryption

The collector checks `StorageEncrypted`.

FAIL means storage encryption is disabled.

The remediation layer cannot enable this on an existing moto instance and
therefore reports `UNSUPPORTED`.

## `IAM-ESC-001`: known escalation pattern

The collector checks user policies for patterns such as:

- `iam:PassRole`;
- policy attachment;
- `iam:PutUserPolicy`;
- `iam:CreatePolicyVersion`;
- role-policy changes;
- service creation;
- wildcard actions;
- wildcard resources.

Evidence includes a list of patterns found.

This is not an exhaustive IAM privilege-escalation proof.

---

## 10. Attack-path graph: meaning of every node

The graph is built only from failing findings.

## `internet`

Represents an external attacker or publicly reachable origin.

It is an abstract graph node, not a real IP address.

## Security-group node

Usually displayed as an ID such as:

```text
sg-...
```

It represents a security group with a public SSH/RDP rule.

The edge from `internet` to this resource corresponds to `EC2-001`.

## EC2 instance node

Represents the simulated EC2 instance.

The edge from security group to EC2 represents the combination of network
exposure and an instance resource.

## `instance-role`

Represents the IAM role attached to an EC2 instance profile.

The edge from EC2 to `instance-role` corresponds to `EC2-002`.

## S3 bucket node

Represents a bucket affected by S3 findings.

An edge from `instance-role` to an S3 bucket illustrates that the role's
permissions and the bucket's configuration combine into a possible data-risk
chain.

## RDS database node

Represents the simulated RDS instance.

An edge from `instance-role` to RDS illustrates a possible workload-to-database
configuration chain.

## IAM escalation user node

An IAM escalation finding can create a separate path from `internet` to the
affected user in the educational graph.

This does not mean the user is literally internet-facing. It represents the
security importance of an escalation-prone identity when combined with an
external compromise scenario.

## Edges

Edges represent relationships inferred from findings, not packets or proven
network routes.

## Plotly behavior

The Plotly graph supports:

- hover;
- pan;
- zoom;
- browser toolbar export;
- deterministic layout.

The graph is generated from NetworkX and rendered by Plotly in Streamlit.

---

## 11. Drift and scan history

## 11.1 What happens to previous scans?

Every dashboard scan calls:

```python
history.record(findings, score)
```

`ScanHistory` serializes:

- timestamp;
- score;
- finding statuses;
- evidence;
- resources.

It inserts the snapshot into:

```text
cloudguard_history.db
```

The database contains a `scans` table with:

```text
id
created_at
payload
```

The current result remains in Streamlit session state, while the historical
copy remains in SQLite.

## 11.2 What happens on the next scan?

The next scan:

1. records a new snapshot;
2. loads the latest two snapshots;
3. compares finding keys:

```text
(rule_id, resource)
```

4. classifies changes.

## 11.3 History categories

### New

A finding key did not exist in the previous scan and is now FAIL.

### Fixed

A previous FAIL is now PASS.

### Recurring

A previous FAIL is still FAIL.

### Changed to UNKNOWN

A previous known result is now UNKNOWN.

## 11.4 Is previous data overwritten?

No. Each scan is inserted as a new snapshot.

The dashboard compares the latest two scans, while the SQLite database keeps
older snapshots for trend history.

## 11.5 How to demonstrate drift correctly

Use the secure fixture:

1. Create secure account.
2. Run scan.
3. Confirm `EC2-001` is PASS.
4. Click **Simulate drift**.
5. Run scan again.
6. Confirm `EC2-001` is FAIL.

The drift function adds:

```text
TCP 22 from 0.0.0.0/0
```

If you start with the insecure fixture, SSH is already public, so clicking
Simulate drift does not create a visibly new finding.

---

## 12. Remediation lifecycle

When **Apply verified remediation** is clicked:

```text
scan before
  → apply boto3 changes
  → record action status
  → scan after
  → compare findings
```

Action statuses:

### `APPLIED`

The simulated configuration change was made.

### `UNSUPPORTED`

Moto cannot safely represent the requested operation.

Current example:

```text
enable encryption on existing RDS instance
```

### `ERROR`

The attempted operation raised an exception.

The result reports:

- requested failures;
- fixed failures;
- per-finding before/after status;
- new failures after remediation.

Remediation is intentionally limited to the moto sandbox.

---

## 13. Fault injection and UNKNOWN

The fault injector simulates collection failures without requiring a real AWS
failure.

Example:

```text
fault type: access_denied
service: s3
```

The collector calls the injector before its boto3 call. The injector raises a
controlled failure. The collector converts it into:

```text
status: UNKNOWN
evidence: { error_class: ... }
```

Retryable failures may be retried with bounded backoff. If they remain
unavailable, the final result is still UNKNOWN.

This prevents a dangerous reporting error:

```text
collection failed → incorrectly report PASS
```

---

## 14. CPSA credential-hygiene UI

The dashboard's lower section contains four CPSA tabs.

## IAM audit

**Run CPSA IAM audit** calls `audit_iam()` and displays IAM findings.

**Run full credential pipeline** calls `run_full_audit()` and demonstrates:

- authorization;
- IAM audit;
- secret scan;
- password analysis;
- hash creation;
- DynamoDB storage;
- password verification;
- report generation;
- audit logging.

The equivalent least-privilege policy section displays a policy artifact for
the analyst role.

## Password strength

The password is accepted through a password-type input.

The tool displays:

- rating;
- score;
- engine;
- length;
- entropy;
- patterns;
- strength findings.

It does not display the password itself.

The expected-versus-actual table compares built-in test expectations with the
engine's results.

## Secrets scanner

The sample file is loaded into a text area. Clicking **Scan for secrets**
passes the text to `scan_text`.

Results include:

- rule;
- location;
- finding detail;
- masked value behavior.

Do not paste real credentials into the UI.

## Audit log

The audit log becomes populated after the full pipeline runs.

It displays sanitized events and allows JSON Lines download.

---

## 15. CLI versus dashboard

Both use the same underlying modules.

### CLI

Best for:

- automation;
- repeatable terminal commands;
- JSON output;
- CI;
- fast validation.

Each CLI command usually creates a fresh simulation, performs its operation,
prints output, and exits.

### Dashboard

Best for:

- presentations;
- filtering;
- graph exploration;
- drift;
- remediation;
- history;
- combining CloudGuard and CPSA;
- interactive human investigation.

The dashboard keeps one simulation alive in session state, which makes
multi-step demonstrations possible.

---

## 16. Complete demonstration script

## Minute 0–1: introduction

Say:

> CloudGuard is an offline AWS configuration scanner. It uses boto3-style
> calls against moto, so no real AWS credentials or account are involved.

Point out:

- CloudGuard posture layer;
- CPSA credential-hygiene layer;
- deterministic fixtures;
- no real data access.

## Minute 1–2: insecure scan

1. Create insecure account.
2. Run scan.
3. Show failed count and risk.

Explain that failures are deliberately seeded.

## Minute 2–3: finding details

1. Filter to EC2.
2. Select `EC2-001`.
3. Explain public SSH/RDP evidence.
4. Show remediation.

## Minute 3–4: graph

1. Scroll to attack paths.
2. Hover nodes.
3. Explain internet, security group, EC2, role, S3/RDS.
4. State that it is illustrative, not exploit proof.

## Minute 4–5: UNKNOWN

1. Select access denied.
2. Select S3.
3. Scan.
4. Show UNKNOWN and reduced coverage.

Explain why unknown is safer than false PASS.

## Minute 5–6: drift

1. Create secure account.
2. Scan and show EC2-001 PASS.
3. Click Simulate drift.
4. Scan again.
5. Show EC2-001 FAIL and history difference.

## Minute 6–7: remediation

1. Apply verified remediation.
2. Show fixed count.
3. Show unsupported RDS encryption action.
4. Explain before/after verification.

## Minute 7–8: secure comparison and evaluation

1. Create secure account.
2. Scan.
3. Show 100% posture and risk 0.
4. Run labelled evaluation.

## Minute 8–10: CPSA

1. Run CPSA IAM audit.
2. Run full pipeline.
3. Analyze weak and strong passwords.
4. Scan sample secrets.
5. Show sanitized audit log.

## Closing statement

> The system demonstrates posture scanning, credential hygiene, safe
> handling of unknown collection states, risk prioritization, graph-based
> reasoning, verified remediation, and reproducible evaluation. It does not
> claim to replace a production AWS security platform.

---

## 17. Limitations and honest claims

The project does not claim:

- complete CIS coverage;
- complete NIST coverage;
- complete OWASP coverage;
- legal GDPR/DPDP compliance;
- production AWS parity;
- exhaustive IAM escalation detection;
- real exploitability;
- real network reachability;
- multi-account inventory;
- scheduled production scanning;
- real secret discovery in cloud storage;
- database-content analysis;
- penetration testing.

The rule catalogue is intentionally small and educational.

The risk score is an internal weighted score capped at 100, not an industry
standard.

The attack graph combines findings into possible relationships; it is not a
packet-level reachability engine.

The secure and insecure evaluation metrics describe only the deterministic
fixtures included in this repository.

---

## 18. Verification commands

From `GroupNumber_6`:

```powershell
python -m pip install -r requirements.txt
python -m compileall -q app.py cloudguard cpsa
python -m pytest -q
python -m cloudguard.cli scan --secure
python -m cloudguard.cli scan
python -m cloudguard.cli evaluate
python -m cpsa.cli demo
python -m streamlit run app.py
```

Expected test result:

```text
87 passed
```

The most important distinction is:

```text
compileall → syntax/pre-flight check
pytest     → behavioral verification
CLI scan   → direct scanner execution
dashboard  → interactive demonstration and investigation
```
