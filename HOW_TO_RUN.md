# How to run CloudGuard

## Install

From the `GroupNumber_6` folder:

```bash
pip install -r requirements.txt
```

The project uses moto for an in-memory AWS simulation. It does not need AWS
credentials, Docker, LocalStack, or an internet login.

## Run the tests

```bash
python -m pytest -q
```

The suite covers both CloudGuard posture checks and the original CPSA
credential-hygiene modules.

## Run CloudGuard from the CLI

```bash
python -m cloudguard.cli scan
python -m cloudguard.cli scan --secure
python -m cloudguard.cli scan --fault access_denied
python -m cloudguard.cli evaluate
```

The scanner checks the deterministic S3, EC2, IAM, and RDS fixtures and
reports PASS, FAIL, and UNKNOWN results. Fault injection demonstrates that
collection failures are never treated as passes.

## Run the CPSA credential-hygiene CLI

```bash
python -m cpsa.cli demo
python -m cpsa.cli audit --harden
python -m cpsa.cli strength
python -m cpsa.cli scan cpsa/data/sample_app.txt
```

## Run the dashboard

```bash
streamlit run app.py
```

The dashboard includes:

- insecure and secure CloudGuard account fixtures;
- S3, EC2, IAM, and RDS posture scanning;
- coverage, posture, risk, filtering, and CSV/JSON export;
- fault injection and UNKNOWN-state demonstrations;
- interactive Plotly attack-path visualization with hoverable resources;
- verified moto-only remediation;
- SQLite history, drift simulation, and trend display;
- labelled rule evaluation;
- CPSA IAM audit and full credential pipeline;
- password-strength analysis;
- hardcoded-secret scanning;
- sanitized CPSA audit-log display.

## Run the notebooks

Open `CloudGuard_Demo.ipynb` and select **Run all** for the CloudGuard
demonstration. `CPSA_Demo.ipynb` remains available for the original
credential-hygiene walkthrough.

The CloudGuard notebook also documents the optional Streamlit/cloudflared
quick-tunnel workflow for Colab. The tunnel is only for the local demo UI;
the scanner still uses moto and never connects to real AWS.

## Honest limitations

This is an educational, deterministic scanner rather than a production AWS
assessment platform. It does not read S3 objects or database records, does not
prove real exploitability, and does not provide complete CIS/NIST/OWASP
coverage or legal compliance certification. Moto behavior can differ from
production AWS; unsupported operations are reported explicitly.
