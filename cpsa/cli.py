"""Command-line interface.   python -m cpsa.cli --help

  demo                      full end-to-end run on the simulated insecure account
  audit [--harden]          IAM audit only (optionally show the fixed account afterwards)
  strength                  score one password (asks securely, nothing is echoed or stored)
  scan FILE [FILE ...]      hardcoded-secret scan
  policy --role ROLE        print the least-privilege IAM policy for a role

Add --role viewer to any command to see the access check deny it.
"""
import argparse
import getpass
import sys

from .access_control import AccessDenied, check_access, policy_json
from .audit_logger import AuditLogger
from .cloud_sim import CloudSimulation
from .iam_auditor import audit_iam
from .pipeline import run_full_audit
from .report import build_report, render_text, to_csv
from .secrets_scanner import scan_file
from .strength_engine import analyze_password, engine_name


def _common(p):
    p.add_argument("--role", default="admin", choices=["admin", "analyst", "viewer"])
    p.add_argument("--actor", default="cli-user")
    p.add_argument("--csv", help="write the findings table to this CSV file")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cpsa", description="Cloud Password Security Analyzer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("demo", "audit", "strength", "scan"):
        _common(sub.add_parser(name))
    sub.choices["audit"].add_argument("--harden", action="store_true", help="fix the account, then audit again")
    sub.choices["strength"].add_argument("--password", help="avoid: visible in shell history. Omit to be prompted.")
    sub.choices["scan"].add_argument("files", nargs="+")
    pol = sub.add_parser("policy")
    pol.add_argument("--role", default="analyst", choices=["admin", "analyst", "viewer"])
    args = ap.parse_args(argv)

    if args.cmd == "policy":
        print(policy_json(args.role))
        return 0

    logger = AuditLogger()
    try:
        if args.cmd == "demo":
            with CloudSimulation() as sim:
                result = run_full_audit(sim, args.actor, args.role, logger=logger)
            report = result["report"]
        elif args.cmd == "audit":
            check_access(args.role, "run_audit", args.actor, logger)
            with CloudSimulation() as sim:
                sim.seed_insecure_account()
                report = build_report(audit_iam(sim.client("iam")), "IAM audit (before)")
                print(render_text(report))
                if args.harden:
                    print("\nHardening account:", sim.harden_account(), "\n")
                    report = build_report(audit_iam(sim.client("iam")), "IAM audit (after hardening)")
        elif args.cmd == "strength":
            check_access(args.role, "analyze_password", args.actor, logger)
            pw = args.password if args.password is not None else getpass.getpass("Password (hidden): ")
            a = analyze_password(pw, label="input")
            print(f"Rating: {a['rating']} (score {a['score']}/4, engine={engine_name()})")
            print(f"Length: {a['length']}  Entropy: {a['entropy_bits']} bits  Patterns: {a['patterns'] or 'none'}")
            for f in a["findings"]:
                print(f" - {f.rule_id}: {f.detail}")
            return 0
        else:   # scan
            check_access(args.role, "scan_secrets", args.actor, logger)
            findings = [f for path in args.files for f in scan_file(path)]
            report = build_report(findings, "Secrets scan")
    except AccessDenied as e:
        print(f"ACCESS DENIED: {e}", file=sys.stderr)
        return 2

    print(render_text(report))
    if args.csv:
        print("CSV written:", to_csv(report, args.csv))
    return 0


if __name__ == "__main__":
    sys.exit(main())
