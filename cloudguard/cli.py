"""Command line entry point: python -m cloudguard.cli scan|evaluate."""
import argparse
import json

from .engine import scan_account
from .evaluation import evaluate_fixtures
from .faults import FaultInjector
from .history import ScanHistory
from .reporting import finding_to_dict
from .simulation import CloudGuardSimulation


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cloudguard")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("--secure", action="store_true")
    scan.add_argument("--fault", choices=["access_denied", "throttle", "timeout"])
    scan.add_argument("--history", default="cloudguard_history.db")
    sub.add_parser("evaluate")
    args = parser.parse_args(argv)
    if args.command == "evaluate":
        print(json.dumps(evaluate_fixtures(), indent=2))
        return 0
    with CloudGuardSimulation() as sim:
        sim.seed_cloudguard_account(secure=args.secure)
        faults = FaultInjector(kind=args.fault, service="s3") if args.fault else None
        result = scan_account(sim, faults)
        history = ScanHistory(args.history)
        history.record(result["findings"], result["score"])
        print(json.dumps({"score": result["score"], "findings": [finding_to_dict(f) for f in result["findings"]]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
