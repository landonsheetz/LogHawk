"""
Command-line interface for LogHawk.

Usage:
    python -m loghawk --logs sample_logs/auth_events.json --rules rules
    python -m loghawk --logs sample_logs/auth_events.json --rules rules --html report.html
"""

import argparse
import sys

from .events import load_events
from .rules import load_rules
from .engine import run_rules
from .report import console_summary, html_report


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="loghawk",
        description="Detection-as-code engine for security event logs.",
    )
    parser.add_argument("--logs", required=True, help="Path to a JSON or JSONL log file.")
    parser.add_argument("--rules", default="rules", help="Directory of YAML detection rules.")
    parser.add_argument("--html", help="Optional path to write an HTML report.")
    parser.add_argument(
        "--fail-on",
        choices=["none", "critical", "high", "medium", "low"],
        default="none",
        help="Exit non-zero if any alert at or above this severity fires. "
             "Useful for wiring LogHawk into CI so a noisy log fails the build.",
    )
    args = parser.parse_args(argv)

    events = load_events(args.logs)
    rules = load_rules(args.rules)
    alerts = run_rules(rules, events)

    print("LogHawk  |  %d events analyzed  |  %d rules loaded" % (len(events), len(rules)))
    print()
    print(console_summary(alerts))

    if args.html:
        with open(args.html, "w", encoding="utf-8") as handle:
            handle.write(html_report(alerts, source_name=args.logs))
        print("\nHTML report written to %s" % args.html)

    if args.fail_on != "none":
        from .engine import SEVERITY_RANK
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK.get(a["severity"], 9) <= threshold for a in alerts):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
