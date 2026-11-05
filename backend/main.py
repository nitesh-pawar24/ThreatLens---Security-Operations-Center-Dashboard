"""
ThreatLens – Main CLI Entry Point
===================================
Run the detection engine against a CSV log file and print alerts.

Usage
-----
    python -m backend.main [path/to/logfile.csv] [--json]

Arguments
---------
    logfile     Path to a CSV log file (defaults to backend/data/sample_logs.csv)
    --json      Output alerts as JSON instead of human-readable text

⚠️  For demonstration only. No real network or system monitoring is performed.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from backend.log_parser import load_log
from backend.detector import run_detection, DetectorConfig

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

DEFAULT_LOG = Path(__file__).parent / "data" / "sample_logs.csv"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="ThreatLens Phase 2 – Security Log Detection Engine"
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        default=str(DEFAULT_LOG),
        help="Path to CSV log file (default: backend/data/sample_logs.csv)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output alerts as JSON",
    )
    args = parser.parse_args(argv)

    # ── Load & parse ──────────────────────────────────────────────────────────
    try:
        df = load_log(args.logfile)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    logger.info("Parsed %d log rows. Running detection rules…", len(df))

    # ── Detect ────────────────────────────────────────────────────────────────
    config = DetectorConfig()
    alerts = run_detection(df, config)

    # ── Output ────────────────────────────────────────────────────────────────
    if not alerts:
        print("✅  No threats detected in the provided log file.")
        return 0

    if args.json:
        print(json.dumps([a.to_dict() for a in alerts], indent=2, default=str))
    else:
        print(f"\n{'='*60}")
        print(f"  ThreatLens – {len(alerts)} Alert(s) Detected")
        print(f"{'='*60}\n")
        for i, alert in enumerate(alerts, 1):
            print(f"[{i}] {alert.alert_id}  |  {alert.severity}  |  {alert.source_ip}")
            print(f"     Rules   : {', '.join(alert.rules_matched)}")
            print(f"     Events  : {alert.event_type}")
            print(f"     Evidence: {len(alert.evidence)} row(s)")
            print(f"     Detail  : {alert.explanation}")
            print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
