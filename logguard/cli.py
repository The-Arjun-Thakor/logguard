"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from . import __version__
from .detectors import Thresholds, run_all
from .models import SEVERITY_ORDER
from .parsers import parse_auth_log, parse_web_log
from .report import summarise, write_json, write_markdown


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logguard",
        description="Detect brute force, compromise and web attacks in SSH and web logs.",
    )
    p.add_argument("--auth", type=Path, help="Path to SSH auth.log / secure file")
    p.add_argument("--web", type=Path, help="Path to Apache/Nginx combined access log")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="Year for syslog timestamps (auth.log has none). Default: current year")
    p.add_argument("--out", type=Path, default=Path("reports"), help="Output directory (default: reports/)")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None,
                   help="Exit with code 2 if any alert is at or above this severity (for automation)")
    p.add_argument("--brute-threshold", type=int, default=Thresholds.brute_force_failures,
                   help="Failed logins from one IP that trigger a brute-force alert")
    p.add_argument("--brute-window", type=int, default=Thresholds.brute_force_window,
                   help="Brute-force sliding window in seconds")
    p.add_argument("--version", action="version", version=f"logguard {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.auth and not args.web:
        print("error: provide at least one of --auth or --web", file=sys.stderr)
        return 1

    th = Thresholds(
        brute_force_failures=args.brute_threshold,
        brute_force_window=args.brute_window,
    )

    auth_events, web_events = [], []
    meta = {}
    if args.auth:
        with args.auth.open(encoding="utf-8", errors="replace") as fh:
            auth_events, skipped = parse_auth_log(fh, args.year)
        if not auth_events:
            print(f"warning: no SSH auth events parsed from {args.auth} - wrong file or format?", file=sys.stderr)
        meta["SSH log"] = f"{args.auth.name} ({len(auth_events)} auth events, {skipped} non-auth lines skipped)"
    if args.web:
        with args.web.open(encoding="utf-8", errors="replace") as fh:
            web_events, skipped = parse_web_log(fh)
        if not web_events:
            print(f"warning: no web requests parsed from {args.web} - expected Apache/Nginx combined format", file=sys.stderr)
        meta["Web log"] = f"{args.web.name} ({len(web_events)} requests, {skipped} unparseable lines skipped)"
    meta["Thresholds"] = (
        f"brute force >= {th.brute_force_failures} failures / {th.brute_force_window}s"
    )

    alerts = run_all(auth_events, web_events, th)

    args.out.mkdir(parents=True, exist_ok=True)
    write_json(alerts, args.out / "alerts.json", meta)
    write_markdown(alerts, args.out / "incident_report.md", meta)

    summary = summarise(alerts)
    sev = summary["by_severity"]
    print(f"logguard: {summary['total_alerts']} alert(s)  "
          f"[critical={sev['critical']} high={sev['high']} medium={sev['medium']} low={sev['low']}]")  # type: ignore[index]
    for a in alerts:
        print(f"  {a.alert_id}  {a.severity.upper():8}  {a.source_ip:15}  {a.title}")
    print(f"Reports written to {args.out}/")

    if args.fail_on:
        limit = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[a.severity] >= limit for a in alerts):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
