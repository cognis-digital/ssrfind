"""Command-line interface for SSRFIND.

Usage:
    python -m ssrfind scan <path> [--format table|json] [--min-severity ...]
    python -m ssrfind --version

Exit codes:
    0  no findings
    1  findings reported
    2  usage / runtime error (e.g. path not found)
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional, Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import Finding, scan_path


def _print_table(findings: List[Finding]) -> None:
    if not findings:
        print("No SSRF-prone sinks found.")
        return
    print(f"{'SEV':<7} {'FILE:LINE':<32} {'RULE':<16} REASON")
    print("-" * 100)
    for f in findings:
        loc = f"{f.file}:{f.line}"
        if len(loc) > 31:
            loc = "..." + loc[-28:]
        print(f"{f.severity:<7} {loc:<32} {f.rule_id:<16} {f.reason}")
        print(f"        sink={f.sink}  arg={f.argument}")
        for note in f.notes:
            print(f"        - {note}")
    highs = sum(1 for f in findings if f.severity == "high")
    print("-" * 100)
    print(f"{len(findings)} finding(s); {highs} high-severity.")


def _print_json(findings: List[Finding], scanned: str) -> None:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "scanned": scanned,
        "summary": {
            "total": len(findings),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
        },
        "findings": [f.to_dict() for f in findings],
    }
    print(json.dumps(payload, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Find SSRF-prone sinks and unvalidated URL fetches in source code (defensive static analysis).",
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a file or directory tree for SSRF hotspots.")
    scan.add_argument("path", help="File or directory to scan.")
    scan.add_argument("--format", choices=["table", "json"], default="table", help="Output format.")
    scan.add_argument(
        "--min-severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Only report findings at or above this severity.",
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        findings = scan_path(args.path, min_severity=args.min_severity)
    except FileNotFoundError as exc:
        print(f"error: path not found: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        _print_json(findings, args.path)
    else:
        _print_table(findings)

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
