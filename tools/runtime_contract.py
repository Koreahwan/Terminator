#!/usr/bin/env python3
"""Utilities for Terminator runtime close-out artifacts."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


EXIT_CLEAN = 0
EXIT_CRITICAL = 1
EXIT_HIGH = 2
EXIT_MEDIUM = 3
EXIT_ERROR = 10


@dataclass
class SeverityCounts:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return ""


def read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def collect_severity_counts(session_log: Path) -> SeverityCounts:
    text = read_text(session_log)
    return SeverityCounts(
        critical=text.count("[CRITICAL]"),
        high=text.count("[HIGH]"),
        medium=text.count("[MEDIUM]"),
        low=text.count("[LOW]"),
        info=text.count("[INFO]"),
    )


def collect_flags(flags_path: Path) -> list[str]:
    if not flags_path.exists():
        return []
    return [line.strip() for line in read_text(flags_path).splitlines() if line.strip()]


def runtime_status(report_dir: Path) -> str | None:
    runtime_result = read_json(report_dir / "runtime_result.json")
    if runtime_result and isinstance(runtime_result.get("status"), str):
        return runtime_result["status"]

    completed = report_dir / ".completed"
    if completed.exists():
        status = read_text(completed).strip()
        return status or None
    return None


def compute_exit_code(report_dir: Path) -> int:
    counts = collect_severity_counts(report_dir / "session.log")
    if counts.critical:
        return EXIT_CRITICAL
    if counts.high:
        return EXIT_HIGH
    if counts.medium:
        return EXIT_MEDIUM
    return EXIT_CLEAN


def build_summary(
    report_dir: Path,
    *,
    mode: str,
    target: str,
    start_ts: int,
    exit_code: int,
    status: str,
) -> dict:
    counts = collect_severity_counts(report_dir / "session.log")
    runtime_result = read_json(report_dir / "runtime_result.json") or {}
    competition_plan_path = report_dir / "competition_plan.json"
    competition_plan = read_json(competition_plan_path)
    effective_status = runtime_result.get("status") if isinstance(runtime_result.get("status"), str) else status
    files = sorted(path.name for path in report_dir.iterdir() if path.is_file()) if report_dir.exists() else []

    summary = {
        "timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": mode,
        "target": target,
        "duration_seconds": max(int(datetime.now(tz=timezone.utc).timestamp()) - start_ts, 0),
        "exit_code": exit_code,
        "flags_found": collect_flags(report_dir / "flags.txt"),
        "findings": {
            "critical": counts.critical,
            "high": counts.high,
            "medium": counts.medium,
            "low": counts.low,
            "info": counts.info,
        },
        "files_generated": files,
        "status": effective_status,
        "backend": runtime_result.get("backend_used", "unknown"),
        "backend_requested": runtime_result.get("backend_requested", "unknown"),
        "failover_used": bool(runtime_result.get("failover_used", False)),
        "failover_count": runtime_result.get("failover_count", 0),
        "session_id": runtime_result.get("session_id", ""),
    }
    if isinstance(competition_plan, dict):
        summary["competition"] = competition_plan
    elif competition_plan_path.exists():
        summary["competition_warning"] = "invalid competition_plan.json ignored"
    return summary


def cmd_exit_code(args: argparse.Namespace) -> int:
    print(compute_exit_code(Path(args.report_dir)))
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    report_dir = Path(args.report_dir)
    summary = build_summary(
        report_dir,
        mode=args.mode,
        target=args.target,
        start_ts=args.start_ts,
        exit_code=args.exit_code,
        status=args.status,
    )
    (report_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    exit_code = sub.add_parser("exit-code")
    exit_code.add_argument("--report-dir", required=True)
    exit_code.set_defaults(func=cmd_exit_code)

    summary = sub.add_parser("summary")
    summary.add_argument("--report-dir", required=True)
    summary.add_argument("--mode", required=True)
    summary.add_argument("--target", required=True)
    summary.add_argument("--start-ts", type=int, required=True)
    summary.add_argument("--exit-code", type=int, required=True)
    summary.add_argument("--status", required=True)
    summary.set_defaults(func=cmd_summary)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
