#!/usr/bin/env python3
"""Exercise terminator.sh dry-run entrypoints across runtime profiles."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROFILES = ["claude-only", "gpt-only", "scope-first-hybrid"]
PIPELINES = ["bounty", "ai-security", "client-pitch"]
PROFILE_BACKEND = {"claude-only": "claude", "gpt-only": "codex", "scope-first-hybrid": "hybrid"}


def ensure_fixtures(out_dir: Path) -> dict[str, Path]:
    fixture_dir = out_dir / "terminator_dry_run_fixtures"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    return {}


def command_for(pipeline: str, profile: str, fixtures: dict[str, Path]) -> list[str]:
    backend = PROFILE_BACKEND[profile]
    base = [
        "./terminator.sh",
        "--dry-run",
        "--backend",
        backend,
        "--failover-to",
        "none",
        "--runtime-profile",
        profile,
    ]
    if pipeline in {"bounty", "client-pitch"}:
        base.insert(1, "--json")
    if pipeline == "bounty":
        return base + ["bounty", "https://hackerone.com/discourse", "https://hackerone.com/discourse"]
    if pipeline == "ai-security":
        return base + ["ai-security", "https://example.invalid/model", "public replay scope"]
    if pipeline == "client-pitch":
        return base + ["client-pitch", "https://example.invalid"]
    raise ValueError(f"unknown pipeline: {pipeline}")


def run_one(pipeline: str, profile: str, out_dir: Path, timeout: int) -> dict[str, Any]:
    fixtures = ensure_fixtures(out_dir)
    cmd = command_for(pipeline, profile, fixtures)
    started = time.monotonic()
    env = os.environ.copy()
    env["TERMINATOR_TIMESTAMP"] = f"dryrun_{profile}_{pipeline}".replace("-", "_")
    proc = subprocess.run(
        cmd,
        cwd=str(PROJECT_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    expected_profile = profile
    if profile == "scope-first-hybrid":
        expected_backend = "hybrid"
    else:
        expected_backend = PROFILE_BACKEND[profile]
    checks = {
        "returncode_zero": proc.returncode == 0,
        "dry_run_output": "dry_run" in output.lower() or "[dry-run]" in output.lower(),
        "runtime_profile_output": expected_profile in output,
        "backend_output": expected_backend in output,
    }
    return {
        "profile": profile,
        "pipeline": pipeline,
        "mode": "terminator-dry-run",
        "status": "pass" if all(checks.values()) else "fail",
        "returncode": proc.returncode,
        "duration_seconds": round(time.monotonic() - started, 2),
        "cmd": cmd,
        "checks": checks,
        "stdout_tail": (proc.stdout or "")[-4000:],
        "stderr_tail": (proc.stderr or "")[-4000:],
    }


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# Terminator Dry-Run Matrix",
        "",
        f"Generated: {payload['generated_at']}",
        "",
        "| Profile | Pipeline | Status | Returncode |",
        "|---|---|---|---:|",
    ]
    for item in payload["results"]:
        lines.append(f"| {item['profile']} | {item['pipeline']} | {item['status']} | {item['returncode']} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--profiles", nargs="+", default=PROFILES)
    parser.add_argument("--pipelines", nargs="+", default=PIPELINES)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    results = [
        run_one(pipeline, profile, args.out.parent, args.timeout)
        for profile in args.profiles
        for pipeline in args.pipelines
    ]
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "profiles": args.profiles,
        "pipelines": args.pipelines,
        "results": results,
        "status": "pass" if all(item["status"] == "pass" for item in results) else "fail",
    }
    args.out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(args.out.with_suffix(".md"), payload)
    print(args.out)
    print(args.out.with_suffix(".md"))
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
