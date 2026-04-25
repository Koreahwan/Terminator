#!/usr/bin/env python3
"""Run passive-live bounty pipeline checks for hybrid A/B target choices."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def slugify(value: str) -> str:
    parsed = urlparse(value)
    base = parsed.path.strip("/").split("/")[-1] or parsed.netloc
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", base).strip("-") or "target"


def platform_for_url(url: str) -> str:
    host = urlparse(url).netloc.lower()
    if "hackerone.com" in host:
        return "hackerone"
    if "bugcrowd.com" in host:
        return "bugcrowd"
    if "yeswehack.com" in host:
        return "yeswehack"
    if "immunefi.com" in host:
        return "immunefi"
    if "intigriti.com" in host:
        return "intigriti"
    if "huntr.com" in host or "github.com" in host:
        return "huntr"
    if "hackenproof.com" in host:
        return "hackenproof"
    return "generic"


def run(cmd: list[str], *, cwd: Path, timeout: int) -> dict:
    started = time.monotonic()
    proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "duration_seconds": round(time.monotonic() - started, 2),
        "stdout": proc.stdout[-8000:],
        "stderr": proc.stderr[-8000:],
    }


def load_selected(discovery_json: Path, profile: str) -> dict:
    payload = json.loads(discovery_json.read_text(encoding="utf-8"))
    for item in payload.get("model_runs", []):
        if item.get("profile") == profile:
            data = item.get("payload") or {}
            return {
                "profile": profile,
                "program_url": data.get("selected_url"),
                "name": data.get("selected_name"),
                "decision": data.get("decision"),
                "scope_risk": data.get("scope_risk"),
                "score": data.get("score"),
                "model_payload": data,
            }
    raise SystemExit(f"profile not found in discovery JSON: {profile}")


def run_one(selection: dict, *, out_dir: Path, timeout: int) -> dict:
    url = str(selection.get("program_url") or "")
    if not url.startswith("http"):
        raise SystemExit(f"selected URL missing/invalid for {selection.get('profile')}: {url}")
    slug = slugify(url)
    platform = platform_for_url(url)
    target_dir = out_dir / selection["profile"] / slug / "target"
    target_dir.mkdir(parents=True, exist_ok=True)

    verify = run(
        ["python3", "tools/bb_preflight.py", "verify-target", platform, url],
        cwd=PROJECT_ROOT,
        timeout=timeout,
    )
    fetch = run(
        ["python3", "-m", "tools.program_fetcher", url, "--out", str(target_dir), "--hold-ok"],
        cwd=PROJECT_ROOT,
        timeout=timeout,
    )
    scope_contract = run(
        ["python3", "tools/scope_contract.py", "create", str(target_dir), "--allow-hold", "--json"],
        cwd=PROJECT_ROOT,
        timeout=timeout,
    )
    dag_out = out_dir / selection["profile"] / slug / "bounty_dag_summary.json"
    dag = run(
        [
            "env",
            "TERMINATOR_RUNTIME_PROFILE=scope-first-hybrid",
            "python3",
            "tools/dag_orchestrator/cli.py",
            "run",
            "--pipeline",
            "bounty",
            "--target",
            slug,
            "--backend",
            "hybrid",
            "--work-dir",
            str(target_dir),
            "--out",
            str(dag_out),
        ],
        cwd=PROJECT_ROOT,
        timeout=timeout,
    )
    terminator = run(
        [
            "./terminator.sh",
            "--json",
            "--dry-run",
            "--backend",
            "hybrid",
            "--runtime-profile",
            "scope-first-hybrid",
            "bounty",
            url,
            url,
        ],
        cwd=PROJECT_ROOT,
        timeout=timeout,
    )
    return {
        **selection,
        "slug": slug,
        "platform": platform,
        "target_dir": str(target_dir),
        "verify_target": verify,
        "fetch_program": fetch,
        "scope_contract": scope_contract,
        "dag_dry_run": dag,
        "terminator_dry_run": terminator,
        "status": "pass"
        if verify["returncode"] in {0, 3}
        and fetch["returncode"] == 0
        and scope_contract["returncode"] == 0
        and dag["returncode"] == 0
        and terminator["returncode"] == 0
        else "fail",
    }


def write_markdown(path: Path, payload: dict) -> None:
    lines = ["# Bounty Hybrid A/B Passive-Live Run", "", f"Generated: {payload['generated_at']}", ""]
    lines.append("This run fetched real public bounty program data and exercised Terminator bounty routing in safe dry-run mode. It did not scan assets, create accounts, autofill, or submit.")
    lines.append("")
    lines.append("| Profile | Program | Platform | Decision | Verify | Fetch | Contract | DAG | Terminator | Status |")
    lines.append("|---|---|---|---|---:|---:|---:|---:|---:|---|")
    for item in payload["runs"]:
        lines.append(
            f"| {item['profile']} | {item.get('name')} | {item['platform']} | {item.get('decision')} | "
            f"{item['verify_target']['returncode']} | {item['fetch_program']['returncode']} | "
            f"{item['scope_contract']['returncode']} | "
            f"{item['dag_dry_run']['returncode']} | {item['terminator_dry_run']['returncode']} | {item['status']} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discovery-json", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--profiles", nargs="+", default=["hybrid-a", "hybrid-b"])
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    runs = []
    for profile in args.profiles:
        print(f"[bounty-live-ab] profile={profile}", flush=True)
        runs.append(run_one(load_selected(args.discovery_json, profile), out_dir=args.out_dir, timeout=args.timeout))

    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "discovery_json": str(args.discovery_json),
        "mode": "passive-live-safe-dry-run",
        "runs": runs,
        "status": "pass" if all(item["status"] == "pass" for item in runs) else "fail",
    }
    out_json = args.out_dir / "bounty_hybrid_ab.json"
    out_md = args.out_dir / "bounty_hybrid_ab.md"
    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(out_md, payload)
    print(out_json)
    print(out_md)
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
