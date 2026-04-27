#!/usr/bin/env python3
"""Fail-closed completion checks for scope-first hybrid bounty runs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


CODEX_EXPLORE_ROLES = {
    "scout",
    "analyst",
    "source-auditor",
    "recon-scanner",
}
CLAUDE_GOVERNANCE_ROLES = {
    "scope-auditor",
    "reporter",
    "submission-review",
}
DEBATE_ROLES = {
    "exploiter",
    "critic",
    "triager-sim",
}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _read_dispatch_log(target_dir: Path) -> list[dict[str, Any]]:
    path = target_dir / "runtime_dispatch_log.jsonl"
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"status": "invalid_json", "raw": line})
    except OSError:
        pass
    return rows


def _phase_reached(target_dir: Path) -> dict[str, bool]:
    checkpoint = _load_json(target_dir / "checkpoint.json")
    produced = set(checkpoint.get("produced_artifacts") or [])
    completed = set(checkpoint.get("completed") or [])
    files = {p.name for p in target_dir.glob("*") if p.is_file()}
    text = "\n".join(str(item) for item in [checkpoint.get("phase"), checkpoint.get("phase_name"), *completed]).lower()

    explore = bool(
        produced
        or {"endpoint_map.md", "vulnerability_candidates.md", "explore_candidates.md", "final_sweep.md"} & files
        or "phase_1" in text
        or "explore" in text
        or "abandon" in text
    )
    submission_exists = (target_dir / "submission").exists() and any((target_dir / "submission").glob("*"))
    prove = bool(
        "phase_2" in text
        or "prove" in text
        or "gate_2" in text
        or submission_exists
    )
    report = bool(
        "phase_3" in text
        or "phase_4" in text
        or "phase_5" in text
        or list(target_dir.glob("submission/**/report.md"))
    )
    return {"explore": explore, "prove": prove, "report": report}


def _runtime_gate_status(target_dir: Path, role: str) -> str:
    candidates = [
        target_dir / f"{role}_runtime_gate.json",
        target_dir / f"{role.replace('-', '_')}_runtime_gate.json",
    ]
    for path in candidates:
        payload = _load_json(path)
        if payload:
            return str(payload.get("status") or "")
    return ""


def validate(target_dir: Path, *, mode: str, require_role_split: bool = True) -> dict[str, Any]:
    rows = _read_dispatch_log(target_dir)
    completed = [row for row in rows if row.get("status") == "completed"]
    codex_roles = {str(row.get("role")) for row in completed if row.get("backend") == "codex"}
    claude_roles = {str(row.get("role")) for row in completed if row.get("backend") == "claude"}
    reached = _phase_reached(target_dir)

    failures: list[str] = []
    warnings: list[str] = []

    if require_role_split and not completed:
        failures.append("missing runtime_dispatch_log.jsonl completed role entries")

    if require_role_split and reached["explore"] and not (codex_roles & CODEX_EXPLORE_ROLES):
        failures.append("explore phase reached without a completed Codex exploration role")

    if require_role_split and reached["explore"] and not (claude_roles & CLAUDE_GOVERNANCE_ROLES):
        failures.append("explore phase reached without a completed Claude governance/reporting role")

    if reached["prove"] and "exploiter" not in codex_roles:
        failures.append("prove phase reached without completed Codex exploiter role")

    if reached["report"]:
        if "critic" not in codex_roles:
            failures.append("report/review phase reached without completed Codex critic role")
        if not (claude_roles & {"reporter", "submission-review"}):
            failures.append("report/review phase reached without completed Claude reporter/submission-review role")

    for role in sorted(DEBATE_ROLES & codex_roles):
        gate_status = _runtime_gate_status(target_dir, role)
        if gate_status != "pass":
            failures.append(f"{role} completed but runtime debate gate is not pass")

    if rows and any(row.get("status") in {"failed", "timeout", "invalid_json"} for row in rows):
        warnings.append("dispatch log contains failed/timeout/invalid entries; inspect runtime_dispatch_log.jsonl")

    return {
        "schema_version": "hybrid-completion-gate/1",
        "mode": mode,
        "target_dir": str(target_dir),
        "status": "pass" if not failures else "fail",
        "phase_reached": reached,
        "completed_dispatches": len(completed),
        "codex_roles": sorted(codex_roles),
        "claude_roles": sorted(claude_roles),
        "failures": failures,
        "warnings": warnings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--mode", default="bounty")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--no-role-split-required", action="store_true")
    args = parser.parse_args()

    payload = validate(
        args.target_dir.resolve(),
        mode=args.mode,
        require_role_split=not args.no_role_split_required,
    )
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
