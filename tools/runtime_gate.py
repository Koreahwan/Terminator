#!/usr/bin/env python3
"""Hard gates for runtime policy metadata after agent execution."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


DEBATE_REQUIRED = ("gpt_proposal", "claude_objection", "arbiter")
CTF_TOOL_RE = re.compile(r"\b(gdb|ghidra|gef|pwntools|ropgadget|angr|z3|objdump|readelf|checksec)\b", re.I)
FILE_CMD_RE = re.compile(r"(^|\n)\s*(\$|>)?\s*file\s+[\w./-]+", re.I)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _has_debate_payload(payload: dict[str, Any]) -> bool:
    if payload.get("schema_version") == "debate-gate/1":
        inputs = payload.get("inputs") or {}
        return all(inputs.get(key) for key in DEBATE_REQUIRED[:2]) and bool(payload.get("verdict"))
    return all(key in payload for key in DEBATE_REQUIRED)


def _debate_files(work_dir: Path, role: str) -> list[Path]:
    names = [
        f"{role}_debate.json",
        f"{role.replace('-', '_')}_debate.json",
        "debate_gate.json",
        "debate_result.json",
    ]
    found = [work_dir / name for name in names if (work_dir / name).exists()]
    found.extend(work_dir.glob(f"*{role}*debate*.json"))
    return sorted(set(found))


def check_debate(work_dir: Path, role: str) -> tuple[bool, str, list[str]]:
    files = _debate_files(work_dir, role)
    for path in files:
        payload = _json(path)
        if payload and _has_debate_payload(payload):
            verdict = str(payload.get("verdict") or payload.get("arbiter", {}).get("verdict") or "")
            if verdict.upper() in {"BLOCK"}:
                return False, f"debate verdict blocked in {path.name}", [str(path)]
            return True, f"debate artifact accepted: {path.name}", [str(path)]
    return False, f"missing debate artifact for role {role}", [str(path) for path in files]


def check_real_tool_output(work_dir: Path, role: str, artifacts: list[str]) -> tuple[bool, str, list[str]]:
    candidates = [work_dir / name for name in artifacts]
    candidates.extend(work_dir.glob("*gdb*"))
    candidates.extend(work_dir.glob("*ghidra*"))
    candidates.extend(work_dir.glob("*tool*output*"))
    for path in candidates:
        text = _read(path)
        if text and (CTF_TOOL_RE.search(text) or FILE_CMD_RE.search(text)):
            return True, f"real tool output reference accepted: {path.name}", [str(path)]
    return False, f"missing real tool output evidence for role {role}", [str(path) for path in candidates if path.exists()]


def check_3x_local_then_remote(work_dir: Path, role: str, artifacts: list[str]) -> tuple[bool, str, list[str]]:
    candidates = [work_dir / name for name in artifacts]
    candidates.extend(work_dir.glob("*verification*"))
    candidates.extend(work_dir.glob("*verify*"))
    candidates.extend(work_dir.glob("*run*log*"))
    for path in candidates:
        text = _read(path).lower()
        if not text:
            continue
        local_ok = any(token in text for token in ("3/3", "3x", "three local", "local passes: 3", "local_passes: 3"))
        remote_ok = any(token in text for token in ("remote flag", "remote_flag", "remote capture", "server flag"))
        if local_ok and remote_ok:
            return True, f"3x local + remote evidence accepted: {path.name}", [str(path)]
    return False, f"missing 3x local plus remote verification evidence for role {role}", [str(path) for path in candidates if path.exists()]


def check_transport_policy(work_dir: Path, role: str, policy: str, artifacts: list[str]) -> tuple[bool, str, list[str]]:
    candidates = [work_dir / name for name in artifacts]
    candidates.extend(work_dir.glob("*transport*"))
    candidates.extend(work_dir.glob("*replay*"))
    candidates.extend(work_dir.glob("*mock*"))
    for path in candidates:
        text = _read(path).lower()
        if text and ("mock" in text or "replay" in text) and "live scan" not in text:
            return True, f"{policy} evidence accepted: {path.name}", [str(path)]
    return False, f"missing {policy} evidence for role {role}", [str(path) for path in candidates if path.exists()]


def check_runtime_gates(work_dir: Path, role: str, policy: dict[str, Any], artifacts: list[str]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(name: str, required: bool, result: tuple[bool, str, list[str]] | None = None) -> None:
        if not required:
            checks.append({"name": name, "status": "not_applicable"})
            return
        ok, detail, refs = result or (False, "missing check result", [])
        checks.append({"name": name, "status": "pass" if ok else "fail", "detail": detail, "refs": refs})

    debate_mode = str(policy.get("debate_mode") or "")
    add("debate", bool(debate_mode), check_debate(work_dir, role) if debate_mode else None)

    evidence_gate = str(policy.get("evidence_gate") or "")
    if evidence_gate == "machine-style-real-tool-output":
        add("evidence_gate", True, check_real_tool_output(work_dir, role, artifacts))
    elif evidence_gate == "machine-style-3x-local-then-remote":
        add("evidence_gate", True, check_3x_local_then_remote(work_dir, role, artifacts))
    else:
        add("evidence_gate", False)

    transport_policy = str(policy.get("transport_policy") or "")
    if transport_policy:
        add("transport_policy", True, check_transport_policy(work_dir, role, transport_policy, artifacts))
    else:
        add("transport_policy", False)

    failures = [item for item in checks if item.get("status") == "fail"]
    return {
        "schema_version": "runtime-gate/1",
        "role": role,
        "runtime_profile": policy.get("runtime_profile", ""),
        "runtime_pipeline": policy.get("runtime_pipeline", ""),
        "status": "pass" if not failures else "fail",
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--policy-json", type=Path, required=True)
    parser.add_argument("--artifacts", nargs="*", default=[])
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    policy = json.loads(args.policy_json.read_text(encoding="utf-8"))
    payload = check_runtime_gates(args.work_dir, args.role, policy, args.artifacts)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
