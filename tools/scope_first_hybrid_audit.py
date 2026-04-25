#!/usr/bin/env python3
"""Audit scope-first hybrid implementation and verification artifacts."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.runtime_policy import apply_profile, load_policy


REQUIRED_TOOLS = [
    "tools/scope_contract.py",
    "tools/safety_wrapper.py",
    "tools/debate_gate.py",
    "tools/scope_first_hybrid_audit.py",
]
OVERCLAIM_RE = re.compile(
    r"\b(successfully submitted|accepted by|confirmed vulnerability|exploited production|live exploit)\b",
    re.I,
)


class Audit:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []

    def require(self, name: str, condition: bool, ok: str, fail: str, **extra: Any) -> None:
        self.checks.append({"name": name, "status": "pass" if condition else "fail", "detail": ok if condition else fail, **extra})


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_code(audit: Audit) -> None:
    for rel in REQUIRED_TOOLS:
        audit.require(f"tool:{rel}", (PROJECT_ROOT / rel).exists(), f"{rel} exists", f"{rel} missing")
    audit.require(
        "agent:scope-auditor",
        (PROJECT_ROOT / ".claude" / "agents" / "scope-auditor.md").exists(),
        "scope-auditor agent exists",
        "scope-auditor agent missing",
    )
    policy = apply_profile(load_policy(), "scope-first-hybrid")
    roles = policy.get("roles", {})
    audit.require("policy:scope-first-profile", policy.get("active_profile") == "scope-first-hybrid", "scope-first-hybrid profile resolves", "scope-first-hybrid profile did not resolve")
    for role in ("target-discovery", "scout", "recon-scanner", "source-auditor", "analyst"):
        audit.require(f"policy:gpt:{role}", roles.get(role, {}).get("backend") == "codex", f"{role} routes to codex", f"{role} route={roles.get(role)}")
    for role in ("scope-auditor", "reporter", "submission-review"):
        audit.require(f"policy:claude:{role}", roles.get(role, {}).get("backend") == "claude", f"{role} routes to claude", f"{role} route={roles.get(role)}")
    for role in ("exploiter", "critic", "triager-sim"):
        audit.require(f"policy:debate:{role}", bool(roles.get(role, {}).get("debate_mode")), f"{role} has debate_mode", f"{role} missing debate_mode")

    handler = (PROJECT_ROOT / "tools" / "dag_orchestrator" / "claude_handler.py").read_text(encoding="utf-8")
    audit.require("gate:handler-profile", "scope-first-hybrid" in handler and "_scope_gate_for_role" in handler, "DAG backend handler has scope-first gate", "DAG backend handler lacks scope-first gate")
    audit.require("gate:artifact-hash", "scope_contract_sha256" in handler and "ArtifactMissingError" in handler, "agent artifacts require scope hash", "artifact scope hash gate missing")


def validate_matrix(audit: Audit, path: Path | None) -> None:
    if not path:
        return
    audit.require("matrix:exists", path.exists(), "runtime matrix exists", f"runtime matrix missing: {path}")
    if not path.exists():
        return
    payload = read_json(path)
    rows = payload.get("results", [])
    matching = [row for row in rows if row.get("profile") == "scope-first-hybrid"]
    audit.require("matrix:scope-first-row", bool(matching), "matrix includes scope-first-hybrid", "matrix lacks scope-first-hybrid rows")
    audit.require("matrix:status", payload.get("status") == "pass" and all(row.get("status") == "pass" for row in matching), "scope-first matrix rows pass", "scope-first matrix row failed")


def validate_passive_run(audit: Audit, path: Path | None) -> None:
    if not path:
        return
    audit.require("passive-run:exists", path.exists(), "passive run JSON exists", f"passive run JSON missing: {path}")
    if not path.exists():
        return
    payload = read_json(path)
    audit.require("passive-run:status", payload.get("status") == "pass", "passive bounty run passed", f"passive bounty run status={payload.get('status')!r}")
    audit.require("passive-run:mode", payload.get("mode") == "passive-live-safe-dry-run", "passive run stayed safe dry-run", f"unexpected mode={payload.get('mode')!r}")
    for item in payload.get("runs", []):
        cmd = item.get("terminator_dry_run", {}).get("cmd", [])
        audit.require(f"passive-run:{item.get('profile')}:dry-run", "--dry-run" in cmd, "terminator command used --dry-run", f"terminator command missing --dry-run: {cmd}")


def validate_markdown_claims(audit: Audit, root: Path | None) -> None:
    if not root or not root.exists():
        return
    for path in sorted(root.rglob("*.md")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        hits = OVERCLAIM_RE.findall(text)
        audit.require(f"markdown:{path.relative_to(root)}:overclaim", not hits, "no unsafe overclaim", f"overclaim hits: {hits}")


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    counts = Counter(item["status"] for item in payload["checks"])
    lines = [
        "# Scope-First Hybrid Audit",
        "",
        f"Generated: {payload['generated_at']}",
        f"Status: {payload['status']}",
        "",
        f"- Pass: {counts.get('pass', 0)}",
        f"- Fail: {counts.get('fail', 0)}",
        "",
        "| Status | Check | Detail |",
        "|---|---|---|",
    ]
    for item in payload["checks"]:
        lines.append(f"| {item['status']} | `{item['name']}` | {item['detail']} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix-json", type=Path)
    parser.add_argument("--passive-run-json", type=Path)
    parser.add_argument("--claim-root", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    audit = Audit()
    validate_code(audit)
    validate_matrix(audit, args.matrix_json)
    validate_passive_run(audit, args.passive_run_json)
    validate_markdown_claims(audit, args.claim_root)
    status = "fail" if any(item["status"] == "fail" for item in audit.checks) else "pass"
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": status,
        "checks": audit.checks,
    }
    out_json = args.out_dir / "scope_first_hybrid_audit.json"
    out_md = args.out_dir / "scope_first_hybrid_audit.md"
    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(out_md, payload)
    print(out_json)
    print(out_md)
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
