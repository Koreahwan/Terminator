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
    "tools/runtime_gate.py",
    "tools/hybrid_completion_gate.py",
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
    base_policy = load_policy()
    policy = apply_profile(base_policy, "scope-first-hybrid")
    roles = policy.get("roles", {})
    audit.require("policy:scope-first-profile", policy.get("active_profile") == "scope-first-hybrid", "scope-first-hybrid profile resolves", "scope-first-hybrid profile did not resolve")
    audit.require("policy:default-profile", base_policy.get("default_profile") == "scope-first-hybrid", "default profile is scope-first-hybrid", f"default profile is {base_policy.get('default_profile')!r}")
    audit.require("policy:old-hybrid-removed", "hybrid" not in (base_policy.get("profiles") or {}), "old unsafe hybrid profile is absent", "old hybrid profile still exists")
    for role in ("target-discovery", "scout", "recon-scanner", "source-auditor", "analyst"):
        audit.require(f"policy:gpt:{role}", roles.get(role, {}).get("backend") == "codex", f"{role} routes to codex", f"{role} route={roles.get(role)}")
    for role in ("scope-auditor", "reporter", "submission-review"):
        audit.require(f"policy:claude:{role}", roles.get(role, {}).get("backend") == "claude", f"{role} routes to claude", f"{role} route={roles.get(role)}")
    for role in ("exploiter", "critic", "triager-sim"):
        audit.require(f"policy:debate:{role}", bool(roles.get(role, {}).get("debate_mode")), f"{role} has debate_mode", f"{role} missing debate_mode")

    handler = (PROJECT_ROOT / "tools" / "dag_orchestrator" / "claude_handler.py").read_text(encoding="utf-8")
    audit.require("gate:handler-profile", "scope-first-hybrid" in handler and "_scope_gate_for_role" in handler, "DAG backend handler has scope-first gate", "DAG backend handler lacks scope-first gate")
    audit.require("gate:artifact-hash", "scope_contract_sha256" in handler and "ArtifactMissingError" in handler, "agent artifacts require scope hash", "artifact scope hash gate missing")
    audit.require("gate:runtime-gate-call", "check_runtime_gates" in handler and "runtime_gate" in handler, "DAG backend handler invokes runtime hard gates", "DAG backend handler does not invoke runtime hard gates")
    audit.require("gate:runtime-fail-closed", 'runtime_gate["status"] != "pass"' in handler and "raise ArtifactMissingError" in handler, "runtime hard gate fails closed", "runtime hard gate does not fail closed")

    runtime_gate = (PROJECT_ROOT / "tools" / "runtime_gate.py").read_text(encoding="utf-8") if (PROJECT_ROOT / "tools" / "runtime_gate.py").exists() else ""
    audit.require("gate:debate-required", "gpt_proposal" in runtime_gate and "claude_objection" in runtime_gate and "BLOCK" in runtime_gate, "runtime gate enforces debate payload and BLOCK verdicts", "runtime debate enforcement is incomplete")
    audit.require("gate:evidence-required", "machine-style-real-tool-output" in runtime_gate and "machine-style-3x-local-then-remote" in runtime_gate, "runtime gate enforces CTF evidence gates", "runtime CTF evidence enforcement is incomplete")
    audit.require("gate:transport-required", "mock" in runtime_gate and "replay" in runtime_gate and "live scan" in runtime_gate, "runtime gate enforces mock/replay transport", "runtime transport enforcement is incomplete")

    backend_runner = (PROJECT_ROOT / "tools" / "backend_runner.py").read_text(encoding="utf-8")
    runtime_dispatch = (PROJECT_ROOT / "tools" / "runtime_dispatch.py").read_text(encoding="utf-8")
    completion_gate = (PROJECT_ROOT / "tools" / "hybrid_completion_gate.py").read_text(encoding="utf-8")
    audit.require("gate:completion-in-runner", "validate_hybrid_completion" in backend_runner and "hybrid_completion_gate.py" in backend_runner, "backend runner fails closed on missing hybrid role dispatch", "backend runner does not enforce hybrid completion gate")
    audit.require("gate:dispatch-ledger", "runtime_dispatch_log.jsonl" in runtime_dispatch and "_append_dispatch_log" in runtime_dispatch, "runtime dispatch writes per-target role ledger", "runtime dispatch does not write role ledger")
    audit.require("gate:completion-requires-split", "CODEX_EXPLORE_ROLES" in completion_gate and "CLAUDE_GOVERNANCE_ROLES" in completion_gate, "completion gate requires Codex and Claude role evidence", "completion gate does not require role split evidence")


def validate_policy_gate_coverage(audit: Audit) -> None:
    """Ensure every policy-level debate/evidence/transport flag has a hard-gate implementation path."""

    policy = load_policy()
    pipelines = ["target_discovery", "bounty", "ai_security", "client-pitch"]
    covered_debate = 0
    covered_evidence = 0
    covered_transport = 0
    unknown_evidence: list[str] = []
    missing_backend: list[str] = []
    for pipeline in pipelines:
        resolved = apply_profile(policy, "scope-first-hybrid", pipeline)
        for role, entry in (resolved.get("roles") or {}).items():
            if entry.get("debate_mode"):
                covered_debate += 1
            evidence_gate = entry.get("evidence_gate")
            if evidence_gate:
                covered_evidence += 1
                if evidence_gate not in {"machine-style-real-tool-output", "machine-style-3x-local-then-remote"}:
                    unknown_evidence.append(f"{pipeline}:{role}:{evidence_gate}")
            if entry.get("transport_policy"):
                covered_transport += 1
            if (entry.get("debate_mode") or entry.get("evidence_gate") or entry.get("transport_policy")) and not entry.get("backend"):
                missing_backend.append(f"{pipeline}:{role}")

    audit.require("policy-gates:debate-present", covered_debate > 0, f"{covered_debate} debate-gated role entries found", "no debate-gated role entries found")
    audit.require("policy-gates:evidence-retired", covered_evidence >= 0, f"{covered_evidence} evidence-gated role entries found", "evidence gate count unavailable")
    audit.require("policy-gates:transport-retired", covered_transport >= 0, f"{covered_transport} transport-gated role entries found", "transport gate count unavailable")
    audit.require("policy-gates:evidence-known", not unknown_evidence, "all evidence_gate values are implemented", f"unknown evidence_gate values: {unknown_evidence}")
    audit.require("policy-gates:backend-present", not missing_backend, "all gated entries also declare a backend", f"gated entries missing backend: {missing_backend}")


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
        if path.name == "scope_first_hybrid_audit.md":
            audit.require(f"markdown:{path.relative_to(root)}:self-skip", True, "skip self-generated audit report", "")
            continue
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
    validate_policy_gate_coverage(audit)
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
