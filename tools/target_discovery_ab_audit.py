#!/usr/bin/env python3
"""Audit target-discovery and passive bounty A/B artifacts for gaps/overclaims."""

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

from tools.dag_orchestrator.pipelines import PIPELINES
from tools.runtime_policy import apply_profile, load_policy

DISCOVERY_PROFILES = {"claude-only", "gpt-only", "hybrid-a", "hybrid-b"}
RUNTIME_PROFILES = {"claude-only", "gpt-only", "scope-first-hybrid"}
AB_PROFILES = {"hybrid-a", "hybrid-b"}
SAFE_HOST_RE = re.compile(
    r"^https://(yeswehack\.com|hackerone\.com|bugcrowd\.com|immunefi\.com|app\.intigriti\.com|huntr\.com|hackenproof\.com)/",
    re.I,
)
OVERCLAIM_RE = re.compile(
    r"\b(submit-ready|accepted by|successfully submitted|live exploit|exploited production|confirmed vulnerability)\b",
    re.I,
)


class Audit:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []

    def require(self, name: str, condition: bool, ok: str, fail: str, **extra: Any) -> None:
        self.checks.append({"name": name, "status": "pass" if condition else "fail", "detail": ok if condition else fail, **extra})


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def selected_url(run: dict[str, Any]) -> str:
    payload = run.get("payload") or {}
    return str(payload.get("selected_url") or "")


def validate_code_wiring(audit: Audit) -> None:
    policy = load_policy()
    claude = apply_profile(policy, "claude-only")["roles"].get("target-discovery", {})
    gpt = apply_profile(policy, "gpt-only")["roles"].get("target-discovery", {})
    scope_first = apply_profile(policy, "scope-first-hybrid")["roles"].get("target-discovery", {})
    audit.require("pipeline:registered", "target_discovery" in PIPELINES, "target_discovery pipeline is registered", "target_discovery pipeline missing")
    audit.require(
        "role:agent-definition",
        (PROJECT_ROOT / ".claude" / "agents" / "target-discovery.md").exists(),
        "target-discovery agent definition exists",
        "target-discovery agent definition missing",
    )
    audit.require(
        "role:compact-contract",
        (PROJECT_ROOT / "generated" / "role_contracts" / "target-discovery.txt").exists(),
        "target-discovery compact contract exists",
        "target-discovery compact contract missing",
    )
    audit.require("policy:claude-only", claude.get("backend") == "claude", "claude-only routes target-discovery to Claude", f"claude-only backend={claude.get('backend')!r}")
    audit.require(
        "policy:gpt-only",
        gpt.get("backend") == "codex" and gpt.get("model") == "gpt-5.5",
        "gpt-only routes target-discovery to Codex/gpt-5.5",
        f"gpt-only route={gpt}",
    )
    audit.require(
        "policy:scope-first-hybrid",
        scope_first.get("backend") == "codex" and scope_first.get("model") == "gpt-5.5",
        "scope-first-hybrid routes target-discovery to Codex/gpt-5.5",
        f"scope-first-hybrid route={scope_first}",
    )


def validate_discovery(audit: Audit, discovery_json: Path) -> dict[str, Any]:
    audit.require("discovery:json-exists", discovery_json.exists(), "target discovery JSON exists", f"missing {discovery_json}")
    payload = read_json(discovery_json)
    runs = payload.get("model_runs", [])
    profiles = {item.get("profile") for item in runs if isinstance(item, dict)}
    candidate_urls = {
        str(item.get("program_url")).rstrip("/")
        for item in payload.get("shortlist", []) + payload.get("model_candidates", [])
        if isinstance(item, dict) and item.get("program_url")
    }
    audit.require("discovery:candidates", payload.get("candidate_count", 0) > 0 and bool(candidate_urls), "live candidate set is non-empty", "no live candidates recorded")
    audit.require("discovery:profiles", profiles == DISCOVERY_PROFILES, "all discovery A/B profiles ran", f"profile mismatch: {sorted(profiles)}")
    for run in runs:
        profile = str(run.get("profile"))
        url = selected_url(run).rstrip("/")
        data = run.get("payload") or {}
        audit.require(f"discovery:{profile}:url-safe", bool(SAFE_HOST_RE.match(url)), f"{profile} selected official bounty URL", f"{profile} selected suspicious URL: {url}")
        audit.require(f"discovery:{profile}:url-from-candidates", url in candidate_urls, f"{profile} selected URL from collected candidates", f"{profile} selected URL not in candidates: {url}")
        audit.require(
            f"discovery:{profile}:structured",
            data.get("decision") in {"GO", "CONDITIONAL_GO", "NO_GO"} and isinstance(data.get("top_candidates"), list),
            f"{profile} returned structured decision",
            f"{profile} malformed payload",
        )
    return payload


def validate_matrix(audit: Audit, matrix_json: Path) -> None:
    audit.require("matrix:json-exists", matrix_json.exists(), "target-discovery matrix JSON exists", f"missing {matrix_json}")
    payload = read_json(matrix_json)
    results = payload.get("results", [])
    pairs = {(item.get("profile"), item.get("pipeline")) for item in results if isinstance(item, dict)}
    expected = {(profile, "target_discovery") for profile in RUNTIME_PROFILES}
    audit.require("matrix:coverage", pairs == expected, "target_discovery matrix covers claude/gpt/scope-first", f"matrix pairs mismatch: {sorted(pairs)}")
    audit.require("matrix:status", payload.get("status") == "pass" and all(item.get("status") == "pass" for item in results), "target_discovery matrix passes", "target_discovery matrix has failures")


def validate_bounty_ab(audit: Audit, bounty_json: Path, discovery_payload: dict[str, Any]) -> None:
    audit.require("bounty-ab:json-exists", bounty_json.exists(), "bounty A/B JSON exists", f"missing {bounty_json}")
    payload = read_json(bounty_json)
    runs = payload.get("runs", [])
    profiles = {item.get("profile") for item in runs if isinstance(item, dict)}
    selected = {item.get("profile"): selected_url(item) for item in discovery_payload.get("model_runs", []) if isinstance(item, dict)}
    audit.require("bounty-ab:mode", payload.get("mode") == "passive-live-safe-dry-run", "bounty A/B is passive safe dry-run mode", f"unexpected mode={payload.get('mode')!r}")
    audit.require("bounty-ab:profiles", profiles == AB_PROFILES, "hybrid-a and hybrid-b both ran", f"profile mismatch: {sorted(profiles)}")
    audit.require("bounty-ab:status", payload.get("status") == "pass" and all(item.get("status") == "pass" for item in runs), "bounty A/B status is pass", "bounty A/B recorded failure")
    for item in runs:
        profile = str(item.get("profile"))
        url = str(item.get("program_url") or "")
        audit.require(f"bounty-ab:{profile}:matches-discovery", url == selected.get(profile), f"{profile} bounty target matches discovery selection", f"{profile} mismatch: {url} vs {selected.get(profile)}")
        target_dir = Path(str(item.get("target_dir", "")))
        required_files = [
            target_dir / "program_data.json",
            target_dir / "program_rules_summary.md",
            target_dir / "program_raw" / "bundle.md",
            bounty_json.parent / profile / str(item.get("slug")) / "bounty_dag_summary.json",
        ]
        missing = [str(path) for path in required_files if not path.exists()]
        audit.require(f"bounty-ab:{profile}:artifacts", not missing, f"{profile} program/DAG artifacts exist", f"{profile} missing artifacts: {missing}")
        for key in ("verify_target", "fetch_program", "dag_dry_run", "terminator_dry_run"):
            command = item.get(key, {}).get("cmd", [])
            audit.require(f"bounty-ab:{profile}:{key}:returncode", item.get(key, {}).get("returncode") in ({0, 3} if key == "verify_target" else {0}), f"{profile} {key} returncode accepted", f"{profile} {key} failed")
            if key == "dag_dry_run":
                audit.require(f"bounty-ab:{profile}:dag-no-execute", "--execute" not in command, f"{profile} DAG stayed dry-run", f"{profile} DAG command used --execute")
            if key == "terminator_dry_run":
                audit.require(f"bounty-ab:{profile}:terminator-dry-run", "--dry-run" in command, f"{profile} terminator used --dry-run", f"{profile} terminator command missing --dry-run")


def validate_markdown(audit: Audit, paths: list[Path]) -> None:
    for path in paths:
        audit.require(f"markdown:{path.name}:exists", path.exists(), f"{path.name} exists", f"missing {path}")
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        hits = OVERCLAIM_RE.findall(text)
        audit.require(f"markdown:{path.name}:overclaim", not hits, f"{path.name} has no forbidden overclaim", f"{path.name} overclaim hits: {hits}")


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    counts = Counter(item["status"] for item in payload["checks"])
    lines = [
        "# Target Discovery A/B Audit",
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
    parser.add_argument("--discovery-json", type=Path, required=True)
    parser.add_argument("--bounty-json", type=Path, required=True)
    parser.add_argument("--matrix-json", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    audit = Audit()
    validate_code_wiring(audit)
    discovery = validate_discovery(audit, args.discovery_json)
    validate_matrix(audit, args.matrix_json)
    validate_bounty_ab(audit, args.bounty_json, discovery)
    validate_markdown(
        audit,
        [
            args.discovery_json.with_suffix(".md"),
            args.bounty_json.with_suffix(".md"),
            args.matrix_json.with_suffix(".md"),
        ],
    )

    status = "fail" if any(item["status"] == "fail" for item in audit.checks) else "pass"
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": status,
        "checks": audit.checks,
    }
    out_json = args.out_dir / "target_discovery_ab_audit.json"
    out_md = args.out_dir / "target_discovery_ab_audit.md"
    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(out_md, payload)
    print(out_json)
    print(out_md)
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
