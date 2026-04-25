#!/usr/bin/env python3
"""Audit implementation completeness against the user's runtime plan.

This is intentionally stricter than runtime_hallucination_audit.py. It checks
whether the implementation and verification evidence satisfy the requested
acceptance criteria, and it marks unmet user intent as fail instead of quietly
burying it in notes.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_ROOT = PROJECT_ROOT.parent / "Terminator"
PROFILES = {"claude-only", "gpt-only", "scope-first-hybrid"}
DAG_PIPELINES = {"ctf_pwn", "ctf_rev", "bounty", "firmware", "ai_security", "robotics", "supplychain"}
TERMINATOR_PIPELINES = {"ctf", "bounty", "firmware", "ai-security", "robotics", "supplychain"}
BASELINE_PACKAGES = {
    "proconnect-identite",
    "qwant",
    "llama_index",
    "onnx",
    "kubeflow",
    "hrsgroup",
    "portofantwerp",
    "magiclabs-mbb-og",
    "paradex",
    "zendesk",
    "rhinofi_prove",
}


@dataclass
class Requirement:
    id: str
    intent: str
    checker: Callable[["Context"], list[dict[str, Any]]]


class Context:
    def __init__(self, eval_dir: Path) -> None:
        self.eval_dir = eval_dir.resolve()
        self.cache: dict[Path, Any] = {}

    def read_json(self, relative: str) -> Any:
        path = self.eval_dir / relative
        if path not in self.cache:
            self.cache[path] = json.loads(path.read_text(encoding="utf-8"))
        return self.cache[path]


def result(status: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {"status": status, "detail": detail, **extra}


def file_exists(path: Path) -> bool:
    return path.exists() and path.is_file()


def shell_output(args: list[str], *, cwd: Path) -> tuple[int, str]:
    proc = subprocess.run(args, cwd=str(cwd), capture_output=True, text=True, timeout=30)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def latest_eval_dir() -> Path:
    root = PROJECT_ROOT / "reports" / "runtime-eval"
    candidates = [p for p in root.iterdir() if p.is_dir()] if root.exists() else []
    if not candidates:
        return root
    return max(candidates, key=lambda p: p.stat().st_mtime)


def check_worktree_isolation(_: Context) -> list[dict[str, Any]]:
    code, branch = shell_output(["git", "branch", "--show-current"], cwd=PROJECT_ROOT)
    branch = branch.strip()
    checks = [
        result(
            "pass" if PROJECT_ROOT.name == "Terminator-gpt-runtime" else "fail",
            f"runtime worktree is {PROJECT_ROOT}",
        ),
        result(
            "pass" if code == 0 and branch == "codex/gpt-runtime-policy" else "fail",
            f"runtime branch is {branch or 'unknown'}",
        ),
    ]
    if ORIGINAL_ROOT.exists():
        code2, branch2 = shell_output(["git", "branch", "--show-current"], cwd=ORIGINAL_ROOT)
        checks.append(
            result(
                "pass" if code2 == 0 else "warn",
                f"original Terminator worktree present at {ORIGINAL_ROOT}, branch {branch2.strip() or 'unknown'}",
            )
        )
    else:
        checks.append(result("warn", f"original Terminator sibling not found at {ORIGINAL_ROOT}"))
    return checks


def check_runtime_entrypoints(_: Context) -> list[dict[str, Any]]:
    terminator = (PROJECT_ROOT / "terminator.sh").read_text(encoding="utf-8")
    backend_runner = (PROJECT_ROOT / "tools" / "backend_runner.py").read_text(encoding="utf-8")
    required_shell = [
        "--backend",
        "--failover-to",
        "--runtime-profile",
        "TERMINATOR_RUNTIME_PROFILE",
        "claude|codex|hybrid",
        "claude|codex|auto|none",
    ]
    required_runner = [
        "normalize_backend",
        "resolve_failover_backend",
        "launcher_backend",
        "build_command",
        "detect_failure_kind",
        '"omx"',
        '"claude"',
    ]
    missing_shell = [needle for needle in required_shell if needle not in terminator]
    missing_runner = [needle for needle in required_runner if needle not in backend_runner]
    return [
        result("pass" if not missing_shell else "fail", "terminator.sh exposes runtime backend/profile/failover controls", missing=missing_shell),
        result("pass" if not missing_runner else "fail", "backend_runner has backend normalization, command build, and failure classification", missing=missing_runner),
    ]


def check_runtime_policy(_: Context) -> list[dict[str, Any]]:
    sys.path.insert(0, str(PROJECT_ROOT))
    from tools.runtime_policy import apply_profile, load_policy

    policy_path = PROJECT_ROOT / "config" / "runtime_policy.yaml"
    checks = [result("pass" if policy_path.exists() else "fail", "config/runtime_policy.yaml exists")]
    policy = load_policy()
    gpt = apply_profile(policy, "gpt-only")
    scope_first = apply_profile(policy, "scope-first-hybrid")
    gpt_backends = {entry.get("backend") for entry in gpt["roles"].values()}
    deep_roles = {"critic", "triager-sim", "exploiter", "source-auditor"}
    scope_first_missing = sorted(role for role in deep_roles if scope_first["roles"].get(role, {}).get("backend") != "codex")
    checks.append(result("pass" if gpt_backends == {"codex"} else "fail", "gpt-only routes every role to Codex/OMX", backends=sorted(gpt_backends)))
    checks.append(result("pass" if not scope_first_missing else "fail", "scope-first-hybrid routes security-critical roles to Codex", missing=scope_first_missing))
    return checks


def check_role_contracts(_: Context) -> list[dict[str, Any]]:
    agents = sorted((PROJECT_ROOT / ".claude" / "agents").glob("*.md"))
    contracts_dir = PROJECT_ROOT / "generated" / "role_contracts"
    contracts = sorted(contracts_dir.glob("*.txt")) if contracts_dir.exists() else []
    oversized = [str(path.relative_to(PROJECT_ROOT)) for path in contracts if path.stat().st_size > 8000]
    missing = []
    for path in agents:
        candidates = {path.stem, path.stem.replace("_", "-")}
        if not any((contracts_dir / f"{candidate}.txt").exists() for candidate in candidates):
            missing.append(path.stem)
    return [
        result("pass" if contracts_dir.exists() else "fail", "generated/role_contracts exists"),
        result("pass" if not missing else "fail", "every Claude agent has a compact contract", missing=missing, agent_count=len(agents), contract_count=len(contracts)),
        result("pass" if not oversized else "fail", "all compact contracts are <=8000 bytes", oversized=oversized),
    ]


def check_required_tools(_: Context) -> list[dict[str, Any]]:
    tools = [
        "runtime_matrix.py",
        "submission_fixture_index.py",
        "submission_quality_compare.py",
        "backend_smoke.py",
        "submission_candidate_replay.py",
        "runtime_hallucination_audit.py",
        "implementation_intent_audit.py",
    ]
    missing = [tool for tool in tools if not file_exists(PROJECT_ROOT / "tools" / tool)]
    return [result("pass" if not missing else "fail", "required verification/runtime tools exist", missing=missing)]


def matrix_pairs(payload: dict[str, Any]) -> set[tuple[str, str]]:
    return {
        (str(item.get("profile")), str(item.get("pipeline")))
        for item in payload.get("results", [])
        if isinstance(item, dict)
    }


def check_verification_matrices(ctx: Context) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    expected_dag = {(profile, pipeline) for profile in PROFILES for pipeline in DAG_PIPELINES}
    expected_term = {(profile, pipeline) for profile in PROFILES for pipeline in TERMINATOR_PIPELINES}
    for rel, expected in [
        ("matrix.json", expected_dag),
        ("live_dry_run/matrix.json", expected_dag),
        ("terminator_dry_run_matrix.json", expected_term),
    ]:
        path = ctx.eval_dir / rel
        if not path.exists():
            checks.append(result("fail", f"{rel} missing"))
            continue
        payload = ctx.read_json(rel)
        pairs = matrix_pairs(payload)
        status = payload.get("status")
        rows = payload.get("results", [])
        failed_rows = [item for item in rows if isinstance(item, dict) and item.get("status") not in {"pass", "passed"}]
        checks.append(result("pass" if pairs == expected else "fail", f"{rel} has exact profile/pipeline coverage", expected=len(expected), actual=len(pairs)))
        checks.append(result("pass" if status == "pass" and not failed_rows else "fail", f"{rel} records passing rows", matrix_status=status, failed_rows=len(failed_rows)))
    return checks


def check_backend_smoke(ctx: Context) -> list[dict[str, Any]]:
    path = ctx.eval_dir / "backend_smoke.json"
    if not path.exists():
        return [result("fail", "backend_smoke.json missing")]
    payload = ctx.read_json("backend_smoke.json")
    observed = payload.get("observed_messages", [])
    expected = payload.get("expected_text")
    runner = payload.get("backend_runner_result", {})
    return [
        result("pass" if payload.get("status") == "pass" else "fail", "real Codex backend smoke passed", smoke_status=payload.get("status")),
        result("pass" if expected in observed else "fail", "expected model text was observed in JSON event stream", expected=expected, observed=observed),
        result("pass" if isinstance(runner, dict) and runner.get("status") == "completed" else "fail", "backend_runner classified Codex success as completed", runner_status=runner.get("status") if isinstance(runner, dict) else None),
    ]


def check_submission_comparison(ctx: Context) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    fixtures = ctx.read_json("submission_fixtures.json")
    packages = fixtures.get("packages", {})
    names = {
        item.get("name")
        for group_items in packages.values()
        if isinstance(group_items, list)
        for item in group_items
        if isinstance(item, dict)
    }
    checks.append(result("pass" if names == BASELINE_PACKAGES else "fail", "baseline manifest covers intended existing submissions", expected=sorted(BASELINE_PACKAGES), actual=sorted(names)))

    quality = ctx.read_json("quality_delta.json")
    baseline_names = {item.get("name") for item in quality.get("baseline", []) if isinstance(item, dict)}
    candidate = quality.get("candidate", [])
    candidate_names = {item.get("name") for item in candidate if isinstance(item, dict)}
    md_text = (ctx.eval_dir / "quality_delta.md").read_text(encoding="utf-8", errors="ignore")
    checks.append(result("pass" if baseline_names == BASELINE_PACKAGES else "fail", "quality_delta rescored every baseline package", actual=sorted(baseline_names)))
    missing_candidate_scores = sorted(BASELINE_PACKAGES - candidate_names)
    checks.append(result("pass" if not missing_candidate_scores else "fail", "all baseline packages have candidate quality scores", candidate_count=len(candidate), missing=missing_candidate_scores))
    if not candidate:
        checks.append(result("pass" if "baseline-only fixture calibration" in md_text else "fail", "baseline-only limitation is disclosed in markdown"))
    return checks


def check_end_to_end_candidate_generation(ctx: Context) -> list[dict[str, Any]]:
    candidate_base = ctx.eval_dir / "candidate_replay"
    coverage: dict[str, list[str]] = {}
    for profile in ["gpt-only", "scope-first-hybrid"]:
        profile_dir = candidate_base / profile
        names = [
            path.parent.name
            for path in profile_dir.glob("*/submission")
            if (path / "report.md").exists()
            and any(path.glob("poc_*"))
            and (path / "evidence_summary.md").exists()
            and (path / "triager_sim_result.json").exists()
        ] if profile_dir.exists() else []
        coverage[profile] = sorted(names)
    missing = {
        profile: sorted(BASELINE_PACKAGES - set(names))
        for profile, names in coverage.items()
        if set(names) != BASELINE_PACKAGES
    }
    return [
        result(
            "pass" if not missing else "fail",
            "gpt-only and scope-first-hybrid real-model replay candidate packages cover every baseline submission",
            coverage=coverage,
            missing=missing,
        )
    ]


def check_hallucination_guard(ctx: Context) -> list[dict[str, Any]]:
    path = ctx.eval_dir / "hallucination_audit.json"
    if not path.exists():
        return [result("fail", "hallucination_audit.json missing")]
    payload = ctx.read_json("hallucination_audit.json")
    failures = [item for item in payload.get("checks", []) if item.get("status") == "fail"]
    return [
        result("pass" if payload.get("status") == "pass" and not failures else "fail", "report-level hallucination audit has no failures", audit_status=payload.get("status"), failures=len(failures)),
    ]


def check_secall_concurrent_work(_: Context) -> list[dict[str, Any]]:
    if not ORIGINAL_ROOT.exists():
        return [result("warn", "original Terminator worktree not present; seCall integration not checked")]
    required = [
        ORIGINAL_ROOT / "tools" / "secall_bridge.py",
        ORIGINAL_ROOT / "scripts" / "install_secall.sh",
        ORIGINAL_ROOT / "docs" / "external-integrations" / "secall.md",
        ORIGINAL_ROOT / "tests" / "test_secall_bridge.py",
    ]
    missing = [str(path) for path in required if not path.exists()]
    gitignore = (ORIGINAL_ROOT / ".gitignore").read_text(encoding="utf-8", errors="ignore") if (ORIGINAL_ROOT / ".gitignore").exists() else ""
    return [
        result("pass" if not missing else "fail", "seCall integration files exist in original worktree", missing=missing),
        result("pass" if ".secall/" in gitignore else "fail", ".secall local state is ignored"),
    ]


REQUIREMENTS = [
    Requirement("worktree-isolation", "Use the dedicated GPT runtime worktree/branch while keeping seCall work separate.", check_worktree_isolation),
    Requirement("runtime-entrypoints", "Make claude/codex/hybrid backend and failover controls real in the launcher.", check_runtime_entrypoints),
    Requirement("runtime-policy", "Provide role-level gpt-only and scope-first-hybrid policy routing.", check_runtime_policy),
    Requirement("role-contracts", "Generate compact Codex-readable contracts for Claude agent roles.", check_role_contracts),
    Requirement("required-tools", "Add matrix, fixture, quality, backend-smoke, and hallucination audit tools.", check_required_tools),
    Requirement("verification-matrices", "Directly exercise every pipeline/profile combination in safe verification modes.", check_verification_matrices),
    Requirement("backend-smoke", "Prove Codex/OMX backend execution works through backend_runner.", check_backend_smoke),
    Requirement("submission-comparison", "Index and rescore existing submissions, and disclose whether candidate comparison exists.", check_submission_comparison),
    Requirement("end-to-end-candidates", "Generate GPT/scope-first-hybrid candidate submission packages for direct quality comparison.", check_end_to_end_candidate_generation),
    Requirement("hallucination-guard", "Run a report-level anti-hallucination audit over generated evidence.", check_hallucination_guard),
    Requirement("secall-concurrent-work", "Keep the original seCall integration coherent while GPT runtime work proceeds.", check_secall_concurrent_work),
]


def run_audit(ctx: Context) -> dict[str, Any]:
    req_results: list[dict[str, Any]] = []
    for requirement in REQUIREMENTS:
        try:
            checks = requirement.checker(ctx)
        except Exception as exc:  # noqa: BLE001 - audit must capture unexpected gaps.
            checks = [result("fail", f"checker raised {type(exc).__name__}: {exc}")]
        statuses = {check["status"] for check in checks}
        if "fail" in statuses:
            status = "fail"
        elif "warn" in statuses:
            status = "warn"
        else:
            status = "pass"
        req_results.append(
            {
                "id": requirement.id,
                "intent": requirement.intent,
                "status": status,
                "checks": checks,
            }
        )
    overall = "incomplete" if any(item["status"] == "fail" for item in req_results) else "pass"
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "eval_dir": str(ctx.eval_dir),
        "status": overall,
        "requirements": req_results,
    }


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    lines = ["# Implementation Intent Audit", ""]
    lines.append(f"Generated: {payload['generated_at']}")
    lines.append(f"Status: {payload['status']}")
    lines.append("")
    lines.append("| Status | Requirement | Intent |")
    lines.append("|---|---|---|")
    for item in payload["requirements"]:
        lines.append(f"| {item['status']} | `{item['id']}` | {item['intent']} |")
    lines.append("")
    lines.append("## Check Details")
    for item in payload["requirements"]:
        lines.append("")
        lines.append(f"### {item['id']} ({item['status']})")
        for check in item["checks"]:
            lines.append(f"- {check['status']}: {check['detail']}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval-dir", type=Path, default=latest_eval_dir())
    parser.add_argument("--exit-zero-on-incomplete", action="store_true")
    args = parser.parse_args()

    ctx = Context(args.eval_dir)
    payload = run_audit(ctx)
    json_path = ctx.eval_dir / "implementation_intent_audit.json"
    md_path = ctx.eval_dir / "implementation_intent_audit.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(md_path, payload)
    print(json_path)
    print(md_path)
    if payload["status"] != "pass" and not args.exit_zero_on_incomplete:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
