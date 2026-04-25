#!/usr/bin/env python3
"""Run or smoke-check every Terminator pipeline across runtime profiles."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_ROOT = PROJECT_ROOT / "reports" / "runtime-eval"
PIPELINES = ["target_discovery", "ctf_pwn", "ctf_rev", "bounty", "firmware", "ai_security", "robotics", "supplychain"]
PROFILES = ["claude-only", "gpt-only", "scope-first-hybrid"]
PROFILE_BACKEND = {"claude-only": "claude", "gpt-only": "codex", "scope-first-hybrid": "hybrid"}
DEEP_HYBRID_ROLES = {
    "analyst",
    "architect",
    "chain",
    "critic",
    "ctf-solver",
    "defi-auditor",
    "exploiter",
    "patch-hunter",
    "solver",
    "source-auditor",
    "submission-review",
    "triager-sim",
    "workflow-auditor",
    "target-discovery",
}
SCOPE_FIRST_GPT_ROLES = {
    "target-discovery",
    "scout",
    "recon-scanner",
    "source-auditor",
    "analyst",
}
SCOPE_FIRST_CLAUDE_ROLES = {
    "scope-auditor",
    "reporter",
    "submission-review",
}
SCOPE_FIRST_DEBATE_ROLES = {
    "exploiter",
    "critic",
    "triager-sim",
}


def load_policy(profile: str, pipeline: str = "") -> dict:
    cmd = ["python3", str(PROJECT_ROOT / "tools" / "runtime_policy.py"), "--profile", profile]
    if pipeline:
        cmd.extend(["--pipeline", pipeline])
    cmd.append("get-policy-summary")
    result = subprocess.run(
        cmd,
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())

    import sys

    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from tools.runtime_policy import apply_profile, load_policy as _load_policy

    return apply_profile(_load_policy(), profile, pipeline)


def compile_contracts() -> None:
    subprocess.run(
        ["python3", str(PROJECT_ROOT / "tools" / "compile_role_contracts.py"), "compile-all"],
        cwd=str(PROJECT_ROOT),
        check=True,
    )


def canonical_role(role: str) -> str:
    return role.replace("_", "-")


def contract_exists(role: str) -> bool:
    return (PROJECT_ROOT / "generated" / "role_contracts" / f"{canonical_role(role)}.txt").exists()


def rel(path: Path) -> str:
    path = path.resolve()
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def pipeline_dag(name: str, target: str):
    import sys

    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from tools.dag_orchestrator.pipelines import get_pipeline

    return get_pipeline(name, target)


def smoke_pipeline(pipeline: str, profile: str, out_dir: Path) -> dict:
    started = time.monotonic()
    policy = load_policy(profile, pipeline)
    dag = pipeline_dag(pipeline, f"matrix-{pipeline}")
    roles = []
    failures: list[str] = []
    for node_name, node in dag.nodes.items():
        role = canonical_role(node.role)
        entry = (policy.get("roles") or {}).get(role)
        if entry is None:
            failures.append(f"missing runtime policy for role {role}")
            backend = "missing"
            model = "missing"
        else:
            backend = entry.get("backend", "claude")
            model = entry.get("model", "")
            if profile == "gpt-only" and backend != "codex":
                failures.append(f"gpt-only role {role} routed to {backend}")
            if profile == "scope-first-hybrid":
                if role in SCOPE_FIRST_GPT_ROLES and backend != "codex":
                    failures.append(f"scope-first GPT role {role} routed to {backend}")
                if role in SCOPE_FIRST_CLAUDE_ROLES and backend != "claude":
                    failures.append(f"scope-first Claude role {role} routed to {backend}")
                if role in SCOPE_FIRST_DEBATE_ROLES and not entry.get("debate_mode"):
                    failures.append(f"scope-first debate role {role} missing debate_mode")
            if backend == "codex" and str(model).lower() in {"sonnet", "opus", "haiku"}:
                failures.append(f"codex role {role} has Claude alias model {model}")
        has_contract = contract_exists(role)
        if backend == "codex" and not has_contract:
            failures.append(f"missing Codex contract for role {role}")
        roles.append(
            {
                "node": node_name,
                "role": role,
                "backend": backend,
                "model": model,
                "contract": has_contract,
                "expected_artifacts": (entry or {}).get("expected_artifacts", []),
            }
        )
    duration = round(time.monotonic() - started, 2)
    return {
        "pipeline": pipeline,
        "profile": profile,
        "mode": "smoke",
        "status": "pass" if not failures else "fail",
        "duration_seconds": duration,
        "roles": roles,
        "failures": failures,
        "work_dir": rel(out_dir / profile / pipeline),
    }


def live_pipeline(pipeline: str, profile: str, out_dir: Path, *, dry_run_backend: bool) -> dict:
    import sys

    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from tools.dag_orchestrator.claude_handler import BackendAgentHandler

    started = time.monotonic()
    work_dir = out_dir / profile / pipeline / "work"
    work_dir.mkdir(parents=True, exist_ok=True)
    dag = pipeline_dag(pipeline, f"matrix-{pipeline}")
    os.environ["TERMINATOR_RUNTIME_PROFILE"] = profile
    os.environ["TERMINATOR_ACTIVE_PIPELINE"] = pipeline
    handler = BackendAgentHandler(
        work_dir=str(work_dir),
        session_id=f"matrix-{profile}-{pipeline}",
        target=f"matrix-{pipeline}",
        backend=PROFILE_BACKEND[profile],
        dry_run=dry_run_backend,
    )
    handler.attach_to_dag(dag)
    try:
        summary = dag.run()
        failed = bool(summary["failed"])
        status = "fail" if failed else "pass"
        failures = summary["failed"]
    except Exception as exc:
        summary = {"error": str(exc)}
        status = "fail"
        failures = [str(exc)]
    return {
        "pipeline": pipeline,
        "profile": profile,
        "mode": "live-dry-run" if dry_run_backend else "live",
        "status": status,
        "duration_seconds": round(time.monotonic() - started, 2),
        "summary": summary,
        "failures": failures,
        "work_dir": rel(work_dir),
    }


def write_markdown(path: Path, payload: dict) -> None:
    lines = ["# Runtime Matrix", ""]
    lines.append(f"Generated: {payload['generated_at']}")
    lines.append("")
    lines.append("| Profile | Pipeline | Mode | Status | Failures |")
    lines.append("|---|---|---|---|---:|")
    for result in payload["results"]:
        lines.append(
            f"| {result['profile']} | {result['pipeline']} | {result['mode']} | "
            f"{result['status']} | {len(result.get('failures', []))} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", nargs="+", default=PROFILES)
    parser.add_argument("--pipelines", nargs="+", default=PIPELINES)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--compile-contracts", action="store_true")
    parser.add_argument("--live", action="store_true", help="Actually attach backend handlers")
    parser.add_argument("--dry-run-backend", action="store_true", help="Use backend handlers in dry-run mode")
    args = parser.parse_args()

    if args.compile_contracts:
        compile_contracts()

    out_dir = args.out_dir or (DEFAULT_OUT_ROOT / time.strftime("%Y%m%d_%H%M%S"))
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for profile in args.profiles:
        for pipeline in args.pipelines:
            if args.live:
                result = live_pipeline(pipeline, profile, out_dir, dry_run_backend=args.dry_run_backend)
            else:
                result = smoke_pipeline(pipeline, profile, out_dir)
            results.append(result)

    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "profiles": args.profiles,
        "pipelines": args.pipelines,
        "results": results,
        "status": "pass" if all(item["status"] == "pass" for item in results) else "fail",
    }
    matrix_json = out_dir / "matrix.json"
    matrix_md = out_dir / "matrix.md"
    matrix_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(matrix_md, payload)
    print(matrix_json)
    print(matrix_md)
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
