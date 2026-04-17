#!/usr/bin/env python3
"""Runtime dispatch tool for Terminator selective offload.

Dispatches roles to Claude or Codex backends based on runtime_policy.yaml.
Manages sync/async execution, state persistence, and result collection.

Commands:
    run-role <role> [--async] [--context-file F] [--work-dir D] [--target T]
    check-status --dispatch-id <id>
    collect-result --dispatch-id <id>
    cleanup-dispatch --dispatch-id <id>
    list-dispatches
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DISPATCH_STATE_DIR = PROJECT_ROOT / ".dispatch_state"
GENERATED_CONTRACTS = PROJECT_ROOT / "generated" / "role_contracts"

# Keepalive marker file — backend_runner.py checks this to suppress idle timeout
KEEPALIVE_FILE = PROJECT_ROOT / ".dispatch_active"


def _load_policy_entry(role: str) -> dict:
    """Load a role's policy entry via runtime_policy.py."""
    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "tools" / "runtime_policy.py"),
         "get-role", role],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT),
    )
    if result.returncode != 0:
        raise ValueError(f"Policy lookup failed for role '{role}': {result.stderr.strip()}")
    return json.loads(result.stdout)


def _load_compact_contract(role: str) -> str | None:
    """Load pre-compiled compact contract for a role, if it exists."""
    contract_path = GENERATED_CONTRACTS / f"{role}.txt"
    if contract_path.exists():
        return contract_path.read_text(encoding="utf-8")
    return None


def _build_dispatch_prompt(role: str, policy: dict, *,
                           context_file: str | None = None,
                           target: str = "",
                           work_dir: str = "") -> str:
    """Assemble the full dispatch prompt from contract + context."""
    parts: list[str] = []

    # 1. Compact contract (if available)
    contract = _load_compact_contract(role)
    if contract:
        parts.append(contract)
    else:
        # Fallback: reference the agent definition file
        agent_path = PROJECT_ROOT / ".claude" / "agents" / f"{role}.md"
        if agent_path.exists():
            parts.append(f"Follow your agent definition in .claude/agents/{role}.md")

    # 2. Context refs
    if context_file:
        ctx_path = Path(context_file)
        if ctx_path.exists():
            ctx_text = ctx_path.read_text(encoding="utf-8")
            parts.append(f"\n## Context\n{ctx_text}")

    # 3. Target / work-dir metadata
    if target:
        parts.append(f"\nTarget: {target}")
    if work_dir:
        parts.append(f"Working directory: {work_dir}")

    return "\n\n".join(parts)


# Codex with ChatGPT accounts only supports OpenAI models.
# Claude-style aliases are dropped (use Codex default model).
CODEX_SKIP_MODELS = {"sonnet", "opus", "haiku"}


def _resolve_codex_model(model: str) -> str | None:
    """Resolve a policy model name to a Codex-compatible model ID.

    Returns None to use Codex default model (recommended for ChatGPT accounts).
    """
    if model in CODEX_SKIP_MODELS:
        return None  # use Codex default
    return model


def _build_command(backend: str, model: str, prompt: str, work_dir: str) -> tuple[list[str], str | None, str | None]:
    """Build CLI command for the chosen backend.

    Returns (cmd, stdin_text, temp_file_path).
    """
    if backend == "codex":
        codex_model = _resolve_codex_model(model)
        cmd = [
            "omx", "exec",
            "--dangerously-bypass-approvals-and-sandbox",
            "-C", work_dir,
        ]
        if codex_model:
            cmd.extend(["-m", codex_model])
        cmd.extend(["--json", "-"])
        return cmd, prompt, None

    # Claude: write prompt to temp file, pipe via stdin
    fd, tmp_path = tempfile.mkstemp(prefix="dispatch_prompt_", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(prompt)
    cmd = [
        "claude", "-p", "-",
        "--permission-mode", "bypassPermissions",
        "--model", model,
        "--output-format", "json",
    ]
    return cmd, None, tmp_path


def _ensure_dispatch_dir(dispatch_id: str) -> Path:
    """Create and return the dispatch state directory."""
    d = DISPATCH_STATE_DIR / dispatch_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_state(dispatch_id: str, state: dict) -> None:
    """Write dispatch state to disk."""
    d = _ensure_dispatch_dir(dispatch_id)
    (d / "state.json").write_text(
        json.dumps(state, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _read_state(dispatch_id: str) -> dict | None:
    """Read dispatch state from disk."""
    state_file = DISPATCH_STATE_DIR / dispatch_id / "state.json"
    if not state_file.exists():
        return None
    return json.loads(state_file.read_text(encoding="utf-8"))


def _update_keepalive(active_count: int) -> None:
    """Update the keepalive marker file. Remove if no active dispatches."""
    if active_count > 0:
        KEEPALIVE_FILE.write_text(
            json.dumps({
                "active_dispatches": active_count,
                "updated_at": time.time(),
            }) + "\n",
            encoding="utf-8",
        )
    elif KEEPALIVE_FILE.exists():
        KEEPALIVE_FILE.unlink(missing_ok=True)


def _count_active_dispatches() -> int:
    """Count dispatches with status 'running'."""
    if not DISPATCH_STATE_DIR.exists():
        return 0
    count = 0
    for d in DISPATCH_STATE_DIR.iterdir():
        sf = d / "state.json"
        if sf.exists():
            try:
                s = json.loads(sf.read_text(encoding="utf-8"))
                if s.get("status") == "running":
                    count += 1
            except (json.JSONDecodeError, OSError):
                pass
    return count


def _extract_token_usage(output: str, backend: str) -> dict | None:
    """Extract token usage from CLI output.

    Claude (--output-format json): single JSON object with 'usage' key.
    Codex (--json): JSONL stream, usage in 'turn.completed' events.
    """
    if not output:
        return None

    if backend == "claude":
        try:
            data = json.loads(output)
            if isinstance(data, dict) and "usage" in data:
                usage = data["usage"]
                return {
                    "input_tokens": usage.get("input_tokens", 0),
                    "output_tokens": usage.get("output_tokens", 0),
                    "cache_read_input_tokens": usage.get("cache_read_input_tokens", 0),
                    "cache_creation_input_tokens": usage.get("cache_creation_input_tokens", 0),
                    "total_cost_usd": data.get("total_cost_usd"),
                }
        except (json.JSONDecodeError, TypeError):
            pass
        return None

    if backend == "codex":
        # Parse JSONL, find last turn.completed with usage
        last_usage = None
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
                if isinstance(evt, dict) and evt.get("type") == "turn.completed" and "usage" in evt:
                    last_usage = evt["usage"]
            except (json.JSONDecodeError, TypeError):
                continue
        if last_usage:
            return {
                "input_tokens": last_usage.get("input_tokens", 0),
                "output_tokens": last_usage.get("output_tokens", 0),
                "cached_input_tokens": last_usage.get("cached_input_tokens", 0),
            }
        return None

    return None


# Known artifact filenames per role — used to scan work_dir after dispatch
ROLE_EXPECTED_ARTIFACTS: dict[str, list[str]] = {
    "patch-hunter": ["patch_analysis.md", "checkpoint.json"],
    "analyst": ["vulnerability_candidates.md", "checkpoint.json"],
    "scout": ["endpoint_map.md", "program_context.md", "workflow_map.md", "checkpoint.json"],
    "workflow-auditor": ["workflow_map.md", "checkpoint.json"],
    "threat-modeler": ["trust_boundary_map.md", "role_matrix.md", "state_machines.md",
                       "invariants.md", "checkpoint.json"],
    "reporter": ["report.md", "bugcrowd_form.md", "checkpoint.json"],
    "target-evaluator": ["target_assessment.md", "checkpoint.json"],
    "exploiter": ["poc.py", "poc_output.txt", "strengthening_report.md", "checkpoint.json"],
    "critic": ["critic_review.md"],
    "verifier": ["verification_report.md", "checkpoint.json"],
    "triager-sim": ["triage_verdict.md"],
}


def _scan_artifacts(work_dir: str, role: str) -> tuple[list[str], list[str]]:
    """Scan work_dir for expected role artifacts.

    Returns (found_paths, missing_names).
    """
    expected = ROLE_EXPECTED_ARTIFACTS.get(role, [])
    found: list[str] = []
    missing: list[str] = []
    wd = Path(work_dir)

    for name in expected:
        # Search in work_dir and common subdirectories
        candidates = [
            wd / name,
            wd / "submission" / name,
        ]
        hit = False
        for c in candidates:
            if c.exists():
                found.append(str(c))
                hit = True
                break
        if not hit:
            missing.append(name)

    return found, missing


def _make_result(state: dict, *, output: str = "", artifacts: list[str] | None = None,
                 missing: list[str] | None = None, error: str = "",
                 token_usage: dict | None = None) -> dict:
    """Build the canonical result JSON."""
    return {
        "status": state.get("status", "unknown"),
        "dispatch_id": state.get("dispatch_id", ""),
        "role": state.get("role", ""),
        "backend": state.get("backend", ""),
        "work_dir": state.get("work_dir", ""),
        "artifacts": artifacts or [],
        "missing_artifacts": missing or [],
        "duration_sec": state.get("duration_sec", 0),
        "token_usage": token_usage,
        "error_summary": error or None,
    }


def _finalize_completion_state(state: dict, *, exit_code: int, output: str = "",
                               error_text: str = "") -> tuple[dict, list[str], list[str]]:
    """Finalize a dispatch state after the backend process exits.

    Sync and async paths must apply the same completion semantics:
    successful exit -> completed
    failed exit + full artifact set -> completed via exit-code override
    failed exit + missing artifacts -> failed
    """
    state["status"] = "completed" if exit_code == 0 else "failed"
    if exit_code != 0:
        failure_excerpt = error_text or output
        if failure_excerpt:
            state["error"] = failure_excerpt[:500]

    work_dir = state.get("work_dir", "")
    role = state.get("role", "")
    found_artifacts, missing_names = _scan_artifacts(work_dir, role) if work_dir else ([], [])

    if state["status"] == "failed" and found_artifacts and not missing_names:
        state["status"] = "completed"
        state["exit_code_override"] = True
        state["original_exit_code"] = exit_code
        state.pop("error", None)

    return state, found_artifacts, missing_names


# ─── Commands ──────────────────────────────────────────────────────

def cmd_run_role(args: argparse.Namespace) -> int:
    """Execute run-role (sync or async)."""
    role = args.role
    is_async = args.async_mode

    # Load policy
    try:
        policy = _load_policy_entry(role)
    except ValueError as e:
        print(json.dumps({"status": "error", "error_summary": str(e)}))
        return 1

    backend = policy.get("backend", "claude")
    model = policy.get("model", "sonnet")
    work_dir = str(Path(args.work_dir or ".").resolve())

    # Build prompt
    prompt = _build_dispatch_prompt(
        role, policy,
        context_file=args.context_file,
        target=args.target or "",
        work_dir=work_dir,
    )

    # Dispatch ID
    dispatch_id = f"{role}-{int(time.time())}-{uuid.uuid4().hex[:8]}"

    # Initial state
    state = {
        "dispatch_id": dispatch_id,
        "role": role,
        "backend": backend,
        "model": model,
        "status": "running",
        "started_at": time.time(),
        "is_async": is_async,
        "work_dir": work_dir,
        "pid": None,
        "duration_sec": 0,
    }

    if is_async:
        return _run_async(dispatch_id, state, prompt, work_dir, backend, model)
    return _run_sync(dispatch_id, state, prompt, work_dir, backend, model)


def _run_sync(dispatch_id: str, state: dict, prompt: str,
              work_dir: str, backend: str, model: str) -> int:
    """Synchronous dispatch — block until done."""
    _write_state(dispatch_id, state)

    cmd, stdin_text, tmp_path = _build_command(backend, model, prompt, work_dir)
    stdin_file = None
    start = time.monotonic()

    try:
        if tmp_path:
            stdin_file = open(tmp_path, "r", encoding="utf-8")

        # input= and stdin= are mutually exclusive in subprocess.run
        run_kwargs: dict = {
            "capture_output": True,
            "text": True,
            "cwd": work_dir,
            "timeout": 3600,  # 1hr hard cap
        }
        if stdin_file:
            run_kwargs["stdin"] = stdin_file
        elif stdin_text is not None:
            run_kwargs["input"] = stdin_text

        result = subprocess.run(cmd, **run_kwargs)

        duration = int(time.monotonic() - start)
        state["duration_sec"] = duration

        # Capture both streams — stdout has JSONL events (token data),
        # stderr has error logs. Both are needed.
        stdout_text = result.stdout or ""
        stderr_text = result.stderr or ""

        dispatch_dir = DISPATCH_STATE_DIR / dispatch_id

        # Save raw output (both streams)
        (dispatch_dir / "output.txt").write_text(stdout_text, encoding="utf-8")
        if stderr_text:
            (dispatch_dir / "stderr.txt").write_text(stderr_text, encoding="utf-8")

        state, found_artifacts, missing_names = _finalize_completion_state(
            state,
            exit_code=result.returncode,
            output=stdout_text,
            error_text=stderr_text,
        )
        _write_state(dispatch_id, state)

        # Extract token usage from stdout (JSONL events)
        token_usage = _extract_token_usage(stdout_text, backend)

        result_json = _make_result(
            state,
            output=stdout_text,
            artifacts=found_artifacts,
            missing=missing_names,
            error=state.get("error", ""),
            token_usage=token_usage,
        )
        print(json.dumps(result_json, indent=2, ensure_ascii=False))
        return 0 if state["status"] == "completed" else 1

    except subprocess.TimeoutExpired:
        state["status"] = "timeout"
        state["duration_sec"] = 3600
        _write_state(dispatch_id, state)
        result_json = _make_result(state, error="Dispatch timed out after 3600s")
        print(json.dumps(result_json, indent=2, ensure_ascii=False))
        return 1
    finally:
        if stdin_file:
            stdin_file.close()
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _run_async(dispatch_id: str, state: dict, prompt: str,
               work_dir: str, backend: str, model: str) -> int:
    """Async dispatch — launch background process, return immediately."""
    dispatch_dir = _ensure_dispatch_dir(dispatch_id)

    # Write prompt to dispatch dir
    prompt_file = dispatch_dir / "prompt.txt"
    prompt_file.write_text(prompt, encoding="utf-8")

    # Build wrapper script that runs the command and writes result
    cmd, stdin_text, tmp_path = _build_command(backend, model, prompt, work_dir)

    # Write a runner script
    runner_script = dispatch_dir / "runner.sh"
    stdout_file = dispatch_dir / "output.txt"
    pid_file = dispatch_dir / "pid"
    done_file = dispatch_dir / "done"

    if backend == "codex":
        cmd_str = " ".join(f"'{c}'" for c in cmd) + f" < '{prompt_file}'"
    else:
        # Claude: pipe prompt file to stdin
        cmd_str = " ".join(f"'{c}'" for c in cmd) + f" < '{prompt_file}'"

    # Clean up any temp file from _build_command since we're using prompt_file instead
    if tmp_path:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    runner_script.write_text(f"""#!/bin/bash
echo $$ > '{pid_file}'
{cmd_str} > '{stdout_file}' 2>&1
echo $? > '{done_file}'
""", encoding="utf-8")
    runner_script.chmod(0o755)

    # Launch background process
    proc = subprocess.Popen(
        ["bash", str(runner_script)],
        cwd=work_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    state["pid"] = proc.pid
    _write_state(dispatch_id, state)

    # Update keepalive
    _update_keepalive(_count_active_dispatches())

    # Return dispatch info immediately
    result = {
        "status": "dispatched",
        "dispatch_id": dispatch_id,
        "role": state["role"],
        "backend": backend,
        "pid": proc.pid,
        "message": f"Async dispatch started. Check with: check-status --dispatch-id {dispatch_id}",
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_check_status(args: argparse.Namespace) -> int:
    """Check status of an async dispatch."""
    dispatch_id = args.dispatch_id
    state = _read_state(dispatch_id)
    if state is None:
        print(json.dumps({"status": "not_found", "dispatch_id": dispatch_id}))
        return 1

    dispatch_dir = DISPATCH_STATE_DIR / dispatch_id
    done_file = dispatch_dir / "done"

    if state["status"] == "running" and done_file.exists():
        # Process finished — update state
        exit_code_str = done_file.read_text(encoding="utf-8").strip()
        exit_code = int(exit_code_str) if exit_code_str.isdigit() else 1
        state["duration_sec"] = int(time.time() - state.get("started_at", time.time()))
        output_text = ""
        output_file = dispatch_dir / "output.txt"
        if output_file.exists():
            output_text = output_file.read_text(encoding="utf-8")
        state, _, _ = _finalize_completion_state(
            state,
            exit_code=exit_code,
            output=output_text,
        )
        _write_state(dispatch_id, state)
        _update_keepalive(_count_active_dispatches())

    print(json.dumps({
        "status": state["status"],
        "dispatch_id": dispatch_id,
        "role": state.get("role", ""),
        "backend": state.get("backend", ""),
        "duration_sec": state.get("duration_sec", 0),
        "pid": state.get("pid"),
    }, indent=2, ensure_ascii=False))
    return 0


def cmd_collect_result(args: argparse.Namespace) -> int:
    """Collect the result of a completed dispatch."""
    dispatch_id = args.dispatch_id
    state = _read_state(dispatch_id)
    if state is None:
        print(json.dumps({"status": "not_found", "dispatch_id": dispatch_id}))
        return 1

    # Re-check done status
    dispatch_dir = DISPATCH_STATE_DIR / dispatch_id
    done_file = dispatch_dir / "done"
    if state["status"] == "running":
        if done_file.exists():
            exit_code_str = done_file.read_text(encoding="utf-8").strip()
            exit_code = int(exit_code_str) if exit_code_str.isdigit() else 1
            state["duration_sec"] = int(time.time() - state.get("started_at", time.time()))
            output_text = ""
            output_file = dispatch_dir / "output.txt"
            if output_file.exists():
                output_text = output_file.read_text(encoding="utf-8")
            state, _, _ = _finalize_completion_state(
                state,
                exit_code=exit_code,
                output=output_text,
            )
            _write_state(dispatch_id, state)
            _update_keepalive(_count_active_dispatches())
        else:
            print(json.dumps({
                "status": "running",
                "dispatch_id": dispatch_id,
                "message": "Dispatch still running. Use check-status to poll.",
            }))
            return 1

    # Read output
    output = ""
    output_file = dispatch_dir / "output.txt"
    if output_file.exists():
        output = output_file.read_text(encoding="utf-8")

    # Extract token usage from output
    backend = state.get("backend", "claude")
    token_usage = _extract_token_usage(output, backend)

    # Scan for produced artifacts
    work_dir = state.get("work_dir", "")
    role = state.get("role", "")
    found_artifacts, missing_names = _scan_artifacts(work_dir, role) if work_dir else ([], [])

    result = _make_result(
        state,
        output=output,
        artifacts=found_artifacts,
        missing=missing_names,
        error=state.get("error", ""),
        token_usage=token_usage,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_cleanup_dispatch(args: argparse.Namespace) -> int:
    """Clean up dispatch state and kill any running process."""
    dispatch_id = args.dispatch_id
    state = _read_state(dispatch_id)
    if state is None:
        print(json.dumps({"status": "not_found", "dispatch_id": dispatch_id}))
        return 1

    # Kill process if still running
    pid = state.get("pid")
    if pid and state.get("status") == "running":
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    # Remove dispatch dir
    dispatch_dir = DISPATCH_STATE_DIR / dispatch_id
    if dispatch_dir.exists():
        import shutil
        shutil.rmtree(dispatch_dir, ignore_errors=True)

    _update_keepalive(_count_active_dispatches())

    print(json.dumps({
        "status": "cleaned",
        "dispatch_id": dispatch_id,
    }))
    return 0


def cmd_list_dispatches(args: argparse.Namespace) -> int:
    """List all tracked dispatches."""
    if not DISPATCH_STATE_DIR.exists():
        print(json.dumps({"dispatches": []}))
        return 0

    dispatches = []
    for d in sorted(DISPATCH_STATE_DIR.iterdir()):
        sf = d / "state.json"
        if sf.exists():
            try:
                s = json.loads(sf.read_text(encoding="utf-8"))
                dispatches.append({
                    "dispatch_id": s.get("dispatch_id", d.name),
                    "role": s.get("role", "?"),
                    "backend": s.get("backend", "?"),
                    "status": s.get("status", "?"),
                    "duration_sec": s.get("duration_sec", 0),
                })
            except (json.JSONDecodeError, OSError):
                pass

    print(json.dumps({"dispatches": dispatches}, indent=2, ensure_ascii=False))
    return 0


# ─── CLI ───────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Runtime dispatch for Terminator selective offload."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # run-role
    run = sub.add_parser("run-role", help="Dispatch a role to its assigned backend")
    run.add_argument("role", help="Role name (e.g. patch-hunter)")
    run.add_argument("--async", dest="async_mode", action="store_true",
                     help="Launch async (returns dispatch ID immediately)")
    run.add_argument("--context-file", help="Path to context refs file")
    run.add_argument("--work-dir", help="Working directory for the backend")
    run.add_argument("--target", help="Target identifier")

    # check-status
    cs = sub.add_parser("check-status", help="Check async dispatch status")
    cs.add_argument("--dispatch-id", required=True)

    # collect-result
    cr = sub.add_parser("collect-result", help="Collect completed dispatch result")
    cr.add_argument("--dispatch-id", required=True)

    # cleanup-dispatch
    cd = sub.add_parser("cleanup-dispatch", help="Clean up dispatch state")
    cd.add_argument("--dispatch-id", required=True)

    # list-dispatches
    sub.add_parser("list-dispatches", help="List all tracked dispatches")

    args = parser.parse_args()

    dispatch = {
        "run-role": cmd_run_role,
        "check-status": cmd_check_status,
        "collect-result": cmd_collect_result,
        "cleanup-dispatch": cmd_cleanup_dispatch,
        "list-dispatches": cmd_list_dispatches,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
