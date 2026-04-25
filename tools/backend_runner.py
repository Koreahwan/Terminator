#!/usr/bin/env python3
"""Backend runner for Terminator launcher sessions.

Supports Claude-only, GPT/Codex-only, and hybrid runtime profiles.  The
launcher backend is still a CLI process (`claude` or `omx`); per-role routing
for hybrid runs is injected through the runtime policy summary.
"""

from __future__ import annotations

import argparse
import json
import os
import selectors
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COORD_CLI = PROJECT_ROOT / "tools" / "coordination_cli.py"

# Dispatch-aware idle timeout integration.
# runtime_dispatch.py writes this file when async dispatches are active.
DISPATCH_KEEPALIVE_FILE = PROJECT_ROOT / ".dispatch_active"
DISPATCH_STATE_DIR = PROJECT_ROOT / ".dispatch_state"
IDLE_TIMEOUT_DEFAULT = 120       # seconds — normal idle kill threshold
IDLE_TIMEOUT_DISPATCH = 600      # seconds — extended when async dispatches active

BACKEND_TOOL = {
    "claude": "claude_code",
    "codex": "omx",
}

FAILOVER_PATTERNS = {
    "quota_exhausted": (
        "quota",
        "hit your limit",
        "you've hit your limit",
        "you hit your limit",
        "usage limit",
        "rate limit",
        "request limit",
        "too many requests",
        "credit balance is too low",
        "tokens per",
        "exceeded your current quota",
        "reached your usage limit",
    ),
    "context_exhausted": (
        "context length",
        "maximum context",
        "too many tokens",
        "prompt is too long",
    ),
    "auth_failed": (
        "authentication",
        "unauthorized",
        "forbidden",
        "invalid api key",
        "login required",
        "not logged in",
    ),
    "network_blocked": (
        "dns error",
        "operation not permitted",
        "failed to connect to websocket",
        "transport channel closed",
        "name or service not known",
        "temporary failure in name resolution",
    ),
    "service_unavailable": (
        "api error",
        "server error",
        "internal server error",
        "service unavailable",
        "bad gateway",
        "gateway timeout",
        "overloaded_error",
        "overloaded",
        "temporarily unavailable",
        "upstream error",
        "connection reset",
        "connection aborted",
        "502",
        "503",
        "504",
    ),
}


def _dispatches_active() -> bool:
    """Check if async runtime dispatches are currently active.

    Returns True if the keepalive file exists and was updated within the
    last 10 minutes, indicating runtime_dispatch.py has live background jobs.
    """
    try:
        if not DISPATCH_KEEPALIVE_FILE.exists():
            return False
        data = json.loads(DISPATCH_KEEPALIVE_FILE.read_text(encoding="utf-8"))
        active = data.get("active_dispatches", 0)
        updated = data.get("updated_at", 0)
        # Stale keepalive (>10min old) is treated as inactive
        if time.time() - updated > 600:
            return False
        return active > 0
    except (json.JSONDecodeError, OSError):
        return False


def _cleanup_orphan_dispatches() -> None:
    """Clean up any async dispatches left running when the outer session ends.

    Spec requirement: no async Codex child may be left orphaned silently.
    """
    if not DISPATCH_STATE_DIR.exists():
        return
    for d in DISPATCH_STATE_DIR.iterdir():
        state_file = d / "state.json"
        if not state_file.exists():
            continue
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
            if state.get("status") == "running":
                pid = state.get("pid")
                if pid:
                    try:
                        import signal as _sig
                        os.killpg(os.getpgid(pid), _sig.SIGTERM)
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                state["status"] = "orphan_killed"
                state["duration_sec"] = int(time.time() - state.get("started_at", time.time()))
                state_file.write_text(
                    json.dumps(state, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
        except (json.JSONDecodeError, OSError):
            pass
    # Remove keepalive
    DISPATCH_KEEPALIVE_FILE.unlink(missing_ok=True)


CODEX_SKIP_MODELS = {"sonnet", "opus", "haiku"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Terminator with Claude, Codex, or hybrid runtime profiles.")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run")
    run.add_argument("--backend", default="claude")
    run.add_argument("--failover-to", default="auto")
    run.add_argument("--prompt-file", required=True)
    run.add_argument("--work-dir", required=True)
    run.add_argument("--report-dir", required=True)
    run.add_argument("--model")
    run.add_argument("--runtime-profile")
    run.add_argument("--mode", default="unknown")
    run.add_argument("--target", default="")
    run.add_argument("--scope", default="")
    run.add_argument("--session-id")
    run.add_argument("--resume-session")
    run.add_argument("--timeout", type=int, default=0)
    run.add_argument("--result-file")
    return parser.parse_args()


def read_prompt(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def runtime_profile_for_backend(requested_backend: str, explicit: str | None = None) -> str:
    if explicit:
        return explicit.strip().lower()
    env_profile = os.environ.get("TERMINATOR_RUNTIME_PROFILE", "").strip().lower()
    if env_profile:
        return env_profile
    if requested_backend == "codex":
        return "gpt-only"
    if requested_backend == "hybrid":
        return "hybrid"
    return "claude-only"


def launcher_backend(requested_backend: str) -> str:
    if requested_backend == "hybrid":
        return os.environ.get("TERMINATOR_HYBRID_LAUNCHER_BACKEND", "claude").strip().lower() or "claude"
    return requested_backend


def default_model(backend: str, explicit: str | None) -> str:
    if explicit:
        return model_for_backend(backend, explicit)
    if backend == "codex":
        return os.environ.get("TERMINATOR_CODEX_MODEL") or os.environ.get("TERMINATOR_MODEL") or "gpt-5.4"
    return os.environ.get("TERMINATOR_CLAUDE_MODEL") or os.environ.get("TERMINATOR_MODEL") or "sonnet"


def model_for_backend(backend: str, value: str | None) -> str:
    """Coerce accidental Claude aliases away from Codex commands."""
    if backend != "codex":
        return value or default_model(backend, None)
    lowered = (value or "").strip().lower()
    if not lowered or lowered in CODEX_SKIP_MODELS or lowered.startswith("claude"):
        return os.environ.get("TERMINATOR_CODEX_MODEL") or "gpt-5.4"
    return value or os.environ.get("TERMINATOR_CODEX_MODEL") or "gpt-5.4"


def normalize_backend(value: str) -> str:
    lowered = (value or "claude").strip().lower()
    if lowered == "auto":
        return os.environ.get("TERMINATOR_PRIMARY_BACKEND", "claude").strip().lower() or "claude"
    if lowered in {"claude", "codex", "hybrid"}:
        return lowered
    raise ValueError(f"Unsupported backend: {value}")


def resolve_failover_backend(primary: str, requested: str) -> str | None:
    lowered = (requested or "auto").strip().lower()
    if lowered in {"", "none"}:
        return None
    if lowered == "auto":
        return "codex" if primary in {"claude", "hybrid"} else "claude"
    if lowered == primary:
        return None
    if lowered in {"claude", "codex"}:
        return lowered
    raise ValueError(f"Unsupported failover backend: {requested}")


def build_command(backend: str, *, work_dir: str, model: str, prompt: str) -> tuple[list[str], str | None]:
    """Return (cmd, stdin_text).

    For claude, prompts are written to a temp file and provided via stdin
    without using a shell pipeline. The temp file path is stored on the
    returned list object so the caller can clean it up.
    """
    backend = launcher_backend(normalize_backend(backend))
    if backend == "claude":
        # Write prompt to temp file; stream_process will open it for stdin.
        fd, tmp_path = tempfile.mkstemp(prefix="terminator_prompt_", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(prompt)
        cmd = _CmdWithTmp(
            [
                "claude",
                "-p",
                "-",
                "--permission-mode", "bypassPermissions",
                "--model", model,
            ],
            tmp_path,
        )
        return cmd, None  # stdin_text=None; prompt goes via file pipe

    codex_model = model_for_backend("codex", model)
    return [
        "omx",
        "exec",
        "--dangerously-bypass-approvals-and-sandbox",
        "-C",
        work_dir,
        "-m",
        codex_model,
        "--json",
        "-",
    ], prompt


class _CmdWithTmp(list):
    """list subclass that carries a temp file path for cleanup."""
    def __init__(self, items: list[str], tmp_path: str):
        super().__init__(items)
        self.tmp_path = tmp_path


def detect_failure_kind(text: str, returncode: int, timed_out: bool) -> str:
    lowered = (text or "").lower()
    if timed_out:
        return "timeout"
    if returncode == 0:
        return "completed"
    for label, patterns in FAILOVER_PATTERNS.items():
        if any(pattern in lowered for pattern in patterns):
            return label
    return "runtime_failed"


def should_failover(primary: str, fallback: str | None, failure_kind: str, output_text: str) -> bool:
    if fallback is None or primary == fallback:
        return False

    if failure_kind in {"quota_exhausted", "context_exhausted", "network_blocked", "service_unavailable"}:
        return True

    lowered = (output_text or "").lower()
    retry_or_api_signals = (
        "retry",
        "api error",
        "server error",
        "service unavailable",
        "internal server error",
        "bad gateway",
        "gateway timeout",
        "overloaded",
        "connection reset",
        "temporarily unavailable",
    )
    if failure_kind in {"runtime_failed", "timeout"} and any(token in lowered for token in retry_or_api_signals):
        return True

    return False


def run_coordination(args: list[str]) -> None:
    if not COORD_CLI.exists():
        return
    try:
        subprocess.run(
            ["python3", str(COORD_CLI), *args],
            cwd=str(PROJECT_ROOT),
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception:
        pass


def ensure_session(session_id: str, *, work_dir: str, backend: str, metadata: dict[str, object]) -> None:
    run_coordination(
        [
            "ensure-session",
            "--session",
            session_id,
            "--cwd",
            work_dir,
            "--leader",
            backend,
            "--tool",
            BACKEND_TOOL[backend],
            "--lead-mode",
            "auto",
            "--status",
            "active",
            "--metadata-json",
            json.dumps(metadata, ensure_ascii=False),
        ]
    )


def write_handoff(
    session_id: str,
    *,
    from_backend: str,
    to_backend: str,
    reason: str,
    decision_scope: str,
    artifacts: list[str],
) -> None:
    command = [
        "write-handoff",
        "--session",
        session_id,
        "--from",
        from_backend,
        "--to",
        to_backend,
        "--reason",
        reason,
        "--decision-scope",
        decision_scope,
        "--required-output",
        "Continue existing Terminator run without repeating completed phases.",
    ]
    for artifact in artifacts:
        command.extend(["--artifact-ref", artifact])
    run_coordination(command)


def existing_artifacts(report_dir: Path) -> list[str]:
    artifacts: list[str] = []
    for path in sorted(report_dir.glob("*")):
        if path.is_file():
            artifacts.append(str(path.resolve()))
    return artifacts[:20]


RUNTIME_POLICY_TOOL = PROJECT_ROOT / "tools" / "runtime_policy.py"


def _load_policy_summary() -> str | None:
    """Load compact runtime policy summary for orchestrator prompt injection.

    Returns the summary text, or None if the policy tool is unavailable.
    """
    if not RUNTIME_POLICY_TOOL.exists():
        return None
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(RUNTIME_POLICY_TOOL),
                "--profile",
                os.environ.get("TERMINATOR_RUNTIME_PROFILE", ""),
                "get-policy-summary",
            ],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT), timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def inject_policy_summary(prompt: str, *, requested_backend: str, launcher: str, profile: str) -> str:
    """Prepend runtime policy summary to the orchestrator prompt.

    Per spec v3.4 §2.1: the production launcher pre-injects a compact
    runtime policy summary into the Claude orchestrator prompt.
    """
    if os.environ.get("TERMINATOR_SKIP_POLICY_INJECTION", "").strip().lower() in {"1", "true", "yes"}:
        return prompt
    summary = _load_policy_summary()
    runtime_block = f"""[RUNTIME MODE]
Requested backend: {requested_backend}
Launcher backend: {launcher}
Runtime profile: {profile}

If the launcher is Codex/OMX, do not use Claude Agent Teams or Task-tool-only
syntax. Execute role work directly from the compact contracts in
generated/role_contracts/ and the artifacts named in the pipeline prompt.

If the runtime profile is hybrid, use tools/runtime_policy.py get-role <role>
and tools/runtime_dispatch.py run-role <role> for offloaded roles when the
orchestrator needs a separate worker. Keep all handoffs in coordination/.
"""
    if not summary:
        return runtime_block.strip() + "\n\n" + prompt
    return f"{runtime_block.strip()}\n\n[RUNTIME POLICY]\n{summary}\n\n{prompt}"


def augment_prompt(
    base_prompt: str,
    *,
    session_id: str,
    backend: str,
    previous_backend: str | None,
    reason: str | None,
    report_dir: Path,
) -> str:
    if not previous_backend:
        return base_prompt

    artifact_lines = "\n".join(f"- {artifact}" for artifact in existing_artifacts(report_dir)) or "- None yet"
    resume_block = f"""
[FAILOVER RESUME]
Session id: {session_id}
Current backend: {backend}
Previous backend: {previous_backend}
Failover reason: {reason or "runtime_failed"}
Report directory: {report_dir}

Continue from the latest completed phase. Reuse existing artifacts and checkpoints.
Do not restart the pipeline from scratch unless the prior run produced no usable artifacts.
You are acting as the spare backend after Claude stopped because of token/context exhaustion or provider/API instability.

Known artifacts:
{artifact_lines}

"""
    return resume_block.strip() + "\n\n" + base_prompt


def stream_process(
    cmd: list[str],
    *,
    cwd: str,
    stdin_text: str | None,
    timeout: int,
) -> tuple[int, str, bool]:
    tmp_path: str | None = getattr(cmd, "tmp_path", None)
    stdin_file = None
    try:
        if tmp_path is not None:
            stdin_file = open(tmp_path, "r", encoding="utf-8")

        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdin=stdin_file if stdin_file is not None else (subprocess.PIPE if stdin_text is not None else None),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        # Feed stdin in a background thread (PIPE mode only)
        stdin_thread: threading.Thread | None = None
        if stdin_text is not None and proc.stdin is not None:
            def _feed_stdin() -> None:
                try:
                    proc.stdin.write(stdin_text)  # type: ignore[union-attr]
                    proc.stdin.flush()
                    proc.stdin.close()  # type: ignore[union-attr]
                except (BrokenPipeError, OSError):
                    pass

            stdin_thread = threading.Thread(target=_feed_stdin, daemon=True)
            stdin_thread.start()

        selector = selectors.DefaultSelector()
        assert proc.stdout is not None
        selector.register(proc.stdout, selectors.EVENT_READ)
        started = time.monotonic()
        last_output = time.monotonic()
        chunks: list[str] = []
        timed_out = False
        # Dispatch-aware idle timeout: extend when async dispatches are active
        try:
            idle_timeout = int(os.environ.get("TERMINATOR_BACKEND_IDLE_TIMEOUT", str(IDLE_TIMEOUT_DEFAULT)))
        except ValueError:
            idle_timeout = IDLE_TIMEOUT_DEFAULT

        while True:
            if timeout and (time.monotonic() - started) > timeout:
                timed_out = True
                proc.kill()
                break

            # Idle detection: dispatch-aware — extend when async jobs are active
            effective_idle = IDLE_TIMEOUT_DISPATCH if _dispatches_active() else idle_timeout
            if (time.monotonic() - last_output) > effective_idle and chunks:
                timed_out = True
                proc.kill()
                break

            if proc.poll() is not None:
                remaining = proc.stdout.read()
                if remaining:
                    print(remaining, end="")
                    chunks.append(remaining)
                break

            events = selector.select(timeout=0.5)
            for key, _ in events:
                line = key.fileobj.readline()
                if line:
                    print(line, end="")
                    chunks.append(line)
                    last_output = time.monotonic()

        if stdin_thread is not None:
            stdin_thread.join(timeout=10)
        returncode = proc.wait()
        selector.close()
        return returncode, "".join(chunks), timed_out
    finally:
        if stdin_file is not None:
            try:
                stdin_file.close()
            except OSError:
                pass
        # Clean up temp prompt file
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def write_result(path: str | None, payload: dict[str, object]) -> None:
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    if args.command != "run":
        return 1

    requested_primary = normalize_backend(args.backend)
    profile = runtime_profile_for_backend(requested_primary, args.runtime_profile)
    os.environ["TERMINATOR_RUNTIME_PROFILE"] = profile
    primary = launcher_backend(requested_primary)
    if primary not in {"claude", "codex"}:
        raise ValueError(f"Unsupported launcher backend for {requested_primary}: {primary}")
    fallback = resolve_failover_backend(primary, args.failover_to)
    prompt = read_prompt(args.prompt_file)
    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    work_dir = str(Path(args.work_dir).resolve())
    session_id = args.resume_session or args.session_id or f"{int(time.time())}-{requested_primary}"

    attempts: list[dict[str, object]] = []
    backend_chain = [primary]
    if fallback:
        backend_chain.append(fallback)

    previous_backend: str | None = None
    previous_failure: str | None = None

    for index, backend in enumerate(backend_chain, start=1):
        model = default_model(backend, args.model if backend == primary else None)
        ensure_session(
            session_id,
            work_dir=work_dir,
            backend=backend,
            metadata={
                "backend": backend,
                "backend_requested": requested_primary,
                "runtime_profile": profile,
                "target": args.target,
                "scope": args.scope,
                "mode": args.mode,
                "report_dir": str(report_dir),
                "attempt": index,
                "backend_chain": backend_chain,
                "resume_session": args.resume_session,
            },
        )

        active_prompt = augment_prompt(
            prompt,
            session_id=session_id,
            backend=backend,
            previous_backend=previous_backend,
            reason=previous_failure,
            report_dir=report_dir,
        )

        active_prompt = inject_policy_summary(
            active_prompt,
            requested_backend=requested_primary,
            launcher=backend,
            profile=profile,
        )

        print(f"=== BACKEND ATTEMPT {index}: {backend} (model={model}) ===")
        cmd, stdin_text = build_command(backend, work_dir=work_dir, model=model, prompt=active_prompt)
        try:
            returncode, output_text, timed_out = stream_process(cmd, cwd=work_dir, stdin_text=stdin_text, timeout=args.timeout)
        except FileNotFoundError as exc:
            returncode, output_text, timed_out = 127, str(exc), False
            print(output_text)
        failure_kind = detect_failure_kind(output_text, returncode, timed_out)

        attempt = {
            "backend": backend,
            "model": model,
            "returncode": returncode,
            "failure_kind": failure_kind,
            "timed_out": timed_out,
        }
        attempts.append(attempt)

        if failure_kind == "completed":
            result = {
                "status": "completed",
                "session_id": session_id,
                "backend_requested": requested_primary,
                "backend_used": backend,
                "runtime_profile": profile,
                "failover_used": backend != primary,
                "failover_count": max(len(attempts) - 1, 0),
                "attempts": attempts,
            }
            write_result(args.result_file, result)
            print(f"\n=== BACKEND COMPLETE: {backend} ===")
            return 0

        if fallback is None or backend == fallback or not should_failover(primary, fallback, failure_kind, output_text):
            break

        write_handoff(
            session_id,
            from_backend=backend,
            to_backend=fallback,
            reason=failure_kind,
            decision_scope=f"Resume {args.mode} run for target {args.target or args.scope or args.mode}",
            artifacts=existing_artifacts(report_dir),
        )
        previous_backend = backend
        previous_failure = failure_kind
        print(f"\n=== FAILOVER: {backend} -> {fallback} ({failure_kind}) ===")

    result = {
        "status": attempts[-1]["failure_kind"] if attempts else "runtime_failed",
        "session_id": session_id,
        "backend_requested": requested_primary,
        "backend_used": attempts[-1]["backend"] if attempts else primary,
        "runtime_profile": profile,
        "failover_used": len(attempts) > 1,
        "failover_count": max(len(attempts) - 1, 0),
        "attempts": attempts,
    }
    write_result(args.result_file, result)
    return 1


if __name__ == "__main__":
    try:
        rc = main()
    finally:
        # Spec: no async Codex child may be left orphaned silently
        _cleanup_orphan_dispatches()
    sys.exit(rc)
