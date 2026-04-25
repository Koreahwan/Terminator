#!/usr/bin/env python3
"""Run a minimal backend_runner smoke and preserve verifiable evidence."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_RUNNER = PROJECT_ROOT / "tools" / "backend_runner.py"


def parse_agent_messages(output: str) -> list[str]:
    messages: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if payload.get("type") != "item.completed":
            continue
        item = payload.get("item")
        if not isinstance(item, dict):
            continue
        if item.get("type") == "agent_message" and isinstance(item.get("text"), str):
            messages.append(item["text"])
    return messages


def write_markdown(path: Path, payload: dict[str, object]) -> None:
    lines = ["# Backend Smoke", ""]
    lines.append(f"Generated: {payload['generated_at']}")
    lines.append("")
    lines.append(f"- Backend: {payload['backend']}")
    lines.append(f"- Runtime profile: {payload['runtime_profile']}")
    lines.append(f"- Status: {payload['status']}")
    lines.append(f"- Expected text observed: {'yes' if payload['expected_text_observed'] else 'no'}")
    lines.append(f"- Failover count: {payload.get('failover_count', 0)}")
    lines.append("")
    lines.append("Observed agent messages:")
    for message in payload.get("observed_messages", []):
        lines.append(f"- `{message}`")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_smoke(
    *,
    backend: str,
    failover_to: str,
    runtime_profile: str,
    model: str,
    expected_text: str,
    timeout: int,
    work_dir: Path,
    out_dir: Path,
) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="terminator-backend-smoke.") as tmp:
        tmpdir = Path(tmp)
        prompt_file = tmpdir / "prompt.txt"
        report_dir = tmpdir / "report"
        result_file = tmpdir / "result.json"
        prompt_file.write_text(f"Respond with exactly: {expected_text}\n", encoding="utf-8")

        cmd = [
            "python3",
            str(BACKEND_RUNNER),
            "run",
            "--backend",
            backend,
            "--failover-to",
            failover_to,
            "--prompt-file",
            str(prompt_file),
            "--work-dir",
            str(work_dir),
            "--report-dir",
            str(report_dir),
            "--model",
            model,
            "--runtime-profile",
            runtime_profile,
            "--mode",
            "smoke",
            "--target",
            "backend-runner",
            "--timeout",
            str(timeout),
            "--result-file",
            str(result_file),
        ]
        started = time.monotonic()
        proc = subprocess.run(
            cmd,
            cwd=str(work_dir),
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )
        combined_output = (proc.stdout or "") + (proc.stderr or "")
        result: dict[str, object] = {}
        if result_file.exists():
            try:
                result = json.loads(result_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                result = {"status": "invalid_result_json"}

    observed_messages = parse_agent_messages(combined_output)
    expected_observed = expected_text in observed_messages
    attempts = result.get("attempts") if isinstance(result, dict) else []
    failover_count = result.get("failover_count", 0) if isinstance(result, dict) else 0
    status = "pass" if proc.returncode == 0 and result.get("status") == "completed" and expected_observed else "fail"
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "smoke": "backend_runner_real_model_call",
        "status": status,
        "backend": backend,
        "runtime_profile": runtime_profile,
        "model": model,
        "returncode": proc.returncode,
        "duration_seconds": round(time.monotonic() - started, 2),
        "expected_text": expected_text,
        "expected_text_observed": expected_observed,
        "observed_messages": observed_messages,
        "backend_runner_result": result,
        "failover_count": failover_count,
        "attempts": attempts if isinstance(attempts, list) else [],
    }
    (out_dir / "backend_smoke.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(out_dir / "backend_smoke.md", payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", default="codex")
    parser.add_argument("--failover-to", default="none")
    parser.add_argument("--runtime-profile", default="gpt-only")
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument("--expected-text", default="TERMINATOR_BACKEND_RUNNER_CODEX_OK")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--work-dir", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()

    payload = run_smoke(
        backend=args.backend,
        failover_to=args.failover_to,
        runtime_profile=args.runtime_profile,
        model=args.model,
        expected_text=args.expected_text,
        timeout=args.timeout,
        work_dir=args.work_dir.resolve(),
        out_dir=args.out_dir,
    )
    print(args.out_dir / "backend_smoke.json")
    print(args.out_dir / "backend_smoke.md")
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
