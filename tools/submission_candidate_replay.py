#!/usr/bin/env python3
"""Generate safe GPT/scope-first replay candidate submission packages.

The generator uses existing submission artifacts as read-only replay fixtures.
It does not probe live targets or submit anything. The selected backend receives
a compact evidence digest and returns a candidate package as JSON; this script
writes the files and records the backend result for later quality comparison.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = PROJECT_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from backend_smoke import parse_agent_messages
from submission_quality_compare import iter_manifest_packages

BACKEND_RUNNER = PROJECT_ROOT / "tools" / "backend_runner.py"

PROFILE_BACKEND = {
    "claude-only": "claude",
    "gpt-only": "codex",
    "scope-first-hybrid": "hybrid",
}
PROFILE_FAILOVER = {
    "claude-only": "none",
    "gpt-only": "none",
    "scope-first-hybrid": "none",
}
TEXT_SUFFIXES = {
    ".md", ".txt", ".json", ".py", ".sh", ".js", ".mjs", ".ts", ".tsx",
    ".sol", ".toml", ".yaml", ".yml", ".log",
}


def safe_read(path: Path, *, max_chars: int) -> str:
    try:
        if path.suffix.lower() not in TEXT_SUFFIXES:
            return f"[binary or unsupported text fixture omitted: {path.name}]"
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return f"[unreadable fixture: {exc}]"
    if len(text) <= max_chars:
        return text
    head = text[: max_chars // 2]
    tail = text[-max_chars // 2 :]
    return f"{head}\n\n[... clipped {len(text) - len(head) - len(tail)} chars ...]\n\n{tail}"


def select_fixture_files(package: Path, *, max_files: int = 8) -> list[Path]:
    priority_patterns = [
        "report*.md",
        "*submission*.md",
        "triager_sim_result.json",
        "triager_sim_result.md",
        "submission_review.json",
        "poc*.py",
        "poc*.sh",
        "poc*.t.sol",
        "*.t.sol",
        "*evidence*.md",
        "*evidence*.txt",
        "*output*.txt",
        "*results*.md",
    ]
    selected: list[Path] = []
    for pattern in priority_patterns:
        for path in sorted(package.rglob(pattern)):
            if path.is_file() and path not in selected:
                selected.append(path)
            if len(selected) >= max_files:
                return selected
    for path in sorted(package.rglob("*")):
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES and path not in selected:
            selected.append(path)
        if len(selected) >= max_files:
            break
    return selected


def build_fixture_digest(package: Path, *, name: str, expected_outcome: str, max_files: int, max_chars_per_file: int) -> str:
    files = select_fixture_files(package, max_files=max_files)
    lines = [
        f"Package: {name}",
        f"Historical outcome class: {expected_outcome}",
        f"Fixture path: {package}",
        "",
        "Selected fixture files:",
    ]
    for path in files:
        rel = path.relative_to(package)
        lines.extend(
            [
                "",
                f"--- FILE: {rel} ({path.stat().st_size} bytes) ---",
                safe_read(path, max_chars=max_chars_per_file),
            ]
        )
    return "\n".join(lines)


def candidate_prompt(*, package_name: str, expected_outcome: str, digest: str) -> str:
    return f"""
You are generating a safe replay candidate submission package for Terminator runtime evaluation.

CRITICAL OUTPUT CONTRACT:
- Return exactly one JSON object.
- The first non-whitespace character of your response must be `{{`.
- The last non-whitespace character of your response must be `}}`.
- Do not summarize your work in prose.
- Do not use markdown fences.

Rules:
- Do not access the network.
- Do not submit anything to a live bounty platform.
- Use only the fixture evidence pasted below.
- Do not invent facts, tokens, endpoint behavior, transaction hashes, screenshots, or triage status.
- If the historical outcome class is negative, do not mark the case eligible for submission unless the pasted fixture contains a clear new evidence delta. In normal replay mode, negative cases should remain NOT_SUBMIT.
- Do not use the literal phrase `submit-ready`; use `eligible for submission` only when evidence supports that decision.
- Return ONLY a valid JSON object. No markdown fences, no prose outside JSON.

JSON schema:
{{
  "report_md": "submission report markdown",
  "poc_filename": "poc_replay.py or poc_replay.sh",
  "poc_body": "safe replay PoC body. It may parse fixture snippets or print recorded evidence, but it must not call live targets.",
  "evidence_summary_md": "short evidence summary markdown with concrete file/line/response references from the pasted fixture",
  "triager_sim_result": {{
    "decision": "SUBMIT|STRENGTHEN|NOT_SUBMIT",
    "historical_outcome_preserved": true,
    "poc_tier": 1,
    "slop_score": 0,
    "reason": "short factual rationale"
  }}
}}

Report requirements:
- Start the report with a three-sentence `Executive Conclusion` in the first 500 characters.
- Include `Historical outcome`, `Replay disposition`, `CWE`, and a CVSS vector or explicit "CVSS not reassessed in replay" line.
- Include a literal CVSS vector string such as `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` when discussing a conditional severity scenario.
- Include an "Honest Severity Expectation" sentence.
- Include at least three numbered replay steps.
- Include at least three numbered attack/evidence-chain steps.
- Include a small Conditional CVSS / disposition table.
- Include two fenced code blocks: one command block for the replay PoC and one expected-output block.
- For negative fixtures, clearly state `NOT_SUBMIT` and the missing evidence delta.
- Avoid em dashes; use commas or periods instead.

PoC requirements:
- Safe local replay only.
- Include explicit `assert` statements for the concrete fixture markers.
- Print a JSON summary containing `mode`, `network_calls: false`, and marker results.
- It must be self-contained: do not open external fixture files and do not rely on relative paths.
- Embed only the fixture markers that are present in the digest below.
- Do not assert a claim unless the exact marker appears in the digest.
- Avoid negative assertions such as "marker must be absent"; only assert positive marker presence and historical outcome preservation.

Package name: {package_name}
Historical outcome class: {expected_outcome}

Fixture evidence digest:
{digest}
""".strip()


def extract_first_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, re.S)
    candidates = [fence.group(1)] if fence else []
    candidates.append(stripped)
    decoder = json.JSONDecoder()
    for candidate in candidates:
        for idx, char in enumerate(candidate):
            if char != "{":
                continue
            try:
                obj, _ = decoder.raw_decode(candidate[idx:])
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                return obj
    raise ValueError("No JSON object found in backend output")


def validate_candidate_payload(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in ["report_md", "poc_filename", "poc_body", "evidence_summary_md", "triager_sim_result"]:
        if key not in payload:
            errors.append(f"missing {key}")
    if not isinstance(payload.get("triager_sim_result"), dict):
        errors.append("triager_sim_result must be an object")
    filename = str(payload.get("poc_filename", ""))
    if not re.match(r"^[A-Za-z0-9_.-]+$", filename):
        errors.append("poc_filename must be a simple filename")
    if filename and not filename.startswith("poc_"):
        errors.append("poc_filename must start with poc_")
    return errors


def write_candidate_files(candidate_dir: Path, payload: dict[str, Any], metadata: dict[str, Any]) -> None:
    submission = candidate_dir / "submission"
    submission.mkdir(parents=True, exist_ok=True)
    (submission / "report.md").write_text(str(payload["report_md"]).strip() + "\n", encoding="utf-8")
    (submission / str(payload["poc_filename"])).write_text(str(payload["poc_body"]).rstrip() + "\n", encoding="utf-8")
    (submission / "evidence_summary.md").write_text(str(payload["evidence_summary_md"]).strip() + "\n", encoding="utf-8")
    (submission / "triager_sim_result.json").write_text(
        json.dumps(payload["triager_sim_result"], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (candidate_dir / "candidate_metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def run_backend(
    *,
    prompt: str,
    profile: str,
    model: str,
    timeout: int,
    work_dir: Path,
    report_dir: Path,
    session_id: str,
) -> tuple[dict[str, Any], str, list[str], int]:
    backend = PROFILE_BACKEND[profile]
    failover = PROFILE_FAILOVER[profile]
    with tempfile.TemporaryDirectory(prefix="terminator-candidate-replay.") as tmp:
        tmpdir = Path(tmp)
        prompt_file = tmpdir / "prompt.txt"
        result_file = tmpdir / "runtime_result.json"
        prompt_file.write_text(prompt, encoding="utf-8")
        cmd = [
            "python3",
            str(BACKEND_RUNNER),
            "run",
            "--backend",
            backend,
            "--failover-to",
            failover,
            "--runtime-profile",
            profile,
            "--prompt-file",
            str(prompt_file),
            "--work-dir",
            str(work_dir),
            "--report-dir",
            str(report_dir),
            "--model",
            model,
            "--mode",
            "submission-candidate-replay",
            "--target",
            session_id,
            "--session-id",
            session_id,
            "--timeout",
            str(timeout),
            "--result-file",
            str(result_file),
        ]
        env = os.environ.copy()
        if profile != "scope-first-hybrid":
            env["TERMINATOR_SKIP_POLICY_INJECTION"] = "1"
        env["TERMINATOR_BACKEND_IDLE_TIMEOUT"] = str(timeout)
        proc = subprocess.run(
            cmd,
            cwd=str(work_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout + 45,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        runtime_result: dict[str, Any] = {}
        if result_file.exists():
            try:
                runtime_result = json.loads(result_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                runtime_result = {"status": "invalid_result_json"}
    return runtime_result, output, parse_agent_messages(output), proc.returncode


def generate_one(
    *,
    name: str,
    package: Path,
    expected_outcome: str,
    profile: str,
    model: str,
    claude_model: str,
    out_root: Path,
    timeout: int,
    max_files: int,
    max_chars_per_file: int,
) -> dict[str, Any]:
    candidate_dir = out_root / profile / name
    candidate_dir.mkdir(parents=True, exist_ok=True)
    digest = build_fixture_digest(
        package,
        name=name,
        expected_outcome=expected_outcome,
        max_files=max_files,
        max_chars_per_file=max_chars_per_file,
    )
    prompt = candidate_prompt(package_name=name, expected_outcome=expected_outcome, digest=digest)
    (candidate_dir / "prompt.txt").write_text(prompt, encoding="utf-8")

    session_id = f"candidate-replay-{profile}-{name}"
    started = time.monotonic()
    backend_model = claude_model if profile in {"claude-only", "scope-first-hybrid"} else model
    runtime_result, output, messages, returncode = run_backend(
        prompt=prompt,
        profile=profile,
        model=backend_model,
        timeout=timeout,
        work_dir=PROJECT_ROOT,
        report_dir=candidate_dir / "backend_report",
        session_id=session_id,
    )
    (candidate_dir / "backend_output.log").write_text(output, encoding="utf-8")
    (candidate_dir / "backend_messages.json").write_text(json.dumps(messages, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    status = "fail"
    errors: list[str] = []
    payload: dict[str, Any] | None = None
    if returncode != 0 or runtime_result.get("status") != "completed":
        errors.append(f"backend failed: returncode={returncode} status={runtime_result.get('status')}")
    if not errors:
        try:
            payload_source = messages[-1] if messages else output
            payload = extract_first_json(payload_source)
            errors.extend(validate_candidate_payload(payload))
        except Exception as exc:  # noqa: BLE001 - keep failure evidence.
            errors.append(f"candidate JSON parse/validation failed: {exc}")
    if payload and not errors:
        metadata = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "name": name,
            "profile": profile,
            "model": model,
            "backend_model": backend_model,
            "source_package": str(package),
            "expected_outcome": expected_outcome,
            "runtime_result": runtime_result,
            "duration_seconds": round(time.monotonic() - started, 2),
        }
        write_candidate_files(candidate_dir, payload, metadata)
        status = "pass"

    result_payload = {
        "name": name,
        "profile": profile,
        "status": status,
        "errors": errors,
        "source_package": str(package),
        "candidate_dir": str(candidate_dir),
        "duration_seconds": round(time.monotonic() - started, 2),
        "runtime_result": runtime_result,
    }
    (candidate_dir / "candidate_result.json").write_text(
        json.dumps(result_payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return result_payload


def collect_existing_results(out_root: Path, current_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for result_file in sorted(out_root.glob("*/*/candidate_result.json")):
        try:
            item = json.loads(result_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(item, dict) and isinstance(item.get("profile"), str) and isinstance(item.get("name"), str):
            by_key[(item["profile"], item["name"])] = item
    for item in current_results:
        by_key[(item["profile"], item["name"])] = item
    return [by_key[key] for key in sorted(by_key)]


def write_manifest(path: Path, results: list[dict[str, Any]]) -> None:
    results = collect_existing_results(path.parent, results)
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "pass" if all(item["status"] == "pass" for item in results) else "fail",
        "results": results,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md = path.with_suffix(".md")
    lines = ["# Submission Candidate Replay", "", f"Generated: {payload['generated_at']}", "", "| Profile | Package | Status | Errors |", "|---|---|---|---|"]
    for item in results:
        lines.append(
            f"| {item['profile']} | {item['name']} | {item['status']} | "
            f"{'; '.join(item['errors']) if item['errors'] else ''} |"
        )
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-manifest", type=Path, required=True)
    parser.add_argument("--out-root", type=Path, required=True)
    parser.add_argument("--profiles", nargs="+", default=["gpt-only"], choices=sorted(PROFILE_BACKEND))
    parser.add_argument("--packages", nargs="*", help="Specific baseline package names to replay")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument("--claude-model", default="sonnet")
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--max-files", type=int, default=8)
    parser.add_argument("--max-chars-per-file", type=int, default=4500)
    args = parser.parse_args()

    manifest = json.loads(args.baseline_manifest.read_text(encoding="utf-8"))
    selected_names = set(args.packages or [])
    packages = []
    for name, path, group in iter_manifest_packages(manifest):
        if selected_names and name not in selected_names:
            continue
        if group not in {"positive", "negative", "gold"}:
            continue
        if not path.exists():
            continue
        packages.append((name, path, group))
    if args.limit:
        packages = packages[: args.limit]

    args.out_root.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for profile in args.profiles:
        for name, path, group in packages:
            print(f"[candidate-replay] {profile} {name}", flush=True)
            results.append(
                generate_one(
                    name=name,
                    package=path,
                    expected_outcome=group,
                    profile=profile,
                    model=args.model,
                    claude_model=args.claude_model,
                    out_root=args.out_root,
                    timeout=args.timeout,
                    max_files=args.max_files,
                    max_chars_per_file=args.max_chars_per_file,
                )
            )

    manifest_path = args.out_root / "candidate_replay_manifest.json"
    write_manifest(manifest_path, results)
    print(manifest_path)
    print(manifest_path.with_suffix(".md"))
    return 0 if all(item["status"] == "pass" for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
