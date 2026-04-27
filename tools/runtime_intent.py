#!/usr/bin/env python3
"""Resolve short natural-language operator intents into Terminator commands."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


@dataclass(frozen=True)
class RuntimeChoice:
    backend: str
    failover_to: str
    runtime_profile: str
    reason: str


def choose_runtime(text: str) -> RuntimeChoice:
    normalized = text.lower()
    wants_codex = any(token in normalized for token in ("codex", "gpt", "오픈ai", "openai"))
    wants_claude = any(token in normalized for token in ("claude", "클로드"))
    only = any(token in normalized for token in ("only", "만", "으로만", "로만"))

    if wants_codex and only and not wants_claude:
        return RuntimeChoice("codex", "none", "gpt-only", "codex-only requested")
    if wants_claude and only and not wants_codex:
        return RuntimeChoice("claude", "none", "claude-only", "claude-only requested")
    if wants_codex and not wants_claude and "fallback" not in normalized and "failover" not in normalized:
        return RuntimeChoice("codex", "none", "gpt-only", "codex requested")
    if wants_claude and not wants_codex and "fallback" not in normalized and "failover" not in normalized:
        return RuntimeChoice("claude", "none", "claude-only", "claude requested")
    return RuntimeChoice("hybrid", "none", "scope-first-hybrid", "default scope-first hybrid role split")


def detect_intent(text: str) -> str:
    normalized = text.lower()
    if any(token in normalized for token in ("client-pitch", "client pitch", "upwork", "영업", "컨택", "제안서", "pitch")):
        return "client-pitch"
    if any(token in normalized for token in ("ai-security", "llm", "ai security", "prompt injection", "rag", "agent", "에이아이", "llm")):
        return "ai-security"
    target_words = ("타겟", "target", "program", "프로그램")
    find_words = ("찾", "find", "discover", "discovery", "추천", "고르", "선정")
    run_words = ("돌", "run", "실행", "start", "launch")
    if any(word in normalized for word in target_words) and any(word in normalized for word in find_words):
        return "target_discovery_then_bounty"
    if URL_RE.search(text) or "bounty" in normalized or "버그바운티" in normalized:
        return "bounty"
    if any(word in normalized for word in run_words):
        return "bounty"
    return "unknown"


def _shell_join(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def resolve(text: str, *, timestamp: str | None = None, dry_run: bool = False) -> dict[str, Any]:
    runtime = choose_runtime(text)
    intent = detect_intent(text)
    stamp = timestamp or time.strftime("%Y%m%d_%H%M%S", time.localtime())
    urls = URL_RE.findall(text)
    commands: list[list[str]] = []
    notes: list[str] = []

    if intent == "target_discovery_then_bounty":
        out_dir = f"reports/runtime-eval/{stamp}_natural_target_run"
        discovery_json = f"{out_dir}/target_discovery/target_candidates.json"
        commands.append(
            [
                "python3",
                "tools/target_discovery.py",
                "--out-dir",
                f"{out_dir}/target_discovery",
            ]
        )
        commands.append(
            [
                "python3",
                "tools/bounty_live_ab.py",
                "--discovery-json",
                discovery_json,
                "--out-dir",
                f"{out_dir}/bounty_live_ab",
            ]
        )
        notes.append("target discovery uses passive public program data")
        notes.append("bounty follow-up is passive-live-safe-dry-run")
    elif intent in {"bounty", "client-pitch", "ai-security"} and urls:
        command = [
            "./terminator.sh",
            "--backend",
            runtime.backend,
            "--failover-to",
            runtime.failover_to,
            "--runtime-profile",
            runtime.runtime_profile,
        ]
        if dry_run:
            command.append("--dry-run")
        command.extend([intent, urls[0]])
        commands.append(command)
    else:
        notes.append("intent unclear; ask for target URL or say '타겟 찾고 돌리자'")

    return {
        "intent": intent,
        "runtime": {
            "backend": runtime.backend,
            "failover_to": runtime.failover_to,
            "runtime_profile": runtime.runtime_profile,
            "reason": runtime.reason,
        },
        "commands": commands,
        "shell": [_shell_join(command) for command in commands],
        "notes": notes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("text", nargs="+", help="Natural-language operator request")
    parser.add_argument("--timestamp", default=None)
    parser.add_argument("--dry-run", action="store_true", help="Add --dry-run to direct bounty commands")
    parser.add_argument("--shell", action="store_true", help="Print shell commands instead of JSON")
    args = parser.parse_args()

    payload = resolve(" ".join(args.text), timestamp=args.timestamp, dry_run=args.dry_run)
    if args.shell:
        for command in payload["shell"]:
            print(command)
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
