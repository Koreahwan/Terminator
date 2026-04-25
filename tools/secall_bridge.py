#!/usr/bin/env python3
"""Thin Terminator wrapper for the external seCall CLI.

The seCall project is distributed as an AGPL Rust CLI. This wrapper does not
vendor or import seCall code; it only executes a user-installed `secall` binary
with project-local state paths by default.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_STATE_DIR = PROJECT_ROOT / ".secall"
DEFAULT_CONFIG_PATH = LOCAL_STATE_DIR / "config.toml"
DEFAULT_DB_PATH = LOCAL_STATE_DIR / "index.sqlite"
DEFAULT_VAULT_PATH = LOCAL_STATE_DIR / "vault"


def _json_print(payload: dict[str, Any]) -> int:
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload.get("ok", False) else int(payload.get("exit_code", 1) or 1)


def _to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def find_secall() -> str | None:
    configured = os.environ.get("SECALL_BIN")
    if configured:
        return configured
    return shutil.which("secall")


def secall_env(use_global_config: bool = False) -> dict[str, str]:
    env = os.environ.copy()
    if not use_global_config:
        env.setdefault("SECALL_CONFIG_PATH", str(DEFAULT_CONFIG_PATH))
        env.setdefault("SECALL_DB_PATH", str(DEFAULT_DB_PATH))
        env.setdefault("SECALL_VAULT_PATH", str(DEFAULT_VAULT_PATH))
    return env


def _missing_binary_payload() -> dict[str, Any]:
    return {
        "ok": False,
        "error": "secall binary not found",
        "install": {
            "script": str(PROJECT_ROOT / "scripts" / "install_secall.sh"),
            "manual": [
                "git clone https://github.com/hang-in/seCall.git /tmp/seCall",
                "cargo install --path /tmp/seCall/crates/secall",
            ],
        },
    }


def run_secall(
    secall_args: list[str],
    *,
    use_global_config: bool = False,
    timeout: int = 60,
) -> dict[str, Any]:
    binary = find_secall()
    if not binary:
        return _missing_binary_payload()

    env = secall_env(use_global_config)
    cmd = [binary, *secall_args]
    try:
        proc = subprocess.run(
            cmd,
            cwd=PROJECT_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "exit_code": 124,
            "command": cmd,
            "error": f"timed out after {timeout}s",
            "stdout": _to_text(exc.stdout),
            "stderr": _to_text(exc.stderr),
        }

    payload: dict[str, Any] = {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "command": cmd,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "paths": {} if use_global_config else project_paths(),
    }
    return payload


def parse_json_stdout(payload: dict[str, Any]) -> dict[str, Any]:
    stdout = payload.get("stdout") or ""
    stripped = stdout.strip()
    if not stripped:
        return payload
    try:
        payload["data"] = json.loads(stdout)
        payload.pop("stdout", None)
    except json.JSONDecodeError:
        if payload.get("ok") and stripped == "No sessions to ingest.":
            payload["data"] = {
                "summary": {
                    "ingested": 0,
                    "skipped": 0,
                    "errors": 0,
                    "skipped_min_turns": 0,
                },
                "errors": [],
                "message": stripped,
            }
            payload.pop("stdout", None)
        elif payload.get("ok") and stripped.startswith("No results found for:"):
            payload["data"] = []
            payload["message"] = stripped
            payload.pop("stdout", None)
        else:
            payload["parse_error"] = "stdout was not valid JSON"
    return payload


def project_paths() -> dict[str, str]:
    return {
        "state_dir": str(LOCAL_STATE_DIR),
        "config": str(DEFAULT_CONFIG_PATH),
        "db": str(DEFAULT_DB_PATH),
        "vault": str(DEFAULT_VAULT_PATH),
    }


def cmd_doctor(args: argparse.Namespace) -> int:
    binary = find_secall()
    payload: dict[str, Any] = {
        "ok": bool(binary),
        "binary": binary,
        "project_local": not args.global_config,
        "paths": None if args.global_config else project_paths(),
    }
    if not binary:
        payload.update(_missing_binary_payload())
        return _json_print(payload)

    version = run_secall(["--version"], use_global_config=args.global_config, timeout=args.timeout)
    payload["version"] = (version.get("stdout") or "").strip()
    if not args.global_config:
        payload["exists"] = {
            "config": DEFAULT_CONFIG_PATH.exists(),
            "db": DEFAULT_DB_PATH.exists(),
            "vault": DEFAULT_VAULT_PATH.exists(),
        }
    return _json_print(payload)


def cmd_init(args: argparse.Namespace) -> int:
    DEFAULT_VAULT_PATH.mkdir(parents=True, exist_ok=True)
    payload = run_secall(
        ["init", "--vault", str(DEFAULT_VAULT_PATH)],
        use_global_config=args.global_config,
        timeout=args.timeout,
    )
    steps = [payload]
    if payload.get("ok") and not args.enable_embeddings:
        steps.append(
            run_secall(
                ["config", "set", "embedding.backend", "none"],
                use_global_config=args.global_config,
                timeout=args.timeout,
            )
        )
    if payload.get("ok") and args.timezone:
        steps.append(
            run_secall(
                ["config", "set", "output.timezone", args.timezone],
                use_global_config=args.global_config,
                timeout=args.timeout,
            )
        )

    result = {
        "ok": all(step.get("ok") for step in steps),
        "steps": steps,
        "paths": None if args.global_config else project_paths(),
    }
    return _json_print(result)


def cmd_status(args: argparse.Namespace) -> int:
    payload = run_secall(["status"], use_global_config=args.global_config, timeout=args.timeout)
    return _json_print(payload)


def cmd_lint(args: argparse.Namespace) -> int:
    cmd = ["lint", "--json"]
    if args.errors_only:
        cmd.append("--errors-only")
    if args.fix:
        cmd.append("--fix")
    payload = parse_json_stdout(run_secall(cmd, use_global_config=args.global_config, timeout=args.timeout))
    return _json_print(payload)


def cmd_ingest(args: argparse.Namespace) -> int:
    cmd = ["--format", "json", "ingest"]
    if args.path:
        cmd.append(args.path)
    if args.auto:
        cmd.append("--auto")
    if args.cwd:
        cmd.extend(["--cwd", args.cwd])
    if args.min_turns:
        cmd.extend(["--min-turns", str(args.min_turns)])
    if args.force:
        cmd.append("--force")
    if not args.semantic:
        cmd.append("--no-semantic")
    payload = parse_json_stdout(run_secall(cmd, use_global_config=args.global_config, timeout=args.timeout))
    return _json_print(payload)


def cmd_recall(args: argparse.Namespace) -> int:
    cmd = ["--format", "json", "recall", args.query, "--limit", str(args.limit)]
    if args.since:
        cmd.extend(["--since", args.since])
    if args.project:
        cmd.extend(["--project", args.project])
    if args.agent:
        cmd.extend(["--agent", args.agent])
    if args.vec:
        cmd.append("--vec")
    elif args.lex:
        cmd.append("--lex")
    if args.include_automated:
        cmd.append("--include-automated")
    if args.no_related:
        cmd.append("--no-related")
    payload = parse_json_stdout(run_secall(cmd, use_global_config=args.global_config, timeout=args.timeout))
    return _json_print(payload)


def cmd_get(args: argparse.Namespace) -> int:
    cmd = ["get", args.id]
    if args.full:
        cmd.append("--full")
    payload = run_secall(cmd, use_global_config=args.global_config, timeout=args.timeout)
    return _json_print(payload)


def cmd_sync(args: argparse.Namespace) -> int:
    cmd = ["sync"]
    if args.local_only:
        cmd.append("--local-only")
    if args.dry_run:
        cmd.append("--dry-run")
    if args.no_wiki:
        cmd.append("--no-wiki")
    if not args.semantic:
        cmd.append("--no-semantic")
    payload = run_secall(cmd, use_global_config=args.global_config, timeout=args.timeout)
    return _json_print(payload)


def cmd_mcp_config(args: argparse.Namespace) -> int:
    command = find_secall() or os.environ.get("SECALL_BIN") or "secall"
    server: dict[str, Any] = {"command": command, "args": ["mcp"]}
    if not args.global_config:
        server["env"] = {
            "SECALL_CONFIG_PATH": str(DEFAULT_CONFIG_PATH),
            "SECALL_DB_PATH": str(DEFAULT_DB_PATH),
            "SECALL_VAULT_PATH": str(DEFAULT_VAULT_PATH),
        }
    return _json_print({"ok": True, "mcpServers": {"secall": server}})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Terminator wrapper for seCall session memory")
    parser.add_argument("--global-config", action="store_true", help="use seCall default/global state paths")
    parser.add_argument("--timeout", type=int, default=60)
    sub = parser.add_subparsers(dest="command", required=True)

    def allow_timeout(command_parser: argparse.ArgumentParser) -> None:
        command_parser.add_argument("--timeout", type=int, default=argparse.SUPPRESS,
                                    help="override command timeout in seconds")

    doctor = sub.add_parser("doctor", help="check seCall availability and state paths")
    allow_timeout(doctor)
    doctor.set_defaults(func=cmd_doctor)

    init = sub.add_parser("init", help="initialize project-local seCall state")
    allow_timeout(init)
    init.add_argument("--enable-embeddings", action="store_true", help="keep seCall's embedding backend enabled")
    init.add_argument("--timezone", default=os.environ.get("TZ", "Asia/Seoul"))
    init.set_defaults(func=cmd_init)

    status = sub.add_parser("status", help="show seCall index status")
    allow_timeout(status)
    status.set_defaults(func=cmd_status)

    ingest = sub.add_parser("ingest", help="ingest agent sessions")
    allow_timeout(ingest)
    ingest.add_argument("path", nargs="?")
    ingest.add_argument("--auto", action="store_true")
    ingest.add_argument("--cwd")
    ingest.add_argument("--min-turns", type=int, default=0)
    ingest.add_argument("--force", action="store_true")
    ingest.add_argument("--semantic", action="store_true", help="allow seCall semantic graph extraction")
    ingest.set_defaults(func=cmd_ingest)

    recall = sub.add_parser("recall", help="search indexed agent sessions")
    allow_timeout(recall)
    recall.add_argument("query")
    recall.add_argument("--since")
    recall.add_argument("--project")
    recall.add_argument("--agent")
    recall.add_argument("--limit", type=int, default=10)
    recall.add_argument("--lex", action="store_true", default=True)
    recall.add_argument("--vec", action="store_true")
    recall.add_argument("--include-automated", action="store_true")
    recall.add_argument("--no-related", action="store_true", default=True)
    recall.set_defaults(func=cmd_recall)

    get_cmd = sub.add_parser("get", help="get a seCall session by id or id:turn")
    allow_timeout(get_cmd)
    get_cmd.add_argument("id")
    get_cmd.add_argument("--full", action="store_true")
    get_cmd.set_defaults(func=cmd_get)

    lint = sub.add_parser("lint", help="validate seCall DB/vault consistency")
    allow_timeout(lint)
    lint.add_argument("--errors-only", action="store_true")
    lint.add_argument("--fix", action="store_true")
    lint.set_defaults(func=cmd_lint)

    sync = sub.add_parser("sync", help="run seCall sync")
    allow_timeout(sync)
    sync.add_argument("--local-only", action="store_true", default=True)
    sync.add_argument("--dry-run", action="store_true")
    sync.add_argument("--no-wiki", action="store_true", default=True)
    sync.add_argument("--semantic", action="store_true", help="allow seCall semantic graph extraction")
    sync.set_defaults(func=cmd_sync)

    mcp_config = sub.add_parser("mcp-config", help="emit an MCP server config snippet")
    allow_timeout(mcp_config)
    mcp_config.set_defaults(func=cmd_mcp_config)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
