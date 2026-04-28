#!/usr/bin/env python3
"""GraphRAG-Security CLI shim — Codex parity for the `analyst` role.

Provides the minimum operations `analyst` needs from the `graphrag-security`
MCP server without requiring the MCP runtime. Shares the underlying pandas
search functions with `tools/mcp-servers/graphrag-mcp/server.py` so the two
paths cannot drift.

Exit codes:
    0 — results returned
    1 — no matches (valid empty result, not an error)
    2 — runtime/environment gap (parquet index missing, pandas unavailable)
    3 — invalid input (bad arguments, unreadable file)

Commands:
    search <query> [--mode local|global|drift]
        Equivalent of mcp graphrag-security knowledge_search.
    similar <description>
        Equivalent of mcp graphrag-security similar_findings.
    stats
        Diagnostic readiness check. Returns index row counts.
    doctor
        End-to-end readiness check for CLI, model endpoint, and parquet output.

Options:
    --json          Emit JSON instead of the default markdown text.
    --top-n N       Cap result count (default 15 for entities, 10 otherwise).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import urllib.request

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_MCP_DIR = os.path.join(_SCRIPT_DIR, "mcp-servers", "graphrag-mcp")
sys.path.insert(0, _MCP_DIR)

# Default index location; overridable for testing / alternative deployments
# via the GRAPHRAG_OUTPUT_DIR env var. When overridden, the shim also rebinds
# the imported MCP server module's OUTPUT_DIR so both paths read the same data.
_OUTPUT_DIR = os.environ.get(
    "GRAPHRAG_OUTPUT_DIR",
    os.path.join(_SCRIPT_DIR, "graphrag-security", "output"),
)

EXIT_OK = 0
EXIT_NO_MATCH = 1
EXIT_ENV_GAP = 2
EXIT_BAD_INPUT = 3


def _env_check() -> tuple[bool, str]:
    """Return (ready, message). Ready = parquet index is accessible."""
    try:
        import pandas  # noqa: F401
    except ImportError:
        return False, "pandas not installed — run `pip install pandas pyarrow`."
    try:
        import pyarrow  # noqa: F401
    except ImportError:
        return False, "pyarrow not installed — run `pip install pyarrow`."
    if not os.path.isdir(_OUTPUT_DIR):
        return False, (
            f"GraphRAG parquet index directory missing: {_OUTPUT_DIR}. "
            "Run `graphrag index --root tools/graphrag-security` to build it."
        )
    expected = [
        "entities.parquet",
        "relationships.parquet",
        "community_reports.parquet",
        "text_units.parquet",
    ]
    missing = [f for f in expected if not os.path.exists(os.path.join(_OUTPUT_DIR, f))]
    if missing:
        return False, f"GraphRAG index incomplete — missing: {', '.join(missing)}."
    return True, f"GraphRAG index ready at {_OUTPUT_DIR}."


def _graphrag_bin() -> str | None:
    env_bin = os.environ.get("GRAPHRAG_BIN")
    if env_bin and os.path.exists(env_bin):
        return env_bin
    path_bin = shutil.which("graphrag")
    if path_bin:
        return path_bin
    repo_bin = os.path.join(os.path.dirname(_SCRIPT_DIR), ".venv", "bin", "graphrag")
    if os.path.exists(repo_bin):
        return repo_bin
    return None


def _load_settings() -> dict:
    settings_path = os.path.join(_SCRIPT_DIR, "graphrag-security", "settings.yaml")
    try:
        import yaml
    except ImportError:
        return {"settings_path": settings_path, "error": "PyYAML not installed"}
    if not os.path.exists(settings_path):
        return {"settings_path": settings_path, "error": "settings.yaml missing"}
    try:
        with open(settings_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception as exc:
        return {"settings_path": settings_path, "error": str(exc)}
    return {"settings_path": settings_path, "data": data}


def _check_ollama(base_url: str, timeout_s: float = 5.0) -> dict:
    url = base_url.rstrip("/") + "/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as response:
            body = response.read(2000).decode("utf-8", errors="replace")
            status = response.status
        return {"url": url, "reachable": True, "status": status, "sample": body[:300]}
    except Exception as exc:
        return {"url": url, "reachable": False, "error": str(exc)}


def _doctor_payload() -> tuple[dict, bool]:
    ready, msg = _env_check()
    payload: dict = {
        "graphrag_bin": _graphrag_bin(),
        "output_dir": _OUTPUT_DIR,
        "index_ready": ready,
        "index_message": msg,
    }

    settings = _load_settings()
    payload["settings_path"] = settings.get("settings_path")
    if "error" in settings:
        payload["settings_error"] = settings["error"]
        return payload, False

    model_checks = []
    data = settings["data"]
    for group_name in ("completion_models", "embedding_models"):
        for model_id, model_cfg in (data.get(group_name) or {}).items():
            api_base = model_cfg.get("api_base")
            check = {
                "group": group_name,
                "id": model_id,
                "provider": model_cfg.get("model_provider"),
                "model": model_cfg.get("model"),
                "api_base": api_base,
            }
            if api_base and "ollama" in str(model_cfg.get("model_provider", "")):
                check["endpoint"] = _check_ollama(api_base)
            model_checks.append(check)
    payload["models"] = model_checks
    endpoints_ready = all(model.get("endpoint", {}).get("reachable", True) for model in model_checks)
    return payload, bool(payload["graphrag_bin"]) and ready and endpoints_ready


def _load_server():
    """Import the MCP server module so the CLI reuses its search helpers."""
    import importlib.util

    server_path = os.path.join(_MCP_DIR, "server.py")
    spec = importlib.util.spec_from_file_location("graphrag_mcp_server", server_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {server_path}")
    module = importlib.util.module_from_spec(spec)
    # The MCP server module tries to register FastMCP decorators at import time;
    # the decorators only attach metadata, so importing is safe even without a
    # live MCP transport.
    spec.loader.exec_module(module)
    # Rebind the server's OUTPUT_DIR + clear its cache if the CLI's env override
    # pointed somewhere else. Keeps a single source of truth for search code.
    if module.OUTPUT_DIR != _OUTPUT_DIR:
        module.OUTPUT_DIR = _OUTPUT_DIR
        module._cache.clear()
    return module


def _emit(payload: str, as_json: bool, meta: dict | None = None) -> None:
    if as_json:
        out = {"text": payload}
        if meta:
            out.update(meta)
        json.dump(out, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(payload.rstrip() + "\n")


def cmd_search(args: argparse.Namespace) -> int:
    ready, msg = _env_check()
    if not ready:
        _emit(f"[graphrag-cli] ENV_GAP: {msg}", args.json, {"env_gap": True})
        return EXIT_ENV_GAP
    server = _load_server()
    result = server.knowledge_search(args.query, mode=args.mode)
    matched = not result.lstrip().lower().startswith(("no ", "empty "))
    _emit(result, args.json, {"mode": args.mode, "matched": matched})
    return EXIT_OK if matched else EXIT_NO_MATCH


def cmd_similar(args: argparse.Namespace) -> int:
    ready, msg = _env_check()
    if not ready:
        _emit(f"[graphrag-cli] ENV_GAP: {msg}", args.json, {"env_gap": True})
        return EXIT_ENV_GAP
    server = _load_server()
    result = server.similar_findings(args.description)
    matched = not result.lstrip().lower().startswith(("no ", "empty "))
    _emit(result, args.json, {"matched": matched})
    return EXIT_OK if matched else EXIT_NO_MATCH


def cmd_stats(args: argparse.Namespace) -> int:
    ready, msg = _env_check()
    if not ready:
        _emit(f"[graphrag-cli] ENV_GAP: {msg}", args.json, {"env_gap": True, "ready": False})
        return EXIT_ENV_GAP
    server = _load_server()
    result = server.knowledge_stats()
    _emit(result, args.json, {"ready": True})
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    payload, all_ready = _doctor_payload()
    if args.json:
        payload["ready"] = all_ready
        json.dump(payload, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        lines = [
            "# GraphRAG Doctor",
            f"- graphrag_bin: {payload.get('graphrag_bin') or '(missing)'}",
            f"- index_ready: {payload.get('index_ready')} — {payload.get('index_message')}",
        ]
        for model in payload.get("models", []):
            endpoint = model.get("endpoint") or {}
            suffix = ""
            if endpoint:
                suffix = f" endpoint_reachable={endpoint.get('reachable')} url={endpoint.get('url')}"
                if endpoint.get("error"):
                    suffix += f" error={endpoint.get('error')}"
            lines.append(
                f"- {model.get('group')}.{model.get('id')}: "
                f"{model.get('provider')} {model.get('model')} api_base={model.get('api_base')}{suffix}"
            )
        _emit("\n".join(lines), False)
    return EXIT_OK if all_ready else EXIT_ENV_GAP


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="graphrag_cli",
        description="Codex parity shim for graphrag-security MCP (analyst role).",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON output.")
    sub = p.add_subparsers(dest="command", required=True)

    ps = sub.add_parser("search", help="Keyword search across the graph.")
    ps.add_argument("query")
    ps.add_argument(
        "--mode",
        choices=["local", "global", "drift"],
        default="local",
        help="local=entities+relationships, global=community reports, drift=text chunks.",
    )
    ps.set_defaults(func=cmd_search)

    pf = sub.add_parser("similar", help="Find similar past findings.")
    pf.add_argument("description")
    pf.set_defaults(func=cmd_similar)

    pst = sub.add_parser("stats", help="Report index readiness.")
    pst.set_defaults(func=cmd_stats)

    pd = sub.add_parser("doctor", help="Check GraphRAG CLI, model endpoint, and parquet readiness.")
    pd.set_defaults(func=cmd_doctor)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return EXIT_BAD_INPUT
    except Exception as e:  # pragma: no cover — last-resort safety
        msg = f"[graphrag-cli] ERROR: {type(e).__name__}: {e}"
        _emit(msg, getattr(args, "json", False), {"error": True})
        return EXIT_ENV_GAP


if __name__ == "__main__":
    sys.exit(main())
