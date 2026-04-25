from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path


def _load_bridge_module():
    bridge_path = Path(__file__).resolve().parents[1] / "tools" / "secall_bridge.py"
    spec = importlib.util.spec_from_file_location("secall_bridge", bridge_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_project_local_env_uses_ignored_secall_state(monkeypatch) -> None:
    module = _load_bridge_module()
    monkeypatch.delenv("SECALL_CONFIG_PATH", raising=False)
    monkeypatch.delenv("SECALL_DB_PATH", raising=False)
    monkeypatch.delenv("SECALL_VAULT_PATH", raising=False)

    env = module.secall_env(use_global_config=False)

    assert env["SECALL_CONFIG_PATH"].endswith(".secall/config.toml")
    assert env["SECALL_DB_PATH"].endswith(".secall/index.sqlite")
    assert env["SECALL_VAULT_PATH"].endswith(".secall/vault")


def test_missing_binary_payload_has_install_hint(monkeypatch) -> None:
    module = _load_bridge_module()
    monkeypatch.delenv("SECALL_BIN", raising=False)
    monkeypatch.setattr(module.shutil, "which", lambda _name: None)

    payload = module.run_secall(["status"])

    assert payload["ok"] is False
    assert payload["error"] == "secall binary not found"
    assert payload["install"]["script"].endswith("scripts/install_secall.sh")


def test_mcp_config_uses_project_local_paths(monkeypatch, capsys) -> None:
    module = _load_bridge_module()
    monkeypatch.setenv("SECALL_BIN", "/opt/bin/secall")

    rc = module.cmd_mcp_config(argparse.Namespace(global_config=False))

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    server = payload["mcpServers"]["secall"]
    assert server["command"] == "/opt/bin/secall"
    assert server["args"] == ["mcp"]
    assert server["env"]["SECALL_DB_PATH"].endswith(".secall/index.sqlite")


def test_recall_vec_does_not_also_force_lex(monkeypatch, capsys) -> None:
    module = _load_bridge_module()
    seen: dict[str, list[str]] = {}

    def fake_run(cmd, *, use_global_config=False, timeout=60):
        seen["cmd"] = cmd
        return {"ok": True, "exit_code": 0, "stdout": "[]", "stderr": ""}

    monkeypatch.setattr(module, "run_secall", fake_run)

    args = argparse.Namespace(
        global_config=False,
        timeout=60,
        query="semantic memory",
        limit=3,
        since=None,
        project=None,
        agent=None,
        lex=True,
        vec=True,
        include_automated=False,
        no_related=True,
    )
    rc = module.cmd_recall(args)

    assert rc == 0
    assert "--vec" in seen["cmd"]
    assert "--lex" not in seen["cmd"]
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"] == []


def test_parse_json_stdout_normalizes_empty_ingest() -> None:
    module = _load_bridge_module()

    payload = module.parse_json_stdout(
        {"ok": True, "exit_code": 0, "stdout": "No sessions to ingest.\n", "stderr": ""}
    )

    assert "parse_error" not in payload
    assert payload["data"]["summary"]["ingested"] == 0
    assert payload["data"]["errors"] == []


def test_parse_json_stdout_normalizes_empty_recall() -> None:
    module = _load_bridge_module()

    payload = module.parse_json_stdout(
        {"ok": True, "exit_code": 0, "stdout": "No results found for: runtime policy\n", "stderr": ""}
    )

    assert "parse_error" not in payload
    assert payload["data"] == []
    assert payload["message"] == "No results found for: runtime policy"


def test_timeout_allowed_after_subcommand() -> None:
    module = _load_bridge_module()

    args = module.build_parser().parse_args(["status", "--timeout", "7"])

    assert args.command == "status"
    assert args.timeout == 7


def test_timeout_payload_is_json_serializable(monkeypatch) -> None:
    module = _load_bridge_module()

    class TimeoutRun:
        def __call__(self, *args, **kwargs):
            raise module.subprocess.TimeoutExpired(
                cmd=["secall", "ingest"],
                timeout=1,
                output=b"partial stdout",
                stderr=b"partial stderr",
            )

    monkeypatch.setenv("SECALL_BIN", "/opt/bin/secall")
    monkeypatch.setattr(module.subprocess, "run", TimeoutRun())

    payload = module.run_secall(["ingest"], timeout=1)

    assert payload["exit_code"] == 124
    assert payload["stdout"] == "partial stdout"
    assert payload["stderr"] == "partial stderr"
    json.dumps(payload)
