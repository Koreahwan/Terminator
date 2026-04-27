"""Tests for tool_lifecycle.py and toolspec registry."""

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools.toolspec.registry import ToolRegistry, ToolSpec, ToolKind


def test_registry_loads_tools_full():
    r = ToolRegistry(registry_path=PROJECT_ROOT / "tools" / "toolspec" / "tools_full.yaml")
    assert len(r) >= 70, f"Expected >= 70 retained tools, got {len(r)}"


def test_registry_backwards_compat():
    r = ToolRegistry(registry_path=PROJECT_ROOT / "tools" / "toolspec" / "tools.yaml")
    assert len(r) >= 10, f"Old tools.yaml should have >= 10 entries, got {len(r)}"


def test_toolspec_new_fields():
    t = ToolSpec.from_dict({
        "tool_id": "test-tool",
        "name": "Test",
        "kind": "execution",
        "entrypoint": "test",
        "install_method": "pip",
        "install_cmd": "test-pkg",
        "binary_path": "/usr/bin/test",
        "category": "web",
        "pipelines": ["bounty", "client-pitch"],
    })
    assert t.install_method == "pip"
    assert t.category == "web"
    assert t.pipelines == ["bounty", "client-pitch"]
    d = t.to_dict()
    assert d["install_method"] == "pip"
    assert d["category"] == "web"
    assert d["pipelines"] == ["bounty", "client-pitch"]


def test_find_by_category():
    r = ToolRegistry(registry_path=PROJECT_ROOT / "tools" / "toolspec" / "tools_full.yaml")
    password_tools = r.find_by_category("password")
    assert len(password_tools) >= 7, f"Expected >= 7 password tools, got {len(password_tools)}"
    ids = {t.tool_id for t in password_tools}
    assert "john" in ids
    assert "hashcat" in ids


def test_find_by_pipeline():
    r = ToolRegistry(registry_path=PROJECT_ROOT / "tools" / "toolspec" / "tools_full.yaml")
    bounty = r.find_by_pipeline("bounty")
    assert len(bounty) >= 20, f"Expected >= 20 bounty tools, got {len(bounty)}"
    client_pitch = r.find_by_pipeline("client-pitch")
    assert len(client_pitch) >= 1, "Expected client-pitch tool metadata"


def test_tool_lifecycle_check_json():
    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "tools" / "tool_lifecycle.py"),
         "check", "--category", "password", "--json"],
        capture_output=True, text=True, timeout=30,
    )
    data = json.loads(result.stdout)
    assert data["total"] >= 7
    assert "tools" in data
    assert all(k in data["tools"][0] for k in ("tool_id", "status", "category"))


def test_tool_lifecycle_list():
    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "tools" / "tool_lifecycle.py"),
         "list", "--category", "recon", "--json"],
        capture_output=True, text=True, timeout=30,
    )
    data = json.loads(result.stdout)
    assert len(data) >= 10


def test_mcp_servers_import():
    from tools.mcp_pentest.scan_server import nmap_scan, dir_enum, vuln_scan
    from tools.mcp_pentest.http_server import http_request
    from tools.mcp_pentest.ssl_server import ssl_check
    from tools.mcp_pentest.tech_server import detect_tech
    from tools.mcp_pentest.findings_server import add_finding, list_findings
    from tools.mcp_pentest.cred_server import cred_add, cred_list, _encrypt, _decrypt
    from tools.mcp_pentest.recon_data_server import add_recon, list_recon


def test_mcp_db_fallback():
    from tools.mcp_pentest.findings_server import list_findings
    from tools.mcp_pentest.cred_server import cred_list
    from tools.mcp_pentest.recon_data_server import list_recon
    r1 = list_findings()
    r2 = cred_list(1)
    r3 = list_recon(1)
    assert "error" in r1
    assert "error" in r2
    assert "error" in r3


def test_fernet_roundtrip():
    from tools.mcp_pentest.cred_server import _encrypt, _decrypt
    for val in ["secret123", "p@$$w0rd!", "Bearer eyJhbGciOi..."]:
        assert _decrypt(_encrypt(val)) == val


if __name__ == "__main__":
    passed = failed = 0
    for name, fn in [(k, v) for k, v in globals().items() if k.startswith("test_") and callable(v)]:
        try:
            fn()
            print(f"  PASS {name}")
            passed += 1
        except Exception as e:
            print(f"  FAIL {name}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
