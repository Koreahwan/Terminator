from __future__ import annotations

import json
from pathlib import Path

from tools.debate_gate import arbiter
from tools.runtime_gate import check_runtime_gates
from tools.safety_wrapper import verdict
from tools.scope_contract import check_artifact, create_contract, validate_contract


def _write_target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    raw = target / "program_raw"
    raw.mkdir(parents=True)
    program_data = {
        "platform": "yeswehack",
        "handle": "example",
        "name": "Example Program",
        "program_url": "https://yeswehack.com/programs/example",
        "policy_url": "https://yeswehack.com/programs/example",
        "scope_in": [{"type": "domain", "identifier": "example.com", "qualifier": "Web application"}],
        "scope_out": ["Denial of service attacks are strictly forbidden", "Do not access real user data"],
        "known_issues": ["None documented"],
        "submission_rules": "Do not use automated scanners. Only interact with accounts you own.",
        "severity_table": [{"severity": "High", "reward": "1000", "asset_class": "Web", "notes": "Access control"}],
        "bounty_range": {"min": "100", "max": "1000", "currency": "EUR"},
        "raw_markdown": "",
        "confidence": 0.95,
        "source": "fixture",
        "fetched_at": "2026-04-25T00:00:00Z",
    }
    rules = """
# Program Rules Summary

## In-Scope Assets
- `example.com` (domain) - Web application

## Out-of-Scope / Exclusion List
- Denial of service attacks are strictly forbidden
- Do not access real user data

## Known Issues
- None documented

## Submission Rules
- Do not use automated scanners.
- Only interact with accounts you own.

## Severity Scope
| Severity | Asset class | Reward | Notes |
|---|---|---|---|
| High | Web | 1000 | Access control |

## Asset Scope Constraints
- `example.com`: production web application only
""".strip()
    bundle = """
example.com Web application
Denial of service attacks are strictly forbidden
Do not access real user data
None documented
Do not use automated scanners.
Only interact with accounts you own.
High Web 1000 Access control
example.com production web application only
""".strip()
    (target / "program_data.json").write_text(json.dumps(program_data), encoding="utf-8")
    (target / "fetch_meta.json").write_text(
        json.dumps({"verdict": "PASS", "confidence": 0.95, "source": "fixture"}),
        encoding="utf-8",
    )
    (target / "program_rules_summary.md").write_text(rules, encoding="utf-8")
    (raw / "bundle.md").write_text(bundle, encoding="utf-8")
    return target


def test_scope_contract_create_and_validate(tmp_path: Path) -> None:
    target = _write_target(tmp_path)

    rc, payload = create_contract(target)

    assert rc == 0, payload
    contract = target / "scope_contract.json"
    assert contract.exists()
    rc2, validation = validate_contract(contract)
    assert rc2 == 0, validation
    assert validation["status"] == "pass"


def test_scope_contract_blocks_missing_raw_bundle(tmp_path: Path) -> None:
    target = _write_target(tmp_path)
    (target / "program_raw" / "bundle.md").unlink()

    rc, payload = create_contract(target)

    assert rc == 1
    assert payload["reason"] == "missing_required_inputs"


def test_scope_contract_artifact_hash_gate(tmp_path: Path) -> None:
    target = _write_target(tmp_path)
    rc, payload = create_contract(target)
    assert rc == 0
    contract_sha = payload["scope_contract_sha256"]
    good = target / "artifact.md"
    bad = target / "bad.md"
    good.write_text(f"scope_contract_sha256: {contract_sha}\n", encoding="utf-8")
    bad.write_text("no hash\n", encoding="utf-8")

    assert check_artifact(good, target / "scope_contract.json")[0] == 0
    assert check_artifact(bad, target / "scope_contract.json")[0] == 1


def test_safety_wrapper_allows_public_metadata_without_contract() -> None:
    payload = verdict({"action_type": "public_program_fetch", "url_or_asset": "https://yeswehack.com/programs/example"})

    assert payload["verdict"] == "ALLOW"
    assert payload["llm_override_allowed"] is False


def test_safety_wrapper_blocks_active_and_unknown_automation(tmp_path: Path) -> None:
    target = _write_target(tmp_path)
    rc, _payload = create_contract(target)
    assert rc == 0

    blocked = verdict({"action_type": "scan", "url_or_asset": "https://example.com"}, contract_path=target / "scope_contract.json")
    assert blocked["verdict"] == "BLOCK"

    live = verdict(
        {
            "action_type": "live_http_request",
            "url_or_asset": "https://example.com/api",
            "method": "GET",
            "payload_class": "none",
            "scope_contract_sha256": json.loads((target / "scope_contract.json").read_text())["scope_contract_sha256"],
        },
        contract_path=target / "scope_contract.json",
    )
    assert live["verdict"] == "BLOCK"
    assert "automation_policy_unknown" not in live["reasons"]  # explicit forbidden scanner policy was parsed
    assert "live_target_action_requires_human_or_explicit_policy_unlock" not in live["reasons"]


def test_debate_gate_blocks_scope_risk() -> None:
    result = arbiter(
        {"claim": "IDOR", "evidence_refs": ["evidence.md"], "poc_plan": "request another user", "scope_verdict": "PASS"},
        {"scope_objection": "OOS: other user data access is forbidden"},
        {"repro_status": "PASS"},
        scope_contract_sha256="abc",
    )

    assert result["verdict"] == "BLOCK"
    assert "scope_or_policy_risk" in result["reasons"]


def test_runtime_gate_requires_debate_artifact(tmp_path: Path) -> None:
    policy = {
        "runtime_profile": "scope-first-hybrid",
        "runtime_pipeline": "bounty",
        "debate_mode": "gpt-propose-claude-object-gpt-respond",
    }

    failed = check_runtime_gates(tmp_path, "critic", policy, [])
    assert failed["status"] == "fail"

    (tmp_path / "critic_debate.json").write_text(
        json.dumps(
            {
                "schema_version": "debate-gate/1",
                "verdict": "REPORTABLE",
                "inputs": {
                    "gpt_proposal": {"evidence_refs": ["http_trace.log"], "poc_plan": "run safe_poc.py"},
                    "claude_objection": {"scope_objection": "none"},
                },
            }
        ),
        encoding="utf-8",
    )

    passed = check_runtime_gates(tmp_path, "critic", policy, [])
    assert passed["status"] == "pass"


def test_runtime_gate_requires_machine_evidence(tmp_path: Path) -> None:
    policy = {
        "runtime_profile": "scope-first-hybrid",
        "runtime_pipeline": "bounty",
        "evidence_gate": "machine-style-3x-local-then-remote",
    }
    report = tmp_path / "verification_report.md"

    report.write_text("local passes: 2\n", encoding="utf-8")
    assert check_runtime_gates(tmp_path, "exploiter", policy, ["verification_report.md"])["status"] == "fail"

    report.write_text("local passes: 3\nremote flag captured: FLAG{ok}\n", encoding="utf-8")
    assert check_runtime_gates(tmp_path, "exploiter", policy, ["verification_report.md"])["status"] == "pass"


def test_runtime_gate_real_tool_output_does_not_accept_generic_file_word(tmp_path: Path) -> None:
    policy = {
        "runtime_profile": "scope-first-hybrid",
        "runtime_pipeline": "bounty",
        "evidence_gate": "machine-style-real-tool-output",
    }
    report = tmp_path / "exploit_notes.md"

    report.write_text("The PoC file should be reviewed manually.\n", encoding="utf-8")
    assert check_runtime_gates(tmp_path, "exploiter", policy, ["exploit_notes.md"])["status"] == "fail"

    report.write_text("$ file ./vuln\n./vuln: ELF 64-bit LSB executable\n", encoding="utf-8")
    assert check_runtime_gates(tmp_path, "exploiter", policy, ["exploit_notes.md"])["status"] == "pass"


def test_runtime_gate_requires_mock_or_replay_transport(tmp_path: Path) -> None:
    policy = {
        "runtime_profile": "scope-first-hybrid",
        "runtime_pipeline": "bounty",
        "transport_policy": "mock-or-replay-required",
    }

    (tmp_path / "endpoint_map.md").write_text("live scan against target\n", encoding="utf-8")
    assert check_runtime_gates(tmp_path, "scout", policy, ["endpoint_map.md"])["status"] == "fail"

    (tmp_path / "endpoint_map.md").write_text("replay transport fixture used\n", encoding="utf-8")
    assert check_runtime_gates(tmp_path, "scout", policy, ["endpoint_map.md"])["status"] == "pass"
