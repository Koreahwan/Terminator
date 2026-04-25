from __future__ import annotations

import json
from pathlib import Path

from tools.debate_gate import arbiter
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
