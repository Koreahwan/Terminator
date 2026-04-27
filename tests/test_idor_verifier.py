from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tools.vuln_assistant.idor_verifier import HttpObservation, verify_candidate, verify_candidates


def _candidate(method: str = "GET", url: str = "https://api.example.com/invoices?invoice_id=inv_test_a_001") -> dict:
    return {
        "method": method,
        "url": url,
        "path": "/invoices",
        "object_refs": [
            {
                "name": "invoice_id",
                "location": "query",
                "safely_replaceable": True,
            }
        ],
    }


OWNED = {"invoice_id": {"account_a_value": "inv_test_a_001", "account_b_value": "inv_test_b_001"}}
AUTH_A = {"Authorization": "Bearer account-a-secret"}
AUTH_B = {"Authorization": "Bearer account-b-secret"}


def test_rejects_client_pitch_unsafe_methods_and_out_of_scope() -> None:
    assert verify_candidate(_candidate(), owned_objects=OWNED, auth_a=AUTH_A, auth_b=AUTH_B, allowed_scope_hosts={"api.example.com"}, mode="client-pitch").verdict == "blocked"
    assert verify_candidate(_candidate(method="POST"), owned_objects=OWNED, auth_a=AUTH_A, auth_b=AUTH_B, allowed_scope_hosts={"api.example.com"}, mode="bounty").signal_type == "unsafe_method"
    assert verify_candidate(_candidate(url="https://evil.com@not-scope.example/invoices?invoice_id=inv_test_a_001"), owned_objects=OWNED, auth_a=AUTH_A, auth_b=AUTH_B, allowed_scope_hosts={"api.example.com"}, mode="bounty").signal_type == "scope_blocked"


def test_rejects_missing_owned_object_pair() -> None:
    result = verify_candidate(_candidate(), owned_objects={}, auth_a=AUTH_A, auth_b=AUTH_B, allowed_scope_hosts={"api.example.com"}, mode="bounty")

    assert result.verdict == "blocked"
    assert result.signal_type == "missing_owned_object_pair"


def test_rejects_non_query_path_references_even_if_legacy_candidate_marks_replaceable() -> None:
    candidate = _candidate()
    candidate["object_refs"][0]["location"] = "graphql"
    candidate["object_refs"][0]["safely_replaceable"] = True

    result = verify_candidate(candidate, owned_objects=OWNED, auth_a=AUTH_A, auth_b=AUTH_B, allowed_scope_hosts={"api.example.com"}, mode="bounty")

    assert result.verdict == "blocked"
    assert result.signal_type == "missing_owned_object_pair"


def test_returns_blocked_for_cross_auth_blocks() -> None:
    def requester(method: str, url: str, headers: dict[str, str]) -> HttpObservation:
        own = ("account-a" in headers["Authorization"] and "inv_test_a_001" in url) or ("account-b" in headers["Authorization"] and "inv_test_b_001" in url)
        if own:
            return HttpObservation(200, {"Content-Type": "application/json"}, b'{"id":"x","amount":1}')
        return HttpObservation(403, {"Content-Type": "application/json"}, b'{"error":"forbidden"}')

    result = verify_candidate(_candidate(), owned_objects=OWNED, auth_a=AUTH_A, auth_b=AUTH_B, allowed_scope_hosts={"api.example.com"}, mode="bounty", requester=requester, delay_seconds=0)

    assert result.verdict == "blocked"
    assert result.signal_type == "auth_blocked"


def test_returns_inconclusive_for_baseline_failure() -> None:
    def requester(method: str, url: str, headers: dict[str, str]) -> HttpObservation:
        return HttpObservation(403, {"Content-Type": "application/json"}, b'{"error":"forbidden"}')

    result = verify_candidate(_candidate(), owned_objects=OWNED, auth_a=AUTH_A, auth_b=AUTH_B, allowed_scope_hosts={"api.example.com"}, mode="bounty", requester=requester, delay_seconds=0)

    assert result.verdict == "inconclusive"
    assert result.signal_type == "baseline_failed"


def test_returns_needs_manual_confirmation_without_storing_bodies_or_secrets() -> None:
    def requester(method: str, url: str, headers: dict[str, str]) -> HttpObservation:
        return HttpObservation(200, {"Content-Type": "application/json"}, b'{"id":"redacted","amount":1,"email":"user@example.com"}')

    results = verify_candidates([_candidate()], owned_objects=OWNED, auth_a=AUTH_A, auth_b=AUTH_B, allowed_scope_hosts={"api.example.com"}, mode="bounty", requester=requester, delay_seconds=0)
    data = json.dumps([r.to_dict() for r in results])

    assert results[0].verdict == "needs_manual_confirmation"
    assert results[0].signal_type == "possible_idor"
    assert "account-a-secret" not in data
    assert "account-b-secret" not in data
    assert "user@example.com" not in data
    assert "amount" in data  # schema key only, not raw body value


def test_returns_needs_manual_confirmation_for_asymmetric_success_like_cross_check() -> None:
    def requester(method: str, url: str, headers: dict[str, str]) -> HttpObservation:
        is_a = "account-a" in headers["Authorization"]
        is_b = "account-b" in headers["Authorization"]
        is_a_object = "inv_test_a_001" in url
        is_b_object = "inv_test_b_001" in url
        if (is_a and is_a_object) or (is_b and is_b_object) or (is_a and is_b_object):
            return HttpObservation(200, {"Content-Type": "application/json"}, b'{"id":"x","amount":1}')
        return HttpObservation(403, {"Content-Type": "application/json"}, b'{"error":"forbidden"}')

    result = verify_candidate(_candidate(), owned_objects=OWNED, auth_a=AUTH_A, auth_b=AUTH_B, allowed_scope_hosts={"api.example.com"}, mode="bounty", requester=requester, delay_seconds=0)

    assert result.verdict == "needs_manual_confirmation"
    assert result.signal_type == "possible_asymmetric_idor"


def test_idor_verify_cli_refuses_client_pitch(tmp_path: Path) -> None:
    candidates = tmp_path / "idor_candidates.json"
    owned = tmp_path / "owned.json"
    candidates.write_text(json.dumps([_candidate()]), encoding="utf-8")
    owned.write_text(json.dumps(OWNED), encoding="utf-8")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.vuln_assistant",
            "idor-verify",
            "--mode",
            "client-pitch",
            "--candidates",
            str(candidates),
            "--owned-objects",
            str(owned),
            "--scope-host",
            "api.example.com",
            "--auth-a-env",
            "ACCOUNT_A_TOKEN",
            "--auth-b-env",
            "ACCOUNT_B_TOKEN",
            "--out",
            str(tmp_path / "out"),
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 2
    assert "passive-only" in proc.stderr
