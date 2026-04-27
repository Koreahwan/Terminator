from __future__ import annotations

import json
from pathlib import Path

from integrations.burp_bridge_server import append_jsonl, is_allowed_url, redact_headers, redact_url_query, sanitize_observation


def test_scope_filter_handles_exact_hostname_and_userinfo_tricks() -> None:
    assert is_allowed_url("https://api.example.com/invoices", {"api.example.com"}) is True
    assert is_allowed_url("https://evil.com@api.example.com/invoices", {"evil.com"}) is False
    assert is_allowed_url("https://api.example.com.evil.test/invoices", {"api.example.com"}) is False


def test_redacts_sensitive_headers() -> None:
    headers = redact_headers(
        {
            "Authorization": "Bearer secret",
            "Cookie": "sid=secret",
            "X-API-Key": "key",
            "X-Session-Id": "session",
            "Accept": "application/json",
        }
    )

    assert headers["Authorization"] == "[REDACTED]"
    assert headers["Cookie"] == "[REDACTED]"
    assert headers["X-API-Key"] == "[REDACTED]"
    assert headers["X-Session-Id"] == "[REDACTED]"
    assert headers["Accept"] == "application/json"
    assert redact_headers(["not", "headers"]) == {}


def test_sanitize_observation_writes_metadata_only(tmp_path: Path) -> None:
    status, payload = sanitize_observation(
        {
            "method": "GET",
            "url": "https://api.example.com/invoices?invoice_id=inv_1",
            "status_code": 200,
            "request_headers": {"Authorization": "Bearer secret"},
            "response_headers": {"Content-Type": "application/json", "Set-Cookie": "sid=secret"},
            "request_body": "should not be saved",
            "response_body": "should not be saved",
            "body_length": 123,
        },
        allowed_hosts={"api.example.com"},
    )
    out = tmp_path / "burp_stream.jsonl"
    append_jsonl(out, payload)
    written = out.read_text(encoding="utf-8")

    assert status == 200
    assert payload["body_saved"] is False
    assert "should not be saved" not in written
    assert "Bearer secret" not in written
    assert "sid=secret" not in written
    assert json.loads(written)["url"].startswith("https://api.example.com")


def test_redacts_sensitive_query_values() -> None:
    url = redact_url_query("https://api.example.com/callback?invoice_id=inv_1&access_token=secret&session_id=sid")

    assert "invoice_id=inv_1" in url
    assert "secret" not in url
    assert "sid" not in url
    assert "%5BREDACTED%5D" in url


def test_rejects_out_of_scope_host() -> None:
    status, payload = sanitize_observation({"url": "https://other.example.com/"}, allowed_hosts={"api.example.com"})

    assert status == 403
    assert payload["error"] == "out_of_scope"


def test_sanitize_observation_ignores_malformed_header_and_numeric_types() -> None:
    status, payload = sanitize_observation(
        {
            "url": "https://api.example.com/",
            "status_code": True,
            "body_length": True,
            "request_headers": ["bad"],
            "response_headers": ["bad"],
        },
        allowed_hosts={"api.example.com"},
    )

    assert status == 200
    assert payload["status_code"] is None
    assert payload["body_length"] is None
    assert payload["request_headers"] == {}
    assert payload["response_headers"] == {}
