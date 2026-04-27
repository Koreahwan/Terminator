from __future__ import annotations

from tools.vuln_assistant.response_fingerprint import (
    fingerprint_response,
    is_auth_block_response,
    looks_like_same_response_class,
    redact_sensitive_text,
    shape_similarity,
)


def test_redacts_emails_tokens_cookies_and_phone_numbers() -> None:
    text = 'email=a@example.com Authorization: Bearer secret.jwt.value "access_token":"abc123" session=xyz +1 415 555 1212'
    redacted = redact_sensitive_text(text)

    assert "a@example.com" not in redacted
    assert "secret.jwt.value" not in redacted
    assert "abc123" not in redacted
    assert "xyz" not in redacted
    assert "415 555 1212" not in redacted


def test_fingerprint_does_not_expose_raw_body_and_shapes_json() -> None:
    fp = fingerprint_response(
        200,
        {"Content-Type": "application/json"},
        b'{"id":123,"email":"user@example.com","items":[{"name":"invoice"}]}',
    )
    data = fp.to_dict()

    assert fp.response_class == "success_like"
    assert data["json_shape"] == {"email": "str", "id": "int", "items": [{"name": "str"}]}
    assert "user@example.com" not in str(data)
    assert "invoice" not in str(data)
    assert "body" not in data


def test_auth_error_and_status_classification() -> None:
    fp = fingerprint_response(403, {"Content-Type": "application/json"}, b'{"error":"forbidden"}')

    assert fp.response_class == "auth_block_like"
    assert is_auth_block_response(fp) is True


def test_shape_similarity_and_same_class() -> None:
    a = fingerprint_response(200, {"Content-Type": "application/json"}, b'{"id":1,"name":"a"}')
    b = fingerprint_response(200, {"Content-Type": "application/json"}, b'{"id":2,"name":"b"}')
    c = fingerprint_response(200, {"Content-Type": "application/json"}, b'{"items":[{"id":2}]}')

    assert shape_similarity(a.json_shape, b.json_shape) == 1.0
    assert looks_like_same_response_class(a, b) is True
    assert looks_like_same_response_class(a, c) is False
