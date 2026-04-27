#!/usr/bin/env python3
"""Response fingerprinting without sensitive body storage."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from .models import ResponseFingerprint

MAX_FINGERPRINT_BYTES = 256 * 1024

REDACTION_PATTERNS = [
    (re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.I), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r'"(access_token|refresh_token|id_token|api_key|session_id|csrf_token)"\s*:\s*"[^"]+"', re.I), r'"\1":"[REDACTED_SECRET]"'),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"\b(?:sk|pk|rk|ak)_[A-Za-z0-9]{16,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\b(session|sid|cookie|token)=([^;\s]+)", re.I), r"\1=[REDACTED]"),
    (re.compile(r"\+?\d[\d .()-]{8,}\d"), "[REDACTED_PHONE]"),
]

AUTH_ERROR_RE = re.compile(
    r"\b(unauthorized|forbidden|access denied|not authorized|permission denied|invalid token|missing token|login required|authentication required)\b",
    re.I,
)


def redact_sensitive_text(text: str) -> str:
    redacted = text
    for pattern, replacement in REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _normalize_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def _body_to_text(body: bytes | str | None) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        return body[:MAX_FINGERPRINT_BYTES].decode("utf-8", errors="replace")
    return body[:MAX_FINGERPRINT_BYTES]


def length_bucket(length: int) -> str:
    if length == 0:
        return "0"
    if length <= 128:
        return "1-128"
    if length <= 1024:
        return "129-1024"
    if length <= 10 * 1024:
        return "1KB-10KB"
    if length <= 100 * 1024:
        return "10KB-100KB"
    if length <= MAX_FINGERPRINT_BYTES:
        return "100KB-256KB"
    return "256KB+"


def json_shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): json_shape(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, list):
        if not value:
            return []
        return [json_shape(value[0])]
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int) and not isinstance(value, bool):
        return "int"
    if isinstance(value, float):
        return "float"
    if value is None:
        return "null"
    return "str"


def _shape_tokens(shape: Any, prefix: str = "") -> set[str]:
    if isinstance(shape, dict):
        tokens: set[str] = set()
        for key, value in shape.items():
            child_prefix = f"{prefix}.{key}" if prefix else key
            tokens.add(child_prefix)
            tokens.update(_shape_tokens(value, child_prefix))
        return tokens
    if isinstance(shape, list):
        return {f"{prefix}[]"} | (_shape_tokens(shape[0], f"{prefix}[]") if shape else set())
    return {f"{prefix}:{shape}" if prefix else str(shape)}


def shape_similarity(a: Any, b: Any) -> float:
    left = _shape_tokens(a)
    right = _shape_tokens(b)
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def _response_class(status_code: int, headers: dict[str, str], redacted_text: str, shape: Any) -> str:
    if 300 <= status_code <= 399:
        return "redirect_like"
    if status_code in {401, 403}:
        return "auth_block_like"
    if status_code == 404:
        return "auth_block_like" if AUTH_ERROR_RE.search(redacted_text) else "not_found_like"
    if status_code >= 500:
        return "server_error_like"
    if 200 <= status_code <= 299 and not AUTH_ERROR_RE.search(redacted_text):
        return "success_like"
    if AUTH_ERROR_RE.search(redacted_text):
        return "auth_block_like"
    return "other_like"


def fingerprint_response(status_code: int, headers: Mapping[str, str] | None, body: bytes | str | None) -> ResponseFingerprint:
    normalized_headers = _normalize_headers(headers)
    content_type = normalized_headers.get("content-type", "").split(";")[0].strip().lower()
    body_text = _body_to_text(body)
    redacted = redact_sensitive_text(body_text)
    parsed_shape: Any = None
    if "json" in content_type or redacted.lstrip().startswith(("{", "[")):
        try:
            parsed_shape = json_shape(json.loads(redacted))
        except json.JSONDecodeError:
            parsed_shape = None
    digest = hashlib.sha256(redacted.encode("utf-8", errors="replace")).hexdigest() if redacted else ""
    response_class = _response_class(status_code, normalized_headers, redacted, parsed_shape)
    return ResponseFingerprint(
        status_code=status_code,
        content_type=content_type,
        length_bucket=length_bucket(len(body if isinstance(body, bytes) else (body or "").encode("utf-8"))),
        body_sha256_redacted=digest,
        json_shape=parsed_shape,
        auth_error_like=bool(AUTH_ERROR_RE.search(redacted)) or status_code in {401, 403},
        redirect_location_present="location" in normalized_headers,
        response_class=response_class,
    )


def is_auth_block_response(fp: ResponseFingerprint) -> bool:
    return fp.response_class == "auth_block_like" or fp.auth_error_like or fp.status_code in {401, 403}


def looks_like_same_response_class(baseline: ResponseFingerprint, cross: ResponseFingerprint) -> bool:
    if baseline.response_class != cross.response_class:
        return False
    if baseline.content_type and cross.content_type and baseline.content_type != cross.content_type:
        return False
    if baseline.json_shape is not None or cross.json_shape is not None:
        return shape_similarity(baseline.json_shape, cross.json_shape) >= 0.65
    return baseline.length_bucket == cross.length_bucket or baseline.response_class == "success_like"
