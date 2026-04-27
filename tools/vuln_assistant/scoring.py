#!/usr/bin/env python3
"""Risk, confidence, and review bucket scoring."""

from __future__ import annotations

from .classifier import STATE_CHANGING_METHODS
from .models import SurfaceItem


CATEGORY_WEIGHTS = {
    "access_control": 3,
    "authentication_session": 3,
    "api_security": 2,
    "business_logic": 4,
    "admin_internal_exposure": 4,
    "ssrf_webhook_integration": 2,
    "file_upload_download": 2,
    "data_exposure_privacy": 3,
    "rate_limit_abuse": 1,
    "sensitive_account_operations": 4,
    "browser_trust_boundary": 1,
    "realtime_event_api": 3,
    "cache_cdn_routing_confusion": 2,
    "cloud_saas_exposure": 4,
    "webhook_integration_integrity": 3,
    "audit_logging_non_repudiation": 1,
    "ai_llm_security": 4,
}

HIGH_VALUE_TOKENS = (
    "billing",
    "refund",
    "payment",
    "invoice",
    "payout",
    "admin",
    "staff",
    "internal",
    "support",
    "impersonat",
    "workspace",
    "org",
    "tenant",
    "team",
    "password",
    "email",
    "mfa",
    "reset",
    "session",
    "token",
    "api_key",
    "webhook_secret",
    "audit",
)


def risk_score(item: SurfaceItem, categories: list[str], possible_vulns: list[str]) -> int:
    score = 1
    score += max((CATEGORY_WEIGHTS.get(category, 0) for category in categories), default=1)
    text = f"{item.url} {item.path} {' '.join(item.params)} {' '.join(item.body_fields)}".lower()
    if any(token in text for token in HIGH_VALUE_TOKENS):
        score += 2
    if item.method.upper() in STATE_CHANGING_METHODS:
        score += 2
    if possible_vulns:
        score += 1
    if item.auth_hint.lower() in {"none", "no", "false", "unauthenticated"} and any(category in categories for category in ("access_control", "business_logic", "admin_internal_exposure", "data_exposure_privacy")):
        score += 2
    if item.source.lower() in {"burp", "har", "authenticated_crawl", "postman", "openapi", "swagger"}:
        score += 1
    return max(1, min(10, score))


def confidence_score(item: SurfaceItem, categories: list[str]) -> int:
    score = 10
    if item.source.lower() in {"burp", "har", "authenticated_crawl"}:
        score += 20
    elif item.source.lower() in {"openapi", "swagger", "postman", "graphql"}:
        score += 15
    elif item.source.lower() in {"endpoint_map", "httpx"}:
        score += 10
    if item.status_code in {200, 201, 202, 204, 301, 302, 403, 405}:
        score += 10
    if item.params or item.body_fields:
        score += 10
    if categories:
        score += 5
    if item.auth_hint.lower() not in {"unknown", ""}:
        score += 5
    return max(0, min(100, score))


def review_bucket(item: SurfaceItem, risk: int, confidence: int, categories: list[str]) -> str:
    if risk >= 7:
        return "high_value"
    if raw_review_reasons(item, risk, categories):
        return "raw_review"
    if risk <= 2 and confidence <= 20:
        return "low_priority"
    return "raw_review"


def raw_review_reasons(item: SurfaceItem, risk: int, categories: list[str]) -> list[str]:
    text = f"{item.url} {item.path} {' '.join(item.params)} {' '.join(item.body_fields)}".lower()
    reasons: list[str] = []
    if any(token in text for token in ("/api/v0", "/beta", "/legacy", "/internal-api", "/v0/", "/deprecated")):
        reasons.append("legacy, beta, deprecated, or undocumented API surface")
    if item.method.upper() in STATE_CHANGING_METHODS:
        reasons.append("state-changing method")
    if (item.params or item.body_fields) and risk < 7:
        reasons.append("parameters present but taxonomy confidence is limited")
    if item.source.lower() in {"burp", "har", "authenticated_crawl"}:
        reasons.append("observed in authenticated or proxy-captured traffic")
    if any(token in text for token in ("/action", "/process", "/submit", "/sync")):
        reasons.append("generic workflow-like endpoint name")
    if any(token in text for token in ("graphql", "grpc", "websocket", "/ws", "sse", "events", "stream")):
        reasons.append("realtime, GraphQL, gRPC, or event API")
    if item.status_code in {401, 403, 405}:
        reasons.append("protected-looking endpoint exists")
    if len(item.params) >= 3 and not categories:
        reasons.append("static-looking endpoint with many query parameters")
    return reasons
