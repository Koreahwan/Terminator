#!/usr/bin/env python3
"""Map technical signals to business and sales language."""

from __future__ import annotations


CATEGORY_CONTEXT = {
    "access_control": (
        "customer data exposure, privacy incident, and compliance risk",
        "access-control review needed",
        "verify object ownership with two authorized test accounts",
        "compare owned test account A/B only",
    ),
    "authentication_session": (
        "account takeover and protected API exposure risk",
        "account takeover and session boundary assessment",
        "test auth/header removal and token lifecycle in scope",
        "compare authenticated, unauthenticated, expired-token, and logout-token responses",
    ),
    "api_security": (
        "core API authorization and data-boundary failure risk",
        "API access-control review",
        "verify object auth, mass assignment, and old API versions",
        "inspect params/body fields and compare expected role/object boundaries",
    ),
    "business_logic": (
        "direct financial loss or workflow abuse risk",
        "Business Logic Abuse Assessment",
        "manual verification only; do not auto-execute state-changing requests",
        "prepare request template and expected state transitions for manual review",
    ),
    "admin_internal_exposure": (
        "privileged/internal function exposure risk",
        "internal attack surface exposure review",
        "verify unauthenticated and low-privileged access safely",
        "check status/body-length only until authorized to inspect behavior",
    ),
    "ssrf_webhook_integration": (
        "server-side request or integration abuse risk",
        "external URL handling review",
        "use controlled benign callback only; never metadata/internal IPs",
        "use a controlled benign URL placeholder and avoid internal targets",
    ),
    "file_upload_download": (
        "sensitive document, invoice, contract, or KYC file exposure risk",
        "sensitive file access review",
        "verify with owned test files only",
        "use owned test file IDs and harmless invalid filenames",
    ),
    "data_exposure_privacy": (
        "personal data or private metadata exposure risk",
        "privacy exposure assessment",
        "compare response fields and negative controls",
        "diff own-account and permitted test-account response fields",
    ),
    "rate_limit_abuse": (
        "account attack, service abuse, and operating cost risk",
        "abuse protection review",
        "do not brute force; review rate-limit design and single safe checks only",
        "document rate-limit expectations without automated brute force",
    ),
    "sensitive_account_operations": (
        "account takeover, financial loss, or audit trail damage risk",
        "high-risk account operation review",
        "state-changing endpoint requires manual verification",
        "queue for manual review with explicit stop conditions",
    ),
    "browser_trust_boundary": (
        "user-session abuse through browser trust boundary risk",
        "browser trust boundary review",
        "prioritize only if state-changing and cookie-authenticated",
        "review CSRF/CORS/cookie posture without cross-user exploitation",
    ),
    "realtime_event_api": (
        "real-time customer data or operational event exposure risk",
        "realtime API access-control review",
        "verify channel isolation with authorized test accounts",
        "subscribe only to owned/test channels",
    ),
    "cache_cdn_routing_confusion": (
        "private data exposure through cache/CDN behavior risk",
        "CDN and cache security review",
        "do not poison cache; inspect cache headers and path behavior",
        "record cache headers and avoid poisoning payloads",
    ),
    "cloud_saas_exposure": (
        "bulk data or secret exposure through cloud/SaaS assets",
        "cloud exposure assessment",
        "confirm public exposure only; do not bulk-read data",
        "check listing/metadata existence only and stop before data collection",
    ),
    "webhook_integration_integrity": (
        "account, billing, or workflow manipulation via third-party integration risk",
        "webhook and integration security review",
        "verify only with owned test integration",
        "prepare signature/replay checks without sending replay automatically",
    ),
    "audit_logging_non_repudiation": (
        "abuse traceability and compliance failure risk",
        "auditability and abuse traceability review",
        "combine with admin, billing, or account takeover impact when possible",
        "check whether important actions have expected audit events",
    ),
    "ai_llm_security": (
        "AI agent misuse of internal tools or private data risk",
        "AI agent and LLM application security assessment",
        "AUP/scope required before non-destructive prompt tests",
        "use non-destructive prompt and tool-boundary checks only after authorization",
    ),
}


def map_business_context(categories: list[str]) -> tuple[str, str, str, str]:
    if not categories:
        return (
            "undifferentiated API exposure risk",
            "API security review",
            "manual verification required",
            "inspect endpoint context manually",
        )
    primary = categories[0]
    return CATEGORY_CONTEXT.get(primary, CATEGORY_CONTEXT["api_security"])
