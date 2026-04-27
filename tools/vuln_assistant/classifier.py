#!/usr/bin/env python3
"""Risk taxonomy classifier.

The classifier favors transparent keyword rules. These are explainable, easy to
test, and appropriate for candidate generation where evidence is gathered later.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import SurfaceItem


TAXONOMY_ORDER = [
    "access_control",
    "authentication_session",
    "api_security",
    "business_logic",
    "admin_internal_exposure",
    "ssrf_webhook_integration",
    "file_upload_download",
    "data_exposure_privacy",
    "rate_limit_abuse",
    "sensitive_account_operations",
    "browser_trust_boundary",
    "realtime_event_api",
    "cache_cdn_routing_confusion",
    "cloud_saas_exposure",
    "webhook_integration_integrity",
    "audit_logging_non_repudiation",
    "ai_llm_security",
]


@dataclass(frozen=True)
class Rule:
    category: str
    keywords: tuple[str, ...]


RULES = [
    Rule("access_control", ("user_id", "account_id", "tenant_id", "org_id", "workspace", "team", "member", "invite", "share", "collaborator", "owner_id", "project_id")),
    Rule("authentication_session", ("login", "logout", "auth", "session", "token", "jwt", "password", "reset", "mfa", "otp", "oauth", "saml", "sso")),
    Rule("api_security", ("graphql", "grpc", "api_key", "api-key", "mobile", "bff", "partner", "v0", "v1", "v2", "beta", "internal-api", "role", "is_admin", "credits", "plan")),
    Rule("business_logic", ("payment", "billing", "invoice", "refund", "coupon", "credit", "subscription", "trial", "order", "checkout", "cart", "approval", "approve", "balance", "points", "stock", "amount", "payout")),
    Rule("admin_internal_exposure", ("admin", "internal", "staff", "debug", "config", "staging", "dev", "swagger", "openapi", "feature", "support", "impersonat")),
    Rule("ssrf_webhook_integration", ("url", "uri", "callback", "webhook", "redirect", "avatar_url", "avatarurl", "import", "fetch", "pdf", "image", "next")),
    Rule("file_upload_download", ("file", "path", "download", "upload", "template", "attachment", "document", "kyc", "s3", "gcs", "blob", "signed")),
    Rule("data_exposure_privacy", ("email", "phone", "address", "billing", "profile", "search", "autocomplete", "metadata", "secret", "log", "error", "note")),
    Rule("rate_limit_abuse", ("rate", "limit", "resend", "verify", "invite", "scrape", "export", "bulk", "expensive")),
    Rule("sensitive_account_operations", ("delete", "deletion", "change-email", "change_password", "password/change", "bank", "api_key", "webhook_secret", "audit", "owner", "transfer", "impersonat")),
    Rule("browser_trust_boundary", ("csrf", "cors", "samesite", "cookie", "frame", "clickjack", "origin")),
    Rule("realtime_event_api", ("websocket", "ws", "socket", "channel", "room", "subscription", "sse", "events", "stream")),
    Rule("cache_cdn_routing_confusion", ("cache", "cdn", "akamai", "cloudfront", "fastly", "varnish", "host", "route", "normalize")),
    Rule("cloud_saas_exposure", (".env", "backup", "dump", "metrics", "dashboard", "artifact", "build", "bucket", "s3", "gcs", "azure")),
    Rule("webhook_integration_integrity", ("signature", "timestamp", "event_type", "event-type", "integration", "oauth_app", "third-party", "thirdparty", "webhook")),
    Rule("audit_logging_non_repudiation", ("audit", "activity", "history", "log", "impersonat", "trace")),
    Rule("ai_llm_security", ("llm", "model", "prompt", "rag", "agent", "tool", "function", "memory", "mcp", "plugin", "completion", "chat")),
]


ID_PARAM_RE = re.compile(r"(^|[_-])(id|uuid)$|^(id|uuid)$", re.I)
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def classify(item: SurfaceItem, *, domain: str = "web") -> list[str]:
    haystack = " ".join(
        [
            item.method,
            item.url,
            item.path,
            " ".join(item.params),
            " ".join(item.body_fields),
            item.notes,
            item.source,
        ]
    ).lower()
    categories: set[str] = set()

    for rule in RULES:
        if any(keyword in haystack for keyword in rule.keywords):
            categories.add(rule.category)

    if any(ID_PARAM_RE.search(param) for param in item.params + item.body_fields):
        categories.add("access_control")
    if item.method.upper() in STATE_CHANGING_METHODS and not categories:
        categories.add("business_logic")
    if domain == "ai":
        categories.add("ai_llm_security")
    if "/api/" in haystack or haystack.startswith("api/"):
        categories.add("api_security")

    return [category for category in TAXONOMY_ORDER if category in categories] or ["api_security"]


def possible_vulns(item: SurfaceItem, categories: list[str]) -> list[str]:
    params = {p.lower() for p in item.params + item.body_fields}
    text = f"{item.url} {item.path} {' '.join(params)}".lower()
    vulns: set[str] = set()

    if "access_control" in categories:
        vulns.add("IDOR/BOLA or broken object authorization")
    if "admin_internal_exposure" in categories:
        vulns.add("BFLA or exposed privileged surface")
    if "authentication_session" in categories:
        vulns.add("auth bypass or session lifecycle flaw")
    if "api_security" in categories:
        vulns.add("API authorization, mass assignment, or version drift")
    if "business_logic" in categories:
        vulns.add("business logic abuse or workflow bypass")
    if params & {"url", "uri", "callback", "webhook", "redirect", "next", "avatar_url"} or "ssrf_webhook_integration" in categories:
        vulns.add("SSRF/open redirect indication")
    if params & {"file", "path", "download", "template"} or "file_upload_download" in categories:
        vulns.add("file access or upload/download authorization issue")
    if "data_exposure_privacy" in categories:
        vulns.add("excessive data exposure or privacy leak")
    if "rate_limit_abuse" in categories:
        vulns.add("abuse protection or rate-limit weakness")
    if "browser_trust_boundary" in categories:
        vulns.add("browser trust boundary issue")
    if "realtime_event_api" in categories:
        vulns.add("realtime channel authorization issue")
    if "cache_cdn_routing_confusion" in categories:
        vulns.add("cache/CDN routing confusion")
    if "cloud_saas_exposure" in categories:
        vulns.add("cloud/SaaS exposure")
    if "webhook_integration_integrity" in categories:
        vulns.add("webhook signature/replay or integration trust issue")
    if "audit_logging_non_repudiation" in categories:
        vulns.add("auditability or non-repudiation gap")
    if "ai_llm_security" in categories:
        vulns.add("prompt injection, tool misuse, or RAG data leakage")
    if item.auth_hint.lower() in {"none", "no", "false", "unauthenticated"} and any(token in text for token in ("admin", "user", "billing", "account", "internal")):
        vulns.add("possible unauthenticated access to sensitive API")

    return sorted(vulns)
