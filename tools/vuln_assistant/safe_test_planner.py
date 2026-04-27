#!/usr/bin/env python3
"""Generate safe, non-destructive test plans and PoC templates."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .classifier import STATE_CHANGING_METHODS
from .models import FindingCandidate, SurfaceItem


def _replace_query(url: str, replacements: dict[str, str]) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(replacements)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def safe_poc(item: SurfaceItem, categories: list[str], *, mode: str) -> str:
    endpoint = item.url or item.path or "/"
    method = item.method.upper() or "GET"
    headers = "-H 'Accept: application/json'"
    if mode == "client-pitch":
        return "Passive-only mode: no PoC is generated before authorization."
    if method in STATE_CHANGING_METHODS:
        return f"# MANUAL_REVIEW_REQUIRED: {method} {endpoint}\n# State-changing requests are not auto-executed."

    if "ssrf_webhook_integration" in categories:
        repl = {param: "{CONTROLLED_BENIGN_URL}" for param in item.params if param.lower() in {"url", "uri", "callback", "webhook", "redirect", "next", "avatar_url"}}
        target = _replace_query(endpoint, repl) if repl and endpoint.startswith("http") else endpoint
        return f"curl -i -sS '{target}' {headers}\n# Use only a controlled benign URL. Do not use metadata or internal IPs."

    if "file_upload_download" in categories:
        repl = {param: "not-a-real-file.txt" for param in item.params if param.lower() in {"file", "path", "download", "template"}}
        target = _replace_query(endpoint, repl) if repl and endpoint.startswith("http") else endpoint
        return f"curl -i -sS '{target}' {headers}\n# Use harmless invalid filenames or owned test files only."

    if "access_control" in categories:
        return "\n".join(
            [
                f"curl -i -sS '{endpoint}' -H 'Authorization: Bearer {{USER_A_TOKEN}}' {headers}",
                f"curl -i -sS '{endpoint}' -H 'Authorization: Bearer {{USER_B_TOKEN}}' {headers}",
                "# Replace only owned test-account identifiers. Do not access real third-party data.",
            ]
        )

    if "authentication_session" in categories:
        return "\n".join(
            [
                f"curl -i -sS '{endpoint}' -H 'Authorization: Bearer {{VALID_TOKEN}}' {headers}",
                f"curl -i -sS '{endpoint}' {headers}",
                "# Compare status, body length, and explicit error fields only.",
            ]
        )

    return f"curl -i -sS '{endpoint}' {headers}\n# Candidate template only; verify scope and authorization first."


def manual_test_plan(candidate: FindingCandidate) -> str:
    return "\n".join(
        [
            f"Test ID: {candidate.review_bucket}-{candidate.raw_rank}",
            f"Endpoint: {candidate.method} {candidate.endpoint()}",
            f"Risk Category: {', '.join(candidate.risk_categories)}",
            "Precondition: authorized scope and owned test accounts/assets",
            f"Safe Request Template: {candidate.safe_poc.splitlines()[0] if candidate.safe_poc else 'manual request required'}",
            "Negative Control: compare benign/empty/own-resource response before any candidate variation",
            "Expected Secure Behavior: authorization is enforced and no private cross-account data is returned",
            "Evidence Needed: raw request/response pairs, timestamps, response field diff, and negative controls",
            "Stop Condition: any private third-party data, destructive state change, rate-limit risk, or OOS signal",
        ]
    )
