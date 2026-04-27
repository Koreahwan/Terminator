#!/usr/bin/env python3
"""Strictly gated read-only IDOR/BOLA verifier."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .models import IdorVerificationResult, ResponseFingerprint
from .response_fingerprint import (
    MAX_FINGERPRINT_BYTES,
    fingerprint_response,
    is_auth_block_response,
    looks_like_same_response_class,
)

READ_ONLY_METHODS = {"GET", "HEAD"}
SAFE_MODES = {"bounty", "ai-security"}


@dataclass
class HttpObservation:
    status_code: int
    headers: dict[str, str]
    body: bytes


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def default_requester(method: str, url: str, headers: Mapping[str, str], *, timeout: float = 10.0) -> HttpObservation:
    request = Request(url, method=method, headers=dict(headers))
    opener = build_opener(NoRedirectHandler)
    try:
        with opener.open(request, timeout=timeout) as response:
            return HttpObservation(
                status_code=int(response.status),
                headers={str(k): str(v) for k, v in response.headers.items()},
                body=response.read(MAX_FINGERPRINT_BYTES),
            )
    except HTTPError as exc:
        body = exc.read(MAX_FINGERPRINT_BYTES)
        return HttpObservation(status_code=int(exc.code), headers={str(k): str(v) for k, v in exc.headers.items()}, body=body)
    except URLError as exc:
        raise RuntimeError(f"request failed: {exc.reason}") from exc


def _candidate_endpoint(candidate: dict[str, Any]) -> str:
    return str(candidate.get("url") or candidate.get("path") or "")


def _scope_host(url: str) -> str:
    parsed = urlsplit(url)
    return (parsed.hostname or "").lower().rstrip(".")


def _is_scope_allowed(url: str, allowed_scope_hosts: set[str]) -> bool:
    host = _scope_host(url)
    normalized = {h.lower().rstrip(".") for h in allowed_scope_hosts}
    return bool(host) and host in normalized


def _object_refs(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    refs = candidate.get("object_refs") or []
    return [ref for ref in refs if isinstance(ref, dict)]


def _select_ref(candidate: dict[str, Any], owned_objects: dict[str, Any]) -> dict[str, Any] | None:
    for ref in _object_refs(candidate):
        if not ref.get("safely_replaceable"):
            continue
        if str(ref.get("location") or "") not in {"query", "path"}:
            continue
        if str(ref.get("name") or "") in owned_objects:
            return ref
    return None


def _replace_object(url: str, ref: dict[str, Any], value: str) -> str | None:
    name = str(ref.get("name") or "")
    location = str(ref.get("location") or "")
    if not name or not value:
        return None
    parts = urlsplit(url)
    if location == "query":
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if not any(k == name for k, _ in pairs):
            return None
        replaced = [(k, value if k == name else v) for k, v in pairs]
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(replaced), parts.fragment))
    if location == "path":
        path = parts.path
        if "{" + name + "}" in path:
            path = path.replace("{" + name + "}", value)
        elif ":" + name in path:
            path = path.replace(":" + name, value)
        else:
            return None
        return urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))
    return None


def _fingerprint(obs: HttpObservation) -> ResponseFingerprint:
    return fingerprint_response(obs.status_code, obs.headers, obs.body)


def _blocked(endpoint: str, method: str, ref: str, signal: str, reason: str) -> IdorVerificationResult:
    return IdorVerificationResult(
        candidate_endpoint=endpoint,
        method=method,
        object_ref=ref,
        verdict="blocked",
        signal_type=signal,
        reasons=[reason],
    )


def verify_candidate(
    candidate: dict[str, Any],
    *,
    owned_objects: dict[str, Any],
    auth_a: Mapping[str, str],
    auth_b: Mapping[str, str],
    allowed_scope_hosts: set[str],
    mode: str,
    requester: Callable[[str, str, Mapping[str, str]], HttpObservation] | None = None,
    delay_seconds: float = 0.2,
) -> IdorVerificationResult:
    endpoint = _candidate_endpoint(candidate)
    method = str(candidate.get("method") or "GET").upper()
    if mode == "client-pitch" or mode not in SAFE_MODES:
        return _blocked(endpoint, method, "", "mode_blocked", "verification is disabled outside authorized bounty/ai-security modes")
    if method not in READ_ONLY_METHODS:
        return _blocked(endpoint, method, "", "unsafe_method", "verification only supports GET/HEAD")
    if not endpoint.startswith("https://") and not endpoint.startswith("http://"):
        return _blocked(endpoint, method, "", "relative_url", "verification requires absolute in-scope URL")
    if not _is_scope_allowed(endpoint, allowed_scope_hosts):
        return _blocked(endpoint, method, "", "scope_blocked", "endpoint host is not in allowed scope hosts")
    if not auth_a or not auth_b:
        return _blocked(endpoint, method, "", "missing_auth", "two auth profiles are required")

    ref = _select_ref(candidate, owned_objects)
    if ref is None:
        return _blocked(endpoint, method, "", "missing_owned_object_pair", "owned object pair is missing or object reference is not safely replaceable")
    ref_name = str(ref.get("name") or "")
    pair = owned_objects.get(ref_name) or {}
    a_value = str(pair.get("account_a_value") or "")
    b_value = str(pair.get("account_b_value") or "")
    if not a_value or not b_value:
        return _blocked(endpoint, method, ref_name, "missing_owned_object_pair", "owned object pair requires account_a_value and account_b_value")

    a_own_url = _replace_object(endpoint, ref, a_value)
    b_own_url = _replace_object(endpoint, ref, b_value)
    a_cross_url = _replace_object(endpoint, ref, b_value)
    b_cross_url = _replace_object(endpoint, ref, a_value)
    if not all([a_own_url, b_own_url, a_cross_url, b_cross_url]):
        return _blocked(endpoint, method, ref_name, "unsafe_replacement", "object reference location cannot be safely replaced")

    run = requester or (lambda m, u, h: default_requester(m, u, h))
    try:
        obs_a = run(method, a_own_url, auth_a)  # type: ignore[arg-type]
        time.sleep(delay_seconds)
        obs_b = run(method, b_own_url, auth_b)  # type: ignore[arg-type]
        time.sleep(delay_seconds)
        obs_a_cross = run(method, a_cross_url, auth_a)  # type: ignore[arg-type]
        time.sleep(delay_seconds)
        obs_b_cross = run(method, b_cross_url, auth_b)  # type: ignore[arg-type]
    except RuntimeError as exc:
        return IdorVerificationResult(
            candidate_endpoint=endpoint,
            method=method,
            object_ref=ref_name,
            verdict="inconclusive",
            signal_type="request_failed",
            reasons=[str(exc)],
        )

    fp_a = _fingerprint(obs_a)
    fp_b = _fingerprint(obs_b)
    fp_a_cross = _fingerprint(obs_a_cross)
    fp_b_cross = _fingerprint(obs_b_cross)

    if fp_a.response_class != "success_like" or fp_b.response_class != "success_like":
        return IdorVerificationResult(
            candidate_endpoint=endpoint,
            method=method,
            object_ref=ref_name,
            verdict="inconclusive",
            signal_type="baseline_failed",
            reasons=["owner baseline did not produce success-like responses"],
            baseline_a=fp_a,
            baseline_b=fp_b,
            cross_a_to_b=fp_a_cross,
            cross_b_to_a=fp_b_cross,
        )
    if is_auth_block_response(fp_a_cross) and is_auth_block_response(fp_b_cross):
        return IdorVerificationResult(
            candidate_endpoint=endpoint,
            method=method,
            object_ref=ref_name,
            verdict="blocked",
            signal_type="auth_blocked",
            reasons=["cross-account requests returned auth-block-like responses"],
            baseline_a=fp_a,
            baseline_b=fp_b,
            cross_a_to_b=fp_a_cross,
            cross_b_to_a=fp_b_cross,
        )
    if fp_a_cross.redirect_location_present or fp_b_cross.redirect_location_present:
        verdict = "inconclusive"
        signal = "redirect_observed"
        reasons = ["cross-account response redirected; manual review required"]
    elif looks_like_same_response_class(fp_b, fp_a_cross) and looks_like_same_response_class(fp_a, fp_b_cross):
        verdict = "needs_manual_confirmation"
        signal = "possible_idor"
        reasons = ["read-only cross-account check produced success-like response fingerprints similar to owner baselines"]
    else:
        verdict = "inconclusive"
        signal = "different_response_class"
        reasons = ["cross-account response fingerprints differed from owner baselines"]

    return IdorVerificationResult(
        candidate_endpoint=endpoint,
        method=method,
        object_ref=ref_name,
        verdict=verdict,
        signal_type=signal,
        reasons=reasons,
        baseline_a=fp_a,
        baseline_b=fp_b,
        cross_a_to_b=fp_a_cross,
        cross_b_to_a=fp_b_cross,
    )


def verify_candidates(
    candidates: list[dict[str, Any]],
    *,
    owned_objects: dict[str, Any],
    auth_a: Mapping[str, str],
    auth_b: Mapping[str, str],
    allowed_scope_hosts: set[str],
    mode: str,
    requester: Callable[[str, str, Mapping[str, str]], HttpObservation] | None = None,
    delay_seconds: float = 0.2,
) -> list[IdorVerificationResult]:
    return [
        verify_candidate(
            candidate,
            owned_objects=owned_objects,
            auth_a=auth_a,
            auth_b=auth_b,
            allowed_scope_hosts=allowed_scope_hosts,
            mode=mode,
            requester=requester,
            delay_seconds=delay_seconds,
        )
        for candidate in candidates
    ]


def render_verification_summary(results: list[IdorVerificationResult]) -> str:
    lines = [
        "# IDOR/BOLA Verification Summary",
        "",
        "Verification uses read-only requests, owned test accounts, and fingerprints only. Results are not automatic confirmation.",
        "",
    ]
    for result in results:
        lines.extend(
            [
                f"## {result.method} {result.candidate_endpoint}",
                "",
                f"- Object reference: `{result.object_ref or 'n/a'}`",
                f"- Verdict: `{result.verdict}`",
                f"- Signal type: `{result.signal_type}`",
                f"- Reason: {'; '.join(result.reasons)}",
                "- Evidence handling: response bodies and auth secrets were not stored.",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def render_idor_report_draft(results: list[IdorVerificationResult]) -> str:
    selected = [r for r in results if r.verdict == "needs_manual_confirmation"]
    lines = [
        "# Possible IDOR/BOLA",
        "",
        "This draft is conservative. It describes possible object-level authorization issues that need manual confirmation.",
        "",
    ]
    if not selected:
        lines.append("No read-only verification result currently needs manual confirmation.")
        return "\n".join(lines).rstrip() + "\n"
    for result in selected:
        lines.extend(
            [
                f"## {result.method} {result.candidate_endpoint}",
                "",
                "### Summary",
                "A read-only cross-account object access check produced a success-like response fingerprint similar to the owning account baseline.",
                "",
                "### Affected Endpoint",
                f"- Method: `{result.method}`",
                f"- Endpoint: `{result.candidate_endpoint}`",
                f"- Object reference: `{result.object_ref}`",
                "",
                "### Evidence Handling",
                "- Owned test accounts only",
                "- Read-only requests only",
                "- No brute force",
                "- No enumeration",
                "- No response bodies stored",
                "- Fingerprints only",
                "",
                "### Potential Impact",
                "If manually confirmed, this may indicate that one authenticated user can access an object belonging to another user, account, workspace, or tenant.",
                "",
                "### Recommendation",
                "Enforce object-level authorization on every request that accesses an object by user-supplied ID.",
                "",
                "### Status",
                "`needs_manual_confirmation`",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def write_verification_outputs(out_dir: Path, results: list[IdorVerificationResult]) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "idor_verification.json"
    summary_path = out_dir / "idor_verification_summary.md"
    report_path = out_dir / "idor_report_draft.md"
    json_path.write_text(json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    summary_path.write_text(render_verification_summary(results), encoding="utf-8")
    report_path.write_text(render_idor_report_draft(results), encoding="utf-8")
    return {
        "idor_verification.json": str(json_path),
        "idor_verification_summary.md": str(summary_path),
        "idor_report_draft.md": str(report_path),
    }
