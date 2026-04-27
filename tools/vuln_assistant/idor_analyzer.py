#!/usr/bin/env python3
"""Passive IDOR/BOLA candidate analysis."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from .models import (
    IdorCandidate,
    ObjectReference,
    STATUS_CANDIDATE,
    STATUS_NEEDS_VERIFICATION,
    SurfaceItem,
)

READ_ONLY_METHODS = {"GET", "HEAD"}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

OBJECT_REFERENCE_NAMES = {
    "id",
    "uuid",
    "user_id",
    "uid",
    "account_id",
    "profile_id",
    "customer_id",
    "member_id",
    "org_id",
    "organization_id",
    "workspace_id",
    "tenant_id",
    "team_id",
    "invoice_id",
    "order_id",
    "payment_id",
    "refund_id",
    "document_id",
    "file_id",
    "attachment_id",
    "project_id",
    "ticket_id",
    "message_id",
    "report_id",
    "shop_id",
    "vehicle_id",
}

OBJECT_SUFFIX_RE = re.compile(r"(^|[_-])(id|uuid)$", re.I)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
OPAQUE_RE = re.compile(r"^[A-Za-z0-9_-]{16,}$")
BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
GRAPHQL_ID_RE = re.compile(r"^(gid://|[A-Za-z]+:[A-Za-z0-9_-]{8,}|[A-Za-z0-9+/]{20,}={0,2}$)")

BUSINESS_CRITICAL = {
    "invoice",
    "order",
    "payment",
    "refund",
    "billing",
    "payout",
    "subscription",
}
IDENTITY_OBJECTS = {"user", "account", "profile", "member", "customer"}
TENANT_OBJECTS = {"org", "organization", "workspace", "tenant", "team", "project"}
DATA_OBJECTS = {"document", "file", "attachment", "message", "report", "ticket"}
PRIVILEGED_TOKENS = {"admin", "internal", "management", "staff", "support", "impersonat"}


def _name_matches(name: str) -> bool:
    lowered = name.strip().lower().replace("-", "_")
    return lowered in OBJECT_REFERENCE_NAMES or bool(OBJECT_SUFFIX_RE.search(lowered))


def _value_matches(value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    if value.isdigit():
        return True
    if UUID_RE.match(value):
        return True
    if GRAPHQL_ID_RE.match(value):
        return True
    if OPAQUE_RE.match(value):
        return True
    if BASE64ISH_RE.match(value):
        return True
    if re.match(r"^[a-z0-9]+(?:-[a-z0-9]+){1,}$", value, re.I):
        return True
    return False


def _field_confidence(name: str, value: str | None, *, structured: bool) -> int:
    score = 35
    if _name_matches(name):
        score += 35
    if value is not None and _value_matches(value):
        score += 20
    if structured:
        score += 10
    return max(0, min(100, score))


def _query_refs(item: SurfaceItem) -> list[ObjectReference]:
    if not item.url:
        return []
    refs: list[ObjectReference] = []
    for name, value in parse_qsl(urlsplit(item.url).query, keep_blank_values=True):
        if _name_matches(name) or _value_matches(value):
            reason = "business object reference in query parameter" if _name_matches(name) else "ID-like value in query parameter"
            refs.append(
                ObjectReference(
                    name=name,
                    location="query",
                    value_present=value != "",
                    confidence=_field_confidence(name, value, structured=item.source.lower() in {"burp", "har", "postman", "openapi"}),
                    reason=reason,
                    safely_replaceable=True,
                )
            )
    return refs


def _named_refs(item: SurfaceItem, fields: list[str], *, location: str) -> list[ObjectReference]:
    refs: list[ObjectReference] = []
    for field in fields:
        if not _name_matches(field):
            continue
        refs.append(
            ObjectReference(
                name=field,
                location=location,
                value_present=False,
                confidence=_field_confidence(field, None, structured=item.source.lower() in {"openapi", "postman", "graphql"}),
                reason=f"object reference field in {location}",
                safely_replaceable=location == "query",
            )
        )
    return refs


def _path_refs(item: SurfaceItem) -> list[ObjectReference]:
    endpoint = item.url or item.path
    if not endpoint:
        return []
    path = urlsplit(endpoint).path if endpoint.startswith("http") else endpoint
    refs: list[ObjectReference] = []
    for name in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}|:([A-Za-z_][A-Za-z0-9_]*)", path):
        field = name[0] or name[1]
        if _name_matches(field):
            refs.append(
                ObjectReference(
                    name=field,
                    location="path",
                    value_present=False,
                    confidence=_field_confidence(field, None, structured=item.source.lower() in {"openapi", "postman"}),
                    reason="named object reference in path parameter",
                    safely_replaceable=True,
                )
            )
    parts = [p for p in path.split("/") if p]
    for idx, segment in enumerate(parts):
        if not _value_matches(segment):
            continue
        previous = parts[idx - 1].lower().replace("-", "_") if idx else "path_segment"
        if previous.endswith("s"):
            previous = previous[:-1]
        inferred = f"{previous}_id" if previous and not previous.endswith("_id") else previous
        refs.append(
            ObjectReference(
                name=inferred or "path_segment_id",
                location="path_segment",
                value_present=True,
                confidence=55,
                reason="ID-like unnamed path segment; requires explicit owned-object mapping before verification",
                safely_replaceable=False,
            )
        )
    return refs


def _graphql_refs(item: SurfaceItem) -> list[ObjectReference]:
    refs: list[ObjectReference] = []
    raw_vars = item.raw.get("graphql_variables") if isinstance(item.raw, dict) else None
    if isinstance(raw_vars, dict):
        for name, value in raw_vars.items():
            text_value = str(value) if value is not None else ""
            if _name_matches(str(name)) or _value_matches(text_value):
                refs.append(
                    ObjectReference(
                        name=str(name),
                        location="graphql",
                        value_present=value is not None,
                        confidence=_field_confidence(str(name), text_value, structured=True),
                        reason="GraphQL variable object reference",
                        safely_replaceable=False,
                    )
                )
    return refs


def detect_object_refs(item: SurfaceItem) -> list[ObjectReference]:
    refs = []
    refs.extend(_query_refs(item))
    refs.extend(_path_refs(item))
    refs.extend(_named_refs(item, item.params, location="query" if item.url and urlsplit(item.url).query else "param"))
    refs.extend(_named_refs(item, item.body_fields, location="body"))
    refs.extend(_graphql_refs(item))

    deduped: dict[tuple[str, str], ObjectReference] = {}
    for ref in refs:
        key = (ref.name.lower(), ref.location)
        current = deduped.get(key)
        if current is None or ref.confidence > current.confidence:
            deduped[key] = ref
    return sorted(deduped.values(), key=lambda r: (r.confidence, r.name), reverse=True)


def _text(item: SurfaceItem) -> str:
    return f"{item.method} {item.url} {item.path} {' '.join(item.params)} {' '.join(item.body_fields)} {item.source}".lower()


def _contains_any(text: str, tokens: set[str]) -> bool:
    return any(token in text for token in tokens)


def score_idor_candidate(item: SurfaceItem, refs: list[ObjectReference]) -> tuple[int, int, list[str]]:
    text = _text(item)
    risk = 3
    confidence = 10
    reasons = ["object reference detected"]

    if _contains_any(text, IDENTITY_OBJECTS):
        risk += 2
        reasons.append("identity or account object keyword")
    if _contains_any(text, BUSINESS_CRITICAL):
        risk += 3
        reasons.append("business-critical object keyword")
    if _contains_any(text, TENANT_OBJECTS):
        risk += 3
        reasons.append("tenant or workspace boundary keyword")
    if _contains_any(text, DATA_OBJECTS):
        risk += 2
        reasons.append("private data object keyword")
    if _contains_any(text, PRIVILEGED_TOKENS):
        risk += 2
        reasons.append("admin or internal surface keyword")
    if "/api/" in text or text.startswith("api/"):
        risk += 1
        reasons.append("API endpoint")
    if item.method.upper() in STATE_CHANGING_METHODS:
        risk += 1
        reasons.append("state-changing method requires manual review")
    elif item.method.upper() in READ_ONLY_METHODS:
        reasons.append("read-only method")
    if item.source.lower() in {"burp", "har", "authenticated_crawl"}:
        risk += 1
        confidence += 20
        reasons.append("observed in Burp/HAR/authenticated traffic")
    elif item.source.lower() in {"openapi", "swagger", "postman", "graphql"}:
        confidence += 15
        reasons.append("structured source")
    if item.status_code in {200, 201, 202, 204}:
        risk += 1
        confidence += 10
        reasons.append("successful observed status code")
    elif item.status_code in {401, 403, 405}:
        confidence += 8
        reasons.append("protected-looking endpoint exists")
    if refs:
        confidence += max(ref.confidence for ref in refs) // 2
    if any(ref.value_present for ref in refs):
        confidence += 10
        reasons.append("ID-like value observed")

    return max(1, min(10, risk)), max(0, min(100, confidence)), reasons


def build_idor_candidate(item: SurfaceItem) -> IdorCandidate | None:
    refs = detect_object_refs(item)
    if not refs:
        return None
    risk, confidence, reasons = score_idor_candidate(item, refs)
    method = item.method.upper()
    eligible = method in READ_ONLY_METHODS and any(ref.safely_replaceable and ref.location in {"query", "path"} for ref in refs)
    manual_only = not eligible
    status = STATUS_NEEDS_VERIFICATION if eligible else STATUS_CANDIDATE
    if method in STATE_CHANGING_METHODS:
        manual_only = True
        eligible = False
    review_bucket = "high_value" if risk >= 7 else "raw_review"
    return IdorCandidate(
        method=method,
        url=item.url,
        path=item.path,
        params=item.params,
        source=item.source,
        raw_rank=item.raw_rank,
        status_code=item.status_code,
        auth_hint=item.auth_hint,
        object_refs=refs,
        risk_score=risk,
        confidence_score=confidence,
        status=status,
        eligible_for_read_only_verification=eligible,
        manual_review_only=manual_only,
        reasons=reasons,
        review_bucket=review_bucket,
    )


def build_idor_candidates(items: list[SurfaceItem]) -> list[IdorCandidate]:
    candidates = [candidate for item in items if (candidate := build_idor_candidate(item))]
    return sorted(candidates, key=lambda c: (c.risk_score, c.confidence_score, -c.raw_rank), reverse=True)


def render_idor_manual_queue(candidates: list[IdorCandidate]) -> str:
    lines = [
        "# IDOR/BOLA Manual Review Queue",
        "",
        "All entries are candidates. Use only authorized scope and owned test accounts.",
        "",
    ]
    for c in candidates:
        lines.extend(
            [
                f"## {c.method} {c.endpoint()}",
                "",
                f"- Status: `{c.status}`",
                f"- Risk score: `{c.risk_score}`",
                f"- Confidence score: `{c.confidence_score}`",
                f"- Review bucket: `{c.review_bucket}`",
                f"- Eligible for read-only verification: `{str(c.eligible_for_read_only_verification).lower()}`",
                f"- Manual review only: `{str(c.manual_review_only).lower()}`",
                "- Object references:",
            ]
        )
        for ref in c.object_refs:
            lines.append(
                f"  - `{ref.name}` ({ref.location}, confidence={ref.confidence}, safely_replaceable={str(ref.safely_replaceable).lower()}): {ref.reason}"
            )
        lines.extend(
            [
                "- Why it matters: object-level authorization failures can expose another account, tenant, invoice, file, or workflow object.",
                "- Safe next step: provide two owned test accounts and owned object ID pairs; run read-only verification only for GET/HEAD candidates.",
                "- Required inputs: Account A auth, Account B auth, owned object value for both accounts, explicit scope host.",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def write_idor_passive_outputs(out_dir: Path, candidates: list[IdorCandidate]) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    candidates_path = out_dir / "idor_candidates.json"
    queue_path = out_dir / "idor_manual_queue.md"
    candidates_path.write_text(json.dumps([c.to_dict() for c in candidates], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    queue_path.write_text(render_idor_manual_queue(candidates), encoding="utf-8")
    return {"idor_candidates.json": str(candidates_path), "idor_manual_queue.md": str(queue_path)}
