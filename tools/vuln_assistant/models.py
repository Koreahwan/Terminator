#!/usr/bin/env python3
"""Shared data models for the vulnerability discovery assistant."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


STATUS_SIGNAL = "signal"
STATUS_CANDIDATE = "candidate"
STATUS_NEEDS_VERIFICATION = "needs_verification"
STATUS_CONFIRMED = "confirmed"
STATUS_REJECTED = "rejected"


@dataclass
class SurfaceItem:
    """A raw or normalized attack-surface item.

    The model intentionally keeps the raw source and rank so low-scoring
    endpoints are not discarded before manual review.
    """

    method: str = "GET"
    url: str = ""
    path: str = ""
    params: list[str] = field(default_factory=list)
    source: str = "unknown"
    raw_rank: int = 0
    status_code: int | None = None
    auth_hint: str = "unknown"
    notes: str = ""
    body_fields: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def endpoint(self) -> str:
        return self.url or self.path or "/"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FindingCandidate:
    """Risk-ranked candidate derived from a surface item."""

    method: str
    url: str
    path: str
    params: list[str]
    source: str
    raw_rank: int
    authorization_level: str
    risk_categories: list[str]
    possible_vulns: list[str]
    business_risk: str
    sales_angle: str
    bug_bounty_angle: str
    safe_next_step: str
    risk_score: int
    confidence_score: int
    status: str
    mode_allowed: list[str]
    review_bucket: str
    raw_review_reasons: list[str] = field(default_factory=list)
    safe_poc: str = ""
    manual_test: str = ""

    def endpoint(self) -> str:
        return self.url or self.path or "/"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ObjectReference:
    """Object reference signal found in a request surface."""

    name: str
    location: str
    value_present: bool = False
    confidence: int = 0
    reason: str = ""
    safely_replaceable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IdorCandidate:
    """Passive IDOR/BOLA candidate derived from a SurfaceItem."""

    method: str
    url: str
    path: str
    params: list[str]
    source: str
    raw_rank: int
    status_code: int | None
    auth_hint: str
    object_refs: list[ObjectReference]
    risk_score: int
    confidence_score: int
    status: str
    eligible_for_read_only_verification: bool
    manual_review_only: bool
    reasons: list[str] = field(default_factory=list)
    review_bucket: str = "raw_review"

    def endpoint(self) -> str:
        return self.url or self.path or "/"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["object_refs"] = [ref.to_dict() for ref in self.object_refs]
        return data


@dataclass
class ResponseFingerprint:
    """Response metadata suitable for comparison without body storage."""

    status_code: int
    content_type: str
    length_bucket: str
    body_sha256_redacted: str
    json_shape: Any
    auth_error_like: bool
    redirect_location_present: bool
    response_class: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IdorVerificationResult:
    """Safe verifier outcome. It never marks findings confirmed."""

    candidate_endpoint: str
    method: str
    object_ref: str
    verdict: str
    signal_type: str
    reasons: list[str]
    baseline_a: ResponseFingerprint | None = None
    baseline_b: ResponseFingerprint | None = None
    cross_a_to_b: ResponseFingerprint | None = None
    cross_b_to_a: ResponseFingerprint | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("baseline_a", "baseline_b", "cross_a_to_b", "cross_b_to_a"):
            value = getattr(self, key)
            data[key] = value.to_dict() if value else None
        return data
