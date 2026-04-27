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
