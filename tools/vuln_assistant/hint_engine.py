#!/usr/bin/env python3
"""Candidate generation from normalized surface items."""

from __future__ import annotations

from .business_risk import map_business_context
from .classifier import classify, possible_vulns
from .models import FindingCandidate, STATUS_CANDIDATE, SurfaceItem
from .safe_test_planner import manual_test_plan, safe_poc
from .scoring import confidence_score, raw_review_reasons, review_bucket, risk_score


def build_candidate(item: SurfaceItem, *, mode: str = "bounty", domain: str = "web") -> FindingCandidate:
    categories = classify(item, domain=domain)
    vulns = possible_vulns(item, categories)
    business_risk, sales_angle, bounty_angle, next_step = map_business_context(categories)
    risk = risk_score(item, categories, vulns)
    confidence = confidence_score(item, categories)
    bucket = review_bucket(item, risk, confidence, categories)
    mode_allowed = ["bounty", "client-pitch"]
    if "ai_llm_security" in categories or domain == "ai":
        mode_allowed.append("ai-security")
    candidate = FindingCandidate(
        method=item.method.upper(),
        url=item.url,
        path=item.path,
        params=item.params,
        source=item.source,
        raw_rank=item.raw_rank,
        authorization_level="passive_only" if mode == "client-pitch" else "program_scope",
        risk_categories=categories,
        possible_vulns=vulns,
        business_risk=business_risk,
        sales_angle=sales_angle,
        bug_bounty_angle=bounty_angle,
        safe_next_step=next_step,
        risk_score=risk,
        confidence_score=confidence,
        status=STATUS_CANDIDATE,
        mode_allowed=mode_allowed,
        review_bucket=bucket,
        raw_review_reasons=raw_review_reasons(item, risk, categories),
    )
    candidate.safe_poc = safe_poc(item, categories, mode=mode)
    candidate.manual_test = manual_test_plan(candidate)
    return candidate


def build_candidates(items: list[SurfaceItem], *, mode: str = "bounty", domain: str = "web") -> list[FindingCandidate]:
    candidates = [build_candidate(item, mode=mode, domain=domain) for item in items]
    return sorted(candidates, key=lambda c: (c.risk_score, c.confidence_score, -c.raw_rank), reverse=True)
