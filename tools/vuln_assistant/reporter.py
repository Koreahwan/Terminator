#!/usr/bin/env python3
"""Markdown and JSON artifact rendering."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .models import FindingCandidate, SurfaceItem


def attack_surface_payload(items: list[SurfaceItem], candidates: list[FindingCandidate], *, mode: str, domain: str) -> dict[str, Any]:
    return {
        "mode": mode,
        "domain": domain,
        "summary": {
            "raw_items": len(items),
            "candidates": len(candidates),
            "high_value": sum(1 for c in candidates if c.review_bucket == "high_value"),
            "raw_review": sum(1 for c in candidates if c.review_bucket == "raw_review"),
        },
        "raw_inventory": [item.to_dict() for item in items],
        "candidates": [candidate.to_dict() for candidate in candidates],
    }


def _candidate_block(c: FindingCandidate) -> str:
    return "\n".join(
        [
            f"{c.method} {c.endpoint()}",
            f"  risk_score: {c.risk_score}",
            f"  confidence_score: {c.confidence_score}",
            f"  category: {', '.join(c.risk_categories)}",
            f"  possible vuln: {', '.join(c.possible_vulns) or 'manual review required'}",
            f"  business risk: {c.business_risk}",
            f"  sales angle: {c.sales_angle}",
            f"  bug bounty angle: {c.bug_bounty_angle}",
            f"  safe next step: {c.safe_next_step}",
            f"  status: {c.status}",
            f"  review_bucket: {c.review_bucket}",
        ]
    )


def render_high_value_targets(candidates: list[FindingCandidate]) -> str:
    selected = [c for c in candidates if c.review_bucket == "high_value"]
    lines = ["# High-Value Targets", "", "These are candidates, not confirmed vulnerabilities.", ""]
    lines.extend(_candidate_block(c) + "\n" for c in selected)
    return "\n".join(lines).rstrip() + "\n"


def render_raw_endpoint_review(candidates: list[FindingCandidate]) -> str:
    selected = [c for c in candidates if c.review_bucket == "raw_review"]
    lines = ["# Raw Endpoint Review Queue", "", "Lower-scored endpoints kept for manual review so hidden business logic is not lost.", ""]
    for c in selected:
        lines.append(_candidate_block(c))
        if c.raw_review_reasons:
            lines.append("  raw reasons: " + "; ".join(c.raw_review_reasons))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_manual_test_queue(candidates: list[FindingCandidate]) -> str:
    selected = [c for c in candidates if c.review_bucket in {"high_value", "raw_review"}]
    lines = ["# Manual Test Queue", "", "All tests require scope authorization and negative controls.", ""]
    for c in selected:
        lines.append("```text")
        lines.append(c.manual_test)
        lines.append("```")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_safe_pocs(candidates: list[FindingCandidate]) -> str:
    selected = [c for c in candidates if c.review_bucket in {"high_value", "raw_review"}]
    lines = ["# Safe PoC Templates", "", "Templates are non-destructive and must not be auto-executed against state-changing endpoints.", ""]
    for c in selected:
        lines.append(f"## {c.method} {c.endpoint()}")
        lines.append("")
        lines.append("```bash")
        lines.append(c.safe_poc)
        lines.append("```")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_external_risk_summary(candidates: list[FindingCandidate]) -> str:
    top = candidates[:10]
    counts = Counter(cat for c in candidates for cat in c.risk_categories)
    lines = [
        "# External Risk Summary",
        "",
        "No destructive testing was performed. Items below are externally observable risk signals that require authorized validation.",
        "",
        "## Priority Themes",
    ]
    for category, count in counts.most_common(8):
        lines.append(f"- {category}: {count} signal(s)")
    lines.extend(["", "## Highest-Value Signals"])
    for c in top:
        lines.append(f"- `{c.method} {c.endpoint()}`: {c.business_risk} ({c.sales_angle})")
    return "\n".join(lines) + "\n"


def render_security_pitch(candidates: list[FindingCandidate]) -> str:
    top = [c for c in candidates if c.review_bucket == "high_value"][:8]
    lines = [
        "# Security Assessment Pitch",
        "",
        "Passive reconnaissance identified high-value API and workflow risk signals that should be reviewed under an authorized assessment.",
        "",
        "## Priority Areas",
    ]
    for c in top:
        lines.append(f"- `{c.method} {c.endpoint()}` - {c.sales_angle}")
    lines.extend(
        [
            "",
            "## Why This Matters",
            "These patterns are commonly associated with access-control failures, authentication boundary issues, API data exposure, business logic abuse, and AI/LLM workflow risks. The current output is a risk indication, not a proven finding report.",
            "",
            "## Proposed Assessment",
            "- API access-control review",
            "- IDOR/BOLA testing with authorized test accounts",
            "- Authentication and session-boundary testing",
            "- Business logic and payment/workflow abuse review",
            "- AI agent, RAG, and tool-calling security review where applicable",
            "- Reproduction-ready remediation report after authorization",
        ]
    )
    return "\n".join(lines) + "\n"


def render_recommended_scope(candidates: list[FindingCandidate]) -> str:
    categories = Counter(cat for c in candidates for cat in c.risk_categories)
    lines = ["# Recommended Test Scope", "", "Recommended scope should be authorized before active testing.", ""]
    for category, _ in categories.most_common():
        lines.append(f"- {category.replace('_', ' ')}")
    return "\n".join(lines) + "\n"


def render_bug_bounty_report(candidates: list[FindingCandidate], *, title: str = "Bug Bounty Report Draft", ai: bool = False) -> str:
    selected = [c for c in candidates if c.review_bucket == "high_value"][:10]
    lines = [
        f"# {title}",
        "",
        "This is a draft candidate queue. Do not submit until evidence, negative controls, and reproducibility requirements are satisfied.",
        "",
    ]
    for c in selected:
        lines.extend(
            [
                f"## {c.method} {c.endpoint()}",
                "",
                f"- Status: `{c.status}`",
                f"- Risk score: `{c.risk_score}`",
                f"- Confidence score: `{c.confidence_score}`",
                f"- Categories: {', '.join(c.risk_categories)}",
                f"- Possible vulnerability: {', '.join(c.possible_vulns)}",
                f"- Business risk: {c.business_risk}",
                f"- Verification: {c.bug_bounty_angle}",
                f"- Safe next step: {c.safe_next_step}",
                "",
                "### Safe Template",
                "```bash",
                c.safe_poc,
                "```",
                "",
            ]
        )
    if ai:
        lines.append("AI/LLM tests require AUP and scope confirmation before probing.")
    return "\n".join(lines).rstrip() + "\n"
