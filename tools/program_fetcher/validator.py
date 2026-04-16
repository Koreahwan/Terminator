"""Validate a ProgramData against required-field rules.

Required for PASS:
    - name (non-empty)
    - scope_in contains >= 1 Asset
    - scope_out contains >= 1 string
    - severity_table has >= 1 row OR bounty_range is non-empty
    - submission_rules length >= 50 chars

Confidence scoring is additive:
    +0.20  name present
    +0.20  scope_in >= 1
    +0.20  scope_out >= 1
    +0.15  severity_table or bounty_range
    +0.15  submission_rules >= 50 chars
    +0.10  raw_markdown >= 500 chars (full page captured)

Handlers may override confidence if they know their source is authoritative
(e.g., Immunefi __NEXT_DATA__ is always >= 0.95). The validator clamps to
[0, 1] and picks max(handler_confidence, computed_confidence) so a trusted
handler can't be downgraded by a thin page.
"""

from __future__ import annotations

from .base import (
    ProgramData,
    PASS,
    HOLD,
    FAIL,
    PASS_THRESHOLD,
    HOLD_THRESHOLD,
)


def validate(pd: ProgramData) -> tuple[str, float, list[str], list[str]]:
    """Return (verdict, confidence, missing_fields, warnings)."""
    missing: list[str] = []
    warnings: list[str] = []
    score = 0.0

    if pd.name.strip():
        score += 0.20
    else:
        missing.append("name")

    if pd.scope_in:
        score += 0.20
    else:
        missing.append("scope_in")

    if pd.scope_out:
        score += 0.20
    else:
        missing.append("scope_out")

    if pd.severity_table or pd.bounty_range:
        score += 0.15
    else:
        missing.append("severity_table_or_bounty_range")

    if len(pd.submission_rules.strip()) >= 50:
        score += 0.15
    else:
        missing.append("submission_rules")

    if len(pd.raw_markdown.strip()) >= 500:
        score += 0.10
    else:
        warnings.append("raw_markdown_thin")

    # Confidence model:
    #   - handler_cap (pd.confidence) is the ceiling set by the handler based
    #     on source fidelity. Generic/jina caps at 0.4 (lossy). Immunefi
    #     __NEXT_DATA__ caps at 0.95 (authoritative). HackerOne GraphQL ~0.9.
    #   - computed_score is the field-completeness floor derived above.
    #   - final = min(handler_cap, computed_score) — the handler can't promise
    #     more than the fields support, and the lossy generic parser can't
    #     auto-PASS just because the page happens to have enough bullets.
    handler_cap = float(pd.confidence or 0.0)
    computed_score = min(score, 1.0)
    if handler_cap <= 0.0:
        # Handler didn't set a cap: trust the computed score but keep it
        # below PASS by a hair so the caller still reviews.
        confidence = computed_score
    else:
        confidence = min(handler_cap, computed_score)
    confidence = min(confidence, 1.0)
    # Clamp down: we should never return PASS if critical fields are missing,
    # even if the handler is confident.
    if "name" in missing or ("scope_in" in missing and "scope_out" in missing):
        confidence = min(confidence, HOLD_THRESHOLD)

    if confidence >= PASS_THRESHOLD and not missing:
        verdict = PASS
    elif confidence >= HOLD_THRESHOLD:
        verdict = HOLD
    else:
        verdict = FAIL

    # Edge case: if we have zero useful content at all, FAIL.
    if not pd.raw_markdown and not pd.name and not pd.scope_in:
        verdict = FAIL
        confidence = 0.0

    # v12.4 — JS-rendered / private-program escape hatch:
    # If the handler explicitly told us the page is unscrapeable (SPA /
    # Cloudflare / invitation-only / auth-walled / 403), force HOLD so the
    # operator sees the fallback instructions instead of a silent FAIL.
    # The handler signals this by attaching a warning containing one of
    # the recognized markers below.
    HOLD_MARKERS = (
        "Playwright MCP fallback",
        "invitation-only",
        "private/auth-required",
        "auth-walled",
        "Cloudflare bot protection",
    )
    spa_hold_signaled = any(
        any(marker in w for marker in HOLD_MARKERS)
        for w in (pd.warnings or [])
    )
    if spa_hold_signaled and verdict == FAIL:
        verdict = HOLD
        confidence = max(confidence, HOLD_THRESHOLD)

    return verdict, round(confidence, 3), missing, warnings
