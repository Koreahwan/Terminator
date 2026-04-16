"""Data model for fetched program intake.

ProgramData is the normalized schema every platform handler fills in.
The validator keys off the same fields, so adding a new platform means:
  1) implement a handler that returns ProgramData
  2) register it in dispatch.py
  3) add a fixture + test

No external dependencies. Stdlib only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any


# Verdicts from the validator.
PASS = "PASS"
HOLD = "HOLD"
FAIL = "FAIL"

# Confidence thresholds.
# >= PASS_THRESHOLD: auto-fill verbatim sections in program_rules_summary.md.
# < PASS_THRESHOLD but > 0: HOLD — artifacts are written but user must review.
# == 0 / raised exception: FAIL — nothing is written, caller must fall back.
PASS_THRESHOLD = 0.8
HOLD_THRESHOLD = 0.4


@dataclass
class Asset:
    """One in-scope or out-of-scope asset, normalized.

    `type`: domain | subdomain | wildcard | smart_contract | repo | mobile_app | api | other
    `identifier`: the literal string (e.g. "*.example.com", "0xabc..def")
    `qualifier`: verbatim qualifier from the program page
                 (e.g. "APIs located under", "Mainnet tags only")
    `in_scope_versions`: list of branch/tag constraints, verbatim
    """

    type: str = "other"
    identifier: str = ""
    qualifier: str = ""
    in_scope_versions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SeverityRow:
    """One row from a program's severity/reward table, verbatim."""

    severity: str = ""  # "Critical" / "High" / "Medium" / "Low" / "Informational"
    reward: str = ""  # "$5,000" / "€1,500 - €5,000" / "swag only"
    asset_class: str = ""  # "Smart contract" / "Web" / "" if not tiered by asset
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProgramData:
    """Normalized program intake.

    Every handler returns one of these. Fields left empty by a handler are
    a signal to the validator that confidence is low.
    """

    # Identity
    platform: str = ""  # "hackerone" / "bugcrowd" / "immunefi" / ...
    handle: str = ""  # platform-specific program slug
    name: str = ""  # human-readable program name
    program_url: str = ""  # canonical program page URL
    policy_url: str = ""  # URL of the policy / scope page (may differ from program_url)

    # Verbatim scope — these are the fields that MUST come from the platform
    # directly, never a summarizer. scope_in/scope_out are structured for
    # programmatic checks; raw_markdown preserves the original text for the
    # audit trail and human review.
    scope_in: list[Asset] = field(default_factory=list)
    scope_out: list[str] = field(default_factory=list)  # verbatim one-line entries
    known_issues: list[str] = field(default_factory=list)
    submission_rules: str = ""  # verbatim paragraph(s)
    severity_table: list[SeverityRow] = field(default_factory=list)
    bounty_range: dict[str, Any] = field(default_factory=dict)
    # {"min": "$100", "max": "$10000", "currency": "USD", "note": "..."}

    cvss_version: str = ""  # "3.1" / "4.0" / ""

    # Provenance
    last_modified: str = ""  # program page Last-Modified or "YYYY-MM-DD" from content
    raw_markdown: str = ""  # full verbatim markdown of the policy section(s)
    confidence: float = 0.0  # 0.0 - 1.0; set by handler
    source: str = ""  # handler name + endpoint hit, e.g. "hackerone.graphql"
    fetched_at: str = ""  # ISO-8601 UTC of fetch
    warnings: list[str] = field(default_factory=list)  # non-fatal handler notes

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON. Nested dataclasses expand via asdict."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProgramData":
        """Rehydrate from a dict (used by the cache layer)."""
        scope_in = [Asset(**a) for a in data.get("scope_in", [])]
        scope_out = list(data.get("scope_out", []))
        severity_table = [SeverityRow(**r) for r in data.get("severity_table", [])]
        kwargs = {k: v for k, v in data.items()
                  if k not in ("scope_in", "scope_out", "severity_table")}
        return cls(
            scope_in=scope_in,
            scope_out=scope_out,
            severity_table=severity_table,
            **kwargs,
        )


@dataclass
class FetchResult:
    """Result of dispatch.fetch(url).

    `data` is the best ProgramData found.
    `verdict` is the validator verdict against `data`.
    `handlers_tried` is a chronological log of handler name → confidence.
    `error` is set iff every handler raised (verdict == FAIL).
    """

    data: ProgramData
    verdict: str = HOLD
    confidence: float = 0.0
    missing_fields: list[str] = field(default_factory=list)
    handlers_tried: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "data": self.data.to_dict(),
            "verdict": self.verdict,
            "confidence": self.confidence,
            "missing_fields": self.missing_fields,
            "handlers_tried": self.handlers_tried,
            "error": self.error,
        }
