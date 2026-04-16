"""tools.program_fetcher — deterministic per-platform program intake.

Replaces ad-hoc `WebFetch(r.jina.ai/...)` summarization with
platform-specific handlers that extract verbatim scope, OOS, severity,
submission rules from HackerOne / Bugcrowd / Immunefi / Intigriti / YWH /
HackenProof / Huntr / GitHub audit contests.

Usage:
    from tools.program_fetcher import fetch
    result = fetch("https://immunefi.com/bug-bounty/lido/")
    if result.verdict == "PASS":
        ...

CLI:
    python3 -m tools.program_fetcher <url> --out <dir>
"""

from .base import (
    ProgramData,
    FetchResult,
    Asset,
    SeverityRow,
    PASS,
    HOLD,
    FAIL,
    PASS_THRESHOLD,
    HOLD_THRESHOLD,
)
from .dispatch import fetch, detect_platform

__all__ = [
    "fetch",
    "detect_platform",
    "ProgramData",
    "FetchResult",
    "Asset",
    "SeverityRow",
    "PASS",
    "HOLD",
    "FAIL",
    "PASS_THRESHOLD",
    "HOLD_THRESHOLD",
]
