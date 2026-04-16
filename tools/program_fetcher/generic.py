"""Generic fallback fetcher via r.jina.ai.

This is the universal fallback — the CLAUDE.md rule says jina is the right
tool for ad-hoc fetches. The catch is jina is LOSSY: it drops collapsed
`<details>` sections, reorders lists, and summarizes tables. So we mark
confidence at 0.4 — it never auto-PASSes for verbatim sections on its own,
but it's enough to HOLD and give the operator raw markdown to review.

For PASS-level confidence a handler must be specific to the platform.
"""

from __future__ import annotations

import re

from .base import Asset, ProgramData, SeverityRow
from .transport import TransportError, http_get


def fetch(url: str) -> ProgramData:
    """Fetch `url` via https://r.jina.ai/<url> and do a best-effort parse.

    Returns a ProgramData with confidence=0.4 when the page is retrievable
    and contains at least some scope-like content. Returns confidence=0 on
    empty/error pages.
    """
    jina_url = f"https://r.jina.ai/{url}"
    try:
        status, body, _headers = http_get(
            jina_url,
            accept="text/markdown",
            timeout=30,
        )
    except TransportError as e:
        raise RuntimeError(f"generic jina fetch failed: {e}") from e

    if status != 200 or len(body.strip()) < 200:
        pd = ProgramData(
            platform="generic",
            program_url=url,
            raw_markdown=body or "",
            source=f"generic.jina status={status}",
            confidence=0.0,
        )
        return pd

    return fetch_from_text(body, url)


def fetch_from_text(text: str, source_url: str) -> ProgramData:
    """Parse a chunk of markdown/plain text into ProgramData.

    Exposed so tests (and the --fixture CLI mode) can run without network.
    """
    pd = ProgramData(
        platform="generic",
        program_url=source_url,
        raw_markdown=text,
        source="generic.jina_or_fixture",
        confidence=0.4,
    )

    # Best-effort title extraction.
    m = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    if m:
        pd.name = m.group(1).strip()

    # Scope sections — loose headings match.
    scope_in_body = _find_section(text, [
        "In Scope", "In-Scope", "Scope", "Targets",
        "Assets in Scope", "Scope & Rewards",
    ])
    scope_out_body = _find_section(text, [
        "Out of Scope", "Out-of-Scope", "Exclusions",
        "Not in Scope", "Excluded",
    ])
    rules_body = _find_section(text, [
        "Rules of Engagement", "Rules", "Submission Rules",
        "Disclosure Policy", "Program Rules", "Reporting Guidelines",
    ])
    severity_body = _find_section(text, [
        "Rewards", "Bounty", "Severity", "Payouts",
        "Reward Structure", "Bounties by Severity",
    ])
    known_body = _find_section(text, [
        "Known Issues", "Known Limitations", "Already Reported",
    ])

    for line in (scope_in_body or "").splitlines():
        stripped = _strip_bullet(line)
        if stripped:
            pd.scope_in.append(Asset(type=_guess_asset_type(stripped), identifier=stripped))

    for line in (scope_out_body or "").splitlines():
        stripped = _strip_bullet(line)
        if stripped:
            pd.scope_out.append(stripped)

    for line in (known_body or "").splitlines():
        stripped = _strip_bullet(line)
        if stripped:
            pd.known_issues.append(stripped)

    if rules_body:
        pd.submission_rules = rules_body.strip()

    for line in (severity_body or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Heuristic: lines like "- Critical: $5,000"
        m_sev = re.match(
            r"[-*]?\s*(Critical|High|Medium|Low|Informational)\s*[:\-]\s*(.+)$",
            stripped,
            re.IGNORECASE,
        )
        if m_sev:
            pd.severity_table.append(
                SeverityRow(severity=m_sev.group(1), reward=m_sev.group(2).strip())
            )

    # Bounty range — look for "$X - $Y" near "bounty"/"reward" keyword.
    rng = re.search(
        r"(\$|€|£)\s*([\d,]+)\s*[-–—to]+\s*(\$|€|£)?\s*([\d,]+)",
        severity_body or text,
    )
    if rng:
        pd.bounty_range = {
            "min": f"{rng.group(1)}{rng.group(2)}",
            "max": f"{rng.group(3) or rng.group(1)}{rng.group(4)}",
            "currency": _currency_name(rng.group(1)),
        }

    if not pd.scope_in and not pd.scope_out and not pd.submission_rules:
        # Page was retrievable but we couldn't locate any structured content.
        pd.confidence = 0.1

    return pd


def _find_section(text: str, headings: list[str]) -> str:
    """Return the body under the first matching markdown heading.

    Body = everything until the next `#` heading or end of file.
    """
    for h in headings:
        # Match `##* <heading>` case-insensitively, allowing a trailing
        # qualifier like "(VERBATIM — ...)".
        pattern = re.compile(
            rf"^#{{1,4}}\s*{re.escape(h)}[^\n]*\n(.*?)(?=^#{{1,4}}\s|\Z)",
            re.MULTILINE | re.DOTALL | re.IGNORECASE,
        )
        m = pattern.search(text)
        if m:
            return m.group(1)
    return ""


def _strip_bullet(line: str) -> str:
    stripped = line.strip()
    # Require whitespace after bullet so "*.example.com" stays intact.
    stripped = re.sub(r"^[-+•]\s+", "", stripped)
    stripped = re.sub(r"^\*\s+", "", stripped)
    stripped = re.sub(r"^\d+[.)]\s+", "", stripped)
    return stripped


def _guess_asset_type(text: str) -> str:
    t = text.lower()
    if t.startswith("0x") and len(t) >= 42:
        return "smart_contract"
    if "://" in t or t.startswith("www."):
        return "url"
    if "*." in t or t.startswith("*"):
        return "wildcard"
    if "github.com" in t:
        return "repo"
    if ".apk" in t or "play.google" in t or "ios" in t:
        return "mobile_app"
    if "api" in t.split():
        return "api"
    return "other"


def _currency_name(symbol: str) -> str:
    return {"$": "USD", "€": "EUR", "£": "GBP"}.get(symbol, "")
