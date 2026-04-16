"""YesWeHack program fetcher.

**v12.4 — public API confirmed (verified 2026-04-10):**
`https://api.yeswehack.com/programs/<slug>` returns the full program object
for any listed public program — no authentication needed. Response shape
includes:
  - scopes (structured list with scope, scope_type, asset_value)
  - out_of_scope (verbatim list of strings)
  - qualifying_vulnerability + non_qualifying_vulnerability (in/out severity list)
  - rules (verbatim markdown) + rules_html
  - reward_grid_default + reward_grid_{low,medium,high,critical} (tiered rewards)
  - bounty_reward_min / bounty_reward_max
  - stats, hall_of_fame, business_unit metadata

**URL shape**: Scout must pass a concrete program slug, not the listing:
    https://yeswehack.com/programs/<slug>
    # NOT /programs/yeswehack (that's the listing landing page)

The listing endpoint (used for verification / discovery) is:
    https://api.yeswehack.com/programs?filter[type][]=bug-bounty
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from .base import Asset, ProgramData, SeverityRow
from .transport import TransportError, http_get

SPA_HOLD_MESSAGE = (
    "YesWeHack program not found via public API. Either the slug is wrong "
    "(the URL /programs/yeswehack is the LISTING, not a program) or the "
    "program is private/invite-only. Use the Playwright MCP fallback "
    "(Phase 0.1 manual path) or supply a correct public program slug."
)


def fetch(url: str) -> ProgramData:
    slug = _extract_slug(url)
    if not slug:
        raise RuntimeError(f"yeswehack: cannot extract slug from {url}")

    pd = ProgramData(
        platform="yeswehack",
        handle=slug,
        program_url=f"https://yeswehack.com/programs/{slug}",
        policy_url=f"https://yeswehack.com/programs/{slug}",
        source="yeswehack.public_api",
        confidence=0.0,
    )

    # Public per-program API. Verified to return 35KB+ of structured data.
    api_url = f"https://api.yeswehack.com/programs/{slug}"
    try:
        status, body, _ = http_get(api_url, accept="application/json", timeout=25)
        if status == 200 and body.strip().startswith("{"):
            data = json.loads(body)
            _populate_from_api(pd, data)
    except TransportError as e:
        pd.warnings.append(f"yeswehack.api: {type(e).__name__}: {e}")
    except json.JSONDecodeError as e:
        pd.warnings.append(f"yeswehack.api JSON error: {e}")

    if not pd.scope_in:
        pd.warnings.append(SPA_HOLD_MESSAGE)

    _score_confidence(pd)
    return pd


def parse_json(data: dict, program_url: str) -> ProgramData:
    """Fixture-friendly parser."""
    slug = _extract_slug(program_url)
    pd = ProgramData(
        platform="yeswehack",
        handle=slug,
        program_url=program_url,
        policy_url=program_url,
        source="yeswehack.public_api",
        confidence=0.0,
    )
    _populate_from_api(pd, data)
    _score_confidence(pd)
    return pd


def _extract_slug(url: str) -> str:
    parsed = urlparse(url)
    m = re.search(r"/programs/([^/?#]+)", parsed.path)
    return m.group(1) if m else ""


def _populate_from_api(pd: ProgramData, data: dict) -> None:
    if not isinstance(data, dict):
        return

    pd.name = data.get("title") or data.get("name") or pd.handle
    pd.last_modified = str(data.get("updated_at") or "")

    # --- Scopes (structured)
    pd.scope_in = []
    for s in data.get("scopes") or []:
        if not isinstance(s, dict):
            continue
        ident = s.get("scope") or ""
        stype = s.get("scope_type") or ""
        stype_name = s.get("scope_type_name") or ""
        asset_value = s.get("asset_value") or ""
        if not ident:
            continue
        qualifier_parts = []
        if stype_name:
            qualifier_parts.append(stype_name)
        if asset_value:
            qualifier_parts.append(f"value={asset_value}")
        pd.scope_in.append(
            Asset(
                type=_map_type(stype),
                identifier=ident,
                qualifier=" | ".join(qualifier_parts),
            )
        )

    # --- Out-of-scope (verbatim list)
    pd.scope_out = []
    oos = data.get("out_of_scope") or data.get("outOfScope") or []
    if isinstance(oos, list):
        for item in oos:
            if isinstance(item, str) and item.strip():
                pd.scope_out.append(item.strip())
            elif isinstance(item, dict):
                txt = item.get("description") or item.get("scope") or ""
                if txt:
                    pd.scope_out.append(txt)

    # Non-qualifying vulnerabilities are also effective OOS classes.
    non_qual = data.get("non_qualifying_vulnerability") or []
    if isinstance(non_qual, list):
        for item in non_qual:
            if isinstance(item, str) and item.strip():
                pd.scope_out.append(item.strip())
            elif isinstance(item, dict):
                txt = item.get("description") or item.get("title") or ""
                if txt:
                    pd.scope_out.append(txt)

    # --- Known issues / disclosure rules
    pd.known_issues = []
    disc = data.get("disclosure_rules") or data.get("known_issues") or []
    if isinstance(disc, list):
        for item in disc:
            if isinstance(item, str):
                pd.known_issues.append(item)

    # Qualifying vulns — informational, but good to surface in rules.
    qual = data.get("qualifying_vulnerability") or []
    qual_strs: list[str] = []
    if isinstance(qual, list):
        for item in qual:
            if isinstance(item, str) and item.strip():
                qual_strs.append(item.strip())
            elif isinstance(item, dict):
                txt = item.get("description") or item.get("title") or ""
                if txt:
                    qual_strs.append(txt)

    # --- Rules (verbatim markdown)
    rules_md = data.get("rules") or ""
    if isinstance(rules_md, str) and rules_md.strip():
        pd.submission_rules = rules_md.strip()

    # Append qualifying vulns to rules if present and not already there.
    if qual_strs and "Qualifying" not in pd.submission_rules:
        pd.submission_rules += "\n\n## Qualifying Vulnerabilities\n" + "\n".join(
            f"- {q}" for q in qual_strs
        )

    # --- Severity / reward grid
    pd.severity_table = []
    min_amount = data.get("bounty_reward_min")
    max_amount = data.get("bounty_reward_max")
    for grid_name in (
        "reward_grid_default",
        "reward_grid_very_low",
        "reward_grid_low",
        "reward_grid_medium",
        "reward_grid_high",
        "reward_grid_critical",
    ):
        grid = data.get(grid_name)
        if not isinstance(grid, dict):
            continue
        tier = grid_name.replace("reward_grid_", "")
        for sev in ("bounty_low", "bounty_medium", "bounty_high", "bounty_critical"):
            amount = grid.get(sev)
            if amount is None:
                continue
            sev_label = sev.replace("bounty_", "").capitalize()
            pd.severity_table.append(
                SeverityRow(
                    severity=sev_label,
                    reward=f"€{amount}" if isinstance(amount, int) else str(amount),
                    asset_class=f"asset_value={tier}",
                )
            )

    if min_amount is not None or max_amount is not None:
        pd.bounty_range = {
            "min": str(min_amount) if min_amount is not None else "",
            "max": str(max_amount) if max_amount is not None else "",
            "currency": "EUR",
        }

    # --- Raw markdown
    raw_parts: list[str] = []
    if pd.name:
        raw_parts.append(f"# {pd.name}")
    if rules_md:
        raw_parts.append(rules_md)
    if pd.scope_out:
        raw_parts.append("## Out of Scope\n" + "\n".join(f"- {x}" for x in pd.scope_out))
    pd.raw_markdown = "\n\n".join(raw_parts)[:50000]


def _map_type(stype: str) -> str:
    s = (stype or "").lower()
    if "web" in s or "api" in s or "url" in s:
        return "url"
    if "mobile" in s or "android" in s or "ios" in s:
        return "mobile_app"
    if "executable" in s or "binary" in s:
        return "binary"
    if "wildcard" in s:
        return "wildcard"
    if "ip" in s:
        return "ip_address"
    return "other"


def _score_confidence(pd: ProgramData) -> None:
    has_scope = len(pd.scope_in) >= 1
    has_oos = len(pd.scope_out) >= 1
    has_rewards = len(pd.severity_table) >= 1 or bool(pd.bounty_range)
    has_rules = len(pd.submission_rules.strip()) >= 200

    if pd.source == "yeswehack.public_api" and has_scope and has_oos and has_rewards and has_rules:
        pd.confidence = 0.95
    elif pd.source == "yeswehack.public_api" and has_scope and has_rewards:
        pd.confidence = 0.9
    elif pd.source == "yeswehack.public_api" and has_scope:
        pd.confidence = 0.8
    elif has_scope and has_oos:
        pd.confidence = 0.6
    else:
        # Force HOLD so the warning surfaces.
        pd.confidence = 0.5
