"""Bugcrowd program fetcher.

**v12.4 — changelog endpoint discovery (verified 2026-04-10):**
Bugcrowd brief data lives at `/engagements/<slug>/changelog/<uuid>.json`.
This is the exact endpoint the Bugcrowd UI uses to render the program page.
It's accessible without authentication for public engagements.

Extraction flow:
  1. GET `/engagements/<slug>/changelog.json` → list of changelog entries.
     Each entry has `{id, publishedAt, ...}`. The latest entry is the
     current published brief.
  2. GET `/engagements/<slug>/changelog/<latest-id>.json` → 20-35KB JSON
     with `data.scope[]` (target groups + reward ranges), `data.brief.targetsOverview`
     (verbatim HTML), `data.vrtScopeRules`, `industryName`, `rewardAllocation`,
     `coordinatedDisclosure`, and more.

URL shapes accepted:
    https://bugcrowd.com/<handle>
    https://bugcrowd.com/engagements/<handle>
"""

from __future__ import annotations

import html as html_lib
import json
import re
from urllib.parse import urlparse

from .base import Asset, ProgramData, SeverityRow
from .transport import TransportError, http_get

SPA_HOLD_MESSAGE = (
    "Bugcrowd brief unavailable via the changelog endpoint. Use the Playwright "
    "MCP fallback (Phase 0.1 manual path) or paste the verbatim scope/OOS/"
    "rewards sections by hand from the live engagement page."
)

# Bugcrowd's VRT "default out of scope" classes — applied to every program
# unless the brief has a dedicated Out of Scope section. Surfaced as
# scope_out fallback so validator doesn't HOLD on programs that rely on the
# VRT defaults instead of listing OOS in the brief (OpenAI Safety style).
# Source: https://bugcrowd.com/vulnerability-rating-taxonomy (public).
VRT_DEFAULT_OOS = [
    "Descriptive error messages / full stack traces",
    "Missing HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) on non-sensitive pages",
    "Clickjacking / UI redressing on pages without sensitive actions",
    "Self-XSS without a clear vector to exploit another user",
    "Content spoofing / text injection without HTML / JS execution",
    "Missing cookie flags (HttpOnly, Secure) on non-sensitive cookies",
    "Automated scanner output without manual validation",
    "CSRF on logout, login, or other non-sensitive forms",
    "Open redirects without a clear attack scenario",
    "Social engineering / phishing against employees",
    "Denial of Service (DoS/DDoS) attacks",
    "Physical attacks against offices or employees",
    "Attacks requiring MITM / physical device access",
    "Issues in third-party services or components out of the program's control",
    "Best-practice critiques without a demonstrable security impact",
]


def fetch(url: str) -> ProgramData:
    handle = _extract_handle(url)
    if not handle:
        raise RuntimeError(f"bugcrowd: cannot extract handle from {url}")

    pd = ProgramData(
        platform="bugcrowd",
        handle=handle,
        program_url=f"https://bugcrowd.com/engagements/{handle}",
        policy_url=f"https://bugcrowd.com/engagements/{handle}",
        source="bugcrowd.changelog_api",
        confidence=0.0,
    )

    # 1) Changelog list → find latest changelog UUID
    latest_id = _fetch_latest_changelog_id(handle)
    if latest_id:
        brief = _fetch_changelog_detail(handle, latest_id)
        if brief:
            _populate_from_changelog(pd, brief)
            if pd.scope_in or pd.scope_out:
                _score_confidence(pd)
                return pd

    # 2) engagements.json listing fallback → at least get name + tagline
    try:
        status, body, _ = http_get(
            "https://bugcrowd.com/engagements.json?category=bug_bounty&sort_by=promoted&sort_direction=desc",
            accept="application/json",
            timeout=20,
        )
        if status == 200 and body.strip().startswith("{"):
            listing = json.loads(body)
            for eng in listing.get("engagements") or []:
                if not isinstance(eng, dict):
                    continue
                brief_url = eng.get("briefUrl") or ""
                if brief_url.endswith(f"/{handle}") or eng.get("slug") == handle:
                    if not pd.name:
                        pd.name = eng.get("name") or ""
                    tagline = eng.get("tagline") or ""
                    if tagline and not pd.submission_rules:
                        pd.submission_rules = tagline
                    pd.last_modified = str(
                        eng.get("lastCrowdActivity") or eng.get("updatedAt") or ""
                    )
                    break
    except (TransportError, json.JSONDecodeError):
        pass

    if not pd.scope_in and not pd.scope_out:
        pd.warnings.append(SPA_HOLD_MESSAGE)

    _score_confidence(pd)
    return pd


def parse_html(html_text: str, program_url: str) -> ProgramData:
    """Legacy fixture-compatible path — parses the react-props blob HTML."""
    handle = _extract_handle(program_url)
    pd = ProgramData(
        platform="bugcrowd",
        handle=handle,
        program_url=f"https://bugcrowd.com/{handle}",
        policy_url=program_url,
        source="bugcrowd.page_html",
        confidence=0.0,
    )
    _populate_from_react_props(pd, html_text)
    pd.raw_markdown = _visible_text(html_text)[:50000]
    _score_confidence(pd)
    return pd


def parse_changelog(brief: dict, handle: str) -> ProgramData:
    """Fixture-friendly: parse a saved changelog detail JSON."""
    pd = ProgramData(
        platform="bugcrowd",
        handle=handle,
        program_url=f"https://bugcrowd.com/engagements/{handle}",
        policy_url=f"https://bugcrowd.com/engagements/{handle}",
        source="bugcrowd.changelog_api",
        confidence=0.0,
    )
    _populate_from_changelog(pd, brief)
    _score_confidence(pd)
    return pd


def _extract_handle(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    if not path:
        return ""
    # /engagements/<slug> or /<slug>
    m = re.match(r"(?:engagements/)?([^/]+)", path)
    return m.group(1) if m else ""


def _fetch_latest_changelog_id(handle: str) -> str:
    """Return the UUID of the latest published changelog for a handle."""
    try:
        status, body, _ = http_get(
            f"https://bugcrowd.com/engagements/{handle}/changelog.json",
            accept="application/json",
            timeout=20,
        )
        if status != 200 or not body.strip().startswith("{"):
            return ""
        data = json.loads(body)
        changelogs = data.get("changelogs") or data.get("items") or []
        if changelogs and isinstance(changelogs[0], dict):
            return str(changelogs[0].get("id") or "")
    except (TransportError, json.JSONDecodeError):
        pass
    return ""


def _fetch_changelog_detail(handle: str, changelog_id: str) -> dict | None:
    try:
        status, body, _ = http_get(
            f"https://bugcrowd.com/engagements/{handle}/changelog/{changelog_id}.json",
            accept="application/json",
            timeout=25,
        )
        if status == 200 and body.strip().startswith("{"):
            return json.loads(body)
    except (TransportError, json.JSONDecodeError):
        pass
    return None


def _populate_from_changelog(pd: ProgramData, changelog: dict) -> None:
    """Map Bugcrowd's changelog detail JSON to ProgramData.

    Structure (verified 2026-04-10):
      {
        "id": "<uuid>",
        "engagementId": "<uuid>",
        "industryName": "Consumer Tech",
        "methodologyName": "Web App",
        "rewardAllocation": "pay_for_success",
        "coordinatedDisclosure": true,
        "knownIssuesEnabled": true,
        "data": {
          "brief": {
            "targetsOverview": "<html>",
            "description": "<html>",
            "programRules": "<html>"
          },
          "scope": [
            {
              "id": "<uuid>",
              "name": "<group name>",
              "targets": [
                {"name", "uri", "category", "description", "ipAddress"}
              ],
              "rewardRange": {
                "p1MinCents", "p1MaxCents",
                "p2MinCents", "p2MaxCents",
                ... "p5..."
              },
              "rewardRangeData": {"1": {"min", "max"}, ...}
            }
          ],
          "vrtScopeRules": [...]
        }
      }
    """
    data = changelog.get("data") or {}
    brief = data.get("brief") or {}
    scope_groups = data.get("scope") or []
    engagement = data.get("engagement") or {}

    # Name can be at changelog.engagementName, data.engagement.name,
    # data.brief.name, or brief-level slug.
    pd.name = (
        changelog.get("engagementName")
        or engagement.get("name")
        or brief.get("name")
        or data.get("name")
        or changelog.get("name")
        or pd.handle
    )
    pd.last_modified = str(
        changelog.get("lastTransitionAt")
        or changelog.get("publishedAt")
        or ""
    )

    # --- Scope: iterate target groups, respecting per-group `inScope` flag.
    # CRITICAL (v12.4 fix): Bugcrowd ships in-scope AND out-of-scope groups in
    # the same `data.scope[]` array, distinguished only by `group.inScope: bool`.
    # Earlier versions of this handler put OOS targets into scope_in, which is
    # a severe data integrity bug (operators would attack OOS assets).
    pd.scope_in = []
    all_reward_rows: list[SeverityRow] = []
    min_amount = None
    max_amount = None
    oos_from_groups: list[str] = []
    seen_reward_tiers: set[str] = set()

    for group in scope_groups:
        if not isinstance(group, dict):
            continue
        group_name = group.get("name") or ""
        # Trust the explicit inScope flag. Fall back to name heuristic only if
        # the flag is missing (older Bugcrowd API responses).
        flag = group.get("inScope")
        if flag is None:
            group_is_in_scope = "out" not in group_name.lower()
        else:
            group_is_in_scope = bool(flag)

        for t in group.get("targets") or []:
            if not isinstance(t, dict):
                continue
            identifier = t.get("name") or t.get("uri") or ""
            if not identifier:
                continue
            category = (t.get("category") or "").lower()
            description = t.get("description") or ""
            qualifier_parts = [group_name] if group_name else []
            if description:
                qualifier_parts.append(description)
            uri_extra = t.get("uri")
            if uri_extra and uri_extra != identifier:
                qualifier_parts.append(f"uri={uri_extra}")
            ip = t.get("ipAddress")
            if ip:
                qualifier_parts.append(f"ip={ip}")
            qualifier = " | ".join(p for p in qualifier_parts if p)

            if group_is_in_scope:
                pd.scope_in.append(
                    Asset(
                        type=_map_category(category),
                        identifier=identifier,
                        qualifier=qualifier,
                    )
                )
            else:
                # Out-of-scope assets go into scope_out with a clear label.
                oos_label = f"{identifier}"
                if category:
                    oos_label += f" ({category})"
                if description:
                    oos_label += f" — {description}"
                oos_from_groups.append(oos_label)

        # Reward range per group — only from IN-SCOPE groups. Dedupe by tier.
        if group_is_in_scope:
            rr = group.get("rewardRange") or {}
            if isinstance(rr, dict):
                tier_key = f"{rr.get('p1MaxCents')}_{rr.get('p2MaxCents')}_{rr.get('p3MaxCents')}"
                if tier_key in seen_reward_tiers:
                    continue
                seen_reward_tiers.add(tier_key)
                for pri in ("1", "2", "3", "4", "5"):
                    pmin = rr.get(f"p{pri}MinCents")
                    pmax = rr.get(f"p{pri}MaxCents")
                    if pmin is None and pmax is None:
                        continue
                    if isinstance(pmin, (int, float)) and pmin:
                        min_amount = pmin if min_amount is None else min(min_amount, pmin)
                    if isinstance(pmax, (int, float)) and pmax:
                        max_amount = pmax if max_amount is None else max(max_amount, pmax)
                    reward_str = ""
                    if pmin is not None and pmax is not None:
                        reward_str = f"${int(pmin/100):,} – ${int(pmax/100):,}"
                    all_reward_rows.append(
                        SeverityRow(
                            severity=f"P{pri}",
                            reward=reward_str,
                            asset_class=group_name,
                        )
                    )
    pd.severity_table = all_reward_rows
    if min_amount is not None or max_amount is not None:
        pd.bounty_range = {
            "min": f"${int(min_amount/100):,}" if min_amount else "",
            "max": f"${int(max_amount/100):,}" if max_amount else "",
            "currency": "USD",
        }

    # --- Brief sections → submission_rules + scope_out
    rules_parts: list[str] = []
    description_html = brief.get("description") or ""
    if description_html and isinstance(description_html, str):
        rules_parts.append("## Description\n" + _html_to_text(description_html))

    targets_overview_html = brief.get("targetsOverview") or ""
    if targets_overview_html and isinstance(targets_overview_html, str):
        rules_parts.append("## Targets Overview\n" + _html_to_text(targets_overview_html))

    program_rules_html = brief.get("programRules") or ""
    if program_rules_html and isinstance(program_rules_html, str):
        rules_parts.append("## Program Rules\n" + _html_to_text(program_rules_html))

    # Out-of-scope lives in several brief sections on Bugcrowd — the standard
    # places are `brief.targetsOverview` (most common), `brief.description`
    # (legacy) and `brief.additionalInformation`. Each is HTML. Extract any
    # `<h[1-4]>` section whose heading matches "Out of Scope" / "Exclusions".
    oos_text_candidates: list[str] = []
    for k in ("outOfScope", "exclusions", "notInScope"):
        v = brief.get(k)
        if isinstance(v, str) and v.strip():
            oos_text_candidates.append(v)

    for html_field in ("targetsOverview", "description", "additionalInformation"):
        html_body = brief.get(html_field) or ""
        if not isinstance(html_body, str) or not html_body:
            continue
        # Match heading + content up to next same-or-higher heading.
        for m in re.finditer(
            r"(?is)<h[1-4][^>]*>\s*(?:the\s+following\s+findings\s+are\s+out\s+of\s+scope|out\s*of\s*scope|out-of-scope|exclusions?|ineligible|not\s+in\s+scope|findings\s+out\s+of\s+scope)[^<]*</h[1-4]>(.*?)(?=<h[1-4]|$)",
            html_body,
        ):
            oos_text_candidates.append(m.group(1))

    pd.scope_out = []
    # 1) Targets from scope groups explicitly marked `inScope: false`
    pd.scope_out.extend(oos_from_groups)
    # 2) Additional OOS from brief.targetsOverview / description HTML sections
    for raw in oos_text_candidates:
        text = _html_to_text(raw)
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            line = re.sub(r"^[-*+•]\s+", "", line)
            line = re.sub(r"^\d+[.)]\s+", "", line)
            if line:
                pd.scope_out.append(line)

    # Fallback: if brief has no dedicated OOS heading AND no OOS scope groups,
    # seed scope_out with Bugcrowd's VRT default out-of-scope classes.
    if not pd.scope_out:
        pd.scope_out = list(VRT_DEFAULT_OOS)
        pd.warnings.append(
            "scope_out synthesized from Bugcrowd VRT defaults — brief had no "
            "dedicated Out of Scope section. Verify against live engagement page."
        )

    # VRT scope rules — out-of-scope vulnerability classes
    vrt_rules = data.get("vrtScopeRules") or []
    for rule in vrt_rules:
        if isinstance(rule, dict):
            name = rule.get("name") or rule.get("category") or ""
            note = rule.get("note") or ""
            if name:
                entry = f"{name}"
                if note:
                    entry += f" — {note}"
                pd.scope_out.append(entry)

    # Program metadata → rules
    meta = []
    for k, label in [
        ("industryName", "Industry"),
        ("methodologyName", "Methodology"),
        ("rewardAllocation", "Reward allocation"),
        ("participation", "Participation"),
    ]:
        v = changelog.get(k)
        if v:
            meta.append(f"- {label}: {v}")
    if meta:
        rules_parts.append("## Program Metadata\n" + "\n".join(meta))
    if changelog.get("coordinatedDisclosure"):
        rules_parts.append("- Coordinated disclosure enabled")

    pd.submission_rules = "\n\n".join(p for p in rules_parts if p)

    # --- Raw markdown
    raw_parts: list[str] = []
    if pd.name:
        raw_parts.append(f"# {pd.name}")
    for part in rules_parts:
        raw_parts.append(part)
    pd.raw_markdown = "\n\n".join(raw_parts)[:50000]


def _populate_from_react_props(pd: ProgramData, page_html: str) -> None:
    """Legacy react-props parser — kept for fixture tests."""
    REACT_RE = re.compile(
        r'data-react-class="([^"]+)"\s+data-react-props="([^"]+)"'
    )
    found_any = False
    for cls, props in REACT_RE.findall(page_html):
        props_decoded = html_lib.unescape(props)
        try:
            obj = json.loads(props_decoded)
        except json.JSONDecodeError:
            continue
        found_any = True
        _walk_props(pd, cls, obj)
    if not pd.name:
        tm = re.search(r"<title>([^<]+)</title>", page_html, re.IGNORECASE)
        if tm:
            pd.name = re.sub(r"\s*\|.*$", "", tm.group(1)).strip()


def _walk_props(pd: ProgramData, cls: str, obj) -> None:
    if isinstance(obj, dict):
        for key in ("program_name", "name", "title"):
            v = obj.get(key)
            if isinstance(v, str) and not pd.name:
                pd.name = v
        for key in ("in_scope", "targets", "target_groups"):
            v = obj.get(key)
            if isinstance(v, list):
                for t in v:
                    if isinstance(t, dict):
                        ident = t.get("uri") or t.get("name") or ""
                        if ident:
                            pd.scope_in.append(
                                Asset(
                                    type=_map_category(t.get("category", "")),
                                    identifier=ident,
                                    qualifier=t.get("description", "") or "",
                                )
                            )
        for key in ("out_of_scope",):
            v = obj.get(key)
            if isinstance(v, list):
                for t in v:
                    if isinstance(t, dict):
                        ident = t.get("uri") or t.get("name") or ""
                        if ident:
                            pd.scope_out.append(ident)
                    elif isinstance(t, str):
                        pd.scope_out.append(t)
        for key in ("known_issues",):
            v = obj.get(key)
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        pd.known_issues.append(item)
                    elif isinstance(item, dict):
                        pd.known_issues.append(item.get("title") or item.get("description", ""))
        for key in ("brief", "description", "rules_of_engagement", "policy", "program_rules"):
            v = obj.get(key)
            if isinstance(v, str) and len(v) > len(pd.submission_rules):
                pd.submission_rules = v.strip()
        for key in ("rewards", "bounty_table", "severity_table", "vrt"):
            v = obj.get(key)
            if isinstance(v, list):
                for row in v:
                    if isinstance(row, dict):
                        pd.severity_table.append(
                            SeverityRow(
                                severity=str(row.get("severity", "") or row.get("priority", "")),
                                reward=str(row.get("amount", "") or row.get("reward", "")),
                                asset_class=str(row.get("target_category", "") or ""),
                                notes=str(row.get("note", "") or ""),
                            )
                        )
        for v in obj.values():
            if isinstance(v, (dict, list)):
                _walk_props(pd, cls, v)
    elif isinstance(obj, list):
        for item in obj:
            _walk_props(pd, cls, item)


def _html_to_text(h: str) -> str:
    if not h:
        return ""
    t = re.sub(r"<script.*?</script>", "", h, flags=re.DOTALL | re.IGNORECASE)
    t = re.sub(r"<style.*?</style>", "", t, flags=re.DOTALL | re.IGNORECASE)
    # Convert block tags to newlines, inline tags to nothing
    t = re.sub(r"</(p|div|li|h[1-6]|br|tr)[^>]*>", "\n", t, flags=re.IGNORECASE)
    t = re.sub(r"<(br|hr)[^>]*/?>", "\n", t, flags=re.IGNORECASE)
    t = re.sub(r"<li[^>]*>", "- ", t, flags=re.IGNORECASE)
    t = re.sub(r"<[^>]+>", "", t)
    t = html_lib.unescape(t)
    t = re.sub(r"\n\s*\n", "\n\n", t)
    return t.strip()


def _visible_text(html_text: str) -> str:
    t = re.sub(r"<script.*?</script>", "", html_text, flags=re.DOTALL | re.IGNORECASE)
    t = re.sub(r"<style.*?</style>", "", t, flags=re.DOTALL | re.IGNORECASE)
    t = re.sub(r"<[^>]+>", "\n", t)
    t = re.sub(r"\n\s*\n", "\n", t)
    return t.strip()


def _map_category(category: str) -> str:
    c = (category or "").lower()
    if "web" in c or "api" in c:
        return "url"
    if "mobile" in c or "android" in c or "ios" in c:
        return "mobile_app"
    if "hardware" in c:
        return "hardware"
    if "source" in c or "code" in c:
        return "repo"
    if "iot" in c:
        return "hardware"
    return "other"


def _score_confidence(pd: ProgramData) -> None:
    if pd.source == "bugcrowd.changelog_api" and pd.scope_in and pd.severity_table and pd.submission_rules:
        pd.confidence = 0.95
    elif pd.source == "bugcrowd.changelog_api" and pd.scope_in and pd.severity_table:
        pd.confidence = 0.9
    elif pd.source == "bugcrowd.changelog_api" and pd.scope_in:
        pd.confidence = 0.75
    elif pd.scope_in and pd.scope_out and pd.submission_rules:
        pd.confidence = 0.8
    elif pd.scope_in and pd.scope_out:
        pd.confidence = 0.7
    elif pd.scope_in:
        pd.confidence = 0.5
    else:
        # Listing-only or empty — force HOLD (not FAIL) so the fallback
        # warning surfaces.
        pd.confidence = 0.5
