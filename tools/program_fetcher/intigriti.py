"""Intigriti program fetcher.

Strategy (verified live 2026-04-10):
  1. GET https://app.intigriti.com/api/core/public/programs/<company>/<program>
     — the REAL public API. Returns 200KB+ JSON with inScopes, outOfScopes,
     bountyTables, severityAssessments, rulesOfEngagements, assetsCollection.
     No auth required for listed programs.
  2. Fall back to parsing the `<script type="application/json">` Angular
     TransferState blob embedded in the program page HTML. The blob is a
     dict keyed by numeric hashes where each entry has `{b, h, s, st, u}`
     — `u` is the API URL that was SSR'd and `b` is the body. We look for
     the entry whose URL ends with `/api/core/public/programs/.../`.

URL shapes:
    https://app.intigriti.com/programs/<company>/<program>
    https://www.intigriti.com/programs/<company>/<program>
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from .base import Asset, ProgramData, SeverityRow
from .transport import TransportError, http_get


def fetch(url: str) -> ProgramData:
    company, program = _extract_handles(url)
    if not company or not program:
        raise RuntimeError(f"intigriti: cannot extract /programs/<co>/<prog> from {url}")

    pd = ProgramData(
        platform="intigriti",
        handle=f"{company}/{program}",
        program_url=f"https://app.intigriti.com/programs/{company}/{program}",
        policy_url=f"https://app.intigriti.com/programs/{company}/{program}",
        source="intigriti",
        confidence=0.0,
    )

    # 1) Public API — verified working without auth for listed programs.
    # NOTE: Some programs (Ubisoft, SolarWinds, Colruyt etc.) are listed in
    # the public listing but their per-program detail API returns 403 because
    # the program is invitation-only. We treat that as HOLD with a clear
    # warning, NOT as FAIL — the handler is working correctly, the program
    # just isn't accessible without auth.
    api_url = f"https://app.intigriti.com/api/core/public/programs/{company}/{program}"
    try:
        status, body, _ = http_get(api_url, accept="application/json", timeout=25)
        if status == 200 and body.strip().startswith("{"):
            data = json.loads(body)
            _populate_from_api(pd, data)
            pd.source = "intigriti.public_api"
    except TransportError as e:
        # 403 = invitation-only program
        if "403" in str(e):
            pd.warnings.append(
                "intigriti: program is invitation-only (detail API returned 403). "
                "Listing shows the program exists but its scope is not publicly readable. "
                "This is HOLD, not FAIL — the handler is working correctly."
            )
            pd.confidence = 0.5  # force HOLD
        else:
            pd.warnings.append(f"intigriti.api: {type(e).__name__}: {e}")
    except json.JSONDecodeError as e:
        pd.warnings.append(f"intigriti.api JSON error: {e}")

    # 2) TransferState HTML fallback (also works because the API blob is
    #    SSR'd into the page as <script type="application/json">).
    if not pd.scope_in:
        try:
            status, html, _ = http_get(pd.program_url, timeout=25)
            if status == 200:
                _populate_from_transfer_state(pd, html, company, program)
                if pd.scope_in:
                    pd.source = "intigriti.transfer_state"
        except TransportError as e:
            pd.warnings.append(f"intigriti.html: {type(e).__name__}: {e}")

    _score_confidence(pd)
    return pd


def parse_api(data: dict, program_url: str) -> ProgramData:
    """Parse a saved Intigriti public API response (fixture-friendly)."""
    company, program = _extract_handles(program_url)
    pd = ProgramData(
        platform="intigriti",
        handle=f"{company}/{program}",
        program_url=program_url,
        policy_url=program_url,
        source="intigriti.public_api",
        confidence=0.0,
    )
    _populate_from_api(pd, data)
    _score_confidence(pd)
    return pd


# Kept for backwards compatibility with the existing test suite.
def parse_json(data: dict, program_url: str) -> ProgramData:
    return parse_api(data, program_url)


def parse_html(html: str, program_url: str) -> ProgramData:
    company, program = _extract_handles(program_url)
    pd = ProgramData(
        platform="intigriti",
        handle=f"{company}/{program}",
        program_url=program_url,
        policy_url=program_url,
        source="intigriti.transfer_state",
        confidence=0.0,
    )
    _populate_from_transfer_state(pd, html, company, program)
    _score_confidence(pd)
    return pd


def _extract_handles(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    m = re.match(r"/programs/([^/?#]+)(?:/([^/?#]+))?", parsed.path)
    if not m:
        return "", ""
    company = m.group(1) or ""
    program = m.group(2) or company  # some programs use just /programs/<slug>
    return company, program


def _populate_from_api(pd: ProgramData, data: dict) -> None:
    """Map the Intigriti public API response to ProgramData.

    Real response shape (verified 2026-04-10):
    {
      "handle": "intigriti",
      "name": "intigriti",
      "companyHandle": "intigriti",
      "programId": "<uuid>",
      "inScopes": [{"content": {"content": "md", "attachments": []}, ...}, ...],
      "outOfScopes": [{"content": {"content": "md"}}, ...],
      "severityAssessments": [{"content": {"content": "md"}}, ...],
      "rulesOfEngagements": [{"content": {"content": {"description": "md"}}}, ...],
      "bountyTables": [{"content": {"currency": "EUR", "bountyRows": [...]}, ...}, ...],
      "assetsCollection": [{"content": {"assetsAndGroups": [...]}, ...}],
      "description": "...",
      "faqs": [...],
      ...
    }
    """
    if not isinstance(data, dict):
        return

    pd.name = data.get("name") or data.get("companyName") or pd.handle
    # lastActivity is a LIST of event dicts. Pull the latest timestamp instead
    # of str()-casting the whole list (which dumped raw dict content into the
    # last_modified field).
    pd.last_modified = _extract_last_activity_timestamp(data)
    # Intigriti uses ISO CVSS always v3.x
    pd.cvss_version = str(data.get("cvssVersion") or "3.1")

    # ---- inScopes (verbatim markdown) + assetsCollection (structured assets)
    in_scope_md_parts: list[str] = []
    for entry in data.get("inScopes") or []:
        md = _dig_content_md(entry)
        if md:
            in_scope_md_parts.append(md)

    # Structured assets from assetsCollection. Intigriti keeps multiple
    # revisions of the same asset group in the collection — only the first
    # (most recent) entry is the current program; later ones are history.
    # Take just assetsCollection[0] to avoid 47x duplication.
    ac_list = data.get("assetsCollection") or []
    if ac_list:
        content = ac_list[0].get("content") if isinstance(ac_list[0], dict) else None
        if isinstance(content, dict):
            # Dedupe per-asset by id so the same asset can't appear twice.
            seen_ids: set[str] = set()
            for ag in content.get("assetsAndGroups") or []:
                if not isinstance(ag, dict):
                    continue
                asset_id = str(ag.get("id") or ag.get("companyAssetId") or "")
                if asset_id and asset_id in seen_ids:
                    continue
                if asset_id:
                    seen_ids.add(asset_id)
                name = str(ag.get("name") or "").strip()
                description = str(ag.get("description") or "").strip()
                type_id = ag.get("typeId")
                bounty_tier = str(ag.get("bountyTierId") or "")

                # Extract the best identifier. Intigriti sometimes stores
                # a numeric app ID in `name` with the real URL in
                # `description`. Prefer a URL from description if name is
                # purely numeric. If description is null and name is numeric,
                # synthesize an Apple App Store URL (typeId=3 = iOS) or
                # Play Store URL (typeId=2 = Android).
                ident = name
                if ident.isdigit() or not ident:
                    url_m = re.search(r"https?://[^\s)]+", description) if description else None
                    if url_m:
                        ident = url_m.group(0).rstrip(".,;")
                    elif name.isdigit() and type_id == 3:
                        # Apple App Store ID without description — synthesize URL
                        ident = f"https://apps.apple.com/app/id{name}"
                    elif type_id == 2 and "." in name:
                        # Android package without description — synthesize Play URL
                        ident = f"https://play.google.com/store/apps/details?id={name}"
                if not ident or ident.isdigit():
                    # Skip purely-numeric identifiers we couldn't promote
                    continue

                asset_type = _map_type_id(type_id) or _guess_type(ident)

                # Pull a clean qualifier: the first bold heading + first
                # paragraph, stripping the per-asset OOS block.
                qualifier = _extract_asset_qualifier(description, bounty_tier)

                pd.scope_in.append(
                    Asset(type=asset_type, identifier=ident, qualifier=qualifier)
                )

                # Merge per-asset Out-of-scope bullets into global scope_out.
                per_asset_oos = _extract_per_asset_oos(description)
                for item in per_asset_oos:
                    pd.scope_out.append(f"[{ident}] {item}")

    # If assetsCollection was empty, fall back to parsing the markdown bullets
    # from inScopes[].content.content.
    if not pd.scope_in and in_scope_md_parts:
        for md in in_scope_md_parts:
            for line in md.splitlines():
                line = line.strip()
                if not line:
                    continue
                line = re.sub(r"^[-+•]\s+", "", line)
                line = re.sub(r"^\*\s+", "", line)
                line = re.sub(r"^\d+[.)]\s+", "", line)
                line = line.replace("\\*", "*")
                if line:
                    pd.scope_in.append(Asset(identifier=line, type=_guess_type(line)))

    # ---- outOfScopes: Intigriti stores a revision history where the same
    # section has dozens of revisions with cumulative edits. Strategy:
    #   1. Group entries by their first `####` heading (section key)
    #   2. Keep only the entry with the highest `createdAt` per section key
    #   3. Parse each kept entry: extract ONLY bullet list items, drop prose,
    #      headings, and cross-section interstitial text
    raw_entries = [e for e in (data.get("outOfScopes") or []) if isinstance(e, dict)]
    latest_per_section: dict[str, tuple[int, str]] = {}
    for entry in raw_entries:
        md = _dig_content_md(entry)
        if not md:
            continue
        created_at = entry.get("createdAt") or 0
        try:
            created_at = int(created_at)
        except (TypeError, ValueError):
            created_at = 0
        # Use first `####` heading as section key; if none, use the first
        # 30 chars of content as a weak key.
        heading_m = re.search(r"^#{1,5}\s+(.+?)$", md, re.MULTILINE)
        key = heading_m.group(1).strip().lower() if heading_m else md[:30]
        prior = latest_per_section.get(key)
        if prior is None or created_at > prior[0]:
            latest_per_section[key] = (created_at, md)

    # Now parse each kept section: bullet-only extraction.
    oos_parts: list[str] = []
    for _ts, md in latest_per_section.values():
        oos_parts.append(md)
        for item in _extract_bullet_items(md):
            if item not in pd.scope_out:
                pd.scope_out.append(item)

    # ---- rulesOfEngagements (verbatim markdown)
    rules_parts: list[str] = []
    for entry in data.get("rulesOfEngagements") or []:
        content = entry.get("content") if isinstance(entry, dict) else None
        if isinstance(content, dict):
            inner = content.get("content")
            if isinstance(inner, dict):
                desc = inner.get("description") or inner.get("content") or ""
                if isinstance(desc, str) and desc.strip():
                    rules_parts.append(desc.strip())
            elif isinstance(inner, str) and inner.strip():
                rules_parts.append(inner.strip())
    if rules_parts:
        pd.submission_rules = "\n\n".join(rules_parts)

    # ---- severityAssessments (verbatim markdown — CVSS guidance)
    sev_parts: list[str] = []
    for entry in data.get("severityAssessments") or []:
        md = _dig_content_md(entry)
        if md:
            sev_parts.append(md)
    if sev_parts and not pd.submission_rules:
        pd.submission_rules = "\n\n".join(sev_parts)
    elif sev_parts:
        pd.submission_rules += "\n\n## Severity assessment\n" + "\n\n".join(sev_parts)

    # ---- bountyTables — structured reward data.
    # Shape: bountyTables[i].content.bountyRows[].bountyRanges[] where each
    # range has minScore/maxScore + minBounty/maxBounty.
    # Multiple bountyTables exist per bountyTierId; dedupe by tier.
    currencies: set[str] = set()
    min_amount, max_amount = None, None
    seen_tiers: set[int] = set()
    for bt in data.get("bountyTables") or []:
        content = bt.get("content") if isinstance(bt, dict) else None
        if not isinstance(content, dict):
            continue
        cur = content.get("currency") or "EUR"
        currencies.add(cur)
        rows = content.get("bountyRows") or []
        for row in rows:
            if not isinstance(row, dict):
                continue
            tier_id = row.get("bountyTierId")
            if tier_id is not None and tier_id in seen_tiers:
                continue
            if tier_id is not None:
                seen_tiers.add(tier_id)
            for br in row.get("bountyRanges") or []:
                if not isinstance(br, dict):
                    continue
                min_score = br.get("minScore")
                max_score = br.get("maxScore")
                if min_score is None or max_score is None:
                    tier_label = "CVSS (unspecified)"
                else:
                    tier_label = f"CVSS {min_score}-{max_score}"
                mn = br.get("minBounty") or {}
                mx = br.get("maxBounty") or {}
                mn_v = mn.get("value") if isinstance(mn, dict) else None
                mx_v = mx.get("value") if isinstance(mx, dict) else None
                if mn_v is not None:
                    min_amount = mn_v if min_amount is None else min(min_amount, mn_v)
                if mx_v is not None:
                    max_amount = mx_v if max_amount is None else max(max_amount, mx_v)
                if mn_v is not None and mx_v is not None and mn_v == mx_v:
                    reward = f"{mn_v:.0f} {cur}"
                elif mn_v is not None or mx_v is not None:
                    reward = f"{mn_v or '?'}–{mx_v or '?'} {cur}"
                else:
                    reward = ""
                pd.severity_table.append(
                    SeverityRow(
                        severity=tier_label,
                        reward=reward,
                        asset_class=f"bountyTier={tier_id}" if tier_id else "",
                    )
                )
    if min_amount is not None or max_amount is not None:
        pd.bounty_range = {
            "min": str(min_amount) if min_amount is not None else "",
            "max": str(max_amount) if max_amount is not None else "",
            "currency": next(iter(currencies)) if currencies else "EUR",
        }

    # ---- Raw markdown assembly: keep the verbatim blobs for audit trail.
    raw_parts: list[str] = []
    if pd.name:
        raw_parts.append(f"# {pd.name}")
    if in_scope_md_parts:
        raw_parts.append("## In Scope\n" + "\n\n".join(in_scope_md_parts))
    if oos_parts:
        raw_parts.append("## Out of Scope\n" + "\n\n".join(oos_parts))
    if rules_parts:
        raw_parts.append("## Rules of Engagement\n" + "\n\n".join(rules_parts))
    if sev_parts:
        raw_parts.append("## Severity Assessment\n" + "\n\n".join(sev_parts))
    pd.raw_markdown = "\n\n".join(raw_parts)[:50000]


def _dig_content_md(entry) -> str:
    """Dig through Intigriti's nested content shape to return the markdown.

    The common shape is: {"content": {"content": "md", "attachments": [...]}}
    — a double-wrapped content field. Some entries use
    {"content": {"content": {"description": "md"}}} instead.
    """
    if not isinstance(entry, dict):
        return ""
    c1 = entry.get("content")
    if isinstance(c1, dict):
        c2 = c1.get("content")
        if isinstance(c2, str):
            return c2.strip()
        if isinstance(c2, dict):
            for key in ("description", "content", "body", "text"):
                v = c2.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    elif isinstance(c1, str):
        return c1.strip()
    return ""


def _populate_from_transfer_state(pd: ProgramData, html: str, company: str, program: str) -> None:
    """Extract Intigriti's Angular TransferState blob from a page HTML.

    Shape: <script type="application/json">{ "<hash>": {b,h,s,st,u}, ... }</script>
    `u` is the API URL that was SSR'd, `b` is the response body.
    """
    m = re.search(
        r'<script[^>]*type="application/json"[^>]*>(.*?)</script>',
        html,
        re.DOTALL,
    )
    if not m:
        # Fallback: raw text only.
        pd.raw_markdown = re.sub(r"<[^>]+>", " ", html)[:50000]
        return
    try:
        blob = json.loads(m.group(1))
    except json.JSONDecodeError:
        return
    if not isinstance(blob, dict):
        return

    wanted_url_fragment = f"/api/core/public/programs/{company}/{program}"
    for key, entry in blob.items():
        if not isinstance(entry, dict):
            continue
        url = entry.get("u", "")
        body = entry.get("b", {})
        if not isinstance(body, dict):
            continue
        # Match the exact program body (not the /routing sibling).
        if url.endswith(wanted_url_fragment) or (
            wanted_url_fragment in url and "inScopes" in body
        ):
            _populate_from_api(pd, body)
            return

    # If we didn't find the exact endpoint, try any body that looks like the
    # program payload.
    for entry in blob.values():
        if not isinstance(entry, dict):
            continue
        body = entry.get("b", {})
        if isinstance(body, dict) and "inScopes" in body and "bountyTables" in body:
            _populate_from_api(pd, body)
            return


# Intigriti typeId → asset type (verified 2026-04-10 against live API responses).
# The raw values come from multiple programs compared side-by-side:
#   1 → URL (domain / web app)            e.g. "accountsettings.visma.com"
#   2 → Mobile app Android (package name) e.g. "com.visma.blue"
#   3 → Mobile app iOS (App Store ID)     e.g. "564141518"
#   7 → Wildcard domain                   e.g. "*.intigriti.com"
# 4, 5, 6 are unverified; default to "other" until confirmed from live data.
_INTIGRITI_TYPE_ID_MAP = {
    1: "url",
    2: "mobile_app",
    3: "mobile_app",
    4: "other",
    5: "other",
    6: "other",
    7: "wildcard",
}


def _map_type_id(type_id) -> str:
    if isinstance(type_id, int):
        return _INTIGRITI_TYPE_ID_MAP.get(type_id, "other")
    return ""


def _extract_asset_qualifier(description: str, tier: str) -> str:
    """From Intigriti's asset description, extract a short qualifier line.

    Description is multi-line markdown that often includes a bold heading,
    a paragraph, URLs, and a `**Out of scope:**` block. Return the heading
    + first non-empty line, stripped.
    """
    if not description:
        return f"tier={tier}" if tier else ""
    # Cut at the Out-of-scope marker
    oos_cut = re.search(r"(?i)\*\*out of scope[:\*]*", description)
    head = description[: oos_cut.start()] if oos_cut else description
    # Take the first bold heading + first content paragraph
    lines = [ln.strip() for ln in head.splitlines() if ln.strip()]
    picked = " / ".join(lines[:2])[:300]
    if tier:
        picked = f"{picked} | tier={tier}"
    return picked


def _extract_last_activity_timestamp(data: dict) -> str:
    """Return the most recent activity as an ISO-style string, else ''.

    Intigriti's lastActivity is a list of event dicts sorted newest-first.
    Each entry has a Unix timestamp under `timestamp`. We pick the max and
    format as YYYY-MM-DDThh:mm:ssZ.
    """
    import datetime as _dt

    # Prefer an explicit updated-at field if present.
    for key in ("lastUpdatedAt", "updatedAt", "lastActivityAt"):
        v = data.get(key)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, (int, float)) and v > 0:
            try:
                return _dt.datetime.utcfromtimestamp(int(v)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            except (ValueError, OSError):
                return str(v)

    # Fallback: walk lastActivity list and pick max timestamp.
    activity = data.get("lastActivity")
    if isinstance(activity, list):
        max_ts = 0
        for item in activity:
            if isinstance(item, dict):
                ts = item.get("timestamp") or 0
                try:
                    ts = int(ts)
                except (TypeError, ValueError):
                    ts = 0
                if ts > max_ts:
                    max_ts = ts
        if max_ts > 0:
            try:
                return _dt.datetime.utcfromtimestamp(max_ts).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            except (ValueError, OSError):
                return str(max_ts)
    return ""


def _extract_bullet_items(md: str) -> list[str]:
    """Extract verbatim bullet list items from a markdown section.

    Drops headings and prose paragraphs so the caller doesn't pick up
    rule-of-engagement sentences that happen to be inside an OOS markdown
    block. Only lines matching `- item`, `* item`, `+ item`, `• item`, or
    `1. item` are returned.
    """
    out: list[str] = []
    for raw in (md or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue  # heading
        # Match bullets. Intigriti uses `*` with tab indents for nested.
        m = re.match(r"^(?:[-+•]|\*)\s+(.+)$", line)
        if m:
            item = m.group(1).strip()
            item = item.replace("\\*", "*")
            if item:
                out.append(item)
            continue
        m = re.match(r"^\d+[.)]\s+(.+)$", line)
        if m:
            item = m.group(1).strip()
            if item:
                out.append(item)
    return out


def _extract_per_asset_oos(description: str) -> list[str]:
    """Pull bullet lines out of a `**Out of scope:**` block inside a
    Intigriti asset description."""
    if not description:
        return []
    m = re.search(
        r"(?is)\*\*out of scope[:\*]*\s*\n(.*?)(?=\n\n|\n\*\*|\Z)",
        description,
    )
    if not m:
        return []
    out: list[str] = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line:
            continue
        line = re.sub(r"^[-+•]\s+", "", line)
        line = re.sub(r"^\*\s+", "", line)
        if line:
            out.append(line)
    return out


def _map_type(atype: str) -> str:
    t = (atype or "").lower()
    if "web" in t or "url" in t:
        return "url"
    if "mobile" in t or "android" in t or "ios" in t:
        return "mobile_app"
    if "api" in t:
        return "api"
    if "wildcard" in t:
        return "wildcard"
    if "iot" in t or "hardware" in t:
        return "hardware"
    return "other"


def _guess_type(identifier: str) -> str:
    i = identifier.lower()
    if "*." in i or i.startswith("*"):
        return "wildcard"
    if "://" in i or i.startswith("www."):
        return "url"
    return "other"


def _score_confidence(pd: ProgramData) -> None:
    if pd.source == "intigriti.public_api" and pd.scope_in and pd.scope_out and pd.bounty_range:
        pd.confidence = 0.95
    elif pd.source == "intigriti.public_api" and pd.scope_in and pd.scope_out:
        pd.confidence = 0.9
    elif pd.source == "intigriti.public_api" and (pd.scope_in or pd.scope_out):
        pd.confidence = 0.8
    elif pd.source == "intigriti.transfer_state" and pd.scope_in and pd.scope_out:
        pd.confidence = 0.85
    elif pd.scope_in or pd.scope_out:
        pd.confidence = 0.5
    else:
        pd.confidence = 0.15
