"""Immunefi program fetcher.

**v12.4 — Flight format discovery (verified 2026-04-10):**
Immunefi moved to Next.js 13 App Router but EMBEDS the full program object
in `self.__next_f.push([1,"..."])` statements inside the static HTML. The
payload is a JS-string-escaped Flight serialization. Once decoded, we get
a 27KB `bounty` object with 60+ fields including every asset, reward tier,
prohibited activity, default/custom OOS, impacts list, KYC flags, and
safe-harbor status.

The extraction path is:
  1. Fetch the static HTML (no JS needed — verified).
  2. Find every `self.__next_f.push([N, "<string>"])` statement.
  3. Decode each string via json.loads('"<payload>"') — this handles the
     JavaScript-string escapes correctly.
  4. Concatenate into one Flight stream (~65KB).
  5. Locate `"bounty": {...}` and extract the balanced JSON object.
  6. Map Immunefi's field names to ProgramData.

Legacy __NEXT_DATA__ path is retained for test fixtures.

URL shape: https://immunefi.com/bug-bounty/<slug>/
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from .base import Asset, ProgramData, SeverityRow
from .transport import TransportError, http_get


_NEXT_DATA_RE = re.compile(
    r'<script\s+id="__NEXT_DATA__"\s+type="application/json"[^>]*>(.*?)</script>',
    re.DOTALL,
)
_FLIGHT_PUSH_RE = re.compile(
    r'self\.__next_f\.push\(\[\d+,\s*"((?:[^"\\]|\\.)*)"\]\)',
    re.DOTALL,
)


def fetch(url: str) -> ProgramData:
    """Fetch an Immunefi bug bounty page and extract ProgramData."""
    parsed = urlparse(url)
    slug = _extract_slug(parsed.path)
    if slug:
        canonical = f"https://immunefi.com/bug-bounty/{slug}/"
    else:
        canonical = url

    try:
        status, body, _headers = http_get(canonical, timeout=30)
    except TransportError as e:
        raise RuntimeError(f"immunefi fetch failed ({canonical}): {e}") from e

    return parse_html(body, canonical)


def parse_html(html: str, program_url: str) -> ProgramData:
    """Parse an Immunefi page HTML.

    Tries three extraction paths in order:
      1. Flight stream (`self.__next_f.push`) — the current production path.
      2. Legacy `__NEXT_DATA__` script — still used by fixtures.
      3. Shell-only fallback with HOLD + Playwright instruction.
    """
    pd = ProgramData(
        platform="immunefi",
        program_url=program_url,
        policy_url=program_url,
        raw_markdown=_extract_visible_text(html),
        source="immunefi.next_flight",
        confidence=0.0,
    )

    parsed = urlparse(program_url)
    pd.handle = _extract_slug(parsed.path) or ""

    # 1) Flight stream path (production).
    bounty = _extract_bounty_from_flight(html)
    if bounty:
        _populate_from_bounty(pd, bounty)
        if pd.scope_in:
            return pd

    # 2) Legacy __NEXT_DATA__ path (fixture support).
    m = _NEXT_DATA_RE.search(html)
    if m:
        try:
            data = json.loads(m.group(1))
            legacy_bounty = (
                data.get("props", {}).get("pageProps", {}).get("bounty")
                or data.get("props", {}).get("pageProps", {}).get("program")
            )
            if legacy_bounty:
                pd.source = "immunefi.__NEXT_DATA__"
                _populate_from_bounty(pd, legacy_bounty)
                if pd.scope_in:
                    return pd
        except json.JSONDecodeError:
            pass

    # 3) Shell fallback — title + meta description only.
    pd.source = "immunefi.static_shell"
    tm = re.search(r"<title>([^<]+)</title>", html, re.IGNORECASE)
    if tm:
        pd.name = re.sub(r"\s*\|.*$", "", tm.group(1)).strip()
    desc_m = re.search(
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)',
        html,
        re.IGNORECASE,
    )
    if desc_m and not pd.submission_rules:
        pd.submission_rules = desc_m.group(1).strip()
    pd.warnings.append(
        "Immunefi static shell only — Flight extraction failed. Use Playwright MCP fallback."
    )
    pd.confidence = 0.5
    return pd


def _extract_bounty_from_flight(html: str) -> dict | None:
    """Decode Flight pushes, find the `bounty` object, return the parsed dict.

    Returns None if no Flight data or no bounty object is present.

    Flight format notes:
      - Each push[1] is a JS-string-escaped chunk; `json.loads('"<chunk>"')`
        decodes it correctly.
      - The concatenated stream contains `<hex>:T<hex_length>,<text>` entries
        that define text references, and `<hex>:<value>` entries for other
        types. Fields in the bounty object can refer to these via `$<hex>`.
      - We build a reference lookup and substitute `$<hex>` values post-hoc.
    """
    pushes = _FLIGHT_PUSH_RE.findall(html)
    if not pushes:
        return None

    parts: list[str] = []
    for p in pushes:
        try:
            parts.append(json.loads('"' + p + '"'))
        except json.JSONDecodeError:
            parts.append(p)
    stream = "".join(parts)
    if not stream:
        return None

    # Build a Flight reference lookup table. Format:
    #   <hex>:T<hex_size>,<text>\n   (text reference)
    #   <hex>:<json_value>\n          (non-text reference)
    refs = _build_flight_refs(stream)

    # Locate the bounty object.
    m = re.search(r'"bounty"\s*:\s*\{', stream)
    if not m:
        return None
    obj_str = _extract_balanced_json(stream, m.end() - 1)
    if not obj_str:
        return None
    try:
        bounty = json.loads(obj_str)
    except json.JSONDecodeError:
        return None

    # Recursively dereference any "$<hex>" string values in the bounty dict.
    return _deref_flight(bounty, refs)


def _build_flight_refs(stream: str) -> dict[str, str]:
    """Parse `<hex>:T<hex_size>,<text>` and `<hex>:<value>` definitions.

    Returns a dict mapping hex refs to their resolved text content.
    """
    refs: dict[str, str] = {}

    # Text references: "<hex>:T<hex_size>,<text>" where text has a known length.
    for m in re.finditer(r"(?m)^([0-9a-f]+):T([0-9a-f]+),", stream):
        ref_id = m.group(1)
        size = int(m.group(2), 16)
        start = m.end()
        end = start + size
        if end > len(stream):
            continue
        refs[ref_id] = stream[start:end]

    # JSON-value references: "<hex>:<json>" — but only if not already set by
    # a text ref. These can be objects, arrays, or primitives.
    for m in re.finditer(r"(?m)^([0-9a-f]+):([^T\n].*)$", stream):
        ref_id = m.group(1)
        if ref_id in refs:
            continue
        value = m.group(2).strip()
        if value:
            refs[ref_id] = value

    return refs


def _deref_flight(obj, refs: dict[str, str], depth: int = 0):
    """Recursively replace `$<hex>` string refs with their resolved text.

    Handles three cases:
      1. Whole-string ref: `"$2f"` → full text of ref 2f.
      2. Embedded ref inside body text: `"see $2e for details"` → inlined.
      3. Nested refs where resolved text contains another ref — re-resolved
         up to 5 hops.
    """
    if depth > 5:
        return obj
    if isinstance(obj, str):
        return _deref_string(obj, refs, depth)
    if isinstance(obj, dict):
        return {k: _deref_flight(v, refs, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deref_flight(v, refs, depth + 1) for v in obj]
    return obj


def _deref_string(s: str, refs: dict[str, str], depth: int = 0) -> str:
    if not s or depth > 5:
        return s
    # Whole-string reference. If the ref is unresolved (Suspense boundary
    # content not in the static HTML), return an empty string so
    # downstream population skips the field entirely.
    m = re.fullmatch(r"\$([0-9a-f]+)", s)
    if m:
        key = m.group(1)
        if key in refs:
            return _deref_string(refs[key], refs, depth + 1)
        # Unresolved: deferred Suspense content. Drop it.
        return ""

    # Inline refs: `$<hex>` not adjacent to word/amount characters.
    # Only substitute when the hex key is actually in the ref table so
    # dollar amounts like "$500" stay intact (the key "500" won't be in
    # refs unless Flight really defined it). Unresolved inline refs are
    # replaced with an empty string to avoid leaking `$2e` into output.
    def _sub(match: re.Match) -> str:
        key = match.group(1)
        if key not in refs:
            # Only drop if it looks like a non-numeric Flight ref (contains
            # hex letters) — pure numbers are probably dollar amounts.
            if re.search(r"[a-f]", key):
                return ""
            return match.group(0)
        return _deref_string(refs[key], refs, depth + 1)

    return re.sub(r"(?<![\w$])\$([0-9a-f]{1,4})(?![\w.,])", _sub, s)


def _extract_balanced_json(text: str, start: int) -> str | None:
    """Extract a balanced JSON object starting at text[start] (must be '{')."""
    if start >= len(text) or text[start] != "{":
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if esc:
            esc = False
            continue
        if c == "\\":
            esc = True
            continue
        if c == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _populate_from_bounty(pd: ProgramData, bounty: dict) -> None:
    """Map Immunefi's `bounty` object (Flight or __NEXT_DATA__) to ProgramData."""
    pd.handle = bounty.get("slug") or bounty.get("id") or pd.handle
    pd.name = (
        bounty.get("project")
        or bounty.get("name")
        or bounty.get("title")
        or pd.name
    )
    pd.last_modified = str(
        bounty.get("updatedDate") or bounty.get("updatedAt") or ""
    )
    pd.cvss_version = str(bounty.get("cvssVersion") or "")

    # ---- Assets (in-scope) — list of {type, url, description, addedAt, ...}
    assets_raw = bounty.get("assets") or bounty.get("assetsInScope") or []
    pd.scope_in = []  # reset
    for a in assets_raw:
        if not isinstance(a, dict):
            continue
        identifier = (
            a.get("url")
            or a.get("address")
            or a.get("target")
            or a.get("identifier")
            or a.get("name")
            or ""
        )
        upstream_type = (a.get("type") or "").lower() or _guess_type(identifier)
        raw_desc = a.get("description")
        qualifier = raw_desc.strip() if isinstance(raw_desc, str) else ""
        versions: list[str] = []
        if a.get("branch"):
            versions.append(f"branch: {a['branch']}")
        if a.get("tag"):
            versions.append(f"tag: {a['tag']}")
        if a.get("isSafeHarbor"):
            versions.append("safe-harbor")
        if a.get("isPrimacyOfImpact"):
            versions.append("primacy-of-impact")
        if identifier:
            # Apply URL-pattern refinement so github.com/… and docs.*
            # URLs don't get mis-labeled as smart_contract.
            canonical = _canonicalize_type(upstream_type)
            refined = _refine_type_by_url(canonical, identifier)
            # Preserve the upstream hint in qualifier if we overrode.
            if refined != canonical and canonical:
                versions.append(f"immunefi-type:{canonical}")
            pd.scope_in.append(
                Asset(
                    type=refined,
                    identifier=identifier,
                    qualifier=qualifier,
                    in_scope_versions=versions,
                )
            )

    # ---- Out-of-scope (VERBATIM — concatenate all OOS blocks the platform ships).
    # Immunefi stores OOS across several fields: defaultOutOfScopeGeneral,
    # defaultOutOfScopeSmartContract, defaultOutOfScopeBlockchain,
    # defaultOutOfScopeWebAndApplications, customOutOfScopeInformation,
    # customProhibitedActivities (list), prohibitedActivites (typo intentional).
    pd.scope_out = []
    oos_string_fields = [
        "defaultOutOfScopeGeneral",
        "defaultOutOfScopeSmartContract",
        "defaultOutOfScopeBlockchain",
        "defaultOutOfScopeWebAndApplications",
        "customOutOfScopeInformation",
        "outOfScopeAndRules",
    ]
    for field in oos_string_fields:
        v = bounty.get(field)
        if isinstance(v, str) and v.strip():
            for line in v.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                line = re.sub(r"^[-*+•]\s+", "", line)
                line = re.sub(r"^\d+[.)]\s+", "", line)
                if line:
                    pd.scope_out.append(line)

    oos_list_fields = [
        "customProhibitedActivities",
        "defaultProhibitedActivities",
        "prohibitedActivites",
        "prohibitedActivities",
    ]
    for field in oos_list_fields:
        v = bounty.get(field)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str) and item.strip():
                    pd.scope_out.append(item.strip())
                elif isinstance(item, dict):
                    txt = (
                        item.get("description")
                        or item.get("text")
                        or item.get("title")
                        or ""
                    )
                    if txt and isinstance(txt, str):
                        pd.scope_out.append(txt.strip())

    # Legacy __NEXT_DATA__ shape: bounty.outOfScope may be a list/string.
    legacy_oos = bounty.get("outOfScope")
    if isinstance(legacy_oos, list):
        for item in legacy_oos:
            if isinstance(item, str) and item.strip():
                pd.scope_out.append(item.strip())
            elif isinstance(item, dict):
                txt = item.get("description") or item.get("text") or ""
                if txt:
                    pd.scope_out.append(txt.strip())
    elif isinstance(legacy_oos, str):
        for line in legacy_oos.splitlines():
            line = line.strip().lstrip("-*•").strip()
            if line:
                pd.scope_out.append(line)

    # ---- Known issues
    pd.known_issues = []
    known = bounty.get("knownIssues") or bounty.get("known_issues") or []
    if isinstance(known, list):
        for item in known:
            if isinstance(item, str) and item.strip():
                pd.known_issues.append(item.strip())
            elif isinstance(item, dict):
                txt = item.get("description") or item.get("title") or ""
                if txt and isinstance(txt, str):
                    pd.known_issues.append(txt.strip())
    elif isinstance(known, str):
        for line in known.splitlines():
            line = line.strip().lstrip("-*•").strip()
            if line:
                pd.known_issues.append(line)

    # ---- Submission rules — concat description, assetsBodyV2, impactsBody,
    # rewardsBody (when they're strings), and primacy + safe-harbor flags.
    rules_parts: list[str] = []
    desc = bounty.get("description")
    if isinstance(desc, str) and desc.strip():
        rules_parts.append(desc.strip())

    # Map Immunefi's internal field names to human-readable section headings.
    _FIELD_HEADINGS = {
        "assetsBodyV2": "Assets (details)",
        "impactsBody": "Impact details",
        "rewardsBody": "Rewards (details)",
        "programOverview": "Program overview",
    }
    for key in ("assetsBodyV2", "impactsBody", "rewardsBody", "programOverview"):
        v = bounty.get(key)
        if isinstance(v, str) and v.strip() and not _is_unresolved_ref(v):
            heading = _FIELD_HEADINGS.get(key, key)
            rules_parts.append(f"## {heading}\n{v.strip()}")

    # Primacy / policy flags
    meta_flags: list[str] = []
    if bounty.get("primacy"):
        meta_flags.append(f"Primacy: {bounty['primacy']}")
    if bounty.get("proofOfConceptType"):
        meta_flags.append(f"PoC: {bounty['proofOfConceptType']}")
    if bounty.get("kyc") is not None:
        meta_flags.append(f"KYC required: {bool(bounty['kyc'])}")
    if bounty.get("isSafeHarborActive") is not None:
        meta_flags.append(f"Safe Harbor active: {bool(bounty['isSafeHarborActive'])}")
    if bounty.get("premiumTriaging") is not None:
        meta_flags.append(f"Premium triaging: {bool(bounty['premiumTriaging'])}")
    if bounty.get("rewardsToken"):
        meta_flags.append(f"Rewards token: {bounty['rewardsToken']}")
    if bounty.get("rewardsTokenNetwork"):
        meta_flags.append(f"Rewards network: {bounty['rewardsTokenNetwork']}")
    if meta_flags:
        rules_parts.append("## Program Metadata\n" + "\n".join(f"- {f}" for f in meta_flags))

    # Legacy __NEXT_DATA__ fields
    for key in ("rewardRules", "submissionRules", "rulesOfEngagement", "impactInScope"):
        v = bounty.get(key)
        if isinstance(v, str) and v.strip():
            rules_parts.append(f"## {key}\n{v.strip()}")

    pd.submission_rules = "\n\n".join(rules_parts)

    # ---- Severity / rewards table
    pd.severity_table = []
    rewards = bounty.get("rewards") or bounty.get("rewardSchemes") or []
    if isinstance(rewards, list):
        for row in rewards:
            if not isinstance(row, dict):
                continue
            sev = str(row.get("severity") or row.get("level") or "")
            min_r = row.get("minReward") or row.get("min") or ""
            max_r = row.get("maxReward") or row.get("amount") or row.get("payout") or ""
            reward_str = ""
            if min_r and max_r:
                reward_str = f"${min_r:,} – ${max_r:,}" if isinstance(min_r, int) and isinstance(max_r, int) else f"{min_r} – {max_r}"
            elif max_r:
                reward_str = f"Up to ${max_r:,}" if isinstance(max_r, int) else str(max_r)
            asset_class = str(row.get("assetType") or row.get("assetClass") or "")
            model = str(row.get("rewardModel") or "")
            pct = row.get("rewardCalculationPercentage")
            notes_parts = []
            if model:
                notes_parts.append(model)
            if pct:
                notes_parts.append(f"{pct}% of economic damage capped")
            pd.severity_table.append(
                SeverityRow(
                    severity=sev,
                    reward=reward_str,
                    asset_class=asset_class,
                    notes="; ".join(notes_parts),
                )
            )

    # ---- Bounty range
    max_b = bounty.get("maxBounty") or bounty.get("maxReward") or bounty.get("bountyMax")
    min_b = bounty.get("minBounty") or bounty.get("minReward") or bounty.get("bountyMin")
    if max_b or min_b:
        pd.bounty_range = {
            "min": str(min_b) if min_b else "",
            "max": str(max_b) if max_b else "",
            "currency": str(bounty.get("currency") or "USD"),
            "token": str(bounty.get("rewardsToken") or ""),
            "network": str(bounty.get("rewardsTokenNetwork") or ""),
        }

    # ---- Raw markdown: concat all verbatim string fields for the audit trail.
    raw_parts = []
    if pd.name:
        raw_parts.append(f"# {pd.name} — Immunefi Bug Bounty")
    if desc and isinstance(desc, str):
        raw_parts.append(desc.strip())
    for field in oos_string_fields + [
        "impactsBody",
        "assetsBodyV2",
        "rewardsBody",
    ]:
        v = bounty.get(field)
        if isinstance(v, str) and v.strip():
            raw_parts.append(f"## {field}\n{v.strip()}")
    pd.raw_markdown = "\n\n".join(raw_parts)[:50000]

    # ---- Confidence: authoritative Flight extraction with full data.
    has_assets = len(pd.scope_in) >= 1
    has_oos = len(pd.scope_out) >= 3
    has_rewards = len(pd.severity_table) >= 1 or bool(pd.bounty_range)
    has_rules = len(pd.submission_rules.strip()) >= 200

    if has_assets and has_oos and has_rewards and has_rules:
        pd.confidence = 0.95
    elif has_assets and has_oos and has_rewards:
        pd.confidence = 0.9
    elif has_assets and has_rewards:
        pd.confidence = 0.8
    elif has_assets:
        pd.confidence = 0.6
    else:
        pd.confidence = 0.3


def _is_unresolved_ref(value: str) -> bool:
    """True if a field value is an unresolved Flight reference like '$30'.

    Unresolved refs happen when the server sent a placeholder for a deferred
    React Server Component boundary and the content is streamed in later.
    Static fetches only see the initial render, so these refs may never
    resolve without running the page. We skip them instead of leaking
    '$30' / '$2f' into the output.
    """
    if not isinstance(value, str):
        return False
    return bool(re.fullmatch(r"\$[0-9a-f]{1,4}", value.strip()))


def _extract_slug(path: str) -> str:
    m = re.search(r"/bug-bounty/([^/?#]+)", path)
    if m:
        return m.group(1)
    return ""


def _guess_type(identifier: str) -> str:
    i = (identifier or "").lower()
    if i.startswith("0x") and len(i) >= 42:
        return "smart_contract"
    if "://" in i or i.startswith("www."):
        return "url"
    if "github.com" in i:
        return "repo"
    return "other"


def _canonicalize_type(t: str) -> str:
    t = (t or "").lower().strip()
    mapping = {
        "smart_contract": "smart_contract",
        "smart contract": "smart_contract",
        "contract": "smart_contract",
        "websites_and_applications": "url",
        "website": "url",
        "web": "url",
        "app": "url",
        "wallet": "wallet",
        "blockchain_dlt": "blockchain",
        "blockchain": "blockchain",
        "executable": "binary",
    }
    return mapping.get(t, t or "other")


def _refine_type_by_url(upstream_type: str, identifier: str) -> str:
    """Refine an Immunefi-labeled asset type based on URL patterns.

    Immunefi sometimes labels a GitHub repo or a documentation page as
    `smart_contract` (because the contract sources live in that repo).
    Downstream tools treat `smart_contract` as "this IS the contract
    address" which is wrong. We override to a more accurate type when the
    URL unambiguously points elsewhere.
    """
    if not identifier:
        return upstream_type
    u = identifier.lower()
    # True on-chain contract addresses always live on an explorer URL.
    if re.search(r"(etherscan|arbiscan|polygonscan|bscscan|optimistic\.etherscan|snowtrace|basescan|ftmscan|cronoscan|era\.zksync)\.(io|com)/address/0x[a-f0-9]{40}", u):
        return "smart_contract"
    if re.match(r"^0x[a-f0-9]{40}$", u):
        return "smart_contract"
    # GitHub repo URLs are source code repositories, not individual contracts.
    if u.startswith("https://github.com/") or u.startswith("http://github.com/"):
        return "repo"
    # Documentation URLs — clearly prose, not a contract address.
    if re.match(r"^https?://(docs|documentation|wiki|knowledge)\.", u):
        return "url"
    if "/docs/" in u and u.startswith("http"):
        return "url"
    # Generic web URLs that aren't explorers
    if u.startswith("http://") or u.startswith("https://"):
        # Only treat as URL if it's NOT an explorer
        if "scan.io" in u or "scan.com" in u or "etherscan" in u:
            return upstream_type  # respect upstream if it says smart_contract
        return "url"
    return upstream_type


def _extract_visible_text(html: str) -> str:
    html = re.sub(r"<script.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<style.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:50000]
