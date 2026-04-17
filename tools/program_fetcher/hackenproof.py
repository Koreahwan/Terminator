"""HackenProof program fetcher.

**v12.4 — Googlebot UA bypass (verified 2026-04-10):**
HackenProof uses Cloudflare to block most user-agents, but whitelists
Googlebot. A plain request with Googlebot's UA returns the full
server-rendered page (300KB+) including In Scope, Out of Scope, Rewards,
and Program Rules sections.

Extraction strategy:
  1. Fetch with Googlebot UA.
  2. Parse `__NUXT_DATA__` flat-reference blob for the program rules text
     (a long string entry deep in the Nuxt 3 serialization).
  3. Parse the visible text for scope / OOS tables and rewards — HackenProof
     renders each target as a row like:
        <target_name> <category> <severity> <reward_type>
     under the "In scope" / "Out of scope" headings.

URL shape: https://hackenproof.com/programs/<handle>
"""

from __future__ import annotations

import html as html_lib
import json
import re
from urllib.parse import urlparse

from .base import Asset, ProgramData, SeverityRow
from .transport import TransportError, http_get

GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

SPA_HOLD_MESSAGE = (
    "HackenProof is behind Cloudflare bot protection. The fetcher retried "
    "with a Googlebot User-Agent but still got no program data. Use the "
    "Playwright MCP fallback (Phase 0.1 manual path) or paste the verbatim "
    "sections from the live page by hand."
)


def fetch(url: str) -> ProgramData:
    handle = _extract_handle(url)
    pd = ProgramData(
        platform="hackenproof",
        handle=handle,
        program_url=f"https://hackenproof.com/programs/{handle}",
        policy_url=f"https://hackenproof.com/programs/{handle}",
        source="hackenproof.googlebot_html",
        confidence=0.0,
    )

    body = ""
    for candidate in [
        f"https://hackenproof.com/programs/{handle}",
        f"https://hackenproof.com/projects/{handle}",
    ]:
        try:
            status, resp, _ = http_get(
                candidate,
                timeout=30,
                headers={"User-Agent": GOOGLEBOT_UA},
            )
            if status == 200 and len(resp) > 10000:
                body = resp
                pd.program_url = candidate
                pd.policy_url = candidate
                break
        except TransportError:
            continue

    if not body:
        pd.warnings.append(SPA_HOLD_MESSAGE)
        pd.confidence = 0.5
        return pd

    _populate_from_html(pd, body)
    if not pd.scope_in and not pd.scope_out:
        pd.warnings.append(SPA_HOLD_MESSAGE)

    _score_confidence(pd)
    return pd


def parse_html(html_text: str, program_url: str) -> ProgramData:
    handle = _extract_handle(program_url)
    pd = ProgramData(
        platform="hackenproof",
        handle=handle,
        program_url=program_url,
        policy_url=program_url,
        source="hackenproof.googlebot_html",
        confidence=0.0,
    )
    _populate_from_html(pd, html_text)
    _score_confidence(pd)
    return pd


def _extract_handle(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    m = re.match(r"(?:programs|projects)/([^/]+)", path)
    if m:
        return m.group(1)
    return path.split("/")[0] if path else ""


def _populate_from_html(pd: ProgramData, html: str) -> None:
    # Title + meta description
    tm = re.search(r"<title>([^<]+)</title>", html, re.IGNORECASE)
    if tm:
        title = tm.group(1).strip()
        # HackenProof titles are usually just the program name
        pd.name = title
    desc_m = re.search(
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)',
        html,
        re.IGNORECASE,
    )
    if desc_m:
        pd.submission_rules = desc_m.group(1).strip()

    # --- Extract Nuxt 3 flat-reference blob for long rules/description strings
    nuxt_strings = _extract_nuxt_strings(html)

    # --- Parse visible text for scope / OOS / rewards tables
    text = _visible_text(html)
    pd.raw_markdown = text[:50000]

    # Locate section markers
    def section_between(start_marker: str, end_markers: list[str]) -> str:
        idx = text.find(start_marker)
        if idx < 0:
            return ""
        start = idx + len(start_marker)
        end = len(text)
        for m in end_markers:
            e = text.find(m, start)
            if e > 0 and e < end:
                end = e
        return text[start:end].strip()

    in_scope_text = section_between(
        "In scope",
        ["Out of scope", "Rewards", "Program rules", "Scope Review", "Stats"],
    )
    oos_text = section_between(
        "Out of scope",
        ["Rewards", "Program rules", "Scope Review", "Stats"],
    )
    rewards_text = section_between(
        "Rewards",
        ["Program rules", "Scope Review", "Stats", "Hackers", "SLA"],
    )
    stats_text = section_between(
        "Stats",
        ["Hackers", "SLA", "Program rules"],
    )
    program_rules_text = section_between(
        "Program rules",
        ["Hackers", "SLA", "FAQs", "Submit a bug"],
    )

    # --- Scope parser: HackenProof shows each target as a row.
    # Row format: <name> Copy Copied [description] <category> <severity> <reward_type>
    # Categories: Web, API, Android, iOS, Smart contract, ...
    def parse_targets(body: str) -> list[tuple[str, str, str, str]]:
        """Return list of (identifier, category, severity, reward) tuples."""
        if not body:
            return []
        # Split on "Copy Copied" which appears between each target's identifier
        # and the rest of its row.
        chunks = re.split(r"Copy\s+Copied", body)
        results: list[tuple[str, str, str, str]] = []
        prev_tail = ""
        for i, chunk in enumerate(chunks):
            chunk = chunk.strip()
            if not chunk:
                continue
            if i == 0:
                # The first chunk only has the first target's identifier.
                prev_tail = chunk
                continue
            # chunk contains: <rest of prev target row> <next target identifier>
            # The "rest" is: maybe description + " <category> <severity> <reward>"
            # We need to find where the next target starts.
            # Category tokens are fixed words.
            m = re.search(
                r"\b(Web|API|Android|iOS|Smart\s*contract|Hardware|Mobile|Desktop|Executable|Source\s*code|Infrastructure|Web3|Other)\s+"
                r"(Critical|High|Medium|Low|Informational|No\s*bounty|None)\s+"
                r"(Bounty|No\s*Bounty|Points|Swag|No\s*reward)",
                chunk,
                re.IGNORECASE,
            )
            if m:
                category = m.group(1)
                severity = m.group(2)
                reward = m.group(3)
                # The text BEFORE the match is part of the prev target's row
                # (description or identifier overflow). The text AFTER is the
                # next target's identifier.
                pre = chunk[: m.start()].strip()
                # Identifier for the prev target = prev_tail + any URL-like
                # prefix from `pre`. Take the LONGEST url/word as identifier.
                full_prev = (prev_tail + " " + pre).strip()
                # Extract the first token / URL / domain.
                ident_m = re.match(
                    r"([\S]+(?:\s+[\S]+)*?)(?=\s{2,}|$)", full_prev
                )
                ident = (ident_m.group(1) if ident_m else full_prev).strip()
                # Cap identifier length
                if len(ident) > 200:
                    ident = ident[:200]
                results.append((ident, category, severity, reward))
                # Reset prev_tail to what comes after the match
                prev_tail = chunk[m.end():].strip()
            else:
                # No category match — append to prev_tail
                prev_tail = (prev_tail + " " + chunk).strip()
        return results

    # Filter out the table header row ("Target Type Severity Reward") which
    # sometimes leaks into the first identifier before the first "Copy Copied".
    HEADER_NOISE = re.compile(
        r"^\s*Target\s+Type\s+Severity\s+Reward\s+",
        re.IGNORECASE,
    )

    def _clean(ident: str) -> str:
        cleaned = HEADER_NOISE.sub("", ident).strip()
        # If the identifier contains " Documentation:" or " Copy" or other
        # metadata tokens, cut at those boundaries so the identifier is just
        # the target.
        for sep in (" Documentation:", " Description:", " Note:", " Focus Area"):
            idx = cleaned.find(sep)
            if idx > 0:
                cleaned = cleaned[:idx].strip()
        # "Android App <url>" / "iOS App <url>" → take the URL
        m = re.match(r"^(?:Android\s+App|iOS\s+App)\s+(https?://\S+)", cleaned)
        if m:
            cleaned = m.group(1)
        return cleaned

    for ident, cat, sev, rew in parse_targets(in_scope_text):
        ident = _clean(ident)
        if ident and len(ident) > 2:
            pd.scope_in.append(
                Asset(
                    type=_map_category(cat),
                    identifier=ident,
                    qualifier=f"severity={sev} reward={rew}",
                )
            )

    for ident, cat, sev, rew in parse_targets(oos_text):
        ident = _clean(ident)
        if ident and len(ident) > 2:
            pd.scope_out.append(f"{ident} ({cat}, {sev}, {rew})")

    # Merge any OOS items found in Nuxt string entries that contain raw
    # markdown with recognisable OOS section headers.
    for nuxt_str in nuxt_strings:
        for item in _extract_oos_from_markdown(nuxt_str):
            if item not in pd.scope_out:
                pd.scope_out.append(item)

    # --- Parse rewards section
    if rewards_text:
        # Bounty range line: "Range of bounty $500 - $1,500"
        rng = re.search(
            r"Range\s+of\s+bounty\s+\$?([\d,]+)\s*[-–]\s*\$?([\d,]+)",
            rewards_text,
            re.IGNORECASE,
        )
        if rng:
            pd.bounty_range = {
                "min": f"${rng.group(1)}",
                "max": f"${rng.group(2)}",
                "currency": "USD",
            }
        # Per-severity rows: "Critical $1,200 - $1,500 High $500 - $900"
        for m in re.finditer(
            r"(Critical|High|Medium|Low|Informational)\s+\$?([\d,]+(?:\s*[-–]\s*\$?[\d,]+)?)",
            rewards_text,
            re.IGNORECASE,
        ):
            sev = m.group(1).capitalize()
            reward = f"${m.group(2).strip()}"
            pd.severity_table.append(
                SeverityRow(severity=sev, reward=reward)
            )

    # --- Rules: prefer the long Nuxt string entries (10+ of which usually
    # contain programRules, scopeReview, faq answers), falling back to the
    # visible "Program rules" section.
    rules_candidates: list[str] = []
    for s in nuxt_strings:
        if len(s) < 200:
            continue
        low = s.lower()
        if any(
            t in low
            for t in (
                "scanner",
                "rate limit",
                "responsible disclosure",
                "in-scope",
                "out-of-scope",
                "do not",
                "please do",
            )
        ):
            rules_candidates.append(s)
    if program_rules_text and len(program_rules_text) > 100:
        rules_candidates.append(program_rules_text)

    if rules_candidates:
        # Use the longest substantive block.
        longest = max(rules_candidates, key=len)
        if len(longest) > len(pd.submission_rules):
            pd.submission_rules = longest

    # Stats (not scope but useful)
    if stats_text:
        m = re.search(r"Total\s+rewards\s+\$?([\d,]+)", stats_text, re.IGNORECASE)
        if m:
            if pd.bounty_range:
                pd.bounty_range["total_paid"] = f"${m.group(1)}"


_OOS_SECTION_HEADERS_HP = re.compile(
    r"^#{1,3}\s*(?:Out of Scope|Exclusions|Not Eligible|Prohibited|Non-Qualifying)\s*$",
    re.IGNORECASE,
)


def _extract_oos_from_markdown(raw_md: str) -> list[str]:
    """Extract OOS items from a markdown string with known OOS section headers.

    Scans for any of: ## Out of Scope, ### Exclusions, ## Not Eligible,
    ## Prohibited, ## Non-Qualifying. Collects everything until the next ##
    header or end of string, extracting both bullet items and prose paragraphs.
    """
    out: list[str] = []
    lines = (raw_md or "").splitlines()
    in_oos_section = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if _OOS_SECTION_HEADERS_HP.match(stripped):
                in_oos_section = True
            else:
                in_oos_section = False
            continue
        if not in_oos_section:
            continue
        m = re.match(r"^(?:[-+•]|\*|\d+[.)])\s+(.+)$", stripped)
        if m:
            item = m.group(1).strip()
            if item and item not in out:
                out.append(item)
        else:
            if stripped and stripped not in out:
                out.append(stripped)
    return out


def _extract_nuxt_strings(html: str) -> list[str]:
    """Pull every string entry out of HackenProof's Nuxt 3 flat-reference blob.

    The blob is `<script id="__NUXT_DATA__" type="application/json">[...flat list...]</script>`
    where each entry is either a primitive, a dict, a list, or an index ref.
    Strings with embedded markdown or program rules live as plain string
    entries. We just pick every string of reasonable length.
    """
    m = re.search(
        r'<script[^>]*id="__NUXT_DATA__"[^>]*>(.*?)</script>',
        html,
        re.DOTALL,
    )
    if not m:
        return []
    try:
        data = json.loads(m.group(1))
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return [entry for entry in data if isinstance(entry, str) and len(entry) > 100]


def _visible_text(html: str) -> str:
    t = re.sub(r"<script.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    t = re.sub(r"<style.*?</style>", "", t, flags=re.DOTALL | re.IGNORECASE)
    t = re.sub(r"<[^>]+>", " ", t)
    t = html_lib.unescape(t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _map_category(category: str) -> str:
    c = (category or "").lower().replace(" ", "_")
    if "web" in c or "api" in c:
        return "url"
    if "android" in c or "ios" in c or "mobile" in c:
        return "mobile_app"
    if "smart" in c and "contract" in c:
        return "smart_contract"
    if "hardware" in c:
        return "hardware"
    if "executable" in c or "binary" in c:
        return "binary"
    if "source" in c:
        return "repo"
    return "other"


def _score_confidence(pd: ProgramData) -> None:
    has_scope = len(pd.scope_in) >= 1
    has_oos = len(pd.scope_out) >= 1
    has_rewards = len(pd.severity_table) >= 1 or bool(pd.bounty_range)
    has_rules = len(pd.submission_rules.strip()) >= 200

    if has_scope and has_oos and has_rewards and has_rules:
        pd.confidence = 0.9
    elif has_scope and has_oos and has_rewards:
        pd.confidence = 0.85
    elif has_scope and has_oos:
        pd.confidence = 0.7
    elif has_scope:
        pd.confidence = 0.5
    else:
        pd.confidence = 0.5  # force HOLD (see SPA_HOLD_MESSAGE)
