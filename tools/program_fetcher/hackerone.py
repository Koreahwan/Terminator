"""HackerOne program fetcher.

Strategy:
  1. POST to public /graphql with an anonymous team(handle:) query.
     HackerOne exposes `policy`, `structured_scopes`, and `bounty_table`
     to unauthenticated callers for public programs. Verified live:
     team { name policy structured_scopes bounty_table } all work.
  2. If GraphQL returns empty (program archived, private, or schema
     changed again), fall back to scraping /<handle>/policy HTML.
     Note: HackerOne aggressively 403s /policy without a real cookie, so
     this fallback is best-effort only.

URL shapes:
    https://hackerone.com/<handle>
    https://hackerone.com/<handle>/policy
    https://hackerone.com/<handle>/hacktivity
"""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from .base import Asset, ProgramData, SeverityRow
from .transport import TransportError, http_get, http_post_json


GRAPHQL_URL = "https://hackerone.com/graphql"

# Query verified against the live schema on 2026-04-10.
# BountyTableRow fields: low, medium, high, critical (and *_minimum variants).
# Team.structured_scopes returns a connection with asset_identifier, asset_type,
# instruction, eligible_for_submission, max_severity.
_QUERY = """
query TeamPolicy($handle: String!) {
  team(handle: $handle) {
    name
    handle
    about
    submission_state
    policy
    base_bounty
    bounty_table {
      bounty_table_rows(first: 100) {
        edges {
          node {
            low
            medium
            high
            critical
            description
          }
        }
      }
    }
    structured_scopes(first: 100, archived: false) {
      edges {
        node {
          asset_identifier
          asset_type
          instruction
          eligible_for_submission
          eligible_for_bounty
          max_severity
        }
      }
    }
  }
}
""".strip()


def fetch(url: str) -> ProgramData:
    handle = _extract_handle(url)
    if not handle:
        raise RuntimeError(f"hackerone: cannot extract handle from {url}")

    pd = ProgramData(
        platform="hackerone",
        handle=handle,
        program_url=f"https://hackerone.com/{handle}",
        policy_url=f"https://hackerone.com/{handle}/policy",
        source="hackerone.graphql",
        confidence=0.0,
    )

    # 1) Public GraphQL — verified working for anonymous callers.
    try:
        status, body, _ = http_post_json(
            GRAPHQL_URL,
            {"query": _QUERY, "variables": {"handle": handle}},
            headers={
                "Origin": "https://hackerone.com",
                "Accept-Encoding": "gzip",
            },
            timeout=20,
        )
        if status == 200:
            data = json.loads(body)
            team = (data.get("data") or {}).get("team")
            errors = data.get("errors") or []
            if team:
                _populate_from_graphql(pd, team)
            elif errors:
                pd.warnings.append(
                    f"hackerone.graphql errors: {errors[0].get('message', 'unknown')[:120]}"
                )
    except (TransportError, json.JSONDecodeError, ValueError) as e:
        pd.warnings.append(f"hackerone.graphql: {type(e).__name__}: {e}")

    # 2) HTML fallback if GraphQL yielded nothing.
    if not pd.scope_in and not pd.scope_out:
        try:
            status, html, _ = http_get(pd.policy_url, timeout=30)
            if status == 200:
                _populate_from_html(pd, html)
                if pd.scope_in or pd.scope_out:
                    pd.source = "hackerone.policy_html"
        except TransportError as e:
            pd.warnings.append(f"hackerone.html: {type(e).__name__}: {e}")

    _score_confidence(pd)
    return pd


def parse_html(html: str, program_url: str) -> ProgramData:
    """Parse a saved HackerOne policy page (fixture-friendly)."""
    handle = _extract_handle(program_url)
    pd = ProgramData(
        platform="hackerone",
        handle=handle,
        program_url=f"https://hackerone.com/{handle}",
        policy_url=program_url,
        source="hackerone.policy_html",
        confidence=0.0,
    )
    _populate_from_html(pd, html)
    _score_confidence(pd)
    return pd


def parse_graphql(team: dict, handle: str) -> ProgramData:
    """Parse a saved GraphQL team response (fixture-friendly)."""
    pd = ProgramData(
        platform="hackerone",
        handle=handle,
        program_url=f"https://hackerone.com/{handle}",
        policy_url=f"https://hackerone.com/{handle}/policy",
        source="hackerone.graphql",
        confidence=0.0,
    )
    _populate_from_graphql(pd, team)
    _score_confidence(pd)
    return pd


def _extract_handle(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    if not path:
        return ""
    return path.split("/")[0]


_SEVERITY_ORDER = ("low", "medium", "high", "critical")


def _populate_from_graphql(pd: ProgramData, team: dict) -> None:
    pd.name = team.get("name") or pd.handle
    policy_md = team.get("policy") or ""
    pd.submission_rules = policy_md.strip()
    pd.raw_markdown = policy_md[:50000]

    # structured_scopes — each edge.node is one asset.
    scopes = (team.get("structured_scopes") or {}).get("edges") or []
    for edge in scopes:
        node = edge.get("node") or {}
        ident = node.get("asset_identifier") or ""
        if not ident:
            continue
        atype = (node.get("asset_type") or "").lower()
        instruction = (node.get("instruction") or "").strip()
        eligible = bool(node.get("eligible_for_submission"))
        max_sev = node.get("max_severity") or ""
        mapped_type = _map_asset_type(atype)
        qualifier_full = f"{instruction}{' [max '+max_sev+']' if max_sev else ''}".strip()
        # Promote numeric App Store IDs / Android package names to full
        # store URLs when the instruction contains the canonical URL.
        ident = _promote_mobile_identifier(ident, qualifier_full, mapped_type)
        asset = Asset(
            type=mapped_type,
            identifier=ident,
            qualifier=qualifier_full,
        )
        if eligible:
            pd.scope_in.append(asset)
        else:
            # Archived / out-of-scope structured items end up here.
            label = f"{ident}"
            if atype:
                label += f" ({atype})"
            if instruction:
                label += f" — {instruction}"
            pd.scope_out.append(label)

    # Also pull verbatim "Out of Scope" text from the policy markdown — the
    # structured_scopes connection only contains eligible assets, so the
    # human-readable OOS list lives inside `policy`.
    if policy_md:
        _extract_oos_from_policy(pd, policy_md)
        _extract_known_from_policy(pd, policy_md)

    # bounty_table — each row is one reward tier.
    bt = team.get("bounty_table") or {}
    rows = (bt.get("bounty_table_rows") or {}).get("edges") or []
    for edge in rows:
        node = edge.get("node") or {}
        # Each row has all four severity amounts. We flatten to 4 SeverityRow
        # entries so the renderer can produce a readable severity column.
        for sev in _SEVERITY_ORDER:
            amount = node.get(sev)
            if amount is None:
                continue
            pd.severity_table.append(
                SeverityRow(
                    severity=sev.capitalize(),
                    reward=f"${amount:,}" if isinstance(amount, int) else str(amount),
                    notes=(node.get("description") or "").strip(),
                )
            )
        if pd.severity_table:
            # One row is typically enough; stop after the first fully-populated
            # tier so we don't emit 40 duplicate rows for multi-asset tables.
            break

    # Bounty range from whatever severities we pulled.
    if pd.severity_table:
        amounts = [
            int(re.sub(r"[^\d]", "", r.reward))
            for r in pd.severity_table
            if re.search(r"\d", r.reward)
        ]
        if amounts:
            pd.bounty_range = {
                "min": f"${min(amounts):,}",
                "max": f"${max(amounts):,}",
                "currency": "USD",
            }


def _extract_oos_from_policy(pd: ProgramData, policy: str) -> None:
    """Find an 'Out of Scope' or 'Exclusions' section in the policy markdown."""
    patterns = [
        r"(?im)^#+\s*Out[\s-]?of[\s-]?Scope.*?\n(.+?)(?=^#+\s|\Z)",
        r"(?im)^#+\s*Exclusions?.*?\n(.+?)(?=^#+\s|\Z)",
        r"(?im)^#+\s*Ineligible.*?\n(.+?)(?=^#+\s|\Z)",
        r"(?im)^\*\*\s*Out[\s-]?of[\s-]?Scope.*?\*\*(.+?)(?=^\*\*|^#+\s|\Z)",
    ]
    for pat in patterns:
        m = re.search(pat, policy, re.DOTALL)
        if not m:
            continue
        body = m.group(1)
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            line = re.sub(r"^[-+•]\s+", "", line)
            line = re.sub(r"^\*\s+", "", line)
            line = re.sub(r"^\d+[.)]\s+", "", line)
            if line and not line.startswith(("#", "**")):
                pd.scope_out.append(line)
        if pd.scope_out:
            return


def _extract_known_from_policy(pd: ProgramData, policy: str) -> None:
    patterns = [
        r"(?im)^#+\s*Known[\s-]?(?:Issues|Vulnerabilities|Bugs).*?\n(.+?)(?=^#+\s|\Z)",
        r"(?im)^#+\s*Known.*?\n(.+?)(?=^#+\s|\Z)",
    ]
    for pat in patterns:
        m = re.search(pat, policy, re.DOTALL)
        if not m:
            continue
        body = m.group(1)
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            line = re.sub(r"^[-+•]\s+", "", line)
            line = re.sub(r"^\*\s+", "", line)
            line = re.sub(r"^\d+[.)]\s+", "", line)
            if line and not line.startswith(("#", "**")):
                pd.known_issues.append(line)
        if pd.known_issues:
            return


class _DetailsExtractor(HTMLParser):
    """Extract headings + bodies from a HackerOne policy HTML.

    Handles `<details>` + `<summary>` blocks because HackerOne collapses
    Out of Scope sub-sections inside them, and jina drops the content.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sections: list[tuple[str, str]] = []
        self._current_heading = ""
        self._current_body: list[str] = []
        self._in_heading = False
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "nav", "header", "footer"):
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag in ("h1", "h2", "h3", "summary"):
            if self._current_heading or self._current_body:
                self.sections.append(
                    (self._current_heading, "".join(self._current_body).strip())
                )
            self._current_heading = ""
            self._current_body = []
            self._in_heading = True
        elif tag in ("li", "p", "br"):
            self._current_body.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "nav", "header", "footer"):
            if self._skip_depth > 0:
                self._skip_depth -= 1
            return
        if tag in ("h1", "h2", "h3", "summary"):
            self._in_heading = False

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._in_heading:
            self._current_heading += data
        else:
            self._current_body.append(data)

    def finalize(self) -> list[tuple[str, str]]:
        if self._current_heading or self._current_body:
            self.sections.append(
                (self._current_heading.strip(),
                 "".join(self._current_body).strip())
            )
        return [(h.strip(), b.strip()) for h, b in self.sections if h or b]


def _populate_from_html(pd: ProgramData, html: str) -> None:
    parser = _DetailsExtractor()
    parser.feed(html)
    sections = parser.finalize()

    pd.raw_markdown = "\n\n".join(
        f"## {h}\n{b}" for h, b in sections if h and b
    )[:50000]

    if not pd.name:
        tm = re.search(r"<title>([^<]+)</title>", html, re.IGNORECASE)
        if tm:
            pd.name = re.sub(r"\s*\|.*$", "", tm.group(1)).strip()

    scope_keywords = (
        "in scope", "scope", "assets", "targets", "what's in scope"
    )
    oos_keywords = (
        "out of scope", "out-of-scope", "exclusions", "excluded",
        "not in scope",
    )
    known_keywords = (
        "known issues", "known limitations", "already reported",
    )
    rules_keywords = (
        "disclosure", "ground rules", "rules", "program rules",
        "reporting", "submission",
    )
    severity_keywords = (
        "severity", "bounty", "rewards", "payout",
    )

    for heading, body in sections:
        h = heading.lower()
        if any(k in h for k in known_keywords):
            for line in _split_bullets(body):
                pd.known_issues.append(line)
        elif any(k in h for k in oos_keywords):
            for line in _split_bullets(body):
                pd.scope_out.append(line)
        elif any(k in h for k in scope_keywords) and "out" not in h:
            for line in _split_bullets(body):
                pd.scope_in.append(Asset(identifier=line, type=_guess_type(line)))
        elif any(k in h for k in rules_keywords):
            if not pd.submission_rules or len(body) > len(pd.submission_rules):
                pd.submission_rules = body
        elif any(k in h for k in severity_keywords):
            for line in _split_bullets(body):
                m = re.match(
                    r"(Critical|High|Medium|Low|Informational)\s*[:\-–]\s*(.+)$",
                    line,
                    re.IGNORECASE,
                )
                if m:
                    pd.severity_table.append(
                        SeverityRow(severity=m.group(1), reward=m.group(2).strip())
                    )


def _split_bullets(text: str) -> list[str]:
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Require whitespace after the bullet char so "*.example.com"
        # (wildcard scope) doesn't get stripped to ".example.com".
        line = re.sub(r"^[-+•]\s+", "", line)
        line = re.sub(r"^\*\s+", "", line)
        line = re.sub(r"^\d+[.)]\s+", "", line)
        if line:
            out.append(line)
    return out


def _guess_type(identifier: str) -> str:
    i = identifier.lower()
    if "://" in i or i.startswith("www."):
        return "url"
    if "*." in i or i.startswith("*"):
        return "wildcard"
    if "github.com" in i:
        return "repo"
    if ".apk" in i or "play.google" in i:
        return "mobile_app"
    return "other"


def _map_asset_type(atype: str) -> str:
    mapping = {
        "url": "url",
        "wildcard": "wildcard",
        "ios_app_store": "mobile_app",
        "ios_app_store_app_id": "mobile_app",
        "apple_store_app_id": "mobile_app",
        "google_play_app_id": "mobile_app",
        "android": "mobile_app",
        "source_code": "repo",
        "other": "other",
        "hardware": "hardware",
        "executable": "binary",
        "cidr": "network",
        "api": "api",
    }
    return mapping.get(atype, atype or "other")


def _promote_mobile_identifier(identifier: str, qualifier: str, atype: str) -> str:
    """If the identifier is a bare App Store ID or package name and the
    instruction qualifier contains a full store URL, promote the URL.
    """
    # Is the identifier already a full URL?
    if identifier.startswith("http://") or identifier.startswith("https://"):
        return identifier
    # Pure numeric App Store ID — look for Apple URL in qualifier
    if identifier.isdigit() and atype == "mobile_app":
        m = re.search(r"https://apps\.apple\.com/[^\s)]+id" + re.escape(identifier), qualifier)
        if m:
            return m.group(0)
        # Or any apple URL
        m = re.search(r"https://apps\.apple\.com/[^\s)]+", qualifier)
        if m:
            return m.group(0)
    # Android package name (com.foo.bar) — look for Play Store URL in qualifier
    if atype == "mobile_app" and re.match(r"^[a-z][\w.]+\.[a-z][\w]+$", identifier):
        m = re.search(
            rf"https://play\.google\.com/store/apps/details\?id={re.escape(identifier)}",
            qualifier,
        )
        if m:
            return m.group(0)
        m = re.search(r"https://play\.google\.com/store/apps/details\?id=[\w.]+", qualifier)
        if m:
            return m.group(0)
    return identifier


def _score_confidence(pd: ProgramData) -> None:
    """HackerOne handler confidence model.

    GraphQL is the authoritative source (0.9). HTML policy scrape is only
    a fallback that captures partial data (0.75 at best).
    """
    has_policy = len(pd.submission_rules.strip()) >= 100
    has_scope = len(pd.scope_in) >= 1
    has_oos = len(pd.scope_out) >= 1
    has_severity = len(pd.severity_table) >= 1

    if pd.source == "hackerone.graphql" and has_scope and has_severity and has_policy:
        pd.confidence = 0.9
    elif pd.source == "hackerone.graphql" and has_scope and has_policy:
        pd.confidence = 0.85
    elif pd.source == "hackerone.graphql" and has_scope:
        pd.confidence = 0.75
    elif pd.source == "hackerone.policy_html" and has_scope and has_oos and has_severity:
        pd.confidence = 0.8
    elif has_scope and has_oos:
        pd.confidence = 0.65
    elif has_scope or has_oos:
        pd.confidence = 0.45
    else:
        pd.confidence = 0.15
