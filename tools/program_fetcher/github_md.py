"""GitHub-hosted audit/bounty contest fetcher.

For Code4rena / Sherlock / Cantina / etc., the "program page" is actually a
GitHub repo README. We fetch the raw README via the public Contents API
(no token needed for public repos) and parse it like any other markdown
contest brief.

URL shapes:
    https://github.com/<owner>/<repo>
    https://github.com/<owner>/<repo>/tree/main/audit
    https://github.com/<owner>/<repo>/blob/main/README.md
"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import urlparse

from .base import Asset, ProgramData, SeverityRow
from .transport import TransportError, http_get


def fetch(url: str) -> ProgramData:
    owner, repo, subpath = _parse_url(url)
    if not owner or not repo:
        raise RuntimeError(f"github_md: cannot parse owner/repo from {url}")

    pd = ProgramData(
        platform="github_md",
        handle=f"{owner}/{repo}",
        name=f"{owner}/{repo}",
        program_url=f"https://github.com/{owner}/{repo}",
        policy_url=f"https://github.com/{owner}/{repo}",
        source="github.contents_api",
        confidence=0.0,
    )

    # 1) Try the README endpoint (canonical, handles any casing of README)
    try:
        status, body, _ = http_get(
            f"https://api.github.com/repos/{owner}/{repo}/readme",
            accept="application/vnd.github.v3+json",
            timeout=20,
        )
        if status == 200:
            data = json.loads(body)
            content_b64 = data.get("content", "")
            if content_b64:
                md = base64.b64decode(content_b64).decode("utf-8", errors="replace")
                _populate_from_markdown(pd, md)
    except (TransportError, json.JSONDecodeError):
        pass

    # 2) Explicit subpath from the URL (e.g. /tree/main/audit)
    candidate_subpaths: list[str] = []
    if subpath:
        candidate_subpaths.append(subpath)
    # Sherlock-style audit repos: scope doc is almost always at audit/ or
    # contest/README.md. Probe these even if the URL didn't mention them.
    for implicit in ("audit", "contest", "scope"):
        if implicit not in candidate_subpaths:
            candidate_subpaths.append(implicit)

    for sp in candidate_subpaths:
        try:
            status, body, _ = http_get(
                f"https://api.github.com/repos/{owner}/{repo}/contents/{sp}/README.md",
                accept="application/vnd.github.v3+json",
                timeout=20,
            )
            if status == 200:
                data = json.loads(body)
                content_b64 = data.get("content", "")
                if content_b64:
                    extra = base64.b64decode(content_b64).decode("utf-8", errors="replace")
                    pd.raw_markdown = (pd.raw_markdown + "\n\n---\n\n" + extra)[:50000]
                    _populate_from_markdown(pd, extra)
        except (TransportError, json.JSONDecodeError):
            continue

    _score_confidence(pd)
    return pd


def parse_markdown(md: str, program_url: str) -> ProgramData:
    """Fixture-friendly entry point."""
    owner, repo, _ = _parse_url(program_url)
    pd = ProgramData(
        platform="github_md",
        handle=f"{owner}/{repo}" if owner and repo else program_url,
        name=f"{owner}/{repo}" if owner and repo else "",
        program_url=program_url,
        policy_url=program_url,
        source="github.contents_api",
        confidence=0.0,
    )
    _populate_from_markdown(pd, md)
    _score_confidence(pd)
    return pd


def _parse_url(url: str) -> tuple[str, str, str]:
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    parts = path.split("/")
    if len(parts) < 2:
        return "", "", ""
    owner, repo = parts[0], parts[1]
    # If path is /owner/repo/tree/<branch>/<subpath>, extract subpath.
    subpath = ""
    if len(parts) > 4 and parts[2] == "tree":
        subpath = "/".join(parts[4:])
    elif len(parts) > 4 and parts[2] == "blob":
        subpath = "/".join(parts[4:-1])
    return owner, repo, subpath


def _populate_from_markdown(pd: ProgramData, md: str) -> None:
    if not pd.raw_markdown:
        pd.raw_markdown = md[:50000]

    # Title
    mt = re.search(r"^#\s+(.+)$", md, re.MULTILINE)
    if mt and not pd.name.replace("/", ""):
        pd.name = mt.group(1).strip()

    def grab(headings: list[str]) -> str:
        for h in headings:
            pat = re.compile(
                rf"^#{{1,4}}\s*{re.escape(h)}[^\n]*\n(.*?)(?=^#{{1,4}}\s|\Z)",
                re.MULTILINE | re.DOTALL | re.IGNORECASE,
            )
            m = pat.search(md)
            if m:
                return m.group(1)
        return ""

    scope_body = grab([
        "Scope", "In Scope", "Contracts in scope",
        "Audit scope", "Assets in scope",
        "Files in scope", "Smart Contracts in Scope",
    ])
    oos_body = grab([
        "Out of Scope", "Out-of-scope", "Out of scope",
        "Out-of-Scope", "Outside the scope",
        "Exclusions", "Not in scope", "Excluded",
        "Issues to ignore", "Out-of-scope rules",
        "Findings out of scope", "What is NOT in scope",
        "Issues NOT eligible", "Out of Scope Issues",
    ])
    rules_body = grab([
        "Rules", "Ground rules", "Submission", "Rules of engagement",
        "Disclosure Policy", "Reporting",
        "Submission Process", "Reporting Guidelines",
    ])
    known_body = grab([
        "Known issues", "Known risks", "Already reported",
        "Automated Findings", "Automated Findings / Publicly Known Issues",
        "Publicly Known Issues", "Previous audits",
        "Known Findings", "Existing Issues",
    ])
    rewards_body = grab(["Rewards", "Payouts", "Bounty", "Severity"])
    # Audit-contest README extras
    overview_body = grab(["Overview", "Audit details", "About", "Description"])
    attack_body = grab(["Attack ideas", "Where to look for bugs", "Additional Context"])

    for line in _bullets(scope_body):
        if line:
            pd.scope_in.append(Asset(identifier=line, type=_guess_type(line)))
    for line in _bullets(oos_body):
        if line:
            pd.scope_out.append(line)
    for line in _bullets(known_body):
        if line:
            pd.known_issues.append(line)

    # Submission rules: concat Rules + Overview + Attack ideas + Additional
    # Context so audit-contest READMEs (which don't always have a dedicated
    # "Rules" section) still have submission_rules populated.
    rules_parts: list[str] = []
    if rules_body.strip():
        rules_parts.append("## Rules\n" + rules_body.strip())
    if overview_body.strip():
        rules_parts.append("## Overview\n" + overview_body.strip())
    if attack_body.strip():
        rules_parts.append("## Attack Ideas\n" + attack_body.strip())
    if rules_parts:
        combined = "\n\n".join(rules_parts)
        if len(combined) > len(pd.submission_rules):
            pd.submission_rules = combined

    for line in _bullets(rewards_body):
        m = re.match(
            r"(Critical|High|Medium|Low|Informational)\s*[:\-–]\s*(.+)$",
            line,
            re.IGNORECASE,
        )
        if m:
            pd.severity_table.append(
                SeverityRow(severity=m.group(1), reward=m.group(2).strip())
            )

    # ---- Prize pool / reward pool extraction for audit-contest READMEs.
    # Look for "Prize Pool: $80,000 USDC", "$X in USDC", "Total Awards",
    # "H/M awards", "Judge awards", etc. This lets Code4rena / Sherlock /
    # Cantina contest briefs populate bounty_range + severity_table without
    # a dedicated Rewards heading.
    prize_pool = re.search(
        r"(?i)(?:prize\s*pool|total\s*(?:prize|awards?|rewards?))\s*[:\-]?\s*\$?([\d,.]+)\s*(USDC|USD|ETH|DAI)?",
        md,
    )
    if prize_pool:
        amount = prize_pool.group(1)
        currency = prize_pool.group(2) or "USD"
        pd.bounty_range = {
            "max": f"${amount}",
            "currency": currency,
            "note": "Total audit contest prize pool",
        }
        pd.severity_table.append(
            SeverityRow(
                severity="Total Pool",
                reward=f"${amount} {currency}",
                notes="Audit contest prize pool",
            )
        )

    # Per-tier awards ("H/M awards: $54,615", "Judge awards: $X")
    for m in re.finditer(
        r"(?i)([HMLJ]\w*|Judge|Bot Race|Lookout)\s+awards?\s*[:\-]?\s*\$([\d,.]+)",
        md,
    ):
        label = m.group(1).strip()
        amount = m.group(2)
        pd.severity_table.append(
            SeverityRow(
                severity=label,
                reward=f"${amount}",
                notes="Per-tier audit contest pool",
            )
        )


def _bullets(text: str) -> list[str]:
    """Extract scope items from a markdown section.

    Handles three formats:
      1. Bullet lists:    `- foo` / `* foo` / `+ foo` / `1. foo`
      2. Markdown tables: skip header + separator rows; take first cell of
         data rows; extract URL from `[name](url)` markdown links.
      3. Plain paragraph lines (fallback only)
    """
    out: list[str] = []
    # Table-state machine: tracks whether we're currently inside a table and
    # how many rows we've seen so we can skip the first (header) row and
    # the second (separator) row.
    table_rows_seen = 0
    in_table = False

    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            in_table = False
            table_rows_seen = 0
            continue
        if stripped.startswith("#"):
            in_table = False
            table_rows_seen = 0
            continue

        # Markdown table row?
        if stripped.startswith("|") and stripped.endswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            # Separator row: every cell is just dashes/colons/spaces
            is_separator = all(
                re.fullmatch(r"[-:\s]+", c or "") for c in cells if c is not None
            )
            if is_separator:
                in_table = True
                table_rows_seen = max(table_rows_seen, 1)  # we've seen header + sep
                continue

            table_rows_seen += 1
            # First row is the header (seen before separator) — skip it.
            if not in_table and table_rows_seen == 1:
                continue

            # Data row: take the first non-empty cell and unwrap any
            # markdown link `[name](url)`.
            first_cell = cells[0] if cells else ""
            if not first_cell:
                continue
            link_m = re.match(r"^\[([^\]]+)\]\(([^)]+)\)", first_cell)
            if link_m:
                name = link_m.group(1)
                url = link_m.group(2)
                # Prefer URL when it's a github blob link (points to an
                # actual source file); otherwise use the display name.
                if "github.com" in url or url.startswith("http"):
                    out.append(url)
                else:
                    out.append(name)
                continue
            # Non-link first cell — take verbatim if it looks like real data
            if first_cell and first_cell != "---":
                out.append(first_cell)
            continue

        # Non-table line: reset table state
        in_table = False
        table_rows_seen = 0

        # Bullet list item?
        m = re.match(r"^(?:[-+•]|\*)\s+(.+)$", stripped)
        if m:
            item = m.group(1).strip()
            # Also unwrap markdown link in bullet item
            link_m = re.match(r"^\[([^\]]+)\]\(([^)]+)\)\s*(.*)$", item)
            if link_m:
                url = link_m.group(2)
                if "github.com" in url or url.startswith("http"):
                    item = url
            if item:
                out.append(item)
            continue
        m = re.match(r"^\d+[.)]\s+(.+)$", stripped)
        if m:
            item = m.group(1).strip()
            if item:
                out.append(item)
            continue

        # Plain paragraph line — keep only if it looks like a URL or file path
        if ("/" in stripped or "." in stripped) and len(stripped) < 200 and stripped != "---":
            out.append(stripped)
    return out


def _guess_type(identifier: str) -> str:
    i = identifier.lower()
    if i.startswith("0x") and len(i) >= 42:
        return "smart_contract"
    if ".sol" in i or ".vy" in i:
        return "smart_contract"
    if "://" in i:
        return "url"
    if "github.com" in i:
        return "repo"
    return "other"


def _score_confidence(pd: ProgramData) -> None:
    # GitHub audit-contest READMEs are authoritative: the contest org controls
    # the repo. If scope + oos + rules are all present, cap at 0.85 so a
    # complete README auto-PASSes.
    if pd.scope_in and pd.scope_out and pd.submission_rules and (pd.severity_table or pd.bounty_range):
        pd.confidence = 0.85
    elif pd.scope_in and pd.scope_out and pd.submission_rules:
        pd.confidence = 0.8
    elif pd.scope_in and pd.scope_out:
        pd.confidence = 0.6
    elif pd.scope_in:
        pd.confidence = 0.45
    else:
        pd.confidence = 0.2
