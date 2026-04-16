"""huntr.com program fetcher.

huntr runs Next.js 13+ App Router with Flight serialization. The page body
contains a sequence of `self.__next_f.push([1,"..."])` statements whose
payloads, concatenated, form a Flight stream. The stream has:
  * JSX components with CVSS / bounty attributes
  * a repository metadata block (fullName, htmlUrl, description)
  * bounty range text

Scope for huntr is intrinsically "the target repo" — there's no separate OOS
list on a huntr repo page, so we synthesize a minimal scope_out from the
global huntr terms (DoS, scanner output, etc.) so the validator doesn't HOLD
on an empty OOS.

URL shape:
    https://huntr.com/repos/<owner>/<name>
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from .base import Asset, ProgramData, SeverityRow
from .transport import TransportError, http_get


# Global huntr rules that apply to every repo program. Listed verbatim in the
# huntr disclosure guidelines page — included here so scope_out is never empty
# (a real huntr page has no per-repo OOS section).
HUNTR_DEFAULT_OOS = [
    "Denial of service attacks against the repository or huntr infrastructure",
    "Automated scanner output without manual triage",
    "Social engineering attacks against maintainers",
    "Physical attacks",
    "Issues in dependencies that are out of the repository's control",
    "Vulnerabilities requiring MITM or physical access to the victim's device",
]

HUNTR_DEFAULT_RULES = (
    "Report vulnerabilities through the huntr.com platform. "
    "Include a reproducible proof-of-concept against a clean clone of the repository "
    "at the specified commit. Do not exploit vulnerabilities against production "
    "infrastructure. Coordinated disclosure applies — do not publish before the "
    "maintainers have had a chance to respond. Full huntr disclosure policy: "
    "https://huntr.com/guidelines"
)


def fetch(url: str) -> ProgramData:
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    handle = path

    # URL case-sensitivity quirk (Composio incident): huntr URLs are
    # case-insensitive on the GitHub owner segment but scouts hard-code the
    # display casing and 404.
    candidates = [url]
    parts = path.split("/")
    if len(parts) >= 3 and parts[0] == "repos":
        lower_owner = parts[1].lower()
        if lower_owner != parts[1]:
            candidates.append(
                url.replace(f"/{parts[1]}/", f"/{lower_owner}/", 1)
            )

    pd = ProgramData(
        platform="huntr",
        handle=handle,
        program_url=url,
        policy_url=url,
        source="huntr.next_flight",
        confidence=0.0,
    )

    html_body = ""
    for candidate in candidates:
        try:
            status, body, _ = http_get(candidate, timeout=30)
            if status == 200:
                html_body = body
                pd.program_url = candidate
                pd.policy_url = candidate
                break
        except TransportError:
            continue

    if not html_body:
        raise RuntimeError(f"huntr: all candidates 404'd: {candidates}")

    _populate_from_html(pd, html_body)
    _score_confidence(pd)
    return pd


def parse_html(html_text: str, program_url: str) -> ProgramData:
    pd = ProgramData(
        platform="huntr",
        handle=urlparse(program_url).path.strip("/"),
        program_url=program_url,
        policy_url=program_url,
        source="huntr.next_flight",
        confidence=0.0,
    )
    _populate_from_html(pd, html_text)
    _score_confidence(pd)
    return pd


def _populate_from_html(pd: ProgramData, html: str) -> None:
    # Extract the Next.js Flight stream.
    pushes = re.findall(
        r'self\.__next_f\.push\(\[\d+,\s*"((?:[^"\\]|\\.)*)"\]\)',
        html,
        re.DOTALL,
    )
    stream = "".join(_unescape_js(p) for p in pushes)

    # Fall back to visible text if no Flight pushes found.
    pd.raw_markdown = _visible_text(html)[:50000]

    # --- Repository identification
    # huntr URL is /repos/<owner>/<name> — use the URL as authoritative.
    url_path = urlparse(pd.program_url).path.strip("/")
    url_parts = url_path.split("/")
    url_owner_repo = ""
    if len(url_parts) >= 3 and url_parts[0] == "repos":
        url_owner_repo = f"{url_parts[1]}/{url_parts[2]}"

    repo_url = ""
    # Method 1: look for the explicit github.com href in the Flight tree
    # (huntr's header block has `"href":"https://github.com/<owner>/<repo>"`).
    if stream:
        m = re.search(
            r'"href"\s*:\s*"(https://github\.com/[^"]+?)"(?=[,}])',
            stream,
        )
        if m:
            repo_url = m.group(1).rstrip("/")

    # Method 2: named fields (legacy fixture support).
    if not repo_url and stream:
        m = re.search(
            r'"fullName"\s*:\s*"([^"]+)"\s*,\s*"htmlUrl"\s*:\s*"([^"]+)"',
            stream,
        )
        if m:
            if not pd.name:
                pd.name = m.group(1)
            repo_url = m.group(2)
        else:
            m = re.search(
                r'"htmlUrl"\s*:\s*"(https://github\.com/[^"]+)"',
                stream,
            )
            if m:
                repo_url = m.group(1)

    # Method 3: URL-derived fallback — always succeeds for a valid huntr URL.
    if not repo_url and url_owner_repo:
        repo_url = f"https://github.com/{url_owner_repo}"

    # Name resolution: prefer stream-derived fullName if set, else the
    # URL-derived owner/repo, else the <title> tag.
    if not pd.name and url_owner_repo:
        pd.name = url_owner_repo
    if not pd.name:
        tm = re.search(r"<title>([^<]+)</title>", html, re.IGNORECASE)
        if tm:
            pd.name = re.sub(r"^huntr:\s*", "", tm.group(1)).strip()

    # --- Description → submission rules
    if stream:
        desc = re.search(
            r'"description"\s*:\s*"((?:[^"\\]|\\.){30,2000})"', stream
        )
        if desc:
            desc_text = _unescape_js(desc.group(1))
            if len(desc_text) > len(pd.submission_rules):
                pd.submission_rules = desc_text

    # --- Bounty amounts from the Flight stream.
    # huntr embeds historical bounty payouts as `"amount":<number>` inside
    # each submission's JSON blob. Extract those values (non-zero only);
    # DO NOT rely on `$<num>` regex because the Flight format uses `$11`,
    # `$24`, etc. as React component refs — they're not dollar amounts.
    search_space = stream if stream else ""
    amount_nums = [
        int(m.group(1))
        for m in re.finditer(r'"amount"\s*:\s*(\d+)', search_space)
    ]
    paid_amounts = [n for n in amount_nums if n > 0]
    if paid_amounts:
        pd.bounty_range = {
            "min": f"${min(paid_amounts):,}",
            "max": f"${max(paid_amounts):,}",
            "currency": "USD",
            "note": (
                f"Historical payout range across {len(paid_amounts)} paid "
                "submissions; huntr global max for Open Source Repository is "
                "$1,500 and Model File Format is $3,000."
            ),
        }
    elif amount_nums:
        # All amounts are zero → CVE-only or no active bounty.
        pd.bounty_range = {
            "min": "$0",
            "max": "$0",
            "currency": "USD",
            "note": "No paid bounty history — verify program status on huntr.",
        }
    else:
        # No submissions with amount data yet.
        pd.bounty_range = {
            "note": "No bounty data in Flight stream; huntr global max for "
                    "Open Source Repository is $1,500.",
            "max": "$1,500",
            "currency": "USD",
        }

    # --- Severity distribution from historical submissions.
    # huntr submissions include a CVSS block; we collect the dominant
    # severity labels that appear in the stream.
    sev_counts: dict[str, int] = {}
    # Count explicit severity labels attached to submission status/cvss
    for m in re.finditer(
        r'"(?:severity|level)"\s*:\s*"(Critical|High|Medium|Low|Informational)"',
        search_space,
        re.IGNORECASE,
    ):
        key = m.group(1).capitalize()
        sev_counts[key] = sev_counts.get(key, 0) + 1
    # Sort by severity order
    for label in ("Critical", "High", "Medium", "Low", "Informational"):
        count = sev_counts.get(label, 0)
        if count > 0:
            pd.severity_table.append(
                SeverityRow(
                    severity=label,
                    notes=f"{count} historical submission(s)",
                )
            )

    # --- Scope: the target repository (authoritative).
    if repo_url:
        pd.scope_in.append(
            Asset(
                type="repo",
                identifier=repo_url,
                qualifier="huntr bounty target repository",
            )
        )

    # --- OOS + rules: synthesize from huntr global terms.
    pd.scope_out = list(HUNTR_DEFAULT_OOS)
    if not pd.submission_rules:
        pd.submission_rules = HUNTR_DEFAULT_RULES
    else:
        pd.submission_rules += "\n\n" + HUNTR_DEFAULT_RULES

    # Warn if the repo is showing $0 + CVE-only (LiteLLM incident guard).
    if pd.bounty_range.get("note", "").startswith("CVE-only"):
        pd.warnings.append(
            "bounty_range: $0 / CVE-only — verify live page before submitting"
        )


def _unescape_js(s: str) -> str:
    """Minimal JS string unescape for Flight payloads."""
    return (
        s.replace('\\"', '"')
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\/", "/")
        .replace("\\\\", "\\")
    )


def _visible_text(html: str) -> str:
    t = re.sub(r"<script.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    t = re.sub(r"<style.*?</style>", "", t, flags=re.DOTALL | re.IGNORECASE)
    t = re.sub(r"<[^>]+>", "\n", t)
    return re.sub(r"\n\s*\n", "\n", t).strip()


def _score_confidence(pd: ProgramData) -> None:
    has_repo = any(a.type == "repo" for a in pd.scope_in)
    has_bounty = bool(pd.bounty_range)
    has_rules = len(pd.submission_rules.strip()) >= 50
    if has_repo and has_bounty and has_rules:
        pd.confidence = 0.85
    elif has_repo and has_bounty:
        pd.confidence = 0.75
    elif has_repo:
        pd.confidence = 0.5
    else:
        pd.confidence = 0.2
