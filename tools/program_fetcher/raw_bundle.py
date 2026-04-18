"""Raw bundle capture layer — verbatim HTML dump + linked page recursion.

Runs alongside the handler's structured parse. Structured parse is good for
programmatic checks (bounty range, asset list); the raw bundle is the
authoritative substring source for verbatim enforcement
(bb_preflight.py rules-check --verbatim).

Why this exists:
- Port of Antwerp OOS x2 (2026-04-14): handler parsed outOfScopes bullets but
  missed the "verbose messages without sensitive info" rule that was in a
  non-bullet format. A raw HTML dump would have caught this with a simple grep.
- Zendesk AI-RAG N/A (2026-04-17): AI impact scope clause missed in summary.
- LiteLLM $0 (2026-04-09): bounty amount scattered across landing + sub-pages.

Design:
  targets/<target>/program_raw/
    landing.html            — exact bytes of the landing page HTTP response
    landing.md              — minimal HTML → text (preserves anchors)
    linked_<NN>__<slug>.html/.md  — depth=1 linked pages (scope/OOS/severity/...)
    bundle.md               — landing + all linked concat, grep-able
    bundle_meta.json        — manifest: URLs, sizes, fetch status, errors
    bundle_index.md         — only when bundle.md > 500KB: table of contents
    bundle_part_NN.md       — split parts when split threshold reached

All transport errors are captured in bundle_meta.json — partial captures never
silently succeed.

Stdlib only (urllib via transport). HTML→text uses a compact tag-stripper
tuned for grep-ability (no external dep on html2text/markdownify).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urldefrag, urljoin, urlparse

from .transport import TransportError, http_get


__all__ = [
    "capture",
    "html_to_text",
    "enumerate_scope_links",
    "slugify",
    "platform_hints",
    "render_by_content_type",
    "accept_for_url",
]


def accept_for_url(url: str) -> str:
    """Pick the right Accept header so JSON APIs don't return HTML fallback.

    Intigriti / YWH / many others will happily serve an HTML marketing page
    instead of the API response if Accept is text/html. This detects API-shaped
    URLs and forces JSON.
    """
    u = urlparse(url)
    host = u.netloc.lower()
    if "/api/" in u.path or u.path.endswith(".json"):
        return "application/json"
    if host.startswith("api."):
        return "application/json"
    return "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"


# Keyword regex for scope / out-of-scope / rules / severity / VRT / reward pages.
# Matches link TEXT or HREF path. Case-insensitive.
_SCOPE_KEYWORDS = re.compile(
    r"scope|exclusion|out[-_\s]?of[-_\s]?scope|known[-_\s]?issue|severity|"
    r"vrt|rating|taxonomy|reward|bounty|polic(y|ies)|rules|"
    r"eligib(le|ility)|terms|brief|impact",
    re.IGNORECASE,
)

# Default size budget. Over this, bundle.md is split into parts.
_DEFAULT_BUNDLE_SPLIT_BYTES = 500 * 1024  # 500 KB
_DEFAULT_MAX_LINKS = 20
_DEFAULT_LINK_DEPTH = 1
_DEFAULT_TIMEOUT = 25.0


# ---------------------------------------------------------------------------
# HTML → text (minimal, grep-friendly). Keeps anchor text + URL as "[text](url)".
# ---------------------------------------------------------------------------

_HTML_ENTITIES = {
    "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'",
    "&nbsp;": " ", "&#39;": "'", "&#34;": '"',
}


def html_to_text(html: str) -> str:
    """Convert HTML to compact plain text. Preserves:

    - Anchor as `[text](href)` so the link URL survives grep.
    - Bullet prefixes for `<li>` as `- ` (matches Intigriti/BC style).
    - Line boundaries at block-level close tags.
    """
    if not html:
        return ""
    # Drop script / style / comments.
    html = re.sub(r"<script\b[^>]*>.*?</script>", "", html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r"<style\b[^>]*>.*?</style>", "", html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)

    # Anchors → [text](url). href may use single or double quotes.
    def _anchor(m: re.Match) -> str:
        attrs = m.group(1) or ""
        inner = m.group(2) or ""
        href_m = re.search(r'href\s*=\s*["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        href = href_m.group(1) if href_m else ""
        text = re.sub(r"<[^>]+>", "", inner).strip()
        if not text:
            text = href
        if not href:
            return text
        return f"[{text}]({href})"

    html = re.sub(
        r"<a\b([^>]*)>(.*?)</a>",
        _anchor,
        html,
        flags=re.DOTALL | re.IGNORECASE,
    )

    # List items: prepend "- ". Must come before generic tag strip.
    html = re.sub(r"<li\b[^>]*>", "\n- ", html, flags=re.IGNORECASE)

    # Line break points.
    html = re.sub(r"<br\s*/?>", "\n", html, flags=re.IGNORECASE)
    html = re.sub(
        r"</(p|div|li|h[1-6]|tr|th|td|ul|ol|section|article|header|footer|nav|aside|details|summary|table)\b[^>]*>",
        "\n",
        html,
        flags=re.IGNORECASE,
    )

    # Strip the rest of the tags.
    text = re.sub(r"<[^>]+>", "", html)

    # Entities.
    for k, v in _HTML_ENTITIES.items():
        text = text.replace(k, v)
    text = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), text)
    text = re.sub(r"&#x([0-9a-fA-F]+);", lambda m: chr(int(m.group(1), 16)), text)

    # Normalise whitespace per line; drop empties; collapse triple+ newlines.
    lines = [ln.rstrip() for ln in text.splitlines()]
    lines = [re.sub(r"[ \t]{2,}", " ", ln) for ln in lines]
    out: list[str] = []
    blank = 0
    for ln in lines:
        if ln.strip():
            out.append(ln.lstrip())
            blank = 0
        else:
            blank += 1
            if blank <= 1:
                out.append("")
    return "\n".join(out).strip() + "\n"


# ---------------------------------------------------------------------------
# Content-type aware rendering
# ---------------------------------------------------------------------------

def render_by_content_type(body: str, content_type: str = "") -> str:
    """Render fetched body based on content-type. Keeps JSON verbatim (indented).

    JSON bodies are returned as indented JSON so scope / OOS / rules strings
    remain substring-searchable. HTML goes through `html_to_text`. Plain text
    passes through unchanged.
    """
    if not body:
        return ""
    ct = (content_type or "").lower()
    stripped = body.lstrip()[:1]
    looks_json = stripped in ("{", "[")
    if "application/json" in ct or looks_json:
        try:
            obj = json.loads(body)
            return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
        except json.JSONDecodeError:
            # Malformed JSON: save verbatim so grep still works.
            return body if body.endswith("\n") else body + "\n"
    if "text/plain" in ct or "text/markdown" in ct:
        return body if body.endswith("\n") else body + "\n"
    # Default: treat as HTML.
    return html_to_text(body)


# ---------------------------------------------------------------------------
# Platform-specific scope URL hints
# ---------------------------------------------------------------------------

def platform_hints(url: str) -> list[str]:
    """Return platform-specific verbatim sources beyond the landing page.

    These are URLs (usually JSON APIs or sibling policy pages) that carry
    authoritative scope/OOS/severity data that doesn't render in the landing
    HTML because the platform is an Angular/React SPA. Handlers already know
    about these URLs for structured parse — raw_bundle re-uses them to make
    bundle.md exhaustive.

    Only generates URLs; transport/fetch logic remains in capture().
    """
    host = urlparse(url).netloc.lower()
    path = urlparse(url).path
    hints: list[str] = []

    # Intigriti: /programs/<company>/<program> — public API JSON.
    if host.endswith("intigriti.com"):
        m = re.match(r"/programs/([^/?#]+)(?:/([^/?#]+))?", path)
        if m:
            co = m.group(1) or ""
            prog = m.group(2) or co
            hints.append(
                f"https://app.intigriti.com/api/core/public/programs/{co}/{prog}"
            )

    # HackerOne: /<handle> — policy + scopes sub-pages.
    if host.endswith("hackerone.com"):
        m = re.match(r"/([^/?#]+)", path)
        reserved = {
            "hacktivity", "opportunities", "directory", "reports", "programs",
            "bug-bounty-programs", "security", "product", "api",
        }
        if m and m.group(1) not in reserved:
            handle = m.group(1)
            hints.append(f"https://hackerone.com/{handle}/policy")
            hints.append(f"https://hackerone.com/{handle}/scopes")

    # Bugcrowd: /engagements/<slug> or /programs/<slug>.
    if host.endswith("bugcrowd.com"):
        m = re.match(r"/engagements/([^/?#]+)", path)
        if m:
            slug = m.group(1)
            hints.append(f"https://bugcrowd.com/engagements/{slug}/target_groups")
            hints.append(f"https://bugcrowd.com/engagements/{slug}/changelog")

    # YesWeHack: /programs/<slug> — public API.
    if host.endswith("yeswehack.com"):
        m = re.match(r"/programs/([^/?#]+)", path)
        if m:
            slug = m.group(1)
            hints.append(f"https://api.yeswehack.com/programs/{slug}")

    # HackenProof: /programs/<slug> — HTML only, no separate API.
    # Immunefi: /bug-bounty/<slug> — data is in __NEXT_DATA__ script tag on
    # the landing HTML itself, so no extra URL.
    # huntr: /repos/<owner>/<name> — landing already contains RSC payload.

    return hints


# ---------------------------------------------------------------------------
# Link enumeration
# ---------------------------------------------------------------------------

def enumerate_scope_links(
    html: str,
    base_url: str,
    *,
    max_links: int = _DEFAULT_MAX_LINKS,
    extra_keywords: Optional[re.Pattern] = None,
) -> list[str]:
    """Return ordered list of absolute URLs whose anchor text or path matches
    scope / exclusion / severity / rules / reward keywords.

    Same-origin only. Fragments stripped. De-duplicated, preserves insertion order.
    """
    base_host = urlparse(base_url).netloc.lower()
    hits: list[str] = []
    seen: set[str] = set()

    pattern = _SCOPE_KEYWORDS
    if extra_keywords is not None:
        # Combine via alternation.
        pattern = re.compile(
            pattern.pattern + "|" + extra_keywords.pattern,
            re.IGNORECASE,
        )

    for m in re.finditer(
        r'<a\b([^>]*)>(.*?)</a>',
        html,
        flags=re.DOTALL | re.IGNORECASE,
    ):
        attrs = m.group(1) or ""
        inner = m.group(2) or ""
        href_m = re.search(r'href\s*=\s*["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        if not href_m:
            continue
        href = href_m.group(1).strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        text = re.sub(r"<[^>]+>", "", inner).strip()
        # Match against URL path + link text + surrounding attrs (title, aria-label).
        combined = f"{href} {text} {attrs}"
        if not pattern.search(combined):
            continue
        absu, _ = urldefrag(urljoin(base_url, href))
        if not absu:
            continue
        host = urlparse(absu).netloc.lower()
        if host and host != base_host:
            continue
        if absu in seen:
            continue
        seen.add(absu)
        hits.append(absu)
        if len(hits) >= max_links:
            break
    return hits


def slugify(url: str) -> str:
    u = urlparse(url)
    path = u.path.strip("/").replace("/", "_") or "root"
    slug = re.sub(r"[^a-zA-Z0-9_.-]", "_", path)
    return (slug[:80] or "root").strip("._") or "root"


# ---------------------------------------------------------------------------
# Main capture routine
# ---------------------------------------------------------------------------

def capture(
    url: str,
    out_dir,
    *,
    depth: int = _DEFAULT_LINK_DEPTH,
    max_links: int = _DEFAULT_MAX_LINKS,
    timeout: float = _DEFAULT_TIMEOUT,
    split_bytes: int = _DEFAULT_BUNDLE_SPLIT_BYTES,
    extra_known_urls: Optional[list[str]] = None,
) -> dict:
    """Capture landing + linked scope pages into out_dir/program_raw/.

    Returns a summary dict persisted as bundle_meta.json.

    Parameters
    ----------
    url : str
        Program page URL to capture.
    out_dir : str | Path
        Target directory (usually `targets/<target>/`). A `program_raw/`
        subdirectory is created.
    depth : int
        1 = landing + 1 hop of keyword-matched links. 0 = landing only.
        2 = follow keyword links from linked pages too (experimental).
    max_links : int
        Cap per depth level.
    timeout : float
        http_get timeout seconds (per request).
    split_bytes : int
        When bundle.md exceeds this size, split into bundle_part_NN.md +
        bundle_index.md.
    extra_known_urls : list[str] | None
        Handler-supplied additional URLs known to carry scope info
        (platform-specific hints — see Story 6).

    Emits
    -----
    program_raw/landing.html
    program_raw/landing.md
    program_raw/linked_<NN>__<slug>.{html,md}       (one per followed link)
    program_raw/bundle.md                            (concat, grep-source)
    program_raw/bundle_meta.json                    (manifest)
    program_raw/bundle_part_NN.md                   (only when size > split_bytes)
    program_raw/bundle_index.md                     (only when split)
    """
    out_dir = Path(out_dir)
    raw_dir = out_dir / "program_raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    summary: dict = {
        "schema": "raw_bundle/1",
        "landing_url": url,
        "landing_status": 0,
        "landing_final_url": "",
        "landing_html_bytes": 0,
        "landing_md_bytes": 0,
        "linked_pages": [],
        "bundle_md_bytes": 0,
        "bundle_split": False,
        "bundle_parts": [],
        "errors": [],
        "depth": depth,
        "max_links": max_links,
    }

    # --- Landing ---
    # v14 (2026-04-18 codex iter 2 P1): when urllib + FlareSolverr + firecrawl
    # all return hard 403/503 (common on Bugcrowd/HackerOne/Intigriti auth-
    # gated program pages), fall through to Playwright tier 4 IMMEDIATELY
    # rather than early-returning. Without this, auth-gated targets never
    # get a bundle.md.
    try:
        status, html, resp_headers = http_get(
            url, accept=accept_for_url(url), timeout=timeout
        )
    except TransportError as e:
        summary["errors"].append({"url": url, "stage": "landing", "error": str(e)})
        # Try Playwright tier 4 immediately — we have nothing else.
        try:
            from .transport import http_get_via_playwright
            summary["landing_403_503_escalation"] = "playwright"
            pw_status, pw_html, pw_headers = http_get_via_playwright(
                url, timeout=max(timeout, 30.0),
            )
            if pw_html and len(pw_html) > 500:
                status = pw_status
                html = pw_html
                resp_headers = pw_headers
                summary["errors"].append({
                    "url": url, "stage": "landing", "error": f"recovered via playwright from: {e}",
                })
            else:
                (raw_dir / "bundle_meta.json").write_text(
                    json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
                )
                return summary
        except Exception as pw_e:
            summary["errors"].append({
                "url": url, "stage": "landing_playwright_recovery", "error": str(pw_e),
            })
            (raw_dir / "bundle_meta.json").write_text(
                json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            return summary

    summary["landing_status"] = status
    summary["landing_final_url"] = url  # transport doesn't surface redirects yet
    landing_ct = (resp_headers.get("content-type") or "").lower()
    summary["landing_content_type"] = landing_ct

    # v14 tier 4 (2026-04-18): SPA escalation. Angular/React/Vue SPAs return
    # a shell HTML with <app-root></app-root> + no visible text. html_to_text
    # of that shell is tiny vs the HTML size. If ratio is catastrophic and
    # we're hitting an HTML page (not JSON), re-fetch via Playwright so the
    # DOM is fully hydrated. Covers Intigriti / HackerOne / BC auth-gated.
    if (
        "application/json" not in landing_ct
        and html.lstrip()[:1] not in ("{", "[")
    ):
        preview_md = html_to_text(html)
        # SPA shell heuristics:
        #  H1: landing md is tiny outright
        #  H2: huge HTML but near-zero rendered text ratio
        #  H3 (v14 hardened): URL has a program identifier in the path
        #     (/programs/<X>, /engagements/<X>, /repos/<X>, /bug-bounty/<X>)
        #     but the rendered text mentions none of those identifiers —
        #     classic Angular/React shell where the real scope is loaded
        #     via XHR after auth, and anonymous fetch lands on marketing.
        path_segments = [
            seg.lower() for seg in urlparse(url).path.strip("/").split("/") if seg
        ]
        program_id_segments = [
            seg for seg in path_segments
            if seg not in {
                "programs", "program", "engagements", "engagement",
                "repos", "repo", "bug-bounty", "bounty", "bounties",
                "advisories", "rules", "scope", "policy",
            } and len(seg) >= 3
        ]
        preview_lower = preview_md.lower()
        program_id_hit = any(seg in preview_lower for seg in program_id_segments)
        is_spa_shell = (
            len(preview_md.strip()) < 500
            or (len(html) > 5000 and len(preview_md.strip()) / max(len(html), 1) < 0.01)
            or (bool(program_id_segments) and not program_id_hit)
        )
        if is_spa_shell:
            try:
                from .transport import http_get_via_playwright
                summary["spa_escalation"] = "playwright"
                pw_status, pw_html, pw_headers = http_get_via_playwright(
                    url, timeout=max(timeout, 30.0),
                )
                pw_md = html_to_text(pw_html)
                # Accept only if Playwright rendering gave us meaningfully
                # more text (2x minimum) AND does NOT look like a login /
                # bot-wall redirect.
                # v14 (codex iter 2 P1): reject if the rendered body is
                # dominated by login / "sign in" / bot-challenge markers —
                # otherwise anonymous Playwright on auth-gated programs
                # replaces the program shell with unrelated login copy.
                pw_lower = pw_md.lower()[:4000]  # check top only (forms at top)
                login_markers = (
                    "sign in", "sign-in", "sign up", "log in", "login",
                    "enter your password", "enter password", "forgot password",
                    "two-factor", "2fa", "verify your identity",
                    "cloudflare", "just a moment", "access denied",
                    "please complete the challenge", "security check",
                )
                login_hits = sum(1 for m in login_markers if m in pw_lower)
                is_login_page = login_hits >= 3  # 3+ markers = almost certainly login
                if is_login_page:
                    summary["spa_escalation_effective"] = False
                    summary["spa_escalation_rejected"] = (
                        f"login/bot-wall markers detected ({login_hits} hits)"
                    )
                elif len(pw_md.strip()) > max(len(preview_md.strip()) * 2, 500):
                    status = pw_status
                    html = pw_html
                    landing_ct = (pw_headers.get("content-type") or "text/html").lower()
                    summary["landing_content_type"] = landing_ct
                    summary["spa_escalation_effective"] = True
                else:
                    summary["spa_escalation_effective"] = False
            except Exception as e:
                summary["errors"].append({
                    "url": url, "stage": "spa_escalation", "error": str(e),
                })
                summary["spa_escalation_effective"] = False

    # Pick raw extension based on content-type so bytes land in the right
    # suffix (JSON APIs vs HTML pages). `bundle.md` is always the grep target.
    if "application/json" in landing_ct or html.lstrip()[:1] in ("{", "["):
        landing_raw_name = "landing.json"
    else:
        landing_raw_name = "landing.html"
    (raw_dir / landing_raw_name).write_text(html, encoding="utf-8")
    landing_md = render_by_content_type(html, landing_ct)
    (raw_dir / "landing.md").write_text(landing_md, encoding="utf-8")
    summary["landing_raw_file"] = landing_raw_name
    summary["landing_html_bytes"] = len(html.encode("utf-8"))
    summary["landing_md_bytes"] = len(landing_md.encode("utf-8"))

    # --- Linked pages (depth=1) ---
    collected_mds: list[tuple[str, str]] = []  # (url, md)
    visited: set[str] = {url}

    def _fetch_and_save(link_url: str, index: int) -> Optional[tuple[str, str]]:
        if link_url in visited:
            return None
        visited.add(link_url)
        try:
            s2, body2, h2_headers = http_get(
                link_url, accept=accept_for_url(link_url), timeout=timeout
            )
        except TransportError as e:
            summary["errors"].append(
                {"url": link_url, "stage": "linked", "error": str(e)}
            )
            summary["linked_pages"].append({
                "url": link_url,
                "status": 0,
                "html_bytes": 0,
                "md_bytes": 0,
                "file_stem": "",
                "error": str(e),
            })
            return None
        stem = f"linked_{index:02d}__{slugify(link_url)}"
        ct2 = (h2_headers.get("content-type") or "").lower()
        if "application/json" in ct2 or body2.lstrip()[:1] in ("{", "["):
            raw_name = f"{stem}.json"
        else:
            raw_name = f"{stem}.html"
        (raw_dir / raw_name).write_text(body2, encoding="utf-8")
        m2 = render_by_content_type(body2, ct2)
        (raw_dir / f"{stem}.md").write_text(m2, encoding="utf-8")
        summary["linked_pages"].append({
            "url": link_url,
            "status": s2,
            "content_type": ct2,
            "raw_file": raw_name,
            "html_bytes": len(body2.encode("utf-8")),
            "md_bytes": len(m2.encode("utf-8")),
            "file_stem": stem,
            "error": "",
        })
        return link_url, m2

    if depth >= 1:
        candidate_urls: list[str] = []
        # Platform-specific known URLs come FIRST (higher confidence than
        # keyword matching). Combine caller-provided + auto-detected from URL.
        auto_hints = platform_hints(url)
        for ku in (extra_known_urls or []):
            if ku and ku not in candidate_urls:
                candidate_urls.append(ku)
        for ku in auto_hints:
            if ku and ku not in candidate_urls:
                candidate_urls.append(ku)
        # Keyword-enumerated links from landing HTML (only if landing was HTML).
        if "application/json" not in landing_ct and html.lstrip()[:1] not in ("{", "["):
            for link in enumerate_scope_links(html, url, max_links=max_links):
                if link not in candidate_urls:
                    candidate_urls.append(link)
        # Cap total.
        candidate_urls = candidate_urls[:max_links]
        summary["candidate_urls"] = candidate_urls

        for i, link_url in enumerate(candidate_urls, start=1):
            result = _fetch_and_save(link_url, i)
            if result is not None:
                collected_mds.append(result)

        # Depth=2: keyword links from the already-collected linked pages.
        if depth >= 2:
            depth2_index = len(candidate_urls) + 1
            for src_url, src_md in list(collected_mds):
                # We no longer have the raw HTML of linked pages in memory;
                # re-read from disk.
                stem = next(
                    (
                        lp["file_stem"] for lp in summary["linked_pages"]
                        if lp["url"] == src_url and lp.get("file_stem")
                    ),
                    "",
                )
                if not stem:
                    continue
                html_path = raw_dir / f"{stem}.html"
                if not html_path.exists():
                    continue
                src_html = html_path.read_text(encoding="utf-8", errors="replace")
                for link in enumerate_scope_links(
                    src_html, src_url, max_links=max_links // 2
                ):
                    if link in visited:
                        continue
                    _fetch_and_save(link, depth2_index)
                    depth2_index += 1
                    if depth2_index > max_links * 2:
                        break

    # --- Bundle concat ---
    bundle_parts = [
        f"<!-- SOURCE: {url} [landing] -->",
        landing_md.rstrip(),
    ]
    for link_url, link_md in collected_mds:
        bundle_parts.append("")
        bundle_parts.append(f"<!-- SOURCE: {link_url} [linked] -->")
        bundle_parts.append(link_md.rstrip())
    bundle = "\n".join(bundle_parts) + "\n"
    bundle_bytes = bundle.encode("utf-8")
    summary["bundle_md_bytes"] = len(bundle_bytes)

    # Size budget: split if > split_bytes.
    if len(bundle_bytes) > split_bytes and split_bytes > 0:
        summary["bundle_split"] = True
        # Split by byte-approx chunks, but on line boundaries.
        lines = bundle.splitlines(keepends=True)
        parts: list[list[str]] = [[]]
        cursor = 0
        for ln in lines:
            ln_bytes = len(ln.encode("utf-8"))
            if cursor + ln_bytes > split_bytes and parts[-1]:
                parts.append([])
                cursor = 0
            parts[-1].append(ln)
            cursor += ln_bytes

        index_lines = ["# Bundle Index", "", f"- Landing: `{url}`", ""]
        for i, chunk in enumerate(parts, start=1):
            part_name = f"bundle_part_{i:02d}.md"
            (raw_dir / part_name).write_text("".join(chunk), encoding="utf-8")
            summary["bundle_parts"].append(part_name)
            index_lines.append(f"- {part_name} ({len(''.join(chunk).encode('utf-8'))} bytes)")
        (raw_dir / "bundle_index.md").write_text(
            "\n".join(index_lines) + "\n", encoding="utf-8"
        )

    # Always emit bundle.md (single concat file) even when split, so downstream
    # `rules-check --verbatim` has a single grep target.
    (raw_dir / "bundle.md").write_text(bundle, encoding="utf-8")

    # --- Meta manifest ---
    (raw_dir / "bundle_meta.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return summary
