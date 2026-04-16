#!/usr/bin/env python3
"""Parallel direct URL fetcher — bypasses r.jina.ai rate limits.

Fetches HTML directly from source URLs using urllib with a browser User-Agent,
converts to text via trafilatura > html2text > bs4 (whichever is available),
and indexes into the web_articles FTS5 table.

Usage:
    python3 tools/bulk_fetch_direct.py <url_file> [--workers 15]
    python3 tools/bulk_fetch_direct.py tools/awesome_hacking_urls_nomitre.txt
"""

import argparse
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Import shared helpers from knowledge_fetcher
# ---------------------------------------------------------------------------
_tools_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(_tools_dir))
from knowledge_fetcher import (
    DB_PATH,
    MAX_CONTENT_BYTES,
    _auto_tag,
    _categorize,
    _ensure_table,
    _extract_domain,
)

# ---------------------------------------------------------------------------
# HTML → text converter selection: trafilatura > html2text > bs4
# ---------------------------------------------------------------------------
_CONVERTER = None

try:
    import trafilatura  # type: ignore
    _CONVERTER = "trafilatura"
except ImportError:
    pass

if _CONVERTER is None:
    try:
        import html2text as _html2text_mod  # type: ignore
        _CONVERTER = "html2text"
    except ImportError:
        pass

if _CONVERTER is None:
    try:
        from bs4 import BeautifulSoup  # type: ignore
        _CONVERTER = "bs4"
    except ImportError:
        pass

if _CONVERTER is None:
    print("ERROR: No HTML converter found. Install one of: trafilatura, html2text, beautifulsoup4")
    sys.exit(1)

print(f"[bulk_fetch_direct] Using converter: {_CONVERTER}", flush=True)

# ---------------------------------------------------------------------------
# Browser-like headers
# ---------------------------------------------------------------------------
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "DNT": "1",
}

# Error page patterns (title and content checks)
_ERROR_TITLE_EXACT = {
    "page not found", "404", "not found", "just a moment",
    "access denied", "forbidden", "error", "captcha",
    "verify you are human", "403 forbidden", "404 not found",
    "attention required", "cloudflare",
}
_ERROR_TITLE_PARTIAL = (
    "page not found", "404", "just a moment", "not found |",
    "access denied", "forbidden", "captcha", "verify you are",
    "attention required!", "enable javascript",
)


# ---------------------------------------------------------------------------
# HTML → plain text
# ---------------------------------------------------------------------------

def _html_to_text(html: bytes, url: str) -> str:
    """Convert raw HTML bytes to plain text using best available converter."""
    if _CONVERTER == "trafilatura":
        result = trafilatura.extract(
            html,
            include_comments=False,
            include_tables=True,
            no_fallback=False,
            url=url,
        )
        return result or ""

    html_str = html.decode("utf-8", errors="replace")

    if _CONVERTER == "html2text":
        h = _html2text_mod.HTML2Text()
        h.ignore_links = False
        h.ignore_images = True
        h.ignore_emphasis = False
        h.body_width = 0
        return h.handle(html_str)

    # bs4 fallback
    soup = BeautifulSoup(html_str, "html.parser")

    # Remove script/style/nav/footer/header noise
    for tag in soup(["script", "style", "nav", "footer", "header",
                      "aside", "noscript", "form", "button"]):
        tag.decompose()

    # Try to find main article content
    article = (
        soup.find("article")
        or soup.find("main")
        or soup.find(id=re.compile(r"(content|article|post|entry)", re.I))
        or soup.find(class_=re.compile(r"(content|article|post|entry|body)", re.I))
    )
    target = article if article else soup.body or soup

    # Extract text with basic spacing
    lines = []
    for elem in target.descendants:
        if hasattr(elem, "name"):
            if elem.name in ("h1", "h2", "h3", "h4", "h5", "h6"):
                text = elem.get_text(strip=True)
                if text:
                    hashes = "#" * int(elem.name[1])
                    lines.append(f"\n{hashes} {text}\n")
            elif elem.name == "p":
                text = elem.get_text(separator=" ", strip=True)
                if text:
                    lines.append(text + "\n")
            elif elem.name == "li":
                text = elem.get_text(separator=" ", strip=True)
                if text:
                    lines.append(f"- {text}")
            elif elem.name in ("pre", "code"):
                text = elem.get_text()
                if text.strip():
                    lines.append(f"\n```\n{text}\n```\n")

    result = "\n".join(lines)
    # Collapse excessive blank lines
    result = re.sub(r"\n{4,}", "\n\n\n", result)
    return result.strip()


def _extract_title_from_html(html: bytes) -> str:
    """Extract <title> tag from raw HTML bytes."""
    # Fast regex approach — avoids full parse for speed
    m = re.search(rb"<title[^>]*>([^<]{1,200})</title>", html, re.IGNORECASE)
    if m:
        raw = m.group(1).decode("utf-8", errors="replace").strip()
        # Unescape common HTML entities
        raw = raw.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        raw = raw.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
        return raw
    return ""


def _extract_title_from_text(text: str) -> str:
    """Extract title from converted text (first H1 or first substantial line)."""
    for line in text.split("\n", 40):
        line = line.strip()
        if line.startswith("# "):
            return line[2:].strip()
    # Fallback: first non-empty line that looks like a title
    for line in text.split("\n", 20):
        line = line.strip()
        if len(line) > 10 and not line.startswith(("#", "-", "*", "```", ">")):
            return line[:120]
    return ""


def _is_error_page(title: str, text: str) -> bool:
    """Return True if this looks like an error/captcha/block page."""
    title_lower = title.lower().strip().rstrip(".!?")
    if title_lower in _ERROR_TITLE_EXACT:
        return True
    if any(p in title_lower for p in _ERROR_TITLE_PARTIAL):
        return True
    # Content-level checks for very short or challenge pages
    text_lower = text[:500].lower()
    if "verify you are human" in text_lower:
        return True
    if "enable javascript and cookies" in text_lower:
        return True
    return False


# ---------------------------------------------------------------------------
# Per-URL fetch (runs in thread)
# ---------------------------------------------------------------------------

def _fetch_one(url: str, timeout: int = 15, delay: float = 0.2) -> dict | None:
    """Fetch a single URL and return a result dict, or None on failure.

    Returns dict with keys: url, title, content, domain, category, tags, fetch_date
    or None if the URL should be skipped/errored.
    """
    time.sleep(delay)

    req = urllib.request.Request(url, headers=_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # Check Content-Type — skip binary, PDF, etc.
            ct = resp.headers.get("Content-Type", "")
            if not any(t in ct for t in ("text/html", "application/xhtml", "text/plain")):
                return {"url": url, "error": f"Non-HTML content-type: {ct}"}

            raw_bytes = resp.read(MAX_CONTENT_BYTES * 4)  # read up to 200KB raw

            # Decompress gzip/deflate if needed (urllib doesn't auto-decompress)
            encoding = resp.headers.get("Content-Encoding", "")
            if encoding == "gzip" or raw_bytes[:2] == b"\x1f\x8b":
                import gzip
                try:
                    html_bytes = gzip.decompress(raw_bytes)
                except Exception:
                    html_bytes = raw_bytes
            elif encoding == "deflate":
                import zlib
                try:
                    html_bytes = zlib.decompress(raw_bytes, -zlib.MAX_WBITS)
                except Exception:
                    html_bytes = raw_bytes
            else:
                html_bytes = raw_bytes
    except urllib.error.HTTPError as e:
        return {"url": url, "error": f"HTTP {e.code}: {e.reason}"}
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return {"url": url, "error": str(e)}

    if len(html_bytes) < 200:
        return {"url": url, "error": "Response too short"}

    # Extract title from raw HTML (fast)
    html_title = _extract_title_from_html(html_bytes)

    # Convert to text
    try:
        text = _html_to_text(html_bytes, url)
    except Exception as e:
        return {"url": url, "error": f"Conversion failed: {e}"}

    if not text or len(text.strip()) < 200:
        return {"url": url, "error": f"Text too short after conversion ({len(text)} chars)"}

    # Title: prefer HTML title tag, fallback to text extraction
    title = html_title or _extract_title_from_text(text) or url.split("/")[-1] or url

    if _is_error_page(title, text):
        return {"url": url, "error": f"Error page: {title!r}"}

    # Truncate content
    if len(text) > MAX_CONTENT_BYTES:
        text = text[:MAX_CONTENT_BYTES]

    domain = _extract_domain(url)
    category = _categorize(domain, text)
    tags = _auto_tag(text)
    fetch_date = datetime.now().strftime("%Y-%m-%d")

    return {
        "url": url,
        "title": title[:500],
        "content": text,
        "domain": domain,
        "category": category,
        "tags": tags,
        "fetch_date": fetch_date,
    }


# ---------------------------------------------------------------------------
# DB helpers (main thread only)
# ---------------------------------------------------------------------------

def _get_existing_urls(db_path: Path) -> set:
    """Return set of source_urls already in web_articles."""
    _ensure_table(db_path)
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute("SELECT source_url FROM web_articles").fetchall()
        return {r[0] for r in rows}
    finally:
        conn.close()


def _batch_insert(results: list[dict], db_path: Path) -> tuple[int, int]:
    """Insert a batch of successful results. Returns (inserted, updated)."""
    inserted = updated = 0
    conn = sqlite3.connect(str(db_path))
    try:
        for r in results:
            if "error" in r:
                continue
            cur = conn.execute(
                "SELECT rowid FROM web_articles WHERE source_url = ?", (r["url"],)
            )
            exists = cur.fetchone()
            if exists:
                conn.execute("DELETE FROM web_articles WHERE source_url = ?", (r["url"],))
                updated += 1
            else:
                inserted += 1
            conn.execute(
                "INSERT INTO web_articles "
                "(title, content, category, tags, source_url, domain, fetch_date) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (r["title"], r["content"], r["category"], r["tags"],
                 r["url"], r["domain"], r["fetch_date"]),
            )
        conn.commit()
    finally:
        conn.close()
    return inserted, updated


# ---------------------------------------------------------------------------
# Main bulk fetch
# ---------------------------------------------------------------------------

def bulk_fetch_direct(
    url_file: str,
    db_path: Path = DB_PATH,
    workers: int = 15,
    timeout: int = 15,
    delay: float = 0.2,
):
    filepath = Path(url_file)
    if not filepath.exists():
        print(f"ERROR: File not found: {url_file}")
        sys.exit(1)

    # Parse URL list
    all_urls = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(">"):
                continue
            if line.startswith("http://") or line.startswith("https://"):
                all_urls.append(line)

    print(f"Loaded {len(all_urls)} URLs from {url_file}")

    # Pre-filter already-indexed URLs
    print("Checking existing DB entries...", end=" ", flush=True)
    existing = _get_existing_urls(db_path)
    urls = [u for u in all_urls if u not in existing]
    skipped_existing = len(all_urls) - len(urls)
    print(f"done. {skipped_existing} already in DB, {len(urls)} to fetch.")

    if not urls:
        print("Nothing to fetch.")
        return

    total = len(urls)
    done = 0
    success_count = 0
    error_count = 0
    skipped_count = 0

    # Batch buffer for DB writes
    BATCH_SIZE = 20
    batch_buffer: list[dict] = []

    def flush_batch():
        nonlocal success_count
        if not batch_buffer:
            return
        ins, upd = _batch_insert(batch_buffer, db_path)
        success_count += ins + upd
        batch_buffer.clear()

    print(f"Starting parallel fetch: {workers} workers, {delay}s delay, {timeout}s timeout")
    print("-" * 70)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_url = {
            executor.submit(_fetch_one, url, timeout, delay): url
            for url in urls
        }

        for future in as_completed(future_to_url):
            url = future_to_url[future]
            done += 1

            try:
                result = future.result()
            except Exception as exc:
                result = {"url": url, "error": f"Exception: {exc}"}

            if result is None:
                result = {"url": url, "error": "None returned"}

            if "error" in result:
                error_count += 1
                err_msg = result["error"]
                # Only show non-trivial errors (skip HTTP 404 spam)
                if not err_msg.startswith("HTTP 404"):
                    print(f"  SKIP [{done}/{total}] {url[:70]} — {err_msg}")
            else:
                batch_buffer.append(result)
                tag_count = len(result["tags"].split(", ")) if result["tags"] else 0
                print(
                    f"  OK   [{done}/{total}] {result['title'][:60]} "
                    f"[{result['category']}] {len(result['content'])}B {tag_count}t"
                )

            # Batch insert every BATCH_SIZE results
            if len(batch_buffer) >= BATCH_SIZE:
                flush_batch()

            # Progress summary every 50 URLs
            if done % 50 == 0:
                print(
                    f"\n--- Progress: {done}/{total} done | "
                    f"{success_count} indexed | {error_count} errors ---\n"
                )

    # Final flush
    flush_batch()

    print("\n" + "=" * 70)
    print(
        f"Bulk fetch complete: {success_count} indexed, "
        f"{error_count} failed, {skipped_existing} pre-existing "
        f"out of {len(all_urls)} total URLs"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Direct parallel URL fetcher — no r.jina.ai rate limits"
    )
    parser.add_argument("url_file", help="Text file with URLs (one per line)")
    parser.add_argument(
        "--workers", type=int, default=15,
        help="ThreadPoolExecutor worker count (default: 15)"
    )
    parser.add_argument(
        "--timeout", type=int, default=15,
        help="Per-request timeout in seconds (default: 15)"
    )
    parser.add_argument(
        "--delay", type=float, default=0.2,
        help="Per-thread polite delay in seconds (default: 0.2)"
    )
    parser.add_argument(
        "--db", type=str, default=None,
        help="Override DB path (default: knowledge/knowledge.db)"
    )
    args = parser.parse_args()

    db_path = Path(args.db) if args.db else DB_PATH

    bulk_fetch_direct(
        url_file=args.url_file,
        db_path=db_path,
        workers=args.workers,
        timeout=args.timeout,
        delay=args.delay,
    )


if __name__ == "__main__":
    main()
