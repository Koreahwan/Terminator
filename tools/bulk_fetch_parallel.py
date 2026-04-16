#!/usr/bin/env python3
"""Parallel bulk fetcher — fetch many URLs into knowledge DB concurrently.

Optimized for network-bound workloads:
  - ThreadPoolExecutor (10 workers) fetches via r.jina.ai in parallel
  - Per-thread 0.3s rate-limit delay (not global)
  - DB check (skip already-indexed URLs) before any fetching
  - Results queued and batch-inserted from main thread (DB-bound, sequential)

Usage:
    python3 tools/bulk_fetch_parallel.py <url_file>
    python3 tools/bulk_fetch_parallel.py <url_file> --workers 20
    python3 tools/bulk_fetch_parallel.py <url_file> --workers 5 --delay 0.5
"""

import argparse
import queue
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from threading import Lock

# Import all helpers from knowledge_fetcher — no duplication
sys.path.insert(0, str(Path(__file__).resolve().parent))
from knowledge_fetcher import (
    DB_PATH,
    MAX_CONTENT_BYTES,
    _auto_tag,
    _categorize,
    _clean_content,
    _ensure_table,
    _extract_domain,
    _extract_title,
)

# Thread-local print lock for clean output
_print_lock = Lock()


def _log(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)


def _fetch_one(url: str, delay: float) -> dict | None:
    """Fetch a single URL via r.jina.ai and return processed data dict.

    Does NOT touch the DB — returns data for batch-insert by main thread.
    Returns None on failure (with reason logged).
    Applies per-thread delay BEFORE fetching to rate-limit jina.ai.
    """
    time.sleep(delay)  # per-thread rate limit

    domain = _extract_domain(url)
    jina_url = f"https://r.jina.ai/{url}"

    try:
        req = urllib.request.Request(
            jina_url,
            headers={
                "Accept": "text/markdown",
                "User-Agent": "Terminator-Knowledge-Fetcher/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        _log(f"  FAIL [{e.code}]: {url}")
        return None
    except (urllib.error.URLError, OSError) as e:
        _log(f"  FAIL [{type(e).__name__}]: {url}")
        return None

    if not content.strip() or len(content.strip()) < 100:
        _log(f"  SKIP [too short]: {url}")
        return None

    # Reject error/challenge pages
    ERROR_TITLES = (
        "page not found", "404", "not found", "just a moment",
        "page non trouvée", "access denied", "forbidden",
        "error", "captcha", "verify you are human",
    )
    raw_title = _extract_title(content) or ""
    title_lower = raw_title.lower()
    if raw_title and raw_title.lower().strip().rstrip(".!") in ERROR_TITLES:
        _log(f"  SKIP [error page: {raw_title!r}]: {url}")
        return None
    if any(ep in title_lower for ep in ("page not found", "404", "just a moment", "not found |", "access denied")):
        _log(f"  SKIP [error page: {raw_title!r}]: {url}")
        return None

    if len(content) > MAX_CONTENT_BYTES:
        content = content[:MAX_CONTENT_BYTES]

    title = _extract_title(content) or url.split("/")[-1]
    content = _clean_content(content)

    if len(content.strip()) < 500:
        _log(f"  SKIP [thin content {len(content.strip())}c]: {url}")
        return None

    category = _categorize(domain, content)
    tags = _auto_tag(content)
    fetch_date = datetime.now().strftime("%Y-%m-%d")

    _log(f"  OK [{category}] {title[:70]}")

    return {
        "title": title,
        "content": content,
        "category": category,
        "tags": tags,
        "source_url": url,
        "domain": domain,
        "fetch_date": fetch_date,
    }


def _load_existing_urls(db_path: Path) -> set:
    """Return set of source_urls already in web_articles."""
    _ensure_table(db_path)
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute("SELECT source_url FROM web_articles").fetchall()
        return {r[0] for r in rows}
    finally:
        conn.close()


def _batch_insert(rows: list[dict], db_path: Path) -> int:
    """Insert a batch of processed article dicts. Returns count inserted."""
    if not rows:
        return 0
    conn = sqlite3.connect(str(db_path))
    inserted = 0
    try:
        for row in rows:
            conn.execute(
                "INSERT INTO web_articles "
                "(title, content, category, tags, source_url, domain, fetch_date) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    row["title"], row["content"], row["category"],
                    row["tags"], row["source_url"], row["domain"],
                    row["fetch_date"],
                ),
            )
            inserted += 1
        conn.commit()
    except sqlite3.OperationalError as e:
        _log(f"  DB ERROR during batch insert: {e}")
    finally:
        conn.close()
    return inserted


def bulk_fetch_parallel(
    url_file: str,
    db_path: Path = DB_PATH,
    workers: int = 10,
    delay: float = 0.3,
    report_every: int = 50,
) -> None:
    filepath = Path(url_file)
    if not filepath.exists():
        print(f"ERROR: File not found: {url_file}")
        sys.exit(1)

    # Parse URLs from file
    all_urls = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(">"):
                continue
            if line.startswith("http://") or line.startswith("https://"):
                all_urls.append(line)

    if not all_urls:
        print("No URLs found in file.")
        return

    print(f"Loaded {len(all_urls)} URLs from {url_file}")

    # Pre-check DB for existing URLs
    print("Checking DB for already-indexed URLs...", end=" ", flush=True)
    existing = _load_existing_urls(db_path)
    to_fetch = [u for u in all_urls if u not in existing]
    skipped_count = len(all_urls) - len(to_fetch)
    print(f"{skipped_count} already indexed, {len(to_fetch)} to fetch.")

    if not to_fetch:
        print("Nothing to fetch — all URLs already in DB.")
        return

    print(f"Starting parallel fetch: {workers} workers, {delay}s per-thread delay\n")

    t_start = time.time()
    success_count = 0
    fail_count = 0
    result_queue: queue.Queue = queue.Queue()

    # We'll track completed count for progress reporting
    completed = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_fetch_one, url, delay): url for url in to_fetch}

        pending_batch: list[dict] = []
        BATCH_SIZE = 20  # insert every 20 results

        for future in as_completed(futures):
            url = futures[future]
            completed += 1

            try:
                result = future.result()
            except Exception as e:
                _log(f"  EXCEPTION for {url}: {e}")
                result = None

            if result is not None:
                pending_batch.append(result)
                success_count += 1
            else:
                fail_count += 1

            # Batch insert when we've accumulated enough
            if len(pending_batch) >= BATCH_SIZE:
                _batch_insert(pending_batch, db_path)
                pending_batch.clear()

            # Progress report
            if completed % report_every == 0:
                elapsed = time.time() - t_start
                rate = completed / elapsed if elapsed > 0 else 0
                remaining = len(to_fetch) - completed
                eta = remaining / rate if rate > 0 else 0
                _log(
                    f"\n--- Progress: {completed}/{len(to_fetch)} "
                    f"({success_count} ok, {fail_count} fail) "
                    f"| {rate:.1f} URL/s | ETA {eta:.0f}s ---\n"
                )

        # Insert any remaining
        if pending_batch:
            _batch_insert(pending_batch, db_path)

    elapsed = time.time() - t_start
    print(f"\n{'='*60}")
    print(f"Parallel bulk fetch complete in {elapsed:.1f}s")
    print(f"  Total URLs in file : {len(all_urls)}")
    print(f"  Skipped (in DB)    : {skipped_count}")
    print(f"  Fetched            : {len(to_fetch)}")
    print(f"    Success          : {success_count}")
    print(f"    Failed           : {fail_count}")
    print(f"  Throughput         : {len(to_fetch)/elapsed:.1f} URL/s")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Parallel bulk fetcher — index many URLs into knowledge DB concurrently"
    )
    parser.add_argument("url_file", help="Text file with URLs (one per line)")
    parser.add_argument(
        "--workers", type=int, default=10,
        help="ThreadPoolExecutor workers (default: 10)"
    )
    parser.add_argument(
        "--delay", type=float, default=0.3,
        help="Per-thread delay in seconds before each fetch (default: 0.3)"
    )
    parser.add_argument(
        "--report-every", type=int, default=50,
        help="Print progress every N completed URLs (default: 50)"
    )
    args = parser.parse_args()

    bulk_fetch_parallel(
        args.url_file,
        workers=args.workers,
        delay=args.delay,
        report_every=args.report_every,
    )


if __name__ == "__main__":
    main()
