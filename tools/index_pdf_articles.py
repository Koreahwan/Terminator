#!/usr/bin/env python3
"""
index_pdf_articles.py - Download and index document URLs into knowledge.db web_articles.

Usage:
    python3 tools/index_pdf_articles.py [--input /tmp/priority_pdfs.txt] [--max 100] [--dry-run]
"""

import argparse
import datetime
import importlib
import os
import re
import socket
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Global socket timeout to prevent hanging in uninterruptible IO
socket.setdefaulttimeout(15)

DB_PATH = Path(__file__).parent.parent / "knowledge" / "knowledge.db"
CACHE_DIR = Path("/tmp/document_cache")
CACHE_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 20  # seconds per download
MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024  # 50 MB limit

SUPPORTED_DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".docx",
    ".pptx",
    ".xlsx",
    ".xls",
    ".html",
    ".htm",
    ".csv",
    ".json",
    ".xml",
    ".txt",
    ".epub",
    ".zip",
}

CONTENT_TYPE_EXTENSIONS = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.ms-excel": ".xls",
    "text/html": ".html",
    "application/xhtml+xml": ".html",
    "text/csv": ".csv",
    "application/json": ".json",
    "text/json": ".json",
    "application/xml": ".xml",
    "text/xml": ".xml",
    "text/plain": ".txt",
    "application/epub+zip": ".epub",
    "application/zip": ".zip",
    "application/x-zip-compressed": ".zip",
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
}


def classify_domain(url: str) -> tuple[str, str]:
    """Return (domain, category) for a document URL."""
    u = url.lower()
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lstrip("www.")

    if "blackhat.com" in u:
        return domain, "conference"
    if "defcon.org" in u or re.search(r"dc\d{2}\.pdf", u):
        return domain, "conference"
    if "usenix.org" in u:
        return domain, "conference"
    if "ndss-symposium.org" in u:
        return domain, "conference"
    if "hitb" in u or "hitbsecconf" in u:
        return domain, "conference"
    if "infiltratecon.com" in u:
        return domain, "conference"
    if "offensivecon.org" in u:
        return domain, "conference"
    if "recon.cx" in u:
        return domain, "conference"
    if "zeronights.ru" in u or "zeronights.org" in u:
        return domain, "conference"
    if "syscan.org" in u:
        return domain, "conference"
    if "troopers.de" in u:
        return domain, "conference"
    if "cansecwest.com" in u:
        return domain, "conference"
    if "ekoparty.org" in u:
        return domain, "conference"
    if "papers.phrack.org" in u or "phrack.org" in u:
        return domain, "research"
    if "arxiv.org" in u:
        return domain, "research"
    if "ieee.org" in u or "ieeexplore" in u:
        return domain, "research"
    if "acm.org" in u:
        return domain, "research"
    return domain, "conference"


def extract_tags(url: str, title: str) -> str:
    """Heuristically extract tags from URL and title."""
    text = (url + " " + title).lower()
    tags = []

    keyword_map = {
        "kernel": "kernel",
        "heap": "heap",
        "overflow": "overflow",
        "buffer": "buffer-overflow",
        "rop": "rop",
        "exploit": "exploit",
        "fuzzing": "fuzzing",
        "fuzz": "fuzzing",
        "format string": "format-string",
        "use.after.free": "uaf",
        "uaf": "uaf",
        "sandbox": "sandbox",
        "escape": "sandbox-escape",
        "jit": "jit",
        "browser": "browser",
        "web": "web",
        "network": "network",
        "android": "android",
        "ios": "ios",
        "windows": "windows",
        "linux": "linux",
        "firmware": "firmware",
        "iot": "iot",
        "hardware": "hardware",
        "side.channel": "side-channel",
        "race condition": "race-condition",
        "toctou": "toctou",
        "privilege": "privesc",
        "escalation": "privesc",
        "memory": "memory",
        "type confusion": "type-confusion",
        "injection": "injection",
        "sql": "sqli",
        "xss": "xss",
        "csrf": "csrf",
        "ssrf": "ssrf",
        "rce": "rce",
        "shellcode": "shellcode",
        "ret2": "rop",
        "aslr": "aslr",
        "mitigation": "mitigation",
        "bypass": "bypass",
        "crypto": "crypto",
        "cryptography": "crypto",
        "tls": "tls",
        "ssl": "ssl",
        "reversing": "reverse-engineering",
        "decompil": "reverse-engineering",
        "ghidra": "tools",
        "ida": "tools",
        "gdb": "tools",
        "malware": "malware",
        "forensic": "forensics",
        "mobile": "mobile",
        "smm": "firmware",
        "uefi": "firmware",
        "bios": "firmware",
        "hypervisor": "hypervisor",
        "vmware": "hypervisor",
        "kvm": "hypervisor",
        "bheu": "blackhat",
        "bh-eu": "blackhat",
        "bh-us": "blackhat",
        "bh-asia": "blackhat",
        "blackhat": "blackhat",
        "defcon": "defcon",
        "usenix": "usenix",
        "ndss": "ndss",
    }

    seen = set()
    for pattern, tag in keyword_map.items():
        if pattern in text and tag not in seen:
            tags.append(tag)
            seen.add(tag)

    return ",".join(tags[:12])


def title_from_url(url: str) -> str:
    """Extract a human-readable title from the URL path."""
    path = urllib.parse.urlparse(url).path
    name = os.path.basename(path)
    # Remove extension
    name = re.sub(
        r"\.(pdf|docx|pptx|xlsx|xls|html|htm|csv|json|xml|txt|epub|zip)$",
        "",
        name,
        flags=re.IGNORECASE,
    )
    # URL decode
    name = urllib.parse.unquote(name)
    # Replace separators
    name = re.sub(r"[-_%+]+", " ", name).strip()
    # Truncate
    if len(name) > 200:
        name = name[:200]
    return name if name else url


def _normalize_content_type(raw_content_type: str) -> str:
    """Return the MIME type without charset or extra parameters."""
    return raw_content_type.split(";", 1)[0].strip().lower()


def detect_document_extension(url: str, content_type: str = "") -> str:
    """Infer a supported file extension from URL path or HTTP content-type."""
    path_suffix = Path(urllib.parse.urlparse(url).path).suffix.lower()
    if path_suffix in SUPPORTED_DOCUMENT_EXTENSIONS:
        return path_suffix

    normalized_type = _normalize_content_type(content_type)
    return CONTENT_TYPE_EXTENSIONS.get(normalized_type, "")


def download_document(url: str) -> Path | None:
    """Download a supported document to cache dir. Returns local path or None."""
    url_hash = abs(hash(url)) % (10**10)
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            content_type = resp.headers.get("Content-Type", "")
            data = resp.read(MAX_DOWNLOAD_SIZE)

        extension = detect_document_extension(url, content_type)
        if not extension and data.startswith(b"%PDF"):
            extension = ".pdf"
        if extension not in SUPPORTED_DOCUMENT_EXTENSIONS:
            return None
        if len(data) < 100:
            return None

        cache_path = CACHE_DIR / f"{url_hash}{extension}"
        if cache_path.exists() and cache_path.stat().st_size > 100:
            return cache_path
        cache_path.write_bytes(data)
        return cache_path
    except Exception:
        return None


def extract_text_pypdf(pdf_path: Path) -> str:
    """Extract text using pypdf."""
    import pypdf

    text_parts = []
    try:
        reader = pypdf.PdfReader(str(pdf_path))
        max_pages = min(len(reader.pages), 30)  # cap at 30 pages for indexing
        for page in reader.pages[:max_pages]:
            try:
                t = page.extract_text()
                if t:
                    text_parts.append(t)
            except Exception:
                pass
    except Exception:
        pass
    return "\n".join(text_parts)


def extract_text_markitdown(document_path: Path) -> str:
    """Extract Markdown using MarkItDown when the optional dependency is installed."""
    try:
        module = importlib.import_module("markitdown")
    except ImportError:
        return ""

    converter_cls = getattr(module, "MarkItDown", None)
    if converter_cls is None:
        return ""

    try:
        result = converter_cls().convert(str(document_path))
    except Exception:
        return ""

    for attr in ("text_content", "markdown", "content"):
        value = getattr(result, attr, None)
        if isinstance(value, str) and value.strip():
            return value.strip()

    if isinstance(result, str) and result.strip():
        return result.strip()

    return ""


def extract_document_text(document_path: Path) -> tuple[str, str]:
    """Extract document content, preferring Markdown-preserving backends when available."""
    content = extract_text_markitdown(document_path)
    if content:
        return content, "markitdown"

    if document_path.suffix.lower() == ".pdf":
        return extract_text_pypdf(document_path), "pypdf"

    return "", "none"


def extract_pdf_text(pdf_path: Path) -> tuple[str, str]:
    """Compatibility wrapper for the legacy PDF-only helper name."""
    return extract_document_text(pdf_path)


def already_indexed(db: sqlite3.Connection, url: str) -> bool:
    cur = db.execute("SELECT 1 FROM web_articles WHERE source_url=? LIMIT 1", (url,))
    return cur.fetchone() is not None


def insert_article(
    db: sqlite3.Connection,
    title: str,
    content: str,
    category: str,
    tags: str,
    source_url: str,
    domain: str,
) -> None:
    fetch_date = datetime.date.today().isoformat()
    db.execute(
        """INSERT INTO web_articles (title, content, category, tags, source_url, domain, fetch_date)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (title, content, category, tags, source_url, domain, fetch_date),
    )
    db.commit()


def process_url(db: sqlite3.Connection, url: str, verbose: bool = True) -> str:
    """Process a single document URL. Returns status string."""
    url = url.strip()
    if not url:
        return "skip:empty"

    if already_indexed(db, url):
        return "skip:duplicate"

    domain, category = classify_domain(url)
    raw_title = title_from_url(url)
    tags = extract_tags(url, raw_title)

    document_path = download_document(url)
    if document_path is None:
        return "fail:download"

    content, backend = extract_document_text(document_path)
    if not content or len(content) < 50:
        # Still index with minimal content (title + URL) so we know it was attempted
        content = f"[Document content extraction failed] {raw_title}\nSource: {url}"

    # Use first meaningful line as title if content is good
    title = raw_title
    if len(content) > 200:
        # Try to find a better title from first non-empty lines
        for line in content.split("\n")[:5]:
            line = line.strip()
            if 20 < len(line) < 150 and not line.startswith("%PDF"):
                title = line
                break

    insert_article(db, title, content, category, tags, source_url=url, domain=domain)
    char_count = len(content)
    return f"ok:{backend}:{char_count}chars"


def main():
    parser = argparse.ArgumentParser(description="Index supported document URLs into knowledge.db")
    parser.add_argument("--input", default="/tmp/priority_pdfs.txt", help="File with document URLs, one per line")
    parser.add_argument("--max", type=int, default=100, help="Max documents to process")
    parser.add_argument("--dry-run", action="store_true", help="Don't write to DB")
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--skip-existing", action="store_true", default=True)
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between downloads (seconds)")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    urls = [line.strip() for line in input_path.read_text().splitlines() if line.strip()]
    print(f"Loaded {len(urls)} URLs from {input_path}")
    print(f"Processing up to {args.max} documents...")
    print(f"DB: {DB_PATH}")

    db = None
    if not args.dry_run:
        db = sqlite3.connect(str(DB_PATH))

    stats = {"ok": 0, "fail": 0, "skip": 0}
    processed = 0

    for i, url in enumerate(urls):
        if processed >= args.max:
            break

        if args.dry_run:
            print(f"[DRY] {url}")
            processed += 1
            continue

        # Check duplicate before downloading
        if already_indexed(db, url):
            stats["skip"] += 1
            if args.verbose:
                print(f"[{i+1}] SKIP(dup) {url[:80]}")
            continue

        status = process_url(db, url, verbose=args.verbose)
        processed += 1

        if status.startswith("ok"):
            stats["ok"] += 1
            print(f"[{processed:3d}] OK    {status} | {url[:80]}")
        elif status.startswith("fail"):
            stats["fail"] += 1
            print(f"[{processed:3d}] FAIL  {status} | {url[:80]}")
        else:
            stats["skip"] += 1
            print(f"[{processed:3d}] SKIP  {status} | {url[:80]}")

        if args.delay > 0:
            time.sleep(args.delay)

    if db:
        db.close()

    print(f"\n=== DONE ===")
    print(f"OK: {stats['ok']}  FAIL: {stats['fail']}  SKIP: {stats['skip']}")
    print(f"Total web_articles rows added: {stats['ok']}")


if __name__ == "__main__":
    main()
