#!/usr/bin/env python3
"""Index cloned Awesome Hacking repos into the knowledge FTS5 database.

Usage:
    python3 tools/index_awesome_hacking.py [--repos-dir DIR] [--db DB] [--reset]

Inserts into the `external_techniques` table:
    (title, content, category, tags, platform, source_repo, file_path)
"""

import argparse
import os
import re
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "knowledge" / "knowledge.db"
DEFAULT_REPOS_DIR = Path.home() / "awesome-hacking-repos"

MAX_FILE_BYTES = 80 * 1024  # 80 KB per file
BATCH_SIZE = 500

# Files to always skip (case-insensitive stem match)
SKIP_STEMS = frozenset({
    "license", "licence", "contributing", "code_of_conduct",
    "codeofconduct", "changelog", "changelog.md", "authors",
    "contributors", "security", "todo", "makefile",
})

# Directory segments that mean "skip everything inside"
SKIP_DIRS = frozenset({
    ".github", "node_modules", "vendor", "test", "tests",
    "__pycache__", ".git", "dist", "build",
})

# Repos to skip entirely (already in knowledge DB via other sources)
SKIP_REPOS = frozenset({
    "trickest_cve",  # 155K CVEs already in knowledge-fts trickest-cve table
})

# Only index files with these extensions
ALLOWED_EXTENSIONS = frozenset({".md", ".txt", ".rst"})

# Subdirectories that are useful doc locations (checked as path components)
USEFUL_SUBDIRS = frozenset({"docs", "doc", "wiki", "guides", "cheatsheets", "notes"})


def read_file(path: Path, max_bytes: int = MAX_FILE_BYTES) -> str:
    try:
        size = path.stat().st_size
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(min(size, max_bytes))
    except (OSError, PermissionError):
        return ""


def extract_md_title(text: str) -> str:
    for line in text.split("\n", 30):
        line = line.strip()
        if line.startswith("# "):
            return line[2:].strip()
    return ""


def extract_md_tags(text: str) -> str:
    """Pull tag/keyword lines from markdown front-matter style comments."""
    tags = []
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith(">") and any(
            kw in stripped.lower() for kw in ("source:", "tag:", "keyword:", "technique:")
        ):
            tags.append(stripped.lstrip("> ").strip())
    return "; ".join(tags)


def split_sections(text: str) -> list[tuple[str, str]]:
    """Split markdown into (section_title, body) pairs at ## headings."""
    sections = []
    parts = re.split(r"^(## .+)$", text, flags=re.MULTILINE)
    if len(parts) < 3:
        title = extract_md_title(text) or "untitled"
        return [(title, text)]
    if parts[0].strip():
        sections.append((extract_md_title(parts[0]) or "intro", parts[0]))
    for i in range(1, len(parts) - 1, 2):
        header = parts[i].lstrip("# ").strip()
        body = parts[i + 1] if i + 1 < len(parts) else ""
        sections.append((header, body))
    return sections


def derive_category(repo_dir_name: str) -> str:
    """Derive a category from the org_repo directory name."""
    name = repo_dir_name.lower()
    # Strip org prefix (first segment before underscore is org name, rest is repo name)
    parts = name.split("_", 1)
    repo_slug = parts[1] if len(parts) > 1 else parts[0]

    # Keyword → category mapping (order matters: more specific first)
    rules = [
        ("ctf", "ctf"),
        ("reverse", "reverse-engineering"),
        ("malware", "malware"),
        ("forensic", "forensics"),
        ("mobile", "mobile"),
        ("android", "mobile"),
        ("ios", "mobile"),
        ("web3", "web3"),
        ("defi", "web3"),
        ("blockchain", "web3"),
        ("smart-contract", "web3"),
        ("bug-bounty", "bug-bounty"),
        ("bugbounty", "bug-bounty"),
        ("pentest", "pentest"),
        ("exploit", "exploitation"),
        ("rop", "exploitation"),
        ("pwn", "exploitation"),
        ("heap", "exploitation"),
        ("kernel", "kernel"),
        ("linux", "linux"),
        ("windows", "windows"),
        ("network", "network"),
        ("pcap", "network"),
        ("rtc", "network"),
        ("wifi", "network"),
        ("web", "web"),
        ("http", "web"),
        ("owasp", "web"),
        ("cloud", "cloud"),
        ("aws", "cloud"),
        ("azure", "cloud"),
        ("devsecops", "devsecops"),
        ("defense", "defense"),
        ("detection", "defense"),
        ("osint", "osint"),
        ("threat", "threat-intel"),
        ("wordlist", "wordlists"),
        ("seclist", "wordlists"),
        ("fuzz", "fuzzing"),
        ("hacking", "hacking"),
        ("security", "security"),
    ]
    for kw, cat in rules:
        if kw in repo_slug:
            return cat
    return "hacking"


def github_url_for(repo_dir_name: str, rel_path: str) -> str:
    """Construct a best-effort GitHub URL from org_repo dir name and relative path."""
    parts = repo_dir_name.split("_", 1)
    if len(parts) == 2:
        org, repo = parts[0], parts[1]
    else:
        org, repo = "unknown", parts[0]
    return f"https://github.com/{org}/{repo}/blob/main/{rel_path}"


def should_skip_path(path: Path, repo_root: Path) -> bool:
    """Return True if this path should be skipped."""
    rel = path.relative_to(repo_root)
    parts = rel.parts

    # Skip hidden/blacklisted directory segments in the path
    for part in parts[:-1]:  # directory components only
        if part in SKIP_DIRS or part.startswith("."):
            return True

    stem_lower = path.stem.lower()
    if stem_lower in SKIP_STEMS:
        return True

    # Only allowed extensions
    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        return True

    return False


def is_useful_doc(path: Path, repo_root: Path) -> bool:
    """
    Accept ALL .md/.txt/.rst files that passed should_skip_path().
    The skip filter already excludes junk (LICENSE, .github, node_modules, etc).
    Remaining files are content worth indexing.

    Only exclude: locale variants (*.zh-cn.md, *.ja.md, etc.) to avoid duplicates.
    """
    stem_lower = path.stem.lower()

    # Skip non-English locale variants (keep English README.md, skip README.zh-cn.md)
    if re.search(r'\.(zh-cn|zh-tw|ja|ko|ru|fr|de|es|pt|it|ar|vi|th|id|tr|pl)$', stem_lower):
        return False

    return True


def collect_files(repo_root: Path) -> list[Path]:
    """
    Walk the repo and return files to index:
    - README.md always
    - Other .md/.txt/.rst in docs/wiki/root if they pass filters
    """
    files = []
    for f in sorted(repo_root.rglob("*")):
        if not f.is_file():
            continue
        if should_skip_path(f, repo_root):
            continue
        if is_useful_doc(f, repo_root):
            files.append(f)
    return files


def build_rows(repo_root: Path, repo_dir_name: str) -> list[tuple]:
    """Return list of (title, content, category, tags, platform, source_repo, file_path) tuples."""
    category = derive_category(repo_dir_name)
    rows = []

    for f in collect_files(repo_root):
        text = read_file(f)
        if not text.strip():
            continue

        rel = str(f.relative_to(repo_root))
        source_repo = github_url_for(repo_dir_name, rel)
        file_path = str(f)
        tags = extract_md_tags(text)
        base_title = extract_md_title(text) or f.stem

        # Split large files into sections for better search granularity
        if len(text) > 10240:
            sections = split_sections(text)
            if len(sections) > 1:
                for sec_title, sec_body in sections:
                    if len(sec_body.strip()) < 30:
                        continue
                    combined = f"{base_title} — {sec_title}"
                    rows.append((combined, sec_body, category, tags, "", source_repo, file_path))
                continue

        rows.append((base_title, text, category, tags, "", source_repo, file_path))

    return rows


def get_indexed_repos(conn: sqlite3.Connection) -> set[str]:
    """Return set of source_repo prefixes already indexed (by repo base URL)."""
    try:
        cur = conn.execute(
            "SELECT DISTINCT source_repo FROM external_techniques WHERE source_repo LIKE 'https://github.com/%'"
        )
        repos = set()
        for (url,) in cur.fetchall():
            # Extract org/repo from URL: https://github.com/org/repo/blob/...
            m = re.match(r"https://github\.com/([^/]+/[^/]+)/", url)
            if m:
                repos.add(m.group(1).lower())
        return repos
    except sqlite3.OperationalError:
        return set()


def ensure_table(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS external_techniques USING fts5(
            title, content, category, tags, platform,
            source_repo UNINDEXED, file_path UNINDEXED,
            tokenize = 'porter ascii'
        )
    """)
    conn.commit()


def index_repos(repos_dir: Path, db_path: Path, reset: bool = False, force: bool = False) -> None:
    if not repos_dir.is_dir():
        print(f"Error: repos dir not found: {repos_dir}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    ensure_table(conn)

    if reset:
        # Delete only awesome-hacking rows (identified by github.com source)
        conn.execute(
            "DELETE FROM external_techniques WHERE source_repo LIKE 'https://github.com/%'"
        )
        conn.commit()
        print("[reset] Cleared existing awesome-hacking entries.")
        already_indexed: set[str] = set()
    else:
        already_indexed = get_indexed_repos(conn) if not force else set()

    repo_dirs = sorted(
        d for d in repos_dir.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    )

    total_rows = 0
    skipped = 0
    processed = 0

    for repo_dir in repo_dirs:
        repo_dir_name = repo_dir.name

        # Derive org/repo key to check idempotency
        parts = repo_dir_name.split("_", 1)
        if len(parts) == 2:
            org_repo_key = f"{parts[0]}/{parts[1]}".lower()
        else:
            org_repo_key = parts[0].lower()

        if repo_dir_name in SKIP_REPOS:
            print(f"  [skip] {repo_dir_name} — in SKIP_REPOS (already in DB via other source)")
            skipped += 1
            continue

        if org_repo_key in already_indexed and not force:
            skipped += 1
            continue

        rows = build_rows(repo_dir, repo_dir_name)
        if not rows:
            print(f"  [skip] {repo_dir_name} — no indexable files")
            continue

        # Batch insert
        for i in range(0, len(rows), BATCH_SIZE):
            batch = rows[i : i + BATCH_SIZE]
            conn.executemany(
                "INSERT INTO external_techniques "
                "(title,content,category,tags,platform,source_repo,file_path) "
                "VALUES (?,?,?,?,?,?,?)",
                batch,
            )
        conn.commit()

        total_rows += len(rows)
        processed += 1
        print(f"  [ok] {repo_dir_name} — {len(rows)} docs (category: {derive_category(repo_dir_name)})")

    conn.close()

    print(f"\n{'='*60}")
    print(f"Done. Processed: {processed} repos, Skipped (already indexed): {skipped}")
    print(f"Total rows inserted: {total_rows:,}")
    print(f"DB: {db_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Index Awesome Hacking repos into knowledge FTS5 DB")
    parser.add_argument("--repos-dir", default=str(DEFAULT_REPOS_DIR),
                        help=f"Path to cloned repos (default: {DEFAULT_REPOS_DIR})")
    parser.add_argument("--db", default=str(DB_PATH),
                        help=f"Path to knowledge.db (default: {DB_PATH})")
    parser.add_argument("--reset", action="store_true",
                        help="Delete existing awesome-hacking entries before re-indexing")
    parser.add_argument("--force", action="store_true",
                        help="Re-index even repos already present in DB")
    args = parser.parse_args()

    repos_dir = Path(args.repos_dir)
    db_path = Path(args.db)

    print(f"Repos dir : {repos_dir}")
    print(f"DB        : {db_path}")
    print(f"Reset     : {args.reset}")
    print(f"Force     : {args.force}")
    print()

    index_repos(repos_dir, db_path, reset=args.reset, force=args.force)


if __name__ == "__main__":
    main()
