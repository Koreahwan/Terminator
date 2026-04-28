#!/usr/bin/env python3
"""Knowledge Indexer — SQLite FTS5 with BM25 ranking.

Zero-dependency Python 3.12 tool that indexes internal knowledge,
external security repos, ExploitDB, Nuclei templates, and PoC-in-GitHub
into a single searchable FTS5 database.
"""

import argparse
import csv
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from urllib.parse import unquote

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "knowledge" / "knowledge.db"
HOME = Path.home()

MAX_FILE_BYTES = 50 * 1024  # 50KB cap for large files

SCHEMA_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS techniques USING fts5(
    title, content, category, tags, vulnerability, platform,
    file_path UNINDEXED, source UNINDEXED,
    tokenize = 'porter ascii'
);

CREATE VIRTUAL TABLE IF NOT EXISTS external_techniques USING fts5(
    title, content, category, tags, platform,
    source_repo UNINDEXED, file_path UNINDEXED,
    tokenize = 'porter ascii'
);

CREATE VIRTUAL TABLE IF NOT EXISTS exploitdb USING fts5(
    exploit_id UNINDEXED, description, platform, exploit_type,
    cve_codes, tags, date_published UNINDEXED,
    tokenize = 'porter ascii'
);

CREATE VIRTUAL TABLE IF NOT EXISTS nuclei USING fts5(
    template_id UNINDEXED, name, description, severity UNINDEXED,
    tags, cve_id, cwe_id, framework,
    file_path UNINDEXED,
    tokenize = 'porter ascii'
);

CREATE VIRTUAL TABLE IF NOT EXISTS poc_github USING fts5(
    cve_id, repo_name, description, github_url UNINDEXED,
    year UNINDEXED,
    tokenize = 'porter ascii'
);

CREATE VIRTUAL TABLE IF NOT EXISTS trickest_cve USING fts5(
    cve_id, description, products, cwe, poc_urls,
    year UNINDEXED,
    tokenize = 'porter ascii'
);

CREATE VIRTUAL TABLE IF NOT EXISTS triage_objections USING fts5(
    title, content, category, tags, program, kill_reason,
    file_path UNINDEXED, source UNINDEXED,
    tokenize = 'porter ascii'
);

CREATE VIRTUAL TABLE IF NOT EXISTS web_articles USING fts5(
    title, content, category, tags, source_url UNINDEXED,
    domain, fetch_date UNINDEXED,
    tokenize = 'porter ascii'
);

CREATE TABLE IF NOT EXISTS db_metadata (key TEXT PRIMARY KEY, value TEXT);
"""


def read_file(path: Path, max_bytes: int = MAX_FILE_BYTES) -> str:
    try:
        size = path.stat().st_size
        if size > max_bytes:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read(max_bytes)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, PermissionError):
        return ""


def extract_md_title(text: str) -> str:
    for line in text.split("\n", 30):
        line = line.strip()
        if line.startswith("# "):
            return line[2:].strip()
    return ""


def extract_md_tags(text: str) -> str:
    tags = []
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith(">") and any(
            kw in stripped.lower() for kw in ("source:", "tag:", "keyword:", "technique:")
        ):
            tags.append(stripped.lstrip("> ").strip())
    return "; ".join(tags)


def category_from_filename(name: str) -> str:
    parts = name.replace(".md", "").split("_")
    if len(parts) >= 2:
        return parts[0]
    return ""


def extract_c_comment(text: str) -> str:
    m = re.search(r"/\*(.*?)\*/", text, re.DOTALL)
    if m:
        lines = m.group(1).strip().split("\n")
        return "\n".join(l.lstrip(" *") for l in lines)
    return ""


def extract_gtfobins_functions(text: str) -> str:
    funcs = re.findall(r"^functions:\s*\n((?:\s+\w+:.*\n?)+)", text, re.MULTILINE)
    if funcs:
        return funcs[0].strip()
    keys = re.findall(r"^\s+-\s+(\w+):", text, re.MULTILINE)
    return ", ".join(keys)


def split_sections(text: str) -> list[tuple[str, str]]:
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


SYNONYMS = {
    "uaf": '"use" "after" "free"',
    "bof": '"buffer" "overflow"',
    "sqli": '"sql" "injection"',
    "xss": '"cross" "site" "scripting"',
    "ssrf": '"server" "side" "request" "forgery"',
    "csrf": '"cross" "site" "request" "forgery"',
    "rce": '"remote" "code" "execution"',
    "lfi": '"local" "file" "inclusion"',
    "rfi": '"remote" "file" "inclusion"',
    "idor": '"insecure" "direct" "object" "reference"',
    "lpe": '"local" "privilege" "escalation"',
    "rop": '"return" "oriented" "programming"',
    "aslr": '"address" "space" "layout" "randomization"',
    "got": '"global" "offset" "table"',
    "plt": '"procedure" "linkage" "table"',
    "oob": '"out" "of" "bounds"',
    "bola": '"broken" "object" "level" "authorization"',
    "jwt": '"json" "web" "token"',
    "toctou": '"time" "of" "check" "time" "of" "use"',
    "xxe": '"xml" "external" "entity"',
    "ssti": '"server" "side" "template" "injection"',
    "deserialization": '"insecure" "deserialization"',
    "prototype-pollution": '"prototype" "pollution"',
    "race-condition": '"race" "condition"',
    "nosqli": '"nosql" "injection"',
    "crlf": '"crlf" "injection" OR "carriage" "return"',
    "cors": '"cross" "origin" "resource" "sharing"',
    "clickjacking": '"click" "hijacking"',
    "open-redirect": '"open" "redirect"',
    "path-traversal": '"path" "traversal" OR "directory" "traversal"',
    "cmdinjection": '"command" "injection"',
    "smm": '"system" "management" "mode"',
    "dma": '"direct" "memory" "access"',
}

STOP_WORDS = frozenset({
    "the", "a", "an", "in", "on", "for", "to", "of", "and", "or",
    "is", "it", "at", "by", "as", "be", "this", "that", "with",
    "from", "not", "are", "was", "were", "been", "has", "have",
    "but", "if", "no", "do", "so", "up", "can", "all", "its",
})


def escape_fts5(query: str) -> str:
    """Escape and preprocess query for FTS5 with synonym expansion and OR support."""
    q = query.strip()
    if not q:
        return q
    # CVE exact match
    if re.match(r'^CVE-\d{4}-\d{4,}$', q, re.IGNORECASE):
        return f'"{q}"'
    # CWE exact match
    if re.match(r'^CWE-\d+$', q, re.IGNORECASE):
        return f'"{q}"'
    # User-level OR
    if ' OR ' in q:
        parts = q.split(' OR ')
        return ' OR '.join(escape_fts5(p.strip()) for p in parts if p.strip())
    # Synonym expansion (whole-query match)
    q_lower = q.lower().strip()
    if q_lower in SYNONYMS:
        original = f'"{q_lower}"'
        expanded = SYNONYMS[q_lower]
        return f'{original} OR ({expanded})'
    # Standard tokenization
    words = re.findall(r"[\w][\w\-]*[\w]|[\w]+", q)
    if not words:
        return q
    # Per-word synonym expansion (inline)
    # Track words already covered by synonym expansions to avoid duplicates
    covered_words = set()
    expanded_words = []
    for w in words:
        w_lower = w.lower()
        if w_lower in SYNONYMS:
            # Inline synonym expansion without parens (AND context)
            expanded_words.append(SYNONYMS[w_lower])
            for syn_word in re.findall(r'"(\w+)"', SYNONYMS[w_lower]):
                covered_words.add(syn_word.lower())
        else:
            expanded_words.append(f'"{w}"')
    # Remove duplicates: drop standalone words already in a synonym expansion
    final = []
    for part in expanded_words:
        if part.startswith('"') and part.endswith('"'):
            inner = part.strip('"').lower()
            if inner in covered_words:
                continue
        final.append(part)
    return " ".join(final)


def fts5_query_variants(query: str) -> list[str]:
    """Return high-recall FTS5 query variants.

    The primary escaped query expands acronym synonyms. A literal-token fallback
    keeps acronym-bearing multi-term queries such as "idor privilege escalation"
    from losing documents that use the acronym itself in titles or headings.
    """
    variants = []
    escaped = escape_fts5(query)
    if escaped.strip():
        variants.append(escaped)

    words = re.findall(r"[\w][\w\-]*[\w]|[\w]+", query)
    if words:
        literal = " ".join(f'"{w}"' for w in words)
        if literal.strip():
            variants.append(literal)

    deduped = []
    seen = set()
    for variant in variants:
        if variant not in seen:
            deduped.append(variant)
            seen.add(variant)
    return deduped


def parse_nuclei_yaml(text: str) -> dict:
    def extract(pattern: str, txt: str) -> str:
        m = re.search(pattern, txt, re.MULTILINE)
        return m.group(1).strip() if m else ""

    tid = extract(r"^id:\s*(.+)$", text)
    name = extract(r"^\s*name:\s*(.+)$", text)
    severity = extract(r"^\s*severity:\s*(.+)$", text)
    tags = extract(r"^\s*tags:\s*(.+)$", text)
    cve_id = extract(r"^\s*cve-id:\s*(.+)$", text)
    cwe_id = extract(r"^\s*cwe-id:\s*(.+)$", text)

    desc_match = re.search(
        r"^\s*description:\s*[|>]\s*\n((?:\s{4,}.+\n?)+)", text, re.MULTILINE
    )
    description = ""
    if desc_match:
        lines = desc_match.group(1).split("\n")
        description = "\n".join(l.strip() for l in lines).strip()
    else:
        description = extract(r"^\s*description:\s*(.+)$", text)

    framework = ""
    for kw in ("wordpress", "joomla", "drupal", "apache", "nginx", "iis", "tomcat",
                "spring", "django", "flask", "rails", "laravel", "express"):
        if kw in text.lower():
            framework = kw
            break

    return {
        "template_id": tid, "name": name, "description": description,
        "severity": severity, "tags": tags, "cve_id": cve_id,
        "cwe_id": cwe_id, "framework": framework,
    }


POC_URL_NOISE_PATTERNS = {
    "ARPSyndicate", "cve-scores", "ProjectZeroDays",
    "nvd-json-data-feeds", "fkie-cad", "vulnscope",
    "cyber-ai-info", "EPSS-Scoring", "nomi-sec/PoC-in-GitHub",
}


def _filter_poc_urls(urls_str: str) -> str:
    """Remove CVE tracker/monitoring repo URLs from PoC URL lists."""
    urls = urls_str.split()
    return " ".join(u for u in urls if not any(n in u for n in POC_URL_NOISE_PATTERNS))


class KnowledgeIndexer:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    _pragma_set: set = set()  # Track which DB files have had PRAGMAs applied

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        # Performance PRAGMAs — once per DB file per process (WAL persists across connections)
        db_key = str(self.db_path)
        if db_key not in KnowledgeIndexer._pragma_set:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA mmap_size = 268435456")  # 256MB mmap
            conn.execute("PRAGMA cache_size = -64000")     # 64MB page cache
            KnowledgeIndexer._pragma_set.add(db_key)
        return conn

    def build(self):
        web_articles = self._dump_web_articles()
        if self.db_path.exists():
            self.db_path.unlink()
        conn = self._connect()
        conn.executescript(SCHEMA_SQL)
        conn.execute("BEGIN")
        t0 = time.time()

        n1 = self._index_tier1(conn)
        n2 = self._index_tier2(conn)
        n3_exp = self._index_exploitdb(conn)
        n3_nuc = self._index_nuclei(conn)
        n3_poc = self._index_poc_github(conn)
        n3_tri = self._index_tier3_trickest(conn)
        n3_obj = self._index_triage_objections(conn)
        n_web = self._restore_web_articles(conn, web_articles)

        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        conn.execute("INSERT OR REPLACE INTO db_metadata VALUES (?, ?)", ("build_timestamp", ts))
        conn.execute("INSERT OR REPLACE INTO db_metadata VALUES (?, ?)",
                     ("build_seconds", f"{time.time() - t0:.1f}"))
        conn.commit()
        conn.close()

        total = n1 + n2 + n3_exp + n3_nuc + n3_poc + n3_tri + n3_obj + n_web
        elapsed = time.time() - t0
        print(f"\n{'='*60}")
        print(f"Build complete: {total:,} rows in {elapsed:.1f}s")
        print(f"  techniques:          {n1:>8,}")
        print(f"  external_techniques: {n2:>8,}")
        print(f"  exploitdb:           {n3_exp:>8,}")
        print(f"  nuclei:              {n3_nuc:>8,}")
        print(f"  poc_github:          {n3_poc:>8,}")
        print(f"  trickest_cve:        {n3_tri:>8,}")
        print(f"  triage_objections:   {n3_obj:>8,}")
        print(f"  web_articles:        {n_web:>8,}")
        print(f"  DB size: {self.db_path.stat().st_size / (1024*1024):.1f} MB")

    def _dump_web_articles(self) -> list[tuple]:
        """Preserve fetched web articles across full rebuilds."""
        if not self.db_path.exists():
            return []
        try:
            conn = sqlite3.connect(str(self.db_path))
            rows = conn.execute(
                "SELECT title,content,category,tags,source_url,domain,fetch_date FROM web_articles"
            ).fetchall()
            conn.close()
            return [tuple(r) for r in rows]
        except sqlite3.OperationalError:
            return []

    def _restore_web_articles(self, conn: sqlite3.Connection, rows: list[tuple]) -> int:
        if not rows:
            return 0
        conn.executemany(
            "INSERT INTO web_articles (title,content,category,tags,source_url,domain,fetch_date) "
            "VALUES (?,?,?,?,?,?,?)",
            rows,
        )
        print(f"[Web] Restored web_articles — {len(rows)} docs")
        return len(rows)

    def update_internal(self):
        """Incremental re-index of internal knowledge and triage objections.

        Drops and rebuilds the techniques table for local knowledge docs, plus
        the dedicated triage_objections table used by Gate pre-checks.
        """
        if not self.db_path.exists():
            print("DB not found. Run 'build' first.")
            return
        conn = self._connect()
        t0 = time.time()
        try:
            conn.execute("BEGIN")
            conn.execute("DELETE FROM techniques")
            n = self._index_tier1(conn)
            # Also re-index triage_objections
            try:
                conn.execute("DELETE FROM triage_objections")
            except sqlite3.OperationalError:
                # Table may not exist in older DBs — create it
                conn.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS triage_objections USING fts5("
                    "title, content, category, tags, program, kill_reason, "
                    "file_path UNINDEXED, source UNINDEXED, "
                    "tokenize = 'porter ascii')"
                )
            n_triage = self._index_triage_objections(conn)
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            conn.execute("INSERT OR REPLACE INTO db_metadata VALUES (?, ?)",
                         ("last_internal_update", ts))
            conn.commit()
            print(f"Internal update: {n} docs + {n_triage} triage objections in {time.time()-t0:.2f}s")
        except Exception as e:
            conn.rollback()
            print(f"Update error: {e}", file=sys.stderr)
        finally:
            conn.close()

    def _index_tier1(self, conn: sqlite3.Connection) -> int:
        count = 0
        configs = [
            ("techniques", "techniques", ["*.md"]),
            ("challenges", "challenges", ["*.md"]),
            ("scenarios", "scenarios", ["**/*.md"]),
            ("submissions", "submissions", ["*.md"]),
            ("decisions", "decisions", ["*.md"]),
            ("sources", "sources", ["*.md"]),
            ("protocol-vulns-index", "protocol_vulns_index", ["**/*.md"]),
        ]

        for subdir, source, patterns in configs:
            dirpath = PROJECT_ROOT / "knowledge" / subdir
            if not dirpath.is_dir():
                print(f"[Tier 1] Skipping {dirpath} (not found)")
                continue
            rows = self._collect_internal_docs(dirpath, source, patterns)
            if rows:
                conn.executemany(
                    "INSERT INTO techniques (title,content,category,tags,vulnerability,platform,file_path,source) "
                    "VALUES (?,?,?,?,?,?,?,?)", rows
                )
                count += len(rows)
                print(f"[Tier 1] Indexed {dirpath.name}/ — {len(rows)} docs")

        root_rows = []
        for f in sorted((PROJECT_ROOT / "knowledge").glob("*.md")):
            text = read_file(f)
            if not text.strip():
                continue
            title = extract_md_title(text) or f.stem
            root_rows.append((title, text, "knowledge-root", extract_md_tags(text), "", "", str(f), "knowledge_root"))
        if root_rows:
            conn.executemany(
                "INSERT INTO techniques (title,content,category,tags,vulnerability,platform,file_path,source) "
                "VALUES (?,?,?,?,?,?,?,?)", root_rows
            )
            count += len(root_rows)
            print(f"[Tier 1] Indexed knowledge root — {len(root_rows)} docs")
        return count

    def _collect_internal_docs(self, dirpath: Path, source: str, patterns: list[str]) -> list[tuple]:
        rows = []
        seen: set[Path] = set()
        for pattern in patterns:
            for f in sorted(dirpath.glob(pattern)):
                if f.is_dir() or f in seen:
                    continue
                seen.add(f)
                text = read_file(f)
                if not text.strip():
                    continue
                title = extract_md_title(text) or f.stem
                category = self._internal_category(f, source)
                tags = extract_md_tags(text)
                rows.append((title, text, category, tags, "", "", str(f), source))
        return rows

    def _internal_category(self, path: Path, source: str) -> str:
        try:
            rel = path.relative_to(PROJECT_ROOT / "knowledge")
        except ValueError:
            return category_from_filename(path.name)
        parts = rel.parts
        if source == "scenarios" and len(parts) >= 2:
            return parts[1]
        if source == "protocol_vulns_index":
            if len(parts) >= 3 and parts[1] == "categories":
                return parts[2]
            return "protocol-vulns"
        if source in {"submissions", "decisions", "sources"}:
            return source
        return category_from_filename(path.name)

    def _index_triage_objections(self, conn: sqlite3.Connection) -> int:
        """Index knowledge/triage_objections/ into FTS5 for Gate pre-checks."""
        dirpath = PROJECT_ROOT / "knowledge" / "triage_objections"
        if not dirpath.is_dir():
            print("[Triage] Skipping triage_objections/ (not found)")
            return 0
        rows = []
        for f in sorted(dirpath.glob("*.md")):
            text = read_file(f)
            if not text.strip():
                continue
            title = extract_md_title(text) or f.stem
            category = category_from_filename(f.name)
            tags = extract_md_tags(text)
            # Extract program name from filename (e.g., "paradex_gate1_kill.md" → "paradex")
            stem_parts = [p for p in re.split(r"[-_]+", f.stem) if p]
            program = stem_parts[0] if stem_parts else f.stem
            # Extract kill reason from first non-heading paragraph
            kill_reason = ""
            for line in text.split("\n"):
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and len(stripped) > 20:
                    kill_reason = stripped[:300]
                    break
            rows.append((title, text, category, tags, program, kill_reason, str(f), "triage_objections"))
        if rows:
            conn.executemany(
                "INSERT INTO triage_objections (title,content,category,tags,program,kill_reason,file_path,source) "
                "VALUES (?,?,?,?,?,?,?,?)", rows
            )
            print(f"[Triage] Indexed triage_objections/ — {len(rows)} docs")
        return len(rows)

    def _index_tier2(self, conn: sqlite3.Connection) -> int:
        total = 0
        repos = self._tier2_repo_configs()
        for cfg in repos:
            path = Path(os.path.expanduser(cfg["path"]))
            if not path.is_dir():
                print(f"[Tier 2] Skipping {cfg['name']} — {path} not found")
                continue
            rows = []
            for pattern in cfg["patterns"]:
                for f in sorted(path.glob(pattern)):
                    if f.is_dir():
                        continue
                    if "workflows" in str(f) or "node_modules" in str(f) or ".git/" in str(f):
                        continue
                    text = read_file(f)
                    if not text.strip():
                        continue
                    items = cfg["extractor"](f, text, cfg)
                    rows.extend(items)
            if rows:
                conn.executemany(
                    "INSERT INTO external_techniques "
                    "(title,content,category,tags,platform,source_repo,file_path) "
                    "VALUES (?,?,?,?,?,?,?)", rows
                )
                total += len(rows)
                print(f"[Tier 2] Indexed {cfg['name']} — {len(rows)} docs")
            else:
                print(f"[Tier 2] Indexed {cfg['name']} — 0 docs")
        return total

    def _tier2_repo_configs(self) -> list[dict]:
        def _md_default(f: Path, text: str, cfg: dict) -> list[tuple]:
            title = extract_md_title(text) or f.stem
            cat = cfg.get("category_fn", lambda p: "")(f)
            tags = extract_md_tags(text)
            # Auto-split large markdown files (>10KB) into sections
            if len(text) > 10240:
                sections = split_sections(text)
                if len(sections) > 1:
                    results = []
                    for sec_title, sec_body in sections:
                        if len(sec_body.strip()) < 20:
                            continue
                        combined_title = f"{title} — {sec_title}"
                        results.append((combined_title, sec_body, cat, tags, "", cfg["name"], str(f)))
                    return results
            return [(title, text, cat, tags, "", cfg["name"], str(f))]

        def _section_split(f: Path, text: str, cfg: dict) -> list[tuple]:
            sections = split_sections(text)
            results = []
            for title, body in sections:
                if len(body.strip()) < 20:
                    continue
                results.append((title, body, cfg.get("category_fn", lambda p: "")(f),
                                "", "", cfg["name"], str(f)))
            return results

        def _c_comment(f: Path, text: str, cfg: dict) -> list[tuple]:
            comment = extract_c_comment(text)
            title = f.stem
            glibc = ""
            for part in f.parts:
                if part.startswith("glibc_"):
                    glibc = part
                    break
            cat = glibc or "heap"
            content = comment if comment else text[:2000]
            return [(title, content, cat, "heap", "", cfg["name"], str(f))]

        def _gtfobins(f: Path, text: str, cfg: dict) -> list[tuple]:
            binary = f.stem
            funcs = extract_gtfobins_functions(text)
            return [(binary, text, "gtfobins", funcs, "linux", cfg["name"], str(f))]

        def _hevd(f: Path, text: str, cfg: dict) -> list[tuple]:
            if f.suffix == ".md":
                return _md_default(f, text, cfg)
            comment = extract_c_comment(text)
            content = comment if comment else text[:3000]
            return [(f.stem, content, "windows-kernel", "", "windows", cfg["name"], str(f))]

        def _google_ctf(f: Path, text: str, cfg: dict) -> list[tuple]:
            parts = f.relative_to(Path(os.path.expanduser(cfg["path"]))).parts
            year = parts[0] if parts else ""
            chal = parts[-2] if len(parts) >= 2 else f.stem
            title = f"{year} {chal}" if year else chal
            return [(title, text, "ctf", "", "", cfg["name"], str(f))]

        def _shannon_compact(f: Path, text: str, cfg: dict) -> list[tuple]:
            """Shannon-analysis: single entry per file, 3KB cap, skip audit/benchmark."""
            str_f = str(f)
            if any(skip in str_f for skip in ("/audit-logs/", "/prompts/", "/xben-benchmark")):
                return []
            title = extract_md_title(text) or f.stem
            content = text[:3072]
            cat = cfg.get("category_fn", lambda p: "")(f)
            return [(title, content, cat, "", "", cfg["name"], str(f))]

        repos = [
            {"name": "PayloadsAllTheThings", "path": "~/PayloadsAllTheThings",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: f.parent.name,
             "extractor": _md_default},
            {"name": "CTF-All-In-One", "path": "~/tools/CTF-All-In-One",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: next((p for p in f.parts if re.match(r"^\d+", p)), ""),
             "extractor": _md_default},
            {"name": "owasp-mastg", "path": "~/tools/owasp-mastg",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "android" if "android" in str(f).lower()
                            else ("ios" if "ios" in str(f).lower() else "mobile"),
             "extractor": _md_default},
            {"name": "google-ctf", "path": "~/tools/google-ctf",
             "patterns": ["**/README.md"],
             "category_fn": lambda f: "ctf",
             "extractor": _google_ctf},
            {"name": "how2heap", "path": "~/tools/how2heap",
             "patterns": ["**/*.c"],
             "category_fn": lambda f: "heap",
             "extractor": _c_comment},
            {"name": "exploit-writeups", "path": "~/tools/exploit-writeups",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "exploit-writeup",
             "extractor": _md_default},
            {"name": "MBE", "path": "~/tools/MBE",
             "patterns": ["**/*.md", "**/*.txt"],
             "category_fn": lambda f: next((p for p in f.parts if p.startswith("lab")), "mbe"),
             "extractor": _md_default},
            {"name": "HEVD", "path": "~/tools/HEVD",
             "patterns": ["**/*.md", "**/*.c", "**/*.h"],
             "category_fn": lambda f: "windows-kernel",
             "extractor": _hevd},
            {"name": "awesome-list-systems", "path": "~/tools/awesome-list-systems",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "systems",
             "extractor": _md_default},
            {"name": "ad-exploitation", "path": "~/tools/ad-exploitation",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "active-directory",
             "extractor": _section_split},
            {"name": "linux-kernel-exploitation", "path": "~/tools/linux-kernel-exploitation",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "kernel",
             "extractor": _section_split},
            {"name": "paper_collection", "path": "~/tools/paper_collection",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "papers",
             "extractor": _md_default},
            {"name": "collisions", "path": "~/collisions",
             "patterns": ["**/*.md", "**/*.txt"],
             "category_fn": lambda f: "hash-collision",
             "extractor": _md_default},
            {"name": "HackTricks", "path": "~/tools/hacktricks",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: next(
                 (p for p in f.relative_to(Path.home() / "tools" / "hacktricks").parts
                  if p not in ("README.md", "SUMMARY.md")), "hacktricks"
             ) if str(f).startswith(str(Path.home() / "tools" / "hacktricks")) else "hacktricks",
             "extractor": _md_default},
            {"name": "GTFOBins", "path": "~/tools/GTFOBins",
             "patterns": ["_gtfobins/*"],
             "category_fn": lambda f: "gtfobins",
             "extractor": _gtfobins},
            {"name": "SecLists", "path": "~/SecLists",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: f.parent.name,
             "extractor": _md_default},
            {"name": "exploitdb-papers", "path": "~/tools/exploitdb-papers",
             "patterns": ["**/*.md", "**/*.txt"],
             "category_fn": lambda f: "exploitdb-paper",
             "extractor": _md_default},
            {"name": "google-ctf-writeups", "path": "~/tools/google-ctf-writeups",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "ctf-writeup",
             "extractor": _md_default},
            {"name": "fuzzdb", "path": "~/tools/fuzzdb",
             "patterns": ["**/*.md", "**/*.txt"],
             "category_fn": lambda f: f.parent.name,
             "extractor": _md_default},
            {"name": "IntruderPayloads", "path": "~/tools/IntruderPayloads",
             "patterns": ["**/*.txt"],
             "category_fn": lambda f: f.parent.name,
             "extractor": _md_default},
            {"name": "awesome-ctf", "path": "~/tools/awesome-ctf",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "ctf-resources",
             "extractor": _md_default},
            {"name": "awesome-ctf-resources", "path": "~/tools/awesome-ctf-resources",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "ctf-resources",
             "extractor": _md_default},
            {"name": "Awesome-CTF", "path": "~/tools/Awesome-CTF",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "ctf-resources-zh",
             "extractor": _md_default},
            # === NEW: Web / Bug Bounty ===
            {"name": "OWASP-CheatSheetSeries", "path": "~/tools/CheatSheetSeries",
             "patterns": ["cheatsheets/*.md", "cheatsheets_draft/*.md"],
             "category_fn": lambda f: "owasp-cheatsheet",
             "extractor": _md_default},
            {"name": "AllAboutBugBounty", "path": "~/tools/AllAboutBugBounty",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: f.parent.name if f.parent.name != "AllAboutBugBounty" else "bugbounty",
             "extractor": _md_default},
            {"name": "KingOfBugBountyTips", "path": "~/tools/KingOfBugBountyTips",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "bugbounty-tips",
             "extractor": _md_default},
            # === NEW: Red Team / Internal ===
            {"name": "InternalAllTheThings", "path": "~/tools/InternalAllTheThings",
             "patterns": ["docs/**/*.md"],
             "category_fn": lambda f: f.parent.name,
             "extractor": _md_default},
            {"name": "AD-Attack-Defense", "path": "~/tools/AD-Attack-Defense",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "ad-attack-defense",
             "extractor": _md_default},
            {"name": "Awesome-Cybersecurity-Handbooks", "path": "~/tools/Awesome-Cybersecurity-Handbooks",
             "patterns": ["handbooks/*.md"],
             "category_fn": lambda f: f.stem.lower(),
             "extractor": _section_split},
            # === NEW: Mobile ===
            {"name": "MobileApp-Pentest-Cheatsheet", "path": "~/tools/MobileApp-Pentest-Cheatsheet",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "mobile-pentest",
             "extractor": _md_default},
            # === NEW: Web3 / Smart Contract ===
            {"name": "smart-contract-vulnerabilities", "path": "~/tools/smart-contract-vulnerabilities",
             "patterns": ["vulnerabilities/*.md"],
             "category_fn": lambda f: "smart-contract",
             "extractor": _md_default},
            {"name": "not-so-smart-contracts", "path": "~/tools/not-so-smart-contracts",
             "patterns": ["**/README.md"],
             "category_fn": lambda f: "smart-contract",
             "extractor": _md_default},
            {"name": "solidity-security-blog", "path": "~/tools/solidity-security-blog",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "solidity-security",
             "extractor": _section_split},
            {"name": "ctf-blockchain", "path": "~/tools/ctf-blockchain",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "blockchain-ctf",
             "extractor": _md_default},
            # === NEW: Cloud ===
            {"name": "cloudgoat", "path": "~/tools/cloudgoat",
             "patterns": ["scenarios/**/README.md"],
             "category_fn": lambda f: "aws-cloud",
             "extractor": _md_default},
            # === NEW: Kernel / OS ===
            {"name": "google-security-research", "path": "~/tools/security-research",
             "patterns": ["**/*.md", "**/*.txt"],
             "category_fn": lambda f: "google-security-research",
             "extractor": _md_default},
            {"name": "CVE-2024-1086", "path": "~/tools/CVE-2024-1086",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "kernel-exploit",
             "extractor": _md_default},
            {"name": "Kernelhub", "path": "~/tools/Kernelhub",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "kernel-privesc",
             "extractor": _md_default},
            # === NEW: AI Security ===
            {"name": "llm-wiki", "path": "~/tools/llm-wiki",
             "patterns": ["**/*.md", "**/*.mdx"],
             "category_fn": lambda f: "llm-security",
             "extractor": _section_split},
            {"name": "llm-wiki-nvk", "path": "~/tools/llm-wiki-nvk",
             "patterns": ["**/*.md", "**/*.mdx"],
             "category_fn": lambda f: "agent-knowledge-wiki",
             "extractor": _section_split},
            {"name": "llm-wiki-home", "path": "~/llm-wiki",
             "patterns": ["**/*.md", "**/*.mdx"],
             "category_fn": lambda f: "llm-security",
             "extractor": _section_split},
            {"name": "prompt-injection-defenses", "path": "~/tools/prompt-injection-defenses",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "ai-security",
             "extractor": _section_split},
            # === NEW: IoT / Firmware ===
            {"name": "owasp-fstm", "path": "~/tools/owasp-fstm",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "firmware-testing",
             "extractor": _md_default},
            # === NEW: ~/tools/ previously unindexed ===
            {"name": "shannon-analysis", "path": "~/tools/shannon-analysis",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "baseband-analysis",
             "extractor": _shannon_compact},
            {"name": "NeuroSploit", "path": "~/tools/NeuroSploit",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "ai-exploit",
             "extractor": _md_default},
            {"name": "PentestGPT", "path": "~/tools/PentestGPT",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "ai-pentest",
             "extractor": _md_default},
            # === NEW: AI Security / Agent Analysis ===
            {"name": "cai-analysis", "path": "~/tools/cai-analysis",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "ai-security",
             "extractor": _md_default},
            {"name": "CyberStrikeAI", "path": "~/tools/CyberStrikeAI",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "ai-security-tools",
             "extractor": _md_default},
            {"name": "pentagi", "path": "~/tools/pentagi",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "pentest-ai",
             "extractor": _md_default},
            {"name": "awesome-android-security", "path": "~/tools/awesome-android-security",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "android-security",
             "extractor": _md_default},
            {"name": "codeql-docs", "path": "~/tools/codeql",
             "patterns": ["**/*.md"],
             "category_fn": lambda f: "codeql",
             "extractor": _md_default},
        ]
        return repos

    def _index_exploitdb(self, conn: sqlite3.Connection) -> int:
        csv_path = HOME / "exploitdb" / "files_exploits.csv"
        if not csv_path.exists():
            print(f"[Tier 3] Skipping ExploitDB — {csv_path} not found")
            return 0
        rows = []
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append((
                    row.get("id", ""),
                    row.get("description", ""),
                    row.get("platform", ""),
                    row.get("type", ""),
                    row.get("codes", ""),
                    row.get("tags", ""),
                    row.get("date_published", ""),
                ))
        if rows:
            conn.executemany(
                "INSERT INTO exploitdb (exploit_id,description,platform,exploit_type,"
                "cve_codes,tags,date_published) VALUES (?,?,?,?,?,?,?)", rows
            )
            print(f"[Tier 3] Indexed ExploitDB — {len(rows):,} exploits")
        return len(rows)

    def _index_nuclei(self, conn: sqlite3.Connection) -> int:
        dirs = [
            HOME / "nuclei-templates",
            HOME / "tools" / "nuclei-templates-ai",
        ]
        rows = []
        seen_ids = set()
        for d in dirs:
            if not d.is_dir():
                print(f"[Tier 3] Skipping nuclei — {d} not found")
                continue
            for f in d.glob("**/*.yaml"):
                if "workflows" in str(f) or ".github" in str(f):
                    continue
                text = read_file(f, max_bytes=20_000)
                if not text.strip():
                    continue
                parsed = parse_nuclei_yaml(text)
                if not parsed["template_id"] or parsed["template_id"] in seen_ids:
                    continue
                seen_ids.add(parsed["template_id"])
                rows.append((
                    parsed["template_id"], parsed["name"], parsed["description"],
                    parsed["severity"], parsed["tags"], parsed["cve_id"],
                    parsed["cwe_id"], parsed["framework"], str(f),
                ))
        if rows:
            conn.executemany(
                "INSERT INTO nuclei (template_id,name,description,severity,"
                "tags,cve_id,cwe_id,framework,file_path) VALUES (?,?,?,?,?,?,?,?,?)", rows
            )
            print(f"[Tier 3] Indexed Nuclei — {len(rows):,} templates")
        return len(rows)

    def _index_poc_github(self, conn: sqlite3.Connection) -> int:
        dirs = [
            (HOME / "PoC-in-GitHub", "v1"),
            (HOME / "tools" / "CVE-PoC-in-GitHub-v2", "v2"),
        ]
        rows = []
        seen_cves = set()
        for base, version in dirs:
            if not base.is_dir():
                print(f"[Tier 3] Skipping PoC-in-GitHub ({version}) — {base} not found")
                continue
            for f in sorted(base.glob("**/*.json")):
                if f.name.startswith(".") or f.stem == "README":
                    continue
                cve_id = f.stem
                if not cve_id.startswith("CVE-"):
                    continue
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)
                year = ""
                for part in f.parts:
                    if re.match(r"^\d{4}$", part):
                        year = part
                        break
                try:
                    data = json.loads(read_file(f, max_bytes=100_000))
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(data, list):
                    continue
                for repo in data:
                    if not isinstance(repo, dict):
                        continue
                    rows.append((
                        cve_id,
                        repo.get("full_name", repo.get("name", "")),
                        repo.get("description", "") or "",
                        repo.get("html_url", ""),
                        year,
                    ))
        if rows:
            conn.executemany(
                "INSERT INTO poc_github (cve_id,repo_name,description,github_url,year) "
                "VALUES (?,?,?,?,?)", rows
            )
            print(f"[Tier 3] Indexed PoC-in-GitHub — {len(rows):,} repos")
        return len(rows)

    def _index_tier3_trickest(self, conn: sqlite3.Connection) -> int:
        """Index ~/trickest-cve — 154K+ CVE markdown files."""
        base = HOME / "trickest-cve"
        if not base.is_dir():
            print(f"[Tier 3] Skipping trickest-cve — {base} not found")
            return 0

        # Pre-compiled regexes for speed
        re_product = re.compile(r"label=Product&message=(.+?)&")
        re_vuln = re.compile(r"label=Vulnerability&message=(.+?)&")
        re_desc_start = re.compile(r"^### Description\s*$", re.MULTILINE)
        re_poc_start = re.compile(r"^### POC\s*$", re.MULTILINE)
        re_urls = re.compile(r"https?://[^\s)>\]]+")

        MAX_READ = 5120  # 5KB per file — useful info is at the top
        BATCH_SIZE = 10_000

        rows = []
        total = 0
        file_count = 0

        # Use os.scandir for speed over glob
        year_dirs = []
        try:
            for entry in os.scandir(str(base)):
                if entry.is_dir() and re.match(r"^\d{4}$", entry.name):
                    year_dirs.append(entry)
        except OSError:
            print(f"[Tier 3] Error scanning {base}")
            return 0

        year_dirs.sort(key=lambda e: e.name)

        for year_entry in year_dirs:
            year = year_entry.name
            try:
                for fentry in os.scandir(year_entry.path):
                    if not fentry.name.startswith("CVE-") or not fentry.name.endswith(".md"):
                        continue
                    file_count += 1

                    cve_id = fentry.name[:-3]  # strip .md

                    try:
                        with open(fentry.path, "r", encoding="utf-8", errors="replace") as fh:
                            text = fh.read(MAX_READ)
                    except (OSError, PermissionError):
                        continue

                    # Extract products
                    products = ", ".join(
                        unquote(m.replace("+", " "))
                        for m in re_product.findall(text)
                    )

                    # Extract CWE/vulnerability
                    cwe = ", ".join(
                        unquote(m.replace("+", " "))
                        for m in re_vuln.findall(text)
                    )

                    # Extract description (between ### Description and ### POC)
                    description = ""
                    desc_m = re_desc_start.search(text)
                    if desc_m:
                        desc_start = desc_m.end()
                        poc_m = re_poc_start.search(text, desc_start)
                        if poc_m:
                            description = text[desc_start:poc_m.start()].strip()
                        else:
                            description = text[desc_start:].strip()

                    # Extract PoC URLs (everything after ### POC)
                    poc_urls = ""
                    poc_m2 = re_poc_start.search(text)
                    if poc_m2:
                        poc_section = text[poc_m2.end():]
                        poc_urls = _filter_poc_urls(" ".join(re_urls.findall(poc_section)))

                    rows.append((cve_id, description, products, cwe, poc_urls, year))

                    if len(rows) >= BATCH_SIZE:
                        conn.executemany(
                            "INSERT INTO trickest_cve "
                            "(cve_id,description,products,cwe,poc_urls,year) "
                            "VALUES (?,?,?,?,?,?)", rows
                        )
                        total += len(rows)
                        rows.clear()
                        print(f"[Tier 3] trickest-cve: {total:,}/{file_count:,}...")
            except OSError:
                continue

        # Flush remaining
        if rows:
            conn.executemany(
                "INSERT INTO trickest_cve "
                "(cve_id,description,products,cwe,poc_urls,year) "
                "VALUES (?,?,?,?,?,?)", rows
            )
            total += len(rows)

        print(f"[Tier 3] Indexed trickest-cve — {total:,} CVEs ({file_count:,} files)")
        return total

    VALID_TABLES = {"techniques", "external_techniques", "exploitdb", "nuclei", "poc_github", "trickest_cve", "web_articles", "triage_objections"}

    # BM25 column weights per table (column order must match CREATE VIRTUAL TABLE)
    # Higher weight = matches in that column rank higher
    BM25_WEIGHTS = {
        # techniques: title, content, category, tags, vulnerability, platform
        "techniques":           (10.0, 1.0, 5.0, 3.0, 2.0, 1.0),
        # external_techniques: title, content, category, tags, platform
        "external_techniques":  (10.0, 1.0, 5.0, 3.0, 1.0),
        # exploitdb: exploit_id, description, platform, exploit_type, cve_codes, tags
        "exploitdb":            (1.0, 5.0, 2.0, 2.0, 8.0, 3.0),
        # nuclei: template_id, name, description, severity, tags, cve_id, cwe_id, framework
        "nuclei":               (1.0, 8.0, 3.0, 1.0, 3.0, 8.0, 5.0, 1.0),
        # poc_github: cve_id, repo_name, description
        "poc_github":           (8.0, 3.0, 2.0),
        # trickest_cve: cve_id, description, products, cwe, poc_urls
        "trickest_cve":         (8.0, 3.0, 5.0, 5.0, 1.0),
        # web_articles: title, content, category, tags, domain, source_url
        "web_articles":         (10.0, 1.0, 5.0, 3.0, 2.0, 1.0),
        # triage_objections: title, content, category, tags, program, kill_reason
        "triage_objections":    (10.0, 1.0, 3.0, 3.0, 5.0, 2.0),
    }

    @staticmethod
    def _dedup_results(results: list[dict]) -> list[dict]:
        """Remove duplicate results by title+path, keeping best rank."""
        seen = set()
        deduped = []
        for r in results:
            title = (r.get("title") or r.get("description") or r.get("name") or "").strip().lower()
            path = (r.get("file_path") or r.get("github_url") or r.get("source_url") or "").strip().lower()
            # Combine title + path for dedup — same title from different files are NOT duplicates
            key = f"{title}|{path}" if path else title
            if not key or key not in seen:
                if key:
                    seen.add(key)
                deduped.append(r)
        return deduped

    def search(self, query: str, table: str = "techniques",
               category: str = "", limit: int = 5) -> list[dict]:
        if table not in self.VALID_TABLES:
            raise ValueError(f"Unknown table: {table}. Valid: {self.VALID_TABLES}")
        variants = fts5_query_variants(query)
        if not variants:
            return []
        conn = self._connect()
        try:
            # Fetch extra rows to compensate for dedup filtering
            fetch_limit = limit * 3
            # Use custom BM25 weights if defined for this table
            weights = self.BM25_WEIGHTS.get(table)
            if weights:
                weight_args = ", ".join(str(w) for w in weights)
                rank_expr = f"bm25({table}, {weight_args})"
            else:
                rank_expr = "rank"
            results = []
            for variant in variants:
                if category:
                    cat_escaped = escape_fts5(category)
                    sql = (f"SELECT *, {rank_expr} as rank FROM {table} "
                           f"WHERE {table} MATCH ? AND category MATCH ? "
                           f"ORDER BY rank LIMIT ?")
                    cur = conn.execute(sql, (variant, cat_escaped, fetch_limit))
                else:
                    sql = (f"SELECT *, {rank_expr} as rank FROM {table} "
                           f"WHERE {table} MATCH ? ORDER BY rank LIMIT ?")
                    cur = conn.execute(sql, (variant, fetch_limit))
                results.extend(dict(row) for row in cur.fetchall())
                results = self._dedup_results(results)
                if len(results) >= limit:
                    break
            results = results[:limit]
        except sqlite3.OperationalError as e:
            print(f"Search error: {e}", file=sys.stderr)
            results = []
        finally:
            conn.close()
        return results

    def search_all(self, query: str, limit: int = 10) -> list[dict]:
        TABLE_WEIGHTS = {
            "techniques": 1.5,
            "external_techniques": 1.3,
            "exploitdb": 1.0,
            "nuclei": 1.0,
            "poc_github": 1.0,
            "trickest_cve": 0.6,
            "web_articles": 1.2,
            "triage_objections": 1.1,
        }
        conn = self._connect()
        try:
            existing_tables = {
                r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '%_content' "
                    "AND name NOT LIKE '%_docsize' AND name NOT LIKE '%_config' "
                    "AND name NOT LIKE '%_data' AND name NOT LIKE '%_idx' "
                    "AND name != 'db_metadata'"
                ).fetchall()
            }
        finally:
            conn.close()
        tables = [t for t in TABLE_WEIGHTS if t in existing_tables]
        all_results = []
        for table in tables:
            results = self.search(query, table=table, limit=limit)
            if not results:
                continue
            ranks = [r.get("rank", 0) for r in results]
            min_rank = min(ranks)
            max_rank = max(ranks)
            span = max_rank - min_rank if max_rank != min_rank else 1.0
            weight = TABLE_WEIGHTS.get(table, 1.0)
            for r in results:
                r["_source_table"] = table
                normalized = (r.get("rank", 0) - min_rank) / span
                r["_normalized_rank"] = normalized / weight
            all_results.extend(results)

        # Diversity: guarantee at least 1 result per table that has results
        seen_tables = set()
        diverse = []
        remaining = []
        for r in sorted(all_results, key=lambda x: x.get("_normalized_rank", 1.0)):
            t = r["_source_table"]
            if t not in seen_tables:
                diverse.append(r)
                seen_tables.add(t)
            else:
                remaining.append(r)
        diverse.extend(remaining)
        return diverse[:limit]

    def _raw_fts_search(self, fts_query: str, table: str,
                        category: str = "", limit: int = 5) -> list[dict]:
        """Execute a pre-escaped FTS5 query string directly."""
        if table not in self.VALID_TABLES:
            raise ValueError(f"Unknown table: {table}")
        if not fts_query.strip():
            return []
        conn = self._connect()
        try:
            # Use custom BM25 weights if defined
            weights = self.BM25_WEIGHTS.get(table)
            if weights:
                weight_args = ", ".join(str(w) for w in weights)
                rank_expr = f"bm25({table}, {weight_args})"
            else:
                rank_expr = "rank"
            if category:
                cat_escaped = escape_fts5(category)
                sql = (f"SELECT *, {rank_expr} as rank FROM {table} "
                       f"WHERE {table} MATCH ? AND category MATCH ? "
                       f"ORDER BY rank LIMIT ?")
                cur = conn.execute(sql, (fts_query, cat_escaped, limit))
            else:
                sql = (f"SELECT *, {rank_expr} as rank FROM {table} "
                       f"WHERE {table} MATCH ? ORDER BY rank LIMIT ?")
                cur = conn.execute(sql, (fts_query, limit))
            results = [dict(row) for row in cur.fetchall()]
        except sqlite3.OperationalError:
            results = []
        finally:
            conn.close()
        return results

    def relaxed_search(self, query: str, table: str = "techniques",
                       category: str = "", limit: int = 5) -> tuple[list[dict], str]:
        """Search with progressive query relaxation. Returns (results, relaxation_level).

        relaxation_level: "exact" | "or" | "top_terms"
        """
        # Step 1: Try exact AND match (current behavior)
        results = self.search(query, table, category, limit)
        if results:
            return results, "exact"

        # Extract words for relaxation
        words = re.findall(r"[\w][\w\-]*[\w]|[\w]+", query)
        if len(words) <= 2:
            return results, "exact"  # Already simple, no further relaxation

        # Step 2: Convert all terms to OR (no synonym expansion — just raw words)
        or_parts = []
        for w in words:
            w_lower = w.lower()
            if w_lower in STOP_WORDS:
                continue
            or_parts.append(f'"{w}"')
        if or_parts:
            or_query = " OR ".join(or_parts)
            results = self._raw_fts_search(or_query, table, category, limit)
            if results:
                return results, "or"

        # Step 3: Keep top 3 most distinctive terms (longest words)
        distinctive = [w for w in words if w.lower() not in STOP_WORDS and len(w) > 2]
        distinctive.sort(key=lambda w: len(w), reverse=True)
        top_terms = distinctive[:3]
        if top_terms:
            subset_query = " OR ".join(f'"{w}"' for w in top_terms)
            results = self._raw_fts_search(subset_query, table, category, limit)
            if results:
                return results, "top_terms"

        return [], "no_results"

    def relaxed_search_all(self, query: str, limit: int = 10) -> tuple[list[dict], str]:
        """Search all tables with progressive relaxation. Returns (results, relaxation_level)."""
        TABLE_WEIGHTS = {
            "techniques": 1.5,
            "external_techniques": 1.3,
            "exploitdb": 1.0,
            "nuclei": 1.0,
            "poc_github": 1.0,
            "trickest_cve": 0.6,
            "web_articles": 1.2,
            "triage_objections": 1.1,
        }
        conn = self._connect()
        try:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '%_content' "
                "AND name NOT LIKE '%_docsize' AND name NOT LIKE '%_config' "
                "AND name NOT LIKE '%_data' AND name NOT LIKE '%_idx' "
                "AND name != 'db_metadata'"
            ).fetchall()]
        finally:
            conn.close()

        all_results = []
        best_level = "no_results"
        level_priority = {"exact": 0, "or": 1, "top_terms": 2, "no_results": 3}

        for table in TABLE_WEIGHTS:
            if table not in tables:
                continue
            if table not in self.VALID_TABLES:
                continue
            try:
                results, level = self.relaxed_search(query, table, limit=max(3, limit // len(TABLE_WEIGHTS)))
            except (ValueError, sqlite3.OperationalError):
                continue
            weight = TABLE_WEIGHTS.get(table, 1.0)
            for r in results:
                r["_source_table"] = table
                if "rank" in r and r["rank"] is not None:
                    r["_weighted_rank"] = r["rank"] * weight
                else:
                    r["_weighted_rank"] = 0
            all_results.extend(results)
            if level_priority.get(level, 3) < level_priority.get(best_level, 3):
                best_level = level

        # Sort by weighted rank (more negative = better in FTS5)
        all_results.sort(key=lambda r: r.get("_weighted_rank", 0))

        # Diversity: ensure at least 1 from each table that had results
        tables_with_results = {}
        for r in all_results:
            t = r["_source_table"]
            if t not in tables_with_results:
                tables_with_results[t] = r

        final = list(tables_with_results.values())
        for r in all_results:
            if r not in final:
                final.append(r)
            if len(final) >= limit:
                break

        return final[:limit], best_level

    def search_exploits(self, query: str, platform: str = "",
                        severity: str = "", limit: int = 10) -> list[dict]:
        escaped = escape_fts5(query)
        if not escaped.strip():
            return []
        conn = self._connect()
        results = []
        try:
            # exploitdb with BM25 weights
            edb_w = self.BM25_WEIGHTS.get("exploitdb", ())
            edb_rank = f"bm25(exploitdb, {', '.join(str(w) for w in edb_w)})" if edb_w else "rank"
            if platform:
                plat_escaped = escape_fts5(platform)
                sql = (f"SELECT *, {edb_rank} as rank, 'exploitdb' as _source_table FROM exploitdb "
                       "WHERE exploitdb MATCH ? AND platform MATCH ? "
                       "ORDER BY rank LIMIT ?")
                cur = conn.execute(sql, (escaped, plat_escaped, limit))
            else:
                sql = (f"SELECT *, {edb_rank} as rank, 'exploitdb' as _source_table FROM exploitdb "
                       "WHERE exploitdb MATCH ? ORDER BY rank LIMIT ?")
                cur = conn.execute(sql, (escaped, limit))
            results.extend(dict(row) for row in cur.fetchall())

            # nuclei with BM25 weights
            nuc_w = self.BM25_WEIGHTS.get("nuclei", ())
            nuc_rank = f"bm25(nuclei, {', '.join(str(w) for w in nuc_w)})" if nuc_w else "rank"
            nuc_sql = (f"SELECT *, {nuc_rank} as rank, 'nuclei' as _source_table FROM nuclei "
                       "WHERE nuclei MATCH ? ORDER BY rank LIMIT ?")
            cur = conn.execute(nuc_sql, (escaped, limit))
            nuc_rows = [dict(row) for row in cur.fetchall()]
            if severity:
                sev_lower = severity.lower()
                nuc_rows = [r for r in nuc_rows if r.get("severity", "").lower() == sev_lower]
            results.extend(nuc_rows)

            # poc_github with BM25 weights
            poc_w = self.BM25_WEIGHTS.get("poc_github", ())
            poc_rank = f"bm25(poc_github, {', '.join(str(w) for w in poc_w)})" if poc_w else "rank"
            poc_sql = (f"SELECT *, {poc_rank} as rank, 'poc_github' as _source_table FROM poc_github "
                       "WHERE poc_github MATCH ? ORDER BY rank LIMIT ?")
            cur = conn.execute(poc_sql, (escaped, limit))
            results.extend(dict(row) for row in cur.fetchall())

            # trickest_cve with BM25 weights
            tri_w = self.BM25_WEIGHTS.get("trickest_cve", ())
            tri_rank = f"bm25(trickest_cve, {', '.join(str(w) for w in tri_w)})" if tri_w else "rank"
            tri_sql = (f"SELECT *, {tri_rank} as rank, 'trickest_cve' as _source_table FROM trickest_cve "
                       "WHERE trickest_cve MATCH ? ORDER BY rank LIMIT ?")
            cur = conn.execute(tri_sql, (escaped, limit))
            results.extend(dict(row) for row in cur.fetchall())
        except sqlite3.OperationalError as e:
            print(f"Search error: {e}", file=sys.stderr)
        finally:
            conn.close()
        results.sort(key=lambda x: x.get("rank", 0))
        return results[:limit]

    def get_content(self, file_path: str, max_lines: int = 100) -> str:
        p = Path(file_path)
        if not p.exists():
            return f"File not found: {file_path}"
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= max_lines:
                        lines.append(f"\n... truncated at {max_lines} lines ...")
                        break
                    lines.append(line)
                return "".join(lines)
        except (OSError, PermissionError) as e:
            return f"Error reading {file_path}: {e}"

    def stats(self) -> dict:
        if not self.db_path.exists():
            return {"error": "Database not found. Run 'build' first."}
        conn = self._connect()
        info = {}
        for table in ["techniques", "external_techniques", "exploitdb", "nuclei", "poc_github", "trickest_cve", "web_articles", "triage_objections"]:
            try:
                cur = conn.execute(f"SELECT COUNT(*) FROM {table}")
                info[table] = cur.fetchone()[0]
            except sqlite3.OperationalError:
                info[table] = 0
        try:
            cur = conn.execute("SELECT key, value FROM db_metadata")
            for row in cur.fetchall():
                info[f"meta_{row[0]}"] = row[1]
        except sqlite3.OperationalError:
            pass
        conn.close()
        info["db_size_mb"] = f"{self.db_path.stat().st_size / (1024*1024):.1f}"
        return info


def format_results(results: list[dict], verbose: bool = False) -> str:
    if not results:
        return "No results found."
    lines = []
    for i, r in enumerate(results, 1):
        src = r.get("_source_table", "")
        rank = r.get("rank", 0)
        lines.append(f"{'─'*60}")
        lines.append(f"[{i}] ({src}) rank={rank:.2f}")

        skip_keys = {"rank", "_source_table", "content"}
        if not verbose:
            skip_keys.add("content")
        for k, v in r.items():
            if k in skip_keys:
                continue
            if v and str(v).strip():
                val = str(v)
                if len(val) > 200 and not verbose:
                    val = val[:200] + "..."
                lines.append(f"  {k}: {val}")
        if verbose and r.get("content"):
            content = str(r["content"])
            if len(content) > 500:
                content = content[:500] + "..."
            lines.append(f"  content: {content}")
    lines.append(f"{'─'*60}")
    lines.append(f"Total: {len(results)} results")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Knowledge Indexer — FTS5/BM25 search over security knowledge"
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("build", help="Full rebuild of the knowledge database")
    sub.add_parser("update-internal", help="Fast re-index of internal docs only (<1s)")

    sp_search = sub.add_parser("search", help="Search a specific table")
    sp_search.add_argument("query", help="Search query")
    sp_search.add_argument("--table", "-t", default="techniques",
                           choices=["techniques", "external_techniques",
                                    "exploitdb", "nuclei", "poc_github",
                                    "trickest_cve", "web_articles",
                                    "triage_objections"])
    sp_search.add_argument("--category", "-c", default="")
    sp_search.add_argument("--limit", "-n", type=int, default=5)
    sp_search.add_argument("--verbose", "-v", action="store_true")

    sp_all = sub.add_parser("search-all", help="Search across all tables")
    sp_all.add_argument("query", help="Search query")
    sp_all.add_argument("--limit", "-n", type=int, default=10)
    sp_all.add_argument("--verbose", "-v", action="store_true")

    sp_exp = sub.add_parser("search-exploits", help="Search exploit databases")
    sp_exp.add_argument("query", help="Search query")
    sp_exp.add_argument("--platform", "-p", default="")
    sp_exp.add_argument("--severity", "-s", default="")
    sp_exp.add_argument("--limit", "-n", type=int, default=10)
    sp_exp.add_argument("--verbose", "-v", action="store_true")

    sp_smart = sub.add_parser("smart-search", help="Relaxed search across all tables")
    sp_smart.add_argument("query")
    sp_smart.add_argument("--limit", type=int, default=10)

    sub.add_parser("stats", help="Show database statistics")

    sp_get = sub.add_parser("get", help="Get file content")
    sp_get.add_argument("file_path", help="Path to file")
    sp_get.add_argument("--lines", "-n", type=int, default=100)

    args = parser.parse_args()
    indexer = KnowledgeIndexer()

    if args.command == "build":
        indexer.build()
    elif args.command == "update-internal":
        indexer.update_internal()
    elif args.command == "search":
        results = indexer.search(args.query, table=args.table,
                                category=args.category, limit=args.limit)
        print(format_results(results, verbose=args.verbose))
    elif args.command == "search-all":
        results = indexer.search_all(args.query, limit=args.limit)
        print(format_results(results, verbose=args.verbose))
    elif args.command == "search-exploits":
        results = indexer.search_exploits(args.query, platform=args.platform,
                                          severity=args.severity, limit=args.limit)
        print(format_results(results, verbose=args.verbose))
    elif args.command == "smart-search":
        results, level = indexer.relaxed_search_all(args.query, limit=args.limit)
        print(f"Query: {args.query}")
        print(f"Relaxation: {level}")
        print(f"Results: {len(results)}")
        for i, r in enumerate(results, 1):
            table = r.get("_source_table", "?")
            title = r.get("title", r.get("name", r.get("description", "untitled")))
            if isinstance(title, str) and len(title) > 100:
                title = title[:100] + "..."
            print(f"  {i}. [{table}] {title}")
    elif args.command == "stats":
        info = indexer.stats()
        print(f"{'='*40}")
        print("Knowledge DB Statistics")
        print(f"{'='*40}")
        for k, v in info.items():
            print(f"  {k:.<30} {v}")
    elif args.command == "get":
        print(indexer.get_content(args.file_path, max_lines=args.lines))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
