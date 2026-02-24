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


def escape_fts5(query: str) -> str:
    # Preserve hyphens for CVE-style identifiers (CVE-2021-44228)
    words = re.findall(r"[\w][\w\-]*[\w]|[\w]+", query)
    if not words:
        return query
    return " ".join(f'"{w}"' for w in words)


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


class KnowledgeIndexer:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def build(self):
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

        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        conn.execute("INSERT OR REPLACE INTO db_metadata VALUES (?, ?)", ("build_timestamp", ts))
        conn.execute("INSERT OR REPLACE INTO db_metadata VALUES (?, ?)",
                     ("build_seconds", f"{time.time() - t0:.1f}"))
        conn.commit()
        conn.close()

        total = n1 + n2 + n3_exp + n3_nuc + n3_poc
        elapsed = time.time() - t0
        print(f"\n{'='*60}")
        print(f"Build complete: {total:,} rows in {elapsed:.1f}s")
        print(f"  techniques:          {n1:>8,}")
        print(f"  external_techniques: {n2:>8,}")
        print(f"  exploitdb:           {n3_exp:>8,}")
        print(f"  nuclei:              {n3_nuc:>8,}")
        print(f"  poc_github:          {n3_poc:>8,}")
        print(f"  DB size: {self.db_path.stat().st_size / (1024*1024):.1f} MB")

    def _index_tier1(self, conn: sqlite3.Connection) -> int:
        count = 0
        for subdir, source in [("techniques", "techniques"), ("challenges", "challenges")]:
            dirpath = PROJECT_ROOT / "knowledge" / subdir
            if not dirpath.is_dir():
                print(f"[Tier 1] Skipping {dirpath} (not found)")
                continue
            rows = []
            for f in sorted(dirpath.glob("*.md")):
                text = read_file(f)
                if not text.strip():
                    continue
                title = extract_md_title(text) or f.stem
                category = category_from_filename(f.name)
                tags = extract_md_tags(text)
                vuln = ""
                platform = ""
                rows.append((title, text, category, tags, vuln, platform, str(f), source))
            if rows:
                conn.executemany(
                    "INSERT INTO techniques (title,content,category,tags,vulnerability,platform,file_path,source) "
                    "VALUES (?,?,?,?,?,?,?,?)", rows
                )
                count += len(rows)
                print(f"[Tier 1] Indexed {dirpath.name}/ — {len(rows)} docs")
        return count

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

    VALID_TABLES = {"techniques", "external_techniques", "exploitdb", "nuclei", "poc_github"}

    def search(self, query: str, table: str = "techniques",
               category: str = "", limit: int = 5) -> list[dict]:
        if table not in self.VALID_TABLES:
            raise ValueError(f"Unknown table: {table}. Valid: {self.VALID_TABLES}")
        escaped = escape_fts5(query)
        if not escaped.strip():
            return []
        conn = self._connect()
        try:
            if category:
                cat_escaped = escape_fts5(category)
                sql = (f"SELECT *, rank FROM {table} "
                       f"WHERE {table} MATCH ? AND category MATCH ? "
                       f"ORDER BY rank LIMIT ?")
                cur = conn.execute(sql, (escaped, cat_escaped, limit))
            else:
                sql = (f"SELECT *, rank FROM {table} "
                       f"WHERE {table} MATCH ? ORDER BY rank LIMIT ?")
                cur = conn.execute(sql, (escaped, limit))
            results = [dict(row) for row in cur.fetchall()]
        except sqlite3.OperationalError as e:
            print(f"Search error: {e}", file=sys.stderr)
            results = []
        finally:
            conn.close()
        return results

    def search_all(self, query: str, limit: int = 10) -> list[dict]:
        tables = ["techniques", "external_techniques", "exploitdb", "nuclei", "poc_github"]
        all_results = []
        for table in tables:
            results = self.search(query, table=table, limit=limit)
            for r in results:
                r["_source_table"] = table
            all_results.extend(results)
        # FTS5 BM25 rank is negative; ascending sort puts best matches first
        all_results.sort(key=lambda x: x.get("rank", 0))
        return all_results[:limit]

    def search_exploits(self, query: str, platform: str = "",
                        severity: str = "", limit: int = 10) -> list[dict]:
        escaped = escape_fts5(query)
        if not escaped.strip():
            return []
        conn = self._connect()
        results = []
        try:
            if platform:
                plat_escaped = escape_fts5(platform)
                sql = ("SELECT *, rank, 'exploitdb' as _source_table FROM exploitdb "
                       "WHERE exploitdb MATCH ? AND platform MATCH ? "
                       "ORDER BY rank LIMIT ?")
                cur = conn.execute(sql, (escaped, plat_escaped, limit))
            else:
                sql = ("SELECT *, rank, 'exploitdb' as _source_table FROM exploitdb "
                       "WHERE exploitdb MATCH ? ORDER BY rank LIMIT ?")
                cur = conn.execute(sql, (escaped, limit))
            results.extend(dict(row) for row in cur.fetchall())

            nuc_sql = ("SELECT *, rank, 'nuclei' as _source_table FROM nuclei "
                       "WHERE nuclei MATCH ? ORDER BY rank LIMIT ?")
            cur = conn.execute(nuc_sql, (escaped, limit))
            nuc_rows = [dict(row) for row in cur.fetchall()]
            if severity:
                sev_lower = severity.lower()
                nuc_rows = [r for r in nuc_rows if r.get("severity", "").lower() == sev_lower]
            results.extend(nuc_rows)

            poc_sql = ("SELECT *, rank, 'poc_github' as _source_table FROM poc_github "
                       "WHERE poc_github MATCH ? ORDER BY rank LIMIT ?")
            cur = conn.execute(poc_sql, (escaped, limit))
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
        for table in ["techniques", "external_techniques", "exploitdb", "nuclei", "poc_github"]:
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

    sp_search = sub.add_parser("search", help="Search a specific table")
    sp_search.add_argument("query", help="Search query")
    sp_search.add_argument("--table", "-t", default="techniques",
                           choices=["techniques", "external_techniques",
                                    "exploitdb", "nuclei", "poc_github"])
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

    sub.add_parser("stats", help="Show database statistics")

    sp_get = sub.add_parser("get", help="Get file content")
    sp_get.add_argument("file_path", help="Path to file")
    sp_get.add_argument("--lines", "-n", type=int, default=100)

    args = parser.parse_args()
    indexer = KnowledgeIndexer()

    if args.command == "build":
        indexer.build()
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
