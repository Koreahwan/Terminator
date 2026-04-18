#!/usr/bin/env python3
"""
accepted_reports_scraper.py — Ingest public bug bounty disclosures into FTS5 DB.

Sources (2026-04-18 probe results):
  - Bugcrowd /crowdstream.json      (200 OK, public JSON API, 20 entries/page)
  - HackerOne /hacktivity            (public HTML scrape; GraphQL 404)
  - Infosec Writeups /feed           (200, Medium RSS)
  - Pentesterland newsletter archive (blog/the-5-hacking-newsletter-N/)
  - Awesome-Bugbounty-Writeups       (gh api repo contents)

Output: knowledge/accepted_reports.db   (SQLite FTS5)

Usage:
  python3 tools/accepted_reports_scraper.py init            # create DB
  python3 tools/accepted_reports_scraper.py ingest bugcrowd --pages 5
  python3 tools/accepted_reports_scraper.py ingest iwu --pages 3
  python3 tools/accepted_reports_scraper.py ingest pentesterland --pages 2
  python3 tools/accepted_reports_scraper.py ingest all
  python3 tools/accepted_reports_scraper.py search "prompt injection" --source bugcrowd
  python3 tools/accepted_reports_scraper.py stats
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "knowledge" / "accepted_reports.db"
DEFAULT_UA = "Mozilla/5.0 (compatible; Terminator-BB-Scraper/1.0)"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _http_get(url: str, headers: dict | None = None, timeout: int = 30) -> bytes:
    req = Request(url, headers={"User-Agent": DEFAULT_UA, **(headers or {})})
    with urlopen(req, timeout=timeout) as r:
        return r.read()


def init_db(db_path: Path = DB_PATH) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS reports USING fts5(
            source,
            platform,
            program,
            researcher,
            title,
            severity,
            status,
            bounty,
            vrt,
            cwe,
            url UNINDEXED,
            disclosed_at UNINDEXED,
            ingested_at UNINDEXED,
            raw_json UNINDEXED,
            tokenize = "porter unicode61"
        );

        CREATE TABLE IF NOT EXISTS ingest_log (
            source TEXT,
            started_at TEXT,
            finished_at TEXT,
            entries_added INTEGER,
            entries_skipped INTEGER,
            notes TEXT
        );
        """
    )
    conn.commit()
    conn.close()
    print(f"[init] DB ready at {db_path}")


def _existing_urls(conn: sqlite3.Connection) -> set[str]:
    cur = conn.execute("SELECT url FROM reports")
    return {row[0] for row in cur.fetchall() if row[0]}


def ingest_bugcrowd(pages: int = 5) -> tuple[int, int]:
    """Fetch Bugcrowd /crowdstream.json and insert into DB."""
    conn = sqlite3.connect(DB_PATH)
    existing = _existing_urls(conn)
    added, skipped = 0, 0

    for page in range(1, pages + 1):
        url = f"https://bugcrowd.com/crowdstream.json?page={page}"
        try:
            data = json.loads(_http_get(url, {"Accept": "application/json"}))
        except (HTTPError, URLError, json.JSONDecodeError) as e:
            print(f"[bugcrowd p{page}] fetch failed: {e}")
            break

        results = data.get("results", [])
        if not results:
            break

        for e in results:
            entry_url = e.get("engagement_path") or ""
            if entry_url and not entry_url.startswith("http"):
                entry_url = f"https://bugcrowd.com{entry_url}"
            uniq = entry_url + "#" + str(e.get("researcher_username", "")) + "#" + str(
                e.get("accepted_at", e.get("disclosed_at", ""))
            )
            if uniq in existing:
                skipped += 1
                continue

            conn.execute(
                "INSERT INTO reports(source, platform, program, researcher, title, severity, status, bounty, vrt, cwe, url, disclosed_at, ingested_at, raw_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "bugcrowd_crowdstream",
                    "bugcrowd",
                    e.get("engagement_name", ""),
                    e.get("researcher_username", ""),
                    e.get("submission_title") or e.get("description_truncated") or "Submission accepted",
                    "",
                    "accepted" if e.get("accepted_at") else "disclosed",
                    "",
                    e.get("vrt_type") or "",
                    "",
                    uniq,
                    e.get("accepted_at") or e.get("disclosed_at") or "",
                    _now(),
                    json.dumps(e),
                ),
            )
            existing.add(uniq)
            added += 1
        time.sleep(1.0)  # politeness

    conn.execute(
        "INSERT INTO ingest_log VALUES(?,?,?,?,?,?)",
        ("bugcrowd_crowdstream", _now(), _now(), added, skipped, f"pages={pages}"),
    )
    conn.commit()
    conn.close()
    print(f"[bugcrowd] added={added} skipped={skipped} (pages={pages})")
    return added, skipped


def ingest_iwu(pages: int = 3) -> tuple[int, int]:
    """Fetch Infosec Writeups RSS feed."""
    conn = sqlite3.connect(DB_PATH)
    existing = _existing_urls(conn)
    added, skipped = 0, 0

    for page in range(1, pages + 1):
        suffix = "" if page == 1 else f"?page={page}"
        url = f"https://infosecwriteups.com/feed{suffix}"
        try:
            xml = _http_get(url).decode("utf-8", errors="replace")
        except (HTTPError, URLError) as e:
            print(f"[iwu p{page}] fetch failed: {e}")
            break

        items = re.findall(r"<item>(.*?)</item>", xml, flags=re.DOTALL)
        if not items:
            break

        for item in items:
            title_m = re.search(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", item, re.DOTALL)
            link_m = re.search(r"<link>(.*?)</link>", item, re.DOTALL)
            pub_m = re.search(r"<pubDate>(.*?)</pubDate>", item, re.DOTALL)
            cat_m = re.findall(r"<category>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</category>", item, re.DOTALL)

            link = (link_m.group(1).strip() if link_m else "").split("?")[0]
            if not link or link in existing:
                skipped += 1
                continue

            title = (title_m.group(1).strip() if title_m else "")
            categories = " ".join(cat_m).lower() if cat_m else ""

            conn.execute(
                "INSERT INTO reports(source, platform, program, researcher, title, severity, status, bounty, vrt, cwe, url, disclosed_at, ingested_at, raw_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "infosecwriteups_rss",
                    "medium",
                    "",
                    "",
                    title,
                    "",
                    "published",
                    "",
                    "",
                    "",
                    link,
                    (pub_m.group(1).strip() if pub_m else ""),
                    _now(),
                    json.dumps({"categories": categories}),
                ),
            )
            existing.add(link)
            added += 1
        time.sleep(1.0)

    conn.execute(
        "INSERT INTO ingest_log VALUES(?,?,?,?,?,?)",
        ("infosecwriteups_rss", _now(), _now(), added, skipped, f"pages={pages}"),
    )
    conn.commit()
    conn.close()
    print(f"[iwu] added={added} skipped={skipped}")
    return added, skipped


def _huntr_extract_vulns(html: str) -> list[dict]:
    """Parse huntr Next.js RSC payload (`self.__next_f.push(...)`) and return
    a list of vulnerability dicts with keys including `id`, `title`, `status`,
    `cve_id`, `cvss`, `maintainer_severity`, `cwe`, `resolved_at`, `createdAt`."""
    push_calls = re.findall(r'self\.__next_f\.push\(\[(\d+),"(.*?)"\]\)', html, re.DOTALL)
    blob = "".join(p[1] for p in push_calls)
    blob = blob.encode().decode("unicode_escape", errors="replace")

    items: list[dict] = []
    for m in re.finditer(
        r'\{"id":"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"',
        blob,
    ):
        start = m.start()
        depth = 0
        in_str = False
        esc = False
        end = -1
        for i in range(start, min(start + 20000, len(blob))):
            c = blob[i]
            if esc:
                esc = False
                continue
            if c == "\\":
                esc = True
                continue
            if c == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end <= 0:
            continue
        chunk = blob[start:end]
        try:
            obj = json.loads(chunk)
        except json.JSONDecodeError:
            cleaned = re.sub(r'"\$[A-Za-z0-9]+"', '"$ref"', chunk)
            try:
                obj = json.loads(cleaned)
            except json.JSONDecodeError:
                continue
        # vuln items have title + status; skip other obj types (repository, user)
        if obj.get("title") and ("status" in obj or "cve_id" in obj):
            items.append(obj)

    # de-dup by id
    seen = set()
    uniq = []
    for it in items:
        if it.get("id") not in seen:
            seen.add(it.get("id"))
            uniq.append(it)
    return uniq


def ingest_huntr_repos(repo_list: list[str]) -> tuple[int, int]:
    """Scrape huntr per-repo pages for disclosed bounties via RSC payload parsing.

    huntr URL pattern: https://huntr.com/repos/<owner>/<name>
    Status taxonomy from RSC: duplicate / not applicable / informative / pending / self closed / Resolved
    """
    conn = sqlite3.connect(DB_PATH)
    # purge previous huntr_repo entries (they had inaccurate 'disclosed' status)
    conn.execute("DELETE FROM reports WHERE source = 'huntr_repo'")
    conn.commit()
    existing = _existing_urls(conn)
    added, skipped = 0, 0

    for repo in repo_list:
        url = f"https://huntr.com/repos/{repo}"
        try:
            html = _http_get(url, timeout=45).decode("utf-8", errors="replace")
        except (HTTPError, URLError) as e:
            print(f"[huntr {repo}] fetch failed: {e}")
            continue

        vulns = _huntr_extract_vulns(html)
        print(f"[huntr {repo}] extracted {len(vulns)} vulns from RSC")
        for v in vulns:
            entry_url = f"https://huntr.com/bounties/{v['id']}"
            if entry_url in existing:
                skipped += 1
                continue
            cvss_obj = v.get("cvss") or {}
            cvss_score = cvss_obj.get("score") if isinstance(cvss_obj, dict) else cvss_obj
            severity = (
                v.get("maintainer_severity")
                or (cvss_obj.get("severity") if isinstance(cvss_obj, dict) else "")
                or ""
            )
            cwe_field = v.get("cwe") or {}
            cwe_id = cwe_field.get("cwe_id") if isinstance(cwe_field, dict) else (cwe_field if isinstance(cwe_field, str) else "")
            disclosed = v.get("resolved_at") or v.get("validation_at") or v.get("createdAt") or ""

            conn.execute(
                "INSERT INTO reports(source, platform, program, researcher, title, severity, status, bounty, vrt, cwe, url, disclosed_at, ingested_at, raw_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "huntr_repo",
                    "huntr",
                    repo,
                    "",
                    (v.get("title") or "")[:280],
                    str(severity)[:30],
                    (v.get("status") or "").lower(),
                    str(cvss_score) if cvss_score is not None else "",
                    "",
                    cwe_id or "",
                    entry_url,
                    disclosed,
                    _now(),
                    json.dumps({k: v[k] for k in ("status", "cvss", "cwe", "cve_id", "resolved_at", "validation_at", "patch_commit_sha") if k in v}, default=str)[:2000],
                ),
            )
            existing.add(entry_url)
            added += 1
        time.sleep(2.0)

    conn.execute(
        "INSERT INTO ingest_log VALUES(?,?,?,?,?,?)",
        ("huntr_repo", _now(), _now(), added, skipped, f"repos={len(repo_list)} (RSC-parsed)"),
    )
    conn.commit()
    conn.close()
    print(f"[huntr] added={added} skipped={skipped} repos={len(repo_list)}")
    return added, skipped


def ingest_ywh_hacktivity(pages: int = 3) -> tuple[int, int]:
    """Scrape YesWeHack public hacktivity feed via jina."""
    conn = sqlite3.connect(DB_PATH)
    existing = _existing_urls(conn)
    added, skipped = 0, 0

    for page in range(1, pages + 1):
        url = f"https://r.jina.ai/https://yeswehack.com/hacktivity?page={page}"
        try:
            md = _http_get(url, timeout=45).decode("utf-8", errors="replace")
        except (HTTPError, URLError) as e:
            print(f"[ywh p{page}] fetch failed: {e}")
            break

        # YWH jina markdown patterns observed 2026-04-18:
        #   Pattern A: " <reporter> <vuln_type> (CWE-NNN)<status> <date>"
        #   Pattern B: "[![Image](url) <reporter>](https://yeswehack.com/hunters/<reporter>)<vuln_type> (CWE-NNN)<status> <date>"
        # Status appears with no whitespace after the closing parenthesis.
        rows = []
        # Pattern B (linked reporter)
        for m in re.finditer(
            r"\]\(https://yeswehack\.com/hunters/([\w\-]+)\)([^(]+?)\s*(\(CWE-\d+\))?\s*(New|Closed|Accepted|Resolved|Won.t fix|Informative|Duplicate|Out of Scope|Invalid|Spam|RTFS)\s+([A-Z][a-z]{2},\s+\d{1,2}\s+\w+\s+\d{4})",
            md,
        ):
            rows.append((m.group(1), m.group(2).strip(), m.group(4), m.group(5).strip(), m.group(3) or ""))
        # Pattern A (anonymous / no link)
        for m in re.finditer(
            r"\b([a-z][\w\-]+)\s+([A-Z][^()\n]{4,80}?)\s*(\(CWE-\d+\))?\s*(New|Closed|Accepted|Resolved|Won.t fix|Informative|Duplicate|Out of Scope|Invalid|Spam|RTFS)\s+([A-Z][a-z]{2},\s+\d{1,2}\s+\w+\s+\d{4})",
            md,
        ):
            rows.append((m.group(1), m.group(2).strip(), m.group(4), m.group(5).strip(), m.group(3) or ""))
        if not rows:
            print(f"[ywh p{page}] no rows extracted (page may be empty)")
            break

        # de-dup within page (regex may double-match)
        seen_local = set()
        for tup in rows:
            reporter, vuln_type, status, date, cwe = tup
            key = (reporter, vuln_type[:60], date)
            if key in seen_local:
                continue
            seen_local.add(key)
            uniq = f"https://yeswehack.com/hacktivity#{reporter}#{vuln_type[:60]}#{date}"
            if uniq in existing:
                skipped += 1
                continue
            conn.execute(
                "INSERT INTO reports(source, platform, program, researcher, title, severity, status, bounty, vrt, cwe, url, disclosed_at, ingested_at, raw_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "ywh_hacktivity",
                    "yeswehack",
                    "",
                    reporter,
                    vuln_type[:280],
                    "",
                    status.lower(),
                    "",
                    "",
                    cwe.strip("()"),
                    uniq,
                    date,
                    _now(),
                    json.dumps({"row": f"{reporter} | {vuln_type} | {status} | {date} | {cwe}"}),
                ),
            )
            existing.add(uniq)
            added += 1
        time.sleep(1.5)

    conn.execute(
        "INSERT INTO ingest_log VALUES(?,?,?,?,?,?)",
        ("ywh_hacktivity", _now(), _now(), added, skipped, f"pages={pages}"),
    )
    conn.commit()
    conn.close()
    print(f"[ywh] added={added} skipped={skipped}")
    return added, skipped


def ingest_nomisec_local(years: list[int] | None = None, base_path: str | None = None) -> tuple[int, int]:
    """Ingest local nomi-sec/PoC-in-GitHub clone (already synced via sync_poc_github.sh).

    Each <year>/CVE-YYYY-NNNN.json file is an array of GitHub PoC repos.
    Each repo is recorded as one entry with status='poc' and cwe field set to CVE id.
    Default scope: years 2024-2026 (manageable size; tens of thousands of entries).
    """
    base = Path(base_path) if base_path else Path.home() / "PoC-in-GitHub"
    if not base.exists():
        print(f"[nomi-sec] {base} missing — run scripts/sync_poc_github.sh first")
        return 0, 0

    years = years or [2024, 2025, 2026]
    conn = sqlite3.connect(DB_PATH)
    existing = _existing_urls(conn)
    added, skipped = 0, 0

    for year in years:
        ydir = base / str(year)
        if not ydir.is_dir():
            continue
        for f in sorted(ydir.glob("CVE-*.json")):
            cve_id = f.stem  # e.g. CVE-2025-0054
            try:
                repos = json.loads(f.read_text(errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(repos, list):
                continue
            for r in repos:
                if not isinstance(r, dict):
                    continue
                url = r.get("html_url") or ""
                if not url or url in existing:
                    skipped += 1
                    continue
                conn.execute(
                    "INSERT INTO reports(source, platform, program, researcher, title, severity, status, bounty, vrt, cwe, url, disclosed_at, ingested_at, raw_json) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "nomisec_poc",
                        "github",
                        (r.get("full_name") or "")[:120],
                        (r.get("owner") or {}).get("login", "")[:60] if isinstance(r.get("owner"), dict) else "",
                        ((r.get("description") or r.get("name") or cve_id))[:280],
                        "",
                        "poc",
                        "",
                        "",
                        cve_id,
                        url,
                        r.get("created_at") or "",
                        _now(),
                        json.dumps({"stars": r.get("stargazers_count"), "updated_at": r.get("updated_at"), "score": r.get("score")}),
                    ),
                )
                existing.add(url)
                added += 1
                if added % 5000 == 0:
                    conn.commit()
                    print(f"[nomi-sec] progress added={added}")
        conn.commit()

    conn.execute(
        "INSERT INTO ingest_log VALUES(?,?,?,?,?,?)",
        ("nomisec_poc", _now(), _now(), added, skipped, f"years={years}"),
    )
    conn.commit()
    conn.close()
    print(f"[nomi-sec] added={added} skipped={skipped} years={years}")
    return added, skipped


def ingest_github_security_lab() -> tuple[int, int]:
    """GitHub Security Lab Advisories — fetch via securitylab.github.com/advisories/ HTML scrape (RSS not exposed)."""
    conn = sqlite3.connect(DB_PATH)
    existing = _existing_urls(conn)
    added, skipped = 0, 0

    try:
        html = _http_get("https://securitylab.github.com/advisories/", timeout=30).decode("utf-8", errors="replace")
    except (HTTPError, URLError) as e:
        print(f"[ghsec-lab] fetch failed: {e}")
        return 0, 0

    # Each advisory entry typically: <a href="/advisories/GHSL-..."> + <h2>title</h2>
    entries = re.findall(
        r'href="(/advisories/(GHSL-[0-9]{4}-[0-9]+)[^"]*?)"[^>]*>\s*([^<]+)',
        html,
    )
    for path, ghsl_id, title in entries:
        url = f"https://securitylab.github.com{path}"
        if url in existing:
            skipped += 1
            continue
        conn.execute(
            "INSERT INTO reports(source, platform, program, researcher, title, severity, status, bounty, vrt, cwe, url, disclosed_at, ingested_at, raw_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "github_securitylab",
                "github",
                "",
                "GitHub Security Lab",
                title.strip()[:280],
                "",
                "advisory",
                "",
                "",
                ghsl_id,
                url,
                "",
                _now(),
                json.dumps({"ghsl_id": ghsl_id}),
            ),
        )
        existing.add(url)
        added += 1

    conn.execute(
        "INSERT INTO ingest_log VALUES(?,?,?,?,?,?)",
        ("github_securitylab", _now(), _now(), added, skipped, "first page"),
    )
    conn.commit()
    conn.close()
    print(f"[ghsec-lab] added={added} skipped={skipped}")
    return added, skipped


def ingest_kh4sh3i_writeups() -> tuple[int, int]:
    """kh4sh3i/bug-bounty-writeups GitHub repo — README contains writeup links."""
    import subprocess
    try:
        out = subprocess.check_output(
            ["gh", "api", "repos/kh4sh3i/bug-bounty-writeups/contents/README.md", "--jq", ".content"],
            text=True, timeout=30,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[kh4sh3i] gh api failed: {e}")
        return 0, 0

    import base64
    try:
        readme = base64.b64decode(out.strip()).decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[kh4sh3i] base64 decode failed: {e}")
        return 0, 0

    conn = sqlite3.connect(DB_PATH)
    existing = _existing_urls(conn)
    added, skipped = 0, 0

    # Each link [Title](url) — keep external (non-internal) writeups
    for m in re.finditer(r"\[([^\]]+)\]\((https?://[^)]+)\)", readme):
        title, url = m.group(1).strip(), m.group(2).strip()
        if "kh4sh3i/bug-bounty-writeups" in url or len(title) < 5:
            continue
        if url in existing:
            skipped += 1
            continue
        # Categorize by url host
        host = re.match(r"https?://([^/]+)", url).group(1) if re.match(r"https?://([^/]+)", url) else ""
        conn.execute(
            "INSERT INTO reports(source, platform, program, researcher, title, severity, status, bounty, vrt, cwe, url, disclosed_at, ingested_at, raw_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "kh4sh3i_writeups",
                "external",
                host,
                "",
                title[:280],
                "",
                "writeup",
                "",
                "",
                "",
                url,
                "",
                _now(),
                json.dumps({"host": host}),
            ),
        )
        existing.add(url)
        added += 1

    conn.execute(
        "INSERT INTO ingest_log VALUES(?,?,?,?,?,?)",
        ("kh4sh3i_writeups", _now(), _now(), added, skipped, "README links"),
    )
    conn.commit()
    conn.close()
    print(f"[kh4sh3i] added={added} skipped={skipped}")
    return added, skipped


def ingest_circl_for_cves(cve_list: list[str]) -> tuple[int, int]:
    """CIRCL Vulnerability-Lookup — fetch metadata + PoC sightings for specific CVEs."""
    conn = sqlite3.connect(DB_PATH)
    existing = _existing_urls(conn)
    added, skipped = 0, 0

    for cve in cve_list:
        url_key = f"https://vulnerability.circl.lu/api/vulnerability/{cve}"
        if url_key in existing:
            skipped += 1
            continue
        try:
            data = json.loads(_http_get(url_key + "?with_pocs=true", timeout=20))
        except (HTTPError, URLError, json.JSONDecodeError):
            continue
        # Title from CVE record
        title = ""
        try:
            title = data["containers"]["cna"]["title"]
        except (KeyError, TypeError):
            title = data.get("cveMetadata", {}).get("cveId", cve)
        cwe_id = ""
        try:
            cwe_id = data["containers"]["cna"]["problemTypes"][0]["descriptions"][0].get("cweId", "")
        except (KeyError, IndexError, TypeError):
            pass
        published = data.get("cveMetadata", {}).get("datePublished", "")

        conn.execute(
            "INSERT INTO reports(source, platform, program, researcher, title, severity, status, bounty, vrt, cwe, url, disclosed_at, ingested_at, raw_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "circl_vuln",
                "circl",
                "",
                "",
                (title or cve)[:280],
                "",
                "published",
                "",
                "",
                cwe_id or cve,
                url_key,
                published,
                _now(),
                json.dumps({"cve": cve, "cwe": cwe_id}),
            ),
        )
        existing.add(url_key)
        added += 1
        time.sleep(0.5)

    conn.execute(
        "INSERT INTO ingest_log VALUES(?,?,?,?,?,?)",
        ("circl_vuln", _now(), _now(), added, skipped, f"cves={len(cve_list)}"),
    )
    conn.commit()
    conn.close()
    print(f"[circl] added={added} skipped={skipped}")
    return added, skipped


def ingest_zdi(limit: int = 100) -> tuple[int, int]:
    """ZDI Published Advisories RSS feed."""
    conn = sqlite3.connect(DB_PATH)
    existing = _existing_urls(conn)
    added, skipped = 0, 0

    try:
        xml = _http_get("https://www.zerodayinitiative.com/rss/published/").decode("utf-8", errors="replace")
    except (HTTPError, URLError) as e:
        print(f"[zdi] fetch failed: {e}")
        return 0, 0

    items = re.findall(r"<item>(.*?)</item>", xml, flags=re.DOTALL)
    for item in items[:limit]:
        title = re.search(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", item, re.DOTALL)
        link = re.search(r"<link>(.*?)</link>", item, re.DOTALL)
        pub = re.search(r"<pubDate>(.*?)</pubDate>", item, re.DOTALL)
        cve = re.search(r"CVE-\d{4}-\d{4,7}", item)
        zdi_id = re.search(r"ZDI-\d{2}-\d{3,5}", item)

        link_url = link.group(1).strip() if link else ""
        if not link_url or link_url in existing:
            skipped += 1
            continue

        conn.execute(
            "INSERT INTO reports(source, platform, program, researcher, title, severity, status, bounty, vrt, cwe, url, disclosed_at, ingested_at, raw_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "zdi_advisories",
                "zdi",
                "",
                "",
                (title.group(1).strip() if title else "")[:280],
                "",
                "published",
                "",
                "",
                cve.group(0) if cve else "",
                link_url,
                pub.group(1).strip() if pub else "",
                _now(),
                json.dumps({"zdi_id": zdi_id.group(0) if zdi_id else ""}),
            ),
        )
        existing.add(link_url)
        added += 1

    conn.execute(
        "INSERT INTO ingest_log VALUES(?,?,?,?,?,?)",
        ("zdi_advisories", _now(), _now(), added, skipped, f"limit={limit}"),
    )
    conn.commit()
    conn.close()
    print(f"[zdi] added={added} skipped={skipped}")
    return added, skipped


def ingest_pentesterland(pages: int = 2) -> tuple[int, int]:
    """Scrape pentester.land newsletter archive pages."""
    conn = sqlite3.connect(DB_PATH)
    existing = _existing_urls(conn)
    added, skipped = 0, 0

    for page in range(1, pages + 1):
        archive = f"https://pentester.land/categories/newsletter/page/{page}/"
        try:
            html = _http_get(archive).decode("utf-8", errors="replace")
        except (HTTPError, URLError) as e:
            print(f"[pentesterland p{page}] fetch failed: {e}")
            break

        posts = re.findall(
            r'href="(/blog/the-5-hacking-newsletter-\d+/)".*?>([^<]+)</a>',
            html,
            flags=re.DOTALL,
        )
        if not posts:
            # fallback: any /blog/ link with newsletter in slug
            posts = [(m.group(1), m.group(1)) for m in re.finditer(r'href="(/blog/[^"]*newsletter[^"]*/)"', html)]

        for slug, title in posts:
            url = f"https://pentester.land{slug}"
            if url in existing:
                skipped += 1
                continue
            conn.execute(
                "INSERT INTO reports(source, platform, program, researcher, title, severity, status, bounty, vrt, cwe, url, disclosed_at, ingested_at, raw_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "pentesterland",
                    "newsletter",
                    "",
                    "pentesterland",
                    title.strip(),
                    "",
                    "curated",
                    "",
                    "",
                    "",
                    url,
                    "",
                    _now(),
                    json.dumps({"archive_page": archive}),
                ),
            )
            existing.add(url)
            added += 1
        time.sleep(1.0)

    conn.execute(
        "INSERT INTO ingest_log VALUES(?,?,?,?,?,?)",
        ("pentesterland", _now(), _now(), added, skipped, f"pages={pages}"),
    )
    conn.commit()
    conn.close()
    print(f"[pentesterland] added={added} skipped={skipped}")
    return added, skipped


def search(query: str, source: str | None = None, limit: int = 10) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # FTS5 MATCH syntax — escape double quotes; quote phrase
    safe = query.replace('"', '""')
    sql = 'SELECT rank, source, platform, program, title, severity, status, bounty, vrt, url, disclosed_at FROM reports WHERE reports MATCH ?'
    params: list = [safe]
    if source:
        sql += " AND source = ?"
        params.append(source)
    sql += " ORDER BY rank LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def stats() -> None:
    conn = sqlite3.connect(DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    by_source = conn.execute(
        "SELECT source, COUNT(*) FROM reports GROUP BY source ORDER BY 2 DESC"
    ).fetchall()
    by_platform = conn.execute(
        "SELECT platform, COUNT(*) FROM reports GROUP BY platform ORDER BY 2 DESC"
    ).fetchall()
    print(f"Total reports: {total}")
    print("\nBy source:")
    for s, n in by_source:
        print(f"  {s}: {n}")
    print("\nBy platform:")
    for p, n in by_platform:
        print(f"  {p}: {n}")
    conn.close()


def main() -> None:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="Create DB if missing")

    i = sub.add_parser("ingest", help="Ingest from a source")
    i.add_argument("source", choices=["bugcrowd", "iwu", "pentesterland", "huntr", "ywh", "zdi", "nomisec", "ghseclab", "kh4sh3i", "circl", "all"])
    i.add_argument("--pages", type=int, default=5)
    i.add_argument(
        "--repos",
        nargs="*",
        default=[
            "run-llama/llama_index",
            "onnx/onnx",
            "kubeflow/kubeflow",
            "parisneo/lollms",
            "keras-team/keras",
            "triton-inference-server/server",
        ],
        help="huntr: repo list to scrape (default = currently active + popular AI/ML repos)",
    )

    s = sub.add_parser("search", help="Search FTS")
    s.add_argument("query")
    s.add_argument("--source")
    s.add_argument("--limit", type=int, default=10)
    s.add_argument("--json", action="store_true")

    sub.add_parser("stats", help="Show counts")

    args = p.parse_args()

    if args.cmd == "init":
        init_db()
    elif args.cmd == "ingest":
        init_db()
        if args.source in ("bugcrowd", "all"):
            ingest_bugcrowd(args.pages)
        if args.source in ("iwu", "all"):
            ingest_iwu(args.pages)
        if args.source in ("pentesterland", "all"):
            ingest_pentesterland(args.pages)
        if args.source in ("huntr", "all"):
            ingest_huntr_repos(args.repos)
        if args.source in ("ywh", "all"):
            ingest_ywh_hacktivity(args.pages)
        if args.source in ("zdi", "all"):
            ingest_zdi(limit=args.pages * 25)
        if args.source in ("nomisec", "all"):
            ingest_nomisec_local()
        if args.source in ("ghseclab", "all"):
            ingest_github_security_lab()
        if args.source in ("kh4sh3i", "all"):
            ingest_kh4sh3i_writeups()
        if args.source == "circl":
            # CIRCL needs explicit CVE list; --repos repurposed for that
            ingest_circl_for_cves(args.repos if args.repos else ["CVE-2024-21626"])
    elif args.cmd == "search":
        init_db()
        results = search(args.query, args.source, args.limit)
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        else:
            if not results:
                print("(no matches)")
            for r in results:
                print(f"- [{r['source']}/{r['platform']}] {r['program']} — {r['title'][:80]} ({r['status']}, {r['bounty'] or '—'}) | {r['url']}")
    elif args.cmd == "stats":
        stats()


if __name__ == "__main__":
    main()
