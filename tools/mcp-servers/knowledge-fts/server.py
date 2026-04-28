#!/usr/bin/env python3
"""Knowledge FTS5 MCP Server — BM25 search over security documents.

Tables indexed:
  - techniques:          internal knowledge/techniques/ + knowledge/challenges/
  - external_techniques: PayloadsAllTheThings, HackTricks, how2heap, GTFOBins, CTF-All-In-One, etc.
  - exploitdb:           47K+ ExploitDB entries
  - nuclei:              12K+ Nuclei detection templates
  - poc_github:          8K+ CVE PoC repos
  - trickest_cve:        155K+ CVE entries with products, CWE, PoC URLs
  - web_articles:        Crawled security writeups and blog posts
  - triage_objections:   Local rejection/KILL reasons and triage feedback
"""
import os
import re as _re
import sys

# Add tools/ to path so we can import knowledge_indexer
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
from knowledge_indexer import KnowledgeIndexer

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("knowledge-fts")
_indexer = KnowledgeIndexer()

# --- Query cache (TTL-based, no external deps) ---
import time as _time
_cache: dict[tuple, tuple[float, list]] = {}
_CACHE_TTL = 300  # 5 minutes
_CACHE_MAX = 1000  # max entries


def _cache_put(key: tuple, results: list) -> None:
    """Store result in cache, evicting oldest if over max size."""
    if len(_cache) >= _CACHE_MAX:
        oldest_key = min(_cache, key=lambda k: _cache[k][0])
        del _cache[oldest_key]
    _cache[key] = (_time.time(), results)


def _cached_search(query: str, table: str, category: str = "", limit: int = 5) -> list[dict]:
    """Cache wrapper around _indexer.search() with TTL expiry."""
    key = (query, table, category, limit)
    now = _time.time()
    if key in _cache and now - _cache[key][0] < _CACHE_TTL:
        return _cache[key][1]
    results = _indexer.search(query, table=table, category=category, limit=limit)
    _cache_put(key, results)
    return results


def _cached_snippet_search(query: str, table: str, category: str = "", limit: int = 5) -> list[dict]:
    """Cache wrapper around _snippet_search() with TTL expiry."""
    key = ("snippet", query, table, category, limit)
    now = _time.time()
    if key in _cache and now - _cache[key][0] < _CACHE_TTL:
        return _cache[key][1]
    results = _snippet_search(query, table=table, category=category, limit=limit)
    _cache_put(key, results)
    return results


def _fmt_snippet(text: str, max_chars: int = 200) -> str:
    """Return first non-empty, non-heading line up to max_chars."""
    if not text:
        return ""
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped[:max_chars] + ("..." if len(stripped) > max_chars else "")
    return text[:max_chars]


def _fts_query_variants(query: str) -> list[str]:
    """Build safe FTS5 query variants for routed searches.

    `escape_fts5()` expands acronyms such as IDOR to their long form. That is
    useful for broad recall, but in a multi-term query it can accidentally drop
    the acronym token itself. Keep a literal-token AND variant as a fallback so
    route-specific searches do not miss documents titled with the acronym.
    """
    from knowledge_indexer import escape_fts5

    variants: list[str] = []
    escaped = escape_fts5(query)
    if escaped.strip():
        variants.append(escaped)

    words = _re.findall(r"[\w][\w\-]*[\w]|[\w]+", query)
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


def _snippet_search(query: str, table: str, category: str = "", limit: int = 5) -> list[dict]:
    """Search with FTS5 snippet() for token-efficient results.

    Returns results with 'snippet' field (match-highlighted, ~64 tokens)
    instead of full 'content' field. Saves 80%+ tokens per result.
    """
    from knowledge_indexer import escape_fts5
    variants = _fts_query_variants(query)
    if not variants:
        return []

    weights = _indexer.BM25_WEIGHTS.get(table, ())
    if weights:
        weight_args = ", ".join(str(w) for w in weights)
        rank_expr = f"bm25({table}, {weight_args})"
    else:
        rank_expr = "rank"

    conn = _indexer._connect()
    try:
        fetch_limit = limit * 3
        # snippet(table, col_idx=-1, open, close, ellipsis, max_tokens)
        snippet_expr = f"snippet({table}, -1, '>>>', '<<<', '...', 64)"
        results = []
        for variant in variants:
            if category:
                cat_escaped = escape_fts5(category)
                sql = (f"SELECT *, {snippet_expr} as snippet, {rank_expr} as rank "
                       f"FROM {table} WHERE {table} MATCH ? AND category MATCH ? "
                       f"ORDER BY rank LIMIT ?")
                cur = conn.execute(sql, (variant, cat_escaped, fetch_limit))
            else:
                sql = (f"SELECT *, {snippet_expr} as snippet, {rank_expr} as rank "
                       f"FROM {table} WHERE {table} MATCH ? ORDER BY rank LIMIT ?")
                cur = conn.execute(sql, (variant, fetch_limit))
            results.extend(dict(row) for row in cur.fetchall())
            results = _indexer._dedup_results(results)
            if len(results) >= limit:
                break
        results = results[:limit]
    except Exception as e:
        print(f"Snippet search error: {e}", file=_import_sys().stderr)
        results = []
    finally:
        conn.close()
    return results


def _triage_snippet_search(query: str, program: str = "", limit: int = 10) -> list[dict]:
    """Search triage_objections, optionally filtering the program column."""
    from knowledge_indexer import escape_fts5
    variants = _fts_query_variants(query)
    if not variants:
        return []

    conn = _indexer._connect()
    try:
        fetch_limit = limit * 3
        snippet_expr = "snippet(triage_objections, -1, '>>>', '<<<', '...', 64)"
        rank_expr = "bm25(triage_objections, 10.0, 1.0, 3.0, 3.0, 5.0, 2.0)"
        results = []
        for variant in variants:
            if program:
                sql = (
                    f"SELECT *, {snippet_expr} as snippet, {rank_expr} as rank "
                    "FROM triage_objections "
                    "WHERE triage_objections MATCH ? AND lower(program) = ? "
                    "ORDER BY rank LIMIT ?"
                )
                cur = conn.execute(sql, (variant, program.lower(), fetch_limit))
            else:
                sql = (
                    f"SELECT *, {snippet_expr} as snippet, {rank_expr} as rank "
                    "FROM triage_objections WHERE triage_objections MATCH ? "
                    "ORDER BY rank LIMIT ?"
                )
                cur = conn.execute(sql, (variant, fetch_limit))
            results.extend(dict(row) for row in cur.fetchall())
            results = _indexer._dedup_results(results)
            if len(results) >= limit:
                break
        return results[:limit]
    except Exception as e:
        print(f"Triage search error: {e}", file=_import_sys().stderr)
        return []
    finally:
        conn.close()


def _filtered_snippet_search(
    query: str,
    table: str,
    *,
    sources: list[str] | None = None,
    categories: list[str] | None = None,
    limit: int = 5,
) -> list[dict]:
    """Snippet search with post-filtering for routing profiles.

    FTS5 stores source/source_repo/category fields differently per table. Pull a
    wider candidate set and filter in Python so routing remains robust across
    old DB builds and UNINDEXED columns.
    """
    variants = _fts_query_variants(query)
    if not variants:
        return []

    sources_l = {s.lower() for s in (sources or [])}
    categories_l = {c.lower() for c in (categories or [])}
    weights = _indexer.BM25_WEIGHTS.get(table, ())
    rank_expr = f"bm25({table}, {', '.join(str(w) for w in weights)})" if weights else "rank"
    snippet_expr = f"snippet({table}, -1, '>>>', '<<<', '...', 64)"

    conn = _indexer._connect()
    try:
        rows = []
        for variant in variants:
            where = [f"{table} MATCH ?"]
            params: list[str | int] = [variant]

            source_col = "source_repo" if table == "external_techniques" else "source"
            if sources_l:
                placeholders = ", ".join("?" for _ in sources_l)
                where.append(f"lower({source_col}) IN ({placeholders})")
                params.extend(sorted(sources_l))
            if categories_l:
                placeholders = ", ".join("?" for _ in categories_l)
                where.append(f"lower(category) IN ({placeholders})")
                params.extend(sorted(categories_l))

            params.append(max(limit * 6, 20))
            sql = (
                f"SELECT *, {snippet_expr} as snippet, {rank_expr} as rank "
                f"FROM {table} WHERE {' AND '.join(where)} ORDER BY rank LIMIT ?"
            )
            cur = conn.execute(sql, params)
            rows.extend(dict(row) for row in cur.fetchall())
            rows = _indexer._dedup_results(rows)
            if len(rows) >= limit:
                break
    except Exception as e:
        print(f"Filtered search error: {e}", file=_import_sys().stderr)
        rows = []
    finally:
        conn.close()

    return _indexer._dedup_results(rows)[:limit]


ROUTING_PROFILES = {
    "target-evaluator": {
        "priority": [
            "program rules and scope facts",
            "triage_objections and accepted/rejected history",
            "decision records and prior submissions",
        ],
        "avoid": ["raw exploit/CVE noise unless a known duplicate check is needed"],
        "sections": [
            {"label": "Triage Memory", "kind": "triage", "limit": 3},
            {"label": "Decisions/Submissions", "kind": "internal", "sources": ["decisions", "submissions", "knowledge_root"], "limit": 3},
            {"label": "Technique Context", "kind": "internal", "sources": ["techniques", "scenarios"], "limit": 2},
        ],
    },
    "scout": {
        "priority": ["attack-surface scenarios", "technique references", "known CVE/exploit signals"],
        "avoid": ["submission style examples during discovery"],
        "sections": [
            {"label": "Scenarios/Protocol Checklists", "kind": "internal", "sources": ["scenarios", "protocol_vulns_index"], "limit": 3},
            {"label": "Techniques", "kind": "internal", "sources": ["techniques"], "limit": 2},
            {"label": "Known Exploits", "kind": "exploit", "limit": 3},
        ],
    },
    "analyst": {
        "priority": ["scenario checklists", "protocol-specific vulnerability classes", "external technique references"],
        "avoid": ["report templates and prior submissions until a candidate exists"],
        "sections": [
            {"label": "Scenarios/Protocol Checklists", "kind": "internal", "sources": ["scenarios", "protocol_vulns_index"], "limit": 4},
            {"label": "Internal Techniques", "kind": "internal", "sources": ["techniques"], "limit": 2},
            {"label": "External Techniques", "kind": "external", "limit": 2},
        ],
    },
    "ai-recon": {
        "priority": ["OWASP/Agentic LLM refs", "local AI attack scenarios", "llm-wiki agent knowledge"],
        "avoid": ["generic CVE noise unless the target exposes a concrete vulnerable component"],
        "sections": [
            {"label": "AI Internal Knowledge", "kind": "internal", "sources": ["techniques", "scenarios"], "categories": ["ai", "llm"], "limit": 4},
            {"label": "LLM Wiki / Agent Knowledge", "kind": "external", "sources": ["llm-wiki", "llm-wiki-nvk"], "limit": 4},
            {"label": "AI Detection/PoC Signals", "kind": "exploit", "limit": 2},
        ],
    },
    "exploiter": {
        "priority": ["known PoCs and CVEs", "bypass alternatives", "evidence-tier patterns"],
        "avoid": ["past submissions as exploit proof"],
        "sections": [
            {"label": "Known Exploits", "kind": "exploit", "limit": 4},
            {"label": "Exploit Techniques", "kind": "internal", "sources": ["techniques", "scenarios", "protocol_vulns_index"], "limit": 3},
        ],
    },
    "reporter": {
        "priority": ["submission quality rules", "platform formats", "successful/failed report patterns"],
        "avoid": ["new vulnerability research and broad CVE search"],
        "sections": [
            {"label": "Submission Examples", "kind": "internal", "sources": ["submissions"], "limit": 3},
            {"label": "Report Quality/Platform Rules", "kind": "internal", "sources": ["techniques"], "limit": 3},
            {"label": "Triage Objections", "kind": "triage", "limit": 2},
        ],
    },
    "critic": {
        "priority": ["triage objections", "decision records", "submission history"],
        "avoid": ["broad technique expansion unless checking a specific claim"],
        "sections": [
            {"label": "Triage Objections", "kind": "triage", "limit": 4},
            {"label": "Decisions/Submissions", "kind": "internal", "sources": ["decisions", "submissions"], "limit": 3},
            {"label": "Claim Check References", "kind": "internal", "sources": ["techniques", "protocol_vulns_index"], "limit": 2},
        ],
    },
    "triager-sim": {
        "priority": ["same-program rejection memory", "common failure patterns", "submission history"],
        "avoid": ["inventing new attack paths while judging evidence"],
        "sections": [
            {"label": "Triage Objections", "kind": "triage", "limit": 5},
            {"label": "Submission/Decision Memory", "kind": "internal", "sources": ["submissions", "decisions"], "limit": 3},
        ],
    },
}

ROLE_ALIASES = {
    "target_evaluator": "target-evaluator",
    "target-discovery": "scout",
    "recon-scanner": "scout",
    "web-tester": "analyst",
    "mobile-analyst": "analyst",
    "defi-auditor": "analyst",
    "source-auditor": "analyst",
    "patch-hunter": "analyst",
    "submission-review": "critic",
}


def _profile_for_role(role: str) -> tuple[str, dict]:
    normalized = (role or "analyst").strip().lower().replace("_", "-")
    normalized = ROLE_ALIASES.get(normalized, normalized)
    return normalized, ROUTING_PROFILES.get(normalized, ROUTING_PROFILES["analyst"])


def _row_title(row: dict) -> str:
    return (row.get("title") or row.get("name") or row.get("description") or row.get("cve_id") or "untitled")


def _format_route_row(row: dict) -> str:
    source_table = row.get("_source_table", "")
    source = row.get("source") or row.get("source_repo") or source_table
    category = row.get("category") or row.get("program") or row.get("platform") or ""
    path = row.get("file_path") or row.get("github_url") or row.get("source_url") or ""
    snippet = row.get("snippet") or row.get("kill_reason") or _fmt_snippet(row.get("content", ""))
    parts = [f"[{source or source_table}] {_row_title(row)[:120]}"]
    meta = []
    if category:
        meta.append(f"cat={category}")
    if snippet:
        meta.append(f"match={snippet[:180]}")
    if path:
        meta.append(f"path={path}")
    if meta:
        parts.append(" | ".join(meta))
    return " — ".join(parts)


def _run_route_section(section: dict, query: str, program: str, limit: int) -> list[dict]:
    kind = section["kind"]
    section_limit = min(section.get("limit", limit), limit)
    if kind == "triage":
        rows = _triage_snippet_search(query, program=program, limit=section_limit)
        for row in rows:
            row["_source_table"] = "triage_objections"
        return rows
    if kind == "internal":
        rows = _filtered_snippet_search(
            query,
            "techniques",
            sources=section.get("sources"),
            categories=section.get("categories"),
            limit=section_limit,
        )
        for row in rows:
            row["_source_table"] = "techniques"
        return rows
    if kind == "external":
        rows = _filtered_snippet_search(
            query,
            "external_techniques",
            sources=section.get("sources"),
            categories=section.get("categories"),
            limit=section_limit,
        )
        for row in rows:
            row["_source_table"] = "external_techniques"
        return rows
    if kind == "exploit":
        rows = _indexer.search_exploits(query, limit=section_limit)
        for row in rows:
            row.pop("content", None)
        return rows
    return []


def _import_sys():
    import sys
    return sys


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def technique_search(query: str, category: str = "", limit: int = 5) -> str:
    """Search internal + external security technique documents using BM25 FTS5.

    Searches both the 'techniques' table (internal knowledge/techniques/ and
    knowledge/challenges/ writeups) and the 'external_techniques' table
    (PayloadsAllTheThings, HackTricks, how2heap, GTFOBins, CTF-All-In-One,
    owasp-mastg, HEVD, linux-kernel-exploitation, ad-exploitation, etc.).

    Use this when you need:
    - Attack technique documentation (heap exploitation, ROP, SQLi, etc.)
    - CTF challenge writeups and past solutions
    - OWASP/HackTricks category knowledge
    - Binary exploitation primitives (house-of-X, ret2libc, etc.)

    Args:
        query:    BM25 search query, e.g. "heap overflow", "format string", "ret2libc"
        category: Optional category filter, e.g. "heap", "web", "kernel", "ctf"
        limit:    Max results per table (default 5, returned up to 2x limit combined)
    """
    int_results = _cached_snippet_search(query, table="techniques", category=category, limit=limit)
    ext_results = _cached_snippet_search(query, table="external_techniques", category=category, limit=limit)

    # Also search web_articles if table exists
    web_results = []
    try:
        web_results = _cached_snippet_search(query, table="web_articles", category=category, limit=limit)
    except (ValueError, Exception):
        pass  # Table may not exist in older DBs

    total = len(int_results) + len(ext_results) + len(web_results)
    if total == 0:
        return f"No technique results for '{query}'" + (f" (category={category})" if category else "") + "."

    lines = [f"## Technique Search: \"{query}\" ({total} results)\n"]

    all_rows = []
    for r in int_results:
        r["_table_label"] = "techniques"
        all_rows.append(r)
    for r in ext_results:
        r["_table_label"] = "external"
        all_rows.append(r)
    for r in web_results:
        r["_table_label"] = "web"
        all_rows.append(r)

    for i, r in enumerate(all_rows, 1):
        label = r.get("_table_label", "?")
        title = r.get("title", r.get("name", "untitled"))
        cat = r.get("category", "")
        tags = r.get("tags", "")
        file_path = r.get("file_path", "")
        source_repo = r.get("source_repo", r.get("source", ""))
        snippet = r.get("snippet", _fmt_snippet(r.get("content", "")))

        lines.append(f"{i}. [{label}] {title}")
        meta_parts = []
        if cat:
            meta_parts.append(f"Category: {cat}")
        if tags:
            meta_parts.append(f"Tags: {tags[:80]}")
        if source_repo:
            meta_parts.append(f"Source: {source_repo}")
        if meta_parts:
            lines.append("   " + " | ".join(meta_parts))
        if file_path:
            lines.append(f"   Path: {file_path}")
        if snippet:
            lines.append(f"   Match: {snippet}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def exploit_search(query: str, platform: str = "", severity: str = "", limit: int = 10) -> str:
    """Search ExploitDB, Nuclei templates, PoC-in-GitHub, and Trickest-CVE for exploits.

    Searches four exploit databases combined:
    - ExploitDB (47K+ exploits with CVE codes, platform, type)
    - Nuclei templates (12K+ detection templates with severity/CWE/CVE)
    - PoC-in-GitHub (8K+ CVE proof-of-concept repositories)
    - Trickest-CVE (155K+ CVE entries with products, CWE, PoC URLs)

    Use this when you need:
    - Known exploits for a CVE (e.g. "CVE-2021-44228")
    - Exploits by service/software (e.g. "apache struts rce")
    - Detection templates for vulnerability scanning
    - PoC code references on GitHub

    Args:
        query:    CVE ID or keyword, e.g. "CVE-2021-41773", "apache log4j", "heap spray"
        platform: Optional platform filter for ExploitDB, e.g. "linux", "windows", "php"
        severity: Optional severity filter for Nuclei, e.g. "critical", "high", "medium"
        limit:    Max results per source (default 10)
    """
    results = _indexer.search_exploits(query, platform=platform, severity=severity, limit=limit)
    # Strip content field from exploit results to save tokens
    for r in results:
        r.pop("content", None)

    # Also search web_articles for exploit/CVE writeups
    try:
        web_results = _cached_search(query, table="web_articles", limit=limit)
        for r in web_results:
            r["_source_table"] = "web_articles"
            r.pop("content", None)
        results.extend(web_results)
    except (ValueError, Exception):
        pass

    # CVE query priority routing: trickest_cve + poc_github first
    if _re.match(r'CVE-\d{4}-\d{4,}', query, _re.IGNORECASE):
        results.sort(key=lambda r: (
            0 if r.get("_source_table") in ("trickest_cve", "poc_github") else 1,
            r.get("rank", 0)
        ))

    if not results:
        return (f"No exploit results for '{query}'"
                + (f" (platform={platform})" if platform else "")
                + (f" (severity={severity})" if severity else "")
                + ".")

    lines = [f"## Exploit Search: \"{query}\" ({len(results)} results)\n"]

    for i, r in enumerate(results, 1):
        source = r.get("_source_table", "?")

        if source == "exploitdb":
            eid = r.get("exploit_id", "?")
            desc = r.get("description", "")
            plat = r.get("platform", "")
            etype = r.get("exploit_type", "")
            cve = r.get("cve_codes", "")
            tags = r.get("tags", "")
            date = r.get("date_published", "")
            lines.append(f"{i}. [ExploitDB #{eid}] {desc[:120]}")
            parts = []
            if plat:
                parts.append(f"Platform: {plat}")
            if etype:
                parts.append(f"Type: {etype}")
            if cve:
                parts.append(f"CVE: {cve}")
            if date:
                parts.append(f"Date: {date}")
            if parts:
                lines.append("   " + " | ".join(parts))
            if tags:
                lines.append(f"   Tags: {tags[:100]}")

        elif source == "nuclei":
            tid = r.get("template_id", "?")
            name = r.get("name", "")
            desc = r.get("description", "")
            sev = r.get("severity", "")
            tags = r.get("tags", "")
            cve_id = r.get("cve_id", "")
            cwe_id = r.get("cwe_id", "")
            fpath = r.get("file_path", "")
            lines.append(f"{i}. [Nuclei: {tid}] {name or desc[:80]}")
            parts = []
            if sev:
                parts.append(f"Severity: {sev.upper()}")
            if cve_id:
                parts.append(f"CVE: {cve_id}")
            if cwe_id:
                parts.append(f"CWE: {cwe_id}")
            if parts:
                lines.append("   " + " | ".join(parts))
            if tags:
                lines.append(f"   Tags: {tags[:100]}")
            if desc and desc != name:
                lines.append(f"   Desc: {desc[:150]}")
            if fpath:
                lines.append(f"   Template: {fpath}")

        elif source == "poc_github":
            cve_id = r.get("cve_id", "?")
            repo = r.get("repo_name", "")
            desc = r.get("description", "")
            url = r.get("github_url", "")
            year = r.get("year", "")
            lines.append(f"{i}. [PoC-GitHub: {cve_id}] {repo}")
            if desc:
                lines.append(f"   Desc: {desc[:150]}")
            if url:
                lines.append(f"   URL: {url}")
            if year:
                lines.append(f"   Year: {year}")

        elif source == "trickest_cve":
            cve_id = r.get("cve_id", "?")
            desc = r.get("description", "")
            products = r.get("products", "")
            cwe = r.get("cwe", "")
            year = r.get("year", "")
            lines.append(f"{i}. [Trickest-CVE: {cve_id}] {desc[:120]}")
            parts = []
            if products:
                parts.append(f"Products: {products[:80]}")
            if cwe:
                parts.append(f"CWE: {cwe}")
            if year:
                parts.append(f"Year: {year}")
            if parts:
                lines.append("   " + " | ".join(parts))

        elif source == "web_articles":
            title = r.get("title", "untitled")[:100]
            domain = r.get("domain", "")
            cat = r.get("category", "")
            tags = r.get("tags", "")
            url = r.get("source_url", "")
            lines.append(f"{i}. [Web: {domain}] {title}")
            parts = []
            if cat:
                parts.append(f"Category: {cat}")
            if tags:
                parts.append(f"Tags: {tags[:80]}")
            if parts:
                lines.append("   " + " | ".join(parts))
            if url:
                lines.append(f"   URL: {url}")

        else:
            lines.append(f"{i}. [{source}] {str(r)[:200]}")

        lines.append("")

    return "\n".join(lines)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def challenge_search(query: str, status: str = "", limit: int = 5) -> str:
    """Search CTF challenge writeups in the internal knowledge base.

    Searches the 'techniques' table filtered to the 'challenges' source,
    which contains writeups from knowledge/challenges/. Each document records
    the challenge name, solution approach, flags, and lessons learned.

    Use this when you need:
    - Past CTF challenge solutions to avoid repeating work
    - Techniques used to solve similar challenge types
    - Known-failed attempts before retrying a challenge

    Args:
        query:  Challenge name or technique, e.g. "heap uaf", "format string pwn", "ret2libc"
        status: Optional text filter applied to category field, e.g. "pwn", "reversing", "crypto"
        limit:  Max results (default 5)
    """
    # Search challenges source via category hint if status provided
    results = _indexer.search(query, table="techniques", category=status, limit=limit * 2)

    # Filter to challenge source entries
    challenge_results = [r for r in results if r.get("source") == "challenges"]
    if not challenge_results:
        # Fallback: return all technique results if no challenges found
        challenge_results = results

    challenge_results = challenge_results[:limit]

    if not challenge_results:
        return f"No challenge results for '{query}'" + (f" (status={status})" if status else "") + "."

    lines = [f"## Challenge Search: \"{query}\" ({len(challenge_results)} results)\n"]

    for i, r in enumerate(challenge_results, 1):
        title = r.get("title", "untitled")
        cat = r.get("category", "")
        tags = r.get("tags", "")
        file_path = r.get("file_path", "")
        source = r.get("source", "")
        snippet = r.get("snippet", _fmt_snippet(r.get("content", "")))

        lines.append(f"{i}. {title}")
        parts = []
        if source:
            parts.append(f"Source: {source}")
        if cat:
            parts.append(f"Category: {cat}")
        if parts:
            lines.append("   " + " | ".join(parts))
        if tags:
            lines.append(f"   Tags: {tags[:100]}")
        if file_path:
            lines.append(f"   Path: {file_path}")
        if snippet:
            lines.append(f"   Match: {snippet}")
        lines.append("")

    return "\n".join(lines)

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def triage_search(query: str, program: str = "", limit: int = 10) -> str:
    """Search triage objections and kill reasons from past bug bounty submissions.

    Searches the 'triage_objections' table which contains documented reasons
    why findings were killed at Gate 1, Gate 2, or Phase 4.5, organized by
    program and kill reason.

    Use this BEFORE Gate 1/Gate 2 to check if similar findings were previously
    killed for the same program or vulnerability class. This prevents repeating
    known-bad submissions.

    Args:
        query:   Kill reason or vulnerability type, e.g. "oracle staleness", "intended behavior"
        program: Optional program name filter, e.g. "paradex", "okto"
        limit:   Max results (default 10)
    """
    if program:
        results = _triage_snippet_search(query, program=program, limit=limit)
    else:
        results = _triage_snippet_search(query, limit=limit)

    if not results:
        return f"No triage objections for '{query}'" + (f" (program={program})" if program else "") + "."

    lines = [f"## Triage Objections: \"{query}\" ({len(results)} results)\n"]

    for i, r in enumerate(results, 1):
        title = r.get("title", "untitled")
        prog = r.get("program", "")
        snippet = r.get("snippet", r.get("kill_reason", "")[:200])
        tags = r.get("tags", "")
        file_path = r.get("file_path", "")

        lines.append(f"{i}. {title}")
        parts = []
        if prog:
            parts.append(f"Program: {prog}")
        if tags:
            parts.append(f"Tags: {tags[:80]}")
        if parts:
            lines.append("   " + " | ".join(parts))
        if snippet:
            lines.append(f"   Match: {snippet}")
        if file_path:
            lines.append(f"   Path: {file_path}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def routed_search(role: str, query: str, phase: str = "", program: str = "", limit: int = 8) -> str:
    """Role-aware knowledge retrieval that avoids mixing incompatible memory types.

    Use this as the DEFAULT pipeline lookup before falling back to smart_search.
    It routes the same query through a role-specific profile:
    - discovery roles emphasize scenarios, protocol checklists, techniques, CVEs
    - reporting/review roles emphasize submissions, decisions, triage objections
    - AI roles emphasize AI/LLM references and llm-wiki sources

    Args:
        role: Agent role, e.g. scout, analyst, ai-recon, reporter, critic, triager-sim.
        query: 2-4 keyword search query.
        phase: Optional pipeline phase label for auditability.
        program: Optional bounty program name for same-program triage memory.
        limit: Max rows per routed section cap (default 8).
    """
    normalized_role, profile = _profile_for_role(role)
    lines = [
        f"## Routed Knowledge Search: {normalized_role}",
        f"Query: {query}",
    ]
    if phase:
        lines.append(f"Phase: {phase}")
    if program:
        lines.append(f"Program filter: {program}")
    lines.append("")
    lines.append("Priority sources:")
    for item in profile["priority"]:
        lines.append(f"- {item}")
    lines.append("Avoid:")
    for item in profile["avoid"]:
        lines.append(f"- {item}")

    any_results = False
    for section in profile["sections"]:
        rows = _run_route_section(section, query, program, limit)
        lines.append("")
        lines.append(f"### {section['label']}")
        if not rows:
            lines.append("(no routed matches)")
            continue
        any_results = True
        for i, row in enumerate(rows, 1):
            lines.append(f"{i}. {_format_route_row(row)}")

    if not any_results:
        lines.append("")
        lines.append("Fallback: use smart_search with a shorter 2-3 keyword query.")
    return "\n".join(lines)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def search_all(query: str, limit: int = 10) -> str:
    """Search all indexed knowledge tables simultaneously for broad coverage.

    Queries techniques, external_techniques, exploitdb, nuclei, poc_github,
    trickest_cve, web_articles, and triage_objections tables at once, with
    cross-table normalized BM25 ranking. Each result is labelled with its
    source table. Use this as the 'I need everything about X' tool.

    Use this when you need:
    - Comprehensive coverage across internal docs + external repos + exploit DBs
    - Initial recon on an unfamiliar vulnerability class or CVE
    - Cross-referencing a topic across multiple knowledge sources

    Args:
        query: Any security topic, CVE, technique, tool name, or keyword
        limit: Max total results returned across all tables (default 10)
    """
    results = _indexer.search_all(query, limit=limit)

    if not results:
        return f"No results for '{query}' across any table."

    lines = [f"## Search All: \"{query}\" ({len(results)} results)\n"]

    for i, r in enumerate(results, 1):
        source_table = r.get("_source_table", "?")
        rank = r.get("rank", 0)

        # Pick the most descriptive field as title depending on table
        if source_table == "exploitdb":
            title = r.get("description", "untitled")[:100]
            ident = f"ExploitDB #{r.get('exploit_id', '?')}"
        elif source_table == "nuclei":
            title = r.get("name", r.get("template_id", "untitled"))
            ident = f"Nuclei: {r.get('template_id', '?')}"
        elif source_table == "poc_github":
            title = f"{r.get('cve_id', '?')} — {r.get('repo_name', '')}"
            ident = "PoC-GitHub"
        elif source_table == "trickest_cve":
            cve_id = r.get("cve_id", "?")
            desc = r.get("description", "")[:80]
            title = f"{cve_id} — {desc}" if desc else cve_id
            ident = f"CVE-DB:{r.get('year', '?')}"
        elif source_table == "external_techniques":
            title = r.get("title", "untitled")
            ident = f"ext:{r.get('source_repo', '?')}"
        elif source_table == "web_articles":
            title = r.get("title", "untitled")[:100]
            ident = f"web:{r.get('domain', '?')}"
        elif source_table == "triage_objections":
            title = r.get("title", "untitled")
            ident = f"triage:{r.get('program', '?')}"
        else:
            title = r.get("title", "untitled")
            ident = "internal"

        lines.append(f"{i}. [{source_table}] ({ident}) {title}")

        # Secondary details
        detail_parts = []
        if source_table in ("techniques", "external_techniques", "web_articles"):
            cat = r.get("category", "")
            if cat:
                detail_parts.append(f"cat={cat}")
            fp = r.get("file_path", r.get("source_url", ""))
            if fp:
                detail_parts.append(f"path={fp}")
            tags = r.get("tags", "")
            if tags:
                detail_parts.append(f"tags={tags[:60]}")
            snippet = r.get("snippet", _fmt_snippet(r.get("content", "")))
            if snippet:
                detail_parts.append(f"match: {snippet}")
        elif source_table == "triage_objections":
            program = r.get("program", "")
            reason = r.get("kill_reason", "")
            file_path = r.get("file_path", "")
            if program:
                detail_parts.append(f"program={program}")
            if reason:
                detail_parts.append(f"reason={reason[:120]}")
            if file_path:
                detail_parts.append(f"path={file_path}")
        elif source_table == "nuclei":
            sev = r.get("severity", "")
            if sev:
                detail_parts.append(f"severity={sev.upper()}")
            cve = r.get("cve_id", "")
            if cve:
                detail_parts.append(f"cve={cve}")
        elif source_table == "exploitdb":
            plat = r.get("platform", "")
            if plat:
                detail_parts.append(f"platform={plat}")
            cve = r.get("cve_codes", "")
            if cve:
                detail_parts.append(f"cve={cve}")
        elif source_table == "poc_github":
            url = r.get("github_url", "")
            if url:
                detail_parts.append(f"url={url}")
        elif source_table == "trickest_cve":
            products = r.get("products", "")
            if products:
                detail_parts.append(f"products={products[:80]}")
            cwe = r.get("cwe", "")
            if cwe:
                detail_parts.append(f"cwe={cwe}")
            poc = r.get("poc_urls", "")
            if poc:
                first_url = poc.split()[0] if poc.strip() else ""
                if first_url:
                    detail_parts.append(f"poc={first_url}")

        if detail_parts:
            lines.append("   " + " | ".join(detail_parts))
        lines.append("")

    return "\n".join(lines)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def smart_search(query: str, limit: int = 10) -> str:
    """Broad fallback search across all knowledge tables with automatic relaxation.

    Unlike search_all which requires all terms to match (AND), smart_search
    progressively relaxes the query if no results are found:
    1. Try exact AND match across all tables
    2. Convert to OR match (any term matches)
    3. Use only the 2-3 most distinctive terms with OR

    Prefer routed_search(role, query, ...) for pipeline agents. Use this when
    routed_search returns too little or when you explicitly want broad recall:
    - Verbose natural language queries ("QNAP buffer overflow in wfm2 function")
    - Multi-keyword searches that might be too specific
    - When you're not sure which terms will match

    Args:
        query: Any search query — can be verbose, smart_search handles it automatically
        limit: Max total results returned across all tables (default 10)
    """
    results, level = _indexer.relaxed_search_all(query, limit=limit)

    if not results:
        return f"No results for '{query}' across any table (tried exact, OR, and top-terms relaxation)."

    lines = [f"## Smart Search: \"{query}\" ({len(results)} results, relaxation={level})\n"]

    for i, r in enumerate(results, 1):
        source_table = r.get("_source_table", "?")

        if source_table == "exploitdb":
            title = r.get("description", "untitled")[:100]
            ident = f"ExploitDB #{r.get('exploit_id', '?')}"
        elif source_table == "nuclei":
            title = r.get("name", r.get("template_id", "untitled"))
            ident = f"Nuclei: {r.get('template_id', '?')}"
        elif source_table == "poc_github":
            title = f"{r.get('cve_id', '?')} — {r.get('repo_name', '')}"
            ident = "PoC-GitHub"
        elif source_table == "trickest_cve":
            cve_id = r.get("cve_id", "?")
            desc = r.get("description", "")[:80]
            title = f"{cve_id} — {desc}" if desc else cve_id
            ident = f"CVE-DB:{r.get('year', '?')}"
        elif source_table == "web_articles":
            title = r.get("title", "untitled")[:100]
            ident = f"web:{r.get('domain', '?')}"
        elif source_table == "triage_objections":
            title = r.get("title", "untitled")
            ident = f"triage:{r.get('program', '?')}"
        elif source_table == "external_techniques":
            title = r.get("title", "untitled")
            ident = f"ext:{r.get('source_repo', '?')}"
        else:
            title = r.get("title", "untitled")
            ident = "internal"

        lines.append(f"{i}. [{source_table}] ({ident}) {title}")

        detail_parts = []
        if source_table in ("techniques", "external_techniques", "web_articles"):
            cat = r.get("category", "")
            if cat:
                detail_parts.append(f"cat={cat}")
            fp = r.get("file_path", r.get("source_url", ""))
            if fp:
                detail_parts.append(f"path={fp}")
            tags = r.get("tags", "")
            if tags:
                detail_parts.append(f"tags={tags[:60]}")
        elif source_table == "triage_objections":
            program = r.get("program", "")
            reason = r.get("kill_reason", "")
            file_path = r.get("file_path", "")
            if program:
                detail_parts.append(f"program={program}")
            if reason:
                detail_parts.append(f"reason={reason[:120]}")
            if file_path:
                detail_parts.append(f"path={file_path}")
        elif source_table == "exploitdb":
            plat = r.get("platform", "")
            cve = r.get("cve_codes", "")
            if plat:
                detail_parts.append(f"platform={plat}")
            if cve:
                detail_parts.append(f"cve={cve}")
        elif source_table in ("nuclei",):
            sev = r.get("severity", "")
            cve_id = r.get("cve_id", "")
            if sev:
                detail_parts.append(f"severity={sev}")
            if cve_id:
                detail_parts.append(f"cve={cve_id}")
        elif source_table in ("trickest_cve",):
            products = r.get("products", "")
            cwe = r.get("cwe", "")
            if products:
                detail_parts.append(f"products={products[:60]}")
            if cwe:
                detail_parts.append(f"cwe={cwe}")

        if detail_parts:
            lines.append("   " + " | ".join(detail_parts))
        lines.append("")

    if level != "exact":
        lines.append(f"Note: Query was relaxed to '{level}' mode to find results.")

    return "\n".join(lines)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def get_technique_content(file_path: str, max_lines: int = 100) -> str:
    """Read the full content of a specific knowledge file (drill-down after search).

    After finding a relevant file via technique_search, challenge_search, or
    search_all, use this to read its complete content. Handles truncation
    gracefully for large files.

    Use this when you need:
    - Full writeup content after a search hit
    - Complete technique documentation
    - Full exploit code or PoC from an indexed file

    Args:
        file_path: Absolute path to the file, as returned in 'Path:' field of search results
        max_lines: Max lines to return (default 100, increase for complete files)
    """
    if not file_path or not file_path.strip():
        return "Error: file_path is required."

    content = _indexer.get_content(file_path.strip(), max_lines=max_lines)
    if content.startswith("File not found:") or content.startswith("Error reading"):
        return content

    lines_count = content.count("\n")
    header = f"## {os.path.basename(file_path)} ({lines_count} lines shown)\n\n"
    return header + content


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def knowledge_stats() -> str:
    """Show statistics about the FTS5 knowledge database.

    Reports row counts per table, total document count, DB size on disk,
    and build timestamp. Use this to verify the DB is populated before
    running searches, or to understand what data is available.
    """
    info = _indexer.stats()

    if "error" in info:
        return f"Error: {info['error']}"

    lines = ["## Knowledge FTS5 Database Statistics\n"]

    tables = ["techniques", "external_techniques", "exploitdb", "nuclei", "poc_github", "trickest_cve", "web_articles", "triage_objections"]
    table_labels = {
        "techniques": "Internal techniques + challenges",
        "external_techniques": "External repos (PayloadsAllTheThings, HackTricks, how2heap, etc.)",
        "exploitdb": "ExploitDB entries",
        "nuclei": "Nuclei detection templates",
        "poc_github": "PoC-in-GitHub CVE repos",
        "trickest_cve": "Trickest CVE database",
        "web_articles": "Web articles (crawled security writeups)",
        "triage_objections": "Triage kill reasons + objections",
    }

    total = 0
    lines.append("### Row Counts")
    for t in tables:
        count = info.get(t, 0)
        total += count
        label = table_labels.get(t, t)
        lines.append(f"  {label:<52} {count:>8,}")

    lines.append(f"  {'TOTAL':<52} {total:>8,}")
    lines.append("")

    db_size = info.get("db_size_mb", "?")
    lines.append(f"### Database")
    lines.append(f"  Size:      {db_size} MB")

    build_ts = info.get("meta_build_timestamp", "unknown")
    build_sec = info.get("meta_build_seconds", "?")
    lines.append(f"  Built:     {build_ts} ({build_sec}s)")

    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
