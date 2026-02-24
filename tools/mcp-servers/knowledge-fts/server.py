#!/usr/bin/env python3
"""Knowledge FTS5 MCP Server — BM25 search over 84K+ security documents.

Tables indexed:
  - techniques:          internal knowledge/techniques/ + knowledge/challenges/
  - external_techniques: PayloadsAllTheThings, HackTricks, how2heap, GTFOBins, CTF-All-In-One, etc.
  - exploitdb:           47K+ ExploitDB entries
  - nuclei:              12K+ Nuclei detection templates
  - poc_github:          8K+ CVE PoC repos
"""
import os
import sys

# Add tools/ to path so we can import knowledge_indexer
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
from knowledge_indexer import KnowledgeIndexer

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("knowledge-fts")
_indexer = KnowledgeIndexer()


def _fmt_snippet(text: str, max_chars: int = 200) -> str:
    """Return first non-empty, non-heading line up to max_chars."""
    if not text:
        return ""
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped[:max_chars] + ("..." if len(stripped) > max_chars else "")
    return text[:max_chars]


@mcp.tool()
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
    int_results = _indexer.search(query, table="techniques", category=category, limit=limit)
    ext_results = _indexer.search(query, table="external_techniques", category=category, limit=limit)

    total = len(int_results) + len(ext_results)
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

    for i, r in enumerate(all_rows, 1):
        label = r.get("_table_label", "?")
        title = r.get("title", r.get("name", "untitled"))
        cat = r.get("category", "")
        tags = r.get("tags", "")
        file_path = r.get("file_path", "")
        source_repo = r.get("source_repo", r.get("source", ""))
        content = r.get("content", "")
        snippet = _fmt_snippet(content)

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
            lines.append(f"   Preview: {snippet}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool()
def exploit_search(query: str, platform: str = "", severity: str = "", limit: int = 10) -> str:
    """Search ExploitDB, Nuclei templates, and PoC-in-GitHub for exploits.

    Searches three exploit databases combined:
    - ExploitDB (47K+ exploits with CVE codes, platform, type)
    - Nuclei templates (12K+ detection templates with severity/CWE/CVE)
    - PoC-in-GitHub (8K+ CVE proof-of-concept repositories)

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

        else:
            lines.append(f"{i}. [{source}] {str(r)[:200]}")

        lines.append("")

    return "\n".join(lines)


@mcp.tool()
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
        content = r.get("content", "")
        snippet = _fmt_snippet(content)

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
            lines.append(f"   Preview: {snippet}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool()
def search_all(query: str, limit: int = 10) -> str:
    """Search ALL 5 knowledge tables simultaneously for the broadest coverage.

    Queries techniques, external_techniques, exploitdb, nuclei, and poc_github
    tables at once, sorted by BM25 rank. Each result is labelled with its
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
        elif source_table == "external_techniques":
            title = r.get("title", "untitled")
            ident = f"ext:{r.get('source_repo', '?')}"
        else:
            title = r.get("title", "untitled")
            ident = "internal"

        lines.append(f"{i}. [{source_table}] ({ident}) {title}")

        # Secondary details
        detail_parts = []
        if source_table in ("techniques", "external_techniques"):
            cat = r.get("category", "")
            if cat:
                detail_parts.append(f"cat={cat}")
            fp = r.get("file_path", "")
            if fp:
                detail_parts.append(f"path={fp}")
            content = r.get("content", "")
            if content:
                snippet = _fmt_snippet(content)
                if snippet:
                    detail_parts.append(f"preview: {snippet}")
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

        if detail_parts:
            lines.append("   " + " | ".join(detail_parts))
        lines.append("")

    return "\n".join(lines)


@mcp.tool()
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


@mcp.tool()
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

    tables = ["techniques", "external_techniques", "exploitdb", "nuclei", "poc_github"]
    table_labels = {
        "techniques": "Internal techniques + challenges",
        "external_techniques": "External repos (PayloadsAllTheThings, HackTricks, how2heap, etc.)",
        "exploitdb": "ExploitDB entries",
        "nuclei": "Nuclei detection templates",
        "poc_github": "PoC-in-GitHub CVE repos",
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
