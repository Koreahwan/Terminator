#!/usr/bin/env python3
"""GraphRAG Security MCP server: pandas-based direct parquet search (no LLM calls)."""
import os
import re
import sys

import pandas as pd
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit_search

mcp = FastMCP("graphrag-security")

GRAPHRAG_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../graphrag-security")
OUTPUT_DIR = os.path.join(GRAPHRAG_ROOT, "output")

# Lazy-loaded DataFrames (cached after first load)
_cache: dict[str, pd.DataFrame] = {}


def _load(name: str) -> pd.DataFrame:
    if name not in _cache:
        path = os.path.join(OUTPUT_DIR, f"{name}.parquet")
        if not os.path.exists(path):
            return pd.DataFrame()
        _cache[name] = pd.read_parquet(path)
    return _cache[name]


def _keyword_score(text: str, keywords: list[str]) -> int:
    if not isinstance(text, str):
        return 0
    text_lower = text.lower()
    return sum(1 for kw in keywords if kw in text_lower)


def _search_entities(query: str, top_n: int = 15) -> str:
    df = _load("entities")
    if df.empty:
        return "No entities data."
    keywords = [k.strip().lower() for k in re.split(r'[\s,]+', query) if len(k.strip()) > 1]
    if not keywords:
        return "Empty query."

    df = df.copy()
    df["_score"] = df["title"].apply(lambda t: _keyword_score(t, keywords) * 3) + \
                   df["description"].apply(lambda d: _keyword_score(d, keywords))
    hits = df[df["_score"] > 0].nlargest(top_n, "_score")
    if hits.empty:
        return f"No entities matching '{query}'."

    lines = [f"## Entities matching '{query}' ({len(hits)} results)\n"]
    for _, row in hits.iterrows():
        desc = str(row.get("description", ""))[:200]
        lines.append(f"- **{row['title']}** (type={row.get('type','?')}, freq={row.get('frequency',0)}, deg={row.get('degree',0)})")
        if desc:
            lines.append(f"  {desc}")
    return "\n".join(lines)


def _search_relationships(query: str, top_n: int = 15) -> str:
    df = _load("relationships")
    if df.empty:
        return "No relationships data."
    keywords = [k.strip().lower() for k in re.split(r'[\s,]+', query) if len(k.strip()) > 1]
    if not keywords:
        return "Empty query."

    df = df.copy()
    df["_score"] = df["source"].apply(lambda s: _keyword_score(s, keywords) * 2) + \
                   df["target"].apply(lambda t: _keyword_score(t, keywords) * 2) + \
                   df["description"].apply(lambda d: _keyword_score(d, keywords))
    hits = df[df["_score"] > 0].nlargest(top_n, "_score")
    if hits.empty:
        return f"No relationships matching '{query}'."

    lines = [f"## Relationships matching '{query}' ({len(hits)} results)\n"]
    for _, row in hits.iterrows():
        desc = str(row.get("description", ""))[:200]
        lines.append(f"- **{row['source']}** → **{row['target']}** (weight={row.get('weight',0):.1f})")
        if desc:
            lines.append(f"  {desc}")
    return "\n".join(lines)


def _search_community_reports(query: str, top_n: int = 10) -> str:
    df = _load("community_reports")
    if df.empty:
        return "No community reports data."
    keywords = [k.strip().lower() for k in re.split(r'[\s,]+', query) if len(k.strip()) > 1]
    if not keywords:
        return "Empty query."

    df = df.copy()
    df["_score"] = df["title"].apply(lambda t: _keyword_score(t, keywords) * 3) + \
                   df["summary"].apply(lambda s: _keyword_score(s, keywords) * 2) + \
                   df["full_content"].apply(lambda c: _keyword_score(c, keywords))
    hits = df[df["_score"] > 0].nlargest(top_n, "_score")
    if hits.empty:
        return f"No community reports matching '{query}'."

    lines = [f"## Community Reports matching '{query}' ({len(hits)} results)\n"]
    for _, row in hits.iterrows():
        summary = str(row.get("summary", ""))[:300]
        lines.append(f"### {row['title']} (rank={row.get('rank',0):.1f}, level={row.get('level','?')})")
        if summary:
            lines.append(f"{summary}\n")
    return "\n".join(lines)


def _search_text_units(query: str, top_n: int = 10) -> str:
    df = _load("text_units")
    if df.empty:
        return "No text units data."
    keywords = [k.strip().lower() for k in re.split(r'[\s,]+', query) if len(k.strip()) > 1]
    if not keywords:
        return "Empty query."

    df = df.copy()
    df["_score"] = df["text"].apply(lambda t: _keyword_score(t, keywords))
    hits = df[df["_score"] > 0].nlargest(top_n, "_score")
    if hits.empty:
        return f"No text chunks matching '{query}'."

    lines = [f"## Text chunks matching '{query}' ({len(hits)} results)\n"]
    for _, row in hits.iterrows():
        text = str(row.get("text", ""))[:400]
        lines.append(f"---\n{text}\n")
    return "\n".join(lines)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def knowledge_search(query: str, mode: str = "local") -> str:
    """Search the security knowledge graph (no LLM, instant pandas search).

    Args:
        query: Search query (e.g., 'heap overflow', 'CVE-2021-44228', 'ROP chain')
        mode: 'local' = entities+relationships, 'global' = community reports, 'drift' = text chunks
    """
    if mode == "global":
        return _search_community_reports(query)
    elif mode == "drift":
        return _search_text_units(query)
    else:
        ent = _search_entities(query)
        rel = _search_relationships(query, top_n=10)
        return f"{ent}\n\n{rel}"


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def knowledge_global(query: str) -> str:
    """Search community-level summaries in the security knowledge graph (instant, no LLM).

    Args:
        query: High-level question about security patterns, attack categories, or vulnerability classes
    """
    return _search_community_reports(query)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def knowledge_drift(query: str) -> str:
    """Broad text search across all indexed security documents (instant, no LLM).

    Args:
        query: Open-ended exploration query to discover related concepts
    """
    return _search_text_units(query)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def exploit_lookup(query: str) -> str:
    """Search ExploitDB, PoC-in-GitHub, and trickest-cve for exploits matching query.

    Args:
        query: CVE ID (e.g., 'CVE-2021-44228') or keyword (e.g., 'apache log4j rce')
    """
    return exploit_search.unified_search(query)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def similar_findings(description: str) -> str:
    """Find similar past security findings by searching entities and community reports.

    Args:
        description: Description of a vulnerability or finding to find similar cases
    """
    ent = _search_entities(description, top_n=10)
    comm = _search_community_reports(description, top_n=5)
    return f"{ent}\n\n{comm}"


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=False))
def knowledge_ingest(file_path: str, doc_type: str = "unknown") -> str:
    """Ingest a new document into the security knowledge graph.

    Args:
        file_path: Absolute path to the document to ingest (markdown, txt, etc.)
        doc_type: Document type hint: 'writeup', 'report', 'technique', 'cve', 'unknown'
    """
    graphrag_root = os.path.abspath(GRAPHRAG_ROOT)
    script = os.path.join(graphrag_root, "incremental_index.sh")

    if not os.path.exists(file_path):
        return f"File not found: {file_path}"

    if not os.path.exists(script):
        input_dir = os.path.join(graphrag_root, "input")
        os.makedirs(input_dir, exist_ok=True)
        dest = os.path.join(input_dir, os.path.basename(file_path))
        try:
            import shutil
            shutil.copy2(file_path, dest)
            return (
                f"Copied {file_path} to {dest}. "
                f"Run 'graphrag index --root {graphrag_root}' to re-index."
            )
        except Exception as e:
            return f"Error copying file: {str(e)}"

    try:
        result = subprocess.run(
            ["bash", script, file_path, doc_type],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            return f"Ingest failed (rc={result.returncode}): {result.stderr[:500]}"
        return result.stdout.strip() or f"Ingested {file_path} as {doc_type}"
    except subprocess.TimeoutExpired:
        return "Ingest timed out after 120s"
    except Exception as e:
        return f"Ingest error: {str(e)}"


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def knowledge_graph_query(cypher: str) -> str:
    """Run a Cypher query against the Neo4j attack graph.

    Args:
        cypher: Cypher query string (e.g., 'MATCH (n:Vulnerability) RETURN n LIMIT 10')
    """
    import subprocess
    cli_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "../../attack_graph/cli.py"
    )
    cli_path = os.path.abspath(cli_path)

    if not os.path.exists(cli_path):
        return f"Attack graph CLI not found at {cli_path}."

    try:
        result = subprocess.run(
            ["python3", cli_path, "query", cypher],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            stderr = result.stderr[:300]
            return f"Query error (rc={result.returncode}): {stderr}"
        return result.stdout.strip() or "(no results)"
    except subprocess.TimeoutExpired:
        return "Cypher query timed out after 30s"
    except Exception as e:
        return f"Graph query error: {str(e)}"


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def knowledge_stats() -> str:
    """Show statistics about the indexed security knowledge graph."""
    stats = []
    for name in ["entities", "relationships", "communities", "community_reports", "text_units", "documents"]:
        df = _load(name)
        stats.append(f"- {name}: {len(df)} rows")

    entities = _load("entities")
    if not entities.empty and "type" in entities.columns:
        type_counts = entities["type"].value_counts().head(10)
        stats.append("\nTop entity types:")
        for t, c in type_counts.items():
            stats.append(f"  - {t}: {c}")

    return "\n".join(stats)


if __name__ == "__main__":
    mcp.run()
