#!/usr/bin/env python3
"""Terminator Infrastructure Client — unified CLI for RAG, Neo4j, PostgreSQL."""

import argparse
import json
import sys
import os
import hashlib
import subprocess
from datetime import datetime

# ── Constants ────────────────────────────────────────────────────────────────

PG_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "dbname": "shadowhunter",
    "user": "postgres",
    "password": "shadowhunter",
}
RAG_URL = os.getenv("RAG_API_URL", "http://localhost:8100")
TIMEOUT = 5


# ── Helpers ──────────────────────────────────────────────────────────────────

def get_pg_conn():
    """Return a psycopg2 connection with autocommit."""
    import psycopg2
    conn = psycopg2.connect(**PG_CONFIG, connect_timeout=TIMEOUT)
    conn.autocommit = True
    return conn


def get_graph():
    """Return an AttackGraph instance (adds project root to sys.path)."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    from tools.attack_graph.graph import AttackGraph
    return AttackGraph()


def output(data, args):
    """Print data as JSON or human-readable table."""
    if getattr(args, "json", False):
        print(json.dumps(data, indent=2, default=str))
        return

    if isinstance(data, dict):
        max_key = max((len(str(k)) for k in data), default=0)
        for k, v in data.items():
            print(f"  {str(k).ljust(max_key)}  {v}")
    elif isinstance(data, list):
        if not data:
            print("  (no results)")
            return
        if isinstance(data[0], dict):
            keys = list(data[0].keys())
            widths = {k: max(len(str(k)), max((len(str(row.get(k, ""))) for row in data), default=0)) for k in keys}
            header = "  ".join(str(k).ljust(widths[k]) for k in keys)
            print(header)
            print("-" * len(header))
            for row in data:
                print("  ".join(str(row.get(k, "")).ljust(widths[k]) for k in keys))
        else:
            for item in data:
                print(f"  {item}")
    else:
        print(data)


def err(msg):
    """Print error to stderr."""
    print(f"[ERROR] {msg}", file=sys.stderr)


# ── RAG Commands ─────────────────────────────────────────────────────────────

def cmd_rag_query(args):
    """POST /query to the RAG API."""
    import requests
    try:
        resp = requests.post(
            f"{RAG_URL}/query",
            json={"query": args.query, "limit": args.limit},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        results = resp.json()
        output(results, args)
    except requests.exceptions.ConnectionError:
        err(f"RAG API not reachable at {RAG_URL}")
    except requests.exceptions.Timeout:
        err(f"RAG API timeout ({TIMEOUT}s)")
    except Exception as e:
        err(f"RAG query failed: {e}")


def cmd_rag_ingest(args):
    """POST /ingest to the RAG API."""
    import requests
    payload = {
        "category": args.category,
        "technique": args.technique,
        "description": args.description,
        "content": args.content,
    }
    try:
        resp = requests.post(
            f"{RAG_URL}/ingest",
            json=payload,
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        result = resp.json()
        output(result, args)
    except requests.exceptions.ConnectionError:
        err(f"RAG API not reachable at {RAG_URL}")
    except requests.exceptions.Timeout:
        err(f"RAG API timeout ({TIMEOUT}s)")
    except Exception as e:
        err(f"RAG ingest failed: {e}")


# ── Graph Commands ───────────────────────────────────────────────────────────

def cmd_graph_ingest(args):
    """Ingest a recon JSON file into the Neo4j attack graph."""
    try:
        with open(args.file, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        err(f"File not found: {args.file}")
        return
    except json.JSONDecodeError as e:
        err(f"Invalid JSON in {args.file}: {e}")
        return

    try:
        graph = get_graph()
        graph.ingest_from_json(data)
        graph.close()
        result = {"status": "ok", "target": data.get("target", "unknown"), "file": args.file}
        output(result, args)
    except Exception as e:
        err(f"Graph ingest failed: {e}")


def cmd_graph_query(args):
    """Run a named query against the Neo4j attack graph."""
    query_name = args.query_name
    target = getattr(args, "target", None)

    try:
        graph = get_graph()

        if query_name == "critical_vulns":
            results = graph.get_critical_vulns(target_name=target)
        elif query_name == "attack_paths":
            if not target:
                err("--target is required for attack_paths query")
                graph.close()
                return
            results = graph.get_attack_paths(target)
        elif query_name == "attack_surface_summary":
            if not target:
                err("--target is required for attack_surface_summary query")
                graph.close()
                return
            results = graph.get_attack_surface_summary(target)
        elif query_name == "exploitable_services":
            if not target:
                err("--target is required for exploitable_services query")
                graph.close()
                return
            results = graph.get_exploitable_services(target)
        else:
            err(f"Unknown query: {query_name}. Available: critical_vulns, attack_paths, attack_surface_summary, exploitable_services")
            graph.close()
            return

        graph.close()
        output(results, args)
    except Exception as e:
        err(f"Graph query failed: {e}")


def cmd_graph_export(args):
    """Export the attack graph for a target as JSON."""
    if not args.target:
        err("--target is required for graph export")
        return
    try:
        graph = get_graph()
        data = graph.export_to_json(args.target)
        graph.close()
        output(data, args)
    except Exception as e:
        err(f"Graph export failed: {e}")


# ── DB Commands: Findings ────────────────────────────────────────────────────

def cmd_db_save_finding(args):
    """INSERT a new finding into the findings table."""
    try:
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO findings
               (target, title, severity, status, poc_tier, cvss_score,
                description, platform)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (
                args.target,
                args.title,
                args.severity,
                args.status or "ACTIVE",
                args.poc_tier,
                args.cvss,
                args.description,
                args.platform,
            ),
        )
        row = cur.fetchone()
        finding_id = row[0] if row else None
        cur.close()
        conn.close()
        result = {"status": "ok", "id": finding_id, "target": args.target, "title": args.title}
        output(result, args)
    except Exception as e:
        err(f"save-finding failed: {e}")


def cmd_db_update_finding(args):
    """UPDATE an existing finding by id."""
    sets = []
    vals = []
    if args.status:
        sets.append("status = %s")
        vals.append(args.status)
    if args.triager_outcome:
        sets.append("triager_outcome = %s")
        vals.append(args.triager_outcome)
    if args.bounty is not None:
        sets.append("bounty_amount = %s")
        vals.append(args.bounty)
    if args.submitted:
        sets.append("submitted_at = NOW()")

    if not sets:
        err("No fields to update. Use --status, --triager-outcome, --bounty, or --submitted.")
        return

    sets.append("updated_at = NOW()")
    vals.append(args.id)

    try:
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute(
            f"UPDATE findings SET {', '.join(sets)} WHERE id = %s",
            vals,
        )
        cur.close()
        conn.close()
        output({"status": "ok", "id": args.id, "updated_fields": [s.split(" =")[0] for s in sets[:-1]]}, args)
    except Exception as e:
        err(f"update-finding failed: {e}")


def cmd_db_list_findings(args):
    """SELECT findings with optional filters."""
    where = []
    vals = []
    if args.target:
        where.append("target = %s")
        vals.append(args.target)
    if args.status:
        where.append("status = %s")
        vals.append(args.status)

    clause = f"WHERE {' AND '.join(where)}" if where else ""
    try:
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute(
            f"""SELECT id, target, title, severity, status, poc_tier,
                       cvss_score, platform, triager_outcome, bounty_amount,
                       created_at
                FROM findings {clause}
                ORDER BY created_at DESC""",
            vals,
        )
        cols = [desc[0] for desc in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        cur.close()
        conn.close()
        output(rows, args)
    except Exception as e:
        err(f"list-findings failed: {e}")


def cmd_db_search_findings(args):
    """ILIKE search on title + description."""
    pattern = f"%{args.keyword}%"
    try:
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT id, target, title, severity, status, cvss_score, created_at
               FROM findings
               WHERE title ILIKE %s OR description ILIKE %s
               ORDER BY created_at DESC""",
            (pattern, pattern),
        )
        cols = [desc[0] for desc in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        cur.close()
        conn.close()
        output(rows, args)
    except Exception as e:
        err(f"search-findings failed: {e}")


# ── DB Commands: Failure Memory ──────────────────────────────────────────────

def cmd_db_log_failure(args):
    """INSERT a failure record into failure_memory."""
    try:
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO failure_memory (technique, error_description, solution)
               VALUES (%s, %s, %s)
               RETURNING id""",
            (args.technique, args.error, args.solution),
        )
        row = cur.fetchone()
        failure_id = row[0] if row else None
        cur.close()
        conn.close()
        output({"status": "ok", "id": failure_id, "technique": args.technique}, args)
    except Exception as e:
        err(f"log-failure failed: {e}")


def cmd_db_check_failures(args):
    """Search failure_memory by error_type or error_context ILIKE."""
    pattern = f"%{args.keyword}%"
    try:
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT id, technique, error_description, solution, created_at
               FROM failure_memory
               WHERE technique ILIKE %s OR error_description ILIKE %s
               ORDER BY created_at DESC""",
            (pattern, pattern),
        )
        cols = [desc[0] for desc in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        cur.close()
        conn.close()
        output(rows, args)
    except Exception as e:
        err(f"check-failures failed: {e}")


# ── DB Commands: Binary Cache ────────────────────────────────────────────────

def _compute_hashes(filepath):
    """Compute MD5 and SHA256 of a file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def _parse_file_output(filepath):
    """Parse `file` command output for arch and bits."""
    arch = "unknown"
    bits = 0
    try:
        result = subprocess.run(
            ["file", filepath],
            capture_output=True, text=True, timeout=TIMEOUT,
        )
        line = result.stdout.lower()
        if "x86-64" in line or "x86_64" in line or "amd64" in line:
            arch = "x86_64"
            bits = 64
        elif "x86" in line or "i386" in line or "i686" in line or "80386" in line:
            arch = "x86"
            bits = 32
        elif "aarch64" in line or "arm64" in line:
            arch = "aarch64"
            bits = 64
        elif "arm" in line:
            arch = "arm"
            bits = 32
        elif "mips" in line:
            arch = "mips"
            bits = 64 if "64" in line else 32
        elif "riscv" in line or "risc-v" in line:
            arch = "riscv"
            bits = 64 if "64" in line else 32

        if bits == 0:
            if "64-bit" in line:
                bits = 64
            elif "32-bit" in line:
                bits = 32
    except Exception:
        pass
    return arch, bits


def cmd_db_cache_binary(args):
    """Compute hashes, parse arch info, and INSERT into binary_cache."""
    filepath = args.file
    if not os.path.isfile(filepath):
        err(f"File not found: {filepath}")
        return

    try:
        md5_hex, sha256_hex = _compute_hashes(filepath)
    except Exception as e:
        err(f"Hash computation failed: {e}")
        return

    arch, bits = _parse_file_output(filepath)
    filename = os.path.basename(filepath)

    protections = None
    if args.protections:
        try:
            protections = json.loads(args.protections)
        except json.JSONDecodeError as e:
            err(f"Invalid JSON for --protections: {e}")
            return

    try:
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO binary_cache
               (md5, sha256, filename, arch, bits, protections, analysis_summary)
               VALUES (%s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (md5) DO UPDATE SET
                   sha256 = EXCLUDED.sha256,
                   filename = EXCLUDED.filename,
                   arch = EXCLUDED.arch,
                   bits = EXCLUDED.bits,
                   protections = COALESCE(EXCLUDED.protections, binary_cache.protections),
                   analysis_summary = COALESCE(EXCLUDED.analysis_summary, binary_cache.analysis_summary)
               RETURNING id""",
            (
                md5_hex,
                sha256_hex,
                filename,
                arch,
                bits,
                json.dumps(protections) if protections else None,
                args.summary,
            ),
        )
        row = cur.fetchone()
        cache_id = row[0] if row else None
        cur.close()
        conn.close()
        output({
            "status": "ok",
            "id": cache_id,
            "md5": md5_hex,
            "sha256": sha256_hex,
            "filename": filename,
            "arch": arch,
            "bits": bits,
        }, args)
    except Exception as e:
        err(f"cache-binary failed: {e}")


def cmd_db_check_binary(args):
    """SELECT from binary_cache by MD5 hash."""
    try:
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT id, md5, sha256, filename, arch, bits, protections,
                      analysis_summary, created_at
               FROM binary_cache WHERE md5 = %s""",
            (args.md5,),
        )
        cols = [desc[0] for desc in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        cur.close()
        conn.close()
        if rows:
            output(rows[0], args)
        else:
            output({"status": "miss", "md5": args.md5}, args)
    except Exception as e:
        err(f"check-binary failed: {e}")


# ── DB Commands: Agent Runs ──────────────────────────────────────────────────

def cmd_db_log_run(args):
    """INSERT an agent run record into agent_runs."""
    completed_at = None
    if args.status in ("COMPLETED", "FAILED"):
        completed_at = datetime.now()

    try:
        conn = get_pg_conn()
        cur = conn.cursor()
        payload = (
            args.session,
            args.agent,
            args.target,
            args.model,
            args.backend,
            args.parallel_group_id,
            args.status or "RUNNING",
            args.duration,
            args.tokens,
            args.summary,
            completed_at,
        )
        try:
            cur.execute(
                """INSERT INTO agent_runs
                   (session_id, agent_role, target, model, backend, parallel_group_id, status,
                    duration_seconds, tokens_used, output_summary, completed_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                payload,
            )
        except Exception:
            conn.rollback()
            cur.execute(
                """INSERT INTO agent_runs
                   (session_id, agent_role, target, model, status,
                    duration_seconds, tokens_used, output_summary, completed_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                (
                    args.session,
                    args.agent,
                    args.target,
                    args.model,
                    args.status or "RUNNING",
                    args.duration,
                    args.tokens,
                    args.summary,
                    completed_at,
                ),
            )
        row = cur.fetchone()
        run_id = row[0] if row else None
        cur.close()
        conn.close()
        output({"status": "ok", "id": run_id, "agent": args.agent, "run_status": args.status}, args)
    except Exception as e:
        err(f"log-run failed: {e}")


def cmd_db_list_runs(args):
    """SELECT from agent_runs with optional filters."""
    where = []
    vals = []
    if args.session:
        where.append("session_id = %s")
        vals.append(args.session)
    if args.target:
        where.append("target = %s")
        vals.append(args.target)

    clause = f"WHERE {' AND '.join(where)}" if where else ""
    try:
        conn = get_pg_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                f"""SELECT id, session_id, agent_role, target, model, backend, parallel_group_id, status,
                           duration_seconds, tokens_used, output_summary,
                           created_at, completed_at
                    FROM agent_runs {clause}
                    ORDER BY created_at DESC""",
                vals,
            )
        except Exception:
            conn.rollback()
            cur.execute(
                f"""SELECT id, session_id, agent_role, target, model, status,
                           duration_seconds, tokens_used, output_summary,
                           created_at, completed_at
                    FROM agent_runs {clause}
                    ORDER BY created_at DESC""",
                vals,
            )
        cols = [desc[0] for desc in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        cur.close()
        conn.close()
        output(rows, args)
    except Exception as e:
        err(f"list-runs failed: {e}")


def cmd_db_cost_summary(args):
    """Aggregate cost/token summary per target from agent_runs."""
    where = []
    vals = []
    if args.target:
        where.append("target = %s")
        vals.append(args.target)

    clause = f"WHERE {' AND '.join(where)}" if where else ""
    try:
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute(
            f"""SELECT target, agent_role,
                       COUNT(*) as runs,
                       COALESCE(SUM(tokens_used), 0) as total_tokens,
                       COALESCE(SUM(duration_seconds), 0) as total_duration_sec,
                       COUNT(CASE WHEN status = 'COMPLETED' THEN 1 END) as completed,
                       COUNT(CASE WHEN status = 'FAILED' THEN 1 END) as failed
                FROM agent_runs {clause}
                GROUP BY target, agent_role
                ORDER BY target, total_tokens DESC""",
            vals,
        )
        cols = [desc[0] for desc in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]

        # Add estimated cost (opus=$15/M input, sonnet=$3/M input — rough)
        MODEL_COST_PER_M = {"opus": 15.0, "sonnet": 3.0, "haiku": 0.25}
        for row in rows:
            row["total_tokens"] = int(row["total_tokens"])
            row["total_duration_sec"] = int(row["total_duration_sec"])

        # Also produce per-target summary
        if args.target:
            total_tokens = sum(r["total_tokens"] for r in rows)
            total_runs = sum(r["runs"] for r in rows)
            summary = {
                "target": args.target,
                "total_runs": total_runs,
                "total_tokens": total_tokens,
                "total_duration_sec": sum(r["total_duration_sec"] for r in rows),
                "agents": rows,
            }
            output(summary, args)
        else:
            output(rows, args)

        cur.close()
        conn.close()
    except Exception as e:
        err(f"cost-summary failed: {e}")


# ── Argument Parsing ─────────────────────────────────────────────────────────

def build_parser():
    """Build the full argparse tree."""
    parser = argparse.ArgumentParser(
        prog="infra_client",
        description="Terminator Infrastructure Client -- unified CLI for RAG, Neo4j, PostgreSQL.",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    subparsers = parser.add_subparsers(dest="service", help="Service to interact with")

    # ── RAG ──────────────────────────────────────────────────────────────
    rag = subparsers.add_parser("rag", help="RAG API commands")
    rag_sub = rag.add_subparsers(dest="action")

    rag_query = rag_sub.add_parser("query", help="Search the RAG knowledge base")
    rag_query.add_argument("query", help="Search query text")
    rag_query.add_argument("--limit", type=int, default=5, help="Max results (default: 5)")
    rag_query.set_defaults(func=cmd_rag_query)

    rag_ingest = rag_sub.add_parser("ingest", help="Ingest a new knowledge entry")
    rag_ingest.add_argument("--category", required=True, help="Category (e.g. Pwn, Web, Crypto)")
    rag_ingest.add_argument("--technique", required=True, help="Technique name")
    rag_ingest.add_argument("--description", required=True, help="Short description")
    rag_ingest.add_argument("--content", required=True, help="Full content text")
    rag_ingest.set_defaults(func=cmd_rag_ingest)

    # ── Graph ────────────────────────────────────────────────────────────
    graph = subparsers.add_parser("graph", help="Neo4j attack graph commands")
    graph_sub = graph.add_subparsers(dest="action")

    graph_ingest = graph_sub.add_parser("ingest", help="Import recon JSON into graph")
    graph_ingest.add_argument("--file", required=True, help="Path to recon_report.json")
    graph_ingest.set_defaults(func=cmd_graph_ingest)

    graph_query = graph_sub.add_parser("query", help="Run a named graph query")
    graph_query.add_argument(
        "query_name",
        choices=["critical_vulns", "attack_paths", "attack_surface_summary", "exploitable_services"],
        help="Query to run",
    )
    graph_query.add_argument("--target", help="Target name filter")
    graph_query.set_defaults(func=cmd_graph_query)

    graph_export = graph_sub.add_parser("export", help="Export attack graph as JSON")
    graph_export.add_argument("--target", required=True, help="Target name to export")
    graph_export.set_defaults(func=cmd_graph_export)

    # ── DB ────────────────────────────────────────────────────────────────
    db = subparsers.add_parser("db", help="PostgreSQL direct commands")
    db_sub = db.add_subparsers(dest="action")

    # save-finding
    sf = db_sub.add_parser("save-finding", help="Insert a new finding")
    sf.add_argument("--target", required=True, help="Target name/URL")
    sf.add_argument("--title", required=True, help="Finding title")
    sf.add_argument("--severity", default="Medium", help="Severity level (default: Medium)")
    sf.add_argument("--status", default="ACTIVE", help="Status (default: ACTIVE)")
    sf.add_argument("--poc-tier", type=int, dest="poc_tier", help="PoC quality tier (1-4)")
    sf.add_argument("--cvss", type=float, help="CVSS score")
    sf.add_argument("--description", help="Detailed description")
    sf.add_argument("--platform", help="Platform (e.g. Immunefi, HackerOne)")
    sf.set_defaults(func=cmd_db_save_finding)

    # update-finding
    uf = db_sub.add_parser("update-finding", help="Update an existing finding")
    uf.add_argument("--id", type=int, required=True, help="Finding ID")
    uf.add_argument("--status", help="New status")
    uf.add_argument("--triager-outcome", dest="triager_outcome", help="Triager outcome")
    uf.add_argument("--bounty", type=float, help="Bounty amount")
    uf.add_argument("--submitted", action="store_true", help="Mark as submitted now")
    uf.set_defaults(func=cmd_db_update_finding)

    # list-findings
    lf = db_sub.add_parser("list-findings", help="List findings with optional filters")
    lf.add_argument("--target", help="Filter by target")
    lf.add_argument("--status", help="Filter by status")
    lf.set_defaults(func=cmd_db_list_findings)

    # search-findings
    sf2 = db_sub.add_parser("search-findings", help="ILIKE search on findings")
    sf2.add_argument("keyword", help="Search keyword")
    sf2.set_defaults(func=cmd_db_search_findings)

    # log-failure
    logf = db_sub.add_parser("log-failure", help="Record a failure in failure_memory")
    logf.add_argument("--technique", required=True, help="Technique that failed (e.g. ROP chain)")
    logf.add_argument("--error", required=True, help="Error context / message")
    logf.add_argument("--solution", required=True, help="Solution or workaround found")
    logf.set_defaults(func=cmd_db_log_failure)

    # check-failures
    cf = db_sub.add_parser("check-failures", help="Search failure_memory by keyword")
    cf.add_argument("keyword", help="Search keyword")
    cf.set_defaults(func=cmd_db_check_failures)

    # cache-binary
    cb = db_sub.add_parser("cache-binary", help="Cache binary metadata with hashes")
    cb.add_argument("--file", required=True, help="Path to binary file")
    cb.add_argument("--summary", help="Analysis summary text")
    cb.add_argument("--protections", help="JSON string of protections (e.g. '{\"canary\":true}')")
    cb.set_defaults(func=cmd_db_cache_binary)

    # check-binary
    chb = db_sub.add_parser("check-binary", help="Look up cached binary by MD5")
    chb.add_argument("--md5", required=True, help="MD5 hash to look up")
    chb.set_defaults(func=cmd_db_check_binary)

    # log-run
    lr = db_sub.add_parser("log-run", help="Record an agent run")
    lr.add_argument("--session", required=True, help="Session ID")
    lr.add_argument("--agent", required=True, help="Agent role (e.g. reverser, chain)")
    lr.add_argument("--target", required=True, help="Target name")
    lr.add_argument("--status", default="RUNNING", help="Run status (default: RUNNING)")
    lr.add_argument("--duration", type=int, dest="duration", help="Duration in seconds")
    lr.add_argument("--tokens", type=int, help="Tokens used")
    lr.add_argument("--model", help="Model used (e.g. sonnet, claude-opus-4-6[1m])")
    lr.add_argument("--backend", help="Backend used (e.g. claude, codex)")
    lr.add_argument("--parallel-group-id", dest="parallel_group_id", help="Parallel execution group ID")
    lr.add_argument("--summary", help="Output summary text")
    lr.set_defaults(func=cmd_db_log_run)

    # list-runs
    lrs = db_sub.add_parser("list-runs", help="List agent runs")
    lrs.add_argument("--session", help="Filter by session ID")
    lrs.add_argument("--target", help="Filter by target")
    lrs.set_defaults(func=cmd_db_list_runs)

    # cost-summary
    cs = db_sub.add_parser("cost-summary", help="Aggregate cost/token summary per target")
    cs.add_argument("--target", help="Filter by target (omit for all targets)")
    cs.set_defaults(func=cmd_db_cost_summary)

    return parser


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.service:
        parser.print_help()
        return

    if not hasattr(args, "func"):
        # Service was given but no action subcommand
        if args.service == "rag":
            parser.parse_args(["rag", "--help"])
        elif args.service == "graph":
            parser.parse_args(["graph", "--help"])
        elif args.service == "db":
            parser.parse_args(["db", "--help"])
        else:
            parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
