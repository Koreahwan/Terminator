"""
Terminator Dashboard - Database Service
PostgreSQL connection and all DB query helpers.
"""

import logging
from typing import Any, Optional, Sequence

from web.config import DB_CONFIG

logger = logging.getLogger(__name__)
_AGENT_RUN_COLUMNS: set[str] | None = None

_ALLOWED_FINDING_FIELDS: set[str] = {
    "target",
    "title",
    "severity",
    "status",
    "poc_tier",
    "cvss_score",
    "description",
    "poc_summary",
    "platform",
    "submitted_at",
    "triager_outcome",
    "bounty_amount",
}


def _fetchall_dicts(cur) -> list[dict[str, Any]]:
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def _isoformat_fields(rows: Sequence[dict[str, Any]], fields: Sequence[str]) -> None:
    for r in rows:
        for k in fields:
            v = r.get(k)
            if v:
                r[k] = v.isoformat()


def get_connection():
    """Get a PostgreSQL connection using psycopg2.

    Returns a new connection each call. Caller is responsible for closing.
    Raises ImportError if psycopg2 is not installed,
    or psycopg2.OperationalError if the DB is unreachable.
    """
    import psycopg2
    return psycopg2.connect(**DB_CONFIG)


def _get_agent_run_columns() -> set[str]:
    global _AGENT_RUN_COLUMNS
    if _AGENT_RUN_COLUMNS is not None:
        return _AGENT_RUN_COLUMNS

    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT column_name
               FROM information_schema.columns
               WHERE table_name = 'agent_runs'"""
        )
        _AGENT_RUN_COLUMNS = {row[0] for row in cur.fetchall()}
        cur.close()
        return _AGENT_RUN_COLUMNS
    finally:
        conn.close()


def _agent_run_select_sql(where: str, *, active_only: bool = False, recent_window: bool = False) -> str:
    columns = _get_agent_run_columns()
    select_parts = [
        "id",
        "session_id",
        "agent_role",
        "target",
        "model",
        "status",
        "duration_seconds",
        "tokens_used",
        "output_summary",
        "artifacts",
        "created_at",
        "completed_at",
    ]
    if "backend" in columns:
        select_parts.append("backend")
    else:
        select_parts.append("NULL AS backend")
    if "parallel_group_id" in columns:
        select_parts.append("parallel_group_id")
    else:
        select_parts.append("NULL AS parallel_group_id")

    base = f"SELECT {', '.join(select_parts)} FROM agent_runs"
    if active_only:
        return base + " WHERE status = 'RUNNING' ORDER BY created_at DESC"
    if recent_window:
        return (
            base
            + " WHERE status = 'RUNNING' OR (completed_at IS NOT NULL AND completed_at > NOW() - INTERVAL '30 seconds')"
            + " ORDER BY created_at DESC"
        )
    return f"{base} {where} ORDER BY created_at DESC LIMIT %s"


# ── Agent Runs ──

def list_agent_runs(session: Optional[str] = None, target: Optional[str] = None, limit: int = 50) -> list:
    """Fetch agent runs from the agent_runs table."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        conditions = []
        params = []
        if session:
            conditions.append("session_id = %s")
            params.append(session)
        if target:
            conditions.append("target = %s")
            params.append(target)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        cur.execute(_agent_run_select_sql(where), params)
        rows = _fetchall_dicts(cur)
        _isoformat_fields(rows, ("created_at", "completed_at"))
        cur.close()
        return rows
    finally:
        conn.close()


def list_active_agent_runs() -> list:
    """Fetch currently running agents (status=RUNNING)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(_agent_run_select_sql("", active_only=True))
        rows = _fetchall_dicts(cur)
        _isoformat_fields(rows, ("created_at", "completed_at"))
        cur.close()
        return rows
    finally:
        conn.close()


def list_recent_and_running_agents() -> list:
    """Fetch running + recently completed agents (for WebSocket streaming)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(_agent_run_select_sql("", recent_window=True))
        rows = _fetchall_dicts(cur)
        _isoformat_fields(rows, ("created_at", "completed_at"))
        cur.close()
        return rows
    finally:
        conn.close()


# ── Findings CRUD ──

def list_findings(target: Optional[str] = None, status: Optional[str] = None, limit: int = 50) -> tuple:
    """Fetch findings from the findings table. Returns (rows, total)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        conditions = []
        params = []
        if target:
            conditions.append("target = %s")
            params.append(target)
        if status:
            conditions.append("status = %s")
            params.append(status)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        cur.execute(
            f"""SELECT id, target, title, severity, status, poc_tier, cvss_score,
                       description, poc_summary, platform, submitted_at,
                       triager_outcome, bounty_amount, created_at, updated_at
                FROM findings {where}
                ORDER BY created_at DESC LIMIT %s""",
            params,
        )
        rows = _fetchall_dicts(cur)
        _isoformat_fields(rows, ("submitted_at", "created_at", "updated_at"))
        total = len(rows)
        cur.close()
        return rows, total
    finally:
        conn.close()


def get_findings_stats() -> tuple:
    """Aggregate finding statistics. Returns (stats_rows, total)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT target, severity, status, COUNT(*) AS count
               FROM findings
               GROUP BY target, severity, status
               ORDER BY count DESC"""
        )
        rows = _fetchall_dicts(cur)
        cur.execute("SELECT COUNT(*) FROM findings")
        total = cur.fetchone()[0]
        cur.close()
        return rows, total
    finally:
        conn.close()


def create_finding(body: dict) -> int:
    """Insert a new finding. Returns the new ID."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO findings
               (target, title, severity, status, poc_tier, cvss_score,
                description, poc_summary, platform, submitted_at,
                triager_outcome, bounty_amount)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (
                body.get("target"),
                body.get("title"),
                body.get("severity"),
                body.get("status", "new"),
                body.get("poc_tier"),
                body.get("cvss_score"),
                body.get("description"),
                body.get("poc_summary"),
                body.get("platform"),
                body.get("submitted_at"),
                body.get("triager_outcome"),
                body.get("bounty_amount"),
            ),
        )
        new_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        return new_id
    finally:
        conn.close()


def update_finding(finding_id: int, fields: dict) -> int:
    """Update a finding by ID. Returns rowcount (0 = not found)."""
    if not fields:
        return 0

    bad_fields = [k for k in fields.keys() if k not in _ALLOWED_FINDING_FIELDS]
    if bad_fields:
        raise ValueError(f"Unsupported finding fields: {bad_fields}")

    conn = get_connection()
    try:
        cur = conn.cursor()
        set_clause = ", ".join(f"{k} = %s" for k in fields)
        params = list(fields.values()) + [finding_id]
        cur.execute(
            f"UPDATE findings SET {set_clause}, updated_at = NOW() WHERE id = %s",
            params,
        )
        rowcount = cur.rowcount
        conn.commit()
        cur.close()
        return rowcount
    finally:
        conn.close()


# ── RAG Stats ──

def get_rag_stats() -> dict:
    """Get exploit_vectors and failure_memory counts."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM exploit_vectors")
        ev_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM failure_memory")
        fm_count = cur.fetchone()[0]
        cur.close()
        return {"exploit_vectors": ev_count, "failure_memory": fm_count}
    finally:
        conn.close()
