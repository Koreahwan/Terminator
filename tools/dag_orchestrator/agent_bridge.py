#!/usr/bin/env python3
"""
DAG↔Agent Teams Bridge
Maps DAG node execution to agent_runs tracking in PostgreSQL.
Used by the Orchestrator to log agent lifecycle events.
"""
import os
import sys
import json
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

PG_CONFIG = {
    "host": os.getenv("PG_HOST", "localhost"),
    "port": int(os.getenv("PG_PORT", "5433")),
    "dbname": "shadowhunter",
    "user": "postgres",
    "password": "shadowhunter",
}

DB_LOGGING_MODE = os.getenv("TERMINATOR_AGENT_DB_LOGGING", "auto").strip().lower()
_DB_UNAVAILABLE_REASON: str | None = None
_DB_WARNED = False


def _db_logging_disabled() -> bool:
    return DB_LOGGING_MODE in {"0", "false", "off", "none", "disabled"}


def _warn_db_once(message: str) -> None:
    global _DB_WARNED
    if _DB_WARNED:
        return
    if os.getenv("TERMINATOR_AGENT_DB_WARN", "").strip().lower() not in {"1", "true", "yes"}:
        return
    print(f"[agent_bridge] Warning: {message}", file=sys.stderr)
    _DB_WARNED = True


# Expected artifacts per agent role
ROLE_ARTIFACTS = {
    "reverser": ["reversal_map.md"],
    "trigger": ["trigger_report.md", "trigger_poc.py"],
    "chain": ["chain_report.md", "solve.py"],
    "solver": ["solve.py"],
    "critic": ["critic_review.md"],
    "verifier": ["verification_report.md"],
    "reporter": [],  # writes to knowledge/challenges/
    "scout": ["recon_report.json", "recon_notes.md"],
    "analyst": ["vulnerability_candidates.md"],
    "exploiter": ["exploit_results.md"],
    "target_evaluator": ["target_assessment.md"],
    "triager_sim": ["triager_verdict.md"],
    "scope-auditor": ["scope_audit.json", "scope_audit.md"],
    "scope_auditor": ["scope_audit.json", "scope_audit.md"],
}


def _get_conn():
    global _DB_UNAVAILABLE_REASON
    if _db_logging_disabled():
        _DB_UNAVAILABLE_REASON = "agent DB logging disabled"
        return None
    try:
        import psycopg2
    except ImportError:
        _DB_UNAVAILABLE_REASON = "psycopg2 not installed; agent DB logging disabled"
        _warn_db_once(_DB_UNAVAILABLE_REASON)
        return None
    conn = psycopg2.connect(**PG_CONFIG)
    conn.autocommit = True
    return conn


def log_run_start(
    session_id: str,
    agent_role: str,
    target: str,
    model: str = None,
    *,
    backend: str | None = None,
    parallel_group_id: str | None = None,
) -> int:
    """Record agent execution start. Returns run_id."""
    try:
        conn = _get_conn()
        if conn is None:
            return -1
        cur = conn.cursor()
        if backend is not None or parallel_group_id is not None:
            try:
                cur.execute(
                    "INSERT INTO agent_runs (session_id, agent_role, target, model, backend, parallel_group_id, status, created_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, 'RUNNING', NOW()) RETURNING id",
                    (session_id, agent_role, target, model, backend, parallel_group_id),
                )
            except Exception:
                conn.rollback()
                cur.execute(
                    "INSERT INTO agent_runs (session_id, agent_role, target, model, status, created_at) "
                    "VALUES (%s, %s, %s, %s, 'RUNNING', NOW()) RETURNING id",
                    (session_id, agent_role, target, model)
                )
        else:
            cur.execute(
                "INSERT INTO agent_runs (session_id, agent_role, target, model, status, created_at) "
                "VALUES (%s, %s, %s, %s, 'RUNNING', NOW()) RETURNING id",
                (session_id, agent_role, target, model)
            )
        run_id = cur.fetchone()[0]
        cur.close()
        conn.close()
        return run_id
    except Exception as e:
        _warn_db_once(f"failed to log run start: {e}")
        return -1


def log_run_complete(run_id: int, status: str = "COMPLETED",
                     duration_seconds: int = None, output_summary: str = None,
                     artifacts: list = None, tokens_used: int = None):
    """Record agent execution completion."""
    if run_id < 0:
        return
    try:
        conn = _get_conn()
        if conn is None:
            return
        cur = conn.cursor()
        cur.execute(
            "UPDATE agent_runs SET status=%s, duration_seconds=%s, output_summary=%s, "
            "artifacts=%s, tokens_used=%s, completed_at=NOW() WHERE id=%s",
            (status, duration_seconds, output_summary, artifacts, tokens_used, run_id)
        )
        cur.close()
        conn.close()
    except Exception as e:
        _warn_db_once(f"failed to log run complete: {e}")


def check_artifacts(work_dir: str, role: str) -> dict:
    """Check which expected artifacts exist for a given role."""
    expected = ROLE_ARTIFACTS.get(role, [])
    found = []
    missing = []
    for artifact in expected:
        path = os.path.join(work_dir, artifact)
        if os.path.exists(path):
            found.append(artifact)
        else:
            missing.append(artifact)
    return {
        "role": role,
        "expected": expected,
        "found": found,
        "missing": missing,
        "complete": len(missing) == 0 and len(expected) > 0,
    }


def get_active_runs(session_id: str = None) -> list:
    """Get all currently running agents."""
    try:
        conn = _get_conn()
        if conn is None:
            return []
        cur = conn.cursor()
        if session_id:
            cur.execute(
                "SELECT id, session_id, agent_role, target, model, status, created_at "
                "FROM agent_runs WHERE status='RUNNING' AND session_id=%s ORDER BY created_at",
                (session_id,)
            )
        else:
            cur.execute(
                "SELECT id, session_id, agent_role, target, model, status, created_at "
                "FROM agent_runs WHERE status='RUNNING' ORDER BY created_at"
            )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        cur.close()
        conn.close()
        return rows
    except Exception as e:
        _warn_db_once(f"failed to get active runs: {e}")
        return []


def get_session_summary(session_id: str) -> dict:
    """Get execution summary for a session."""
    try:
        conn = _get_conn()
        if conn is None:
            return {"session_id": session_id, "runs": [], "db_logging": "unavailable", "reason": _DB_UNAVAILABLE_REASON}
        cur = conn.cursor()
        cur.execute(
            "SELECT agent_role, status, duration_seconds, model "
            "FROM agent_runs WHERE session_id=%s ORDER BY created_at",
            (session_id,)
        )
        cols = [d[0] for d in cur.description]
        runs = [dict(zip(cols, row)) for row in cur.fetchall()]
        cur.close()
        conn.close()

        total_duration = sum(r.get("duration_seconds") or 0 for r in runs)
        completed = sum(1 for r in runs if r["status"] == "COMPLETED")
        failed = sum(1 for r in runs if r["status"] == "FAILED")

        return {
            "session_id": session_id,
            "total_runs": len(runs),
            "completed": completed,
            "failed": failed,
            "total_duration_seconds": total_duration,
            "runs": runs,
        }
    except Exception as e:
        _warn_db_once(f"failed to get session summary: {e}")
        return {"session_id": session_id, "error": str(e)}


def create_agent_handler(role: str, target: str, session_id: str):
    """Create a DAG node handler that logs agent execution to PostgreSQL.

    This is used by the DAG orchestrator to wrap agent execution with tracking.
    The actual agent execution is done by Claude Code's Task tool — this handler
    only manages the tracking lifecycle.
    """
    def handler(context: dict) -> dict:
        run_id = log_run_start(
            session_id,
            role,
            target,
            context.get("model"),
            backend=os.getenv("TERMINATOR_ACTIVE_BACKEND"),
            parallel_group_id=os.getenv("TERMINATOR_PARALLEL_GROUP_ID"),
        )
        context["current_agent"] = role
        context["run_id"] = run_id
        context["expected_artifacts"] = ROLE_ARTIFACTS.get(role, [])
        return {"status": "delegated", "run_id": run_id, "role": role}
    return handler


# CLI interface for bash-based agent hooks
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Agent Bridge CLI")
    parser.add_argument("action", choices=["start", "complete", "check", "active", "summary"])
    parser.add_argument("--session", "-s")
    parser.add_argument("--role", "-r")
    parser.add_argument("--target", "-t")
    parser.add_argument("--model", "-m")
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--status", default="COMPLETED")
    parser.add_argument("--duration", type=int)
    parser.add_argument("--summary-text")
    parser.add_argument("--artifacts", nargs="*")
    parser.add_argument("--work-dir", default=".")

    args = parser.parse_args()

    if args.action == "start":
        rid = log_run_start(
            args.session,
            args.role,
            args.target,
            args.model,
            backend=os.getenv("TERMINATOR_ACTIVE_BACKEND"),
            parallel_group_id=os.getenv("TERMINATOR_PARALLEL_GROUP_ID"),
        )
        print(json.dumps({"run_id": rid}))
    elif args.action == "complete":
        log_run_complete(args.run_id, args.status, args.duration,
                        args.summary_text, args.artifacts)
        print(json.dumps({"status": "ok"}))
    elif args.action == "check":
        result = check_artifacts(args.work_dir, args.role)
        print(json.dumps(result, indent=2))
    elif args.action == "active":
        runs = get_active_runs(args.session)
        print(json.dumps(runs, indent=2, default=str))
    elif args.action == "summary":
        s = get_session_summary(args.session)
        print(json.dumps(s, indent=2, default=str))
