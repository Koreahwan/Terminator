#!/usr/bin/env python3
"""Command approval CLI — manage pending commands in filtered/closed mode.

AIDA-inspired: human-in-the-loop command approval workflow.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta

PG_CONFIG = {
    "host": os.getenv("TERMINATOR_DB_HOST", "localhost"),
    "port": int(os.getenv("TERMINATOR_DB_PORT", "5433")),
    "dbname": os.getenv("TERMINATOR_DB_NAME", "terminator"),
    "user": os.getenv("TERMINATOR_DB_USER", "shadowhunter"),
    "password": os.getenv("TERMINATOR_DB_PASS", "terminator"),
}


def _get_conn():
    import psycopg2
    return psycopg2.connect(**PG_CONFIG)


def cmd_list(args):
    conn = _get_conn()
    cur = conn.cursor()
    q = """SELECT id, agent_role, command, command_type, approval_status, phase, created_at
           FROM command_log WHERE 1=1"""
    params = []
    if args.pending_only:
        q += " AND approval_status = 'pending'"
    if args.assessment_id:
        q += " AND assessment_id = %s"
        params.append(args.assessment_id)
    q += " ORDER BY created_at DESC LIMIT %s"
    params.append(args.limit)
    cur.execute(q, params)
    rows = cur.fetchall()
    conn.close()

    if args.json:
        print(json.dumps([
            {"id": r[0], "agent": r[1], "command": r[2][:100], "type": r[3],
             "status": r[4], "phase": r[5],
             "time": r[6].isoformat() if r[6] else ""}
            for r in rows
        ], indent=2))
    else:
        print(f"\n{'ID':<6} {'Agent':<15} {'Status':<15} {'Type':<10} Command")
        print("-" * 80)
        for r in rows:
            status = r[4] or "unknown"
            sym = {"pending": "?", "approved": "+", "rejected": "x", "auto_approved": "~"}.get(status, " ")
            print(f"  [{sym}] {r[0]:<4} {(r[1] or ''):<15} {status:<15} {(r[3] or ''):<10} {(r[2] or '')[:40]}")
        print(f"\n  Total: {len(rows)}")


def cmd_approve(args):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE command_log SET approval_status = 'approved' WHERE id = %s AND approval_status = 'pending' RETURNING id",
        (args.id,),
    )
    row = cur.fetchone()
    conn.commit()
    conn.close()
    if row:
        print(f"Approved command #{args.id}")
    else:
        print(f"Command #{args.id} not found or not pending", file=sys.stderr)


def cmd_reject(args):
    conn = _get_conn()
    cur = conn.cursor()
    stderr_msg = f"REJECTED: {args.reason}" if args.reason else "REJECTED"
    cur.execute(
        "UPDATE command_log SET approval_status = 'rejected', stderr = %s WHERE id = %s AND approval_status = 'pending' RETURNING id",
        (stderr_msg, args.id),
    )
    row = cur.fetchone()
    conn.commit()
    conn.close()
    if row:
        print(f"Rejected command #{args.id}: {args.reason}")
    else:
        print(f"Command #{args.id} not found or not pending", file=sys.stderr)


def cmd_timeout(args):
    conn = _get_conn()
    cur = conn.cursor()
    cutoff = datetime.utcnow() - timedelta(seconds=args.seconds)
    cur.execute(
        "UPDATE command_log SET approval_status = 'timeout' WHERE approval_status = 'pending' AND created_at < %s RETURNING id",
        (cutoff,),
    )
    timed_out = cur.fetchall()
    conn.commit()
    conn.close()
    print(f"Timed out {len(timed_out)} commands older than {args.seconds}s")


def main():
    p = argparse.ArgumentParser(description="Command approval manager")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("list", help="List commands")
    s.add_argument("--pending-only", action="store_true")
    s.add_argument("--assessment-id", type=int, default=0)
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("approve", help="Approve pending command")
    s.add_argument("--id", type=int, required=True)

    s = sub.add_parser("reject", help="Reject pending command")
    s.add_argument("--id", type=int, required=True)
    s.add_argument("--reason", default="")

    s = sub.add_parser("timeout", help="Auto-cancel old pending commands")
    s.add_argument("--seconds", type=int, default=30)

    args = p.parse_args()
    {"list": cmd_list, "approve": cmd_approve, "reject": cmd_reject, "timeout": cmd_timeout}[args.command](args)


if __name__ == "__main__":
    main()
