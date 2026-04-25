#!/usr/bin/env python3
"""Attack timeline manager — phase-based visualization of assessment events.

AIDA-inspired: recon → scanning → exploitation → post_exploitation → reporting.
Reads/writes timeline_events table.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

PG_CONFIG = {
    "host": os.getenv("TERMINATOR_DB_HOST", "localhost"),
    "port": int(os.getenv("TERMINATOR_DB_PORT", "5433")),
    "dbname": os.getenv("TERMINATOR_DB_NAME", "terminator"),
    "user": os.getenv("TERMINATOR_DB_USER", "shadowhunter"),
    "password": os.getenv("TERMINATOR_DB_PASS", "terminator"),
}

PHASES = ["recon", "scanning", "exploitation", "post_exploitation", "reporting"]
PHASE_COLORS = {
    "recon": "#3498db",
    "scanning": "#f39c12",
    "exploitation": "#e74c3c",
    "post_exploitation": "#9b59b6",
    "reporting": "#2ecc71",
}


def _get_conn():
    import psycopg2
    return psycopg2.connect(**PG_CONFIG)


def cmd_add(args):
    try:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO timeline_events
               (assessment_id, phase, event_type, severity, title, details, agent_role)
               VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (args.assessment_id, args.phase, args.type, args.severity,
             args.title, args.details, args.agent),
        )
        eid = cur.fetchone()[0]
        conn.commit()
        conn.close()
        print(json.dumps({"id": eid, "phase": args.phase, "title": args.title}))
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)


def cmd_show(args):
    try:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT id, phase, event_type, severity, title, details, agent_role, created_at
               FROM timeline_events WHERE assessment_id = %s ORDER BY created_at""",
            (args.assessment_id,),
        )
        rows = cur.fetchall()
        conn.close()

        events = [
            {"id": r[0], "phase": r[1], "type": r[2], "severity": r[3],
             "title": r[4], "details": r[5], "agent": r[6],
             "time": r[7].isoformat() if r[7] else ""}
            for r in rows
        ]

        if args.json:
            print(json.dumps({"assessment_id": args.assessment_id, "events": events}, indent=2))
        else:
            print(f"\nTimeline for assessment #{args.assessment_id} ({len(events)} events)\n")
            current_phase = ""
            for e in events:
                if e["phase"] != current_phase:
                    current_phase = e["phase"]
                    print(f"\n  [{current_phase.upper()}]")
                sev = f" [{e['severity']}]" if e["severity"] else ""
                agent = f" @{e['agent']}" if e["agent"] else ""
                print(f"    {e['time'][:19]}  {e['type']:<12}{sev}  {e['title']}{agent}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_export(args):
    try:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT phase, event_type, severity, title, agent_role, created_at
               FROM timeline_events WHERE assessment_id = %s ORDER BY created_at""",
            (args.assessment_id,),
        )
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    by_phase: dict[str, list] = {p: [] for p in PHASES}
    for r in rows:
        phase = r[0] if r[0] in by_phase else "recon"
        by_phase[phase].append({
            "type": r[1], "severity": r[2], "title": r[3],
            "agent": r[4], "time": r[5].strftime("%H:%M") if r[5] else "",
        })

    html_parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>Attack Timeline</title>",
        "<style>",
        "body{font-family:system-ui;margin:20px;background:#1a1a2e;color:#eee}",
        ".timeline{display:flex;gap:16px;overflow-x:auto;padding:20px 0}",
        ".phase{min-width:220px;border-radius:8px;padding:12px}",
        ".phase h3{margin:0 0 10px;text-transform:uppercase;font-size:13px;letter-spacing:1px}",
        ".event{background:rgba(255,255,255,0.08);border-radius:4px;padding:8px;margin:6px 0;font-size:12px}",
        ".event .sev{font-weight:bold} .CRITICAL{color:#e74c3c} .HIGH{color:#e67e22} .MEDIUM{color:#f1c40f}",
        ".event .time{color:#888;font-size:10px}",
        "</style></head><body>",
        f"<h2>Assessment #{args.assessment_id} — Attack Timeline</h2>",
        "<div class='timeline'>",
    ]

    for phase in PHASES:
        color = PHASE_COLORS[phase]
        events = by_phase[phase]
        html_parts.append(f"<div class='phase' style='border-top:3px solid {color}'>")
        html_parts.append(f"<h3 style='color:{color}'>{phase.replace('_', ' ')} ({len(events)})</h3>")
        for e in events:
            sev_class = e['severity'] or ''
            html_parts.append(
                f"<div class='event'>"
                f"<span class='sev {sev_class}'>{e['severity'] or ''}</span> {e['title']}"
                f"<br><span class='time'>{e['time']} @{e['agent'] or '?'}</span></div>"
            )
        if not events:
            html_parts.append("<div class='event' style='color:#666'>No events</div>")
        html_parts.append("</div>")

    html_parts.append("</div></body></html>")
    print("\n".join(html_parts))


def main():
    p = argparse.ArgumentParser(description="Attack timeline manager")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("add", help="Add timeline event")
    s.add_argument("--assessment-id", type=int, required=True)
    s.add_argument("--phase", choices=PHASES, required=True)
    s.add_argument("--type", default="manual", choices=["command", "finding", "recon", "credential", "manual", "observation"])
    s.add_argument("--severity", default="")
    s.add_argument("--title", required=True)
    s.add_argument("--details", default="")
    s.add_argument("--agent", default="")

    s = sub.add_parser("show", help="Show timeline")
    s.add_argument("--assessment-id", type=int, required=True)
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("export", help="Export timeline as HTML")
    s.add_argument("--assessment-id", type=int, required=True)

    args = p.parse_args()
    {"add": cmd_add, "show": cmd_show, "export": cmd_export}[args.command](args)


if __name__ == "__main__":
    main()
