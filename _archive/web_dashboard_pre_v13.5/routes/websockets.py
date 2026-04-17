"""
Terminator Dashboard - WebSocket Routes
/ws/live (log tailing), /ws/agents (agent status stream)
"""

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from web.config import REPORTS_DIR
from web.services import database as db
from web.services.filesystem import get_agent_runs_from_filesystem

logger = logging.getLogger(__name__)

active_connections: list[WebSocket] = []


def register(app: FastAPI):
    """Register WebSocket endpoints on the app (cannot use APIRouter for websockets cleanly)."""

    @app.websocket("/ws/live")
    async def websocket_live(websocket: WebSocket):
        """WebSocket for live session monitoring -- tails the latest session log."""
        await websocket.accept()
        active_connections.append(websocket)

        try:
            log_file: Optional[Path] = None
            position = 0

            while True:
                # Refresh: pick the newest session directory
                if REPORTS_DIR.exists():
                    sessions = sorted(REPORTS_DIR.glob("20*"), reverse=True)
                    for sd in sessions:
                        candidate = sd / "session.log"
                        if candidate.exists():
                            if candidate != log_file:
                                log_file = candidate
                                position = 0
                            break

                if log_file and log_file.exists():
                    try:
                        size = log_file.stat().st_size
                        if size > position:
                            with open(log_file, errors="replace") as f:
                                f.seek(position)
                                new_data = f.read(65536)
                            position = log_file.stat().st_size
                            if new_data:
                                await websocket.send_json({
                                    "type": "log",
                                    "session": log_file.parent.name,
                                    "data": new_data,
                                    "ts": datetime.now(timezone.utc).isoformat() + "Z",
                                })
                    except Exception as e:
                        logger.warning("Error tailing log file: %s", e)
                        await websocket.send_json({"type": "error", "message": str(e)})
                else:
                    await websocket.send_json({
                        "type": "idle",
                        "message": "No active session log found.",
                        "ts": datetime.now(timezone.utc).isoformat() + "Z",
                    })

                await asyncio.sleep(1)

        except WebSocketDisconnect:
            logger.debug("WebSocket /ws/live client disconnected")
        finally:
            if websocket in active_connections:
                active_connections.remove(websocket)

    @app.websocket("/ws/agents")
    async def websocket_agents(websocket: WebSocket):
        """Real-time agent status stream -- polls agent_runs table with filesystem fallback."""
        await websocket.accept()
        last_check: dict = {}
        consecutive_db_failures = 0
        max_backoff = 30  # max seconds between polls on repeated failures

        try:
            while True:
                rows = None
                source = "database"

                # Try DB first
                try:
                    rows = db.list_recent_and_running_agents()
                    consecutive_db_failures = 0  # reset on success
                except Exception:
                    consecutive_db_failures += 1
                    if consecutive_db_failures <= 1:
                        logger.warning("DB unavailable for /ws/agents, falling back to filesystem")

                    # Filesystem fallback: scan teams for agent info
                    try:
                        fs_runs = get_agent_runs_from_filesystem(limit=20)
                        rows = fs_runs
                        source = "filesystem"
                    except Exception:
                        logger.exception("Filesystem fallback also failed for /ws/agents")
                        rows = []
                        source = "unavailable"

                if rows is not None:
                    # Detect deltas vs last_check
                    current_ids = {}
                    for r in rows:
                        rid = r.get("id", "")
                        current_ids[rid] = r

                    changed = [r for r in rows if last_check.get(r.get("id", "")) != r]
                    last_check = current_ids

                    if changed:
                        await websocket.send_json({
                            "type": "agent_update",
                            "runs": changed,
                            "source": source,
                            "ts": datetime.now(timezone.utc).isoformat() + "Z",
                        })

                # Exponential backoff on repeated DB failures (don't spam error JSON every 2s)
                if consecutive_db_failures > 1:
                    backoff = min(2 ** consecutive_db_failures, max_backoff)
                    await asyncio.sleep(backoff)
                else:
                    await asyncio.sleep(2)

        except WebSocketDisconnect:
            logger.debug("WebSocket /ws/agents client disconnected")
