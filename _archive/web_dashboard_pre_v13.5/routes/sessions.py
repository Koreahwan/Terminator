"""
Terminator Dashboard - Session Routes
/api/sessions, /api/sessions/{id}, /api/sessions/{id}/log, /api/sessions/{id}/writeup
"""

import logging

from fastapi import APIRouter, HTTPException

from web.config import REPORTS_DIR
from web.services.filesystem import parse_session, scan_sessions

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


@router.get("")
async def list_sessions():
    """List all session reports with summary data."""
    sessions = scan_sessions(limit=30)
    return {"sessions": sessions}


@router.get("/{session_id}")
async def get_session(session_id: str):
    """Get detailed session info."""
    session_dir = REPORTS_DIR / session_id
    if not session_dir.exists():
        raise HTTPException(status_code=404, detail="Session not found")

    data = parse_session(session_dir)

    # Include writeup content if exists
    for candidate in ["writeup.md", "report.md"]:
        wp = session_dir / candidate
        if wp.exists():
            try:
                data["writeup"] = wp.read_text()[:8000]
            except Exception:
                logger.exception("Failed to read writeup %s in session %s", candidate, session_id)
            break

    return data


@router.get("/{session_id}/log")
async def get_session_log(session_id: str, tail: int = 100):
    """Get last N lines of session log."""
    session_dir = REPORTS_DIR / session_id
    if not session_dir.exists():
        raise HTTPException(status_code=404, detail="Session not found")

    log_file = session_dir / "session.log"
    if not log_file.exists():
        # Try other log files
        for candidate in session_dir.glob("*.log"):
            log_file = candidate
            break
        else:
            return {"lines": [], "log_file": None}

    try:
        lines = log_file.read_text(errors="replace").splitlines()
        return {
            "lines": lines[-tail:],
            "log_file": log_file.name,
            "total_lines": len(lines),
        }
    except Exception as e:
        logger.exception("Failed to read log for session %s", session_id)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{session_id}/writeup")
async def get_session_writeup(session_id: str):
    """Get writeup content for a session."""
    session_dir = REPORTS_DIR / session_id
    if not session_dir.exists():
        raise HTTPException(status_code=404, detail="Session not found")

    for candidate in ["writeup.md", "report.md"]:
        wp = session_dir / candidate
        if wp.exists():
            try:
                return {"content": wp.read_text(errors="replace"), "filename": candidate}
            except Exception:
                logger.exception("Failed to read writeup %s in session %s", candidate, session_id)

    return {"content": None, "filename": None}
