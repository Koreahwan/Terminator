"""
Terminator Dashboard - Infrastructure Routes
/api/stats, /api/tools, /api/health, /api/db/agent-runs, /api/rag/search, /api/rag/stats
"""

import logging
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from web.config import REPORTS_DIR, TARGETS_DIR, RAG_API_BASE
from web.services import database as db
from web.services.filesystem import (
    aggregate_findings,
    extract_status,
    get_agent_runs_from_filesystem,
    get_health,
    get_tools,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["infrastructure"])


@router.get("/api/stats")
async def get_stats():
    """Dashboard statistics."""
    all_sessions = list(REPORTS_DIR.glob("20*")) if REPORTS_DIR.exists() else []
    total_sessions = len(all_sessions)

    flags = 0
    for sd in all_sessions:
        ff = sd / "flags.txt"
        if ff.exists():
            try:
                flags += len([line for line in ff.read_text().splitlines() if line.strip()])
            except Exception:
                logger.warning("Failed to read flags.txt in %s", sd.name)

    agg = aggregate_findings()

    # Count missions from targets/
    total_missions = 0
    active_missions = 0
    if TARGETS_DIR.exists():
        for entry in TARGETS_DIR.iterdir():
            if entry.is_dir():
                total_missions += 1
                assess = entry / "target_assessment.md"
                if assess.exists():
                    try:
                        text = assess.read_text(errors="replace")
                        status = extract_status(text)
                        if status in ("GO", "CONDITIONAL_GO"):
                            active_missions += 1
                    except Exception:
                        logger.warning("Failed to parse assessment in %s", entry.name)

    health = get_health()
    tools_available = sum(1 for v in health.values() if v == "up")

    return {
        "total_sessions": total_sessions,
        "flags_captured": flags,
        "findings": agg["counts"],
        "total_findings": len(agg["findings"]),
        "total_missions": total_missions,
        "active_missions": active_missions,
        "tools_available": tools_available,
        "health": health,
        "reports_dir": str(REPORTS_DIR),
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
    }


@router.get("/api/tools")
async def list_tools():
    """Check which security tools are available."""
    return get_tools()


@router.get("/api/agent-runs")
async def list_agent_runs(session: str = None, target: str = None, limit: int = 50):
    """List agent execution history from agent_runs table, with filesystem fallback."""
    try:
        rows = db.list_agent_runs(session=session, target=target, limit=limit)
        return {"runs": rows}
    except Exception:
        logger.warning("DB unavailable for agent runs, falling back to filesystem")
        runs = get_agent_runs_from_filesystem(limit)
        return {"runs": runs, "source": "filesystem"}


@router.get("/api/agent-runs/active")
async def active_agent_runs():
    """List currently running agents (status=RUNNING)."""
    try:
        rows = db.list_active_agent_runs()
        return {"active": rows}
    except Exception:
        logger.warning("DB unavailable for active agent runs, falling back to filesystem")
        return {"active": get_agent_runs_from_filesystem(limit=50), "source": "filesystem"}


@router.post("/api/rag/search")
async def rag_search(request: Request):
    """Proxy search to RAG API."""
    try:
        body = await request.json()
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{RAG_API_BASE}/query", json=body)
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("RAG API unavailable: %s", e)
        return JSONResponse(status_code=503, content={"error": str(e)})


@router.get("/api/rag/stats")
async def rag_stats():
    """Get RAG knowledge base statistics."""
    try:
        stats = db.get_rag_stats()
        return stats
    except Exception as e:
        logger.warning("DB unavailable for RAG stats: %s", e)
        return JSONResponse(status_code=503, content={"error": str(e), "exploit_vectors": 0, "failure_memory": 0})
