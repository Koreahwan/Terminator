"""
Terminator Dashboard - Findings Routes
/api/findings, /api/db/findings (GET/POST), /api/db/findings/{id} (PATCH), /api/db/findings/stats
"""

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from web.services import database as db
from web.services.filesystem import aggregate_findings, get_findings_stats_from_filesystem

logger = logging.getLogger(__name__)

router = APIRouter(tags=["findings"])


@router.get("/api/findings")
async def list_findings_filesystem():
    """Aggregate findings across all sessions (filesystem-only)."""
    return aggregate_findings()


@router.get("/api/db/findings")
async def list_db_findings(target: str = None, status: str = None, limit: int = 50):
    """List findings from DB, with filesystem fallback."""
    try:
        rows, total = db.list_findings(target=target, status=status, limit=limit)
        return {"findings": rows, "total": total}
    except Exception:
        logger.warning("DB unavailable for findings list, falling back to filesystem")
        agg = aggregate_findings()
        fs_findings = agg["findings"]
        if target:
            fs_findings = [f for f in fs_findings if f.get("target") == target]
        return {"findings": fs_findings[:limit], "total": len(fs_findings), "source": "filesystem"}


@router.get("/api/db/findings/stats")
async def findings_stats():
    """Aggregate finding statistics by target and severity."""
    try:
        rows, total = db.get_findings_stats()
        return {"stats": rows, "total": total}
    except Exception:
        logger.warning("DB unavailable for findings stats, falling back to filesystem")
        return get_findings_stats_from_filesystem()


@router.post("/api/db/findings")
async def create_finding(request: Request):
    """Create a new finding (called by infra_client)."""
    try:
        body = await request.json()
        new_id = db.create_finding(body)
        return {"id": new_id, "status": "created"}
    except Exception:
        logger.warning("DB unavailable for finding creation")
        return JSONResponse(status_code=503, content={
            "error": "Database not available. Start Docker services for write operations."
        })


@router.patch("/api/db/findings/{finding_id}")
async def update_finding(finding_id: int, request: Request):
    """Update finding status/outcome."""
    try:
        body = await request.json()
        if not body:
            return JSONResponse(status_code=400, content={"error": "Empty request body"})
        allowed = {"status", "triager_outcome", "bounty_amount", "poc_tier",
                   "cvss_score", "description", "poc_summary", "submitted_at"}
        fields = {k: v for k, v in body.items() if k in allowed}
        if not fields:
            return JSONResponse(status_code=400, content={"error": "No updatable fields provided"})
        rowcount = db.update_finding(finding_id, fields)
        if rowcount == 0:
            return JSONResponse(status_code=404, content={"error": "Finding not found"})
        return {"status": "updated"}
    except Exception:
        logger.warning("DB unavailable for finding update")
        return JSONResponse(status_code=503, content={
            "error": "Database not available. Start Docker services for write operations."
        })
