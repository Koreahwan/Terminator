"""
Terminator Dashboard - Bounty Mission Routes
/api/bounty/missions, /api/bounty/missions/{name}, /api/bounty/missions/{name}/pipeline
"""

import logging

from fastapi import APIRouter, HTTPException

from web.config import TARGETS_DIR
from web.services.filesystem import parse_mission, scan_missions, get_pipeline_phase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/bounty", tags=["bounty"])


@router.get("/missions")
async def list_missions():
    """List all bounty missions from targets/ directory."""
    missions = scan_missions()
    return {"missions": missions}


@router.get("/missions/{name}")
async def get_mission(name: str):
    """Detailed mission view including findings and reports."""
    # Sanitize name to prevent path traversal
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(status_code=400, detail="Invalid mission name")
    mission_dir = TARGETS_DIR / name
    if not mission_dir.is_dir():
        raise HTTPException(status_code=404, detail="Mission not found")

    data = parse_mission(mission_dir)

    # Assessment
    assess_file = mission_dir / "target_assessment.md"
    if assess_file.exists():
        try:
            data["assessment"] = assess_file.read_text(errors="replace")[:50000]
        except Exception:
            logger.exception("Failed to read assessment for mission %s", name)

    # Vulnerability candidates
    vuln_file = mission_dir / "vulnerability_candidates.md"
    if vuln_file.exists():
        try:
            data["vulnerability_candidates"] = vuln_file.read_text(errors="replace")[:50000]
        except Exception:
            logger.exception("Failed to read vuln candidates for mission %s", name)

    # Exploit results
    exploit_file = mission_dir / "exploit_results.md"
    if exploit_file.exists():
        try:
            data["exploit_results"] = exploit_file.read_text(errors="replace")[:50000]
        except Exception:
            logger.exception("Failed to read exploit results for mission %s", name)

    # Report drafts from immunefi_reports/
    reports_dir = mission_dir / "immunefi_reports"
    report_drafts = []
    if reports_dir.is_dir():
        for md in sorted(reports_dir.glob("*.md")):
            try:
                report_drafts.append({
                    "filename": md.name,
                    "content": md.read_text(errors="replace")[:50000],
                })
            except Exception:
                logger.exception("Failed to read report draft %s for mission %s", md.name, name)
    data["report_drafts"] = report_drafts

    # Review files
    for review_key, review_file in [("critic_review", "critic_review.md"), ("architect_review", "architect_review.md")]:
        rpath = mission_dir / review_file
        if rpath.exists():
            try:
                data[review_key] = rpath.read_text(errors="replace")[:50000]
            except Exception:
                logger.exception("Failed to read %s for mission %s", review_file, name)

    return data


@router.get("/missions/{name}/pipeline")
async def get_mission_pipeline(name: str):
    """Pipeline phase status for a mission."""
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(status_code=400, detail="Invalid mission name")
    mission_dir = TARGETS_DIR / name
    if not mission_dir.is_dir():
        raise HTTPException(status_code=404, detail="Mission not found")

    return get_pipeline_phase(mission_dir)
