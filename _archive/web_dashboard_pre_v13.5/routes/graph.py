"""
Terminator Dashboard - Graph Routes
/api/graph/summary, /api/graph/critical-vulns, /api/graph/attack-paths, /api/graph/export
"""

import logging

from fastapi import APIRouter

from web.services import neo4j_client
from web.services.filesystem import build_graph_from_filesystem

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/graph", tags=["graph"])


@router.get("/summary")
async def graph_summary(target: str):
    """Get attack surface summary, with filesystem fallback."""
    try:
        return neo4j_client.get_attack_surface_summary(target)
    except Exception:
        logger.warning("Neo4j unavailable for graph summary, falling back to filesystem")
        graph_data = build_graph_from_filesystem(target)
        finding_nodes = [n for n in graph_data["nodes"] if n["type"] == "finding"]
        technique_nodes = [n for n in graph_data["nodes"] if n["type"] == "technique"]
        service_nodes = [n for n in graph_data["nodes"] if n["type"] == "service"]
        return {
            "hosts": 1,
            "services": len(service_nodes),
            "endpoints": 0,
            "vulnerabilities": len(finding_nodes),
            "findings": len(finding_nodes) + len(technique_nodes),
            "source": "filesystem",
        }


@router.get("/critical-vulns")
async def graph_critical_vulns(target: str = None):
    """Get critical vulnerabilities, with filesystem fallback."""
    try:
        return neo4j_client.get_critical_vulns(target)
    except Exception:
        logger.warning("Neo4j unavailable for critical vulns, falling back to filesystem")
        graph_data = build_graph_from_filesystem(target)
        critical = []
        for n in graph_data["nodes"]:
            if n["type"] in ("finding", "technique"):
                cvss = n.get("cvss")
                if cvss and cvss >= 7.0:
                    critical.append({
                        "cve_id": n["label"],
                        "description": n["label"],
                        "severity": n.get("severity", "high").upper(),
                        "cvss": cvss,
                    })
        return critical


@router.get("/attack-paths")
async def graph_attack_paths(target: str):
    """Get attack paths, with filesystem fallback."""
    try:
        return neo4j_client.get_attack_paths(target)
    except Exception:
        logger.warning("Neo4j unavailable for attack paths, falling back to filesystem")
        graph_data = build_graph_from_filesystem(target)
        paths = []
        for link in graph_data["links"]:
            paths.append({
                "from": link["source"],
                "to": link["target"],
                "relationship": link["relationship"],
            })
        return {"paths": paths, "source": "filesystem"}


@router.get("/export")
async def graph_export(target: str):
    """Export full attack graph as d3-compatible JSON, with filesystem fallback."""
    try:
        return neo4j_client.export_graph(target)
    except Exception:
        logger.warning("Neo4j unavailable for graph export, falling back to filesystem")
        graph_data = build_graph_from_filesystem(target)
        return {
            "target": target,
            "nodes": graph_data["nodes"],
            "links": graph_data["links"],
            "source": "filesystem",
        }
