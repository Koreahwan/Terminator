"""
Terminator Dashboard - Neo4j Client Service
Neo4j graph queries wrapper.
"""

import logging
import sys
from pathlib import Path

from web.config import BASE_DIR

logger = logging.getLogger(__name__)


def get_graph():
    """Import and return an AttackGraph instance.

    Uses sys.path manipulation to import from tools/attack_graph/.
    Raises ImportError or connection errors if Neo4j is unavailable.
    """
    tools_path = str(BASE_DIR)
    if tools_path not in sys.path:
        sys.path.insert(0, tools_path)
    from tools.attack_graph.graph import AttackGraph
    logger.debug("AttackGraph imported successfully")
    return AttackGraph()


def get_attack_surface_summary(target: str) -> dict:
    """Get attack surface summary from Neo4j."""
    graph = get_graph()
    return graph.get_attack_surface_summary(target)


def get_critical_vulns(target: str = None):
    """Get critical vulnerabilities from Neo4j."""
    graph = get_graph()
    return graph.get_critical_vulns(target)


def get_attack_paths(target: str):
    """Get attack paths from Neo4j."""
    graph = get_graph()
    return graph.get_attack_paths(target)


def export_graph(target: str):
    """Export full attack graph as d3-compatible JSON."""
    graph = get_graph()
    return graph.export_to_json(target)
