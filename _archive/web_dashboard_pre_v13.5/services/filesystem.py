"""
Terminator Dashboard - Filesystem Service
All filesystem scanning, finding aggregation, session/mission parsing, and CVSS extraction.
"""

import json
import logging
import re
import shutil
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from web.config import REPORTS_DIR, TARGETS_DIR, PID_DIR, PIPELINE_PHASES, TEAMS_DIR, TOOL_HEALTH_MAP, TOOL_FULL_MAP

logger = logging.getLogger(__name__)


# ── CVSS / Severity Helpers ──

def cvss_to_severity(score: float) -> str:
    """Convert a CVSS numeric score to a severity label."""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score >= 0.1:
        return "low"
    return "info"


def extract_cvss_from_text(text: str) -> Optional[float]:
    """Extract CVSS score from markdown text."""
    patterns = [
        r'CVSS[\s:]+(?:3\.[01]\s+)?\*{0,2}(\d+\.?\d*)',
        r'CVSS[\s_]?(?:Score|Base)?[\s:]+\*{0,2}(\d+\.?\d*)',
        r'cvss_score["\s:]+(\d+\.?\d*)',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                logger.debug("Failed to parse CVSS float from match: %s", m.group(1))
    return None


def extract_score(text: str) -> Optional[int]:
    """Extract a score like 8/10 or Score: 8 from assessment text."""
    m = re.search(r'\b(\d{1,2})\s*/\s*10\b', text)
    if m:
        return int(m.group(1))
    m = re.search(r'[Ss]core[:\s]+(\d{1,2})', text)
    if m:
        return int(m.group(1))
    return None


def extract_status(text: str) -> str:
    """Extract GO/NO-GO/CONDITIONAL GO from target assessment text."""
    m = re.search(r'\b(CONDITIONAL\s+GO|NO[- ]?GO|GO)\b', text, re.IGNORECASE)
    if m:
        val = m.group(1).upper().replace(' ', '_').replace('-', '_')
        return val
    return "UNKNOWN"


def count_findings(vuln_file: Path) -> int:
    """Count findings in vulnerability_candidates.md (count ## headers)."""
    if not vuln_file.exists():
        return 0
    text = vuln_file.read_text(errors="replace")
    return len(re.findall(r'^##\s+', text, re.MULTILINE))


# ── Finding Aggregation ──

def aggregate_findings() -> dict:
    """Walk all sessions and targets to aggregate vulnerability findings."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings = []

    # Part 1: Scan reports/ directory
    if REPORTS_DIR.exists():
        for session_dir in sorted(REPORTS_DIR.glob("20*"), reverse=True):
            summary_file = session_dir / "summary.json"
            if summary_file.exists():
                try:
                    with open(summary_file) as f:
                        data = json.load(f)
                    for finding in data.get("findings", []):
                        sev = finding.get("severity", "info").lower()
                        if sev in counts:
                            counts[sev] += 1
                        findings.append({
                            "session_id": session_dir.name,
                            "title": finding.get("title", "Unknown"),
                            "severity": sev,
                            "target": data.get("target"),
                            "source": "reports",
                        })
                except Exception:
                    logger.exception("Failed to parse summary.json in %s", session_dir.name)

            flags_file = session_dir / "flags.txt"
            if flags_file.exists():
                try:
                    flag_lines = flags_file.read_text().strip().splitlines()
                    for line in flag_lines:
                        if line.strip():
                            findings.append({
                                "session_id": session_dir.name,
                                "title": f"FLAG: {line.strip()}",
                                "severity": "critical",
                                "target": session_dir.name,
                                "source": "reports",
                            })
                            counts["critical"] += 1
                except Exception:
                    logger.exception("Failed to read flags.txt in %s", session_dir.name)

    # Part 2: Scan targets/ directory
    if TARGETS_DIR.exists():
        for target_dir in sorted(TARGETS_DIR.iterdir()):
            if not target_dir.is_dir():
                continue
            target_name = target_dir.name

            # Report/submission markdown files
            report_patterns = ["report_*.md", "*_submission.md"]
            for pattern in report_patterns:
                for md_file in target_dir.glob(pattern):
                    try:
                        text = md_file.read_text(errors="replace")[:50000]
                        cvss = extract_cvss_from_text(text)
                        sev = cvss_to_severity(cvss) if cvss else "medium"

                        title_match = re.search(r'^#\s+(.+)', text, re.MULTILINE)
                        title = title_match.group(1).strip() if title_match else md_file.stem.replace("_", " ").title()

                        if sev in counts:
                            counts[sev] += 1
                        findings.append({
                            "id": f"{target_name}/{md_file.name}",
                            "title": title[:120],
                            "severity": sev,
                            "target": target_name,
                            "cvss_score": cvss,
                            "file": str(md_file.relative_to(TARGETS_DIR)),
                            "source": "targets",
                        })
                    except Exception:
                        logger.exception("Failed to parse report %s", md_file)

            # immunefi_reports/ subdirectory
            immunefi_dir = target_dir / "immunefi_reports"
            if immunefi_dir.is_dir():
                for md_file in immunefi_dir.glob("*.md"):
                    try:
                        text = md_file.read_text(errors="replace")[:50000]
                        cvss = extract_cvss_from_text(text)
                        sev = cvss_to_severity(cvss) if cvss else "medium"

                        title_match = re.search(r'^#\s+(.+)', text, re.MULTILINE)
                        title = title_match.group(1).strip() if title_match else md_file.stem.replace("_", " ").title()

                        if sev in counts:
                            counts[sev] += 1
                        findings.append({
                            "id": f"{target_name}/immunefi_reports/{md_file.name}",
                            "title": title[:120],
                            "severity": sev,
                            "target": target_name,
                            "cvss_score": cvss,
                            "file": str(md_file.relative_to(TARGETS_DIR)),
                            "source": "targets",
                        })
                    except Exception:
                        logger.exception("Failed to parse immunefi report %s", md_file)

            # vulnerability_candidates.md
            vuln_file = target_dir / "vulnerability_candidates.md"
            if vuln_file.exists():
                try:
                    text = vuln_file.read_text(errors="replace")[:100000]
                    sections = re.split(r'^##\s+', text, flags=re.MULTILINE)
                    for section in sections[1:]:
                        lines = section.strip().split("\n")
                        title = lines[0].strip()[:120] if lines else "Unknown Finding"
                        section_text = "\n".join(lines)
                        cvss = extract_cvss_from_text(section_text)
                        sev = cvss_to_severity(cvss) if cvss else "info"

                        if sev in counts:
                            counts[sev] += 1
                        findings.append({
                            "id": f"{target_name}/vuln_candidates/{title[:40]}",
                            "title": title,
                            "severity": sev,
                            "target": target_name,
                            "cvss_score": cvss,
                            "file": f"{target_name}/vulnerability_candidates.md",
                            "source": "targets",
                        })
                except Exception:
                    logger.exception("Failed to parse vulnerability_candidates.md in %s", target_name)

    return {"counts": counts, "findings": findings[:200]}


def get_findings_stats_from_filesystem(target: Optional[str] = None) -> dict:
    """Compute finding stats from filesystem as fallback."""
    agg = aggregate_findings()
    by_target_sev = Counter()
    for f in agg["findings"]:
        key = (f.get("target", "unknown"), f.get("severity", "info"))
        by_target_sev[key] += 1
    stats = [
        {"target": t, "severity": s, "status": "filesystem", "count": c}
        for (t, s), c in by_target_sev.most_common()
    ]
    return {"stats": stats, "total": len(agg["findings"]), "source": "filesystem"}


# ── Session Scanning ──

def parse_session(session_dir: Path) -> dict:
    """Build a session summary dict from a session directory."""
    summary_file = session_dir / "summary.json"
    if summary_file.exists():
        try:
            with open(summary_file) as f:
                data = json.load(f)
            data["session_id"] = session_dir.name
            return data
        except Exception:
            logger.exception("Failed to parse summary.json in %s", session_dir.name)

    # Fallback: derive info from directory contents
    files = [f.name for f in session_dir.iterdir()] if session_dir.is_dir() else []
    status = "completed" if "flags.txt" in files else "unknown"
    flags = []
    if "flags.txt" in files:
        try:
            flags = (session_dir / "flags.txt").read_text().strip().splitlines()
        except Exception:
            logger.exception("Failed to read flags.txt in %s", session_dir.name)

    return {
        "session_id": session_dir.name,
        "status": status,
        "files": files,
        "flags": flags,
        "findings_count": 0,
        "mode": "unknown",
        "target": None,
        "duration_seconds": None,
        "timestamp": session_dir.name,
    }


def scan_sessions(limit: int = 30) -> list:
    """Scan reports/ directory for sessions."""
    if not REPORTS_DIR.exists():
        logger.debug("Reports directory does not exist: %s", REPORTS_DIR)
        return []
    sessions = []
    for session_dir in sorted(REPORTS_DIR.glob("20*"), reverse=True)[:limit]:
        sessions.append(parse_session(session_dir))
    return sessions


# ── Mission Scanning ──

def get_pipeline_phase(mission_dir: Path) -> dict:
    """Determine current pipeline phase by checking which artifacts exist."""
    phases = []
    for label, patterns in PIPELINE_PHASES:
        complete = False
        matched_artifact = None
        for pattern in patterns:
            if "*" in pattern or "?" in pattern:
                matches = list(mission_dir.glob(pattern))
                if matches:
                    complete = True
                    matched_artifact = matches[0].name
                    break
            else:
                if (mission_dir / pattern).exists():
                    complete = True
                    matched_artifact = pattern
                    break
        artifact_display = matched_artifact or patterns[0]
        phases.append({"label": label, "artifact": artifact_display, "complete": complete})

    completed = [p for p in phases if p["complete"]]
    current_idx = len(completed)
    current = phases[current_idx]["label"] if current_idx < len(phases) else "Complete"

    return {
        "phases": phases,
        "current_phase": current,
        "phases_complete": len(completed),
        "phases_total": len(phases),
    }


def parse_mission(mission_dir: Path) -> dict:
    """Build a mission summary dict from a targets/ subdirectory."""
    name = mission_dir.name

    assess_file = mission_dir / "target_assessment.md"
    score = None
    status = "UNKNOWN"
    if assess_file.exists():
        try:
            text = assess_file.read_text(errors="replace")
            score = extract_score(text)
            status = extract_status(text)
        except Exception:
            logger.exception("Failed to parse target_assessment.md in %s", name)

    vuln_file = mission_dir / "vulnerability_candidates.md"
    findings_count = count_findings(vuln_file)
    pipeline = get_pipeline_phase(mission_dir)

    return {
        "name": name,
        "score": score,
        "status": status,
        "findings_count": findings_count,
        "current_phase": pipeline["current_phase"],
        "phases_complete": pipeline["phases_complete"],
        "phases_total": pipeline["phases_total"],
        "has_assessment": assess_file.exists(),
        "has_exploits": (mission_dir / "exploit_results.md").exists() or (mission_dir / "dynamic_poc_evidence.md").exists(),
        "has_reports": (
            (mission_dir / "immunefi_reports").is_dir()
            or (mission_dir / "h1_reports").is_dir()
            or bool(list(mission_dir.glob("report_*.md")))
            or bool(list(mission_dir.glob("*_submission.md")))
        ),
    }


def scan_missions() -> list:
    """Scan targets/ directory for missions."""
    if not TARGETS_DIR.exists():
        logger.debug("Targets directory does not exist: %s", TARGETS_DIR)
        return []
    missions = []
    for entry in sorted(TARGETS_DIR.iterdir()):
        if not entry.is_dir():
            continue
        has_content = any(entry.glob("*.md")) or any(entry.glob("*.json"))
        if not has_content:
            continue
        try:
            missions.append(parse_mission(entry))
        except Exception:
            logger.exception("Failed to parse mission %s", entry.name)
    return missions


# ── Agent Runs from Filesystem ──

def get_agent_runs_from_filesystem(limit: int = 50) -> list:
    """Fallback: scan runtime pid metadata first, then ~/.claude/teams/."""
    runs = []
    if PID_DIR.exists():
        for meta_file in sorted(PID_DIR.glob("*.json"), reverse=True):
            try:
                with open(meta_file) as f:
                    meta = json.load(f)
                pid = meta.get("pid")
                created = datetime.fromtimestamp(meta_file.stat().st_mtime, tz=timezone.utc).isoformat()
                if pid:
                    runs.append({
                        "id": str(pid),
                        "session_id": meta.get("session_id", meta_file.stem),
                        "agent_role": meta.get("mode", "session"),
                        "target": meta.get("target", ""),
                        "model": meta.get("backend", "unknown"),
                        "backend": meta.get("backend"),
                        "parallel_group_id": meta.get("parallel_group_id"),
                        "status": "RUNNING",
                        "duration_seconds": None,
                        "tokens_used": None,
                        "output_summary": meta.get("report_dir"),
                        "artifacts": None,
                        "created_at": created,
                        "completed_at": None,
                    })
            except Exception:
                logger.exception("Failed to parse pid metadata %s", meta_file.name)
            if len(runs) >= limit:
                return runs[:limit]

    if not TEAMS_DIR.exists():
        logger.debug("Teams directory does not exist: %s", TEAMS_DIR)
        return runs

    for team_dir in sorted(TEAMS_DIR.iterdir(), reverse=True):
        if not team_dir.is_dir():
            continue
        config_file = team_dir / "config.json"
        if config_file.exists():
            try:
                with open(config_file) as f:
                    config = json.load(f)
                team_name = config.get("name", team_dir.name)
                members = config.get("members", [])
                mtime = datetime.fromtimestamp(config_file.stat().st_mtime, tz=timezone.utc)
                for member in members:
                    runs.append({
                        "id": member.get("agentId", ""),
                        "session_id": team_name,
                        "agent_role": member.get("name", member.get("agentType", "unknown")),
                        "target": team_name.replace("mission-", ""),
                        "model": member.get("agentType", "unknown"),
                        "backend": "claude",
                        "parallel_group_id": None,
                        "status": "COMPLETED",
                        "duration_seconds": None,
                        "tokens_used": None,
                        "output_summary": None,
                        "artifacts": None,
                        "created_at": mtime.isoformat(),
                        "completed_at": mtime.isoformat(),
                    })
            except Exception:
                logger.exception("Failed to parse team config in %s", team_dir.name)
        if len(runs) >= limit:
            break
    return runs[:limit]


# ── Graph from Filesystem ──

def build_graph_from_filesystem(target: Optional[str] = None) -> dict:
    """Build a graph data structure from targets/ filesystem data."""
    nodes = []
    links = []
    node_ids = set()

    def add_node(nid, label, ntype, **extra):
        if nid not in node_ids:
            node_ids.add(nid)
            node = {"id": nid, "label": label, "type": ntype}
            node.update(extra)
            nodes.append(node)

    def add_link(source, target_id, rel="related"):
        links.append({"source": source, "target": target_id, "relationship": rel})

    scan_dirs = []
    if target and TARGETS_DIR.exists():
        td = TARGETS_DIR / target
        if td.is_dir():
            scan_dirs = [td]
    elif TARGETS_DIR.exists():
        scan_dirs = [d for d in TARGETS_DIR.iterdir() if d.is_dir()]

    for tdir in scan_dirs:
        tname = tdir.name
        add_node(f"target:{tname}", tname, "target")

        # Findings from vulnerability_candidates.md
        vuln_file = tdir / "vulnerability_candidates.md"
        if vuln_file.exists():
            try:
                text = vuln_file.read_text(errors="replace")[:100000]
                sections = re.split(r'^##\s+', text, flags=re.MULTILINE)
                for i, section in enumerate(sections[1:], 1):
                    lines = section.strip().split("\n")
                    title = lines[0].strip()[:80] if lines else f"Finding {i}"
                    section_text = "\n".join(lines)
                    cvss = extract_cvss_from_text(section_text)
                    sev = cvss_to_severity(cvss) if cvss else "info"
                    fid = f"finding:{tname}:{i}"
                    add_node(fid, title, "finding", severity=sev, cvss=cvss)
                    add_link(f"target:{tname}", fid, "has_finding")
            except Exception:
                logger.exception("Failed to parse vuln candidates for graph in %s", tname)

        # Reports as technique nodes
        report_patterns = ["report_*.md", "*_submission.md"]
        for pattern in report_patterns:
            for md_file in tdir.glob(pattern):
                try:
                    text = md_file.read_text(errors="replace")[:20000]
                    title_match = re.search(r'^#\s+(.+)', text, re.MULTILINE)
                    title = title_match.group(1).strip()[:60] if title_match else md_file.stem
                    cvss = extract_cvss_from_text(text)
                    sev = cvss_to_severity(cvss) if cvss else "medium"
                    rid = f"report:{tname}:{md_file.stem}"
                    add_node(rid, title, "technique", severity=sev, cvss=cvss)
                    finding_nodes = [n["id"] for n in nodes if n["type"] == "finding" and tname in n["id"]]
                    if finding_nodes:
                        add_link(finding_nodes[0], rid, "exploited_by")
                    else:
                        add_link(f"target:{tname}", rid, "has_technique")
                except Exception:
                    logger.exception("Failed to parse report for graph %s", md_file)

        # Recon data for services
        recon_file = tdir / "recon_notes.md"
        if not recon_file.exists():
            recon_file = tdir / "recon_report.json"
        if recon_file.exists():
            try:
                text = recon_file.read_text(errors="replace")[:30000]
                ports = re.findall(r'(?:port|service)[:\s]+(\d+)(?:/(\w+))?', text, re.IGNORECASE)
                for port, proto in ports[:10]:
                    sid = f"service:{tname}:{port}"
                    add_node(sid, f"{proto or 'tcp'}:{port}", "service")
                    add_link(f"target:{tname}", sid, "has_service")
            except Exception:
                logger.exception("Failed to parse recon data for graph in %s", tname)

    return {"nodes": nodes, "links": links}


# ── Tool Health ──

def get_health() -> dict:
    """Check availability of local security tools."""
    result = {}
    for name, binary in TOOL_HEALTH_MAP.items():
        result[name] = "up" if shutil.which(binary) else "down"
    result["Dashboard"] = "up"
    result["WebSocket"] = "up"
    return result


def get_tools() -> dict:
    """Check which security tools are available (detailed)."""
    tools = {}
    for name, binary in TOOL_FULL_MAP.items():
        path = shutil.which(binary)
        tools[name] = {"available": path is not None, "path": path}
    return {
        "tools": tools,
        "total_available": sum(1 for t in tools.values() if t["available"]),
        "total": len(tools),
    }
