"""
Terminator Dashboard - Configuration
All settings, constants, env vars, and path definitions.
"""

import os
from pathlib import Path

# ── Directory Paths ──
BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
TARGETS_DIR = BASE_DIR / "targets"
KNOWLEDGE_DIR = BASE_DIR / "knowledge"
STATIC_DIR = Path(__file__).resolve().parent / "static"
TEAMS_DIR = Path.home() / ".claude" / "teams"
PID_DIR = BASE_DIR / ".pids"

# ── Service Discovery (Docker vs Local) ──
SERVICE_DISCOVERY = os.environ.get("SERVICE_DISCOVERY", "docker")

# ── PostgreSQL ──
DB_CONFIG = {
    "host": "db" if SERVICE_DISCOVERY == "docker" else "localhost",
    "port": 5432 if SERVICE_DISCOVERY == "docker" else 5433,
    "dbname": "shadowhunter",
    "user": "postgres",
    "password": "shadowhunter",
}

# ── Neo4j ──
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687" if SERVICE_DISCOVERY == "docker" else "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASSWORD", "shadowhunter")

# ── RAG API ──
RAG_API_BASE = os.environ.get(
    "RAG_API_URL",
    "http://rag-api:8100" if SERVICE_DISCOVERY == "docker" else "http://localhost:8100",
)

# ── Pipeline Phase Definitions ──
PIPELINE_PHASES = [
    ("Phase 0: Target Assessment", ["target_assessment.md"]),
    ("Phase 1: Reconnaissance",    ["recon_notes.md", "recon_report.json", "recon_report.md"]),
    ("Phase 1: Vuln Candidates",   ["vulnerability_candidates.md"]),
    ("Phase 2: Exploit Results",   ["exploit_results.md", "dynamic_poc_evidence.md"]),
    ("Phase 3: Reports",           ["immunefi_reports", "report_A_*.md", "report_B_*.md", "*_submission.md", "h1_reports"]),
    ("Phase 4: Critic Review",     ["critic_review.md", "critic_review_v2.md"]),
    ("Phase 4: Architect Review",  ["architect_review.md"]),
    ("Phase 5: Final Report",      ["final_report.md", "*_bugcrowd_submission.md"]),
]

# ── Tool Registry (for health checks) ──
TOOL_HEALTH_MAP = {
    "Radare2": "r2",
    "GDB": "gdb",
    "Nuclei": "nuclei",
    "SearchSploit": "searchsploit",
    "Semgrep": "semgrep",
    "CodeQL": "codeql",
    "Slither": "slither",
    "Foundry": "forge",
    "Nmap": "nmap",
    "SQLMap": "sqlmap",
    "FFUF": "ffuf",
    "GitHub CLI": "gh",
}

TOOL_FULL_MAP = {
    "radare2": "r2",
    "gdb": "gdb",
    "nuclei": "nuclei",
    "searchsploit": "searchsploit",
    "semgrep": "semgrep",
    "codeql": "codeql",
    "slither": "slither",
    "foundry": "forge",
    "nmap": "nmap",
    "sqlmap": "sqlmap",
    "ffuf": "ffuf",
    "gh": "gh",
    "mythril": "myth",
    "trufflehog": "trufflehog",
    "dalfox": "dalfox",
    "httpx": "httpx",
}
