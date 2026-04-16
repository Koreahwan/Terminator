#!/usr/bin/env python3
"""BB Pipeline Gate — Validates prerequisites before phase transitions.

Enforces two structural rules that LLM instructions alone cannot guarantee:
1. Program rules (auth headers, mandatory headers, known issues) must be
   documented BEFORE any agent starts work.
2. Endpoint coverage must reach threshold BEFORE advancing to Phase 2+.

Usage:
    bb_preflight.py init <target_dir>                  Create template files
    bb_preflight.py fetch-program <target_dir> <program_url> [--no-cache] [--hold-ok] [--json]
                                                       Fetch program page verbatim + auto-fill rules (Phase 0.1)
    bb_preflight.py rules-check <target_dir>           Validate program_rules_summary.md
    bb_preflight.py coverage-check <target_dir> [THR] [--json]  Check endpoint coverage %
    bb_preflight.py inject-rules <target_dir>          Output compact rules for HANDOFF
    bb_preflight.py exclusion-filter <target_dir>      Output exclusion list for analyst
    bb_preflight.py kill-gate-1 <target_dir> --finding "<desc>" --severity <sev> [--impact "<claimed>"]  Pre-validate finding viability
                                                       (v12.5: info-disc + verbose-OOS collision → HARD_KILL unless --impact cites sensitivity anchor)
    bb_preflight.py kill-gate-2 <submission_dir>       Pre-validate PoC/evidence quality (includes evidence-tier enforcement)
    bb_preflight.py workflow-check <target_dir>        Validate workflow_map.md completeness (v12)
    bb_preflight.py fresh-surface-check <target_dir> [--repo <path>]  Check for fresh attack surface (v12)
    bb_preflight.py evidence-tier-check <submission_dir> [--json]     Classify evidence E1-E4 tier (v12)
    bb_preflight.py duplicate-graph-check <target_dir> --finding "<desc>" [--json]  Enhanced duplicate detection (v12)

Global option: --domain <bounty|ai|robotics|supplychain>  (default: bounty)
  Selects domain-specific rules file, endpoint map, coverage threshold, and required sections.

Exit: 0=PASS, 1=FAIL (with specific error message); kill-gate-1: 0=PASS, 1=WARN, 2=HARD_KILL; kill-gate-2: 0=PASS, 1=FAIL

Created: 2026-02-25 (NAMUHX retrospective — structural fix for rule compliance & coverage gap)
Updated: 2026-03-14 (v12 — workflow-check, fresh-surface-check, evidence-tier-check, duplicate-graph-check)
Updated: 2026-04-07 (v12.3 — Immunefi postmortem: severity mandatory, impact-scope match, evidence-tier enforcement in gate-2)
Updated: 2026-04-14 (v12.5 — Port of Antwerp postmortem: info-disclosure / verbose-OOS collision check in kill-gate-1)
"""

import sys
import os
import re
import json
import shutil
import time
from pathlib import Path
from datetime import datetime

RULES_FILE = "program_rules_summary.md"
ENDPOINT_MAP = "endpoint_map.md"
COVERAGE_THRESHOLD = 80

REQUIRED_RULES_SECTIONS = [
    "Auth Header Format",
    "Mandatory Headers",
    "Known Issues",
    "Exclusion List",
    "Submission Rules",
    "Severity Scope",
    "Asset Scope Constraints",
]

TEMPLATE_DIR = Path(__file__).parent / "templates"

# --- Domain-specific overrides ---

DOMAIN_CONFIG = {
    "bounty": {
        "rules_file": RULES_FILE,
        "endpoint_map": ENDPOINT_MAP,
        "coverage_threshold": 80,
        "required_sections": REQUIRED_RULES_SECTIONS,
    },
    "ai": {
        "rules_file": "ai_program_rules_summary.md",
        "endpoint_map": "ai_endpoint_map.md",
        "coverage_threshold": 80,
        "required_sections": [
            "Model Type",
            "API Endpoint",
            "Known Issues",
            "Exclusion List",
            "Acceptable Use Policy",
            "Severity Scope",
            "Prompt Injection Scope",  # explicit: is prompt injection in-scope?
        ],
    },
    "robotics": {
        "rules_file": "robo_program_rules_summary.md",
        "endpoint_map": "robo_endpoint_map.md",
        "coverage_threshold": 70,  # lower due to physical access constraints
        "required_sections": [
            "Robot Model",
            "ROS Version",
            "Network Access",
            "Known Issues",
            "Exclusion List",
            "Safety Constraints",  # physical safety limitations
            "CVE Submission Target",  # GHSA or MITRE
        ],
    },
    "supplychain": {
        "rules_file": "sc_program_rules_summary.md",
        "endpoint_map": "sc_endpoint_map.md",
        "coverage_threshold": 80,
        "required_sections": [
            "Package Manager",
            "Registry Configuration",
            "Known Issues",
            "Exclusion List",
            "Submission Rules",
            "Severity Scope",
            "Build Pipeline Platform",
        ],
    },
}


def _get_domain_config(domain: str) -> dict:
    """Get domain-specific configuration. Defaults to 'bounty'."""
    return DOMAIN_CONFIG.get(domain, DOMAIN_CONFIG["bounty"])


def init(target_dir: str, domain: str = "bounty") -> int:
    """Create template files in target directory."""
    cfg = _get_domain_config(domain)
    tdir = Path(target_dir)
    tdir.mkdir(parents=True, exist_ok=True)

    rules_name = cfg["rules_file"]
    map_name = cfg["endpoint_map"]

    rules_src = TEMPLATE_DIR / rules_name
    map_src = TEMPLATE_DIR / map_name
    # For non-bounty domains, prefer inline domain templates over bounty fallback
    if domain != "bounty":
        if not rules_src.exists():
            rules_src = None  # will use inline domain template
        if not map_src.exists():
            map_src = None  # will use inline domain template
    else:
        # Bounty: fallback to default templates
        if not rules_src.exists():
            rules_src = TEMPLATE_DIR / RULES_FILE
        if not map_src.exists():
            map_src = TEMPLATE_DIR / ENDPOINT_MAP

    created = []
    for src, name in [(rules_src, rules_name), (map_src, map_name)]:
        dst = tdir / name
        if dst.exists():
            print(f"SKIP: {name} already exists in {target_dir}")
            continue
        if src and src.exists():
            shutil.copy2(src, dst)
        else:
            # Inline domain-specific template
            if name == rules_name:
                dst.write_text(_inline_rules_template(target_dir, domain))
            else:
                dst.write_text(_inline_map_template(target_dir, domain))
        created.append(name)

    # Cost tracking template (SCONE-bench inspired — $1.22/contract benchmark)
    cost_file = tdir / "cost_tracking.json"
    if not cost_file.exists():
        cost_template = {
            "target": os.path.basename(target_dir.rstrip("/")),
            "created": datetime.now().isoformat(),
            "phases": {
                "phase_0": {"tokens": 0, "duration_sec": 0, "api_cost_est": 0.0},
                "phase_1": {"tokens": 0, "duration_sec": 0, "api_cost_est": 0.0},
                "phase_2": {"tokens": 0, "duration_sec": 0, "api_cost_est": 0.0},
                "phase_3_5": {"tokens": 0, "duration_sec": 0, "api_cost_est": 0.0},
            },
            "agents": {},
            "total_tokens": 0,
            "total_cost_est": 0.0,
            "roi": None,
        }
        cost_file.write_text(json.dumps(cost_template, indent=2))
        created.append("cost_tracking.json")

    # Create standard scaffold files
    scaffold_files = {
        "checkpoint.json": json.dumps({
            "agent": "orchestrator",
            "status": "initialized",
            "phase": "0",
            "phase_name": "target_evaluation",
            "completed": [],
            "in_progress": [],
            "critical_facts": [],
            "expected_artifacts": [rules_name, map_name],
            "produced_artifacts": created,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")
        }, indent=2),
        "explore_candidates.md": f"# Explore Candidates — {Path(target_dir).name}\n\n"
                                  "<!-- E3/E4 findings parked here for potential recycling -->\n",
    }
    for fname, content in scaffold_files.items():
        fpath = tdir / fname
        if not fpath.exists():
            fpath.write_text(content, encoding="utf-8")
            created.append(fname)

    # Create submission/ directory
    sub_dir = tdir / "submission"
    if not sub_dir.exists():
        sub_dir.mkdir(parents=True, exist_ok=True)
        created.append("submission/")

    if created:
        print(f"CREATED ({domain}): {', '.join(created)} in {target_dir}")
    else:
        print(f"All templates already exist in {target_dir}")
    return 0


def rules_check(target_dir: str, domain: str = "bounty") -> int:
    """Validate program_rules_summary.md exists and has all required sections."""
    cfg = _get_domain_config(domain)
    rules_file = cfg["rules_file"]
    required_sections = cfg["required_sections"]

    rules_path = Path(target_dir) / rules_file
    if not rules_path.exists():
        print(f"FAIL: {rules_file} not found in {target_dir}")
        print(f"  → Run: python3 {__file__} init {target_dir} --domain {domain}")
        print(f"  → Then fill in ALL <REQUIRED> fields before spawning agents")
        return 1

    content = rules_path.read_text()

    # Check required sections
    missing = []
    for section in required_sections:
        if section not in content:
            missing.append(section)

    if missing:
        print(f"FAIL: Missing sections in {rules_file}: {', '.join(missing)}")
        return 1

    # Check for unfilled placeholders
    placeholders = re.findall(r"<(?:TODO|FILL|REQUIRED|PLACEHOLDER)[^>]*>", content)
    if placeholders:
        unique = list(set(placeholders))
        print(f"FAIL: {len(unique)} unfilled placeholder(s): {unique[:5]}")
        print(f"  → Fill ALL <REQUIRED:...> fields in {rules_path}")
        return 1

    # Check minimum content (not just section headers)
    for section in required_sections:
        # Find section and check it has content after it
        pattern = rf"##\s*{re.escape(section)}\s*\n(.*?)(?=\n##|\Z)"
        match = re.search(pattern, content, re.DOTALL)
        if match:
            body = match.group(1).strip()
            if len(body) < 10:
                print(f"FAIL: Section '{section}' appears empty (< 10 chars)")
                return 1

    # v12.3 — LiteLLM $0/duplicate + Composio 404 incidents: HARD FAIL if program page
    # was inaccessible. Check BOTH rules file AND target_assessment.md because scouts
    # sometimes sanitize the rules file but leave the warning in target_assessment.md.
    inaccessible_markers = [
        "returns 404", "returned 404",
        "returns 403", "returned 403",
        "not retrievable", "not accessible",
        "page inaccessible", "page returns 404",
        "OOS list not retrievable", "program detail page returned",
        "program may be unlisted", "program may be inactive",
        "no confirmed active program listing",
        "0 reports found", "hacktivity shows 0",
        "program listing not confirmed",
        "huntr program page returns 404",
    ]

    # Scan rules file
    content_lower = content.lower()
    hit_markers = [f"{rules_file}: '{m}'" for m in inaccessible_markers if m.lower() in content_lower]

    # ALSO scan target_assessment.md — scouts may sanitize rules file but leave warnings here
    ta_path = Path(target_dir) / "target_assessment.md"
    if ta_path.exists():
        ta_content = ta_path.read_text().lower()
        hit_markers.extend(
            f"target_assessment.md: '{m}'" for m in inaccessible_markers if m.lower() in ta_content
        )

    if hit_markers:
        print(f"FAIL (HARD): program page inaccessibility markers detected:")
        for m in hit_markers:
            print(f"  - {m}")
        print("  → Scout could not retrieve authoritative scope/OOS/bounty. Do NOT proceed.")
        print("  → Resolve one of:")
        print("    1. Find alternate program URL that returns 200")
        print("    2. Contact program directly for scope confirmation")
        print("    3. NO-GO this target — submission risk unacceptable")
        print("  → v12.3 rule: program page must be live-retrievable before Phase 1.")
        return 1

    # v12.3 — LiteLLM $0 incident: HARD FAIL if live bounty status is $0 with CVE-only tag
    # For huntr targets, the per-repo active bounty must be checked, not just the platform max
    live_bounty_markers = [
        "$0", "cve-only", "cve only",
        "no cash bounty", "attribution only",
    ]
    # Only trigger if the markers appear in the bounty-related context, not as negation
    bounty_section_pattern = r"(?i)(bounty|reward).*?(?=\n##|\Z)"
    bounty_matches = re.findall(bounty_section_pattern, content, re.DOTALL)
    if bounty_matches:
        bounty_text = " ".join(bounty_matches).lower()
        if "$0" in bounty_text and "cve" in bounty_text and "not" not in bounty_text[:200]:
            print(f"WARN: live bounty appears to be $0 / CVE-only in {rules_file}")
            print(f"  → Target may pay CVE attribution only, no cash bounty")
            print(f"  → User must explicitly opt in for CVE-only targets")
            print(f"  → v12.3 rule: verify per-repo live bounty before Phase 1")
            # WARN not FAIL — some users may want CVE attribution
            return 2

    print(f"PASS: {rules_file} validated ({len(required_sections)} sections, no placeholders)")
    return 0


def coverage_check(target_dir: str, threshold: int = None, json_output: bool = False, domain: str = "bounty") -> int:
    """Parse endpoint_map.md and calculate coverage percentage.

    Args:
        target_dir: Path to target directory containing endpoint_map.md
        threshold: Minimum coverage percentage (None = use domain default)
        json_output: If True, output structured JSON instead of text
        domain: Domain type for config lookup
    Returns:
        0 if PASS, 1 if FAIL
    """
    cfg = _get_domain_config(domain)
    if threshold is None:
        threshold = cfg["coverage_threshold"]
    map_file = cfg["endpoint_map"]
    map_path = Path(target_dir) / map_file
    if not map_path.exists():
        if json_output:
            import json
            print(json.dumps({"result": "FAIL", "error": f"{map_file} not found", "coverage": 0}))
        else:
            print(f"FAIL: {ENDPOINT_MAP} not found in {target_dir}")
            print(f"  → Scout must generate {ENDPOINT_MAP} during Phase 1")
        return 1

    content = map_path.read_text()
    lines = content.split("\n")

    statuses = {"UNTESTED": 0, "TESTED": 0, "VULN": 0, "SAFE": 0, "EXCLUDED": 0}
    untested_endpoints = []
    total = 0

    # Find Status column index from header row
    status_col = None
    for line in lines:
        if "|" in line and "Status" in line:
            hcells = [c.strip() for c in line.split("|")]
            for idx, cell in enumerate(hcells):
                if cell.upper() == "STATUS":
                    status_col = idx
                    break
            break
    if status_col is None:
        status_col = 4  # Default: | Endpoint | Method | Auth | Status | Notes |

    for line in lines:
        if "|" not in line:
            continue
        cells = [c.strip() for c in line.split("|")]
        if len(cells) <= status_col:
            continue
        # Skip header, separator, empty rows
        if cells[1] in ("", "Endpoint", "---") or cells[1].startswith("-"):
            continue
        if set(cells[1]) <= {"-", " "}:
            continue

        status = cells[status_col].upper()
        if status in statuses:
            statuses[status] += 1
            total += 1
            if status == "UNTESTED":
                untested_endpoints.append(cells[1])

    if total == 0:
        if json_output:
            import json
            print(json.dumps({"result": "FAIL", "error": "No endpoints found", "coverage": 0}))
        else:
            print(f"FAIL: No endpoints found in {ENDPOINT_MAP}")
            print(f"  → Scout must populate the endpoint table")
        return 1

    testable = total - statuses["EXCLUDED"]
    if testable == 0:
        if json_output:
            import json
            print(json.dumps({"result": "FAIL", "error": "All endpoints EXCLUDED", "coverage": 0}))
        else:
            print(f"FAIL: All {total} endpoints are EXCLUDED — nothing to test")
        return 1

    # Auto-adjust threshold for small targets
    effective_threshold = 100 if testable < 10 else threshold

    tested = statuses["TESTED"] + statuses["VULN"] + statuses["SAFE"]
    coverage = (tested / testable) * 100

    passed = coverage >= effective_threshold

    if json_output:
        import json
        print(json.dumps({
            "result": "PASS" if passed else "FAIL",
            "coverage": round(coverage, 1),
            "threshold": effective_threshold,
            "total": total,
            "testable": testable,
            "tested": tested,
            "statuses": statuses,
            "untested_endpoints": untested_endpoints,
            "small_target_override": testable < 10,
        }))
    else:
        print(f"Coverage: {coverage:.1f}% ({tested}/{testable} testable endpoints)")
        print(f"  VULN={statuses['VULN']} SAFE={statuses['SAFE']} "
              f"TESTED={statuses['TESTED']} UNTESTED={statuses['UNTESTED']} "
              f"EXCLUDED={statuses['EXCLUDED']}")
        if testable < 10:
            print(f"  (Small target: <10 endpoints → threshold auto-raised to 100%)")

        if not passed:
            print(f"FAIL: Coverage {coverage:.1f}% < threshold {effective_threshold}%")
            print(f"  → Spawn additional exploiter/analyst round for UNTESTED endpoints")
            if untested_endpoints:
                print(f"  → UNTESTED: {', '.join(untested_endpoints[:20])}")
        else:
            print(f"PASS: Coverage {coverage:.1f}% >= threshold {effective_threshold}%")

    return 0 if passed else 1


def inject_rules(target_dir: str) -> int:
    """Output compact rules for HANDOFF injection (first 3 lines of agent prompt)."""
    rules_path = Path(target_dir) / RULES_FILE
    if not rules_path.exists():
        print(f"FAIL: {RULES_FILE} not found", file=sys.stderr)
        return 1

    content = rules_path.read_text()

    # Extract key fields for compact injection (allow extra text after section name)
    auth_match = re.search(
        r"##\s*Auth Header Format[^\n]*\n(.*?)(?=\n##|\Z)", content, re.DOTALL
    )
    headers_match = re.search(
        r"##\s*Mandatory Headers[^\n]*\n(.*?)(?=\n##|\Z)", content, re.DOTALL
    )
    curl_match = re.search(
        r"##\s*Verified Curl Template[^\n]*\n(.*?)(?=\n##|\Z)", content, re.DOTALL
    )

    print("[PROGRAM RULES — READ FIRST, FOLLOW EXACTLY]")
    if auth_match:
        print(f"AUTH: {auth_match.group(1).strip()[:200]}")
    if headers_match:
        print(f"HEADERS: {headers_match.group(1).strip()[:300]}")
    if curl_match:
        print(f"CURL TEMPLATE:\n{curl_match.group(1).strip()[:500]}")
    print("[END PROGRAM RULES]")
    return 0


def exclusion_filter(target_dir: str) -> int:
    """Output exclusion list for analyst (Known Issues + Exclusion List)."""
    rules_path = Path(target_dir) / RULES_FILE
    if not rules_path.exists():
        print(f"FAIL: {RULES_FILE} not found", file=sys.stderr)
        return 1

    content = rules_path.read_text()

    known_match = re.search(
        r"##\s*Known Issues[^\n]*\n(.*?)(?=\n##|\Z)", content, re.DOTALL
    )
    submitted_match = re.search(
        r"##\s*Already Submitted[^\n]*\n(.*?)(?=\n##|\Z)", content, re.DOTALL
    )
    excl_match = re.search(
        r"##\s*Exclusion List[^\n]*\n(.*?)(?=\n##|\Z)", content, re.DOTALL
    )

    print("[EXCLUSION FILTER — Skip findings matching these patterns]")
    if known_match:
        print(f"\n### Known Issues (already reported/acknowledged):")
        print(known_match.group(1).strip())
    if submitted_match:
        print(f"\n### Already Submitted (do NOT duplicate):")
        print(submitted_match.group(1).strip())
    if excl_match:
        print(f"\n### Program Exclusions (out of scope):")
        print(excl_match.group(1).strip())
    print("\n[END EXCLUSION FILTER]")
    return 0


# --- Kill Gates (advisory pre-validation, exit 0=PASS, 1=WARN) ---

# v12.5: Port of Antwerp postmortem (2026-04-14) — info-disclosure collision guards.
# Both PORTOFANTWERP-7TS0VZVW and PORTOFANTWERP-56QI3QB6 closed OOS with
# 'Verbose messages/files/directory listings without disclosing any sensitive
# information'. The prior word-overlap exclusion check missed it: finding titles
# used 'Exposes K8s Pod Hostname' / 'Stack Trace Disclosure' — zero shared
# ≥4-char words with 'verbose/messages/files/directory/listings'.

_INFO_DISC_KEYWORDS = (
    "stack trace", "stacktrace", "verbose", "error message", "error response",
    "directory listing", "banner", "version disclosure", "source map",
    "exception trace", "hostname disclosure", "pod hostname",
    "internal url", "internal host", "internal endpoint", "path disclosure",
    "server header", "debug output", "debug info", "env dump",
    "environment variable", "configuration exposure", "information disclosure",
    "information exposure", "info leak", "info disclosure",
    "exposes k8s", "k8s hostname", "kubernetes hostname",
)

_VERBOSE_OOS_PATTERNS = (
    r"verbose\s+(?:message|file|error)",
    r"error\s+message[^.\n]*without",
    r"stack\s*trace[^.\n]*without",
    r"banner\s+grab",
    r"version\s+disclosure",
    r"directory\s+listing",
    r"information\s+disclosure[^.\n]*without[^.\n]*sensitive",
    r"internal\s+(?:ip|hostname|url|address)[^.\n]*without",
    r"non[\s-]?sensitive\s+information",
    r"without\s+disclosing[^.\n]*sensitive",
    r"(?:missing|lack\s+of)\s+(?:security\s+)?headers?",
)

# Anchors that make info-disclosure concretely "sensitive" enough to survive OOS.
# These must appear in --impact or finding to promote HARD_KILL → WARN.
_SENSITIVITY_ANCHORS = (
    "credential", "password", "secret", "api key", "api-key",
    "private key", "session token", "session cookie", "access token",
    "bearer token", "refresh token", "jwt", "oauth token",
    "pii", "personally identifiable", "personal data",
    "ssn", "social security", "credit card", "payment card",
    "financial data", "health record", "phi",
    "authentication bypass", "auth bypass", "credential theft",
    "account takeover", "privilege escalation",
    "rce via", "remote code execution via",
    "sql injection via", "command injection via",
    "source code leak", "source code disclosure",
)


def _info_disc_oos_check(finding: str, impact: str, rules_content: str) -> tuple[list, list]:
    """v12.5: Catch info-disclosure findings that collide with a program's
    verbose/error/banner-class OOS rule unless --impact cites a concrete
    sensitivity anchor. Returns (warnings, hard_kills)."""
    warnings: list = []
    hard_kills: list = []

    finding_lower = (finding or "").lower()
    impact_lower = (impact or "").lower()

    # Gate 1: does finding class as info-disclosure?
    info_hit = next((kw for kw in _INFO_DISC_KEYWORDS if kw in finding_lower), None)
    if not info_hit:
        return warnings, hard_kills

    # Gate 2: does program OOS contain a verbose-class exclusion?
    oos_match = re.search(
        r"##\s*(?:Out-of-Scope|Exclusion List)[^\n]*\n(.*?)(?=\n##|\Z)",
        rules_content, re.DOTALL | re.IGNORECASE,
    )
    if not oos_match:
        warnings.append(
            f"[INFO-DISC UNCHECKED] Finding is info-disclosure class (keyword '{info_hit}') "
            f"but OOS section not parseable — manually verify program does not exclude "
            f"verbose/error/banner/stack-trace findings."
        )
        return warnings, hard_kills

    oos_body = oos_match.group(1).lower()
    verbose_oos_hit = next(
        (pat for pat in _VERBOSE_OOS_PATTERNS if re.search(pat, oos_body)), None
    )
    if not verbose_oos_hit:
        return warnings, hard_kills

    # Gate 3: demand concrete sensitivity anchor in --impact or finding.
    sensitivity_hit = next(
        (a for a in _SENSITIVITY_ANCHORS if a in impact_lower or a in finding_lower),
        None,
    )

    if not sensitivity_hit:
        hard_kills.append(
            f"[HARD_KILL] INFO-DISC / VERBOSE-OOS COLLISION. "
            f"Finding is info-disclosure class (matched '{info_hit}') AND program OOS "
            f"excludes verbose/error-class findings (matched pattern r'{verbose_oos_hit}'). "
            f"--impact does NOT cite a concrete sensitivity anchor "
            f"(credentials/tokens/PII/auth-bypass/RCE chain/source-code leak). "
            f"Port of Antwerp 2026-04-14 postmortem: same class closed as OOS, €0. "
            f"Either (a) provide concrete attack scenario via --impact, or (b) KILL."
        )
    else:
        warnings.append(
            f"[INFO-DISC GREY-ZONE] Info-disclosure finding (keyword '{info_hit}') "
            f"collides with verbose-class OOS (pattern r'{verbose_oos_hit}'). "
            f"Sensitivity anchor '{sensitivity_hit}' claimed — verify it is DEMONSTRATED "
            f"in PoC, not just asserted. Triager will test the sensitivity claim."
        )

    return warnings, hard_kills


def kill_gate_1(target_dir: str, finding: str, severity: str = "", impact: str = "") -> int:
    """Pre-validate finding viability before Kill Gate 1.

    v12.3 HARDENED (Immunefi postmortem):
    - --severity is MANDATORY — no more guessing from finding description
    - Severity OOS = HARD_KILL (exit 2), not advisory
    - Impact-scope matching against program's in-scope impact list
    - Exclusion + duplicate checks remain advisory (exit 1)

    v12.5 ADDED (Port of Antwerp postmortem 2026-04-14):
    - Info-disclosure / verbose-OOS collision check (Check 3.5)
    - If finding class is info-disclosure AND program OOS has verbose/error/banner
      exclusion AND --impact lacks a concrete sensitivity anchor → HARD_KILL.
    - If sensitivity anchor is claimed → WARN (grey-zone; triager will test claim).

    Returns: 0=PASS, 1=WARN (advisory), 2=HARD_KILL (blocks gate)
    """
    warnings = []
    hard_kills = []
    tdir = Path(target_dir)

    # --- Severity parameter validation (MANDATORY since v12.3) ---
    severity = severity.strip().lower()
    if not severity:
        hard_kills.append(
            "[HARD_KILL] --severity not provided. MANDATORY since v12.3. "
            "Usage: kill-gate-1 <dir> --finding '<desc>' --severity <critical|high|medium|low>"
        )
    elif severity not in ("critical", "high", "medium", "low"):
        hard_kills.append(
            f"[HARD_KILL] Invalid severity '{severity}'. Must be: critical, high, medium, low"
        )

    rules_path = tdir / RULES_FILE
    rules_content = ""
    if rules_path.exists():
        rules_content = rules_path.read_text()
    else:
        hard_kills.append(f"[HARD_KILL] {RULES_FILE} not found in {target_dir} — cannot validate scope")

    # --- Check 1: HARD severity scope check (v12.3 — KILL not advisory) ---
    if severity and rules_content:
        sev_match = re.search(
            r"##\s*Severity Scope[^\n]*\n(.*?)(?=\n##|\Z)", rules_content, re.DOTALL
        )
        if sev_match:
            sev_body = sev_match.group(1).strip().lower()

            # Parse accepted severities from scope table
            accepted_sevs = set()
            for sev_name in ["critical", "high", "medium", "low"]:
                # Match patterns: "Critical | $50,000", "Critical", "High+", etc.
                if sev_name in sev_body:
                    accepted_sevs.add(sev_name)
            # Handle "High+" pattern — means high, critical
            if "high+" in sev_body or "high and above" in sev_body:
                accepted_sevs.update({"high", "critical"})
            # Handle "Critical only"
            if "critical only" in sev_body:
                accepted_sevs = {"critical"}

            if accepted_sevs and severity not in accepted_sevs:
                hard_kills.append(
                    f"[HARD_KILL] Severity '{severity}' NOT in program scope. "
                    f"Accepted: {', '.join(sorted(accepted_sevs))}. "
                    f"This was the #1 cause of Immunefi rejections (Daimo Pay, Utix)."
                )
        else:
            warnings.append(f"[MISSING] Severity Scope section not found in {RULES_FILE}")

    # --- Check 2: Impact-scope matching (v12.3 NEW — Utix postmortem) ---
    if rules_content:
        # Extract in-scope impacts from program rules
        inscope_match = re.search(
            r"##\s*In-Scope Assets.*?\n(.*?)(?=\n##|\Z)", rules_content, re.DOTALL
        )
        # Also check for explicit impact categories (Immunefi-style)
        impact_match = re.search(
            r"(?:Impact|Impacts? in Scope)[^\n]*\n(.*?)(?=\n##|\Z)", rules_content, re.DOTALL | re.IGNORECASE
        )

        scope_impacts = set()
        for match in [inscope_match, impact_match]:
            if match:
                body = match.group(1).strip().lower()
                # Extract impact phrases (common Immunefi/Bugcrowd patterns)
                impact_phrases = re.findall(
                    r'(?:permanent freezing|temporary freezing|direct theft|manipulation|'
                    r'unauthorized minting|griefing|unlocking stuck|denial of service|'
                    r'temporary dos|governance manipulation|privilege escalation|'
                    r'data exposure|rce|remote code|xss|sqli|ssrf|idor|'
                    r'fund loss|fund theft|token drain|price manipulation|'
                    r'access control|authentication bypass|authorization bypass)[a-z ]*',
                    body
                )
                scope_impacts.update(impact_phrases)

        claimed_impact = impact.strip().lower() if impact else ""
        if claimed_impact and scope_impacts:
            # Check if claimed impact matches any in-scope impact
            claimed_words = set(w for w in re.split(r"\W+", claimed_impact) if len(w) >= 4)
            best_match_score = 0
            best_match = ""
            for si in scope_impacts:
                si_words = set(w for w in re.split(r"\W+", si) if len(w) >= 4)
                if not si_words:
                    continue
                overlap = claimed_words & si_words
                score = len(overlap) / max(len(si_words), 1)
                if score > best_match_score:
                    best_match_score = score
                    best_match = si
            if best_match_score < 0.3:
                hard_kills.append(
                    f"[HARD_KILL] Claimed impact '{claimed_impact}' does NOT match any in-scope impact. "
                    f"Closest match: '{best_match}' (score: {best_match_score:.0%}). "
                    f"In-scope impacts: {', '.join(sorted(scope_impacts)[:5])}... "
                    f"Reframe impact to match program's exact wording or KILL."
                )
            elif best_match_score < 0.6:
                warnings.append(
                    f"[IMPACT WEAK MATCH] Claimed '{claimed_impact}' partially matches '{best_match}' "
                    f"(score: {best_match_score:.0%}). Verify wording matches program exactly."
                )
        elif claimed_impact and not scope_impacts:
            warnings.append(
                "[IMPACT UNCHECKED] No in-scope impacts extracted from program rules — manual verification required"
            )

    # --- Check 3: Exclusion list match (unchanged) ---
    if rules_content:
        excl_match = re.search(
            r"##\s*(?:Out-of-Scope|Exclusion List)[^\n]*\n(.*?)(?=\n##|\Z)", rules_content, re.DOTALL
        )
        if excl_match:
            excl_body = excl_match.group(1).strip()
            finding_lower = finding.lower()
            for line in excl_body.splitlines():
                line_clean = line.strip().lstrip("0123456789.-) ").lower()
                if not line_clean or line_clean.startswith("#"):
                    continue
                excl_words = set(w for w in re.split(r"\W+", line_clean) if len(w) >= 4)
                finding_words = set(w for w in re.split(r"\W+", finding_lower) if len(w) >= 4)
                overlap = excl_words & finding_words
                if overlap:
                    warnings.append(
                        f"[EXCLUSION MATCH] Finding overlaps with exclusion entry: '{line.strip()}'"
                        f" (shared keywords: {', '.join(sorted(overlap))})"
                    )

    # --- Check 3.5: Info-disclosure / verbose-OOS collision (v12.5) ---
    if rules_content:
        idoc_warnings, idoc_kills = _info_disc_oos_check(finding, impact, rules_content)
        warnings.extend(idoc_warnings)
        hard_kills.extend(idoc_kills)

    # --- Check 4: Asset scope constraints (branch/tag) ---
    if rules_content:
        asset_match = re.search(
            r"##\s*Asset Scope Constraints[^\n]*\n(.*?)(?=\n##|\Z)", rules_content, re.DOTALL
        )
        if asset_match:
            asset_body = asset_match.group(1).strip().lower()
            finding_lower = finding.lower()
            if any(kw in asset_body for kw in ["mainnet tags only", "testnet tags only", "tagged releases only"]):
                if "main branch" in finding_lower or "main only" in finding_lower:
                    warnings.append(
                        "[BRANCH OOS] Finding is on main branch but program scopes to tagged releases only"
                    )
                warnings.append(
                    "[BRANCH CHECK] Asset scope has branch/tag restriction — verify affected code exists in scoped version"
                )

    # --- Check 5: Duplicate against previous submission titles ---
    submission_glob = tdir / "submission"
    form_files = list(submission_glob.glob("report_*/bugcrowd_form.md")) + list(submission_glob.glob("*/bugcrowd_form.md"))
    if form_files:
        finding_lower = finding.lower()
        finding_words = set(w for w in re.split(r"\W+", finding_lower) if len(w) >= 4)
        for form_path in form_files:
            form_content = form_path.read_text()
            title_match = re.search(r"(?i)^#+\s*Title[:\s]+(.+)$", form_content, re.MULTILINE)
            if not title_match:
                title_match = re.search(r"(?i)^Title[:\s]+(.+)$", form_content, re.MULTILINE)
            if not title_match:
                continue
            title = title_match.group(1).strip().lower()
            title_words = set(w for w in re.split(r"\W+", title) if len(w) >= 4)
            overlap = finding_words & title_words
            if len(overlap) >= 2:
                warnings.append(
                    f"[DUPLICATE RISK] Finding shares keywords with previous submission"
                    f" '{form_path.parent.name}/bugcrowd_form.md' title: '{title_match.group(1).strip()}'"
                    f" (overlap: {', '.join(sorted(overlap))})"
                )

    # --- Report ---
    if hard_kills:
        print(f"HARD_KILL: kill-gate-1 raised {len(hard_kills)} blocking issue(s) for: \"{finding}\"")
        for hk in hard_kills:
            print(f"  {hk}")
        if warnings:
            print(f"  (also {len(warnings)} advisory warning(s))")
            for w in warnings:
                print(f"  {w}")
        print("  → BLOCKED. Fix severity/impact/scope before proceeding. No exploiter spawn allowed.")
        return 2

    if warnings:
        print(f"WARN: kill-gate-1 raised {len(warnings)} advisory flag(s) for: \"{finding}\"")
        for w in warnings:
            print(f"  {w}")
        print("  → Advisory only. Confirm with triager-sim before proceeding.")
        return 1

    print(f"PASS: kill-gate-1 — no scope/severity/exclusion/duplicate flags for: \"{finding}\"")
    return 0


def kill_gate_2(submission_dir: str) -> int:
    """Pre-validate PoC/evidence quality before Kill Gate 2.

    v12.3 HARDENED (Immunefi postmortem):
    - Evidence tier check INTEGRATED and ENFORCED (E3/E4 = FAIL, was advisory)
    - Mock PoC detection = FAIL (was advisory)
    - Severity OOS in submission files = FAIL (was advisory)
    - Weak-claim language remains advisory (WARN)

    Returns: 0=PASS, 1=FAIL (blocks gate)
    """
    warnings = []
    failures = []
    sdir = Path(submission_dir)

    if not sdir.exists():
        print(f"FAIL: submission directory not found: {submission_dir}")
        return 1

    # --- Check -1: Strengthening Report (v12.3 — LiteLLM cross-user exfil lesson) ---
    # MUST run before any other Gate 2 check. strengthening_report.md is required.
    print("[Gate 2 Pre-check] Running strengthening-check...")
    strength_ret = strengthening_check(submission_dir)
    if strength_ret == 1:
        print("FAIL (HARD): strengthening-check failed. Gate 2 blocked.")
        return 1
    elif strength_ret == 2:
        warnings.append(
            "[STRENGTHENING WARN] Phase 2 → Gate 2 transition was rushed (delta < 30min). "
            "Verify strengthening attempts were genuine."
        )

    # --- Check 0: severity/scope pre-check from program_rules_summary.md ---
    target_dir = sdir.parent.parent  # submission/<name>/ → target/
    rules_path = target_dir / RULES_FILE
    if rules_path.exists():
        rules_content = rules_path.read_text()
        sev_match = re.search(
            r"##\s*Severity Scope[^\n]*\n(.*?)(?=\n##|\Z)", rules_content, re.DOTALL
        )
        if sev_match:
            sev_body = sev_match.group(1).strip().lower()
            # Parse accepted severities
            accepted_sevs = set()
            for sev_name in ["critical", "high", "medium", "low"]:
                if sev_name in sev_body:
                    accepted_sevs.add(sev_name)
            if "critical only" in sev_body:
                accepted_sevs = {"critical"}
            if "high+" in sev_body or "high and above" in sev_body:
                accepted_sevs = {"high", "critical"}

            # Scan submission files for severity claims
            if accepted_sevs:
                for md in sdir.glob("**/*.md"):
                    try:
                        md_text = md.read_text(errors="replace").lower()
                    except OSError:
                        continue
                    for sev in ["critical", "high", "medium", "low"]:
                        if f"severity: {sev}" in md_text or f"severity**: {sev}" in md_text:
                            if sev not in accepted_sevs:
                                failures.append(
                                    f"[SEVERITY OOS] {md.name} claims '{sev}' but program accepts: "
                                    f"{', '.join(sorted(accepted_sevs))}. "
                                    f"This caused Daimo Pay rejection."
                                )
                            break

        # Check branch/tag scope
        asset_match = re.search(
            r"##\s*Asset Scope Constraints[^\n]*\n(.*?)(?=\n##|\Z)", rules_content, re.DOTALL
        )
        if asset_match:
            asset_body = asset_match.group(1).strip().lower()
            if any(kw in asset_body for kw in ["mainnet tags only", "testnet tags only", "tagged releases only"]):
                warnings.append(
                    "[BRANCH CHECK REQUIRED] Program scopes to tagged releases — verify PoC code exists in scoped version"
                )

    POC_KEYWORDS = ["mock", "simulated", "fake", "dummy"]
    EVIDENCE_WEAK_KEYWORDS = ["inferred", "would", "likely", "probably", "could potentially"]

    py_files = list(sdir.glob("**/*.py"))
    sh_files = list(sdir.glob("**/*.sh"))
    md_files = list(sdir.glob("**/*.md"))

    # --- Check 1: PoC files for mock/fake/simulated/dummy → FAIL (was WARN) ---
    poc_files = py_files + sh_files
    for fpath in poc_files:
        try:
            content = fpath.read_text(errors="replace")
        except OSError:
            continue
        content_lower = content.lower()
        found = [kw for kw in POC_KEYWORDS if kw in content_lower]
        if found:
            failures.append(
                f"[MOCK POC] {fpath.relative_to(sdir) if fpath.is_relative_to(sdir) else fpath}"
                f" contains: {', '.join(found)}. "
                f"This caused Paradex #72310 rejection. Replace with real fork/devnet PoC."
            )

    # --- Check 2: Evidence files for weak-claim language + empty check ---
    for fpath in md_files:
        try:
            size = fpath.stat().st_size
        except OSError:
            continue
        if size == 0:
            failures.append(
                f"[EMPTY FILE] {fpath.relative_to(sdir) if fpath.is_relative_to(sdir) else fpath}"
                f" is 0 bytes — no empty evidence files allowed"
            )
            continue

        try:
            content = fpath.read_text(errors="replace")
        except OSError:
            continue
        content_lower = content.lower()
        found = [kw for kw in EVIDENCE_WEAK_KEYWORDS if kw in content_lower]
        if found:
            warnings.append(
                f"[WEAK CLAIM] {fpath.relative_to(sdir) if fpath.is_relative_to(sdir) else fpath}"
                f" contains: {', '.join(found)}"
            )

    # --- Check 3: Evidence tier enforcement (v12.3 — INTEGRATED, was separate) ---
    # Inline the evidence_tier_check logic — E3/E4 = FAIL
    signals = {
        "has_poc_script": bool(poc_files),
        "has_output_file": False,
        "has_real_target_url": False,
        "has_before_after": False,
    }

    evidence_patterns = ["output_*.txt", "evidence_*.png", "evidence_*.txt", "response_*.txt",
                         "*_evidence.*", "race_evidence_*"]
    for pattern in evidence_patterns:
        if list(sdir.glob(pattern)):
            signals["has_output_file"] = True
            break

    for poc_file in poc_files:
        try:
            content = poc_file.read_text(encoding="utf-8", errors="ignore").lower()
            if any(m in content for m in ["https://", "http://", "requests.post", "requests.get", "cast call", "forge test"]):
                if "localhost" not in content and "127.0.0.1" not in content and "mock" not in content:
                    signals["has_real_target_url"] = True
            if any(m in content for m in ["before", "after", "diff", "delta", "balance_before", "balance_after"]):
                signals["has_before_after"] = True
        except Exception:
            continue

    # Determine tier
    if signals["has_poc_script"] and signals["has_output_file"] and signals["has_real_target_url"]:
        if signals["has_before_after"]:
            e_tier = "E1"
        else:
            e_tier = "E2"
    elif signals["has_poc_script"]:
        e_tier = "E3"
    else:
        e_tier = "E4"

    if e_tier in ("E3", "E4"):
        failures.append(
            f"[EVIDENCE {e_tier}] Evidence tier is {e_tier} (explore-only). "
            f"Requires E1/E2 for submission. "
            f"Missing: {', '.join(k.replace('has_', '') for k, v in signals.items() if not v)}. "
            f"Paradex #72310 was rejected for E3-level evidence (mock PoC, no fork)."
        )
    else:
        print(f"  [EVIDENCE {e_tier}] Evidence tier: {e_tier} (submit-ready)")

    # --- Report ---
    scanned = len(poc_files) + len(md_files)
    if failures:
        print(f"FAIL: kill-gate-2 raised {len(failures)} blocking issue(s) across {scanned} file(s) in {submission_dir}")
        for f in failures:
            print(f"  {f}")
        if warnings:
            print(f"  (also {len(warnings)} advisory warning(s))")
            for w in warnings:
                print(f"  {w}")
        print("  → BLOCKED. Fix evidence quality before proceeding. No reporter spawn allowed.")
        return 1

    if warnings:
        print(f"WARN: kill-gate-2 — {scanned} file(s) scanned, {len(warnings)} advisory warning(s) in {submission_dir}")
        for w in warnings:
            print(f"  {w}")
        print("  → Advisory only. Confirm with triager-sim before proceeding.")
        return 0  # Warnings don't block

    print(f"PASS: kill-gate-2 — {scanned} file(s) scanned, evidence {e_tier}, no issues in {submission_dir}")
    return 0


# --- Inline templates (fallback if templates/ dir missing) ---

def _inline_rules_template(target_dir: str, domain: str = "bounty") -> str:
    name = Path(target_dir).name.upper()
    cfg = _get_domain_config(domain)

    # Build section templates from domain config
    verbatim_sections = {"Known Issues", "Exclusion List", "Severity Scope",
                         "Safety Constraints", "CVE Submission Target",
                         "Acceptable Use Policy", "Prompt Injection Scope"}
    sections = ""
    for section_name in cfg["required_sections"]:
        if section_name in verbatim_sections:
            sections += f"\n## {section_name} (VERBATIM — 원문 통째로 복사, 요약 금지)\n<REQUIRED: 프로그램/제품 페이지에서 원문 그대로 복사>\n"
        else:
            sections += f"\n## {section_name}\n<REQUIRED: Fill this section>\n"

    if domain != "bounty":
        return f"""# {domain.upper()} Program Rules Summary — {name}
{sections}
## Verified Curl Template
<REQUIRED: A WORKING curl/command that demonstrates correct access>
"""

    return f"""# Program Rules Summary — {name}

## Platform
<REQUIRED: Platform name (FindTheGap, Bugcrowd, H1, Immunefi, etc.)>

## Auth Header Format
<REQUIRED: Exact auth header format used in API requests>
Example: `IdToken: <COGNITO_ID_TOKEN>` (NOT `Authorization: Bearer`)

## Mandatory Headers
<REQUIRED: All required headers for valid requests — copy exact values>
Example:
- `bugbounty: [FindtheGap]security_test_c16508a5-ebcb-4d0f-bf7a-811668fbaa44`

## In-Scope Assets (VERBATIM — 프로그램 페이지에서 통째로 복사, 요약 금지)
<REQUIRED: 프로그램 페이지의 in-scope 자산 목록을 한 글자도 빠짐없이 복사>
<REQUIRED: 자산 옆에 qualifier가 있으면 반드시 포함 (예: "APIs located under", "Smart contracts only", "This is not a wildcard scope")>

## Out-of-Scope / Exclusion List (VERBATIM — 프로그램 페이지에서 통째로 복사, 요약 금지)
<REQUIRED: 프로그램 페이지의 out-of-scope 및 exclusion 전체 목록을 한 글자도 빠짐없이 복사>
<REQUIRED: 번호, 불릿, 문구 모두 원본 그대로. 축약/paraphrase = 파이프라인 위반>

## Known Issues (VERBATIM — 프로그램 페이지에서 통째로 복사)
<REQUIRED: 프로그램이 이미 인지한 이슈 목록을 원문 그대로 복사>

## Submission Rules (VERBATIM — 프로그램 페이지에서 통째로 복사)
<REQUIRED: 제출 규칙 전문을 원본 그대로 복사>

## Severity Scope (VERBATIM — 프로그램 페이지에서 통째로 복사)
<REQUIRED: severity/bounty 테이블 전체를 원문 그대로 복사>
- NOTE: If scope table shows only "Critical" next to asset, findings below Critical may be OOS

## Asset Scope Constraints (VERBATIM — 프로그램 페이지에서 통째로 복사)
<REQUIRED: version/branch/tag/environment 제약사항 원문 그대로 복사>
- NOTE: Smart contract programs often scope to specific tags — verify affected code exists in scoped version BEFORE Gate 1

## Verified Curl Template
<REQUIRED: A WORKING curl command that demonstrates correct auth — copy from actual successful test>
```bash
curl -s "https://api.example.com/endpoint" \\
  -H "<auth_header>: <token>" \\
  -H "<mandatory_header>: <value>"
```
"""


def _inline_map_template(target_dir: str, domain: str = "bounty") -> str:
    name = Path(target_dir).name.upper()
    domain_label = {"ai": "AI/LLM", "robotics": "Robotics/ROS", "supplychain": "Supply Chain"}.get(domain, "")
    if domain_label:
        return f"""# {domain_label} Endpoint Map — {name}

Generated: <DATE>
Total: 0 endpoints
Coverage: 0%

Status values: UNTESTED | TESTED | VULN | SAFE | EXCLUDED

| Endpoint | Type | Auth | Status | Risk | Notes |
|----------|------|------|--------|------|-------|
| (fill during Phase 1) | | | UNTESTED | | |
"""

    return f"""# Endpoint Map — {name}

Generated: <DATE>
Total: 0 endpoints
Coverage: 0%

Status values: UNTESTED | TESTED | VULN | SAFE | EXCLUDED

| Endpoint | Method | Auth | Status | Notes |
|----------|--------|------|--------|-------|
| /api/example | GET | Required | UNTESTED | |
"""


# --- v12 Subcommands ---

def workflow_check(target_dir: str) -> int:
    """Check that workflow_map.md exists and has minimum content.

    v12: Validates workflow mapping completeness before Phase 2 handoff.
    Rationale: Business logic bugs (CWE-840, CWE-362) have the highest
    acceptance rate on Bugcrowd but require workflow understanding that
    endpoint scanning alone misses.

    Returns: 0=PASS, 1=FAIL
    """
    target = Path(target_dir)
    wf_path = target / "workflow_map.md"

    if not wf_path.exists():
        print("[FAIL] workflow_map.md not found in", target_dir)
        print("  → Run threat-modeler or workflow-auditor first")
        return 1

    content = wf_path.read_text(encoding="utf-8")
    lines = content.strip().split("\n")

    if len(lines) < 10:
        print("[FAIL] workflow_map.md too short ({} lines) — needs substantive content".format(len(lines)))
        return 1

    # Check for workflow structure markers
    has_workflow = False
    has_states = False
    has_transitions = False

    for line in lines:
        lower = line.lower()
        if "## workflow" in lower or "### workflow" in lower:
            has_workflow = True
        if "state" in lower and ("→" in line or "->" in line or "transition" in lower):
            has_transitions = True
        if any(marker in lower for marker in ["entry", "terminal", "pending", "active", "completed", "init"]):
            has_states = True

    issues = []
    if not has_workflow:
        issues.append("No workflow sections found (expected ## Workflow headers)")
    if not has_states:
        issues.append("No state definitions found (expected entry/terminal states)")
    if not has_transitions:
        issues.append("No transitions found (expected state → state patterns)")

    if issues:
        print("[FAIL] workflow_map.md structure incomplete:")
        for issue in issues:
            print("  →", issue)
        return 1

    print("[PASS] workflow_map.md exists with valid structure ({} lines)".format(len(lines)))
    return 0


def fresh_surface_check(target_dir: str, repo_path: str = None) -> int:
    """Check if a mature target has fresh attack surface worth investigating.

    v12: Enables Fresh-Surface Exception for targets that would otherwise
    be NO-GO due to maturity. Analyzes git history for recent security-relevant
    changes.
    Rationale: 33 CLOSED/ABANDONED targets included cases where mature targets
    had fresh modules that were prematurely skipped.

    Returns: 0=FRESH_SURFACE_FOUND, 1=NO_FRESH_SURFACE
    """
    import subprocess

    target = Path(target_dir)
    repo = Path(repo_path) if repo_path else target

    # Check if it's a git repo
    git_dir = repo / ".git"
    if not git_dir.exists():
        # Try to find git repo in parent directories
        check = repo
        while check != check.parent:
            if (check / ".git").exists():
                repo = check
                git_dir = check / ".git"
                break
            check = check.parent
        else:
            print("[SKIP] Not a git repository:", str(repo))
            print("  → Cannot check for fresh surface without git history")
            return 1

    fresh_indicators = []

    # Check 1: Recent commits (last 6 months) touching security-relevant files
    try:
        result = subprocess.run(
            ["git", "log", "--oneline", "--since=6 months ago", "-n", "50",
             "--", "**/*auth*", "**/*middleware*", "**/*permission*", "**/*security*",
             "**/*payment*", "**/*billing*", "**/*admin*", "**/*bridge*", "**/*migration*"],
            capture_output=True, text=True, cwd=str(repo), timeout=30
        )
        recent_security = [l for l in result.stdout.strip().split("\n") if l.strip()]
        if recent_security:
            fresh_indicators.append("Security-relevant commits in last 6mo: {}".format(len(recent_security)))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Check 2: New files added in last 6 months
    try:
        result = subprocess.run(
            ["git", "log", "--oneline", "--since=6 months ago", "--diff-filter=A", "--name-only", "-n", "50"],
            capture_output=True, text=True, cwd=str(repo), timeout=30
        )
        new_files = [l for l in result.stdout.strip().split("\n") if l.strip() and not l.startswith(" ")]
        # Filter for code files only
        code_extensions = {".py", ".js", ".ts", ".sol", ".go", ".rs", ".java", ".rb", ".php"}
        new_code_files = [f for f in new_files if any(f.endswith(ext) for ext in code_extensions)]
        if new_code_files:
            fresh_indicators.append("New code files in last 6mo: {}".format(len(new_code_files)))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Check 3: Check endpoint_map.md for recently added endpoints
    endpoint_map = target / "endpoint_map.md"
    if endpoint_map.exists():
        content = endpoint_map.read_text(encoding="utf-8")
        new_markers = content.lower().count("new") + content.lower().count("added") + content.lower().count("v2")
        if new_markers > 2:
            fresh_indicators.append("Endpoint map contains 'new'/'added' markers: {}".format(new_markers))

    # Check 4: Look for migration/bridge files
    try:
        result = subprocess.run(
            ["git", "log", "--oneline", "--since=6 months ago", "-n", "20",
             "--grep=migration\\|bridge\\|upgrade\\|v2\\|new module\\|scope expansion"],
            capture_output=True, text=True, cwd=str(repo), timeout=30
        )
        migration_commits = [l for l in result.stdout.strip().split("\n") if l.strip()]
        if migration_commits:
            fresh_indicators.append("Migration/bridge/upgrade commits: {}".format(len(migration_commits)))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    if fresh_indicators:
        print("[FOUND] Fresh attack surface detected:")
        for indicator in fresh_indicators:
            print("  ✓", indicator)
        print("  → Fresh-Surface Exception may apply. Scope investigation to new surface only.")
        return 0
    else:
        print("[NONE] No fresh surface detected in last 6 months")
        print("  → Original NO-GO assessment stands")
        return 1


def evidence_tier_check(submission_dir: str, json_output: bool = False) -> int:
    """Classify evidence quality into E1-E4 tiers.

    v12: Separates exploration findings from submission-ready findings.
    E1/E2 are submit-ready. E3/E4 need more investigation.
    Rationale: Binary Tier 1-2/3-4 model from v11 silently killed findings
    worth investigating. Evidence tiers create an explore lane for borderline
    findings. (Evidence: Chain-of-Verification, Dhuliawala et al.)

    Returns: 0=E1/E2 (submit-ready), 1=E3/E4 (explore-only)
    """
    import json as json_module

    sub = Path(submission_dir)

    if not sub.exists():
        print("[FAIL] Submission directory not found:", submission_dir)
        return 1

    # Collect evidence signals
    signals = {
        "has_poc_script": False,
        "has_output_file": False,
        "has_real_target_url": False,
        "has_before_after": False,
        "has_invariant_ref": False,
        "has_config_proof": False,
    }

    # Check for PoC scripts
    poc_patterns = ["poc_*.py", "exploit_*.py", "solve.py", "poc_*.sh", "test_*.py"]
    for pattern in poc_patterns:
        if list(sub.glob(pattern)):
            signals["has_poc_script"] = True
            break

    # Check for output/evidence files
    evidence_patterns = ["output_*.txt", "evidence_*.png", "evidence_*.txt", "response_*.txt",
                         "*_evidence.*", "race_evidence_*"]
    for pattern in evidence_patterns:
        if list(sub.glob(pattern)):
            signals["has_output_file"] = True
            break

    # Check PoC content for real target indicators
    for poc_file in sub.glob("*.py"):
        try:
            content = poc_file.read_text(encoding="utf-8", errors="ignore")
            # Real target = actual URLs, not localhost/mock
            if any(marker in content for marker in ["https://", "http://", "remote(", "requests.post", "requests.get"]):
                if "localhost" not in content and "127.0.0.1" not in content and "mock" not in content.lower():
                    signals["has_real_target_url"] = True
            # Before/after evidence
            if any(marker in content.lower() for marker in ["before", "after", "diff", "delta", "comparison"]):
                signals["has_before_after"] = True
            # Invariant reference
            if any(marker in content.lower() for marker in ["invariant", "inv-", "violation", "assertion"]):
                signals["has_invariant_ref"] = True
        except Exception:
            continue

    # Check for config/reachability proof
    for txt_file in sub.glob("*.md"):
        try:
            content = txt_file.read_text(encoding="utf-8", errors="ignore")
            if any(marker in content.lower() for marker in ["config", "enabled", "reachable", "code path"]):
                signals["has_config_proof"] = True
        except Exception:
            continue

    # Classify tier
    tier = "E4"  # Default: lowest
    reasoning = []

    if signals["has_poc_script"] and signals["has_output_file"] and signals["has_real_target_url"]:
        if signals["has_before_after"]:
            tier = "E1"
            reasoning.append("Full live exploit: PoC + output + real target + before/after evidence")
        else:
            tier = "E2"
            reasoning.append("Live differential proof: PoC + output + real target (no before/after)")
    elif signals["has_poc_script"] and signals["has_invariant_ref"]:
        tier = "E3"
        reasoning.append("Invariant violation proof: PoC references invariant but lacks live target evidence")
    elif signals["has_config_proof"] or signals["has_poc_script"]:
        tier = "E4"
        reasoning.append("Config-backed reachability: code path analysis without runtime evidence")
    else:
        tier = "E4"
        reasoning.append("Insufficient evidence: no PoC or config proof found")

    submit_ready = tier in ("E1", "E2")

    if json_output:
        result = {
            "tier": tier,
            "submit_ready": submit_ready,
            "signals": signals,
            "reasoning": reasoning
        }
        print(json_module.dumps(result, indent=2))
    else:
        status = "PASS" if submit_ready else "FAIL"
        print("[{}] Evidence tier: {} ({})".format(status, tier, "submit-ready" if submit_ready else "explore-only"))
        for r in reasoning:
            print("  →", r)
        if not submit_ready:
            print("  → Log to explore_candidates.md for potential re-investigation")

    return 0 if submit_ready else 1


def duplicate_graph_check(target_dir: str, finding: str, json_output: bool = False) -> int:
    """Check finding against all prior submissions and triage feedback.

    v12: Enhanced duplicate detection using submission history, triage feedback,
    and knowledge base. Goes beyond kill-gate-1's keyword overlap by checking
    CWE patterns and root cause descriptions.
    Rationale: bb_preflight v11's kill-gate-1 used title keyword overlap which
    missed semantically identical findings with different wording, and flagged
    different findings with overlapping keywords.

    Returns: 0=PASS (no duplicates), 1=WARN (possible duplicates found)
    """
    import json as json_module

    target = Path(target_dir)
    finding_lower = finding.lower()

    # Extract keywords from finding description
    stop_words = {"the", "a", "an", "is", "in", "on", "at", "to", "for", "of", "and", "or", "via", "by", "with"}
    finding_words = set(re.findall(r'\b[a-z]{3,}\b', finding_lower)) - stop_words

    # Extract CWE if mentioned
    cwe_match = re.search(r'cwe-(\d+)', finding_lower)
    finding_cwe = cwe_match.group(0) if cwe_match else None

    duplicates = []

    # Source 1: Previous submissions in this target
    submission_dir = target / "submission"
    if submission_dir.exists():
        for report_dir in submission_dir.iterdir():
            if not report_dir.is_dir():
                continue
            # Check bugcrowd_form.md
            form = report_dir / "bugcrowd_form.md"
            if form.exists():
                try:
                    content = form.read_text(encoding="utf-8").lower()
                    content_words = set(re.findall(r'\b[a-z]{3,}\b', content)) - stop_words
                    overlap = finding_words & content_words
                    overlap_ratio = len(overlap) / max(len(finding_words), 1)

                    if overlap_ratio > 0.5:
                        duplicates.append({
                            "source": "submission/" + report_dir.name,
                            "overlap_ratio": round(overlap_ratio, 2),
                            "matching_words": sorted(overlap)[:10]
                        })
                except Exception:
                    continue

            # Check report markdown files
            for md_file in report_dir.glob("*.md"):
                if md_file.name == "bugcrowd_form.md":
                    continue
                try:
                    content = md_file.read_text(encoding="utf-8").lower()
                    # CWE match is stronger signal
                    if finding_cwe and finding_cwe in content:
                        duplicates.append({
                            "source": "submission/" + report_dir.name + "/" + md_file.name,
                            "match_type": "CWE match",
                            "cwe": finding_cwe
                        })
                except Exception:
                    continue

    # Source 2: Triage objections (v12)
    objections_dir = Path(target_dir).parent.parent / "knowledge" / "triage_objections"
    if not objections_dir.exists():
        objections_dir = Path("knowledge/triage_objections")

    if objections_dir.exists():
        for obj_file in objections_dir.rglob("*.md"):
            try:
                content = obj_file.read_text(encoding="utf-8").lower()
                content_words = set(re.findall(r'\b[a-z]{3,}\b', content)) - stop_words
                overlap = finding_words & content_words
                overlap_ratio = len(overlap) / max(len(finding_words), 1)

                if overlap_ratio > 0.4:
                    # Check if this was a DUPLICATE rejection
                    is_dup_rejection = "duplicate" in content or "already reported" in content
                    duplicates.append({
                        "source": "triage_objections/" + obj_file.name,
                        "overlap_ratio": round(overlap_ratio, 2),
                        "was_duplicate_rejection": is_dup_rejection
                    })
            except Exception:
                continue

    # Source 3: Knowledge base bugbounty findings
    kb_dir = Path("knowledge/bugbounty")
    if kb_dir.exists():
        for kb_file in kb_dir.rglob("*.md"):
            try:
                content = kb_file.read_text(encoding="utf-8").lower()
                if finding_cwe and finding_cwe in content:
                    duplicates.append({
                        "source": "knowledge/bugbounty/" + kb_file.name,
                        "match_type": "CWE match in knowledge base",
                        "cwe": finding_cwe
                    })
            except Exception:
                continue

    has_duplicates = len(duplicates) > 0

    if json_output:
        result = {
            "finding": finding,
            "duplicates_found": len(duplicates),
            "verdict": "WARN" if has_duplicates else "PASS",
            "matches": duplicates
        }
        print(json_module.dumps(result, indent=2))
    else:
        if has_duplicates:
            print("[WARN] Possible duplicates found: {}".format(len(duplicates)))
            for dup in duplicates[:5]:  # Show top 5
                print("  →", dup.get("source", "unknown"), "| overlap:", dup.get("overlap_ratio", dup.get("match_type", "?")))
            print("  → Review these before submitting. May need differentiation argument.")
        else:
            print("[PASS] No duplicates found for:", finding[:80])

    return 1 if has_duplicates else 0

# --- Candidate Index ---
def candidate_index(targets_dir: str, json_output: bool = False) -> int:
    """Scan all targets/*/explore_candidates.md and build a global index.

    Produces knowledge/candidate_index.json with all E3/E4 candidates
    across all targets for recycling into the prove lane.
    """
    targets_path = Path(targets_dir)
    if not targets_path.is_dir():
        # If a specific target was given, go up to targets/
        targets_path = targets_path.parent
        if not targets_path.is_dir():
            print(f"FAIL: targets directory not found: {targets_path}")
            return 1

    candidates = []
    for ec_file in sorted(targets_path.glob("*/explore_candidates.md")):
        target_name = ec_file.parent.name
        if target_name.startswith("_archive"):
            continue
        text = ec_file.read_text(encoding="utf-8", errors="replace")
        if not text.strip():
            continue

        # Parse candidates from markdown — look for headers and evidence tier markers
        current = None
        for line in text.split("\n"):
            stripped = line.strip()
            if stripped.startswith("## ") or stripped.startswith("### "):
                if current and current.get("title"):
                    candidates.append(current)
                current = {
                    "target": target_name,
                    "title": stripped.lstrip("#").strip(),
                    "tier": "",
                    "status": "",
                    "file": str(ec_file),
                }
            elif current:
                low = stripped.lower()
                if "e1" in low or "e2" in low or "e3" in low or "e4" in low:
                    for tier in ["E1", "E2", "E3", "E4"]:
                        if tier.lower() in low:
                            current["tier"] = tier
                            break
                if "killed" in low or "archived" in low:
                    current["status"] = "killed"
                elif "proven" in low or "submitted" in low:
                    current["status"] = "proven"
                elif "pending" in low or "explore" in low:
                    current["status"] = "pending"
        if current and current.get("title"):
            candidates.append(current)

    # Write index
    project_root = Path(__file__).resolve().parent.parent
    index_path = project_root / "knowledge" / "candidate_index.json"
    index_path.parent.mkdir(parents=True, exist_ok=True)

    summary = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_candidates": len(candidates),
        "by_tier": {},
        "by_status": {},
        "candidates": candidates,
    }
    for c in candidates:
        tier = c.get("tier", "unknown") or "unknown"
        status = c.get("status", "unknown") or "unknown"
        summary["by_tier"][tier] = summary["by_tier"].get(tier, 0) + 1
        summary["by_status"][status] = summary["by_status"].get(status, 0) + 1

    index_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    if json_output:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        print(f"Candidate index: {len(candidates)} candidates from {len(set(c['target'] for c in candidates))} targets")
        for tier, count in sorted(summary["by_tier"].items()):
            print(f"  {tier}: {count}")
        for status, count in sorted(summary["by_status"].items()):
            print(f"  [{status}]: {count}")
        print(f"Written to: {index_path}")
    return 0


# ---------------------------------------------------------------------------
# verify_target: Phase -1 gate — unified API, platform-specific parsers
# ---------------------------------------------------------------------------
# Return codes (shared across all platforms):
#   0 = GO       (program exists with live cash bounty)
#   1 = NO-GO    HARD   (program not found / unlisted / all URL variants 404)
#   2 = NO-GO    CASH   ($0 / CVE-only — override with --cve-only)
#   3 = WARN     DUPLICATE (high duplicate/informative rate on recent submissions)
# ---------------------------------------------------------------------------

def _vt_fetch(url: str) -> tuple[int, str]:
    """Fetch a URL via r.jina.ai proxy. Returns (status_code, body).

    r.jina.ai wraps HTTP errors — it returns 200 even when the underlying page
    was 404/403/500, and embeds a "Warning: Target URL returned error N" line
    at the top of the markdown body. We detect that and normalize to the real
    HTTP code so parsers can distinguish dead pages from live ones.
    """
    import urllib.request as _urlreq
    try:
        req = _urlreq.Request(
            f"https://r.jina.ai/{url}",
            headers={"User-Agent": "terminator-verify-target/12.3"},
        )
        with _urlreq.urlopen(req, timeout=25) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            status = resp.status
    except _urlreq.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""

    # Detect Cloudflare / CAPTCHA challenge pages — r.jina.ai can't bypass these,
    # but that doesn't mean the site is dead. Return a special 599 code so parsers
    # can fall through to WARN (cannot verify) instead of HARD FAIL.
    cf_challenge_markers = [
        "Performing security verification",
        "This page maybe requiring CAPTCHA",
        "Checking your browser before accessing",
        "Just a moment...",
        "cf-challenge",
        "cf_chl_",
        "Attention Required! | Cloudflare",
    ]
    head = body[:2500]
    if any(m in head for m in cf_challenge_markers):
        return 599, body  # custom: "cannot verify — CF/CAPTCHA"

    # Detect r.jina.ai's "underlying HTTP error" banner
    # Example: "Warning: Target URL returned error 404: Not Found"
    m = re.search(r"Warning:\s*Target URL returned error\s*(\d{3})", body[:2000])
    if m:
        real_code = int(m.group(1))
        # Return the real HTTP error code with body so parsers can still inspect
        return real_code, body

    # Detect additional dead-page patterns that r.jina.ai might not flag
    dead_patterns = [
        r"^#\s*(?:huntr|bugcrowd|hackerone|intigriti|yeswehack|hackenproof)[:\s]*Page not found",
        r"^##?\s*The requested page was not found",
        r"^Title:\s*Resource not found 404",
        r"^Title:\s*(?:huntr|bugcrowd|hackerone|intigriti|yeswehack|hackenproof)[:\s]*Page not found",
        r"^Title:\s*404",
        r"HTTP ERROR 404",
    ]
    for pat in dead_patterns:
        if re.search(pat, body[:2000], re.I | re.M):
            return 404, body

    return status, body


def _vt_probe(candidates: list[str]) -> tuple[str, str, list[tuple[str, int]]]:
    """Try each candidate URL, return (canonical_url, body, probe_log).

    - 200 = live, accept
    - 599 = Cloudflare/CAPTCHA challenge, accept but body will be the challenge
            page (parsers should detect and return WARN — cannot verify)
    - 403/404/5xx = dead, reject
    """
    log = []
    for url in candidates:
        code, body = _vt_fetch(url)
        log.append((url, code))
        if code in (200, 599) and body:
            return url, body, log
    return "", "", log


def _vt_count_recent_status(body: str) -> tuple[int, int]:
    """Count recent 'duplicate' / 'informative' mentions (indicative of triager fatigue)."""
    return (
        len(re.findall(r"\bduplicate\b", body, re.I)),
        len(re.findall(r"\binformative\b", body, re.I)),
    )


def _vt_is_cf_challenge(body: str) -> bool:
    """Return True if body is a Cloudflare/CAPTCHA challenge page (not real content)."""
    head = body[:2500]
    return any(m in head for m in (
        "Performing security verification",
        "This page maybe requiring CAPTCHA",
        "Checking your browser before accessing",
        "Just a moment...",
        "Attention Required! | Cloudflare",
    ))


def _verify_huntr(target_url: str, accept_cve_only: bool) -> int:
    """huntr: owner/repo from GitHub URL, case-insensitive but scout-trap."""
    gh = re.match(r"https?://github\.com/([^/]+)/([^/?#]+)", target_url)
    if not gh:
        print(f"FAIL: huntr requires GitHub URL (got: {target_url})")
        return 1
    owner, repo = gh.group(1), gh.group(2)

    # Try both casings — scout trap: GitHub display case != huntr URL case
    variants = list(dict.fromkeys([
        f"https://huntr.com/repos/{owner}/{repo}",
        f"https://huntr.com/repos/{owner.lower()}/{repo.lower()}",
    ]))
    canonical, body, log = _vt_probe(variants)
    if not body:
        print("FAIL (HARD): huntr program not found at any case variant:")
        for u, c in log:
            print(f"  {c}  {u}")
        return 1
    print(f"huntr program resolved: {canonical}")

    # Parse LIVE active bounty from header block: "#### CRITICAL\n\n#### $N"
    bounty = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        m = re.search(rf"####\s+{sev}\s*\n+####\s+\$(\d+(?:,\d{{3}})*)", body)
        if m:
            bounty[sev.lower()] = int(m.group(1).replace(",", ""))
    if not bounty and re.search(r"\$0", body):
        bounty = {"all": 0}
    print(f"bounty (live active): {bounty}")

    if not any(v > 0 for v in bounty.values() if isinstance(v, int)):
        if not accept_cve_only:
            print("NO-GO (CASH): $0 / CVE-only")
            return 2

    dupes, info = _vt_count_recent_status(body)
    if dupes >= 3 or info >= 3:
        print(f"WARN: {dupes} duplicates / {info} informative in recent history")
        return 3

    print(f"GO: huntr target verified")
    return 0


def _verify_bugcrowd(target_url: str, accept_cve_only: bool) -> int:
    """bugcrowd: engagement URL at /engagements/<slug> or /<slug>."""
    # Accept both: https://bugcrowd.com/engagements/<slug> and https://bugcrowd.com/<slug>
    m = re.match(r"https?://bugcrowd\.com/(?:engagements/)?([^/?#]+)", target_url)
    if not m:
        print(f"FAIL: bugcrowd URL unrecognized: {target_url}")
        return 1
    slug = m.group(1)
    variants = [
        f"https://bugcrowd.com/engagements/{slug}",
        f"https://bugcrowd.com/{slug}",
    ]
    canonical, body, log = _vt_probe(variants)
    if not body:
        print("FAIL (HARD): bugcrowd program not found:")
        for u, c in log:
            print(f"  {c}  {u}")
        return 1
    print(f"bugcrowd program resolved: {canonical}")

    # Parse rewards section: look for "$X - $Y" or "up to $X" near severity labels
    bounty_found = False
    for m in re.finditer(r"\$(\d+(?:,\d{3})*)\s*(?:-\s*\$(\d+(?:,\d{3})*))?", body):
        low = int(m.group(1).replace(",", ""))
        if low > 0:
            bounty_found = True
            break

    if not bounty_found:
        if re.search(r"points only|no cash|VDP|kudos", body, re.I):
            print("NO-GO (CASH): bugcrowd program is points-only / VDP")
            return 2 if not accept_cve_only else 0
        print("WARN: no bounty amounts parsed. Possible private program or layout change.")

    dupes, info = _vt_count_recent_status(body)
    if dupes >= 5 or info >= 5:
        print(f"WARN: {dupes} duplicates / {info} informative")
        return 3

    print(f"GO: bugcrowd target verified")
    return 0


def _verify_yeswehack(target_url: str, accept_cve_only: bool) -> int:
    """yeswehack: program at /programs/<slug>"""
    m = re.match(r"https?://(?:www\.)?yeswehack\.com/programs/([^/?#]+)", target_url)
    if not m:
        print(f"FAIL: yeswehack URL must match /programs/<slug>: {target_url}")
        return 1
    slug = m.group(1)
    canonical = f"https://yeswehack.com/programs/{slug}"
    code, body = _vt_fetch(canonical)
    if code != 200 or not body:
        print(f"FAIL (HARD): yeswehack program not found ({code}): {canonical}")
        return 1
    print(f"yeswehack program resolved: {canonical}")

    # Parse reward ranges (YWH uses € or $ with severity tiers)
    bounty_found = bool(re.search(r"[€$](\d+(?:,\d{3})*)", body))
    if not bounty_found:
        if re.search(r"VDP|no reward|kudos only", body, re.I):
            print("NO-GO (CASH): yeswehack program is VDP")
            return 2 if not accept_cve_only else 0

    dupes, info = _vt_count_recent_status(body)
    if dupes >= 5 or info >= 5:
        print(f"WARN: {dupes} duplicates / {info} informative")
        return 3

    print(f"GO: yeswehack target verified")
    return 0


def _verify_intigriti(target_url: str, accept_cve_only: bool) -> int:
    """intigriti: program at /programs/<company>[/<program>]"""
    m = re.match(r"https?://(?:www\.|app\.)?intigriti\.com/programs/([^/?#]+)", target_url)
    if not m:
        print(f"FAIL: intigriti URL must match /programs/<slug>: {target_url}")
        return 1
    slug = m.group(1)
    variants = [
        f"https://www.intigriti.com/programs/{slug}",
        f"https://app.intigriti.com/programs/{slug}",
    ]
    canonical, body, log = _vt_probe(variants)
    if not body:
        print("FAIL (HARD): intigriti program not found:")
        for u, c in log:
            print(f"  {c}  {u}")
        return 1
    print(f"intigriti program resolved: {canonical}")

    bounty_found = bool(re.search(r"[€$](\d+(?:,\d{3})*)", body))
    if not bounty_found and re.search(r"no reward|point-only|kudos only", body, re.I):
        print("NO-GO (CASH): intigriti program has no cash reward")
        return 2 if not accept_cve_only else 0

    dupes, info = _vt_count_recent_status(body)
    if dupes >= 5 or info >= 5:
        print(f"WARN: {dupes} duplicates / {info} informative")
        return 3

    print(f"GO: intigriti target verified")
    return 0


def _verify_immunefi(target_url: str, accept_cve_only: bool) -> int:
    """immunefi: program at /bug-bounty/<project>[/information]"""
    m = re.match(r"https?://immunefi\.com/(?:bug-bounty|bounty)/([^/?#]+)", target_url)
    if not m:
        print(f"FAIL: immunefi URL must match /bug-bounty/<project>: {target_url}")
        return 1
    slug = m.group(1)
    variants = [
        f"https://immunefi.com/bug-bounty/{slug}/information",
        f"https://immunefi.com/bug-bounty/{slug}",
        f"https://immunefi.com/bounty/{slug}",
    ]
    canonical, body, log = _vt_probe(variants)
    if not body:
        print("FAIL (HARD): immunefi program not found:")
        for u, c in log:
            print(f"  {c}  {u}")
        return 1
    print(f"immunefi program resolved: {canonical}")

    # Immunefi: look for "$X up to $Y" or CVSS tier table with $ amounts
    bounty_found = bool(re.search(r"up to\s*\$(\d+(?:,\d{3})*)", body, re.I))
    if not bounty_found:
        bounty_found = bool(re.search(r"Critical[\s\S]{0,300}\$(\d+(?:,\d{3})*)", body))
    if not bounty_found:
        print("WARN: no bounty amounts parsed from immunefi page")

    # Immunefi-specific: paused programs show an explicit status banner.
    # Narrow regex to avoid false positives on help-text/doc mentions of the word "paused".
    paused_patterns = [
        r"Status[:\s]+Paused",
        r"Program\s+status[:\s]+Paused",
        r"This program is (?:currently )?paused",
        r"Program PAUSED",
        r"Bounty paused",
        r"bounty program is paused",
    ]
    for p in paused_patterns:
        if re.search(p, body, re.I):
            print(f"WARN: immunefi program appears PAUSED (matched: {p})")
            return 3

    dupes, info = _vt_count_recent_status(body)
    if dupes >= 5 or info >= 5:
        print(f"WARN: {dupes} duplicates / {info} informative")
        return 3

    print(f"GO: immunefi target verified")
    return 0


def _verify_hackenproof(target_url: str, accept_cve_only: bool) -> int:
    """hackenproof: program at /programs/<slug>"""
    m = re.match(r"https?://hackenproof\.com/(?:programs|projects)/([^/?#]+)", target_url)
    if not m:
        print(f"FAIL: hackenproof URL must match /programs/<slug>: {target_url}")
        return 1
    slug = m.group(1)
    variants = [
        f"https://hackenproof.com/programs/{slug}",
        f"https://hackenproof.com/projects/{slug}",
    ]
    canonical, body, log = _vt_probe(variants)
    if not body:
        print("FAIL (HARD): hackenproof program not found:")
        for u, c in log:
            print(f"  {c}  {u}")
        return 1
    print(f"hackenproof program resolved: {canonical}")

    if _vt_is_cf_challenge(body):
        print("WARN: hackenproof behind Cloudflare — cannot verify via proxy.")
        print("       Manual check required: visit the URL in a real browser.")
        return 0  # accept as GO — Cloudflare challenge = page probably exists

    bounty_found = bool(re.search(r"\$(\d+(?:,\d{3})*)", body))
    if not bounty_found and re.search(r"VDP|no reward", body, re.I):
        print("NO-GO (CASH): hackenproof program has no cash reward")
        return 2 if not accept_cve_only else 0

    dupes, info = _vt_count_recent_status(body)
    if dupes >= 5 or info >= 5:
        print(f"WARN: {dupes} duplicates / {info} informative")
        return 3

    print(f"GO: hackenproof target verified")
    return 0


def _verify_generic(target_url: str, accept_cve_only: bool, platform_key: str = "") -> int:
    """
    Generic fallback: probe the URL, detect live/dead, basic bounty signal extraction.
    Used for platforms without a dedicated _verify_<platform> parser. Returns:
      0 = GO (URL resolves, no NO-GO signal)
      1 = HARD NO-GO (URL dead on all variants)
      2 = NO-GO CASH (clear "$0" or "no reward" signal)
      3 = WARN (live but unverified parser precision — recommend custom parser)
    """
    import urllib.parse as _up

    # Load platforms.json to resolve URL from platform key if target_url not given
    if platform_key and not target_url:
        pf = Path(__file__).parent / "platforms.json"
        if pf.exists():
            with pf.open() as f:
                d = json.load(f)
            entry = d.get("platforms", {}).get(platform_key, {})
            target_url = entry.get("url", "")

    if not target_url:
        print(f"FAIL: no URL to probe for platform '{platform_key}'")
        return 1

    # Try the URL as-is, and with www. prefix fallback
    parsed = _up.urlparse(target_url)
    variants = [target_url]
    if parsed.hostname and not parsed.hostname.startswith("www."):
        variants.append(target_url.replace(parsed.hostname, f"www.{parsed.hostname}", 1))

    canonical = ""
    body = ""
    probe_log = []
    for url in variants:
        code, b = _vt_fetch(url)
        probe_log.append((url, code))
        if code in (200, 403):  # 403 = bot-blocked but live
            canonical = url
            body = b
            break

    if not canonical:
        print(f"FAIL (HARD): generic probe — no live URL variant for {platform_key}:")
        for u, c in probe_log:
            print(f"  {c}  {u}")
        return 1

    print(f"generic probe resolved: {canonical}")

    # NO-GO CASH signals (platform explicitly no-cash)
    cash_signals_negative = [
        r"\$0\b",
        r"\bcve[\s-]only\b",
        r"\bno cash\b",
        r"\bvdp only\b",
        r"\bvulnerability disclosure only\b",
        r"\brecognition[- ]only\b",
        r"\bhall of fame\b",
        r"\bpoint[s]?[- ]only\b",
    ]
    for pat in cash_signals_negative:
        if re.search(pat, body, re.I):
            if not accept_cve_only:
                print(f"NO-GO (CASH): generic probe detected '{pat}' — non-cash program")
                return 2

    # Duplicate/informative frequency (same heuristic as specialized parsers)
    dupes, info = _vt_count_recent_status(body)
    if dupes >= 5 or info >= 5:
        print(f"WARN: {dupes} duplicates / {info} informative (generic parser)")
        return 3

    print(f"WARN (generic): live but no specialized parser — custom _verify_{platform_key} recommended for precision")
    return 3  # always WARN for generic — reminds to implement custom parser


_VERIFY_DISPATCH = {
    "huntr": _verify_huntr,
    "bugcrowd": _verify_bugcrowd,
    "yeswehack": _verify_yeswehack,
    "ywh": _verify_yeswehack,
    "intigriti": _verify_intigriti,
    "immunefi": _verify_immunefi,
    "hackenproof": _verify_hackenproof,
}


def verify_target(platform: str, target_url: str, accept_cve_only: bool = False) -> int:
    """
    Phase -1 gate: verify a target is worth analyzing BEFORE spawning any agent.

    Dispatches to platform-specific parser for supported platforms. For platforms
    without a dedicated parser, falls back to _verify_generic which probes the URL
    and checks for obvious live/dead/no-cash signals.

    The generic fallback ALWAYS returns WARN (exit 3) even on success — this is
    intentional to remind developers that a custom parser is more precise and
    should eventually be implemented (v12.3 IRON RULE).
    """
    platform = platform.lower().strip()
    target_url = target_url.strip().rstrip("/")

    handler = _VERIFY_DISPATCH.get(platform)
    if handler is not None:
        return handler(target_url, accept_cve_only)

    # Generic fallback — works for all 88+ platforms in platforms.json
    print(f"verify-target: no custom parser for '{platform}', using generic fallback")
    print(f"  (supported with custom parser: {sorted(_VERIFY_DISPATCH.keys())})")
    return _verify_generic(target_url, accept_cve_only, platform)


def fetch_program(
    target_dir: str,
    program_url: str,
    *,
    use_cache: bool = True,
    hold_ok: bool = False,
    json_output: bool = False,
) -> int:
    """Phase 0.1: fetch a program page verbatim and auto-fill rules.

    Dispatches to tools.program_fetcher which runs platform-specific handlers
    (HackerOne GraphQL, Bugcrowd target_groups.json, Immunefi __NEXT_DATA__,
    Intigriti/YWH/HackenProof APIs, huntr/github_md scrapers, generic jina
    fallback) to produce a structured ProgramData.

    Writes into target_dir:
        - program_data.json     (structured)
        - program_page_raw.md   (verbatim)
        - fetch_meta.json       (handler trace + confidence)
        - program_rules_summary.md  (verbatim sections patched in)

    Operational sections (Auth Header Format, Mandatory Headers, Verified
    Curl Template) are intentionally LEFT as <REQUIRED> placeholders — those
    still need live traffic verification by scout/web-tester.

    Exit codes:
        0 = PASS (verbatim sections auto-filled)
        1 = FAIL (no handler succeeded / page unreachable)
        2 = HOLD (confidence below 0.8; artifacts still written)

    --hold-ok makes HOLD return exit 0 so callers that want best-effort
    intake (Phase 5.7 live scope re-check) can skip the manual review loop.
    """
    try:
        from tools.program_fetcher import fetch as pf_fetch
        from tools.program_fetcher.render import render_to_target, write_artifacts
        from tools.program_fetcher.base import PASS, HOLD, FAIL
    except ImportError as e:
        print(f"FAIL: program_fetcher import failed: {e}")
        return 1

    tdir = Path(target_dir)
    tdir.mkdir(parents=True, exist_ok=True)

    cache_dir = str(tdir / ".cache" / "program_fetch") if use_cache else ""
    try:
        result = pf_fetch(program_url, use_cache=use_cache, cache_dir=cache_dir)
    except Exception as e:
        print(f"FAIL: fetch raised {type(e).__name__}: {e}")
        return 1

    # Always write artifacts — even on HOLD, having the raw page helps the
    # operator verify manually. Only skip on catastrophic FAIL.
    if result.verdict != FAIL:
        write_artifacts(result, tdir)
        render_to_target(result.data, tdir)

    # Record into checkpoint.json if present.
    ckpt_path = tdir / "checkpoint.json"
    if ckpt_path.exists():
        try:
            ckpt = json.loads(ckpt_path.read_text())
            ckpt.setdefault("program_fetch", {})
            ckpt["program_fetch"] = {
                "url": program_url,
                "verdict": result.verdict,
                "confidence": result.confidence,
                "handler": result.data.source,
                "fetched_at": result.data.fetched_at,
            }
            ckpt_path.write_text(json.dumps(ckpt, indent=2, ensure_ascii=False))
        except (OSError, json.JSONDecodeError):
            pass

    if json_output:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))

    if result.verdict == PASS:
        print(
            f"PASS: {result.data.platform} {result.data.handle} "
            f"conf={result.confidence:.2f} handler={result.data.source}"
        )
        print(f"  → artifacts in {tdir}/ (program_data.json, program_page_raw.md, program_rules_summary.md)")
        print(f"  → Phase 0.2: verify auto-filled verbatim sections, then fill operational sections from live traffic")
        return 0

    if result.verdict == HOLD:
        missing = ", ".join(result.missing_fields) or "unknown"
        print(
            f"HOLD: {result.data.platform} {result.data.handle} "
            f"conf={result.confidence:.2f} handler={result.data.source}"
        )
        print(f"  → missing/thin: {missing}")
        print(f"  → artifacts still written to {tdir}/ for manual review")
        print(f"  → rerun with --hold-ok to accept, or supplement by hand from the live page")
        if hold_ok:
            return 0
        return 2

    # FAIL
    handler_log = ", ".join(
        f"{h.get('handler')}={h.get('status')}" for h in result.handlers_tried
    )
    print(f"FAIL: {result.error or 'no handler succeeded'}")
    print(f"  → handlers tried: {handler_log}")
    print(f"  → Fall back to manual program_rules_summary.md fill from the live page")
    return 1


def strengthening_check(submission_dir: str) -> int:
    """
    v12.3 — LiteLLM cross-user exfil lesson:
    Verify strengthening_report.md exists and all checklist items have explicit status.

    Called by kill-gate-2 pre-check AND by Phase 5.5b pre-submission final check.

    Returns:
        0 = PASS (all items ATTEMPTED/NOT_APPLICABLE/INFEASIBLE, no NOT_ATTEMPTED)
        1 = FAIL (missing file, missing items, or any NOT_ATTEMPTED)
        2 = WARN (rushed: delta_minutes < 30 with non-NOT_APPLICABLE items)
    """
    sub_dir = Path(submission_dir)
    if not sub_dir.exists():
        print(f"FAIL: submission directory not found: {submission_dir}")
        return 1

    report_path = sub_dir / "strengthening_report.md"
    if not report_path.exists():
        print(f"FAIL (HARD): strengthening_report.md missing in {submission_dir}")
        print("  → Phase 2 MUST produce this file before Gate 2.")
        print("  → Required sections: Timestamps, 5 checklist items, Verdict")
        print("  → Template: see bb_pipeline_v12.md Phase 2 Strengthening Report section")
        return 1

    content = report_path.read_text()

    # Required checklist items (must all be present)
    required_items = [
        "Cross-user",
        "Two-step",
        "E2 → E1",
        "Variant hunt",
        "Static source quote",
    ]
    missing_items = [item for item in required_items if item not in content]
    if missing_items:
        print(f"FAIL: strengthening_report.md missing checklist items: {missing_items}")
        return 1

    # Parse status for each item
    # Pattern: each "### <N>. <title>" followed by "- Status: <value>"
    import re as _re
    item_statuses = _re.findall(r"###\s+\d+\..*?\n\s*-\s*Status:\s*([A-Z_]+)", content)
    if len(item_statuses) < 5:
        print(f"FAIL: strengthening_report.md only has {len(item_statuses)}/5 status entries")
        print(f"  → Found: {item_statuses}")
        print("  → Each checklist item needs explicit '- Status: ATTEMPTED|NOT_APPLICABLE|INFEASIBLE'")
        return 1

    valid_statuses = {"ATTEMPTED", "NOT_APPLICABLE", "INFEASIBLE"}
    invalid = [s for s in item_statuses if s not in valid_statuses]
    if invalid:
        print(f"FAIL: invalid status values: {invalid}")
        print(f"  → Must be one of: {sorted(valid_statuses)}")
        return 1

    # HARD FAIL: NOT_ATTEMPTED is not a valid status — it means the item wasn't even considered
    # (this is the most common violation when the agent rushes to Gate 2)
    if "NOT_ATTEMPTED" in item_statuses:
        print(f"FAIL (HARD): NOT_ATTEMPTED found in strengthening_report.md")
        print(f"  → Every item must have explicit status (ATTEMPTED/NOT_APPLICABLE/INFEASIBLE)")
        print(f"  → Item status is how you RECORD that you considered it — you cannot skip any")
        return 1

    # Parse timestamps to detect rush
    ts_match = _re.search(r"delta_minutes:\s*(\d+(?:\.\d+)?)", content)
    if not ts_match:
        print("FAIL: strengthening_report.md missing 'delta_minutes' in Timestamps section")
        return 1
    delta = float(ts_match.group(1))

    attempted_count = item_statuses.count("ATTEMPTED")
    print(f"Strengthening Report Analysis:")
    print(f"  Items: {len(item_statuses)}")
    for i, status in enumerate(item_statuses, 1):
        print(f"    {i}. {status}")
    print(f"  delta_minutes: {delta}")
    print(f"  ATTEMPTED count: {attempted_count}")

    # WARN if rushed
    if delta < 30 and attempted_count > 0:
        # Rushed = Phase 2 → Gate 2 transition under 30 minutes with actual work done
        # This usually means agent skipped real strengthening
        print(f"WARN: Phase 2 → Gate 2 delta = {delta}min (< 30min threshold)")
        print(f"  → Rushed transition detected. Verify strengthening was genuine.")
        return 2

    print(f"PASS: strengthening_report.md validated")
    return 0
# --- Main ---

def _parse_domain(argv: list) -> str:
    """Extract --domain value from argv. Returns 'bounty' if not specified."""
    if "--domain" in argv:
        idx = argv.index("--domain")
        if idx + 1 < len(argv):
            return argv[idx + 1]
    return "bounty"


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    target = sys.argv[2]
    domain = _parse_domain(sys.argv)

    if cmd == "init":
        sys.exit(init(target, domain))
    elif cmd == "fetch-program":
        # Usage: fetch-program <target_dir> <program_url> [--no-cache] [--hold-ok] [--json]
        if len(sys.argv) < 4:
            print("Usage: bb_preflight.py fetch-program <target_dir> <program_url> [--no-cache] [--hold-ok] [--json]")
            sys.exit(1)
        program_url = sys.argv[3]
        no_cache = "--no-cache" in sys.argv
        hold_ok_flag = "--hold-ok" in sys.argv
        json_flag = "--json" in sys.argv
        sys.exit(
            fetch_program(
                target,
                program_url,
                use_cache=not no_cache,
                hold_ok=hold_ok_flag,
                json_output=json_flag,
            )
        )
    elif cmd == "rules-check":
        sys.exit(rules_check(target, domain))
    elif cmd == "coverage-check":
        threshold = None
        json_out = False
        for arg in sys.argv[3:]:
            if arg == "--json":
                json_out = True
            elif arg in ("--domain",) or arg == domain:
                continue  # skip --domain and its value
            else:
                try:
                    threshold = int(arg)
                except ValueError:
                    pass
        sys.exit(coverage_check(target, threshold, json_out, domain))
    elif cmd == "inject-rules":
        sys.exit(inject_rules(target))
    elif cmd == "exclusion-filter":
        sys.exit(exclusion_filter(target))
    elif cmd == "kill-gate-1":
        finding = ""
        severity = ""
        impact = ""
        args = sys.argv[3:]
        for i, arg in enumerate(args):
            if arg == "--finding" and i + 1 < len(args):
                finding = args[i + 1]
            elif arg == "--severity" and i + 1 < len(args):
                severity = args[i + 1]
            elif arg == "--impact" and i + 1 < len(args):
                impact = args[i + 1]
        if not finding:
            print("FAIL: kill-gate-1 requires --finding \"<description>\"")
            sys.exit(1)
        if not severity:
            print("FAIL: kill-gate-1 requires --severity <critical|high|medium|low> (MANDATORY since v12.3)")
            sys.exit(1)
        sys.exit(kill_gate_1(target, finding, severity, impact))
    elif cmd == "kill-gate-2":
        ret = kill_gate_2(target)
        sys.exit(ret)
    elif cmd == "workflow-check":
        if len(sys.argv) < 3:
            print("Usage: bb_preflight.py workflow-check <target_dir>")
            sys.exit(1)
        sys.exit(workflow_check(sys.argv[2]))
    elif cmd == "fresh-surface-check":
        repo_path = None
        if "--repo" in sys.argv:
            repo_idx = sys.argv.index("--repo")
            if repo_idx + 1 < len(sys.argv):
                repo_path = sys.argv[repo_idx + 1]
        sys.exit(fresh_surface_check(sys.argv[2], repo_path))
    elif cmd == "evidence-tier-check":
        json_flag = "--json" in sys.argv
        sys.exit(evidence_tier_check(sys.argv[2], json_flag))
    elif cmd == "duplicate-graph-check":
        if "--finding" not in sys.argv:
            print("Usage: bb_preflight.py duplicate-graph-check <target_dir> --finding \"<desc>\" [--json]")
            sys.exit(1)
        finding_idx = sys.argv.index("--finding")
        finding_desc = sys.argv[finding_idx + 1] if finding_idx + 1 < len(sys.argv) else ""
        json_flag = "--json" in sys.argv
        sys.exit(duplicate_graph_check(sys.argv[2], finding_desc, json_flag))
    elif cmd == "candidate-index":
        json_flag = "--json" in sys.argv
        sys.exit(candidate_index(sys.argv[2], json_flag))
    elif cmd == "strengthening-check":
        sys.exit(strengthening_check(sys.argv[2]))
    elif cmd == "verify-target":
        # Usage: verify-target <platform> <target_url> [--cve-only]
        if len(sys.argv) < 4:
            print("Usage: bb_preflight.py verify-target <platform> <target_url> [--cve-only]")
            sys.exit(1)
        platform_arg = sys.argv[2]
        target_arg = sys.argv[3]
        cve_opt_in = "--cve-only" in sys.argv
        sys.exit(verify_target(platform_arg, target_arg, cve_opt_in))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
