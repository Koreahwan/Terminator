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
                                                       v14: also writes program_raw/bundle.md via raw_bundle layer
    bb_preflight.py rules-check <target_dir>           Validate program_rules_summary.md
    bb_preflight.py verbatim-check <target_dir> [--warn] [--json]  (v14) Verify every VERBATIM section bullet
                                                       exists as substring in program_raw/bundle.md. HARD FAIL by default;
                                                       --warn downgrades to exit 2. Prevents Port-of-Antwerp-class OOS leakage.
    bb_preflight.py historical-match <target_dir> [--finding "<>"] [--vuln-type "<>"] [--program "<>"] [--platform "<>"] [--json]
                                                       (v13.7) Query knowledge/accepted_reports.db for same-program
                                                       same-vuln-class reject history. Advisory for kill-gate-1 calibration.
    bb_preflight.py coverage-check <target_dir> [THR] [--json]  Check risk-weighted endpoint coverage %
    bb_preflight.py inject-rules <target_dir>          Output compact rules for HANDOFF
    bb_preflight.py exclusion-filter <target_dir>      Output exclusion list for analyst
    bb_preflight.py kill-gate-1 <target_dir> --finding "<desc>" --severity <sev> [--impact "<claimed>"]  Pre-validate finding viability
                                                       (v12.5: info-disc + verbose-OOS collision → HARD_KILL unless --impact cites sensitivity anchor)
    bb_preflight.py kill-gate-2 <submission_dir>       Pre-validate PoC/evidence quality (includes evidence-tier enforcement)
    bb_preflight.py workflow-check <target_dir>        Validate workflow_map.md semantic completeness (v12)
    bb_preflight.py fresh-surface-check <target_dir> [--repo <path>]  Check for fresh attack surface (v12)
    bb_preflight.py evidence-tier-check <submission_dir> [--json]     Classify evidence E1-E4 tier (v12)
    bb_preflight.py duplicate-graph-check <target_dir> --finding "<desc>" [--json]  Graph-assisted duplicate detection with heuristic fallback (v12)

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
import ast
import json
import shutil
import time
from pathlib import Path
from datetime import datetime

# v14 self-contained PYTHONPATH: ensure `import tools.program_fetcher...`
# resolves when bb_preflight.py is invoked as a script from any cwd.
# Previously required callers to export PYTHONPATH=<repo_root>.
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

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
RISK_WEIGHTS = {"HIGH": 2, "MEDIUM": 1, "LOW": 1}
WORKFLOW_ATTACK_CLASS_PATTERNS = {
    "skip-step": r"\bskip[- ]step\b",
    "replay": r"\breplay\b",
    "race condition": r"\brace condition\b",
    "state reversal": r"\bstate reversal\b",
    "partial-failure": r"\bpartial[- ]failure\b",
}


def _validate_workflow_section(section_text: str) -> list[str]:
    """Return semantic validation issues for a single workflow section."""
    section_lower = section_text.lower()
    state_nodes = re.findall(r"\[[^\]]+\]", section_text)
    has_state_diagram = "state diagram" in section_lower or len(state_nodes) >= 2
    has_state_parameters = "state parameters" in section_lower
    has_entry = "entry point" in section_lower or "entry state" in section_lower or has_state_diagram
    has_terminal = "terminal" in section_lower or len(state_nodes) >= 2 or has_state_parameters
    has_reversible = "reversible" in section_lower
    has_rollback = "rollback" in section_lower or has_reversible
    has_anomaly_flags = "anomaly flags" in section_lower or "expected anomalies" in section_lower
    has_transitions = (
        "### transitions" in section_lower
        or re.search(r"\|\s*from\s*\|\s*to\s*\|", section_lower) is not None
        or "→" in section_text
        or "->" in section_text
    )
    attack_classes_found = [
        name for name, pattern in WORKFLOW_ATTACK_CLASS_PATTERNS.items()
        if re.search(pattern, section_lower)
    ]
    has_attack_analysis = (
        "5-class attack analysis" in section_lower
        or len(attack_classes_found) == len(WORKFLOW_ATTACK_CLASS_PATTERNS)
        or has_anomaly_flags
    )

    issues = []
    if not has_entry:
        issues.append("No entry point/state found")
    if not has_terminal:
        issues.append("No terminal/state-outcome coverage found")
    if not (has_rollback or has_anomaly_flags or has_state_parameters):
        issues.append("No rollback, reversibility, or anomaly coverage found")
    if not has_transitions:
        issues.append("No transitions found (expected state → state patterns)")
    if not has_attack_analysis:
        issues.append("No explicit attack-analysis section found")
    if not has_anomaly_flags and len(attack_classes_found) != len(WORKFLOW_ATTACK_CLASS_PATTERNS):
        missing = sorted(set(WORKFLOW_ATTACK_CLASS_PATTERNS) - set(attack_classes_found))
        issues.append("Missing attack classes: {}".format(", ".join(missing)))
    return issues

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


def verbatim_check(
    target_dir: str,
    *,
    strict: bool = True,
    json_output: bool = False,
) -> int:
    """v14: verify every bullet line of program_rules_summary.md's VERBATIM
    sections exists as a substring in program_raw/bundle.md.

    Catches Port-of-Antwerp-class OOS sandbox sites: handler summarised the
    OOS list and dropped "verbose messages without sensitive info" — the
    exact line never existed in any artefact before Phase 2. Now verbatim
    sections become a PROVABLE derivative of bundle.md, or fail the gate.

    Exit codes:
      0 PASS  — every verbatim bullet found in bundle.md
      1 FAIL  — at least one bullet missing (strict mode, default)
      2 WARN  — bullets missing but strict=False
      3 ERROR — bundle.md missing or rules_summary missing

    Normalisation before substring match:
      - bullet prefix stripped (`- `, `* `, `+ `, `• `, `1. `, `1) `)
      - backticks stripped (so `foo.bar` matches foo.bar)
      - whitespace collapsed
      - case-insensitive
      - anchor-style markdown links `[text](url)` collapse to `text url`
    """
    import json as _json

    target = Path(target_dir)
    rules_path = target / "program_rules_summary.md"
    bundle_path = target / "program_raw" / "bundle.md"

    if not rules_path.exists():
        msg = f"ERROR: {rules_path} not found — run bb_preflight.py init first"
        if json_output:
            print(_json.dumps({"verdict": "ERROR", "exit_code": 3, "message": msg}))
        else:
            print(msg)
        return 3

    if not bundle_path.exists():
        msg = (
            f"ERROR: {bundle_path} not found.\n"
            f"  → Run: python3 -m tools.program_fetcher <program_url> --out {target}\n"
            f"  → v14 raw-bundle capture must run before verbatim-check."
        )
        if json_output:
            print(_json.dumps({"verdict": "ERROR", "exit_code": 3, "message": msg}))
        else:
            print(msg)
        return 3

    rules_text = rules_path.read_text(encoding="utf-8")
    bundle_text = bundle_path.read_text(encoding="utf-8")

    # Sections whose bullets are verbatim claims about the program page.
    # v14 (2026-04-18 codex review P2): Submission Rules included — previously
    # paraphrased mandatory-headers / safe-harbour wording would slip past.
    VERBATIM_HEADINGS = [
        "Out-of-Scope / Exclusion List",
        "In-Scope Assets",
        "Known Issues",
        "Severity Scope",
        "Asset Scope Constraints",
        "Submission Rules",
    ]

    def _normalise(s: str) -> str:
        """Collapse markdown bullet / backticks / whitespace; lowercase.

        v14 (2026-04-18 codex review P2): JSON string bodies in bundle.md
        keep their escape sequences (\\" \\n \\t), so rules summaries that
        paste the raw text won't substring-match. Unescape a conservative
        subset before normalising.
        """
        s = s.strip()
        # Markdown link: [text](url) → "text url"
        s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 \2", s)
        # Strip bullet prefixes (one pass).
        s = re.sub(r"^(?:[-+•*]|\d+[.)])\s+", "", s)
        # JSON-escape unescape (\" → ", \\n → space, etc.)
        s = s.replace('\\"', '"').replace("\\'", "'")
        s = re.sub(r"\\[ntr]", " ", s)
        # Strip backticks.
        s = s.replace("`", "")
        # Strip bold/italic markers.
        s = re.sub(r"\*\*|__|_|\*", "", s)
        # Quote character normalisation (curly vs straight, JSON escaped).
        s = s.replace("\u201c", '"').replace("\u201d", '"')
        s = s.replace("\u2018", "'").replace("\u2019", "'")
        # Whitespace collapse.
        s = re.sub(r"\s+", " ", s)
        return s.strip().lower()

    bundle_norm = _normalise(bundle_text)

    missing: list[dict] = []
    checked = 0
    for heading in VERBATIM_HEADINGS:
        pattern = re.compile(
            rf"^##\s*{re.escape(heading)}[^\n]*\n(.*?)(?=\n##|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        m = pattern.search(rules_text)
        if not m:
            continue
        section_body = m.group(1)
        # Extract bullet lines only — prose paragraphs are intentionally skipped
        # because Intigriti-style handlers prepend "(prose) " themselves.
        for raw_line in section_body.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            # Skip section sub-headings / instructions.
            if line.startswith(("##", "###", "<!--", "<REQUIRED")):
                continue
            # Skip bullets that are purely a placeholder.
            if re.match(r"^(?:[-+•*]|\d+[.)])\s*(TODO|REQUIRED|FILL|PLACEHOLDER|TBD|none|NOTE|FIXME)\b", line, re.IGNORECASE):
                continue
            # Skip fetcher self-disclosure notes (renderer adds these when a
            # field couldn't be auto-detected — they're not verbatim claims).
            if re.search(r"fetcher did not detect|verify against the live", line, re.IGNORECASE):
                continue
            # Accept bullet / numbered items — prose is meta-commentary.
            # v14 (2026-04-18 codex review P2): also accept markdown table
            # rows (|cell|cell|) when the section is Severity Scope, since
            # render.py renders the severity matrix as a pipe-table and
            # skipping it left `checked == 0` for the whole section.
            is_bullet = bool(re.match(r"^(?:[-+•*]|\d+[.)])\s+", line))
            is_table_row = (
                heading in ("Severity Scope", "Asset Scope Constraints")
                and line.startswith("|")
                and line.count("|") >= 2
                # Skip divider rows like |---|---|
                and not re.match(r"^\|[\s|:\-]+\|\s*$", line)
                # Skip header row by heuristic (all cells short / bold-ish)
                and not re.match(r"^\|\s*(?:Severity|Asset class|Reward|Notes|Asset|Tier|Range)\s*\|", line, re.IGNORECASE)
            )
            if not (is_bullet or is_table_row):
                continue
            normalised = _normalise(line)
            # Too-short fragments can false-match. Enforce min 6 chars after
            # normalisation.
            if len(normalised) < 6:
                continue
            checked += 1

            # Strategy 1: full normalised line match. Works for true-verbatim
            # OOS bullets copied straight from the program page.
            if normalised in bundle_norm:
                continue

            # Strategy 2: token-level match. Renderer often adds metadata
            # suffix to In-Scope Assets (`- \`www.qwant.com\` (url) — Web app`).
            # Extract backtick-quoted identifiers AND the first url-ish token;
            # PASS if any of them is present in bundle_norm.
            tokens = set()
            for btok in re.findall(r"`([^`]+)`", line):
                tokens.add(btok.strip().lower())
            # URL-shaped tokens (domains, paths, wildcards).
            for utok in re.findall(r"[A-Za-z0-9][A-Za-z0-9._*-]+\.[A-Za-z]{2,}(?:/\S*)?", line):
                tokens.add(utok.lower())
            # 0xAddress smart-contract tokens.
            for atok in re.findall(r"0x[a-fA-F0-9]{40}", line):
                tokens.add(atok.lower())
            # v14 (2026-04-18 codex review P2): monetary reward tokens for
            # Severity Scope table rows (€100, $5,000, etc).
            for mtok in re.findall(r"[€$£¥]\s?\d[\d,.]*", line):
                tokens.add(re.sub(r"\s+", "", mtok.lower()))
            # Severity label tokens.
            for ltok in re.findall(r"\b(?:critical|high|medium|low|informational|info)\b", line, re.IGNORECASE):
                tokens.add(ltok.lower())
            if tokens and any(t in bundle_norm for t in tokens if len(t) >= 3):
                continue

            missing.append({
                "section": heading,
                "line": line,
                "normalised": normalised,
                "tokens_tried": sorted(tokens),
            })

    if not missing:
        msg = f"PASS: all {checked} verbatim bullets found in program_raw/bundle.md"
        if json_output:
            print(_json.dumps({
                "verdict": "PASS",
                "exit_code": 0,
                "checked": checked,
                "missing": [],
            }))
        else:
            print(msg)
        return 0

    verdict = "FAIL" if strict else "WARN"
    exit_code = 1 if strict else 2
    if json_output:
        print(_json.dumps({
            "verdict": verdict,
            "exit_code": exit_code,
            "checked": checked,
            "missing": missing,
            "message": (
                f"{len(missing)}/{checked} verbatim bullets NOT found in bundle.md — "
                "summarisation leakage detected"
            ),
        }, indent=2))
    else:
        print(f"{verdict} (HARD): {len(missing)}/{checked} verbatim bullets missing from "
              f"program_raw/bundle.md — summarisation leakage detected")
        for item in missing[:20]:
            print(f"  - [{item['section']}] {item['line']}")
        if len(missing) > 20:
            print(f"  … {len(missing) - 20} more missing lines (see --json)")
        print("  → Summary says these lines are verbatim from the program page,")
        print("    but bundle.md does not contain them. Re-run fetch-program")
        print("    or paste verbatim from the live page. This is Port-of-Antwerp-class risk.")
    return exit_code


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

    content = map_path.read_text(encoding="utf-8")
    lines = content.split("\n")

    statuses = {"UNTESTED": 0, "TESTED": 0, "VULN": 0, "SAFE": 0, "EXCLUDED": 0}
    untested_endpoints = []
    total = 0
    weighted_testable = 0
    weighted_tested = 0

    def _table_cells(line: str) -> list[str]:
        stripped = line.strip()
        if "|" not in stripped:
            return []
        return [c.strip() for c in stripped.strip("|").split("|")]

    def _normalise_status(raw_status: str) -> str | None:
        cleaned = raw_status.upper().strip()
        for known in statuses:
            if cleaned.startswith(known):
                return known
        return None

    def _normalise_risk(raw_risk: str) -> str:
        cleaned = raw_risk.upper()
        for risk in RISK_WEIGHTS:
            if risk in cleaned:
                return risk
        return "MEDIUM"

    # Find Status/Risk column indices from the header row.
    endpoint_col = None
    status_col = None
    risk_col = None
    for line in lines:
        hcells = _table_cells(line)
        upper_cells = [c.upper() for c in hcells]
        if "STATUS" in upper_cells and "ENDPOINT" in upper_cells:
            endpoint_col = upper_cells.index("ENDPOINT")
            status_col = upper_cells.index("STATUS")
            risk_col = upper_cells.index("RISK") if "RISK" in upper_cells else None
            break
    if status_col is None:
        endpoint_col = 0
        status_col = 3  # Default stripped row: Endpoint | Method | Auth | Status | Notes

    for line in lines:
        cells = _table_cells(line)
        if not cells:
            continue
        if len(cells) <= status_col:
            continue
        # Skip header, separator, empty rows
        endpoint = cells[endpoint_col] if endpoint_col is not None and len(cells) > endpoint_col else ""
        if endpoint in ("", "Endpoint", "---") or endpoint.startswith("-"):
            continue
        if set(endpoint) <= {"-", " "}:
            continue

        status = _normalise_status(cells[status_col])
        if status in statuses:
            statuses[status] += 1
            total += 1
            if status == "UNTESTED":
                untested_endpoints.append(endpoint)
            if status != "EXCLUDED":
                risk_value = cells[risk_col] if risk_col is not None and len(cells) > risk_col else ""
                weight = RISK_WEIGHTS[_normalise_risk(risk_value)]
                weighted_testable += weight
                if status in {"TESTED", "VULN", "SAFE"}:
                    weighted_tested += weight

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
    coverage = (weighted_tested / weighted_testable) * 100

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
            "weighted_testable": weighted_testable,
            "weighted_tested": weighted_tested,
            "risk_weighting_active": risk_col is not None,
            "statuses": statuses,
            "untested_endpoints": untested_endpoints,
            "small_target_override": testable < 10,
        }))
    else:
        print(
            f"Coverage: {coverage:.1f}% "
            f"(weighted {weighted_tested}/{weighted_testable}; raw {tested}/{testable} endpoints)"
        )
        print(f"  VULN={statuses['VULN']} SAFE={statuses['SAFE']} "
              f"TESTED={statuses['TESTED']} UNTESTED={statuses['UNTESTED']} "
              f"EXCLUDED={statuses['EXCLUDED']}")
        if risk_col is None:
            print("  (Risk column absent → all testable endpoints counted as 1x)")
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

# v13: Semantic OOS Checks 6-10 (2026-04-17) — cover G02/G03/G04/G08/G14 gaps.

# Check 6 — Ambiguous OOS keyword semantic (G02, G05, G13)
# "Site vulnerabilities" / "hypothetical flaw" / broad catch-all clauses have zero
# ≥4-char token overlap with standard vuln class names; Check 3 never fires on them.
_AMBIGUOUS_OOS_PATTERNS = (
    # "Site vulnerabilities" — DataDome catch-all for web app vulns on customer sites
    (r"\bsite\s+vulnerabilit", "web_app_class"),
    # "General web issues / general web vulnerabilities" — catch-all
    (r"\bgeneral\s+web\s+(?:issues?|vulnerabilit)", "web_app_class"),
    # "Hypothetical flaw / theoretical / without a demonstrated / without a working PoC"
    (r"\bhypothetical\s+(?:flaw|issue|vulnerabilit)", "speculative"),
    (r"\btheoretical\s+(?:attack|scenario|vulnerabilit|issue)", "speculative"),
    (r"\bwithout\s+(?:a\s+)?demonstrated\b", "speculative"),
    (r"\bwithout\s+(?:a\s+)?working\s+(?:PoC|poc|exploit|proof)", "speculative"),
    # "Do not accept / considered out of scope / will not be rewarded" catch-all sentences
    (r"\b(?:do\s+not\s+accept|not\s+eligible|considered\s+out\s+of\s+scope|will\s+not\s+be\s+rewarded)\b",
     "explicit_oos_sentence"),
    # G13: "Disclosure of information without direct security impact" generalised form
    (r"\bdisclosure\s+of\s+information\s+without\s+(?:direct\s+)?security\s+impact", "info_disc_no_impact"),
    (r"\binformation\s+(?:exposure|disclosure)\s+without\s+(?:an?\s+)?exploitable", "info_disc_no_impact"),
    (r"\bnon[\s-]?exploitable\s+information", "info_disc_no_impact"),
    (r"\blow[\s-]?risk\s+information\s+disclosure", "info_disc_no_impact"),
    # 2026-04-17 추가 — US-W8 (docs/platform-rejection-guidelines.md + 2026 Medium articles)
    (r"un[\s-]?prompted\s+(?:user\s+)?actions?", "explicit_oos_sentence"),
    (r"theoretical\s+(?:impacts?|scenarios?|vuln)", "speculative"),
    (r"captcha\s+bypass\s+(?:using|via|with)\s+(?:ocr|machine)", "explicit_oos_sentence"),
    (r"social\s+engineering(?:\s+of\s+(?:staff|employees|contractors))?", "prohibited_activity"),
    (r"reflected\s+plain[\s-]?text\s+injection", "explicit_oos_sentence"),
    (r"clickjacking\s+on\s+(?:static|informational|login|logout)", "explicit_oos_sentence"),
    (r"(?:logout|login)\s+csrf", "explicit_oos_sentence"),
    (r"non[\s-]?sensitive\s+(?:api[\s-]?key|data|information|disclosure)", "info_disc_no_impact"),
    # 2026-04-17 재-fetch (YWH helpcenter.yeswehack.io + Intigriti kb verbatim)
    (r"post[\s-]?authentication\s+tests?\s+on\s+pre[\s-]?authentication\s+scopes?",
     "explicit_oos_sentence"),
    (r"mass\s+non[\s-]?qualifying\s+vulnerabilit(?:y|ies)", "prohibited_activity"),
    (r"AI[\s-]?generated\s+(?:hypotheses|assumptions?|reports?)\s+without\s+manual\s+verification",
     "prohibited_activity"),
    (r"poor[\s-]?quality\s+(?:findings?|reports?)\s+without\s+(?:expert\s+)?validation",
     "speculative"),
)

# Speculative language in finding descriptions — triggers HARD_KILL when combined
# with a "hypothetical/theoretical/without demonstrated" OOS clause.
_SPECULATIVE_FINDING_WORDS = (
    "potential", "could", "might", "may allow", "possibly", "theoretically",
    "hypothetically", "would allow", "could allow", "could potentially",
)

# Check 7 — Program intent mismatch (G03)
# Patterns that signal the program accepts only a narrow class of findings.
_PROGRAM_INTENT_PATTERNS = (
    r"(?:the\s+)?goal\s+of\s+this\s+program\s+is\s+(?:to\s+report\s+ways?\s+around|only|specifically)\s+(.{5,80})",
    r"this\s+program\s+rewards?\s+(?:only|specifically)\s+(.{5,80})",
    r"we\s+only\s+accept\s+reports?\s+of\s+(.{5,80})",
    r"dedicated\s+to\s+(?:finding|reporting|research\s+(?:into|on))\s+(.{5,80})",
    r"this\s+is\s+a\s+(?:bounty|research)\s+(?:program\s+)?for\s+(.{5,80})",
)

# Check 8 — Extended impact-scope section headings (G04)
# Immunefi renders impact categories under non-standard headings; extend Check 2's
# regex to catch them with a dedicated hard-kill path.
_IMPACT_SCOPE_HEADINGS = re.compile(
    r"##\s+(?:"
    r"Impacts?\s+in\s+Scope"
    r"|Smart\s+Contract\s+Bug\s+Impacts?"
    r"|Blockchain[/\w\s]+Bug\s+Impacts?"
    r"|Website\s+and\s+Applications?\s+Bug\s+Impacts?"
    r"|In[\s-]Scope\s+Impacts?"
    r"|Accepted\s+Impacts?"
    r"|Qualifying\s+Impacts?"
    r")",
    re.IGNORECASE,
)

# Check 9 — Client-side-only N/R patterns (G08, magiclabs PKCE incident)
# Appear in ## Submission Rules (not ## Exclusion List) — missed by Check 3.
_CLIENT_SIDE_ONLY_PATTERNS = (
    r"client[\s-]?side\s+(?:only\s+)?vulnerabilit\w+\s+(?:are\s+)?not\s+(?:applicable|accepted|rewarded|eligible)",
    r"client[\s-]?side\s+(?:only\s+)?(?:issues?|findings?)\s+(?:are\s+)?(?:not\s+)?(?:applicable|n/?a\b)",
    r"(?:require|requiring)\s+(?:victim\s+|user\s+)?(?:browser\s+)?interaction\s+(?:are\s+)?(?:not|n/a)",
    r"theoretical\s+(?:attacks?|scenarios?|vulnerabilit\w+)\s+(?:are\s+)?not\s+(?:accepted|rewarded|eligible)",
    r"(?:must\s+)?demonstrate\w*\s+(?:on\s+)?(?:production|live)\s+(?:target|environment|system)",
    r"no\s+server[\s-]?side\s+impact\s+(?:are\s+)?not\s+(?:eligible|accepted|applicable)",
)

# Self-limiting phrases in finding descriptions that signal client-side-only scope.
_CLIENT_SIDE_SELF_LIMITING = (
    "client-side only", "client side only", "requires victim interaction",
    "no server-side impact", "no server side impact",
    "browser interaction required", "client-side extraction",
    "requires xss", "requires physical access",
)

# Check 10 — Government / public platform intentional-behavior (G14, DINUM incident)
_GOVT_PLATFORM_INDICATORS = (
    "demarches-simplifiees", "service-public", ".gouv.fr", ".gov.uk",
    ".gsa.gov", ".digital.gov", ".gov.au", ".gov.nz",
    "public service", "public platform", "government", "civic tech",
    "open government", "public sector",
)
_GOVT_ACCESSIBILITY_KEYWORDS = (
    "accessibility", "accessib", "universel", "tous et toutes", "all citizens",
    "open to all", "no barriers", "public access", "universal access",
)
_ACCESSIBILITY_FINDING_PATTERNS = (
    "input validation", "character limit", "rate limit", "rate limiting",
    "captcha", "missing validation", "no validation", "input length",
    "input restriction", "missing input", "length limit",
)

# ---------------------------------------------------------------------------
# US-W2+W5: Immunefi 41-category exclusion gate (Check 11) + platform-aware dispatch
# ---------------------------------------------------------------------------

# 41 Immunefi common exclusions (2026-04-17).
# Each entry: (short_key, regex_pattern, require_sensitivity_anchor)
# require_sensitivity_anchor=True → WARN if anchor present, HARD_KILL otherwise.
# require_sensitivity_anchor=False → always HARD_KILL on match.
_IMMUNEFI_EXCLUSIONS: tuple[tuple[str, str, bool], ...] = (
    # General (1-8)
    (
        "already_exploited",
        r"attack[s]?\s+(?:that\s+)?(?:the\s+)?reporter\s+has\s+already\s+exploit"
        r"|already[\s-]exploit|reusing\s+(?:my|their|own)\s+(?:previously[\s-])?exploit",
        False,
    ),
    (
        "leaked_credentials",
        r"(?:access\s+to\s+)?leaked\s+(?:key|credential|secret|token|password)"
        r"|leaked\s+private\s+key|from\s+leaked\s+(?:key|cred)",
        False,
    ),
    (
        "privileged_address",
        r"privileged\s+address"
        r"|(?:access\s+to\s+)?governance\s+(?:key|address|wallet|role)"
        r"|strategist\s+(?:key|role|wallet)"
        r"|requires?\s+(?:admin|owner|governance|privileged)\s+(?:key|access|address|role)",
        False,
    ),
    (
        "external_stablecoin_depeg",
        r"depegg?ing\s+of\s+(?:an?\s+)?external\s+stablecoin"
        r"|external\s+stablecoin\s+depeg"
        r"|stablecoin\s+loses?\s+(?:its\s+)?peg",
        False,
    ),
    (
        "exposed_github_secrets",
        r"(?:secret|api[\s-]?key|access[\s-]?token|private[\s-]?key|password)[s]?\s+"
        r"(?:exposed|found|leaked|visible|disclosed)\s+in\s+(?:github|git|repo|commit|source)"
        r"|github\s+(?:secret|credential|key)\s+(?:exposure|leak|disclosure)",
        False,
    ),
    (
        "best_practice_recommendation",
        r"best[\s-]?practice\s+recommendation"
        r"|recommended\s+(?:security\s+)?best\s+practice"
        r"|(?:improve|improve\s+(?:the\s+)?)?security\s+posture\s+recommendation",
        False,
    ),
    (
        "feature_request",
        r"\bfeature\s+request\b"
        r"|requesting?\s+(?:a\s+)?(?:new\s+)?feature"
        r"|enhancement\s+request",
        False,
    ),
    (
        "test_config_file_impact",
        r"impact[s]?\s+on\s+test\s+(?:file[s]?|configuration)"
        r"|test\s+file[s]?\s+(?:impact|vulnerability|vuln)"
        r"|configuration\s+file[s]?\s+(?:impact|vulnerability|vuln)"
        r"|only\s+affects?\s+(?:test|config(?:uration)?)\s+file[s]?",
        False,
    ),
    # Smart Contracts (9-13)
    (
        "incorrect_oracle_data",
        r"incorrect\s+(?:data\s+)?supplied\s+by\s+(?:third[\s-]?party\s+)?oracle"
        r"|(?:third[\s-]?party\s+)?oracle\s+(?:data\s+)?manipulation"
        r"|oracle\s+staleness|stale\s+oracle\s+(?:data|price|feed)",
        False,
    ),
    (
        "economic_governance_attack",
        r"51\s*%\s+attack"
        r"|basic\s+economic\s+(?:and\s+governance\s+)?attack"
        r"|governance\s+attack"
        r"|basic\s+governance\s+attack"
        r"|majority\s+hash(?:rate)?\s+attack",
        False,
    ),
    (
        "liquidity_impact",
        r"lack\s+of\s+liquidity\s+impact"
        r"|(?:insufficient|low)\s+liquidity\s+(?:impact|risk)"
        r"|liquidity\s+(?:shortage|crisis)\s+(?:impact|vulnerability)",
        False,
    ),
    (
        "sybil_attack",
        r"\bsybil\s+attack\b"
        r"|multiple\s+(?:fake\s+)?identit(?:y|ies)\s+(?:attack|exploit)"
        r"|sybil\s+(?:resistance|vulnerability|exploit)",
        False,
    ),
    (
        "centralization_risk",
        r"\bcentralization\s+risk\b"
        r"|centrali[sz]ation\s+(?:concern|vulnerability|risk|issue)"
        r"|over[\s-]?centrali[sz]",
        False,
    ),
    # Websites/Apps (14-34)
    (
        "theoretical_impact",
        r"theoretical\s+impact[s]?\s+without\s+(?:any\s+)?(?:proof|demonstration)"
        r"|theoretical\s+(?:attack|scenario|vulnerabilit\w+)\s+without\s+(?:a\s+)?(?:working\s+)?(?:proof|poc|demo|demonstration)"
        r"|impact\s+without\s+(?:any\s+)?proof\s+or\s+demonstration",
        False,
    ),
    (
        "physical_device_access",
        r"(?:requires?\s+)?physical\s+(?:device\s+)?access"
        r"|physical\s+(?:access\s+to\s+)?(?:device|machine|server|hardware)"
        r"|requires?\s+(?:local\s+)?physical\s+(?:access|presence)",
        False,
    ),
    (
        "local_network_attack",
        r"\blocal\s+network\s+attack"
        r"|attack\s+(?:from|via|on)\s+(?:the\s+)?local\s+network"
        r"|(?:requires?\s+)?(?:same[\s-]?)?local[\s-]?network\s+(?:access|position)",
        False,
    ),
    (
        "reflected_plain_text_injection",
        r"reflected\s+plain[\s-]?text\s+injection"
        r"|plain[\s-]?text\s+(?:reflected\s+)?injection\s+(?:in|via|through)"
        r"|reflected\s+(?:plain\s+text|plaintext)\s+(?:in|via)",
        False,
    ),
    (
        "self_xss",
        r"\bself[\s-]?xss\b"
        r"|xss\s+(?:that\s+)?(?:only\s+)?(?:affects?\s+)?(?:the\s+)?(?:attacker|own\s+(?:account|session|browser))"
        r"|cross[\s-]?site\s+scripting\s+(?:that\s+)?only\s+(?:affects?\s+)?(?:attacker|own\s+session)",
        False,
    ),
    (
        "captcha_bypass_ocr",
        r"captcha\s+bypass\s+using\s+ocr"
        r"|ocr[\s-]?based\s+captcha\s+bypass"
        r"|captcha\s+ocr\s+(?:bypass|circumvention)",
        False,
    ),
    (
        "csrf_no_state_modification",
        r"csrf\s+(?:without|that\s+does\s+not)\s+(?:cause\s+)?(?:state\s+modification|modify\s+state)"
        r"|logout\s+csrf"
        r"|csrf\s+(?:only\s+)?(?:on\s+)?(?:logout|read[\s-]?only|non[\s-]?state[\s-]?changing)",
        False,
    ),
    (
        "missing_http_security_headers",
        r"missing\s+(?:http\s+)?security\s+headers?"
        r"|(?:absence|lack)\s+of\s+(?:http\s+)?security\s+headers?"
        r"|(?:x[\s-]?frame[\s-]?options|content[\s-]?security[\s-]?policy|hsts|"
        r"x[\s-]?content[\s-]?type|referrer[\s-]?policy)\s+(?:header\s+)?(?:missing|not\s+set|absent)",
        True,  # WARN if sensitivity anchor present
    ),
    (
        "server_side_non_confidential_info_disclosure",
        r"server[\s-]?side\s+non[\s-]?confidential\s+information\s+disclosure"
        r"|(?:discloses?|exposes?|leaks?)\s+(?:internal\s+)?(?:ip\s+address|server\s+name|hostname)\s+"
        r"(?:without|that\s+(?:is|are)\s+not)",
        False,
    ),
    (
        "user_enumeration",
        r"\buser\s+enumeration\b"
        r"|username\s+enumeration"
        r"|account\s+enumeration"
        r"|enumerat(?:e|ing|ion)\s+(?:valid\s+)?(?:users?|accounts?|emails?)",
        False,
    ),
    (
        "unprompted_user_action",
        r"un[\s-]?prompted\s+(?:in[\s-]?app\s+)?user\s+action"
        r"|requires?\s+(?:un[\s-]?prompted|victim'?s?)\s+(?:in[\s-]?app\s+)?(?:user\s+)?action"
        r"|victim\s+(?:must\s+)?(?:manually\s+)?(?:click|perform|initiate)\s+(?:an?\s+)?(?:in[\s-]?app\s+)?action",
        False,
    ),
    (
        "ssl_tls_best_practices",
        r"ssl[\s/]?tls\s+best\s+practices?"
        r"|(?:weak|insecure|deprecated)\s+(?:ssl|tls|cipher|protocol)\s+(?:version|suite|configuration)?\s+"
        r"(?:best\s+practice|recommendation|configuration)"
        r"|ssl[\s/]tls\s+(?:configuration\s+)?(?:best\s+practice|recommendation)",
        False,
    ),
    (
        "ddos_only",
        r"(?:only\s+)?ddos(?:\s+attack)?(?:\s+impact)?(?:\s+vulnerability)?"
        r"(?:\s+only)?"
        r"|\bdenial[\s-]of[\s-]service\s+only\b"
        r"|(?:the\s+)?only\s+(?:possible\s+)?impact\s+is\s+(?:a\s+)?(?:ddos|denial[\s-]of[\s-]service)",
        False,
    ),
    (
        "ux_ui_disruption",
        r"ux[\s/]?ui\s+disruption\s+without\s+material\s+disruption"
        r"|(?:minor\s+)?(?:ux|ui|user\s+(?:interface|experience))\s+disruption"
        r"|(?:cosmetic|visual|ui)\s+(?:issue|bug|defect)\s+without\s+(?:security\s+)?impact",
        False,
    ),
    (
        "browser_plugin_defect",
        r"browser[\s/]plugin\s+defect\s+(?:as\s+)?primary\s+cause"
        r"|(?:caused|caused\s+by|due\s+to)\s+(?:a\s+)?browser\s+(?:bug|defect|vulnerability)"
        r"|browser[\s-]?specific\s+(?:bug|defect|vulnerability)\s+(?:as\s+)?(?:primary\s+)?(?:root\s+)?cause",
        False,
    ),
    (
        "non_sensitive_api_key_leakage",
        r"(?:non[\s-]?sensitive\s+)?(?:etherscan|infura|alchemy)\s+api[\s-]?key\s+"
        r"(?:leak|exposure|disclosure|found|exposed)"
        r"|api[\s-]?key\s+(?:for\s+)?(?:etherscan|infura|alchemy)\s+(?:leak|exposure|disclosure)"
        r"|(?:rate[\s-]?limited|public)\s+(?:etherscan|infura|alchemy)\s+(?:api[\s-]?key|key)",
        False,
    ),
    (
        "browser_exploitation_dependency",
        r"(?:requires?|dependent\s+on|depends?\s+on)\s+(?:a\s+)?browser\s+exploit(?:ation)?"
        r"|browser\s+exploitation\s+(?:bug\s+)?(?:as\s+)?(?:pre[\s-]?)?(?:condition|dependency|requirement)"
        r"|(?:only\s+)?exploit(?:able|ed)\s+(?:via|through|using)\s+(?:a\s+)?browser\s+(?:bug|vulnerability|exploit)",
        False,
    ),
    (
        "spf_dmarc_misconfigured",
        r"\bspf\b.*\bmisconfigur"
        r"|\bdmarc\b.*\bmisconfigur"
        r"|\bspf\b.*\b(?:missing|not\s+set|absent|incorrect)"
        r"|\bdmarc\b.*\b(?:missing|not\s+set|absent|incorrect)"
        r"|(?:missing|misconfigured|absent)\s+(?:spf|dmarc|dkim)\s+(?:record|policy|configuration)",
        False,
    ),
    (
        "automated_scanner_report",
        r"automated\s+scanner\s+report[s]?\s+without\s+(?:demonstrated\s+)?impact"
        r"|(?:automated|tool[\s-]?generated)\s+(?:vulnerability\s+)?scan(?:ner)?\s+(?:output|report|finding)\s+"
        r"without\s+(?:manual\s+)?(?:demonstrated|verified|proven)\s+(?:impact|exploitation)"
        r"|(?:only\s+)?(?:reported\s+by\s+)?(?:automated|scanner|tool)\s+without\s+(?:manual\s+)?(?:verification|exploitation|poc)",
        True,  # WARN if sensitivity anchor present
    ),
    (
        "ui_ux_best_practice",
        r"ui[\s/]?ux\s+best[\s-]?practice\s+recommendation"
        r"|user\s+(?:interface|experience)\s+best[\s-]?practice"
        r"|(?:improve|improving)\s+(?:the\s+)?(?:ux|ui|user\s+(?:interface|experience))\s+"
        r"(?:without\s+(?:security\s+)?impact|recommendation)",
        True,  # WARN if sensitivity anchor present
    ),
    (
        "non_future_proof_nft_rendering",
        r"non[\s-]?future[\s-]?proof\s+nft\s+rendering"
        r"|nft\s+(?:rendering|display|metadata)\s+(?:that\s+(?:is|may\s+become)\s+)?(?:not\s+)?future[\s-]?proof"
        r"|nft\s+(?:rendering|display)\s+(?:compatibility|support)\s+(?:issue|problem|concern)",
        False,
    ),
    # Prohibited (35-41)
    (
        "mainnet_testnet_testing",
        r"(?:testing\s+(?:on|against)\s+)?(?:mainnet|public\s+testnet)\s+testing"
        r"|(?:performed|conducted|ran|executed)\s+(?:on|against)\s+(?:the\s+)?(?:mainnet|live\s+network)"
        r"|(?:mainnet|public\s+testnet)\s+(?:exploit|attack|test(?:ed|ing)?)",
        False,
    ),
    (
        "third_party_oracle_contract_testing",
        r"(?:testing\s+)?third[\s-]?party\s+(?:oracle|contract)\s+testing"
        r"|test(?:ed|ing)?\s+(?:a\s+)?third[\s-]?party\s+(?:oracle|contract|protocol)"
        r"|exploit(?:ed|ing)?\s+(?:a\s+)?third[\s-]?party\s+(?:oracle|smart\s+contract)",
        False,
    ),
    (
        "social_engineering_phishing",
        r"\bsocial\s+engineering\b"
        r"|\bphishing\b"
        r"|(?:spear[\s-]?)?phishing\s+attack"
        r"|(?:via|through|using)\s+(?:social\s+engineering|phishing)",
        False,
    ),
    (
        "third_party_system_testing",
        r"third[\s-]?party\s+system\s+testing"
        r"|test(?:ed|ing)?\s+(?:a\s+)?third[\s-]?party\s+system"
        r"|attack(?:ed|ing)?\s+(?:a\s+)?third[\s-]?party\s+(?:system|service|infrastructure)",
        False,
    ),
    (
        "ddos_attack_on_assets",
        r"ddos\s+(?:attack[s]?\s+(?:on|against))\s+(?:project|protocol|platform)\s+assets?"
        r"|(?:launch(?:ed|ing)?|perform(?:ed|ing)?|conduct(?:ed|ing)?)\s+(?:a\s+)?ddos\s+attack"
        r"|flooding\s+(?:the\s+)?(?:project|protocol|platform|contract)\s+(?:with\s+)?(?:requests?|transactions?)",
        False,
    ),
    (
        "excessive_traffic",
        r"excessive\s+traffic\s+generation"
        r"|generat(?:e|ed|ing)\s+excessive\s+(?:network\s+)?traffic"
        r"|(?:high|large)\s+volume\s+(?:of\s+)?(?:requests?|traffic)\s+(?:generation|generated|sent)",
        False,
    ),
    (
        "public_disclosure_embargoed",
        r"public\s+disclosure\s+of\s+(?:an?\s+)?embargoed\s+(?:bounty|finding|vulnerability|report)"
        r"|disclose[d]?\s+(?:an?\s+)?embargoed\s+(?:vulnerability|finding|bounty)"
        r"|(?:early|premature|unauthorized)\s+(?:public\s+)?disclosure\s+(?:of\s+)?(?:an?\s+)?"
        r"embargoed",
        False,
    ),
    # 2026 Immunefi additions (G-W1 closure 2026-04-17)
    (
        "mev_frontrunning_only",
        r"\b(?:front[\s-]?running|back[\s-]?running|mev)\b[^.\n]{0,60}"
        r"(?:without|no)\s+(?:code|smart[\s-]?contract)\s+(?:bug|vulnerability)",
        False,
    ),
    (
        "gas_griefing_only",
        r"gas\s+griefing\b[^.\n]{0,40}(?:without|no)\s+(?:fund\s+theft|financial\s+impact)",
        False,
    ),
    (
        "first_deposit_precision_loss_minor",
        r"first[\s-]?deposit\s+(?:attack|precision\s+loss)[^.\n]{0,80}"
        r"(?:<\s*\$?\s*10|negligible|minor\s+(?:rounding|precision))",
        False,
    ),
    (
        "flash_loan_without_code_bug",
        r"flash[\s-]?loan\b[^.\n]{0,60}(?:without|no)\s+(?:underlying\s+)?(?:code|smart[\s-]?contract)\s+(?:bug|vulnerability)",
        False,
    ),
    (
        "passive_yield_arbitrage",
        r"(?:passive\s+)?(?:yield|liquidity\s+provision)\s+arbitrage\b[^.\n]{0,40}"
        r"(?:without|no)\s+(?:code\s+bug|contract\s+vulnerability)",
        False,
    ),
    (
        "donation_rounding_minor",
        r"donations?\s+to\s+(?:the\s+)?contract(?:s)?[^.\n]{0,50}(?:minor\s+)?rounding\s+(?:errors?|loss)",
        False,
    ),
    (
        "outdated_not_in_production",
        r"(?:outdated|legacy|deprecated)\s+contracts?\s+(?:not\s+|no\s+longer\s+)?in\s+production",
        False,
    ),
    (
        "griefing_no_attacker_benefit",
        r"griefing\s+attacks?[^.\n]{0,50}(?:no|without)\s+financial\s+benefit\s+(?:to|for)\s+(?:the\s+)?attacker",
        False,
    ),
    (
        "unused_function_dead_code",
        r"(?:unused|dead|unreachable)\s+(?:function|code|branch)[^.\n]{0,40}(?:without|no)\s+(?:exploit|reachable)",
        False,
    ),
)


_BUGCROWD_P5_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("autocomplete_enabled", r"autocomplete\s+(?:enabled|on|attribute)",
     "Autocomplete enabled on form (P5)"),
    ("save_password", r"save\s+password|password\s+autofill",
     "Save password browser feature (P5)"),
    ("non_sensitive_disclosure",
     r"non[\s-]?sensitive\s+(?:data\s+|information\s+)?(?:disclosure|exposure|leak|exposed)",
     "Non-sensitive information disclosure (P5)"),
    ("missing_headers_non_sensitive",
     r"missing\s+(?:security\s+)?header[^.\n]{0,60}non[\s-]?sensitive",
     "Missing headers on non-sensitive page (P5)"),
    ("outdated_software_no_exploit",
     r"outdated\s+(?:software|library|dependency|version)[^.\n]{0,50}(?:without|no|lacking)\s+(?:exploit|poc|working|demonstrated)",
     "Outdated software without exploit path (P5)"),
    ("ie_only_xss", r"(?:ie|internet\s+explorer)[\s-]?only\s+xss",
     "IE-only XSS (P5)"),
    ("flash_based", r"flash[\s-]?based\s+(?:attack|exploit|vulnerability|xss)",
     "Flash-based vulnerability (P5)"),
    ("tabnabbing", r"tab[\s-]?nabbing",
     "Tabnabbing (P5)"),
    ("ssl_tls_config",
     r"ssl[/\s]?tls\s+(?:config|cipher|best\s+practice|expired|version|suite|weak|misconfig)",
     "SSL/TLS best practices / cipher config (P5)"),
    ("missing_cookie_flags",
     r"missing\s+(?:cookie|http[\s-]?only|secure)\s+flag",
     "Missing cookie flags (P5)"),
    ("clickjacking_static",
     r"clickjacking[^.\n]{0,40}(?:static|informational|login|logout|public)",
     "Clickjacking on static/login page (P5)"),
    ("open_redirect_headers",
     r"open\s+redirect\s+(?:through|via|using|in)\s+(?:http\s+)?header",
     "Open Redirect through HTTP headers (P5)"),
    ("csrf_logout",
     r"(?:logout|login)\s+csrf",
     "Logout/login CSRF (P5)"),
    ("broken_links",
     r"broken\s+link(?:s|\s+hijack)?",
     "Broken link / social media hijack (P5)"),
    ("verbose_error_no_impact",
     r"verbose\s+error[^.\n]{0,40}(?:without|no|lacking)\s+(?:impact|sensitive)",
     "Verbose error without sensitive impact (P5)"),
    ("banner_grab_version",
     r"banner\s+grab|version\s+disclosure|software\s+version\s+exposed",
     "Banner grab / version disclosure (P5)"),
    ("subdomain_takeover_no_poc",
     r"subdomain\s+takeover[^.\n]{0,40}(?:without|no)\s+(?:exploitable|poc|working|demonstrated)",
     "Subdomain takeover without working PoC (P5)"),
    ("email_spf_dmarc",
     r"(?:spf|dmarc|dkim)\s+(?:missing|misconfig|record|issue|fail)",
     "Missing/misconfigured SPF/DMARC/DKIM (P5)"),
    ("rate_limiting_brute",
     r"(?:lack\s+of\s+|missing\s+|no\s+)?rate[\s-]?limit|brute[\s-]?forc(?:e|ing)|captcha\s+bypass(?:\s+without\s+impact)?",
     "Lack of rate limiting / brute force / captcha bypass (P5)"),
    ("email_flooding",
     r"(?:email|sms|message)\s+(?:flood|spam|abuse|bomb)",
     "Email/SMS flooding (P5)"),
)


def _detect_platform(rules_content: str) -> str:
    """Parse program_rules_summary.md to detect the bounty platform.

    Looks for '## Platform' or 'Platform:' lines and returns a canonical
    platform identifier. Case-insensitive. Returns 'unknown' if not found.

    Returns: 'immunefi' | 'bugcrowd' | 'hackerone' | 'yeswehack' |
             'intigriti' | 'huntr' | 'unknown'
    """
    platform_match = re.search(
        r"(?:^|\n)##?\s*Platform[:\s]+([^\n]+)",
        rules_content,
        re.IGNORECASE,
    )
    if not platform_match:
        # Also try inline "Platform: X" without ## heading
        platform_match = re.search(
            r"\bPlatform\s*:\s*([^\n]+)",
            rules_content,
            re.IGNORECASE,
        )
    if not platform_match:
        return "unknown"

    raw = platform_match.group(1).strip().lower()
    if "immunefi" in raw:
        return "immunefi"
    if "bugcrowd" in raw:
        return "bugcrowd"
    if "hackerone" in raw or "h1" == raw:
        return "hackerone"
    if "yeswehack" in raw or "ywh" in raw or "yes we hack" in raw:
        return "yeswehack"
    if "intigriti" in raw:
        return "intigriti"
    if "huntr" in raw:
        return "huntr"
    return "unknown"


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

# HackerOne NA/Informative prevention triggers (v13.2 — W4)
# Each entry: (key, regex, description)
_H1_NA_TRIGGERS: tuple[tuple[str, str, str], ...] = (
    (
        "hypothetical",
        r"\b(?:hypothetical|theoretical|potential|could\s+possibly|may\s+allow)\b",
        "Speculative language without live proof — HackerOne marks as Informative.",
    ),
    (
        "no_poc",
        r"\b(?:no\s+poc|without\s+poc|proof[\s-]?of[\s-]?concept\s+not\s+provided)\b",
        "PoC absent — HackerOne requires reproducible proof for valid report.",
    ),
    (
        "needs_invest",
        r"\b(?:needs\s+(?:more\s+)?investigation|requires\s+further\s+(?:testing|analysis))\b",
        "Incomplete investigation — triager cannot validate without complete analysis.",
    ),
    (
        "vague_steps",
        r"\b(?:vague|unclear|not\s+reproducible)\s+(?:steps|reproduction)\b",
        "Vague/unclear reproduction steps — HackerOne marks as Not Applicable.",
    ),
    (
        "third_party_saas",
        r"\b(?:third[\s-]?party\s+(?:saas|integration|service|vendor)|external\s+(?:vendor|service))\b",
        "Third-party SaaS/integration out of scope — HackerOne redirects to vendor.",
    ),
    (
        "scanner_output",
        r"\b(?:nuclei|nessus|burp|zap|automated\s+scanner)\s+(?:output|report|finding)\b",
        "Raw scanner output without manual verification — HackerOne marks as Informative.",
    ),
    (
        "dup_unchecked",
        r"\b(?:duplicates?\s+not\s+verified|did\s+not\s+check\s+duplicates)\b",
        "Duplicates not checked — HackerOne penalizes unverified duplicate submissions.",
    ),
)

_AI_SLOP_MARKERS = (
    "it is worth noting",
    "this showcases",
    "it should be noted",
    "it is important to note",
    "furthermore",
    "moreover",
    "in conclusion",
    "to summarize",
    "in essence",
    "it is crucial to",
    "seamless",
    "robust",
    "comprehensive",
    "cutting-edge",
    "state-of-the-art",
    "leverage",
    "navigate",
    "elevate",
    "embark on",
    "delve into",
)

_AI_SLOP_EMOJI_RE = r"[\U0001F300-\U0001FAFF\u2600-\u27BF]"


def _scope_domains_from_rules(rules_content: str) -> list[str]:
    """Extract in-scope domain/host entries from program_rules_summary.md."""
    match = re.search(
        r"##\s*In-Scope Assets[^\n]*\n(.*?)(?=\n##|\Z)",
        rules_content,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return []
    domains: list[str] = []
    for line in match.group(1).splitlines():
        line_clean = line.strip().lstrip("-*•").strip()
        if not line_clean or line_clean.startswith("#"):
            continue
        m = re.search(
            r"(https?://)?(\*\.)?([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            line_clean,
        )
        if m:
            domains.append(m.group(0).rstrip("/"))
    return domains


def _parse_scope_has_wildcard(scope_domains: list) -> bool:
    return any(d.startswith("*.") or "*." in d for d in scope_domains)


# ---- Past-incident cross-reference (v13.4, G-W2 follow-up) ----
# Cached parse of knowledge/triage_objections/*.md. Each incident file has:
#   - Filename: <YYYYMMDD-|target-slug->pattern.md
#   - Root Cause section describing why the submission was rejected
#   - Outcome (OOS close / Won't fix / N/R / autoban / etc.)
# kill_gate_1 Check 16 compares the incoming finding against these cases and
# raises a WARN when the keyword overlap is high enough to be actionable.

_INCIDENT_CACHE = None  # type: list[dict] | None — lazy-loaded by _load_incident_cache
_INCIDENT_STOPWORDS = {
    "this", "that", "with", "from", "when", "where", "what", "which", "have",
    "been", "will", "were", "they", "them", "then", "than", "into", "also",
    "such", "some", "much", "many", "most", "more", "less", "very", "only",
    "would", "could", "should", "might", "about", "after", "before", "because",
    "while", "during", "without", "through", "however", "other", "another",
    "these", "those", "there", "their", "whose", "being", "having", "finding",
    "report", "close", "closed", "vuln", "vulnerability", "security", "program",
    "bounty", "hunter", "triager", "case", "impact", "severity", "scope",
}


def _load_incident_cache() -> list[dict]:
    global _INCIDENT_CACHE
    if _INCIDENT_CACHE is not None:
        return _INCIDENT_CACHE
    cache: list[dict] = []
    kdir = Path(__file__).resolve().parent.parent / "knowledge" / "triage_objections"
    if not kdir.is_dir():
        _INCIDENT_CACHE = cache
        return cache
    for md_path in sorted(kdir.glob("*.md")):
        name = md_path.stem
        if name.startswith("_") or name.upper() == "README":
            continue
        try:
            body = md_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Pull outcome from **Reward Outcome** line if present
        outcome_m = re.search(r"\*\*Reward Outcome\*\*:\s*([^\n]+)", body)
        outcome = outcome_m.group(1).strip() if outcome_m else "unknown"
        # Pull platform from **Date / Platform / Finding** line
        plat_m = re.search(r"\*\*Date / Platform / Finding\*\*[^\n]*?/\s*([A-Za-z0-9.+-]+)\s*/", body)
        platform = (plat_m.group(1) if plat_m else "unknown").strip().lower()
        # Root cause section
        rc_m = re.search(r"##\s*1\.?\s*Root Cause\s*\n(.*?)(?=\n##|\Z)", body, re.DOTALL | re.IGNORECASE)
        root_cause = rc_m.group(1).strip() if rc_m else body[:600]
        # Build keyword set from title + root cause
        text = (name.replace("-", " ") + " " + root_cause).lower()
        words = set(w for w in re.split(r"\W+", text) if len(w) >= 5 and w not in _INCIDENT_STOPWORDS)
        summary = re.sub(r"\s+", " ", root_cause)[:240]
        cache.append({
            "case": name,
            "platform": platform,
            "outcome": outcome,
            "keywords": words,
            "summary": summary,
        })
    _INCIDENT_CACHE = cache
    return cache


def _match_past_incidents(text: str, platform_hint: str) -> list[dict]:
    """Return incidents whose keyword overlap with `text` is >= 3 and that
    match the platform hint when available. Sorted by overlap desc."""
    cache = _load_incident_cache()
    if not cache:
        return []
    text_words = set(w for w in re.split(r"\W+", text) if len(w) >= 5 and w not in _INCIDENT_STOPWORDS)
    if not text_words:
        return []
    results = []
    for inc in cache:
        overlap_set = text_words & inc["keywords"]
        if len(overlap_set) < 3:
            continue
        if platform_hint and platform_hint != "unknown" and inc["platform"] != "unknown":
            if platform_hint not in inc["platform"] and inc["platform"] not in platform_hint:
                # platform mismatch — still report but de-priorited
                pass
        results.append({
            **inc,
            "overlap": sorted(overlap_set)[:6],
        })
    results.sort(key=lambda r: (len(r["overlap"]), r["case"]), reverse=True)
    return results


def _finding_mentions_ood_subdomain(
    finding: str, impact: str, scope_domains: list[str]
) -> tuple[bool, str]:
    """Check if finding/impact mentions a host not covered by scope_domains.

    Returns (is_out_of_domain, detected_host).
    """
    combined = (finding + " " + impact).lower()
    for m in re.finditer(r"\b([a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9-]+){2,})\b", combined):
        candidate = m.group(1)
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", candidate):
            continue  # skip IPs
        matched = False
        for d in scope_domains:
            dl = d.lower().replace("https://", "").replace("http://", "").rstrip("/")
            if dl.startswith("*."):
                if candidate.endswith(dl[2:]):
                    matched = True
                    break
            elif candidate == dl:
                matched = True
                break
        if not matched:
            return True, candidate
    return False, ""


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
    # v13 FIX: ignore anchors that appear in a negation context, e.g.
    # "no credentials leaked", "without session tokens", "not exposing PII".
    # Previously "credentials" matched even with "no" in front, so a finding
    # explicitly denying any sensitive impact still got grey-zoned instead of
    # HARD_KILL'd.
    def _anchor_present(anchor: str, text: str) -> bool:
        if anchor not in text:
            return False
        # Look at the 40 chars preceding each occurrence for negation markers.
        start = 0
        while True:
            idx = text.find(anchor, start)
            if idx < 0:
                return False
            prefix = text[max(0, idx - 40):idx]
            if not re.search(
                r"\b(?:no|without|not|never|zero|absent|exclude(?:s|d)?|"
                r"does\s+not\s+(?:leak|expose|disclose)|doesn'?t\s+(?:leak|expose)|"
                r"lack(?:s|ing)?\s+of|none\s+of\s+the)\s+(?:\w+\s+){0,3}$",
                prefix,
            ):
                return True
            start = idx + len(anchor)

    sensitivity_hit = next(
        (
            a for a in _SENSITIVITY_ANCHORS
            if _anchor_present(a, impact_lower) or _anchor_present(a, finding_lower)
        ),
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


def _detect_finding_class(finding: str) -> str:
    """Classify finding description into a broad vulnerability class.

    Returns: 'xss' | 'sqli' | 'ssrf' | 'idor' | 'rce' | 'csrf' | 'info_disc'
             | 'dos' | 'broken_auth' | 'other'
    """
    f = finding.lower()
    if re.search(r"\bxss\b|cross[\s-]?site\s+script", f):
        return "xss"
    if re.search(r"\bsqli?\b|sql\s+injection|structured\s+query", f):
        return "sqli"
    if re.search(r"\bssrf\b|server[\s-]?side\s+request\s+forg", f):
        return "ssrf"
    if re.search(r"\bidor\b|insecure\s+direct\s+object|broken\s+access\s+control", f):
        return "idor"
    if re.search(r"\brce\b|remote\s+code\s+exec|command\s+injection|code\s+execution", f):
        return "rce"
    if re.search(r"\bcsrf\b|cross[\s-]?site\s+request\s+forg", f):
        return "csrf"
    if re.search(r"\bdos\b|denial[\s-]?of[\s-]?service|resource\s+exhaustion", f):
        return "dos"
    if re.search(
        r"stack\s*trace|verbose|error\s+message|banner|version\s+disclosure|"
        r"info(?:rmation)?\s+(?:disclosure|exposure|leak)|env\s+dump|hostname\s+disclosure",
        f,
    ):
        return "info_disc"
    if re.search(
        r"auth(?:entication)?\s+bypass|broken\s+auth|account\s+takeover|"
        r"session\s+(?:hijack|fixation)|pkce|oauth",
        f,
    ):
        return "broken_auth"
    return "other"


def _web_app_vuln_class(finding_class: str) -> bool:
    """Return True if finding_class is a standard web-app vulnerability."""
    return finding_class in ("xss", "sqli", "ssrf", "idor", "rce", "csrf", "info_disc", "broken_auth")


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
        # Also check for explicit impact categories (Immunefi-style).
        # v13 FIX (bookbeat false-positive): the regex must be anchored to a proper
        # Markdown heading (## ...) so we do not accidentally capture "impact" used
        # inside exclusion prose ("Self-XSS ... to impact other users"). Previously
        # IGNORECASE + no heading anchor meant any occurrence of the substring
        # "impact" started the extraction and pulled in whole OOS sections, which
        # then surfaced "xss"/"sqli" words as fake in-scope impacts.
        impact_match = re.search(
            r"(?:^|\n)##\s*(?:Impacts?\s+in\s+Scope|Impact\s+Scope|Impacts?)\b[^\n]*\n(.*?)(?=\n##|\Z)",
            rules_content,
            re.DOTALL | re.IGNORECASE,
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
            # Check if claimed impact matches any in-scope impact.
            # v13 FIX: keep short vuln abbreviations ("xss", "rce", "dos", "xxe")
            # — the original >=4 filter dropped them so an "XSS" impact could
            # never score against an "xss" scope_impact entry.
            vuln_shorthands = {"xss", "rce", "dos", "xxe", "csrf", "idor", "ssrf", "sqli"}

            def _impact_tokens(text: str) -> set[str]:
                return set(
                    w for w in re.split(r"\W+", text)
                    if len(w) >= 4 or w in vuln_shorthands
                )

            claimed_words = _impact_tokens(claimed_impact)
            best_match_score = 0
            best_match = ""
            for si in scope_impacts:
                si_words = _impact_tokens(si)
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

    # --- Check 6: Ambiguous OOS keyword semantic (v13 — G02, G05, G13) ---
    # Catches "site vulnerabilities", "hypothetical flaw", generalised info-disc catch-alls.
    if rules_content:
        excl_match6 = re.search(
            r"##\s*(?:Out-of-Scope|Exclusion List)[^\n]*\n(.*?)(?=\n##|\Z)",
            rules_content, re.DOTALL | re.IGNORECASE,
        )
        if excl_match6:
            oos_body6 = excl_match6.group(1).lower()
            finding_lower6 = finding.lower()
            finding_class6 = _detect_finding_class(finding)

            for pattern, oos_class in _AMBIGUOUS_OOS_PATTERNS:
                if re.search(pattern, oos_body6, re.IGNORECASE):
                    if oos_class == "web_app_class" and _web_app_vuln_class(finding_class6):
                        hard_kills.append(
                            f"[HARD_KILL] AMBIGUOUS OOS CATCH-ALL: Program OOS contains a broad "
                            f"web-app-class exclusion (matched r'{pattern}'). Finding is classified "
                            f"as '{finding_class6}' — directly covered by this catch-all. "
                            f"DataDome 'site vulnerabilities' pattern. KILL."
                        )
                    elif oos_class == "speculative":
                        # Check if finding description itself uses speculative language
                        if any(spec in finding_lower6 for spec in _SPECULATIVE_FINDING_WORDS):
                            hard_kills.append(
                                f"[HARD_KILL] SPECULATIVE FINDING + SPECULATIVE OOS: Program OOS "
                                f"excludes hypothetical/theoretical findings (matched r'{pattern}') "
                                f"AND finding uses speculative language "
                                f"(e.g. 'could', 'potential', 'might'). "
                                f"Provide a working PoC or KILL."
                            )
                    elif oos_class == "info_disc_no_impact":
                        # Duplicate with Check 3.5 but escalate to HARD_KILL here for G13 generalised form
                        if _detect_finding_class(finding) == "info_disc":
                            hard_kills.append(
                                f"[HARD_KILL] INFO-DISC / GENERALISED-NO-IMPACT OOS: Program OOS "
                                f"contains a broad info-disclosure exclusion without direct security "
                                f"impact (matched r'{pattern}'). Finding is info-disclosure class. "
                                f"G13 pattern (Port of Antwerp generalised form). KILL unless "
                                f"--impact cites concrete credentials/RCE/account-takeover chain."
                            )
                    elif oos_class == "prohibited_activity":
                        # Only fire when the finding itself mentions social engineering / phishing
                        _SOCIAL_ENG_FINDING_WORDS = (
                            "social engineering", "phishing", "spear phishing",
                            "vishing", "pretexting", "impersonat",
                        )
                        if any(kw in finding_lower6 for kw in _SOCIAL_ENG_FINDING_WORDS):
                            hard_kills.append(
                                f"[HARD_KILL] PROHIBITED ACTIVITY: Program OOS explicitly bans this class "
                                f"(matched r'{pattern}'). Social engineering/phishing findings are "
                                f"categorically rejected — do NOT submit."
                            )
                    elif oos_class == "explicit_oos_sentence":
                        # For patterns added in 2026-04-17 (US-W8) that directly name a
                        # specific prohibited finding class (captcha bypass OCR, clickjacking
                        # on static, logout/login CSRF, reflected plain text injection,
                        # un-prompted user actions), the OOS match itself is sufficient for
                        # HARD_KILL — no secondary keyword overlap needed.
                        _DIRECT_KILL_PATTERNS = (
                            r"un[\s-]?prompted\s+(?:user\s+)?actions?",
                            r"captcha\s+bypass\s+(?:using|via|with)\s+(?:ocr|machine)",
                            r"reflected\s+plain[\s-]?text\s+injection",
                            r"clickjacking\s+on\s+(?:static|informational|login|logout)",
                            r"(?:logout|login)\s+csrf",
                        )
                        if any(re.search(p, oos_body6, re.IGNORECASE) for p in _DIRECT_KILL_PATTERNS):
                            hard_kills.append(
                                f"[HARD_KILL] EXPLICIT OOS — NAMED FINDING CLASS: Program OOS "
                                f"explicitly names this finding class as excluded "
                                f"(matched r'{pattern}'). Categorically rejected. KILL."
                            )
                        # Extract the 6-8 words after the trigger phrase for semantic overlap
                        sent_match = re.search(
                            r"(?:do\s+not\s+accept|not\s+eligible|considered\s+out\s+of\s+scope|"
                            r"will\s+not\s+be\s+rewarded)[^.\n]{0,80}",
                            oos_body6, re.IGNORECASE,
                        )
                        if sent_match:
                            sent_text = sent_match.group(0)
                            sent_words = set(w for w in re.split(r"\W+", sent_text) if len(w) >= 4)
                            finding_words6 = set(
                                w for w in re.split(r"\W+", finding_lower6) if len(w) >= 4
                            )
                            overlap6 = sent_words & finding_words6
                            if len(overlap6) >= 3:
                                hard_kills.append(
                                    f"[HARD_KILL] EXPLICIT OOS SENTENCE MATCH: Program OOS sentence "
                                    f"'{sent_text.strip()}' shares {len(overlap6)} keywords with "
                                    f"finding (overlap: {', '.join(sorted(overlap6))}). KILL."
                                )
                            elif len(overlap6) >= 2:
                                warnings.append(
                                    f"[WARN] EXPLICIT OOS SENTENCE PARTIAL MATCH: OOS sentence "
                                    f"'{sent_text.strip()}' shares {len(overlap6)} keywords with "
                                    f"finding (overlap: {', '.join(sorted(overlap6))}). Verify manually."
                                )

    # --- Check 7: Program intent mismatch (v13 — G03) ---
    # Detects narrow-scope programs (anti-bot, CDN, dedicated track) and kills generic vuln findings.
    if rules_content:
        subm_match7 = re.search(
            r"##\s*Submission Rules[^\n]*\n(.*?)(?=\n##|\Z)", rules_content, re.DOTALL
        )
        if subm_match7:
            subm_body7 = subm_match7.group(1).lower()
            for intent_pattern in _PROGRAM_INTENT_PATTERNS:
                m7 = re.search(intent_pattern, subm_body7, re.IGNORECASE)
                if m7:
                    expected_scope_raw = m7.group(1).rstrip(".;, \n")
                    expected_words = set(
                        w for w in re.split(r"\W+", expected_scope_raw.lower()) if len(w) >= 4
                    )
                    finding_words7 = set(
                        w for w in re.split(r"\W+", finding.lower()) if len(w) >= 4
                    )
                    overlap7 = expected_words & finding_words7
                    # Finding must share at least 1 word with the expected scope to be considered aligned
                    if not overlap7:
                        hard_kills.append(
                            f"[HARD_KILL] PROGRAM INTENT MISMATCH: Program submission rules declare "
                            f"a narrow scope: '...{expected_scope_raw}...'. "
                            f"Finding has zero keyword overlap with declared scope. "
                            f"DataDome/anti-bot pattern (G03) — generic web vulns are OOS "
                            f"even when asset domain matches. KILL."
                        )
                    break  # Only apply the first matching intent pattern

    # --- Check 8: Separate Impacts in Scope list (v13 — G04) ---
    # Extend Check 2 with Immunefi-specific section headings for impact scope.
    if rules_content:
        impact8 = (impact or "").strip().lower()
        if impact8:
            # Search for Immunefi-style impact-scope sections not caught by Check 2
            impact_section8 = _IMPACT_SCOPE_HEADINGS.search(rules_content)
            if impact_section8:
                # Extract body of that section
                section_start = impact_section8.end()
                next_heading = re.search(r"\n##\s", rules_content[section_start:])
                section_end = section_start + next_heading.start() if next_heading else len(rules_content)
                impact_body8 = rules_content[section_start:section_end].lower()

                # Extract individual impact bullet items
                impact_items8 = [
                    line.strip().lstrip("-*• ").strip()
                    for line in impact_body8.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
                impact_items8 = [i for i in impact_items8 if len(i) >= 5]

                if impact_items8:
                    claimed_words8 = set(w for w in re.split(r"\W+", impact8) if len(w) >= 4)
                    best8 = 0.0
                    best8_item = ""
                    for item in impact_items8:
                        item_words = set(w for w in re.split(r"\W+", item) if len(w) >= 4)
                        if not item_words:
                            continue
                        overlap8 = claimed_words8 & item_words
                        score8 = len(overlap8) / max(len(item_words), 1)
                        if score8 > best8:
                            best8 = score8
                            best8_item = item
                    if best8 < 0.3:
                        hard_kills.append(
                            f"[HARD_KILL] IMPACT NOT IN SCOPE LIST (extended heading check): "
                            f"Claimed impact '{impact8}' does not match any item in the program's "
                            f"dedicated impact scope section (section: '{impact_section8.group(0).strip()}'). "
                            f"Closest item: '{best8_item}' (score: {best8:.0%}). "
                            f"Immunefi impact-scope mismatch is an immediate auto-reject (Utix incident). KILL."
                        )
                    elif best8 < 0.6:
                        warnings.append(
                            f"[IMPACT WEAK MATCH v2] Claimed '{impact8}' partially matches "
                            f"impact-scope item '{best8_item}' (score: {best8:.0%}) in extended "
                            f"impact section '{impact_section8.group(0).strip()}'. Verify wording."
                        )

    # --- Check 9: Client-side-only N/R pattern (v13 — G08, magiclabs PKCE incident) ---
    # Reads ## Submission Rules (not ## Exclusion List) for client-side eligibility clauses.
    if rules_content:
        subm_match9 = re.search(
            r"##\s*Submission Rules[^\n]*\n(.*?)(?=\n##|\Z)", rules_content, re.DOTALL
        )
        if subm_match9:
            subm_body9 = subm_match9.group(1).lower()
            for cs_pattern in _CLIENT_SIDE_ONLY_PATTERNS:
                if re.search(cs_pattern, subm_body9, re.IGNORECASE):
                    # Check if finding itself describes a client-side-only scenario
                    finding_lower9 = finding.lower()
                    if any(sl in finding_lower9 for sl in _CLIENT_SIDE_SELF_LIMITING):
                        hard_kills.append(
                            f"[HARD_KILL] CLIENT-SIDE-ONLY N/R: Program submission rules exclude "
                            f"client-side-only vulnerabilities (matched r'{cs_pattern}'). "
                            f"Finding description contains a self-limiting client-side indicator. "
                            f"Magic Labs PKCE bc91fc04 pattern (G08). "
                            f"No server-side impact demonstrated → KILL."
                        )
                    else:
                        warnings.append(
                            f"[WARN] CLIENT-SIDE ELIGIBILITY CLAUSE: Program submission rules "
                            f"contain a client-side-only exclusion (matched r'{cs_pattern}'). "
                            f"Verify finding has server-side impact before proceeding."
                        )
                    break  # One client-side check per finding is sufficient

    # --- Check 10: Government/public platform intentional behavior (v13 — G14, DINUM incident) ---
    # Warns when a government/civic platform's accessibility mandate may cover the finding class.
    if rules_content:
        rules_lower10 = rules_content.lower()
        is_govt = any(ind in rules_lower10 for ind in _GOVT_PLATFORM_INDICATORS)
        has_accessibility = any(kw in rules_lower10 for kw in _GOVT_ACCESSIBILITY_KEYWORDS)
        if is_govt or has_accessibility:
            finding_lower10 = finding.lower()
            if any(afp in finding_lower10 for afp in _ACCESSIBILITY_FINDING_PATTERNS):
                warnings.append(
                    "[WARN] GOVT/PUBLIC PLATFORM ACCESSIBILITY DESIGN: Program rules indicate a "
                    "government or public platform with accessibility-first mandate. Finding "
                    "describes an input/rate/validation restriction absence which may be "
                    "intentional design for universal access (DINUM 'tous et toutes' pattern, G14). "
                    "Verify finding has a concrete security consequence beyond the restriction gap. "
                    "Won't Fix risk: high."
                )

    # --- Check 11: Immunefi-specific 41-category exclusion gate (US-W2+W5) ---
    if rules_content:
        platform11 = _detect_platform(rules_content)
        if platform11 == "immunefi":
            finding_lower11 = finding.lower()
            impact_lower11 = (impact or "").lower()
            combined11 = f"{finding_lower11} {impact_lower11}"
            for cat_idx, (short_key, pattern, need_anchor) in enumerate(_IMMUNEFI_EXCLUSIONS, start=1):
                if re.search(pattern, combined11, re.IGNORECASE):
                    if need_anchor:
                        # Check for sensitivity anchor — if present, downgrade to WARN
                        anchor_hit11 = next(
                            (a for a in _SENSITIVITY_ANCHORS
                             if a in finding_lower11 or a in impact_lower11),
                            None,
                        )
                        if anchor_hit11:
                            warnings.append(
                                f"[IMMUNEFI CAT-{cat_idx} GREY-ZONE] Finding matches Immunefi "
                                f"common exclusion category {cat_idx} ('{short_key}', "
                                f"r'{pattern[:60]}...'). Sensitivity anchor '{anchor_hit11}' "
                                f"claimed — verify it is concretely demonstrated, not asserted."
                            )
                        else:
                            hard_kills.append(
                                f"[HARD_KILL] IMMUNEFI EXCLUSION CAT-{cat_idx}: Finding matches "
                                f"Immunefi common exclusion category {cat_idx} ('{short_key}'). "
                                f"Verbatim: \"{_IMMUNEFI_EXCLUSIONS[cat_idx - 1][1][:80]}\". "
                                f"No sensitivity anchor found in --impact or finding. "
                                f"Immunefi common-vulnerabilities-to-exclude list. KILL."
                            )
                    else:
                        hard_kills.append(
                            f"[HARD_KILL] IMMUNEFI EXCLUSION CAT-{cat_idx}: Finding matches "
                            f"Immunefi common exclusion category {cat_idx} ('{short_key}'). "
                            f"Verbatim: \"{_IMMUNEFI_EXCLUSIONS[cat_idx - 1][1][:80]}\". "
                            f"This class is explicitly excluded by Immunefi regardless of severity. KILL."
                        )

    # --- Check 12: Bugcrowd VRT-P5 severity downgrade gate (v13.2 — W3) ---
    if rules_content:
        platform12 = _detect_platform(rules_content)
        if platform12 == "bugcrowd":
            finding_lower12 = finding.lower()
            impact_lower12 = (impact or "").lower()
            combined12 = f"{finding_lower12} {impact_lower12}"
            for short_key12, pattern12, desc12 in _BUGCROWD_P5_PATTERNS:
                if re.search(pattern12, combined12, re.IGNORECASE):
                    sev = severity  # already normalised to lower earlier
                    if sev in ("", "low"):
                        warnings.append(
                            f"[BUGCROWD P5 INFO] Finding matches P5/varies category "
                            f"'{desc12}' (key={short_key12}). Appropriate severity is 'low' or informational. "
                            f"Bugcrowd VRT: https://bugcrowd.com/vulnerability-rating-taxonomy"
                        )
                    else:
                        hard_kills.append(
                            f"[HARD_KILL] BUGCROWD P5 SEVERITY MISMATCH: Finding matches "
                            f"Bugcrowd P5 category '{desc12}' (key={short_key12}) — claimed severity "
                            f"'{sev}' exceeds maximum severity for this category. "
                            f"Downgrade to 'low' or KILL. "
                            f"Bugcrowd VRT: https://bugcrowd.com/vulnerability-rating-taxonomy"
                        )

    # --- Check 13: HackerOne Informative/NA prevention (v13.2 — W4) ---
    if rules_content:
        platform_h1 = _detect_platform(rules_content)
        if platform_h1 == "hackerone":
            scope_domains = _scope_domains_from_rules(rules_content)
            if scope_domains:
                is_ood, detected = _finding_mentions_ood_subdomain(finding, impact, scope_domains)
                if is_ood:
                    hard_kills.append(
                        f"[HARD_KILL] HACKERONE SUBDOMAIN DRIFT: Finding mentions host '{detected}' "
                        f"which is NOT covered by in-scope {scope_domains[:5]}. "
                        f"HackerOne #1 cause of 'Not Applicable' (reputation -5)."
                    )
            combined = (finding + " " + (impact or "")).lower()
            for key, pat, desc in _H1_NA_TRIGGERS:
                if re.search(pat, combined, re.IGNORECASE):
                    warnings.append(f"[HACKERONE NA/INFORMATIVE RISK] {key}: {desc}")

    # --- Check 14: AI-slop report pattern (v13.2 — W6) ---
    combined_slop = (finding + " " + (impact or "")).lower()
    slop_hits = [m for m in _AI_SLOP_MARKERS if m in combined_slop]
    emoji_count = len(re.findall(_AI_SLOP_EMOJI_RE, finding + (impact or "")))
    slop_score = len(slop_hits) + (emoji_count // 2)
    if slop_score >= 3:
        warnings.append(
            f"[AI-SLOP RISK score={slop_score}] Finding/impact uses AI-template language: "
            f"{slop_hits[:5]}"
            + (f" + {emoji_count} emojis" if emoji_count else "")
            + ". Rhino.fi / similar platforms reject AI-spam. Rewrite naturally."
        )

    # --- Check 15: Scope drift detection (v13.2 — W7) ---
    # HackerOne #1 informative 원인: scope가 main URL만이고 wildcard 없는데
    # finding이 서브도메인/서브패스 명시
    if rules_content:
        scope_domains15 = _scope_domains_from_rules(rules_content)
        if scope_domains15 and not _parse_scope_has_wildcard(scope_domains15):
            # only main URLs in scope, no wildcards — strict scope
            combined15 = finding + " " + (impact or "")
            # detect mentioned hostnames in finding
            host_pattern = re.compile(
                r"\b([a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\b"
            )
            for m in host_pattern.finditer(combined15):
                candidate = m.group(1).lower()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", candidate):
                    continue  # IP, skip
                # check if candidate is an exact in-scope entry
                exact_match = False
                for d in scope_domains15:
                    dl = d.lower().replace("https://", "").replace("http://", "").rstrip("/")
                    if candidate == dl:
                        exact_match = True
                        break
                if not exact_match:
                    # is it a subdomain of a scope entry? If program has only
                    # main URL without wildcard, subdomain drift = informative risk
                    parent_hit = False
                    for d in scope_domains15:
                        dl = d.lower().replace("https://", "").replace("http://", "").rstrip("/")
                        if candidate.endswith("." + dl) and candidate != dl:
                            parent_hit = True
                            break
                    if parent_hit:
                        warnings.append(
                            f"[SCOPE DRIFT] Finding mentions '{candidate}' which is a subdomain "
                            f"of an in-scope asset, but program scope lists only main URLs "
                            f"without wildcards ({scope_domains15[:3]}). "
                            f"HackerOne #1 'Informative' cause. Verify scope wildcard wording."
                        )
                        break  # one warning sufficient

    # --- Check 16: Past incident cross-reference (v13.4 — G-W2 follow-up) ---
    # Scan knowledge/triage_objections/*.md for cases with overlapping finding
    # keywords. Raises a WARN with case-specific context so the user can see
    # "you're about to repeat the X incident".
    combined16 = (finding + " " + (impact or "")).lower()
    past_hits = _match_past_incidents(combined16, _detect_platform(rules_content) if rules_content else "unknown")
    for hit in past_hits[:3]:  # top-3 matches
        warnings.append(
            f"[PAST INCIDENT] Finding resembles '{hit['case']}' "
            f"({hit['outcome']} on {hit['platform']}, "
            f"overlap={hit['overlap']}): {hit['summary'][:180]}"
        )

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


def poc_pattern_check(submission_dir: str) -> tuple:
    """Static-analyse PoC .py files for Paradex-style anti-patterns.

    Detects three classes of defects that caused Paradex #72418 / #72759 autoban:
    1. try/except wrapping attack logic with hardcoded fallback values
    2. bare except (or except Exception) swallowing on-chain call failures
    3. assert statements that only compare Python literals (arithmetic simulation,
       no live on-chain read involved)

    Infrastructure files (name starts with devnet_, setup_, infra_) are skipped
    because they legitimately use try/except for process management.

    Returns: (warnings: list[str], hard_kills: list[str])
    """
    INFRA_PREFIXES = ("devnet_", "setup_", "infra_")
    ONCHAIN_ATTRS = ("starknet_call", "eth_call", "w3.", "rpc.", "contract.",
                     "web3.", "cast ", "forge ", "provider.", "client.")

    warnings: list = []
    hard_kills: list = []

    sdir = Path(submission_dir)
    py_files = list(sdir.glob("**/*.py"))

    for fpath in py_files:
        # Skip infrastructure files
        if fpath.name.startswith(INFRA_PREFIXES):
            continue

        try:
            source = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        try:
            tree = ast.parse(source, filename=str(fpath))
        except SyntaxError:
            # Unparseable file — skip AST checks, text-based checks already done
            continue

        rel = str(fpath.relative_to(sdir)) if fpath.is_relative_to(sdir) else str(fpath)

        for node in ast.walk(tree):
            # ---- Check 1 & 2: Try/Except patterns ----
            if isinstance(node, ast.Try):
                body_source = ast.unparse(node.body) if hasattr(ast, "unparse") else ""
                has_onchain = any(kw in body_source for kw in ONCHAIN_ATTRS)
                has_call = any(isinstance(n, ast.Call) for n in ast.walk(
                    ast.Module(body=node.body, type_ignores=[])))

                for handler in node.handlers:
                    handler_source = ast.unparse(handler) if hasattr(ast, "unparse") else ""

                    # Detect bare except / except Exception
                    is_broad = (
                        handler.type is None
                        or (isinstance(handler.type, ast.Name)
                            and handler.type.id == "Exception")
                        or (isinstance(handler.type, ast.Attribute)
                            and getattr(handler.type, "attr", "") == "Exception")
                    )

                    # Detect hardcoded fallback: assignment of a literal in handler body
                    has_literal_fallback = False
                    for stmt in handler.body:
                        if isinstance(stmt, ast.Assign):
                            for val in ast.walk(stmt.value):
                                if isinstance(val, (ast.Constant, ast.Tuple, ast.List)):
                                    has_literal_fallback = True
                                    break
                        elif isinstance(stmt, (ast.Return,)):
                            for val in ast.walk(stmt):
                                if isinstance(val, (ast.Constant, ast.Tuple, ast.List)):
                                    has_literal_fallback = True
                                    break

                    # Detect silent swallow: print + exit(0)
                    has_print_exit = (
                        "print(" in handler_source and "exit(0)" in handler_source
                    )

                    # HARD_KILL: on-chain call in try + broad except swallowing failure
                    if has_onchain and is_broad:
                        hard_kills.append(
                            f"[POC PATTERN] {rel}: broad except swallows on-chain call failure "
                            f"(try body contains on-chain interaction + bare/Exception handler). "
                            f"Paradex #72418 root cause: failures silenced → PoC appeared to succeed."
                        )

                    # HARD_KILL: attack logic in try + literal fallback in except
                    if has_call and has_literal_fallback:
                        hard_kills.append(
                            f"[POC PATTERN] {rel}: except handler assigns hardcoded literal "
                            f"fallback when attack call fails. "
                            f"This masks PoC failure and inflates claimed impact."
                        )

                    # HARD_KILL: silent swallow
                    if has_print_exit:
                        hard_kills.append(
                            f"[POC PATTERN] {rel}: except handler prints error then calls exit(0) "
                            f"— failure is silenced. PoC must exit non-zero on attack failure."
                        )

            # ---- Check 2b: contextlib.suppress swallowing attack logic ----
            # NH1 follow-up: `with contextlib.suppress(Exception): <on-chain call>`
            # is equivalent to a bare except and must be caught the same way.
            if isinstance(node, ast.With):
                with_source = ast.unparse(node) if hasattr(ast, "unparse") else ""
                body_source = ast.unparse(node.body) if hasattr(ast, "unparse") else ""
                has_onchain_w = any(kw in body_source for kw in ONCHAIN_ATTRS)
                has_call_w = any(
                    isinstance(n, ast.Call)
                    for n in ast.walk(ast.Module(body=list(node.body), type_ignores=[]))
                )

                def _is_broad_suppress(call: ast.Call) -> bool:
                    # Match suppress(...) or contextlib.suppress(...).
                    func = call.func
                    name = None
                    if isinstance(func, ast.Name):
                        name = func.id
                    elif isinstance(func, ast.Attribute):
                        name = func.attr
                    if name != "suppress":
                        return False
                    if not call.args:
                        return False
                    for arg in call.args:
                        arg_name = None
                        if isinstance(arg, ast.Name):
                            arg_name = arg.id
                        elif isinstance(arg, ast.Attribute):
                            arg_name = arg.attr
                        if arg_name in ("Exception", "BaseException"):
                            return True
                    return False

                for item in node.items:
                    cm = item.context_expr
                    if isinstance(cm, ast.Call) and _is_broad_suppress(cm):
                        if has_onchain_w or has_call_w:
                            hard_kills.append(
                                f"[POC PATTERN] {rel}: contextlib.suppress(Exception) swallows "
                                f"attack call (or on-chain interaction). "
                                f"Equivalent to bare except — use explicit failure handling."
                            )
                        break

            # ---- Check 3: Arithmetic-only assert ----
            if isinstance(node, ast.Assert):
                test = node.test

                def _is_pure_arithmetic(n: ast.expr) -> bool:
                    """True if expression is built entirely from literals + BinOp/UnaryOp."""
                    if isinstance(n, ast.Constant):
                        return True
                    if isinstance(n, (ast.BinOp, ast.UnaryOp)):
                        return all(_is_pure_arithmetic(c) for c in ast.walk(n)
                                   if c is not n and isinstance(c, ast.expr))
                    return False

                def _has_live_call(n: ast.expr) -> bool:
                    """True if expression contains any function call."""
                    return any(isinstance(c, ast.Call) for c in ast.walk(n))

                # assert <expr> == <expr> — check both sides
                if isinstance(test, ast.Compare):
                    lhs = test.left
                    rhs_list = test.comparators
                    all_rhs_arith = all(_is_pure_arithmetic(r) for r in rhs_list)
                    lhs_arith = _is_pure_arithmetic(lhs)
                    lhs_has_call = _has_live_call(lhs)
                    rhs_has_call = any(_has_live_call(r) for r in rhs_list)

                    if all_rhs_arith and lhs_arith and not lhs_has_call and not rhs_has_call:
                        warnings.append(
                            f"[ARITHMETIC ASSERT] {rel} line {node.lineno}: "
                            f"`{ast.unparse(node.test) if hasattr(ast, 'unparse') else 'assert ...'}` "
                            f"compares only Python literals — no on-chain read involved. "
                            f"Replace with assertion on live contract/RPC state."
                        )

    return warnings, hard_kills


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

    # --- Check -2: PoC static pattern analysis (v12.6 — Paradex #72418/#72759) ---
    print("[Gate 2 Pre-check] Running poc_pattern_check (static AST analysis)...")
    poc_warns, poc_kills = poc_pattern_check(submission_dir)
    warnings.extend(poc_warns)
    failures.extend(poc_kills)

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

    # --- Check: Report word count (v13.9.1 — AI detection risk) ---
    report_path = sdir / "report.md"
    if report_path.exists():
        try:
            report_text = report_path.read_text(errors="replace")
            report_wc = len(report_text.split())
            if report_wc > 2500:
                failures.append(
                    f"[WORD COUNT] report.md is {report_wc} words (hard cap: 2500). "
                    f"AI detection risk — triager flagged AI-generated on magiclabs (2026-04-23). "
                    f"Target 800-1200 words. Move variants/output to evidence files."
                )
            elif report_wc > 1500:
                warnings.append(
                    f"[WORD COUNT] report.md is {report_wc} words (soft cap: 1500). "
                    f"Trim to reduce AI suspicion. Target 800-1200 words."
                )
            else:
                print(f"  [WORD COUNT OK] report.md is {report_wc} words (under 1500)")
        except OSError:
            pass

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
    """Check that workflow_map.md exists and has semantically useful content.

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

    workflow_starts = list(re.finditer(r"^##+\s+workflow\b.*$", content, re.MULTILINE | re.IGNORECASE))
    issues = []
    if not workflow_starts:
        issues.append("No workflow sections found (expected ## Workflow headers)")
    else:
        for idx, match in enumerate(workflow_starts, start=1):
            start = match.start()
            end = workflow_starts[idx].start() if idx < len(workflow_starts) else len(content)
            section = content[start:end]
            section_title = match.group(0).strip()
            section_issues = _validate_workflow_section(section)
            for issue in section_issues:
                issues.append(f"{section_title}: {issue}")

    if issues:
        print("[FAIL] workflow_map.md structure incomplete:")
        for issue in issues:
            print("  →", issue)
        return 1

    print(
        "[PASS] workflow_map.md passes semantic validation "
        f"({len(workflow_starts)} workflows, {len(lines)} lines)"
    )
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


def _graphrag_duplicate_lookup(finding: str) -> dict[str, object]:
    """Try graph-backed similar-findings lookup via the local GraphRAG CLI."""
    import subprocess

    cli_path = Path(__file__).resolve().parent / "graphrag_cli.py"
    if not cli_path.exists():
        return {
            "available": False,
            "matched": False,
            "mode": "heuristic_fallback",
            "reason": "graphrag_cli_missing",
            "text": "",
        }

    try:
        result = subprocess.run(
            ["python3", str(cli_path), "--json", "similar", finding],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return {
            "available": False,
            "matched": False,
            "mode": "heuristic_fallback",
            "reason": f"graph_lookup_error:{type(exc).__name__}",
            "text": "",
        }

    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return {
            "available": False,
            "matched": False,
            "mode": "heuristic_fallback",
            "reason": f"graph_lookup_unparseable_rc_{result.returncode}",
            "text": (result.stdout or result.stderr or "")[:200],
        }

    if payload.get("env_gap") or result.returncode == 2:
        return {
            "available": False,
            "matched": False,
            "mode": "heuristic_fallback",
            "reason": "graph_env_gap",
            "text": payload.get("text", ""),
        }

    return {
        "available": True,
        "matched": bool(payload.get("matched")),
        "mode": "graph+heuristic",
        "reason": "graph_query_ok",
        "text": payload.get("text", ""),
    }


def duplicate_graph_check(target_dir: str, finding: str, json_output: bool = False) -> int:
    """Check finding against graph-backed hints plus local submission history.

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
    graph_lookup = _graphrag_duplicate_lookup(finding)
    if graph_lookup["available"] and graph_lookup["matched"]:
        duplicates.append({
            "source": "graphrag/similar_findings",
            "match_type": "Graph similarity",
            "detail": str(graph_lookup.get("text", ""))[:240],
        })

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
            "match_mode": graph_lookup["mode"],
            "graph_reason": graph_lookup["reason"],
            "matches": duplicates
        }
        print(json_module.dumps(result, indent=2))
    else:
        if has_duplicates:
            print("[WARN] Possible duplicates found: {} [{}]".format(len(duplicates), graph_lookup["mode"]))
            for dup in duplicates[:5]:  # Show top 5
                print("  →", dup.get("source", "unknown"), "| overlap:", dup.get("overlap_ratio", dup.get("match_type", "?")))
            print("  → Review these before submitting. May need differentiation argument.")
        else:
            print(
                "[PASS] No duplicates found for: {} [{}:{}]".format(
                    finding[:80], graph_lookup["mode"], graph_lookup["reason"]
                )
            )

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

    # v14: raw-bundle capture runs REGARDLESS of structured verdict. Even if
    # every handler fails, we still want verbatim landing HTML + linked pages
    # on disk so the operator (or Phase 0.2 verbatim-check) can work against
    # the authoritative substring source. This is the entire point of the
    # raw-bundle layer: independent of platform-specific parsers.
    try:
        from tools.program_fetcher.raw_bundle import capture as capture_raw_bundle
        bundle_summary = capture_raw_bundle(program_url, tdir)
        errs = bundle_summary.get("errors") or []
        linked_n = len(bundle_summary.get("linked_pages", []))
        spa_note = ""
        if bundle_summary.get("spa_escalation") == "playwright":
            effective = bundle_summary.get("spa_escalation_effective")
            spa_note = f" [SPA→Playwright {'hit' if effective else 'miss'}]"
        if errs:
            print(
                f"raw-bundle: landing + {linked_n} linked pages "
                f"({bundle_summary.get('bundle_md_bytes', 0)} bytes) "
                f"with {len(errs)} non-fatal error(s){spa_note}",
                file=sys.stderr,
            )
        else:
            print(
                f"raw-bundle: landing + {linked_n} linked pages "
                f"({bundle_summary.get('bundle_md_bytes', 0)} bytes){spa_note}",
                file=sys.stderr,
            )
    except Exception as e:
        # Raw-bundle failure must NOT break structured intake — bubble up
        # a warning so Phase 0.2 verbatim-check can flag missing bundle.md.
        print(
            f"raw-bundle: CAPTURE FAILED ({type(e).__name__}: {e}) — "
            "structured parse was still saved (if any); verbatim-check will ERROR",
            file=sys.stderr,
        )

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
        print("  → Template: see bb_pipeline_v13.md Phase 2 Strengthening Report section")
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

def historical_match(
    target_dir: str,
    finding: str = "",
    vuln_type: str = "",
    program: str = "",
    platform: str = "",
    json_output: bool = False,
) -> int:
    """Search knowledge/accepted_reports.db for similar accepted/rejected cases (v13.7).

    Calibrates kill-gate-1 with public-disclosure history. Designed to catch
    'this exact vuln class on this exact program was just closed as duplicate'
    patterns that triage_objections (which is local-only) misses.

    Exit codes:
      0 PASS  — no strong negative signal
      2 WARN  — recurring rejection pattern detected (advisory, not blocking)
      3 HARD  — same-program identical-vuln-type was closed duplicate/N/A within 30 days
                (use --strict to enable HARD blocking; default behaviour is WARN)
    """
    import sqlite3
    from pathlib import Path as _P

    db_path = _P(__file__).resolve().parent.parent / "knowledge" / "accepted_reports.db"
    if not db_path.exists():
        print(f"WARN: {db_path} missing. Run `python3 tools/accepted_reports_scraper.py ingest all` first.")
        return 0  # advisory only — never block on missing data

    # v14 (2026-04-18 codex review P1): split search terms from filter terms.
    # Previously all 4 were OR-joined in the FTS query, so passing just
    # `--platform bugcrowd` would match every row that mentioned Bugcrowd
    # anywhere, inflating the rejected-count and producing spurious WARNs.
    # Now: finding + vuln_type are FTS text search; program + platform are
    # SQL LIKE filters applied on top.
    search_terms = [t.strip() for t in (finding, vuln_type) if t and t.strip()]
    program_filter = program.strip() if program and program.strip() else ""
    platform_filter = platform.strip() if platform and platform.strip() else ""

    if not search_terms and not (program_filter or platform_filter):
        print("FAIL: historical-match requires at least one of --finding / --vuln-type / --program / --platform")
        return 1

    if search_terms:
        safe_terms = [t.replace('"', '""') for t in search_terms]
        fts_query = " OR ".join(f'"{t}"' for t in safe_terms)
    else:
        # No text search — use the program or platform as a broad FTS term
        # so SQLite FTS has something to MATCH against. LIKE filters narrow
        # the result set afterwards.
        broad = (program_filter or platform_filter).replace('"', '""')
        fts_query = f'"{broad}"'

    where_clauses = ["reports MATCH ?"]
    sql_params: list = [fts_query]
    if program_filter:
        where_clauses.append("lower(program) LIKE ?")
        sql_params.append(f"%{program_filter.lower()}%")
    if platform_filter:
        where_clauses.append("lower(platform) LIKE ?")
        sql_params.append(f"%{platform_filter.lower()}%")
    sql = (
        "SELECT source, platform, program, title, status, bounty, url, disclosed_at "
        "FROM reports WHERE " + " AND ".join(where_clauses)
        + " ORDER BY rank LIMIT 30"
    )

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(sql, sql_params).fetchall()
    except sqlite3.OperationalError as e:
        print(f"FAIL: FTS query error ({e}). Query was: {fts_query}")
        conn.close()
        return 1

    accepted_keywords = {"accepted", "resolved", "paid"}
    rejected_keywords = {
        "duplicate", "not applicable", "informative", "invalid",
        "spam", "out of scope", "self closed", "self-closed", "won't fix",
        "won t fix", "n/r", "not reproducible", "n/a",
    }
    other_keywords = {"published", "disclosed", "pending", "triage", "new", "curated"}

    accepted = [dict(r) for r in rows if r["status"].lower() in accepted_keywords]
    rejected = [dict(r) for r in rows if r["status"].lower() in rejected_keywords]
    other = [dict(r) for r in rows if r["status"].lower() in other_keywords]

    same_program_rejected = [
        r for r in rejected if program and program.lower() in (r["program"] or "").lower()
    ]

    if len(rejected) >= 3 and len(accepted) == 0:
        verdict = "WARN"
        verdict_msg = (
            f"{len(rejected)} similar findings rejected, 0 accepted in DB — "
            "history strongly suggests this finding class is rarely accepted."
        )
        exit_code = 2
    elif same_program_rejected:
        verdict = "WARN"
        verdict_msg = (
            f"Same program ({program}) has {len(same_program_rejected)} similar rejected findings "
            f"(top status: {same_program_rejected[0]['status']}). Calibrate expectations."
        )
        exit_code = 2
    elif accepted:
        verdict = "PASS"
        verdict_msg = (
            f"{len(accepted)} similar accepted/resolved findings found — proceed with confidence."
        )
        exit_code = 0
    else:
        verdict = "PASS"
        verdict_msg = (
            f"No strong negative or positive signal ({len(other)} disclosed, {len(rejected)} rejected). "
            "Insufficient public history — kill-gate-1 still applies normally."
        )
        exit_code = 0

    if json_output:
        print(json.dumps({
            "verdict": verdict,
            "exit_code": exit_code,
            "message": verdict_msg,
            "query": {
                "search_terms": search_terms,
                "program_filter": program_filter,
                "platform_filter": platform_filter,
                "fts": fts_query,
            },
            "counts": {
                "total": len(rows),
                "accepted": len(accepted),
                "rejected": len(rejected),
                "other": len(other),
                "same_program_rejected": len(same_program_rejected),
            },
            "top_accepted": accepted[:5],
            "top_rejected": rejected[:5],
            "same_program_rejected": same_program_rejected[:5],
        }, indent=2, default=str))
    else:
        print(f"# historical-match — {verdict}")
        print(f"\n{verdict_msg}\n")
        print(f"## Top accepted/resolved ({len(accepted)})")
        for r in accepted[:5]:
            print(f"  - [{r['source']:18s}] {r['program'][:30]:30s} — {(r['title'] or '')[:60]} ({r['bounty'] or '—'})")
        if not accepted:
            print("  (none)")
        print(f"\n## Top rejected ({len(rejected)})")
        for r in rejected[:5]:
            print(f"  - [{r['status']:18s}] {r['program'][:30]:30s} — {(r['title'] or '')[:60]}")
        if not rejected:
            print("  (none)")
        if same_program_rejected:
            print(f"\n## ⚠ Same-program rejected ({len(same_program_rejected)})")
            for r in same_program_rejected[:5]:
                print(f"  - [{r['status']:18s}] {(r['title'] or '')[:80]}")

    conn.close()
    return exit_code


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
    elif cmd == "verbatim-check":
        # Usage: verbatim-check <target_dir> [--strict] [--warn] [--json]
        strict = "--warn" not in sys.argv
        json_flag = "--json" in sys.argv
        sys.exit(verbatim_check(target, strict=strict, json_output=json_flag))
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
    elif cmd == "historical-match":
        # Usage: historical-match <target_dir> [--finding "<>"] [--vuln-type "<>"]
        #         [--program "<>"] [--platform "<>"] [--json]
        finding = ""
        vuln_type = ""
        program = ""
        platform_arg = ""
        json_flag = "--json" in sys.argv
        args = sys.argv[3:]
        for i, arg in enumerate(args):
            if arg == "--finding" and i + 1 < len(args):
                finding = args[i + 1]
            elif arg == "--vuln-type" and i + 1 < len(args):
                vuln_type = args[i + 1]
            elif arg == "--program" and i + 1 < len(args):
                program = args[i + 1]
            elif arg == "--platform" and i + 1 < len(args):
                platform_arg = args[i + 1]
        sys.exit(historical_match(target, finding, vuln_type, program, platform_arg, json_flag))
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
