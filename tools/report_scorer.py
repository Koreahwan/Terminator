#!/usr/bin/env python3
"""Report Quality Scorer for Terminator Bug Bounty Pipeline.

Scores vulnerability reports across 5 dimensions, returns structured JSON
with composite score and priority fixes. Integrates into Phase 3 quality loop.

Usage:
    python3 tools/report_scorer.py <report.md> [--json] [--threshold 75]
    python3 tools/report_scorer.py <report.md> --poc-dir evidence/

Exit: 0=PASS (composite >= threshold), 1=FAIL (below threshold)
"""

import argparse
import json
import re
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tools import areuai_bridge

# ---------------------------------------------------------------------------
# Dimension weights (sum = 1.0)
# ---------------------------------------------------------------------------
WEIGHTS = {
    "evidence_completeness": 0.30,
    "impact_clarity": 0.25,
    "reproducibility": 0.20,
    "triage_readability": 0.15,
    "ai_slop": 0.10,
}

DEFAULT_THRESHOLD = 75

# ---------------------------------------------------------------------------
# AI slop patterns (from seomachine editor + Terminator slop-check)
# ---------------------------------------------------------------------------
AI_SLOP_PHRASES = [
    r"\bin today'?s\b.*\b(landscape|world|era|age)\b",
    r"\bit is important to note\b",
    r"\bin conclusion\b",
    r"\bcomprehensive\b",
    r"\brobust\b",
    r"\bseamless(ly)?\b",
    r"\bleverag(e|ing)\b",
    r"\butiliz(e|ing)\b",
    r"\bin order to\b",
    r"\bdue to the fact that\b",
    r"\bgoing forward\b",
    r"\bat the end of the day\b",
    r"\bfurthermore\b",
    r"\bmoreover\b",
    r"\bnevertheless\b",
    r"\bnotwithstanding\b",
    r"\bit should be noted\b",
    r"\bneedless to say\b",
    r"\bparadigm\b",
    r"\bsynerg(y|ies|istic)\b",
    r"\bholistic\b",
    r"\bcutting.?edge\b",
    r"\bstate.?of.?the.?art\b",
    r"\bgame.?chang(er|ing)\b",
]

OBSERVATIONAL_VIOLATIONS = [
    r"\bwe discovered\b",
    r"\bwe found\b",
    r"\bwe identified\b",
    r"\bthe vulnerability exists\b",
    r"\bthis proves\b",
    r"\bobviously\b",
    r"\btrivially\b",
    r"\bclearly\b",
    r"\bundoubtedly\b",
]

CLIENT_PITCH_PROHIBITED = [
    r"\bconfirmed vulnerability\b",
    r"\bexploit succeeded\b",
    r"\bdata exposed\b",
    r"\battacker can definitely\b",
    r"\bsubmission[- ]ready\b",
]

PASSIVE_VOICE_PATTERN = re.compile(
    r"\b(is|are|was|were|be|been|being)\s+(being\s+)?"
    r"(found|discovered|identified|noted|observed|considered|seen|regarded|"
    r"thought|believed|known|assumed|expected|supposed|reported|said|claimed)\b",
    re.IGNORECASE,
)

EM_DASH_PATTERN = re.compile(r"\u2014")


@dataclass
class Fix:
    location: str
    dimension: str
    issue: str
    fix: str
    severity: str  # critical, high, medium, low


@dataclass
class ScoreResult:
    evidence_completeness: int = 0
    impact_clarity: int = 0
    reproducibility: int = 0
    triage_readability: int = 0
    ai_slop: int = 0
    composite: float = 0.0
    passed: bool = False
    threshold: int = DEFAULT_THRESHOLD
    priority_fixes: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Scoring functions
# ---------------------------------------------------------------------------

def score_evidence_completeness(text: str, poc_dir: Path | None) -> tuple[int, list[Fix]]:
    """Score evidence quality: PoC presence, output, steps, screenshots."""
    score = 100
    fixes = []

    # Check for PoC section
    if not re.search(r"(?i)proof\s+of\s+concept|poc|reproduction|exploit", text):
        score -= 40
        fixes.append(Fix(
            "Report body", "evidence_completeness",
            "No PoC/Reproduction section found",
            "Add a 'Proof of Concept' section with reproduction steps and script",
            "critical",
        ))

    # Check for code blocks (PoC commands)
    code_blocks = re.findall(r"```[\s\S]*?```", text)
    if len(code_blocks) < 2:
        score -= 20
        fixes.append(Fix(
            "PoC section", "evidence_completeness",
            f"Only {len(code_blocks)} code block(s) found, need >= 2 (command + output)",
            "Add code blocks showing both the PoC command and its output",
            "high",
        ))

    # Check for evidence output (timestamps, HTTP responses)
    has_timestamp = bool(re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}", text))
    has_http = bool(re.search(r"HTTP/[12]\.\d\s+\d{3}", text))
    has_output = has_timestamp or has_http
    if not has_output:
        score -= 15
        fixes.append(Fix(
            "Evidence section", "evidence_completeness",
            "No timestamped output or HTTP response evidence found",
            "Include captured output with timestamps or HTTP response codes",
            "high",
        ))

    # Check for file:line references
    file_refs = re.findall(r"[\w/.-]+\.(js|ts|py|go|rs|c|cpp|java|sol|rb|php):\d+", text)
    if len(file_refs) < 1:
        score -= 10
        fixes.append(Fix(
            "Technical Analysis", "evidence_completeness",
            "No file:line references found in report",
            "Add exact source code references (e.g., auth.js:42)",
            "medium",
        ))

    # Check evidence directory
    if poc_dir and poc_dir.exists():
        evidence_files = list(poc_dir.iterdir())
        if len(evidence_files) < 2:
            score -= 15
            fixes.append(Fix(
                "evidence/ directory", "evidence_completeness",
                f"Evidence directory has only {len(evidence_files)} file(s)",
                "Add PoC script + output capture to evidence directory",
                "high",
            ))
    elif poc_dir:
        score -= 15
        fixes.append(Fix(
            "evidence/ directory", "evidence_completeness",
            "Evidence directory not found",
            f"Create {poc_dir} with PoC script and output files",
            "high",
        ))

    return max(0, score), fixes


def score_impact_clarity(text: str) -> tuple[int, list[Fix]]:
    """Score impact assessment quality: CVSS, business impact, scenarios."""
    score = 100
    fixes = []

    # Check for CVSS vector
    has_cvss = bool(re.search(r"CVSS\s*[34]\.\d|AV:[NALP]/AC:[LH]", text))
    if not has_cvss:
        score -= 25
        fixes.append(Fix(
            "Summary section", "impact_clarity",
            "No CVSS vector string found",
            "Add CVSS 3.1/4.0 vector string computed programmatically",
            "critical",
        ))

    # Check for CWE
    has_cwe = bool(re.search(r"CWE-\d+", text))
    if not has_cwe:
        score -= 15
        fixes.append(Fix(
            "Summary section", "impact_clarity",
            "No CWE identifier found",
            "Add CWE classification (e.g., CWE-639 for IDOR)",
            "high",
        ))

    # Check for Conditional CVSS table
    has_conditional = bool(re.search(r"(?i)conditional\s+cvss|scenario.*adjustment.*score", text))
    if not has_conditional:
        score -= 15
        fixes.append(Fix(
            "Impact section", "impact_clarity",
            "No Conditional CVSS table found",
            "Add table with at least 2 scenarios (intended behavior + confirmed vuln)",
            "medium",
        ))

    # Check for attack chain / numbered steps
    attack_steps = re.findall(r"(?m)^\s*\d+\.\s+.*(step|attacker|request|send|call|trigger)", text, re.IGNORECASE)
    if len(attack_steps) < 2:
        score -= 15
        fixes.append(Fix(
            "Attack Chain section", "impact_clarity",
            f"Only {len(attack_steps)} attack step(s) found, need >= 3",
            "Add numbered attack chain steps (precondition → action → result)",
            "high",
        ))

    # Check for executive conclusion at top
    first_500 = text[:500]
    has_exec = bool(re.search(r"(?i)executive\s+conclusion|executive\s+summary|tl;?dr", first_500))
    if not has_exec:
        score -= 10
        fixes.append(Fix(
            "Report opening", "impact_clarity",
            "No Executive Conclusion in first 500 chars",
            "Add 3-sentence Executive Conclusion as the first thing triager reads",
            "high",
        ))

    # Check for severity honesty
    has_honesty = bool(re.search(r"(?i)honest\s+severity|expect\s+triager|we\s+expect", text))
    if not has_honesty:
        score -= 10
        fixes.append(Fix(
            "Summary section", "impact_clarity",
            "No honest severity expectation statement",
            "Add 'Honest Severity Expectation: We expect triager to rate this X because Y'",
            "medium",
        ))

    # Check for remediation
    has_remediation = bool(re.search(r"(?i)remediation|fix|mitigation|recommendation", text))
    if not has_remediation:
        score -= 10
        fixes.append(Fix(
            "Report body", "impact_clarity",
            "No remediation section found",
            "Add 3-layer remediation (Quick Win + Defense in Depth + Architectural)",
            "medium",
        ))

    return max(0, score), fixes


def score_reproducibility(text: str) -> tuple[int, list[Fix]]:
    """Score reproduction clarity: steps, environment, prerequisites."""
    score = 100
    fixes = []

    # Check for numbered reproduction steps
    repro_steps = re.findall(r"(?m)^\s*\d+\.\s+", text)
    if len(repro_steps) < 3:
        score -= 30
        fixes.append(Fix(
            "PoC section", "reproducibility",
            f"Only {len(repro_steps)} numbered step(s), need >= 3 for clear reproduction",
            "Add numbered step-by-step reproduction instructions",
            "critical",
        ))

    # Check for curl/HTTP commands or script references
    has_commands = bool(re.search(r"(?i)curl\s|fetch\(|requests\.|\.py|\.sh|\.js", text))
    if not has_commands:
        score -= 20
        fixes.append(Fix(
            "PoC section", "reproducibility",
            "No executable commands or script references found",
            "Add curl commands or reference to PoC script",
            "high",
        ))

    # Check for environment/version info
    has_env = bool(re.search(r"(?i)version|v\d+\.\d+|environment|platform|endpoint|url|https?://", text))
    if not has_env:
        score -= 15
        fixes.append(Fix(
            "Summary/Prerequisites", "reproducibility",
            "No version or environment information found",
            "Add affected version, target URL, and environment details",
            "high",
        ))

    # Check for prerequisites/preconditions
    has_prereq = bool(re.search(r"(?i)prerequisite|precondition|requires?|need|must\s+have|setup", text))
    if not has_prereq:
        score -= 15
        fixes.append(Fix(
            "Attack Chain", "reproducibility",
            "No prerequisites/preconditions specified",
            "List what attacker needs (account type, permissions, network access)",
            "medium",
        ))

    # Check for expected vs actual output
    has_expected = bool(re.search(r"(?i)expected|actual|result|response|output|return", text))
    if not has_expected:
        score -= 10
        fixes.append(Fix(
            "PoC section", "reproducibility",
            "No expected/actual comparison in output",
            "Show what response is expected vs what was actually received",
            "medium",
        ))

    word_count = len(text.split())

    return max(0, score), fixes


def score_triage_readability(text: str) -> tuple[int, list[Fix]]:
    """Score readability for triage analysts: structure, scannability, clarity."""
    score = 100
    fixes = []

    # Check heading structure
    h2_count = len(re.findall(r"(?m)^##\s+", text))
    if h2_count < 3:
        score -= 20
        fixes.append(Fix(
            "Report structure", "triage_readability",
            f"Only {h2_count} H2 section(s), need >= 3 for scannable structure",
            "Add sections: Summary, Technical Analysis, PoC, Impact, Remediation",
            "high",
        ))

    # Check first 3 sentences convey the finding
    first_para = text.split("\n\n")[0] if "\n\n" in text else text[:300]
    first_sentences = re.split(r"[.!?]\s+", first_para)[:3]
    total_first_words = sum(len(s.split()) for s in first_sentences)
    if total_first_words > 120:
        score -= 15
        fixes.append(Fix(
            "Opening paragraph", "triage_readability",
            f"First 3 sentences are {total_first_words} words; too verbose for quick triage",
            "First 3 sentences should be under 80 words total: what, how, impact",
            "high",
        ))

    # Check paragraph length (no walls of text)
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    long_paras = [p for p in paragraphs if len(p.split()) > 100]
    if long_paras:
        score -= 10
        fixes.append(Fix(
            "Multiple locations", "triage_readability",
            f"{len(long_paras)} paragraph(s) exceed 100 words",
            "Break long paragraphs into shorter ones (4-5 sentences max)",
            "medium",
        ))

    # Check for bullet points / lists (scannability)
    bullet_count = len(re.findall(r"(?m)^\s*[-*]\s+", text))
    if bullet_count < 3:
        score -= 10
        fixes.append(Fix(
            "Report body", "triage_readability",
            "Few bullet points found; report may be hard to scan",
            "Use bullet lists for attack steps, impact items, prerequisites",
            "low",
        ))

    # Check for table usage
    has_table = bool(re.search(r"\|.*\|.*\|", text))
    if not has_table:
        score -= 5
        fixes.append(Fix(
            "Report body", "triage_readability",
            "No tables found (Conditional CVSS, component info, etc.)",
            "Add at least one table for structured data presentation",
            "low",
        ))

    # Average sentence length
    sentences = re.split(r"[.!?]\s+", text)
    sentences = [s for s in sentences if len(s.split()) > 2]
    if sentences:
        avg_len = sum(len(s.split()) for s in sentences) / len(sentences)
        if avg_len > 30:
            score -= 10
            fixes.append(Fix(
                "Overall", "triage_readability",
                f"Average sentence length is {avg_len:.0f} words (target: < 25)",
                "Break complex sentences into shorter ones",
                "medium",
            ))

    return max(0, score), fixes


def score_ai_slop(text: str) -> tuple[int, list[Fix]]:
    """Score AI signature absence: slop phrases, observational violations, em-dashes."""
    score = 100
    fixes = []
    bridge_result = areuai_bridge.analyze_text(text, mode="report")
    bridge_score = float(bridge_result.get("score", 0))
    if bridge_score > 2:
        penalty = min(50, int(round(bridge_score * 8)))
        score -= penalty
        spans = bridge_result.get("spans", [])[:5]
        issues = ", ".join(str(s.get("text", s.get("pattern_id", ""))) for s in spans) or "areuai patterns"
        fixes.append(Fix(
            "Throughout report", "ai_slop",
            f"areuai score {bridge_score:.1f}/10 detected: {issues}",
            "Run areuai suggest/evade, then replace generic wording with target-specific technical facts",
            "critical" if bridge_score > 5 else "high" if bridge_score > 2 else "medium",
        ))
        if bridge_score > 5:
            return max(0, score), fixes
    text_lower = text.lower()

    # Check AI slop phrases
    slop_hits = []
    for pattern in AI_SLOP_PHRASES:
        matches = re.findall(pattern, text_lower)
        if matches:
            slop_hits.append((pattern, len(matches)))

    if slop_hits:
        penalty = min(40, len(slop_hits) * 8)
        score -= penalty
        top_hits = slop_hits[:3]
        fixes.append(Fix(
            "Throughout report", "ai_slop",
            f"{len(slop_hits)} AI slop pattern(s) detected: {', '.join(p for p, _ in top_hits)}",
            "Replace with target-specific technical language",
            "critical" if len(slop_hits) > 3 else "high",
        ))

    # Check observational language violations
    obs_hits = []
    for pattern in OBSERVATIONAL_VIOLATIONS:
        matches = re.findall(pattern, text_lower)
        if matches:
            obs_hits.append((pattern, len(matches)))

    if obs_hits:
        penalty = min(25, len(obs_hits) * 10)
        score -= penalty
        fixes.append(Fix(
            "Throughout report", "ai_slop",
            f"{len(obs_hits)} observational language violation(s)",
            "Use 'Testing revealed', 'Identified in reviewed implementation' instead",
            "high",
        ))

    # Check em-dash overuse
    em_dash_count = len(EM_DASH_PATTERN.findall(text))
    if em_dash_count > 5:
        score -= min(15, (em_dash_count - 5) * 3)
        fixes.append(Fix(
            "Throughout report", "ai_slop",
            f"{em_dash_count} em-dashes found (AI overuse pattern)",
            "Replace em-dashes with commas, semicolons, or periods as appropriate",
            "medium",
        ))

    # Check passive voice ratio
    passive_matches = PASSIVE_VOICE_PATTERN.findall(text)
    sentences = re.split(r"[.!?]\s+", text)
    sentence_count = max(1, len([s for s in sentences if len(s.split()) > 2]))
    passive_ratio = len(passive_matches) / sentence_count
    if passive_ratio > 0.3:
        score -= 10
        fixes.append(Fix(
            "Throughout report", "ai_slop",
            f"Passive voice ratio: {passive_ratio:.0%} (target: < 30%)",
            "Rewrite passive constructions to active voice",
            "medium",
        ))

    # Word count gate (v13.9.1 — AI detection: human hunters write 500-1200 words)
    word_count = len(text.split())
    if word_count > 2500:
        score -= 30
        fixes.append(Fix(
            "Overall", "ai_slop",
            f"Report is {word_count} words (hard cap: 2500). Major AI detection risk",
            "Move variant tables and PoC output to separate evidence files. Target 800-1200 words",
            "high",
        ))
    elif word_count > 1500:
        score -= 15
        fixes.append(Fix(
            "Overall", "ai_slop",
            f"Report is {word_count} words (soft cap: 1500). Trim to avoid AI suspicion",
            "Cut background/history sections, inline only key PoC output, reference evidence files",
            "medium",
        ))

    return max(0, score), fixes


# ---------------------------------------------------------------------------
# Main scorer
# ---------------------------------------------------------------------------

def score_client_pitch_boundaries(text: str) -> tuple[int, list[Fix]]:
    """Score passive-only client pitch language and required sales artifacts."""
    score = 100
    fixes: list[Fix] = []
    for pattern in CLIENT_PITCH_PROHIBITED:
        if re.search(pattern, text, re.I):
            score -= 25
            fixes.append(Fix(
                "Client pitch body",
                "triage_readability",
                f"Client pitch uses prohibited confirmed-finding language: {pattern}",
                "Rewrite as a risk signal or recommended assessment area, not a proven vulnerability",
                "critical",
            ))
    required = [
        ("risk signal", r"(?i)risk signal|candidate|needs verification|requires.*review"),
        ("recommended scope", r"(?i)recommended.*scope|proposed assessment|assessment scope"),
        ("no destructive testing", r"(?i)no destructive testing|passive|authorization"),
    ]
    for label, pattern in required:
        if not re.search(pattern, text):
            score -= 15
            fixes.append(Fix(
                "Client pitch body",
                "impact_clarity",
                f"Missing client-pitch marker: {label}",
                f"Add a concise {label} statement",
                "high",
            ))
    return max(0, score), fixes


def score_report(report_path: str, poc_dir: str | None = None, threshold: int = DEFAULT_THRESHOLD, mode: str = "bounty") -> ScoreResult:
    path = Path(report_path)
    if not path.exists():
        print(f"Error: Report not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    text = path.read_text(encoding="utf-8")
    poc_path = Path(poc_dir) if poc_dir else None

    result = ScoreResult(threshold=threshold)
    all_fixes: list[Fix] = []

    # Score each dimension. Client-pitch is passive sales material, so it must
    # not be punished for missing exploit evidence; it is scored on boundary
    # language instead.
    if mode == "client-pitch":
        result.evidence_completeness = 100
        result.reproducibility = 100
        boundary_score, fixes = score_client_pitch_boundaries(text)
        result.impact_clarity = boundary_score
        result.triage_readability = boundary_score
        all_fixes.extend(fixes)
    else:
        result.evidence_completeness, fixes = score_evidence_completeness(text, poc_path)
        all_fixes.extend(fixes)

        result.impact_clarity, fixes = score_impact_clarity(text)
        all_fixes.extend(fixes)

    if mode != "client-pitch":
        result.reproducibility, fixes = score_reproducibility(text)
        all_fixes.extend(fixes)

    if mode != "client-pitch":
        result.triage_readability, fixes = score_triage_readability(text)
        all_fixes.extend(fixes)

    result.ai_slop, fixes = score_ai_slop(text)
    all_fixes.extend(fixes)

    # Compute weighted composite
    result.composite = round(
        result.evidence_completeness * WEIGHTS["evidence_completeness"]
        + result.impact_clarity * WEIGHTS["impact_clarity"]
        + result.reproducibility * WEIGHTS["reproducibility"]
        + result.triage_readability * WEIGHTS["triage_readability"]
        + result.ai_slop * WEIGHTS["ai_slop"],
        1,
    )
    result.passed = result.composite >= threshold

    # Sort fixes by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_fixes.sort(key=lambda f: severity_order.get(f.severity, 99))
    result.priority_fixes = [asdict(f) for f in all_fixes]

    return result


def print_human(result: ScoreResult, report_path: str) -> None:
    status = "PASS" if result.passed else "FAIL"
    print(f"\n{'=' * 60}")
    print(f"Report Quality Score: {report_path}")
    print(f"{'=' * 60}")
    print(f"\n  Evidence Completeness (30%):  {result.evidence_completeness}/100")
    print(f"  Impact Clarity       (25%):  {result.impact_clarity}/100")
    print(f"  Reproducibility      (20%):  {result.reproducibility}/100")
    print(f"  Triage Readability   (15%):  {result.triage_readability}/100")
    print(f"  AI Slop Score        (10%):  {result.ai_slop}/100")
    print(f"\n  Composite: {result.composite}/100  [{status}]  (threshold: {result.threshold})")

    if result.priority_fixes:
        print(f"\n  Priority Fixes ({len(result.priority_fixes)}):")
        for i, fix in enumerate(result.priority_fixes[:10], 1):
            sev = fix["severity"].upper()
            print(f"    {i}. [{sev}] {fix['location']}: {fix['issue']}")
            print(f"       Fix: {fix['fix']}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Score vulnerability report quality across 5 dimensions"
    )
    parser.add_argument("report", help="Path to report markdown file")
    parser.add_argument("--poc-dir", help="Path to evidence/PoC directory")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                        help=f"Pass threshold (default: {DEFAULT_THRESHOLD})")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--mode", choices=["bounty", "client-pitch"], default="bounty",
                        help="Report mode (default: bounty)")
    args = parser.parse_args()

    result = score_report(args.report, args.poc_dir, args.threshold, args.mode)

    if args.json:
        print(json.dumps(asdict(result), indent=2, ensure_ascii=False))
    else:
        print_human(result, args.report)

    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()
