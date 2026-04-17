#!/usr/bin/env python3
"""3-Layer AI Detection System — Pre-submission report humanness check.

Immunefi postmortem: Rhino.fi "AI spam" marking → accuracy tank → autoban.
This tool ensures reports don't trigger AI detection before submission.

Layer 1: Enhanced heuristic analysis (pattern matching, statistical)
Layer 2: Claude self-review prompt generation (for in-session use)
Layer 3: ZeroGPT web check via Playwright MCP (browser automation)

Usage:
    ai_detect.py heuristic <file>              Layer 1: enhanced pattern analysis
    ai_detect.py self-review-prompt <file>     Layer 2: generate Claude self-review prompt
    ai_detect.py zerogpt-instructions <file>   Layer 3: print Playwright MCP steps for ZeroGPT
    ai_detect.py full <file>                   Run Layer 1 + generate Layer 2+3 instructions

Exit: 0=PASS (human-like), 1=WARN (borderline), 2=FAIL (AI-detected)

Created: 2026-04-07 (Immunefi postmortem — AI spam defense)
"""

import sys
import re
import math
from pathlib import Path
from collections import Counter


# ─── Layer 1: Enhanced Heuristic Analysis ────────────────────────────────

# AI template phrases (weighted by suspicion level)
TEMPLATE_PHRASES = {
    # High suspicion (1.0 each)
    "it is important to note": 1.0,
    "it should be noted": 1.0,
    "it is worth noting": 1.0,
    "it is crucial to": 1.0,
    "in conclusion": 1.0,
    "in summary": 1.0,
    "as mentioned earlier": 1.0,
    "as previously discussed": 1.0,
    "comprehensive analysis": 1.0,
    "thorough examination": 1.0,
    "holistic approach": 1.0,
    "robust mechanism": 1.0,
    "robust implementation": 1.0,
    "delve into": 1.0,
    "delve deeper": 1.0,
    "multifaceted": 1.0,
    "paradigm": 1.0,
    "synergy": 1.0,
    "leverage this": 1.0,
    "utilizing this": 1.0,
    "facilitates": 0.8,
    "seamlessly": 1.0,
    "subsequently": 0.8,
    "consequently": 0.6,
    "furthermore": 0.6,
    "moreover": 0.6,
    "additionally": 0.5,
    "notably": 0.5,
    "specifically": 0.3,
    "importantly": 0.5,
    # Medium suspicion (0.5 each)
    "this vulnerability": 0.5,
    "this attack": 0.3,
    "the attacker can": 0.3,
    "an attacker could": 0.5,
    "a malicious actor": 0.8,
    "a malicious user": 0.5,
    "significant impact": 0.5,
    "significant risk": 0.5,
    "severe implications": 0.8,
    "security implications": 0.5,
    "potential impact": 0.5,
    "critical vulnerability": 0.3,
}

# Uncertain / hedging language (triagers hate this)
HEDGE_PHRASES = {
    "could potentially": 1.0,
    "might potentially": 1.0,
    "would potentially": 1.0,
    "theoretically": 0.8,
    "presumably": 0.8,
    "it is believed": 1.0,
    "appears to be": 0.5,
    "seems to be": 0.5,
    "most likely": 0.5,
    "probably": 0.3,
    "should work": 0.5,
    "may lead to": 0.3,
    "could lead to": 0.3,
}

# Positive signals (human-like, deductions)
HUMAN_SIGNALS = [
    (r"0x[0-9a-fA-F]{8,}", -2.0, "hex address/hash"),
    (r"block\s*#?\d{6,}", -2.0, "block number"),
    (r"tx\s*(?:hash)?:?\s*0x[0-9a-fA-F]{20,}", -2.5, "transaction hash"),
    (r"[a-zA-Z_]+\.[a-z]{2,4}:\d+", -1.5, "file:line reference"),
    (r"```[\s\S]{20,}```", -1.5, "code block with content"),
    (r"curl\s+-", -1.5, "curl command"),
    (r"HTTP/\d\.\d\s+\d{3}", -1.5, "HTTP response"),
    (r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", -1.0, "ISO timestamp"),
    (r"CVE-\d{4}-\d+", -0.5, "CVE reference"),
    (r"CWE-\d+", -0.3, "CWE reference"),
    (r"eyJ[a-zA-Z0-9_-]{10,}", -1.0, "JWT token"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", -1.0, "IP address"),
    (r"cast\s+(?:call|send|block)", -1.5, "foundry cast command"),
    (r"forge\s+test", -1.5, "foundry forge test"),
]


def _sentence_stats(text: str) -> dict:
    """Compute sentence-level statistics that distinguish AI from human text."""
    sentences = re.split(r'[.!?]+\s+', text)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 10]

    if len(sentences) < 3:
        return {"count": len(sentences), "avg_len": 0, "std_len": 0, "uniformity": 0}

    lengths = [len(s.split()) for s in sentences]
    avg = sum(lengths) / len(lengths)
    variance = sum((l - avg) ** 2 for l in lengths) / len(lengths)
    std = math.sqrt(variance)

    # AI text tends to have very uniform sentence lengths
    # Human text has more variation (short punchy + long detailed)
    uniformity = 1.0 - min(std / max(avg, 1), 1.0)  # 0=varied(human), 1=uniform(AI)

    return {
        "count": len(sentences),
        "avg_len": avg,
        "std_len": std,
        "uniformity": uniformity,
    }


def _paragraph_starts(text: str) -> float:
    """Check if paragraphs start with similar patterns (AI tendency)."""
    paragraphs = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 20]
    if len(paragraphs) < 3:
        return 0

    # Extract first 3 words of each paragraph
    starts = []
    for p in paragraphs:
        words = p.split()[:3]
        starts.append(" ".join(words).lower())

    # Check for repetitive openings
    first_words = [s.split()[0] if s.split() else "" for s in starts]
    counter = Counter(first_words)
    most_common_count = counter.most_common(1)[0][1] if counter else 0
    repetition_ratio = most_common_count / len(first_words)

    # >50% paragraphs start with same word = AI signal
    return max(0, (repetition_ratio - 0.3) * 3)  # 0-2.1 range


def heuristic_check(filepath: str) -> int:
    """Layer 1: Enhanced heuristic AI detection."""
    path = Path(filepath)
    if not path.exists():
        print(f"ERROR: File not found: {filepath}")
        return 2

    text = path.read_text(encoding="utf-8", errors="replace")
    text_lower = text.lower()
    word_count = len(text.split())

    if word_count < 50:
        print(f"[L1] File too short ({word_count} words) — skipping heuristic check")
        return 0

    score = 0.0
    details = []

    # 1. Template phrase detection
    template_score = 0
    template_hits = []
    for phrase, weight in TEMPLATE_PHRASES.items():
        count = text_lower.count(phrase)
        if count > 0:
            template_score += weight * count
            template_hits.append(f"'{phrase}' x{count}")
    if template_score > 0:
        details.append(f"Template phrases ({template_score:.1f}): {', '.join(template_hits[:5])}")
    score += template_score

    # 2. Hedge phrase detection
    hedge_score = 0
    hedge_hits = []
    for phrase, weight in HEDGE_PHRASES.items():
        count = text_lower.count(phrase)
        if count > 0:
            hedge_score += weight * count
            hedge_hits.append(f"'{phrase}' x{count}")
    if hedge_score > 0:
        details.append(f"Hedge phrases ({hedge_score:.1f}): {', '.join(hedge_hits[:5])}")
    score += hedge_score

    # 3. Sentence uniformity (AI = uniform lengths)
    stats = _sentence_stats(text)
    if stats["uniformity"] > 0.7:
        uniformity_penalty = (stats["uniformity"] - 0.5) * 4  # 0-2 range
        score += uniformity_penalty
        details.append(f"Sentence uniformity: {stats['uniformity']:.2f} (penalty: +{uniformity_penalty:.1f})")

    # 4. Paragraph opening repetition
    para_score = _paragraph_starts(text)
    if para_score > 0:
        score += para_score
        details.append(f"Repetitive paragraph openings: +{para_score:.1f}")

    # 5. Structural AI signals (catches disguised AI — no template phrases but AI structure)
    structural_score = 0
    structural_details = []

    # 5a. Passive voice ratio (AI overuses passive)
    passive_patterns = re.findall(
        r'\b(?:is|are|was|were|be|been|being)\s+(?:\w+ed|validated|identified|observed|'
        r'discovered|detected|found|noted|determined|processed|handled|implemented|'
        r'performed|executed|granted|leaked|accepted|created)\b',
        text_lower
    )
    passive_ratio = len(passive_patterns) / max(stats["count"], 1)
    if passive_ratio > 0.3:
        penalty = (passive_ratio - 0.2) * 5  # 0-4 range
        structural_score += penalty
        structural_details.append(f"passive voice {passive_ratio:.0%} (+{penalty:.1f})")

    # 5b. "The [noun]" sentence starts (AI pattern: "The application", "The vulnerability", "The server")
    the_starts = len(re.findall(r'(?:^|\n)\s*The\s+[a-z]+', text))
    the_ratio = the_starts / max(stats["count"], 1)
    if the_ratio > 0.3:
        penalty = (the_ratio - 0.2) * 4
        structural_score += penalty
        structural_details.append(f"'The X' sentence starts {the_ratio:.0%} (+{penalty:.1f})")

    # 5c. Lack of specific values (AI generates generic descriptions without real data)
    specific_values = len(re.findall(
        r'(?:0x[0-9a-fA-F]{6,}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'eyJ[a-zA-Z0-9_-]{10,}|[a-f0-9]{32,}|'
        r':\d{2,5}[/\s]|HTTP/\d|status.?(?:code)?:?\s*\d{3}|'
        r'port\s+\d{2,5}|\b\d{4}-\d{2}-\d{2}\b)',
        text
    ))
    if word_count > 100 and specific_values == 0:
        structural_score += 2.0
        structural_details.append("no specific values/hashes/IPs/dates (+2.0)")

    # 5d. "This [verb]s" pattern (AI: "This allows", "This enables", "This occurs", "This vulnerability")
    this_pattern = len(re.findall(r'\bthis\s+(?:allows|enables|occurs|results|means|represents|'
                                   r'ensures|prevents|causes|grants|permits|facilitates|affects)\b', text_lower))
    if this_pattern >= 3:
        penalty = min(this_pattern * 0.5, 2.0)
        structural_score += penalty
        structural_details.append(f"'This [verb]s' x{this_pattern} (+{penalty:.1f})")

    # 5e. Numbered list of generic steps without real data
    generic_steps = re.findall(r'^\s*\d+\.\s+(?:Navigate|Send|Observe|Verify|Log in|Intercept|Forward|Check)\b',
                                text, re.MULTILINE)
    if len(generic_steps) >= 4:
        penalty = 1.5
        structural_score += penalty
        structural_details.append(f"generic numbered steps x{len(generic_steps)} (+{penalty:.1f})")

    if structural_score > 0:
        score += structural_score
        details.append(f"Structural AI signals ({structural_score:.1f}): {', '.join(structural_details)}")

    # 6. Density normalization (per 500 words, capped to prevent short-text inflation)
    # Bug reports are naturally 100-300 words. Cap amplification at 2x.
    density_factor = min(500 / max(word_count, 100), 2.0)
    normalized_score = score * density_factor

    # 7. Human signals (deductions)
    human_deductions = 0
    human_details = []
    for pattern, deduction, label in HUMAN_SIGNALS:
        matches = len(re.findall(pattern, text))
        if matches > 0:
            applied = deduction * min(matches, 3)  # Cap at 3 matches
            human_deductions += applied
            human_details.append(f"{label} x{matches} ({applied:+.1f})")
    if human_details:
        details.append(f"Human signals: {', '.join(human_details[:5])}")

    final_score = max(0, min(10, normalized_score + human_deductions))

    # Verdict
    if final_score <= 2:
        verdict = "PASS"
        exit_code = 0
    elif final_score <= 5:
        verdict = "WARN"
        exit_code = 1
    else:
        verdict = "FAIL"
        exit_code = 2

    print(f"[L1-HEURISTIC] File: {filepath} ({word_count} words)")
    print(f"[L1-HEURISTIC] Raw score: {score:.1f} → Normalized: {normalized_score:.1f} → Final: {final_score:.1f}/10")
    for d in details:
        print(f"  {d}")
    print(f"[L1-HEURISTIC] Verdict: {verdict} ({final_score:.1f}/10)")

    if exit_code == 2:
        print("  → REWRITE REQUIRED. Remove all template phrases, add specific evidence.")
    elif exit_code == 1:
        print("  → Review flagged patterns. Add more target-specific details.")

    return exit_code


# ─── Layer 2: Claude Self-Review Prompt ──────────────────────────────────

def generate_self_review_prompt(filepath: str) -> int:
    """Layer 2: Generate a prompt for Claude to self-review the report."""
    path = Path(filepath)
    if not path.exists():
        print(f"ERROR: File not found: {filepath}")
        return 2

    text = path.read_text(encoding="utf-8", errors="replace")

    # Truncate if too long
    if len(text) > 8000:
        text = text[:8000] + "\n... [TRUNCATED]"

    prompt = f"""You are a skeptical bug bounty triager at a major platform. You have seen thousands of AI-generated spam reports and can detect them instantly.

Read the following bug bounty report and evaluate it for AI-generated characteristics. Score it 0-10 where:
- 0-2: Clearly human-written (specific, concise, evidence-rich)
- 3-5: Suspicious (some AI patterns but has specifics)
- 6-10: Almost certainly AI-generated (template language, vague, no real evidence)

Check for:
1. Template phrases ("it is important to note", "comprehensive", "robust", "furthermore")
2. Vague impact claims without specific evidence
3. Hedging language ("could potentially", "theoretically")
4. Uniform sentence length and structure
5. Generic recommendations not specific to the target
6. Missing concrete evidence (no tx hash, block number, actual output, file:line)

Also check what makes it look HUMAN:
1. Specific code references with line numbers
2. Actual command output or HTTP responses pasted
3. Concrete reproduction steps that only work on this target
4. Terse, direct language (not flowery)
5. Evidence of manual testing (timestamps, specific values)

Report format:
[AI-SCORE] X/10
[VERDICT] PASS/WARN/FAIL
[AI-PATTERNS] list each detected AI pattern with the exact quote
[HUMAN-PATTERNS] list each human signal found
[FIX] specific suggestions to make it more human-like

---REPORT START---
{text}
---REPORT END---"""

    print("[L2-SELF-REVIEW] Prompt generated. Copy-paste or pipe to Claude for evaluation.")
    print("=" * 80)
    print(prompt)
    print("=" * 80)
    return 0


# ─── Layer 3: ZeroGPT Playwright Instructions ───────────────────────────

def zerogpt_instructions(filepath: str) -> int:
    """Layer 3: Print Playwright MCP steps for ZeroGPT free check."""
    path = Path(filepath)
    if not path.exists():
        print(f"ERROR: File not found: {filepath}")
        return 2

    text = path.read_text(encoding="utf-8", errors="replace")
    # ZeroGPT has a character limit on free tier
    if len(text) > 15000:
        text = text[:15000]
        print(f"[L3-ZEROGPT] Text truncated to 15000 chars for free tier limit")

    word_count = len(text.split())

    print(f"""[L3-ZEROGPT] Playwright MCP Instructions for AI Detection Check
{"=" * 60}

Execute these MCP tool calls in sequence:

1. browser_navigate(url="https://www.zerogpt.com")
2. browser_snapshot() → find the text input area
3. browser_click(element="textarea or text input ref")
4. browser_type(text=<report content>, element=<textarea ref>)
   NOTE: Paste the report content from: {filepath} ({word_count} words)
5. browser_click(element="Detect Text" button ref)
6. browser_wait_for(selector=".result", timeout=15000)  # Wait for result
7. browser_snapshot() → read the AI detection result

Interpret results:
- "Your text is Human written" or <10% AI → PASS
- 10-50% AI → WARN (review flagged sentences)
- >50% AI → FAIL (rewrite required)

Alternative free services (if ZeroGPT is down):
- https://contentatscale.ai/ai-content-detector/ (free, no signup)
- https://writer.com/ai-content-detector/ (free, 1500 words)
""")
    return 0


# ─── Full Check ──────────────────────────────────────────────────────────

def full_check(filepath: str) -> int:
    """Run Layer 1 + generate instructions for Layer 2 and 3."""
    print("=" * 60)
    print("[AI-DETECT] Full 3-Layer Check")
    print("=" * 60)

    # Layer 1: Automatic
    print("\n--- Layer 1: Heuristic Analysis ---")
    l1_result = heuristic_check(filepath)

    if l1_result == 0:
        print("\n[L1 PASS] Layer 1 passed. Running Layer 2 self-review for extra safety...\n")
    elif l1_result == 1:
        print("\n[L1 WARN] Layer 1 borderline. Layer 2+3 checks MANDATORY.\n")
    else:
        print("\n[L1 FAIL] Layer 1 failed. Fix heuristic issues BEFORE running Layer 2+3.\n")
        return 2

    # Layer 2: Generate prompt
    print("--- Layer 2: Self-Review Prompt ---")
    generate_self_review_prompt(filepath)

    # Layer 3: Generate instructions
    print("\n--- Layer 3: ZeroGPT Instructions ---")
    zerogpt_instructions(filepath)

    print(f"\n{'=' * 60}")
    print("[AI-DETECT] Summary:")
    print(f"  Layer 1 (heuristic): {'PASS' if l1_result == 0 else 'WARN' if l1_result == 1 else 'FAIL'}")
    print(f"  Layer 2 (self-review): RUN THE PROMPT ABOVE")
    print(f"  Layer 3 (ZeroGPT): RUN THE PLAYWRIGHT STEPS ABOVE")
    print(f"  → All 3 layers must PASS before submission")

    return l1_result


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    filepath = sys.argv[2]

    if cmd == "heuristic":
        sys.exit(heuristic_check(filepath))
    elif cmd == "self-review-prompt":
        sys.exit(generate_self_review_prompt(filepath))
    elif cmd == "zerogpt-instructions":
        sys.exit(zerogpt_instructions(filepath))
    elif cmd == "full":
        sys.exit(full_check(filepath))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
