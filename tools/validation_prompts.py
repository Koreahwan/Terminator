#!/usr/bin/env python3
"""
Terminator - Anti-Hallucination Validation Prompts

Composable anti-hallucination prompts adapted for Terminator's retained
bounty, client-pitch, and AI-security pipelines. Enforces evidence-based reasoning,
prevents speculative claims, and calibrates severity to demonstrated impact.

Inspired by NeuroSploit v3's anti-hallucination architecture, adapted for
Terminator's critic and triager_sim review pipeline.

Usage:
    # Get composed prompt for a context
    from tools.validation_prompts import get_prompts
    prompt = get_prompts("bb_verification")

    # Check text for speculative language
    from tools.validation_prompts import check_speculative
    matches = check_speculative("the server might be vulnerable to XSS")

    # CLI
    python3 tools/validation_prompts.py bb_verification
    python3 tools/validation_prompts.py check "the server might be vulnerable"
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tools import areuai_bridge


# ---------------------------------------------------------------------------
# Core Anti-Hallucination Prompts
# ---------------------------------------------------------------------------

ANTI_HALLUCINATION = """## ANTI-HALLUCINATION DIRECTIVE

AI reasoning NEVER constitutes proof. You MUST NOT:
- Infer a vulnerability exists based on theoretical analysis alone.
- Claim "likely vulnerable" without concrete evidence from actual execution output.
- Fabricate evidence not present in actual tool output, server response, source quote, or business workflow observation.
- Report findings based on what "could happen" rather than what DID happen.
- Treat pattern recognition as confirmation (seeing a function name != proving it is reachable).

RULE: If you cannot point to a specific string, value, address, behavioral change, or captured
output that proves the claim, the finding is INVALID. Your confidence in your own reasoning
is NOT evidence. Only observable, reproducible outputs are evidence.

For Bug Bounty: HTTP response body, captured headers, timing measurements, source code quotes, and safe workflow observations = evidence. "The endpoint appears to" = not evidence.
For Client Pitch: passive exposure indicators are sales signals only. They are not confirmed vulnerabilities."""


PROOF_OF_EXECUTION = """## PROOF OF EXECUTION (PoE) REQUIREMENTS

No proof = No finding. Every confirmed claim MUST have execution evidence:

### Web Vulnerability PoE:
- XSS: Payload renders in executable context (not HTML-encoded, not in comment). JS fires in browser/Playwright.
- SQLi: Database content extracted (version, table names, user data) OR consistent boolean/time differential (3+ trials).
- SSRF: Internal resource content in response (metadata values, localhost HTML). Status code change alone is NOT proof.
- RCE: Command output captured (uid=, hostname, file content). Timeout alone is NOT proof without 3+ consistent measurements.
- IDOR/BOLA: Other user's PRIVATE data in response body. 200 OK with empty/own data = NOT a finding.
- BFLA: Admin function returns admin data to non-admin user. Empty response with 200 = NOT broken.
- LFI: File content markers (root:x:0:0, [boot loader], <?php) in response. Path traversal in URL alone is NOT proof.
- CSRF: State-changing action verified (not just missing token).
- Open Redirect: Location header points to attacker domain in 3xx response.

### Smart Contract PoE:
- Fund Loss: Foundry fork test showing balance change with specific block number.
- Access Control: Transaction from unauthorized address succeeds (cast send + receipt).
- Oracle Issue: Actual price deviation measured on mainnet fork, not theoretical calculation."""


NEGATIVE_CONTROLS = """## MANDATORY NEGATIVE CONTROLS

Skipping negative controls invalidates any finding. For every potential finding:

### Web:
1. Send a BENIGN value (e.g., "test123") to the same parameter. Record the response.
2. Send an EMPTY value. Record the response.
3. Compare: If the "attack" response is identical to benign/empty (same status, similar body length, same behavior),
   the observed behavior is NOT caused by your payload. It is generic application behavior.

### Smart Contract:
1. Call with normal parameters. Record state change.
2. Call with exploit parameters. Record state change.
3. Difference must demonstrate unauthorized state change, not normal protocol behavior.

RULE: A response difference MUST be payload-specific. If every input produces the same output,
no vulnerability exists regardless of AI reasoning."""


ANTI_SEVERITY_INFLATION = """## ANTI-SEVERITY INFLATION

Severity inflation destroys credibility. Match severity to DEMONSTRATED impact:

### Web Severity Calibration:
- 200 OK without sensitive data in body != High (could be error page, login redirect, or generic response)
- Error message without data extraction != Medium (information disclosure at most)
- Missing security header != High (Info/Low at most)
- Reflected XSS != Critical (requires user interaction -> Medium)
- CORS misconfiguration without credential access != High (Low/Medium)
- Self-XSS != a vulnerability (attacker types in own browser)
- Open redirect alone != High (phishing vector -> Medium)

### Smart Contract Severity:
- Code path exists but config is zero/disabled in production = Low (latent bug, not exploitable)
- Requires admin action to trigger = downgrade by 2 levels
- Theoretical maximum loss != demonstrated loss (use actual pool/vault balances)

RULE: Every severity rating MUST match the ACTUAL demonstrated impact, not theoretical maximum.
When in doubt, rate LOWER. Conservative ratings build credibility; inflation destroys it."""


CONFIDENCE_SCORE = """## CONFIDENCE SCORING FORMULA (0-100)

Every finding receives a confidence score. Apply HONESTLY:

### Positive Signals (additive, max 100):
  +0 to +40: Proof of Execution present and matches vulnerability type requirements
  +0 to +30: Demonstrated real-world impact (data extracted, code executed, state changed)
  +0 to +20: Negative controls passed (attack response differs from benign input)
  +0 to +10: Reproducibility (multiple successful trials, different environments)

### Negative Signals (subtractive):
  -30: No negative control performed (baseline comparison missing)
  -20: Speculative language in evidence ("could be", "might be", "potentially")
  -40: No Proof of Execution (payload sent but no proof it executed)
  -25: Status-code-only evidence (200 OK / 500 error without body analysis)
  -15: Single trial only (no reproducibility evidence)
  -10: Environment-specific (works locally but untested on target)

### Thresholds:
  >= 90: CONFIRMED — proceed with full confidence
  70-89: LIKELY — proceed but flag uncertainties explicitly
  50-69: NEEDS VERIFICATION — do not approve without additional evidence
  < 50: REJECT — insufficient evidence, finding is not substantiated

RULE: Score < 70 = REJECT for bug bounty submissions. Client-pitch items below 70 must remain passive risk indicators."""


OPERATIONAL_HUMILITY = """## OPERATIONAL HUMILITY

Uncertainty is better than fabrication. When evidence is incomplete:
- Report as "needs verification" instead of "confirmed"
- Lower severity instead of inflating it
- Say "I could not verify this claim" instead of assuming truth
- Mark assumptions explicitly in a separate ## Assumptions section

The cost hierarchy:
- Fabricated evidence >> Missed finding (fabrication destroys all credibility)
- False positive >> False negative (FP wastes team resources and burns platform reputation)
- Inflated severity >> Conservative severity (inflation triggers triager skepticism)

RULE: If your confidence in a claim is below 70%, be transparent. Mark it as unverified.
Professional security researchers mark uncertain findings for manual review."""


FRONTEND_BACKEND_CORRELATION = """## FRONTEND / BACKEND CORRELATION

UI-only observations are not server-side vulnerabilities:
- A 200 OK in the browser does NOT mean the server performed the action. Check response BODY.
- A client-side error does NOT mean the server is vulnerable. Reproduce with curl/raw HTTP.
- DOM-rendered content may not reflect server-side processing.
- Browser console errors are client-side artifacts, not server vulnerabilities.

RULE: Every web finding must be reproducible with raw HTTP requests (curl, Python requests, pwntools).
If it only manifests in browser JavaScript, it requires explicit client-side verification evidence
and severity is capped at Medium unless server-side impact is separately proven."""


ACCESS_CONTROL_INTELLIGENCE = """## ACCESS CONTROL TESTING (BOLA/BFLA/IDOR)

HTTP status codes are NOT sufficient for access control testing.

CRITICAL RULES:
1. 200 OK does NOT mean access was granted. Response may contain error message, login page, or empty data.
2. 403 does NOT always mean properly protected. Some apps return 403 for invalid requests but 200 for all valid ones.
3. Compare ACTUAL DATA: Does the response contain User B's specific fields when authenticated as User A?

CORRECT TESTING (three-way comparison):
1. Authenticate as User A -> GET /api/users/A -> Record response body
2. Authenticate as User A -> GET /api/users/B -> Record response body
3. Authenticate as User B -> GET /api/users/B -> Record response body
4. Compare: Step 2 returning User B's private data (matching step 3) = BOLA. Otherwise = NOT BOLA.

FALSE POSITIVE PATTERNS:
- 200 with {"error": "unauthorized"} = NOT a finding
- 200 with YOUR OWN data regardless of ID = NOT BOLA (server ignores the ID parameter)
- 200 with empty array for other user's ID = Properly protected
- 200 with PUBLIC profile data only = NOT a finding (unless private fields included)"""


CLIENT_PITCH_BOUNDARY = """## CLIENT-PITCH BOUNDARY

Client-pitch artifacts are sales/risk-indication materials, not penetration-test
reports. Before authorization, you MUST NOT claim:
- "confirmed vulnerability"
- "exploit succeeded"
- "data exposed"
- "attacker can definitely"
- "submission ready"

Allowed language:
- "externally observable risk signal"
- "requires authorized access-control review"
- "recommended assessment area"
- "candidate"
- "needs verification"

RULE: A client-pitch document may describe why a surface is worth testing, but
must not imply a vulnerability was proven."""


# ---------------------------------------------------------------------------
# Speculative Language Detection
# ---------------------------------------------------------------------------

SPECULATIVE_PATTERNS = re.compile(
    r"\b("
    r"could be|might be|may be|theoretically|potentially vulnerable|"
    r"possibly|appears to be vulnerable|suggests? (?:a )?vulnerab|"
    r"it is possible|in theory|hypothetically|"
    r"should work|should be correct|should pass|"
    r"probably|most likely|presumably|"
    r"seems to|appears to|"
    r"I think|I believe|"
    r"could lead to|might allow|may enable|"
    r"likely vulnerable|likely exploitable|"
    r"it appears that|it seems that|"
    r"would suggest|would indicate"
    r"|)\b",
    re.IGNORECASE,
)

# AI slop patterns (template language that signals AI-generated content)
AI_SLOP_PATTERNS = re.compile(
    r"\b("
    r"it is important to note|comprehensive|robust|leveraging|"
    r"in conclusion|furthermore|moreover|it should be noted|"
    r"the aforementioned|as previously mentioned|"
    r"this underscores|this highlights|"
    r"a holistic approach|a comprehensive approach|"
    r"it is worth mentioning|it bears mentioning|"
    r"needless to say|it goes without saying"
    r")\b",
    re.IGNORECASE,
)


def check_speculative(text: str) -> List[str]:
    """Detect speculative language in text.

    Returns list of speculative phrases found. Empty list = clean.
    """
    return [m.group(0) for m in SPECULATIVE_PATTERNS.finditer(text)]


def check_ai_slop(text: str) -> List[str]:
    """Detect AI template/slop language in text.

    Returns list of AI slop phrases found. Empty list = clean.
    """
    result = areuai_bridge.analyze_text(text, mode="report")
    spans = [str(span.get("text", "")) for span in result.get("spans", []) if span.get("text")]
    if spans:
        return spans
    return [m.group(0) for m in AI_SLOP_PATTERNS.finditer(text)]


def compute_confidence(
    has_poe: bool = False,
    has_impact: bool = False,
    has_negative_control: bool = False,
    has_reproducibility: bool = False,
    speculative_count: int = 0,
    status_code_only: bool = False,
    single_trial: bool = False,
    env_specific: bool = False,
) -> int:
    """Compute confidence score based on evidence quality.

    Returns integer 0-100.
    """
    score = 0

    # Positive signals
    if has_poe:
        score += 40
    if has_impact:
        score += 30
    if has_negative_control:
        score += 20
    if has_reproducibility:
        score += 10

    # Negative signals
    if not has_negative_control:
        score -= 30
    if speculative_count > 0:
        score -= min(20, speculative_count * 5)
    if not has_poe:
        score -= 40
    if status_code_only:
        score -= 25
    if single_trial:
        score -= 15
    if env_specific:
        score -= 10

    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Context-Based Prompt Composition
# ---------------------------------------------------------------------------

# Map context -> list of prompt constants to include
CONTEXT_MAP: Dict[str, List[str]] = {
    # Bug Bounty: active testing phase
    "bb_testing": [
        "ANTI_HALLUCINATION",
        "PROOF_OF_EXECUTION",
        "NEGATIVE_CONTROLS",
        "FRONTEND_BACKEND_CORRELATION",
        "ACCESS_CONTROL_INTELLIGENCE",
        "OPERATIONAL_HUMILITY",
    ],
    # Bug Bounty: critic/triager reviewing findings
    "bb_verification": [
        "ANTI_HALLUCINATION",
        "PROOF_OF_EXECUTION",
        "NEGATIVE_CONTROLS",
        "ANTI_SEVERITY_INFLATION",
        "CONFIDENCE_SCORE",
        "FRONTEND_BACKEND_CORRELATION",
        "ACCESS_CONTROL_INTELLIGENCE",
        "OPERATIONAL_HUMILITY",
    ],
    # Bug Bounty: reporter writing final report / triager_sim reviewing
    "bb_reporting": [
        "ANTI_HALLUCINATION",
        "ANTI_SEVERITY_INFLATION",
        "CONFIDENCE_SCORE",
        "OPERATIONAL_HUMILITY",
    ],
    # Client pitch: passive risk indications for sales/outreach
    "client_pitch": [
        "ANTI_HALLUCINATION",
        "ANTI_SEVERITY_INFLATION",
        "OPERATIONAL_HUMILITY",
        "CLIENT_PITCH_BOUNDARY",
    ],
    # General exploit/PoC review
    "exploit_review": [
        "ANTI_HALLUCINATION",
        "PROOF_OF_EXECUTION",
        "NEGATIVE_CONTROLS",
        "CONFIDENCE_SCORE",
        "OPERATIONAL_HUMILITY",
    ],
}

# Resolve names to actual prompt strings
_PROMPT_REGISTRY: Dict[str, str] = {
    "ANTI_HALLUCINATION": ANTI_HALLUCINATION,
    "PROOF_OF_EXECUTION": PROOF_OF_EXECUTION,
    "NEGATIVE_CONTROLS": NEGATIVE_CONTROLS,
    "ANTI_SEVERITY_INFLATION": ANTI_SEVERITY_INFLATION,
    "CONFIDENCE_SCORE": CONFIDENCE_SCORE,
    "OPERATIONAL_HUMILITY": OPERATIONAL_HUMILITY,
    "FRONTEND_BACKEND_CORRELATION": FRONTEND_BACKEND_CORRELATION,
    "ACCESS_CONTROL_INTELLIGENCE": ACCESS_CONTROL_INTELLIGENCE,
    "CLIENT_PITCH_BOUNDARY": CLIENT_PITCH_BOUNDARY,
}


def get_prompts(context: str) -> str:
    """Get composed anti-hallucination prompt for a given context.

    Args:
        context: One of "bb_testing", "bb_verification", "bb_reporting",
                 "client_pitch", "exploit_review"

    Returns:
        Combined prompt string with all relevant directives for the context.

    Raises:
        ValueError: If context is not recognized.
    """
    prompt_names = CONTEXT_MAP.get(context)
    if prompt_names is None:
        valid = ", ".join(sorted(CONTEXT_MAP.keys()))
        raise ValueError(f"Unknown context '{context}'. Valid contexts: {valid}")

    parts = [
        "# Anti-Hallucination Validation Directives\n"
        f"Context: {context}\n"
        "Follow ALL directives below. Violations invalidate findings.\n"
    ]

    for name in prompt_names:
        prompt_text = _PROMPT_REGISTRY.get(name)
        if prompt_text:
            parts.append(prompt_text)

    return "\n\n".join(parts)


def get_prompt_by_id(prompt_id: str) -> Optional[str]:
    """Get a single prompt by its ID (e.g., 'ANTI_HALLUCINATION')."""
    return _PROMPT_REGISTRY.get(prompt_id)


def get_all_prompt_ids() -> List[str]:
    """Return all available prompt IDs."""
    return list(_PROMPT_REGISTRY.keys())


def get_all_contexts() -> List[str]:
    """Return all available context names."""
    return list(CONTEXT_MAP.keys())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli_main() -> None:
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 tools/validation_prompts.py <context>")
        print("  python3 tools/validation_prompts.py check \"<text>\"")
        print("  python3 tools/validation_prompts.py slop \"<text>\"")
        print("  python3 tools/validation_prompts.py list")
        print()
        print(f"Contexts: {', '.join(get_all_contexts())}")
        print(f"Prompts:  {', '.join(get_all_prompt_ids())}")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "check":
        if len(sys.argv) < 3:
            print("Usage: python3 tools/validation_prompts.py check \"<text>\"")
            sys.exit(1)
        text = " ".join(sys.argv[2:])
        matches = check_speculative(text)
        if matches:
            print(f"SPECULATIVE LANGUAGE DETECTED ({len(matches)} instance(s)):")
            for m in matches:
                print(f"  - \"{m}\"")
            sys.exit(1)
        else:
            print("CLEAN: No speculative language detected.")
            sys.exit(0)

    elif cmd == "slop":
        if len(sys.argv) < 3:
            print("Usage: python3 tools/validation_prompts.py slop \"<text>\"")
            sys.exit(1)
        text = " ".join(sys.argv[2:])
        matches = check_ai_slop(text)
        if matches:
            print(f"AI SLOP DETECTED ({len(matches)} instance(s)):")
            for m in matches:
                print(f"  - \"{m}\"")
            sys.exit(1)
        else:
            print("CLEAN: No AI slop language detected.")
            sys.exit(0)

    elif cmd == "list":
        print("Available contexts:")
        for ctx in get_all_contexts():
            prompts = CONTEXT_MAP[ctx]
            print(f"  {ctx}: {', '.join(prompts)}")
        print()
        print("Available prompts:")
        for pid in get_all_prompt_ids():
            first_line = _PROMPT_REGISTRY[pid].strip().split("\n")[0]
            print(f"  {pid}: {first_line}")

    else:
        # Treat as context name
        try:
            print(get_prompts(cmd))
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    _cli_main()
