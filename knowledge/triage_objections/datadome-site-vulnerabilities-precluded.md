# DataDome "Site Vulnerabilities" Ambiguous OOS — Preventive Postmortem

**Date / Platform / Finding**: 2026-04-17 (preventive, no submission made) / Hypothetical / Web application vulnerabilities (XSS, SQLi, SSRF class)
**Reward Outcome**: Preventive — no submission. This postmortem documents a structural OOS interpretation gap to prevent a future incorrect submission.

## 1. Root Cause (Hypothetical)

DataDome (or similar bot-protection / CDN-layer programs) may include an OOS clause such as: **"Site vulnerabilities"** or **"Vulnerabilities affecting client websites using the DataDome SDK"**.

This is a structurally ambiguous OOS item. The token "site" does not overlap with common web vulnerability keywords ("xss", "sqli", "ssrf", "injection", "csrf"). A standard keyword-based exclusion filter would NOT match "site vulnerabilities" against a finding described as "Reflected XSS in the DataDome dashboard" — because "site" and "xss" share no tokens.

The finding could be OOS (if "site vulnerabilities" means any web vuln affecting the vendor's web properties), or it could be in scope (if "site vulnerabilities" refers only to customer-side deployments using the SDK, not the vendor's own dashboard). The ambiguity would only surface after submission when the triager interprets the clause.

## 2. Expected Gate Behavior

**kill-gate-1, Check 3 (SCOPE CHECK)** combined with **Phase 5.7 (Live Scope Verification)** should catch this.

Expected: `bb_preflight.py exclusion-filter` detects that "site vulnerabilities" is a catch-all OOS clause with high semantic ambiguity. Rather than passing (no keyword match) or hard-killing, it should return a HOLD with the verbatim OOS text and a request for human interpretation before proceeding.

Phase 5.7 scope qualifier check: "does the scope have qualifiers like 'APIs', 'smart contracts', 'site vulnerabilities'? If finding's asset type doesn't match the qualifier → HOLD."

## 3. Actual Gate Behavior (Gap Analysis)

Current `exclusion-filter` implementation uses token-overlap between finding keywords and OOS item text. "Site vulnerabilities" + finding keywords ["xss", "dashboard", "reflected"] → zero overlap → filter passes with no warning.

Kill-gate-1 Check 3 (SCOPE CHECK: "Out-of-Scope per program brief?") runs via triager-sim LLM judgment. A competent triager-sim would flag "site vulnerabilities" as ambiguous and ask for clarification. However, if the triager-sim prompt focuses on semantic matching rather than ambiguity detection, this could be missed.

**Implementation gap**: exclusion-filter has no concept of "catch-all" OOS clauses (clauses that are deliberately broad to preclude entire categories). Broad OOS items like "site vulnerabilities", "general web issues", "client-side vulnerabilities", "third-party component issues" need a separate handling path: automatic HOLD for human review rather than pass-or-kill.

## 4. Fix Path

Add a catch-all OOS clause detector to `bb_preflight.py exclusion-filter`:

```python
CATCH_ALL_OOS_PATTERNS = [
    r'\bsite\s+vulnerabilities?\b',
    r'\bgeneral\s+web\s+(issues?|vulnerabilities?)\b',
    r'\bclient.?side\s+(only\s+)?vulnerabilities?\b',
    r'\bthird.?party\s+(component|library|sdk)\s+issues?\b',
    r'\bvulnerabilities?\s+(in|of|affecting)\s+third.?party\b',
]
# If any pattern matches an OOS item: exit 3 (HOLD — human review required)
# Include verbatim OOS text in output for human interpretation
```

Phase 5.7 Scope Qualifier Check should explicitly test for catch-all patterns and return HOLD (not PASS) when ambiguity is detected. This prevents silent pass-through of broad exclusion clauses that could subsume entire vulnerability classes.
