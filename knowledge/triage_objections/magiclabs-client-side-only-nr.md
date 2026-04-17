# Magic Labs PKCE Client-Side-Only N/R Postmortem

**Date / Platform / Finding**: 2026-04-03 (submitted) / Bugcrowd / PKCE codeVerifier persisted to localStorage
**Report ID**: bc91fc04
**Reward Outcome**: Not Reproducible (N/R), closed 2026-04-13. -1 accuracy point. Triager: brunoc_bugcrowd.

## 1. Root Cause

Triager message (verbatim): **"We believe this issue to be a false-positive... This is all theoretical with no actual valid proof of concept."**

The finding demonstrated that `codeVerifier` was written to `localStorage` (real Chromium differential, evidence tier E2). However, it required an XSS precondition that was never proven on the live production target. Bugcrowd triagers require an end-to-end attacker-to-victim session flow on the actual production deployment — not an SDK behavior demonstrated in isolation.

The program's Bugcrowd brief contained a clause excluding client-side-only vulnerabilities: findings without a demonstrated server-side consequence or attacker-controlled cross-origin access are classified Not Applicable. This clause was present in the program rules but was not extracted by Phase 0.2 as a gate-relevant constraint.

## 2. Expected Gate Behavior

**kill-gate-1, Check 1 (FEATURE CHECK / client-side-only filter)** or a dedicated pre-submission client-side filter should have flagged this.

Trigger: finding requires XSS precondition OR victim browser interaction OR server-side validation is untested AND program OOS/rules contain "client-side only vulnerabilities are Not Applicable" → HARD_KILL.

Alternatively: evidence-tier-check should have flagged E2 (localStorage differential without live target exploitation) as insufficient for Bugcrowd platform standards and required E1 upgrade before submission.

## 3. Actual Gate Behavior

Phase 0.2 extracted the program rules but the "client-side-only vulnerabilities not applicable" clause was not parsed as a structured constraint. Kill-gate-1's Check 1 (FEATURE CHECK) tested for "documented/intended behavior" but not for "client-side SDK behavior in isolation."

Evidence-tier-check classified the finding as E2 (real differential evidence), which was treated as sufficient for Gate 2. However, E2 sufficiency is platform-dependent — Bugcrowd requires E1 (live target end-to-end demonstration) for client-side findings with server-side prerequisites.

**Implementation gap**: kill-gate-1 had no platform-specific evidence threshold mapping. E2 was treated as gate-passing regardless of platform or finding class. The client-side-only exclusion clause was in the program rules but not surfaced to any gate as a blocking constraint.

## 4. Fix Path

Add to `bb_preflight.py kill-gate-1`:
- Parse program rules for "client-side only", "SDK behavior", "theoretical" exclusion patterns.
- If found: require evidence tier E1 (live target, end-to-end) for any finding with XSS prerequisite or server-side validation gap → WARN with E1 requirement, or HARD_KILL if E1 is structurally infeasible.

Add to evidence-tier-check: platform-specific minimum tier table. Bugcrowd: E1 required for client-side findings. Immunefi: E1/E2 both acceptable. Flag E2-with-precondition for Bugcrowd as WARN before Gate 2.

Lesson recorded in `feedback_magiclabs_nr.md`: **client-side SDK findings without live e2e exploit = N/R on Bugcrowd. Do not submit.**
