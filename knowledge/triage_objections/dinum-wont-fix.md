# DINUM Démarches Simplifiées Won't Fix Postmortem

**Date / Platform / Finding**: 2026-04-04 (submitted), 2026-04-13 (resolved) / YesWeHack / SIRET prefill validation bypass
**Report ID**: #7419-178 (YWH program 7419)
**Reward Outcome**: Won't Fix. No ranking point loss. Program subsequently disabled 2026-04-15 (platform-level closure, unrelated to this report).

## 1. Root Cause

Platform response: **"Toutes les démarches doivent être accessibles à toutes et tous"** (all procedures must be accessible to everyone). The DINUM mission is universal citizen access — input restrictions of any kind contradict the platform's core design principle.

The finding reported that SIRET (French business ID) prefill could be bypassed: a user could trigger the prefill flow with an invalid or arbitrary SIRET. This was classified as a vulnerability (missing server-side input validation, CWE-20 class). However, for DINUM (Démarches Simplifiées), the absence of input restrictions is **intentional design**: restricting who can start a procedure conflicts with the accessibility-first mandate.

Kill-gate-1 Check 1 (FEATURE CHECK: "documented/intended behavior?") should have caught this, but the platform's accessibility-first design philosophy was not captured in program_rules_summary.md during Phase 0.

## 2. Expected Gate Behavior

**kill-gate-1, Check 1 (FEATURE CHECK)** — the SIRET prefill behavior (no validation) should have been identified as intentional design at Phase 0 before any agent was spawned.

Expected: Phase 0 target-evaluator reads the program's About page and mission statement. For government/civic platforms with "universal access" or "accessibility-first" language, all input restriction findings are flagged for Check 1 FEATURE CHECK with elevated false-positive risk. Gate 1 would require explicit documentation that the missing validation causes a security consequence beyond accessibility, before passing.

## 3. Actual Gate Behavior

Phase 0 target-evaluator analyzed the program scope and tech stack but did not extract the platform's accessibility design mandate from the About/mission pages. The mandate was present in public documentation but was not part of the standard target assessment.

Kill-gate-1 Check 1 tested for "documented/intended behavior" against the program rules document — not against the platform's broader design philosophy. The prefill behavior was not explicitly described as intended in the program rules, so Check 1 passed.

**Implementation gap**: kill-gate-1 Check 1 only checked the program's explicit OOS list and known-issues sections. It did not consider platform design philosophy (accessibility-first, public-sector universal access) as a source of "intended behavior" signals.

## 4. Fix Path

Add to Phase 0 target-evaluator prompt: for government / civic / public-sector platforms, fetch the About page and mission statement. If the platform declares "universal access," "accessibility," or "no barriers to entry" as a core principle → flag all input-validation findings for FEATURE CHECK with high false-positive risk.

Add to kill-gate-1 Check 1 trigger conditions:
```
IF platform_type IN [government, civic_tech, public_sector]
AND finding_class IN [input_validation, missing_restriction, rate_limit]
AND program_mission CONTAINS [accessibility, universal_access, open_to_all]
THEN: HARD_KILL unless impact demonstrates concrete security consequence
      beyond the missing restriction itself
```

Lesson recorded in `feedback_govt_platform_accessibility_design.md`.
