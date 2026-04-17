# Walrus Smart Contracts Severity + Branch Scope Postmortem

**Date / Platform / Finding**: 2026-04-05 / Immunefi / slashing.move vulnerability (High)
**Reward Outcome**: Killed at Phase 5.5 (manual pre-submit check) — no submission made. Two violations discovered simultaneously.

## 1. Root Cause

Two distinct scope violations were found during Phase 5.5 manual review:

**Violation 1 — Severity scope**: The Walrus program's scope table showed only **Critical** severity as accepted. Our finding was classified as **High**. Submitting High to a Critical-only program results in immediate OOS close.

**Violation 2 — Branch/tag scope**: The affected file `slashing.move` existed in the `main` branch but was **absent from the scoped `mainnet` and `testnet` tags**. The program scope constraint specified "mainnet tags / testnet tags only." Verification: `git checkout mainnet -- slashing.move` → file not found.

Both violations were discovered only at Phase 5.5, after full exploit development and report writing (Phase 2–5). The violations are cited in `bb_pipeline_v12.md` as the walrus incident, driving Checks 7 and 8 in kill-gate-1.

## 2. Expected Gate Behavior

**kill-gate-1, Check 7 (SEVERITY SCOPE CHECK)** and **Check 8 (BRANCH/TAG SCOPE CHECK)** (both added in v12.3) should have blocked this at Gate 1 before exploiter spawn.

Check 7: severity tier must appear in the program's severity scope table. Mismatch → adjust (not KILL) to maximize acceptance probability, then re-assess with adjusted severity.
Check 8: `git checkout <scoped-tag> -- <affected-file>` must succeed. main-only presence → HARD KILL (exit 2).

## 3. Actual Gate Behavior

At submission time (2026-04-05), kill-gate-1 had the original 5 checks. Severity scope and branch/tag scope checks did not exist.

`program_rules_summary.md` had a "Severity Scope" section but it was populated from Phase 0.2 rules-check output, which at the time was not enforced to be verbatim. The smart contract branch/tag constraint was noted in the program page but not extracted as a structured field that could be machine-checked.

**Implementation gap**: kill-gate-1 did not query `program_rules_summary.md` structured fields for severity constraints or asset version constraints. Branch/tag verification was manual-only and not enforced by the gate.

## 4. Fix Path

v12.3 added both checks to kill-gate-1:
- Check 7: `bb_preflight.py kill-gate-1 --severity <tier>` cross-checks against "Severity Scope" section in `program_rules_summary.md`. Mismatch = WARN + adjustment required (not immediate KILL, since severity can be adjusted downward).
- Check 8: `bb_preflight.py kill-gate-1` runs `git checkout <scoped-tag> -- <affected-file>` and treats non-zero exit as HARD_KILL.

Phase 0.2 `rules-check` now requires "Severity Scope" and "Asset Scope Constraints" as mandatory sections. Missing sections → FAIL → no agent spawn until filled verbatim from the program page.
