# Utix Impact Scope Mismatch Postmortem

**Date / Platform / Finding**: ~2026-04-04 / Immunefi / Fund freezing vulnerability (Critical)
**Report ID**: #72165
**Reward Outcome**: Closed — impact OOS. Forwarded to project. €0.

## 1. Root Cause

Utix program "Impacts in Scope" listed exactly one impact: **"Unlocking stuck funds"**.

Our report claimed impact: **"Permanent freezing of funds"**. This is a different impact category — it describes creating a new frozen state, not recovering from one. Immunefi's submission form enforces a dropdown of in-scope impacts; selecting an impact not in the program's list results in automatic rejection.

The asset and severity were both valid (Critical, in-scope contract). Only the impact framing was wrong. The finding itself was real — the error was in how we described its consequence relative to the program's accepted vocabulary.

## 2. Expected Gate Behavior

**kill-gate-1, Check 6 (IMPACT SCOPE CHECK, v12.3)** should have caught this before exploiter spawn.

Expected behavior: triager-sim (mode=finding-viability) cross-references the claimed impact against the program's verbatim "Impacts in Scope" list. "Permanent freezing" vs "Unlocking stuck funds" — no match → attempt reframing → "frozen funds that cannot be unlocked" maps to "Unlocking stuck funds" → CONDITIONAL GO with reframed impact. If reframing produces a semantically coherent match, gate passes with a note to use the in-scope vocabulary in the report.

## 3. Actual Gate Behavior

At submission time, kill-gate-1 had the original 5-question destruction test but not Check 6. The impact-scope cross-check was not implemented.

The triager-sim prompt did not include the Immunefi-specific enforcement that impact selection is a constrained dropdown (not free text). The gate treated impact as a narrative quality issue rather than a hard match constraint.

**Implementation gap**: kill-gate-1 had no awareness of platform-specific impact enumeration. Immunefi enforces an exact match between submitted impact and program's in-scope list — other platforms (Bugcrowd, Intigriti) do not have this constraint, so the check was platform-specific and was missing.

## 4. Fix Path

v12.3 added Check 6 to kill-gate-1: `--impact "<claimed impact>"` is now mandatory for Immunefi submissions. The check:
1. Extracts `program_rules_summary.md` → "Impacts in Scope" section (verbatim, from fetch-program).
2. Attempts semantic match between claimed impact and each in-scope item.
3. No match → attempt reframing (e.g. "freezing" → "unlocking" if the vulnerability enables both states).
4. Reframing successful → WARN (use in-scope vocabulary). Reframing fails → HARD_KILL (exit 2).

Future hardening: `bb_preflight.py kill-gate-1` should also validate the impact against Immunefi's common-exclusions list at `immunefi.com/common-vulnerabilities-to-exclude/` and flag if the impact class appears there.
