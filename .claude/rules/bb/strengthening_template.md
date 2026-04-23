# Phase 2 Pre-Gate-2 Strengthening — Detailed Spec

Referenced from `bb_pipeline_v13.md` Phase 2. This file contains the strengthening loop mechanics + `strengthening_report.md` canonical template + enforcement rules.

## Loop Semantics

Strengthening is **iterative, not a single pass.** 이 루프는 **`/ralph` skill로 구동 의무** — "정말 더 이상 발전할 것 없는가?" 까지 PRD-driven persistence로 수렴.

### Ralph invocation

```
/ralph --critic=critic "Phase 2 maximum strengthening for <target>/<finding>:
  run 5-item strengthening checklist, apply NEW discoveries to report.md + poc +
  autofill_payload + severity, re-run checklist until NO new improvements for 2
  consecutive iterations, or all 5 items NOT_APPLICABLE/INFEASIBLE. Reviewer verifies
  each iteration's strengthening_report.md vs actual artefact integration."
```

### Ralph PRD stories (auto-generated)

- Story 1: Cross-user / cross-trust-domain PoC attempted + incorporated
- Story 2: Two-step exploitation chain attempted + incorporated
- Story 3: E2 → E1 evidence tier upgrade attempted + incorporated
- Story 4: Variant hunt in sibling modules attempted + LIVE evidence + incorporated
- Story 5: Static source quote eliminates try/except
- Story 6 (meta): No new improvements discovered in 2 consecutive iterations (convergence)
- Each story acceptance = reviewer agent confirms strengthening_report.md item is COMPLETED/NOT_APPLICABLE/INFEASIBLE with evidence AND report.md actually reflects the new information

### Manual fallback (ralph unavailable)

```
REPEAT:
  1. Run the 5-item strengthening checklist (discover phase)
  2. For each ATTEMPTED item that produced NEW information (variants, chains, evidence):
     → INCORPORATE that information into report.md, poc, autofill_payload.json, severity
  3. Re-run the checklist against the UPDATED submission
  4. If any checklist item changes status (NEW variant found, severity upgraded, etc.)
     → LOOP again
UNTIL:
  - All 5 items either NOT_APPLICABLE/INFEASIBLE, or
  - All ATTEMPTED items are fully reflected in report.md + poc + autofill_payload
  - No new improvements discovered in 2 consecutive iterations
```

**"ATTEMPTED" does NOT mean "wrote it down in strengthening_report".**
It means **"discovered AND incorporated into the actual submission artifacts."**
Gate 2 HARD FAILs if strengthening_report lists findings (e.g. "4 sibling variants")
but report.md Occurrences section only contains 1 of them.

## `strengthening_report.md` Canonical Template

Before calling Gate 2, you MUST write `targets/<target>/submission/<name>/strengthening_report.md`
with the following exact structure. Gate 2 will HARD FAIL if this file is missing,
incomplete, has any `NOT_ATTEMPTED` entry, or has ATTEMPTED items whose evidence is
NOT reflected in the final submission artifacts.

```markdown
# Strengthening Report — <finding name>

## Timestamps
- phase_2_started: <ISO timestamp when exploiter spawned>
- gate_2_started: <ISO timestamp when Gate 2 invoked>
- delta_minutes: <gate_2 - phase_2 in minutes>

## Strengthening Checklist (every item: ATTEMPTED / NOT_APPLICABLE / INFEASIBLE)

### 1. Cross-user / cross-trust-domain PoC
- Status: <one of ATTEMPTED|NOT_APPLICABLE|INFEASIBLE>
- Reason: <why NOT_APPLICABLE/INFEASIBLE, or what was built>
- Evidence: <file path to cross-user PoC, or N/A>

### 2. Two-step exploitation chain
- Status: <ATTEMPTED|NOT_APPLICABLE|INFEASIBLE>
- Reason: <...>
- Evidence: <chain PoC file, or N/A>

### 3. E2 → E1 evidence tier upgrade
- Status: <ATTEMPTED|NOT_APPLICABLE|INFEASIBLE>
- Reason: <e.g. "no cloud account available" = INFEASIBLE; "source-review only" = NOT_APPLICABLE>
- Evidence: <live-data PoC output, or N/A>

### 4. Variant hunt in sibling modules
- Status: <ATTEMPTED|NOT_APPLICABLE|INFEASIBLE>
- Reason: <grep/AST search done? which files?>
- Evidence: <variant findings file, or confirmation "no variants found">

### 5. Static source quote to eliminate try/except
- Status: <ATTEMPTED|NOT_APPLICABLE|INFEASIBLE>
- Reason: <does PoC use try/except? if yes, can inspect.getsource replace it?>
- Evidence: <updated PoC file, or "no try/except to eliminate">

## Verdict
- total_NOT_ATTEMPTED: <count>
- gate_2_ready: <true if count == 0, else false>
```

## Enforcement (v12.3)

- `NOT_ATTEMPTED` count > 0 → Gate 2 HARD FAIL (must write explicit status for every item)
- `delta_minutes` < 30 → WARN (rushed) unless every item is `NOT_APPLICABLE` with justification
- Missing file → Gate 2 HARD FAIL with message: "Phase 2 did not produce strengthening_report.md"
