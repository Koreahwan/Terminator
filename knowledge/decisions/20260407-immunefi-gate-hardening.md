# [20260407] Immunefi Gate Hardening (v12.3)

## Context
Paradex #72310 rejected. Immunefi issued conditional unban warning.
Root cause analysis: Gate 1 and Gate 2 were too permissive — mock PoC keywords,
E3/E4 evidence, and severity mismatches passed through unchecked.

## Decision
Harden bb_pipeline_v12 to v12.3:
- kill-gate-1: --severity flag MANDATORY, HARD_KILL exit code (2) blocks gate
- kill-gate-2: E3/E4 evidence tier = FAIL (was advisory), mock PoC keywords = FAIL
- 3-layer AI detection mandatory before Phase 5 (heuristic + self-review + ZeroGPT)

## Alternatives Considered
- Manual review only (rejected: human bottleneck, inconsistent)
- Separate pre-submission review agent (rejected: adds latency without addressing root cause)

## Consequences
- Fewer findings reach submission (higher bar)
- Each submitted finding has higher acceptance probability
- Token cost slightly increased per gate (additional checks)
- Immunefi ban risk significantly reduced

## Status
accepted
