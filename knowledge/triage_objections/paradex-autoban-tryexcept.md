# Paradex Immunefi Autoban — try/except PoC Postmortem

**Date / Platform / Finding**: 2026-04-05 (#72310), 2026-04-06 (#72418), 2026-04-09 (#72759) / Immunefi / Vault donate() Share Inflation (Critical)
**Reward Outcome**: #72310 closed (mock PoC). #72418 active then account banned. #72759 closed 12 minutes after submission via autoban (2nd permanent ban). Account permanently disabled.

## 1. Root Cause

**Report #72310** — Triager OxBehroz: *"PoC does not fork real chain state"*, *"relies on mock contracts"*. Closed immediately.

**Report #72418** — Triager WAL feedback (verbatim from `feedback_poc_quality_ironrules.md`): *"The PoC catches all contract call exceptions and continues execution using hardcoded Python values. Final assertions check local variables, not on-chain state. The attack sequence is arithmetic simulation, not a demonstrated exploit."*

Three specific PoC quality violations:
1. `try/except` blocks in attack logic — exceptions were silently caught, allowing the script to "succeed" even when transactions failed.
2. Hardcoded fallback values — when a call failed, a Python-computed value replaced the on-chain result, making the simulation appear to work.
3. Arithmetic simulation — final assertions checked Python variables, not RPC-read on-chain state.

**Report #72759** — Triager instructed resubmission after #72418. Resubmit triggered Immunefi's automated spam/accuracy detector (second disabled event in 3 days → permanent ban). No human review.

## 2. Expected Gate Behavior

**kill-gate-2, Section A (Evidence Quality Check 1: LIVE vs MOCK)** should have caught #72310 and #72418.

For #72418 specifically: a PoC AST analysis check should have detected `try/except` blocks in attack-phase code and flagged `hardcoded_fallback` pattern → STRENGTHEN mandate before Gate 2 pass. The mock PoC keyword check should have caught the MockParaclear contract usage (#72310).

For #72759: `platform_accuracy.py` circuit-breaker (added v12.3) should have blocked the resubmission attempt: Immunefi account had just been re-enabled after one ban — accuracy was 0/4 (0%). Circuit breaker at <33% after 3+ submissions → block (or at minimum require explicit user override).

## 3. Actual Gate Behavior

At submission time of #72310 and #72418, kill-gate-2 had Section A quality checks but they were narrative/heuristic — the gate checked for mock PoC keywords in the finding description but did not perform AST analysis of the actual PoC Python file.

The `try/except` pattern was not checked by any automated gate. Kill-gate-2 Section A asked "LIVE vs MOCK" as a triager-sim judgment call rather than a code analysis step. The triager-sim missed the `try/except` + hardcoded fallback pattern.

For #72759: `platform_accuracy.py` was created as part of the v12.3 postmortem response (after the ban), so it did not exist at resubmission time. No circuit breaker was active.

**Implementation gap**: kill-gate-2 relied on triager-sim LLM judgment for PoC quality rather than deterministic code analysis. No AST-based `try/except` detection existed.

## 4. Fix Path

v12.3 added to kill-gate-2:
- Mock PoC keyword detection = FAIL (was WARN).
- Evidence tier E3/E4 = FAIL (was advisory).

Additional fix needed (not yet implemented): `bb_preflight.py kill-gate-2` should invoke Python `ast` module on the PoC file and check:
```python
# Flag any try/except in attack-phase functions (exclude main/setup)
# Flag assert on non-RPC variables
# Flag hardcoded numeric literals used in assertions
```

`platform_accuracy.py` circuit-breaker (implemented post-ban) prevents resubmission when accuracy < 33% after 3+ submissions or after a recent ban event.

PoC Iron Rules now in `bb_pipeline_v13.md` Phase 2: 0 try/except in attack logic, all tx succeed, all assertions on on-chain RPC reads. Enforced as IRON RULE.
