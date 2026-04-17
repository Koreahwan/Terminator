# Okto OOS Paraphrase Postmortem

**Date / Platform / Finding**: 2026-04-05 / Immunefi / OAuth redirect (CAND-08, HIGH) + postMessage origin bypass (CAND-09, MEDIUM)
**Reward Outcome**: OOS — both killed at Phase 5.7 before submission (saved by live scope re-fetch). Root cause was paraphrased scope intake upstream.

## 1. Root Cause

Program scope verbatim: **"This is not a wildcard scope"** — only specific listed domains were in scope. `onboarding.okto.tech` was not listed.

During Phase 0.2, scope was extracted via WebFetch + jina (pre-v12.4). Jina summarized the scope section: the non-wildcard qualifier was dropped and the resulting `program_rules_summary.md` implied broader coverage. Scout and analyst proceeded with `onboarding.okto.tech` as if in scope.

Phase 5.7 (live scope verification, added 2026-04-05) caught the mismatch by re-fetching the program page verbatim: the asset was not listed, verdict KILL. No submission was made, avoiding a duplicate/OOS mark. However, significant work (Phase 1–5) was wasted.

The Okto incident is cited in `bb_pipeline_v12.md` Phase 0.2 VERBATIM RULE: **"한 글자라도 빠뜨리면 OOS 제출 사고 발생 (Okto incident 교훈)"**.

## 2. Expected Gate Behavior

**Phase 0.1 + Phase 0.2 verbatim rule** should have caught this at scope intake — before any agent was spawned.

Expected behavior: `bb_preflight.py fetch-program` (v12.4 platform handler) extracts scope assets as a structured list with no summarization. `rules-check` then validates that the verbatim section matches the live page word-for-word.

## 3. Actual Gate Behavior

At the time (2026-04-05), Phase 0.1 did not exist. Phase 0.2 relied on WebFetch + jina for scope extraction. Jina collapsed the scope section (common with dynamic pages and collapsed `<details>` elements), dropping the "not a wildcard" qualifier.

`exclusion-filter` and `kill-gate-1` received the paraphrased scope and had no basis to flag the asset as OOS. The pipeline ran to Phase 5 before Phase 5.7 caught it.

**Implementation gap**: No structured, platform-specific scope extraction existed. Jina text summarization is lossy by design and cannot be trusted for verbatim accuracy.

## 4. Fix Path

v12.4 implemented the fix: `tools/bb_preflight.py fetch-program` with platform-specific handlers (Immunefi `__NEXT_DATA__` regex, HackerOne GraphQL, etc.) extracts In-Scope Assets, Out-of-Scope, and Asset Scope Constraints as structured verbatim data. Confidence < 0.8 → HOLD (never auto-PASS). Jina fallback capped at confidence 0.4 (HOLD only).

Additional guard: Phase 0.2 `rules-check` now validates that the auto-filled verbatim sections are present and not paraphrased before allowing agent spawn. If a section looks summarized or reordered, `fetch-program` must be re-run.
