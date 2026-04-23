# Best@N for Exploiter (BB-specific)

Referenced from `bb_pipeline_v13.md` Phase 2.

When exploiter fails on a CONDITIONAL GO finding (SCONE-bench Best@N 방법론):

1. First attempt: standard exploiter with analyst's approach
2. If fail → re-spawn exploiter with different approach hint (e.g., different auth bypass, injection vector, exploit primitive)
3. Max 2 re-attempts per finding (total 3 tries). 3rd fail → archive to `explore_candidates.md` as "explored, not proven"
4. Each re-attempt MUST use a **different strategy** — same payload retry is forbidden
