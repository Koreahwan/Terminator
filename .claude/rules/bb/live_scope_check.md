# Phase 5.7 — Live Scope Verification (Detailed Spec)

Referenced from `bb_pipeline_v13.md` Phase 5.7. v12.2 MANDATORY. Orchestrator runs directly (not agent). EVERY submission must pass this before Phase 5.8.

## Procedure

1. **Re-fetch live program page via fetch-program** (v12.4 — replaces jina WebFetch):
   ```bash
   python3 tools/bb_preflight.py fetch-program targets/<target>/ <program_url> --no-cache --json > /tmp/live_scope.json
   # --no-cache bypasses the 24h fetch cache so this always hits the live page.
   # Writes fresh program_data.json, program_page_raw.md to targets/<target>/.
   ```
   Read back the verbatim In-Scope Assets, Out-of-Scope, and Asset Scope Constraints
   from the updated `program_rules_summary.md` + the new `program_page_raw.md`.

2. **Extract verbatim scope**: in-scope assets list (domains, apps, contracts, repos) + out-of-scope/exclusion list — EXACT wording from the live page (no summarization; fetch-program ships structured data).

3. **3-point verification**:
   - **Asset Match**: is the affected asset (exact domain/contract/repo) listed verbatim in scope, OR covered by a wildcard? If scope says "APIs located under *.example.com" but finding is on a **web page** (not API), flag as RISK.
   - **Scope Qualifier Check**: does the scope have qualifiers like "APIs", "smart contracts", "mobile apps only"? If finding's asset type doesn't match the qualifier → **HOLD** (report back to user with exact scope wording + concern)
   - **OOS Verbatim Match**: does finding match ANY out-of-scope item verbatim? → **KILL**

4. **Compare vs program_rules_summary.md**: if live scope differs from scout's summary → update program_rules_summary.md immediately.

5. **Save result**: `live_scope_check.md` in submission directory.

## Verdicts

- **PASS** (asset + type match, no OOS match) → Phase 5.8
- **HOLD** (scope qualifier ambiguity, e.g. "APIs" vs web page) → notify user with exact wording, user decides
- **KILL** (OOS verbatim match, asset not in scope at all) → archive

## IRON RULE

No auto-fill without Phase 5.7 PASS or user override on HOLD.
