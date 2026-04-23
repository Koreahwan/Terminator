# Phase 0 — Live Bounty + Recent Submission Scans

Referenced from `bb_pipeline_v13.md` Phase 0. These are the v12.3 MANDATORY scans that run inside target-evaluator per candidate repo/program.

## Live Bounty Status Check (v12.3 — LiteLLM $0 incident, MANDATORY for huntr)

- WebFetch the per-repo bounty page (e.g. `https://huntr.com/repos/<owner>/<name>`)
- Parse repo header: look for `$<amount>` and `CVE` tag
- If repo shows **`$0` + `CVE` tag**: program is CVE-only, NO cash bounty → treat as NO-GO unless user explicitly opts in for CVE attribution only
- If repo shows `$N` but recent (≤6mo) submissions show `duplicate`/`informative` for the SAME vuln class: lower effective reward probability
- NEVER trust the program-level max (e.g. "up to $1,500") — always verify per-target active bounty
- Record the observed value verbatim in `target_assessment.md` under "Bounty Range (live)"

## Recent Submission Status Scan (v12.3 — LiteLLM duplicate incident, MANDATORY)

- Fetch most recent 10 reports from the target repo's submission history
- For each: record status (accepted/duplicate/informative/spam) + date + vuln class
- If same vuln class as your candidate was marked duplicate/informative in last 6 months → escalate to Gate 1 Q3 with calibrated duplicate risk
- Record findings verbatim in `target_assessment.md` under "Recent Submission History"
