# Rejection Cases — Regression Fixtures

Each subdirectory represents one historical bug bounty rejection incident.
The fixtures are consumed by `tests/regression_oos_rejection.py`.

## Directory Structure

```
tests/fixtures/rejection_cases/
  <case>/
    program_rules_summary.md   # Realistic program rules in verbatim style
    finding_meta.json          # {"finding": "...", "severity": "...", "impact": "..."}
    expected_verdict.json      # {"verdict": "HARD_KILL|WARN|PASS", "expected_check": "...", "reason": "..."}
```

## Cases

| Case | Expected Verdict | Check | Incident |
|------|-----------------|-------|---------|
| port_of_antwerp_1 | HARD_KILL | 3.5 | K8s hostname disclosure, OOS verbose-messages clause |
| port_of_antwerp_2 | HARD_KILL | 3.5 | Java stack trace, OOS verbose-messages clause |
| okto | HARD_KILL | 3 | OAuth bypass on OOS asset onboarding.okto.tech |
| utix | HARD_KILL | 2 | Impact mismatch: "freezing" vs "unlocking stuck funds" |
| walrus | HARD_KILL | 1 | Severity "high" on Critical-only program |
| magiclabs | HARD_KILL | 9 | PKCE client-side-only N/R, submission rules exclusion |
| dinum | WARN | 10 | SIRET validation, government accessibility platform |
| paradex | HARD_KILL | kg2 | try/except + hardcoded fallback in PoC, kill_gate_2 |
| datadome | HARD_KILL | 6 | "Site vulnerabilities" catch-all OOS + XSS finding |

## program_rules_summary.md Format

Headers must use `##` prefix so `kill_gate_1` regex parsers match correctly:

```markdown
## Severity Scope
## In-Scope Assets
## Out-of-Scope
## Submission Rules
## Asset Scope Constraints
## Known Issues
## Impacts in Scope       (Immunefi-style programs only)
```

## Notes

- The `paradex` case uses `kill_gate_2` / `poc_pattern_check` instead of `kill_gate_1`.
  `finding_meta.json` includes a `poc_content` field with the bad PoC code.
- The `okto` case tests Check 3 (exclusion keyword match). The fixture OOS section
  explicitly lists `onboarding.okto.tech` as out-of-scope; the finding is on that asset.
- The `utix` case tests Check 2 (impact-scope mismatch). The `Impacts in Scope` section
  contains only "Unlocking stuck funds"; the finding impact is "permanent freezing."
- The `dinum` case expects exit code 1 (WARN), not 2 (HARD_KILL), because government
  accessibility design intent produces an advisory warning, not a hard block.

## Adding New Cases

1. Create `tests/fixtures/rejection_cases/<new_case>/`
2. Add all three files (`program_rules_summary.md`, `finding_meta.json`, `expected_verdict.json`)
3. Add the case tuple to `CASES` in `tests/regression_oos_rejection.py`
4. Run `PYTHONPATH=. python3 -m pytest tests/regression_oos_rejection.py -v` to verify
