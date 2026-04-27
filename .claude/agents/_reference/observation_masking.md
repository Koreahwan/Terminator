# Observation Masking (Context Efficiency)

Apply masking rules to SendMessage outputs. Agents must respect token budgets while maintaining evidence integrity.

## Masking Thresholds

| Output Size | Handling |
|-------------|----------|
| < 100 lines | Full inline — no masking needed |
| 100-500 lines | Key findings inline + save full to file + reference path |
| 500+ lines | **MASKING REQUIRED** — `[Obs elided. Key: "..."]` + save to file + file path |

## Implementation

### Small Output (< 100 lines) — Inline

```
I found 3 high-value endpoint candidates:
- POST /api/billing/refund -> business logic + money movement
- GET /api/users/{id}/invoices -> possible IDOR/BOLA
- GET /api/v0/export -> legacy data export review

Next: analyst reviews access-control and workflow context.
```

### Medium Output (100-500 lines) — Key + File

```
Found 47 endpoints across authenticated crawl and passive sources:

[KEY FINDINGS]
- 6 billing/account endpoints scored 8+
- 9 low-score endpoints kept in raw review because they are state-changing
- 3 endpoints returned 401/403 but expose protected resource names

[FULL ANALYSIS]
Saved to: /absolute/path/to/high_value_targets.md

Next: safe test planner builds manual verification steps.
```

### Large Output (500+ lines) — Masking Required

```
[Obs elided. Key: "Endpoint inventory preserved 312 raw URLs. High-value queue contains billing refund, invoice access, admin invite, and legacy export candidates; raw-review queue keeps ambiguous POST /api/process and /api/v0/sync."]

Full analysis: /absolute/path/to/attack_surface.json

Next: analyst receives high_value_targets.md and raw_endpoint_review.md
```

**Format**: `[Obs elided. Key: "<1-2 sentence summary>"]`

## File Saving Rules

- **Always use absolute paths** when referencing saved files
- **Confirm file exists** before referencing
- **Archive location**: Same dir as task (`targets/<target>/` or the active report directory)
- **Naming**: descriptive + timestamp if multiple rounds
  ```
  gadget_analysis_round1.md
  endpoint_map_phase1.md
  vulnerability_candidates_draft.md
  ```

## HANDOFF Protocol (Agent to Agent)

Always include `[KNOWLEDGE CONTEXT]` and `[OBSERVATIONS]` sections:

```
[KNOWLEDGE CONTEXT]
1. [IDOR/BOLA] — Object identifiers in user, order, invoice, and workspace APIs need ownership checks
2. [BusinessLogic] — Billing, refund, invite, and role-change flows require state-machine review

[OBSERVATIONS]
[Obs elided. Key: "GET /api/users/{id}/invoices and POST /api/billing/refund are high-value candidates. /api/v0/export is raw-review due legacy version + export keyword."]
Full details: /path/to/high_value_targets.md (47 lines)

[CRITICAL FACTS]
- Scope: *.example.com web/API only
- State-changing endpoints are manual review only
- Client pitch mode can use passive indicators only

[NEXT ACTION]
analyst: map auth, object ownership, tenant boundary, and safe verification plan
```

## Never Do

- ❌ Paste 500+ line tool output directly into SendMessage
- ❌ Inline full decompile output (save to file)
- ❌ Inline full CodeQL results (summarize + reference)
- ❌ Repeat the same large output across multiple agents (cite file path once)

## Exception: Evidence Preservation

If output is **critical evidence** (exploit seed, core vulnerability, triager input):
- Always include full output in chat
- Also save to file for record
- Example: triager-sim destruction tests always get full PoC inline (for Gate evaluation)
