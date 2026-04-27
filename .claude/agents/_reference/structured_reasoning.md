# Structured Reasoning (MANDATORY at Decision Points)

At every significant decision point, separate evidence layers before concluding.

## Decision Framework

```
OBSERVED: [concrete evidence from tools/execution — what you directly see/measure]
INFERRED: [logical deductions from observations — patterns, implications]
ASSUMED:  [unverified beliefs — FLAG THESE EXPLICITLY]
RISK:     [what breaks if assumptions are wrong]
DECISION: [action + brief rationale tying to observations]
```

## Examples

### Example 1: Access-Control Candidate Selection
```
OBSERVED:
- GET /api/users/{id}/invoices appears in authenticated crawl
- Path contains an object identifier and financial-data keyword
- Same resource family also exposes /api/users/me/invoices

INFERRED:
- Object-level authorization may be required
- This is a high-value manual IDOR/BOLA candidate
- Business impact could include billing data exposure

ASSUMED:
- The `{id}` value maps to a user-owned object
- Two authorized test accounts can be used after scope approval

RISK:
- Endpoint may enforce ownership correctly
- Client-pitch mode cannot actively test this

DECISION:
Queue for bounty manual verification with safe account-pair test; in client-pitch mode describe as an access-control review indicator only.
```

### Example 2: Vulnerability Classification
```
OBSERVED:
- POST /api/billing/refund is present in endpoint inventory
- Method is state-changing
- Path contains billing/refund keywords

INFERRED:
- Business-logic risk is high if workflow state is not enforced
- Automated execution is unsafe because the endpoint may move money or alter account state

ASSUMED:
- Refund requires auth and valid order context
- Program rules allow manual workflow testing only after scope confirmation

RISK:
- Accidental state change or financial impact
- False positive if endpoint is internal-only or properly protected

DECISION:
Do not auto-run. Put in `manual_test_queue.md` with safe preconditions, negative controls, and explicit user approval requirement.
```

## Usage Rules

1. **Never skip ASSUMED section** — all assumptions explicit
2. **RISK always present** — ask "what if assumptions wrong?"
3. **Evidence → conclusion order** — never reverse-engineer justification
4. **Shared with agent team** — include in HANDOFF for transparency
5. **On disagreement** — clearly mark which assumptions differ between agents

## Anti-Pattern (AVOID)

```
OBSERVED: Endpoint returns 200
INFERRED: Auth bypass exists
ASSUMED: ???
RISK: ???
DECISION: Submit finding

❌ This is backwards. Decision pre-made, framework used as justification cover.
```

## Correct Anti-Pattern Rewrite

```
OBSERVED: Endpoint returns 200 to an authenticated user
INFERRED: Endpoint exists and current user can access at least one object
ASSUMED: Other users' objects may be accessible (untested)
RISK: Ownership checks may block cross-user access; client-pitch mode cannot test this

DECISION: analyst → design two-account safe verification; reporter must keep status as candidate until evidence exists
```
