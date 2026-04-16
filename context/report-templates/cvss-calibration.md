# CVSS Calibration Guide

## Principle: Conservative by Default

Over-claiming severity damages credibility. Under-claiming loses money.
The sweet spot: honest assessment with conditional scenarios.

## Common Over-claims

| Metric | Over-claim | Reality | Fix |
|--------|-----------|---------|-----|
| AC:L | "Easy to exploit" | Requires specific config/timing | AC:H if any non-trivial precondition |
| PR:N | "No auth needed" | Needs basic account | PR:L unless truly unauthenticated |
| UI:N | "No user interaction" | Victim must click/visit | UI:R if any user action required |
| C:H/I:H/A:H | "Full compromise" | Limited to one component | Scope to actually proven impact |
| S:C | "Scope changed" | Impact stays in same component | S:U unless proven cross-boundary |

## Common Under-claims

| Scenario | Under-claim | Reality |
|----------|------------|---------|
| IDOR with PII | "Information disclosure" | Could be account takeover if settings writable |
| SSRF to internal | "SSRF — Medium" | Could be Critical if cloud metadata accessible |
| Auth bypass | "Missing authorization" | Full account takeover if admin accessible |

## Conditional CVSS Table (MANDATORY for ambiguous findings)

Always include at least 2 scenarios:

```markdown
| Scenario | Adjustment | Vector | Score |
|----------|-----------|--------|-------|
| If vendor considers intended behavior | AT:P, PR:H | AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N | 2.3 (Low) |
| If auth confirmed absent | PR:N, UI:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | 8.7 (High) |
| If chained with SSRF | VC:H, VI:H | AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N | 9.3 (Critical) |
```

## Programmatic Computation

Always compute, never estimate:

```bash
# CVSS 4.0
python3 -c "from cvss import CVSS4; v=CVSS4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'); print(v.score, v.severity)"

# CVSS 3.1
python3 -c "from cvss import CVSS3; v=CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'); print(v.score, v.severity)"
```

## VRT → CVSS Alignment (Bugcrowd)

VRT determines priority on Bugcrowd, but CVSS should be consistent:
- P1 (Critical): CVSS 9.0-10.0
- P2 (Severe): CVSS 7.0-8.9
- P3 (Moderate): CVSS 4.0-6.9
- P4 (Low): CVSS 0.1-3.9

If your CVSS says 9.5 but VRT maps to P3, something is wrong.
Re-evaluate both.
