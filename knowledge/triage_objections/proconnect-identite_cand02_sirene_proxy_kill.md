# KILL: proconnect-identite CAND-02 — Unauthenticated SIRENE API Proxy

**Program**: proconnect-identite (YesWeHack)
**Date**: 2026-04-17
**Gate**: Kill Gate 1
**Verdict**: KILL (3 independent signals)

## Finding
Unauthenticated /api/sirene/organization-info/:siret endpoint uses server-side API Entreprise bearer token — no session auth guard, rate limiting disabled in sandbox.

## Kill Reasons

1. **OOS — Rate-limiting clause**: Harm mechanism = unlimited unauthenticated requests exhausting quota. Program OOS verbatim: "Lack of rate-limiting, brute-forcing or captcha issues". Auth-gap reframe doesn't change the structural rate-limiting nature.

2. **No concrete sensitivity anchor (v12.5)**: SIRENE data = public via INSEE. "Unauthorized token use" = ToS/contractual harm between ProConnect and DAPI, not user security impact. No credentials/PII/auth-bypass chain.

3. **Likely intended design (P6 gov platform)**: Pre-authentication onboarding flow requires org lookup before login. Team has optional rate-limiter feature flag — aware of risk, chose feature-flag approach. Architecture is consistent with purpose.

## Pattern
French government SSO (DINUM ecosystem) — same P6 pattern as DINUM accessibility-first design. Missing restriction on pre-auth flow = likely intentional.

## Lesson
API quota exhaustion against public-data proxy = OOS (rate-limiting clause). "Unauthorized government token use" framing does NOT create security impact if the data returned is public.
