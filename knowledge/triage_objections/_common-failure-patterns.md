# Common Failure Patterns — Bug Bounty Rejection Postmortems

Synthesized from 8 rejection cases (2026-03 to 2026-04). Each pattern maps to one or more postmortem files and identifies the current gate limitation and proposed v13 fix.

## Pattern Table

| # | Pattern | 발생 케이스 | 현재 gate 한계 | v13 fix proposal |
|---|---------|------------|----------------|------------------|
| P1 | **Info-disc + verbose-OOS collision** — finding is information exposure class but program has "verbose messages without sensitive info" OOS clause. No concrete exploit chain → triager closes as OOS. | Port of Antwerp (×2, PORTOFANTWERP-7TS0VZVW + 56QI3QB6) | kill-gate-1 exclusion-filter uses token-overlap only. "verbose messages" tokens don't match "hostname/stack trace" keywords → false PASS. Check 9 (v12.5) added post-incident. | Semantic category mapping: info-disc class → check for verbose-OOS clause family. Require `--impact` concrete sensitivity anchor (credentials/PII/auth-bypass) before allowing WARN instead of HARD_KILL. |
| P2 | **Paraphrased scope intake** — WebFetch+jina summarizes scope section, drops qualifiers ("not a wildcard", "APIs only"). Downstream gates operate on incorrect scope. Waste of Phase 1–5 work. | Okto (CAND-08 HIGH + CAND-09 MEDIUM, both OOS) | Phase 0.2 relied on jina text extraction (lossy). exclusion-filter and kill-gate-1 received paraphrased scope with no structural check. Phase 5.7 caught it late. | Phase 0.1 `fetch-program` platform handlers (v12.4) extract verbatim structured data. Confidence < 0.8 → HOLD. Jina capped at 0.4 (never auto-PASS). `rules-check` enforces verbatim presence before agent spawn. |
| P3 | **Impact vocabulary mismatch** — Immunefi submission form uses a constrained impact dropdown. Claiming an impact not in the program's "Impacts in Scope" list triggers auto-reject, regardless of finding quality. | Utix (#72165, "Permanent freezing" vs "Unlocking stuck funds") | kill-gate-1 had no platform-specific impact enumeration check. Impact was treated as narrative quality, not hard constraint. | Check 6 (v12.3): `--impact` cross-check against verbatim "Impacts in Scope" list. No match → reframe attempt → still no match → HARD_KILL. Immunefi-specific enforcement. |
| P4 | **Severity + branch/tag scope misses** — Program accepts only Critical; finding is High. Or: affected file exists in `main` branch but not in scoped `mainnet`/`testnet` tags. Both are immediate KILL conditions that can be checked mechanically. | Walrus Smart Contracts (High severity + `slashing.move` main-only) | kill-gate-1 had no severity-scope or branch/tag verification steps. `program_rules_summary.md` fields existed but were not queried by the gate. | Check 7 (severity scope, v12.3) + Check 8 (branch/tag `git checkout`, v12.3). Phase 0.2 `rules-check` requires "Severity Scope" + "Asset Scope Constraints" as mandatory sections. |
| P5 | **Client-side-only finding on Bugcrowd** — Finding demonstrates SDK behavior in isolation (real package, real evidence) but requires XSS precondition or server-side validation to be proven. Bugcrowd marks as N/R: "theoretical, no valid PoC." | Magic Labs PKCE codeVerifier localStorage (bc91fc04, E2 evidence, -1 accuracy point) | kill-gate-1 Check 1 (FEATURE CHECK) tested for explicit intended-behavior documentation, not for client-side-only exclusion clauses. evidence-tier-check treated E2 as platform-agnostic pass. | Parse program rules for client-side-only exclusion clauses. Add platform-specific evidence tier table: Bugcrowd requires E1 for client-side findings with server-side prerequisites. E2-with-precondition → WARN or HARD_KILL depending on clause presence. |
| P6 | **Platform accessibility-first design** — Government/civic platforms intentionally omit input restrictions as a matter of mission ("universal access"). "Missing validation" findings are Won't Fix by design, not by oversight. | DINUM Démarches Simplifiées (#7419-178, SIRET prefill bypass, Won't Fix) | kill-gate-1 Check 1 only checked explicit OOS items and known-issues. Platform design philosophy (About page, mission statement) was not analyzed during Phase 0. | Phase 0 target-evaluator: for government/civic/public-sector platforms, fetch About/mission pages. If "universal access" / "accessibility" is core mandate → flag input-validation findings for high-confidence false-positive risk with FEATURE CHECK elevation. |
| P7 | **PoC try/except + arithmetic simulation** — Attack logic wraps contract calls in try/except, uses hardcoded fallback values on failure, and asserts on Python variables rather than on-chain RPC state. Triager: "arithmetic simulation, not a demonstrated exploit." Led to Immunefi account ban. | Paradex (#72310 mock contracts, #72418 try/except arithmetic, #72759 autoban) | kill-gate-2 Section A relied on triager-sim LLM judgment for PoC quality. No AST analysis of PoC source. Mock-PoC keyword check was WARN (not FAIL) pre-v12.3. No circuit-breaker on account accuracy. | kill-gate-2: Python `ast` module scan on PoC file — flag try/except in attack functions, hardcoded numeric literals in assertions, non-RPC variables in assert statements. `platform_accuracy.py` circuit-breaker (v12.3) blocks submission when accuracy < 33% after 3+ submissions. |

## Cross-Cutting Observations

**Gate timing failures**: P2 (Okto) and P4 (Walrus) were both caught eventually — by Phase 5.7 and Phase 5.5 respectively — but only after full exploit development. The pattern is the same: a mechanically checkable constraint was not verified at Gate 1 (pre-exploiter). Cost: 3–6 hours wasted per incident.

**LLM judgment vs. deterministic checks**: P3, P5, P7 all suffered from using LLM-based triager-sim judgment for checks that are structurally deterministic (impact dropdown match, AST analysis, severity table lookup). Future gate hardening should prefer deterministic code over LLM judgment wherever the check can be expressed as a rule.

**Semantic mismatch in exclusion-filter**: P1 and P8/DataDome both expose the same root issue — token-overlap matching cannot detect semantic category equivalence ("verbose messages" = info-disc class; "site vulnerabilities" = catch-all web vuln category). A category-aware exclusion matcher would prevent both.

**Platform-specific calibration gap**: P3 (Immunefi impact dropdown), P5 (Bugcrowd E2 threshold), P6 (YWH government platform) all require platform-specific logic that was missing from generic gate checks. The fix path is a platform-specific override table in `bb_preflight.py` rather than trying to make a single gate handle all platforms uniformly.

## Files Referenced

| File | Pattern |
|------|---------|
| `20260414-port-of-antwerp-verbose-oos.md` | P1 |
| `okto-oos-paraphrase.md` | P2 |
| `utix-impact-scope-mismatch.md` | P3 |
| `walrus-severity-branch-scope.md` | P4 |
| `magiclabs-client-side-only-nr.md` | P5 |
| `dinum-wont-fix.md` | P6 |
| `paradex-autoban-tryexcept.md` | P7 |
| `datadome-site-vulnerabilities-precluded.md` | P1 variant (catch-all OOS) |
