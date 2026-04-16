# program_fetcher benchmark — main vs dev

**Date**: 2026-04-10
**Branch under test**: `dev/program-fetcher-v1`
**Baseline**: `main` (WebFetch → r.jina.ai → regex extraction)
**Candidate**: `dev` (`tools.program_fetcher.fetch` — per-platform handlers)

**Raw data**: [`results/main_vs_dev_2026-04-10.json`](./results/main_vs_dev_2026-04-10.json)

## Target set

29 targets covering all 8 supported platforms. Targets were drawn from each
platform's public listing (`engagements.json`, public programs API, etc.) —
no cherry-picking. Each target was fetched once per path with the cache
bypassed (`use_cache=False`).

## Headline metrics

| Metric | main (jina+regex) | dev (program_fetcher) | delta |
|---|---|---|---|
| ≥3 of 5 required fields populated | **4/29 (13%)** | **29/29 (100%)** | **+87 pp** |
| 5/5 fields populated | 0/29 (0%) | 27/29 (93%) | +93 pp |
| Total extracted content bytes | 51,305 | **632,437** | **12.3× more** |
| Average latency per target | 2.61 s | **1.57 s** | **1.7× faster** |
| Unhandled exceptions | 0 | 0 | same |

**Required fields** counted: `name`, `scope_in`, `scope_out`, `submission_rules`, `severity_table`.

## Per-platform breakdown

| Platform | Targets | main ≥3/5 | dev ≥3/5 | Δ | main bytes | dev bytes | ratio | verdict |
|---|---|---|---|---|---|---|---|---|
| hackerone | 5 | 1/5 | **5/5** | +4 | 22,998 | 113,905 | 5.0× | **WIN** |
| intigriti | 2 | 0/2 | **2/2** | +2 | 2,215 | 285,600 | 128.9× | **WIN** |
| immunefi | 5 | 0/5 | **5/5** | +5 | 346 | 85,238 | **246.4×** | **WIN** |
| bugcrowd | 5 | 0/5 | **5/5** | +5 | 3,738 | 54,500 | 14.6× | **WIN** |
| yeswehack | 4 | 2/4 | **4/4** | +2 | 10,206 | 61,733 | 6.0× | **WIN** |
| hackenproof | 4 | 0/4 | **4/4** | +4 | 0 | 16,269 | ∞ (main=0) | **WIN** |
| huntr | 2 | 0/2 | **2/2** | +2 | 24 | 1,700 | 70.8× | **WIN** |
| github_md | 2 | 1/2 | **2/2** | +1 | 11,778 | 13,492 | 1.1× | **WIN** |

Every platform is a win for `dev`.

## Dev verdict distribution

- **PASS**: 27/29 (93%)
- **HOLD**: 2/29 (7%)
- **FAIL**: 0/29

The two HOLDs are both from HackenProof (`nicehash-mining-platform`,
`init-capital-web`) — those programs do not ship a dedicated "Out of Scope"
section on their live pages. Not a handler bug; the upstream data is absent.

## Key reasons `main` loses

1. **JS-rendered content**: Bugcrowd, Immunefi, Intigriti, YesWeHack, and
   HackenProof all serve a ~3-150 KB HTML shell to unauthenticated callers.
   jina renders the shell; the actual program data is loaded at runtime
   via framework-specific paths (Next.js Flight, Angular TransferState,
   `changelog/<uuid>.json`, public REST APIs). The old pipeline sees
   navigation + footer + meta tags and nothing else.

2. **Cloudflare-blocked pages**: HackenProof returns 403 to curl/Mozilla
   user-agents. Googlebot UA passes through. The new handler uses
   Googlebot UA by default; the old pipeline has no such fallback.

3. **Collapsed `<details>` sections**: HackerOne policy pages collapse
   their "Out of Scope" lists inside `<details>` tags. jina drops them.
   The new handler uses GraphQL which returns both `structured_scopes` and
   the full `policy` markdown including OOS sub-headings.

4. **No verbatim extraction**: even when jina does return the markdown,
   the old regex extractor looks only for headings named exactly "In
   Scope" / "Out of Scope" / "Rules". Intigriti says "Scope & Rewards",
   Immunefi uses "Assets in Scope", Code4rena uses "Scope" with a
   markdown table — the old path misses all of them.

## Latency

Dev is 1.7× faster overall because:
- HackerOne GraphQL is a single 200-300 ms POST
- Intigriti / YesWeHack public APIs return JSON in 800-900 ms
- Bugcrowd changelog fetch is 1.3-1.4 s (two sequential JSON calls)
- Immunefi / HackenProof static HTML parsing is 1.5-2 s

jina is slower because every target routes through the reader proxy
(6-11 s for larger pages), and it times out against some dynamic URLs.

## Merge gate

| Check | Result |
|---|---|
| dev success ≥ main success | **PASS** (29 ≥ 4) |
| dev delta > +50 pp | **PASS** (+87 pp) |
| dev content > 2× main content | **PASS** (12.3×) |
| dev latency ≤ 2× main latency | **PASS** (dev is faster) |
| no dev exceptions | **PASS** (0/29) |

**OVERALL: MERGE APPROVED**

## Caveats & future work

- **HackenProof Cloudflare bypass**: the Googlebot UA whitelist could be
  revoked at any time. If that happens the handler falls back to HOLD with a
  clear Playwright fallback message.
- **Immunefi deferred Suspense content**: some `customOutOfScopeInformation`
  fields reference React Server Component Suspense boundaries
  (e.g. `$2e`, `$30`) that aren't in the initial HTML stream. The current
  handler drops those refs cleanly (no `$xxx` leakage into output) but the
  content itself is unrecoverable without executing JS. Playwright fallback
  would resolve this at the cost of 8-15 s per target.
- **GitHub API rate limit**: the unauthenticated limit is 60 requests / hour
  per IP. Production should export `GH_TOKEN` (5000/hr) before running
  large-scale audits.
- **HackerOne GraphQL schema drift**: HackerOne has changed their GraphQL
  schema twice in the last year (removed `severity`/`amount` from
  `BountyTableRow`, added `_minimum` variants). The current query is
  verified against the 2026-04-10 live schema. If it breaks again, the
  fix is to re-introspect via `{__type(name:"BountyTableRow"){fields{name}}}`.

## How to reproduce

```bash
# Run the benchmark (live network required, ~70 s total)
python3 tests/benchmarks/program_fetcher/program_fetcher_bench.py --path both

# Or use the standalone script used for this report
python3 /tmp/full_bench.py
```
