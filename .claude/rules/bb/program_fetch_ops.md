# Phase 0.1 Program Fetch — Raw-Bundle Layer + Playwright Operations

Referenced from `bb_pipeline_v13.md` Phase 0.1. This file contains the v14 raw-bundle details, private/invitation-only SPA login flow, retrospective refetch procedure, and per-platform handler confidence.

## Supported handlers (v12.4+) — confidence / priority

- **HackerOne** — GraphQL + policy HTML (0.9 / 0.85 confidence)
- **Bugcrowd** — target_groups.json + react-props HTML (0.9 / 0.8)
- **Immunefi** — `__NEXT_DATA__` regex (0.95 — authoritative)
- **Intigriti** — public researcher API + Nuxt fallback (0.9 / 0.7)
- **YesWeHack** — api.yeswehack.com + HTML fallback (0.9 / 0.6)
- **HackenProof** — SSR HTML (0.8)
- **huntr** — `__NEXT_DATA__` + URL case variants (0.85 / 0.7)
- **Code4rena / Sherlock / audit contests** — github raw README (0.85)
- **Generic (jina)** — universal fallback, caps at 0.4 (HOLD only, never auto-PASS)

## Rationale

WebFetch+jina is lossy — HackerOne collapsed `<details>` sub-sections, Bugcrowd react-props payloads, Immunefi `__NEXT_DATA__` all get dropped or summarized. Per-platform handlers extract verbatim text directly so Phase 0.2 can move from "hand-fill from prose" to "verify auto-filled + fill live-traffic-only sections".

## v14 — raw-bundle layer (2026-04-18 NEW, MANDATORY)

`fetch-program` now runs `tools/program_fetcher/raw_bundle.capture()` automatically
after the structured parse. Emits:

```
targets/<target>/program_raw/
  landing.{html,json}     # raw HTTP response bytes of the landing page
  landing.md              # rendered text (HTML→text or JSON-indented)
  linked_NN__<slug>.{html,json,md}   # platform-hinted + keyword-matched depth=1 pages
  bundle.md               # concat: landing.md + all linked md (grep-source)
  bundle_meta.json        # manifest: URLs, sizes, content-type, errors
  bundle_part_NN.md       # split into parts when bundle.md > 500KB
  bundle_index.md         # only when split
```

`raw_bundle` **is not a structured parser** — it's the authoritative verbatim substring
source for Phase 0.2 `verbatim-check`. Platform hints auto-inject known API URLs
(Intigriti public_api, YWH api.yeswehack.com, BC target_groups, H1 policy/scopes,
Immunefi __NEXT_DATA__-on-landing, huntr landing RSC). Accept header auto-switches
to `application/json` for API-shaped URLs so you don't get HTML fallback.

**Why**: Port of Antwerp OOS x2 (2026-04-14) — handler parsed `outOfScopes` bullet
list but missed "verbose messages without sensitive info" in non-bullet format. A
raw `landing.html` + `linked_*.json` dump catches it with `grep -i verbose
bundle.md`. Zendesk AI-RAG N/A (2026-04-17) same class — AI impact clause scattered
across landing + KB-article schema. Single authoritative substring target = zero
summarisation leakage.

Opt-out (NOT recommended): `--no-raw-bundle`. Disables verbatim kill-gate.

## Private / invitation-only SPA programs

Supported platforms: Intigriti / HackerOne private / BC private.

Raw-bundle tier 4 (Playwright) auto-escalates on SPA shells but defaults
to **anonymous** Chromium session. Invitation-only programs 404 / redirect
to marketing without a logged-in session. One-time setup:

```bash
# 1. Run the login helper — opens a visible Chromium with persistent profile.
./scripts/playwright_login.sh https://app.intigriti.com/auth/login
#    (or https://hackerone.com/users/sign_in for H1 private)
# 2. Log in normally (OAuth / 2FA / passkey — whatever the platform requires).
# 3. Close the browser window. Profile is saved to
#    $PLAYWRIGHT_BOUNTY_PROFILE (default: ~/.config/playwright-bounty-profile).
# 4. Thereafter, every bb_preflight.py fetch-program run auto-detects the
#    profile and Playwright tier 4 uses session cookies. Headless.
```

Verification: `bundle_meta.json` records `x-playwright-auth: persistent` vs
`anonymous`. If a private program still lands on marketing after login,
the session expired — re-run step 1.

## Retrospective refetch for pre-v14 targets

Targets captured before 2026-04-18 have no `program_raw/bundle.md`.
Run once to populate:

```bash
./scripts/refetch_active_targets.sh             # all public + auth-required where profile exists
./scripts/refetch_active_targets.sh --dry-run   # preview
./scripts/refetch_active_targets.sh --only qwant  # filter
```

Auth-required targets are auto-skipped if no Playwright session cookies
are present — run `scripts/playwright_login.sh` first.
