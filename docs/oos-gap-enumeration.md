# OOS / Invalid Rejection Gap Enumeration (v13 target)

**Document version**: 1.0 — 2026-04-17
**Status**: Draft for v13 implementation planning
**Source inputs**:
- `docs/oos-rule-audit.md` — section 8 known unhandled patterns (G01–G10)
- `knowledge/triage_objections/_common-failure-patterns.md` — 7 common patterns (P1–P7)
- `knowledge/triage_objections/*.md` — 8 postmortem files (real rejection incidents)

---

## Overview

This document enumerates all known gaps in the current OOS / Invalid rejection detection pipeline
(v12.5 snapshot). Each gap represents a case where a finding would pass all automated checks but
should have been killed or held before exploiter spawn (Gate 1) or before reporter spawn (Gate 2).

**Total gaps enumerated**: 15 (G01–G15)

### Current v12.5 Coverage vs v13 Target

| Metric | v12.5 Current | v13 Target |
|--------|--------------|------------|
| Total known gap classes | 15 | 15 |
| Gaps with HARD_KILL or FAIL enforcement | 5 (G01-partial, G08-partial, G09-partial, G10-partial, G15-partial) | 12 |
| Gaps with WARN-only enforcement | 3 (G04-partial, G07-partial, G11) | 3 remaining WARN |
| Gaps with zero automated enforcement | 7 (G02, G03, G05, G06, G12, G13, G14) | 0 |
| Real incidents traceable to these gaps | 11 submissions, 2 account bans, ~$12,000 in missed bounties | — |

### Key incidents mapped to gaps

| Incident | Gap(s) | Phase caught | Wasted work |
|----------|--------|-------------|-------------|
| Port of Antwerp ×2 OOS close (2026-04-14) | G01, G13 | Phase 5 (post-submit) | Full Phase 1–5 ×2 |
| Okto CAND-08/09 OOS scope intake error (2026-04-05) | G15 (pre-v12.4) | Phase 5.7 (saved) | Phase 1–5 ×2 |
| Utix #72165 impact mismatch (2026-04-04) | G04 | Phase 5 (post-submit) | Phase 1–5 |
| Walrus severity + branch scope (2026-04-05) | G10, G11 | Phase 5.5 (saved) | Phase 2–5 |
| Magic Labs PKCE bc91fc04 N/R −1 (2026-04-13) | G08 | Phase 5 (post-submit) | Phase 1–5 |
| Paradex #72310/#72418 autoban (2026-04-06/09) | G09 | Post-ban | Phase 1–5 ×3 + account ban |
| DataDome catch-all OOS (2026-04-17, preventive) | G02, G03 | Phase 0 (preventive) | None (caught early) |
| DINUM Won't Fix #7419-178 (2026-04-13) | G14 | Phase 5 (post-submit) | Phase 1–5 |

---

## Gap Table

---

### G01: Prose-only OOS paragraph not parsed by Intigriti handler

- **Pattern**: Intigriti `_extract_bullet_items()` silently drops non-bullet OOS content, leaving `scope_out` empty and allowing info-disc class findings to pass `kill_gate_1` Check 3 unwarned.

- **Why current rule misses it**:
  `intigriti.py` line 273 calls `_extract_bullet_items()` on each OOS revision entry. This function splits on bullet prefix characters (`-`, `*`, numbered list) and discards all other text. A program that writes its OOS as a prose paragraph — e.g. "We do not accept reports about verbose error messages or missing security headers as these are considered low risk in our threat model." — produces zero items in `pd.scope_out`. When `kill_gate_1` Check 3 (`bb_preflight.py` lines 751–770) tokenises `## Exclusion List` or `## Out-of-Scope`, it finds an empty section and emits no WARN. The info-disc finding then proceeds to exploiter spawn unchallenged.

- **Concrete example**:
  Port of Antwerp (Intigriti, 2026-04-14): program OOS verbatim was "Verbose messages/files/directory listings without disclosing any sensitive information." This was written as a single prose sentence in the OOS section, not a bullet. `_extract_bullet_items()` returned zero items. The K8s hostname and Java stack-trace findings passed Gate 1. Both were closed OOS after submission with triager comment matching the exact prose clause.

- **Proposed rule**:
  ```python
  # intigriti.py: _extract_bullet_items() fallback
  def _extract_bullet_items(text: str) -> list[str]:
      bullets = [line.lstrip("-*• ").strip() for line in text.splitlines()
                 if re.match(r"^\s*[-*•]|\s*\d+\.", line) and line.strip()]
      if bullets:
          return bullets
      # Fallback: sentence-level extraction when no bullets found
      sentences = [s.strip() for s in re.split(r"[.!?]+", text) if len(s.strip()) > 15]
      return sentences  # flag as prose_fallback=True in ProgramData
  ```
  Additionally, `kill_gate_1` Check 3 should treat `scope_out` items flagged `prose_fallback=True` with semantic matching (see G02) rather than pure token-overlap.

- **Severity of impact**: **Critical** — prose OOS clauses are common on Intigriti and GitHub-md programs. Missing them causes direct OOS submissions with accuracy penalty. Caused 2 OOS closes in the Port of Antwerp incident.

---

### G02: Ambiguous OOS keyword semantic mismatch ("Site vulnerabilities", "hypothetical flaw")

- **Pattern**: Broad or product-specific OOS vocabulary has zero token overlap with standard vulnerability class names, so `exclusion-filter` and `kill_gate_1` Check 3 return no match and the finding passes silently.

- **Why current rule misses it**:
  `kill_gate_1` Check 3 (`bb_preflight.py` lines 751–770) tokenises each exclusion line on `\W+` (filter `len >= 4`) and computes word overlap with the finding description. Any overlap fires a WARN. But "site vulnerabilities" contains tokens `["site", "vuln"]` — both < 4 chars after stripping — so the check produces zero tokens and fires no WARN for any finding. Similarly, "hypothetical flaw" (`["hypo", "flaw"]`) and "general web issues" produce no useful ≥4-char tokens. The program-specific vocabulary is semantically equivalent to "XSS, SQLi, CSRF, SSRF on web assets" but the token match cannot reach that equivalence.

- **Concrete example**:
  DataDome (preventive postmortem, 2026-04-17): OOS includes "Site vulnerabilities" as a catch-all for generic web application vulnerabilities affecting customer deployments. A finding "Reflected XSS on DataDome-protected customer site" has zero token overlap with "site vulnerabilities." Both `exclusion-filter` and Check 3 produce no warning. The finding would reach exploiter spawn and Phase 5 before being killed by a human reviewer or Phase 5.7.

- **Proposed rule**:
  ```python
  # bb_preflight.py: exclusion-filter and kill_gate_1 Check 3 addition
  CATCH_ALL_OOS_PATTERNS = [
      (r'\bsite\s+vulnerabilities?\b', "catch-all: web vulnerabilities on site assets"),
      (r'\bgeneral\s+web\s+(issues?|vulnerabilities?)\b', "catch-all: generic web findings"),
      (r'\bclient.?side\s+(only\s+)?vulnerabilities?\b', "catch-all: client-side class"),
      (r'\bthird.?party\s+(component|library|sdk)\s+(issues?|vulnerabilities?)\b',
       "catch-all: third-party dependencies"),
      (r'\bhypothetical\s+(flaw|issue|vulnerability)\b', "catch-all: theoretical findings"),
      (r'\bout.of.scope\s+by\s+design\b', "catch-all: design intent"),
  ]

  def check_catch_all_oos(scope_out: list[str], finding: str) -> str:
      """Returns 'HOLD:<matched_clause>' if any catch-all OOS clause found."""
      for item in scope_out:
          for pattern, label in CATCH_ALL_OOS_PATTERNS:
              if re.search(pattern, item, re.IGNORECASE):
                  return f"HOLD:{label}|verbatim:{item!r}"
      return "PASS"
  # exit 3 = HOLD — human review required before exploiter spawn
  ```

- **Severity of impact**: **High** — catch-all clauses appear in approximately 20% of programs. Missing them wastes full Phase 1–5 pipeline on OOS findings. No accuracy penalty since the finding is typically killed before submission, but 4–6 hours of agent time is lost per incident.

---

### G03: Program intent mismatch (anti-bot / CDN product scope)

- **Pattern**: Some programs accept only vulnerabilities within their product's specific threat model (e.g. bot-detection bypass, CDN misconfiguration). Standard web/API/smart-contract vulnerability classes found on any asset in their wildcard scope are OOS by intent, not by explicit exclusion listing.

- **Why current rule misses it**:
  No check in the current pipeline validates whether the finding *class* aligns with the program's *stated threat model*. `target-evaluator` outputs a `target_assessment.md` with tech stack match but no `threat_model_scope` field. `kill_gate_1` checks asset presence in scope (Check 2, Check 4) and impact vocabulary (Check 6) but does not cross-check the finding class against the program's primary product function. A standard IDOR finding on `api.datadome.co` would pass all gate checks because the asset is in scope and IDOR is not explicitly listed as OOS.

- **Concrete example**:
  DataDome (hypothetical, preventive): Their program's intent is to receive bypass/evasion reports against their bot-detection algorithms. An IDOR or SSRF found on their API backend is technically on an in-scope domain but misses the program's threat model. Triager would close as "not aligned with our security focus" or "intended behavior for API users." No current gate catches this.

- **Proposed rule**:
  ```python
  # target-evaluator prompt addition (Phase 0):
  # Output a new field: threat_model_scope (free-text, max 2 sentences)
  # Example: "Bot-detection bypass and evasion only. Generic web/API vulns are OOS."

  # kill_gate_1 new check: threat_model_class_check(finding, threat_model_scope)
  def threat_model_class_check(finding: str, threat_model_scope: str) -> str:
      """
      If threat_model_scope specifies a narrow product function,
      classify finding into: IN_MODEL | OUT_OF_MODEL | UNCERTAIN.
      OUT_OF_MODEL with narrow scope -> WARN (triager-sim judgment required).
      """
      # Use semantic overlap between finding class and threat_model_scope
      # Narrow scope keywords: "only", "bypass", "evasion", "specific to", "limited to"
      if re.search(r'\bonly\b|\bsolely\b|\bexclusively\b', threat_model_scope):
          # narrow scope declared — check finding class alignment
          ...
  ```
  Verdict: WARN with explicit triager-sim review required before exploiter spawn if threat model is narrow.

- **Severity of impact**: **Medium** — affects niche product-category programs (anti-bot, CDN, WAF vendors). Failure mode is full Phase 1–5 wasted on OOS finding with no accuracy penalty (triager closes without marking informative/duplicate, typically).

---

### G04: Separate "Impacts in Scope" list not extracted (Immunefi / Bugcrowd separate field)

- **Pattern**: Programs on Immunefi and Bugcrowd publish a constrained list of accepted impact categories (e.g. "Direct theft of any user funds", "Permanent freezing of funds") in a dedicated section. `kill_gate_1` Check 2's regex does not reliably locate this section, leaving `scope_impacts` empty and degrading the impact match to a WARN-only advisory instead of a blocking check.

- **Why current rule misses it**:
  `kill_gate_1` Check 2 (`bb_preflight.py` lines 692–749) reads in-scope impact phrases from `## In-Scope Assets` and `## Impacts? in Scope` sections using `re.findall`. The regex `Impacts? in Scope` matches "Impact in Scope" and "Impacts in Scope" but misses Immunefi-specific headings rendered by `render.py` as:
  - `## Smart Contract Bug Impacts`
  - `## Blockchain/DLT Bug Impacts`
  - `## Website and Applications Bug Impacts`
  When none of these match, `scope_impacts` is empty. Per lines 728–731, empty `scope_impacts` triggers only a WARN (`"No in-scope impacts parseable from rules"`), not a HARD_KILL. The impact cross-check is silently skipped, allowing any claimed impact to proceed.

- **Concrete example**:
  Utix #72165 (Immunefi, 2026-04-04): Utix listed exactly one accepted impact: "Unlocking stuck funds." Our report claimed "Permanent freezing of funds." The `## Impacts in Scope` section was rendered under `## Smart Contract Bug Impacts` by the Immunefi handler, which did not match the Check 2 regex. `scope_impacts` was empty → WARN only → gate passed → report submitted → triager closed as impact OOS.

- **Proposed rule**:
  ```python
  # bb_preflight.py kill_gate_1 Check 2: extend section heading regex
  IMPACT_SCOPE_HEADINGS = re.compile(
      r"##\s+(?:"
      r"Impacts?\s+in\s+Scope"
      r"|Smart\s+Contract\s+Bug\s+Impacts?"
      r"|Blockchain[/\w\s]+Bug\s+Impacts?"
      r"|Website\s+and\s+Applications?\s+Bug\s+Impacts?"
      r"|In.Scope\s+Impacts?"
      r"|Accepted\s+Impacts?"
      r"|Qualifying\s+Impacts?"
      r")",
      re.IGNORECASE,
  )
  # If heading matched but scope_impacts still empty after extraction:
  # → HARD_KILL (section exists but unparseable = structural error in rules file)
  # If no heading found at all: → WARN (section may be missing from template)
  ```
  Additionally, `render.py` should normalise all Immunefi impact-scope section headings to `## Impacts in Scope` at fetch time.

- **Severity of impact**: **Critical** — Immunefi enforces impact as a dropdown match. Any mismatch causes immediate auto-reject regardless of finding quality. Loss: full Phase 1–5 work + accuracy penalty. Caused 1 confirmed rejection (Utix #72165).

---

### G05: YesWeHack `non_qualifying_vulnerability` field not propagated effectively to kill_gate_1

- **Pattern**: YesWeHack's structured `non_qualifying_vulnerability` list is appended to `scope_out` but the token-overlap matching algorithm in `kill_gate_1` Check 3 fails to detect matches because YWH's non-qualifying items use multi-word phrases whose individual tokens are all short (< 4 chars) or use vocabulary with no overlap with finding descriptions.

- **Why current rule misses it**:
  `yeswehack.py` line 139 appends `non_qualifying_vulnerability` items to `pd.scope_out`. These items appear under `## Exclusion List` in `program_rules_summary.md`. `kill_gate_1` Check 3 tokenises each exclusion line on `\W+` with `len >= 4` filter and looks for any overlap with the finding description.
  YWH non-qualifying items like "Missing CSRF token on non-sensitive forms", "Lack of rate limiting on non-critical endpoints", "Self-XSS", "Tab nabbing" produce short-token sets: `["miss", "csrf", "lack", "rate", "self", "xss", "tab"]` — all ≤ 4 chars, all filtered out. Zero tokens survive the filter → zero overlap → no WARN fires. The check effectively never detects YWH-specific non-qualifying patterns.

- **Concrete example**:
  A finding "Missing CSRF protection on account settings form" on a YWH program where "Missing CSRF token on non-sensitive forms" is a `non_qualifying_vulnerability` item. Finding keywords: `["missing", "csrf", "protection", "account", "settings"]`. Non-qualifying item tokens after filter: empty (`csrf` = 4 chars → included, but `missing` also included → overlap 2 tokens → WARN fires). Edge case: "Self-XSS requiring social engineering" → `["self", "requ", "soci"]` → none ≥ 4 chars → no WARN. The check is inconsistent and cannot be relied upon for YWH findings.

- **Proposed rule**:
  ```python
  # bb_preflight.py: dedicated non-qualifying check for YWH
  def check_non_qualifying_ywh(scope_out: list[str], finding: str,
                                 platform: str) -> str:
      """
      For YesWeHack programs, non_qualifying_vulnerability items are stored
      with a platform tag. Use exact-string containment and semantic category
      matching instead of token-overlap.
      """
      if platform != "yeswehack":
          return "PASS"
      NQ_CATEGORY_MAP = {
          "csrf": ["csrf", "cross-site request forgery"],
          "rate_limit": ["rate limit", "brute force", "account lockout"],
          "self_xss": ["self-xss", "self xss"],
          "tabnabbing": ["tab nab", "tabnabbing", "reverse tabnap"],
          "missing_headers": ["missing header", "security header", "hsts", "csp", "x-frame"],
          "clickjacking": ["clickjack", "ui redress"],
      }
      for nq_item in [s for s in scope_out if s.get("source") == "non_qualifying"]:
          for category, synonyms in NQ_CATEGORY_MAP.items():
              if any(syn in nq_item["text"].lower() for syn in synonyms):
                  if any(syn in finding.lower() for syn in synonyms):
                      return f"WARN:non_qualifying_match|category:{category}|item:{nq_item['text']!r}"
      return "PASS"
  ```
  `scope_out` items should carry a `source` field (`"non_qualifying"` vs `"oos"`) set by the YWH handler to enable this disambiguation.

- **Severity of impact**: **High** — YWH programs commonly list 5–15 non-qualifying items. Token-overlap failure rate is estimated at >60% for short-token items. Missed detection leads to N/R or informative closes with potential accuracy/reputation impact on YWH.

---

### G06: HackenProof and huntr raw markdown prose loss

- **Pattern**: HackenProof's OOS text parser discards free-form prose OOS items that don't match the structured row format. huntr's `scope_out` is entirely synthetic (6 hardcoded items) and never includes per-repo restrictions from the maintainer's `SECURITY.md`.

- **Why current rule misses it**:
  **HackenProof**: `hackenproof.py`'s `_populate_from_html()` calls `section_between("Out of scope", ...)` to extract raw OOS text, then passes it to `parse_targets()` which expects the rigid `<name> Copy Copied <category> <severity> <reward>` row format. OOS items written as prose ("We do not pay for issues related to rate limiting, phishing, or social engineering attacks") do not match this row parser — they are silently dropped, leaving `scope_out` empty.
  **huntr**: `huntr.py` defines `HUNTR_DEFAULT_OOS` (6 synthesised items representing the global huntr platform policy). Per-repo restrictions written by maintainers in the repo's `SECURITY.md` or `SECURITY.rst` are not fetched. A repo maintainer who adds "We consider SQL injection issues out of scope for this project" to their `SECURITY.md` would never have that restriction visible to `kill_gate_1`.

- **Concrete example**:
  HackenProof program page: "Out of scope: Denial of service, spam, social engineering, physical attacks, and known issues listed at [URL]." This is raw prose. `parse_targets()` produces zero rows → `scope_out` empty → `kill_gate_1` Check 3 fires no WARN. A DoS finding passes Gate 1.
  huntr LlamaIndex repo: maintainer added `SECURITY.md` clarifying "Prompt injection via third-party data is accepted; path traversal via untrusted filenames is NOT considered a security issue." The `path traversal` OOS note is never loaded → Gate 1 passes path traversal findings.

- **Proposed rule**:
  ```python
  # hackenproof.py: add prose-fallback OOS parser
  def _parse_oos_prose(raw_text: str) -> list[str]:
      """Extract OOS items from free-form prose when row parser yields nothing."""
      # Split on comma, semicolon, and newline; strip common list prefixes
      items = re.split(r"[,;\n]", raw_text)
      return [i.strip().lstrip("-•*").strip() for i in items
              if len(i.strip()) > 8 and not re.match(r"^(out of scope|oos)$", i.strip(), re.I)]

  # huntr.py: add SECURITY.md fetch
  def _fetch_security_md(owner: str, repo: str) -> list[str]:
      """Fetch repo SECURITY.md via GitHub API and extract OOS-class sentences."""
      url = f"https://api.github.com/repos/{owner}/{repo}/contents/SECURITY.md"
      # Parse sections with headings containing "out of scope", "not accepted",
      # "exclusion", "will not fix", "not a vulnerability"
      ...
  ```

- **Severity of impact**: **High** — HackenProof is a primary platform for Web3/blockchain targets. huntr is primary for OSS CVE track. Silent OOS data loss on both platforms is a structural gap. Each missed OOS item can cause a direct OOS close.

---

### G07: Ambiguous in-scope qualifier ("APIs located under *.example.com" web-page asset mismatch)

- **Pattern**: Programs scope a wildcard domain with a type qualifier (e.g. "APIs", "mobile apps") but the automated gate checks only validate domain match, not asset-type match. A finding on a web page under the in-scope domain passes Gate 1 even though the program only covers APIs.

- **Why current rule misses it**:
  `kill_gate_1` Check 2 (`bb_preflight.py` lines 692–749) validates impact vocabulary against `## In-Scope Assets`. Asset type qualifiers within in-scope entries ("APIs located under *.example.com", "mobile app on iOS only") are not extracted or stored separately. The domain wildcard is matched but the type qualifier is silently ignored. Phase 5.7's "Scope Qualifier Check" is specified in `bb_pipeline_v12.md` as an Orchestrator manual judgment step — there is no automated enforcement before Gate 1. A finding can proceed through the entire Phase 1–5 pipeline before the type qualifier mismatch surfaces at Phase 5.7.

- **Concrete example**:
  A program scopes "REST APIs located under `*.api.example.com`". A finding is a UI redress / clickjacking issue on `app.example.com` (the web frontend, not the API). The domain `app.example.com` matches the wildcard `*.example.com` at a naive level. `kill_gate_1` passes the finding. Phase 5.7 Scope Qualifier Check: "APIs" qualifier vs web-page finding → HOLD. If the Orchestrator proceeds without noticing, the report is submitted and triager closes as OOS ("we only accept API-layer vulnerabilities").

- **Proposed rule**:
  ```python
  # program_data.py: extend scope_in entries with asset_type field
  # fetch-program handlers should extract qualifier keywords and store:
  # {"asset": "*.api.example.com", "asset_type": "api", "qualifier": "REST APIs"}

  # kill_gate_1: new check (runs after Check 2)
  ASSET_TYPE_KEYWORDS = {
      "api": ["api", "rest", "graphql", "grpc", "endpoint", "websocket"],
      "mobile": ["ios", "android", "mobile app", "apk", "ipa"],
      "smart_contract": ["smart contract", "solidity", "evm", "on-chain", "blockchain"],
      "web": ["web", "website", "web application", "portal", "dashboard"],
  }

  def check_asset_type_qualifier(finding: str, scope_in: list[dict]) -> str:
      """
      If in-scope entries have asset_type qualifiers, infer finding asset type
      from finding description and check for mismatch.
      """
      for asset in scope_in:
          if "asset_type" in asset and asset["asset"] in finding:
              inferred_type = infer_asset_type(finding)  # keyword-based
              if inferred_type != asset["asset_type"] and inferred_type != "unknown":
                  return f"WARN:asset_type_mismatch|scope_type:{asset['asset_type']}|finding_type:{inferred_type}|verbatim:{asset['qualifier']!r}"
      return "PASS"
  ```
  Phase 5.7 automated qualifier check should be upgraded from manual judgment to deterministic HOLD trigger.

- **Severity of impact**: **High** — asset-type qualifiers are present in approximately 30% of Bugcrowd and Intigriti programs. Mismatch causes OOS close at triager level. Entire Phase 1–5 pipeline is wasted per incident.

---

### G08: Client-side-only vulnerability N/R pattern (magiclabs PKCE incident)

- **Pattern**: Bugcrowd and some Intigriti programs contain clauses excluding client-side-only findings that lack a demonstrated server-side consequence. These clauses are phrased as submission-eligibility rules, not OOS items, so `exclusion-filter` and `kill_gate_1` Check 3 (exclusion-list matcher) never see them.

- **Why current rule misses it**:
  `exclusion-filter` (`bb_preflight.py` line 476) reads only three sections: `## Known Issues`, `## Already Submitted`, `## Exclusion List`. Client-side-only exclusion clauses on Bugcrowd are typically written under `## Submission Rules` or `## Additional Notes` — sections that `exclusion-filter` does not parse. `kill_gate_1` Check 1 (FEATURE CHECK) tests for "documented/intended behavior" but evaluates whether the behavior is a documented feature of the application, not whether it meets platform-specific evidence standards. No check validates whether the finding's precondition structure (client-side XSS required, user-interaction required, non-HTTPS network required) matches Bugcrowd's N/R eligibility criteria.

- **Concrete example**:
  Magic Labs PKCE (Bugcrowd bc91fc04, 2026-04-13): finding demonstrated `codeVerifier` persisted to `localStorage` (real SDK, real Chromium differential, evidence tier E2). However, extracting the value required either XSS on the same origin or physical device access — neither was demonstrated on the live production target. Bugcrowd's program brief included "client-side vulnerabilities that require victim browser interaction are Not Applicable." This clause was in `## Submission Rules`, not `## Exclusion List`. Gate 1 passed, Gate 2 passed (E2 tier), report submitted, triager closed N/R with −1 accuracy.

- **Proposed rule**:
  ```python
  # bb_preflight.py: extend exclusion-filter to parse Submission Rules section
  CLIENT_SIDE_ONLY_PATTERNS = [
      r"client.?side\s+(only\s+)?vulnerabilities?\s+(?:are\s+)?not\s+(applicable|accepted|rewarded)",
      r"(?:require|requiring)\s+(?:victim\s+)?(?:user\s+)?(?:browser\s+)?interaction\s+(?:are\s+)?(?:not|n/a)",
      r"(?:xss|cross.site\s+scripting)\s+(?:as\s+a?\s+)?prerequisite",
      r"theoretical\s+(?:attacks?|scenarios?|vulnerabilities?)\s+(?:are\s+)?not\s+(?:accepted|rewarded)",
      r"(?:must\s+)?(?:demonstrate|proven?)\s+(?:on\s+)?(?:production|live)\s+(?:target|environment)",
  ]

  def check_client_side_only(submission_rules: str, finding: str,
                              evidence_tier: str, platform: str) -> str:
      """
      If Submission Rules contain a client-side-only exclusion pattern,
      and finding requires XSS/browser interaction precondition:
      - E1 evidence: PASS
      - E2 evidence (Bugcrowd): WARN (platform requires E1 for client-side)
      - E3/E4: HARD_KILL
      """
      for pattern in CLIENT_SIDE_ONLY_PATTERNS:
          if re.search(pattern, submission_rules, re.IGNORECASE):
              if "xss" in finding.lower() or "browser" in finding.lower() or "interaction" in finding.lower():
                  if platform == "bugcrowd" and evidence_tier == "E2":
                      return "WARN:client_side_e1_required_bugcrowd"
                  elif evidence_tier in ("E3", "E4"):
                      return "HARD_KILL:client_side_no_poc"
      return "PASS"
  ```
  This check should run as part of `kill_gate_1` and also as part of `evidence-tier-check` after Phase 2.

- **Severity of impact**: **Critical** — Bugcrowd N/R results in −1 accuracy points. At Bugcrowd, accuracy score affects program invitation and priority queue position. Accumulated N/R marks can lead to reduced access to private programs. The magiclabs incident cost 1 accuracy point and full Phase 1–5 pipeline time.

---

### G09: try/except + hardcoded fallback PoC auto-detection gap (Paradex incident)

- **Pattern**: `kill_gate_2` Check 1 detects four mock-indicator keywords (`mock`, `simulated`, `fake`, `dummy`) but does not perform AST analysis on PoC files. `try/except` blocks suppressing transaction failures and assertions on Python arithmetic variables (not on-chain RPC reads) pass Gate 2 with evidence tier E2 if output files and real target URLs are present.

- **Why current rule misses it**:
  `kill_gate_2` Check 1 (`bb_preflight.py` lines 928–942) is a substring scan for four keywords. It cannot detect structural PoC quality violations: (1) bare `except` or `except Exception` in attack-phase code, (2) hardcoded numeric literal assignments immediately before assertion statements (e.g. `balance = 1_000_000`; `assert balance > 0`), (3) assertion operands derived from Python arithmetic rather than from a network call return value. None of these patterns contain the mock-indicator keywords. A PoC with `try: tx.send() except Exception: balance = expected_value; assert balance > 0` passes Check 1 and proceeds to evidence tier classification where real target URL presence elevates it to E2 → Gate 2 passes.

- **Concrete example**:
  Paradex #72418 (Immunefi, 2026-04-06): triager WAL feedback verbatim — "The PoC catches all contract call exceptions and continues execution using hardcoded Python values. Final assertions check local variables, not on-chain state. The attack sequence is arithmetic simulation, not a demonstrated exploit." Gate 2 passed this PoC. Result: Immunefi account permanent ban (accuracy 0/4, second disabled event in 3 days → autoban trigger).

- **Proposed rule**:
  ```python
  # bb_preflight.py kill_gate_2: new Check 1b — AST-based PoC quality
  import ast

  def check_poc_ast_quality(poc_file: Path) -> list[str]:
      """
      Parse PoC Python file and flag structural quality violations.
      Returns list of violation strings (empty = PASS).
      """
      violations = []
      tree = ast.parse(poc_file.read_text())

      # Visitor: collect all function defs, identify attack-phase functions
      # (exclude: main, setup, deploy, initialize — only flag exploit/attack/poc functions)
      for node in ast.walk(tree):
          if isinstance(node, ast.FunctionDef):
              func_name = node.name.lower()
              is_attack = any(k in func_name for k in
                              ["attack", "exploit", "poc", "execute", "drain", "steal"])
              is_infra = any(k in func_name for k in ["setup", "deploy", "main", "init"])
              if is_infra:
                  continue

              for child in ast.walk(node):
                  # Check 1: bare except in attack code
                  if isinstance(child, ast.ExceptHandler) and child.type is None:
                      violations.append(f"bare_except_in:{node.name}:line{child.lineno}")
                  # Check 2: except Exception (swallows all exceptions)
                  if isinstance(child, ast.ExceptHandler):
                      if child.type and getattr(child.type, "id", "") == "Exception":
                          violations.append(f"except_exception_in:{node.name}:line{child.lineno}")
                  # Check 3: assert on non-RPC variable (heuristic)
                  if isinstance(child, ast.Assert):
                      test = child.test
                      # If assert compares a Name that was last assigned from a literal
                      # (not from a Call), flag it
                      violations.append(f"review_assert_source_in:{node.name}:line{child.lineno}")

      return violations
  # Any violation from attack-phase function → FAIL (not WARN)
  ```

- **Severity of impact**: **Critical** — Submitting arithmetic-simulation PoCs to Immunefi triggered a permanent account ban (2x ban = autoban). Loss: Immunefi platform access permanently. No path to recover. This is the highest-severity gap class.

---

### G10: Severity boundary ambiguity in per-asset-class severity scope

- **Pattern**: `kill_gate_1` Check 1 builds `accepted_sevs` by substring-scanning the `## Severity Scope` section body. Programs that scope different severity tiers per asset class ("Critical for Smart Contracts, High for Web") produce `accepted_sevs = {critical, high}`, allowing a High-severity smart contract finding to pass even though the program only accepts Critical for that asset class.

- **Why current rule misses it**:
  `kill_gate_1` Check 1 (`bb_preflight.py` lines 662–690) uses four substring checks: `"critical" in sev_body`, `"high" in sev_body`, `"medium" in sev_body`, `"low" in sev_body`. It special-cases `"high+"` / `"high and above"` and `"critical only"` but does not parse asset-class-specific severity rows. Immunefi programs commonly use a two-column severity table:

  | Asset Class | Accepted Severities |
  |---|---|
  | Smart Contract | Critical |
  | Website/App | Critical, High |

  Substring scan of this table body finds both "Critical" and "High" → `accepted_sevs = {critical, high}`. A High-severity smart contract finding passes Check 1. The asset-class dimension is completely absent from the check logic.

- **Concrete example**:
  Walrus Smart Contracts (Immunefi, 2026-04-05): program accepted Critical only for smart contracts. Check 1 at the time had no severity scope logic (pre-v12.3). Post-v12.3, Check 1 was added but uses the substring scan described above. If Walrus had also accepted "High for Website", the check would produce `accepted_sevs = {critical, high}` and pass the High smart contract finding — the same bug reproduced at a different boundary.

- **Proposed rule**:
  ```python
  # bb_preflight.py kill_gate_1 Check 1: context-aware severity extraction
  def extract_severity_scope(rules_content: str) -> dict[str, set[str]]:
      """
      Returns a dict mapping asset_class → set of accepted severities.
      "global" key for program-wide scope (no per-asset table).
      """
      sev_section = extract_section(rules_content, "## Severity Scope")
      if not sev_section:
          return {}

      # Detect table format: lines with "|" separators
      if "|" in sev_section:
          result = {}
          for row in sev_section.splitlines():
              parts = [c.strip().lower() for c in row.split("|") if c.strip()]
              if len(parts) >= 2 and any(s in parts[0] for s in
                                         ["smart contract", "blockchain", "website", "web", "app"]):
                  asset_class = parts[0]
                  sevs = {s for s in ["critical", "high", "medium", "low"] if s in parts[1]}
                  result[asset_class] = sevs
          return result if result else {"global": extract_flat_severities(sev_section)}
      else:
          return {"global": extract_flat_severities(sev_section)}

  # kill_gate_1: check severity against asset-class-specific accepted set
  def check_severity_scope(severity: str, finding: str,
                            scope_map: dict[str, set[str]]) -> str:
      inferred_class = infer_asset_class(finding)  # "smart_contract" | "web" | "blockchain"
      applicable = scope_map.get(inferred_class, scope_map.get("global", set()))
      if applicable and severity not in applicable:
          return f"HARD_KILL:severity_{severity}_not_in_{inferred_class}_scope:{applicable}"
      return "PASS"
  ```

- **Severity of impact**: **High** — per-asset-class severity scoping is the standard Immunefi table format. Passing invalid-severity findings through Gate 1 leads to either direct OOS close (Immunefi auto-reject) or significant triager friction. The Walrus incident lost Phase 2–5 work.

---

### G11: Asset scope branch/tag drift (walrus main-only file)

- **Pattern**: `kill_gate_1` Check 4 emits a WARN when branch/tag constraints are detected in `## Asset Scope Constraints`, but does not perform automated `git checkout <tag> -- <file>` verification. The branch/tag check is advisory-only and can be missed under pipeline time pressure.

- **Why current rule misses it**:
  `kill_gate_1` Check 4 (`bb_preflight.py` lines 778–793) reads `## Asset Scope Constraints`. If any of three exact phrases are present (`"mainnet tags only"`, `"testnet tags only"`, `"tagged releases only"`), it emits a WARN and optionally checks the finding description for the strings `"main branch"` or `"main only"`. No automated `git checkout` command is executed. The walrus postmortem explicitly states that `git checkout mainnet -- slashing.move` returns non-zero exit (file not found in scoped tag) — this check was recommended but not implemented in v12.3. The WARN is advisory and easy to overlook during rapid Phase 0→Gate 1 progression.

- **Concrete example**:
  Walrus `slashing.move` (Immunefi, 2026-04-05): finding affected a file present in `main` branch but absent from the scoped `mainnet` and `testnet` tags. Check 4 would have emitted a WARN (the program had "mainnet tags only" in Asset Scope Constraints), but WARN is not blocking. Phase 2–5 proceeded until Phase 5.5 manual review caught it. Fix: upgrade Check 4 to attempt `git checkout <scoped_tag> -- <affected_file>` and treat non-zero exit as HARD_KILL.

- **Proposed rule**:
  ```python
  # bb_preflight.py kill_gate_1 Check 4: add automated git verification
  def check_branch_tag_scope(finding: str, constraints: str,
                              repo_path: Path) -> str:
      tag_match = re.search(
          r"(mainnet|testnet|release|audited)\s+tags?\s+only", constraints, re.I
      )
      if not tag_match:
          return "PASS"
      scoped_tag = tag_match.group(1)  # "mainnet", "testnet", etc.
      # Extract affected file paths from finding description
      affected_files = re.findall(r"[\w/]+\.(?:move|sol|rs|py|go|ts|js)", finding)
      for af in affected_files:
          result = subprocess.run(
              ["git", "checkout", scoped_tag, "--", af],
              cwd=repo_path, capture_output=True
          )
          if result.returncode != 0:
              return f"HARD_KILL:file_{af}_absent_from_{scoped_tag}_tag"
      return "PASS" if affected_files else "WARN:no_affected_files_in_finding_for_branch_check"
  ```
  Required: `repo_path` plumbed through from target workspace. If repo is not cloned locally, emit WARN + manual check instruction rather than skipping silently.

- **Severity of impact**: **High** — smart contract and Move/Rust programs commonly have explicit mainnet/testnet tag scoping. File-absent-in-scoped-tag is an immediate HARD KILL condition. The walrus incident wasted full Phase 2–5 work.

---

### G12: Platform autoban threshold not circuit-breaking submission

- **Pattern**: `platform_accuracy.py` circuit-breaker (added v12.3) blocks submission when Immunefi accuracy < 33% after 3+ submissions. However, the threshold and trigger conditions are not enforced before Gate 1 (pre-exploiter), only at Phase 5.5b before auto-fill. On platforms with aggressive autoban (Immunefi, Rhino.fi), a single marginal submission immediately following a close can trigger the ban — the circuit-breaker fires too late in the pipeline.

- **Why current rule misses it**:
  `platform_accuracy.py check <platform>` is called at Phase 5.5b (`bb_pipeline_v12.md` Phase 5.5b: Platform Safety Check). This is after full Phase 2–5 completion. If accuracy is borderline (e.g. 1/3 accepted = 33%, exactly at threshold), the check may PASS and allow the submission — but the third submission (even if high quality) could trigger the autoban if the platform's internal algorithm weighs recent closes more heavily than the simple ratio. Additionally, the AI-spam detection that banned Paradex #72759 was triggered by re-submitting within 48 hours after a ban-and-reinstatement cycle, which `platform_accuracy.py` does not model.

- **Concrete example**:
  Paradex #72759 (Immunefi, 2026-04-09): account was re-enabled after #72310 ban. #72418 was active (non-closed). Resubmitting #72759 within 72 hours of the re-enable event triggered the permanent ban. `platform_accuracy.py` was not yet implemented at this time. With v12.3 implementation: accuracy at that point was 0/2 closed = 0% → circuit-breaker would have blocked. But the "resubmit within 48h of ban-reinstatement" rule is not modeled — if accuracy were 1/2 = 50% (above threshold), the circuit-breaker would not have fired.

- **Proposed rule**:
  ```python
  # platform_accuracy.py: add ban-cooldown guard
  def check_platform_safety(platform: str) -> int:
      """Returns 0=SAFE, 1=WARNING, 2=BLOCKED."""
      record = load_accuracy_record(platform)

      # Existing: accuracy ratio check
      if record["total"] >= 3 and record["accepted"] / record["total"] < 0.33:
          return 2  # BLOCKED

      # New: ban-cooldown check
      if record.get("last_ban_reinstated_at"):
          days_since = (datetime.now() - record["last_ban_reinstated_at"]).days
          if days_since < 7:
              return 2  # BLOCKED: within 7-day cooldown after ban reinstatement
          elif days_since < 14:
              return 1  # WARNING: within 14-day cooldown

      # New: recent-velocity check (rapid submissions = autoban signal)
      recent_submissions = [s for s in record["submissions"]
                            if (datetime.now() - s["submitted_at"]).days <= 7]
      if len(recent_submissions) >= 3:
          return 1  # WARNING: 3+ submissions in 7 days on this platform

      return 0  # SAFE
  ```
  Also: circuit-breaker should be checked at Gate 1 (not only Phase 5.5b) so that exploiter spawn is blocked when the platform is unsafe — avoiding 3+ hours of Phase 2–5 work on a submission that cannot be sent.

- **Severity of impact**: **Critical** — platform account bans are permanent and unrecoverable. Immunefi ban caused ~$12,000 in missed bounties (active reports closed, future access blocked). Rhino.fi AI spam ban = permanent reputation damage. Early circuit-breaking at Gate 1 prevents committing Phase 2–5 resources to a submission that will trigger another ban.

---

### G13: Disclosure of information without direct security impact (catch-all OOS clause)

- **Pattern**: Programs on Intigriti, Bugcrowd, and HackenProof include broad clauses such as "Disclosure of information without direct security impact" or "Information exposure without exploitable consequence." These clauses are semantically equivalent to the Port of Antwerp verbose-OOS clause but use different wording that is not covered by the `_VERBOSE_OOS_PATTERNS` regex set in `_info_disc_oos_check`.

- **Why current rule misses it**:
  `_info_disc_oos_check` Gate 2 (`bb_preflight.py` line 529, `_VERBOSE_OOS_PATTERNS`) has 11 regex patterns covering "verbose messages/files/errors", "stack trace without", "banner grab", "version disclosure", etc. However, the generalised clause "disclosure of information without direct security impact" does not match any of the 11 patterns. The tokens "disclosure", "information", "impact" are common English words that do not trigger any specific pattern. A finding titled "Internal hostname disclosure" would match Gate 1 (`_INFO_DISC_KEYWORDS` has "hostname disclosure") but Gate 2 would fail to match the OOS clause → no HARD_KILL fired → finding proceeds to exploiter.

- **Concrete example**:
  Port of Antwerp ×2: the OOS clause "Verbose messages/files/directory listings without disclosing any sensitive information" was partially handled by v12.5 `_VERBOSE_OOS_PATTERNS`. However, if the same program had phrased the clause as "Disclosure of information without direct security impact," the current Gate 2 patterns would not match, and the finding would proceed despite being semantically identical. Any Intigriti program using the standard Intigriti platform-default OOS template (which includes this broader phrasing) would bypass the check.

- **Proposed rule**:
  ```python
  # bb_preflight.py: extend _VERBOSE_OOS_PATTERNS with generalised info-disc clauses
  _VERBOSE_OOS_PATTERNS_EXTENDED = _VERBOSE_OOS_PATTERNS + (
      r"disclosure\s+of\s+information\s+without\s+(?:direct\s+)?security\s+impact",
      r"information\s+(?:exposure|disclosure)\s+without\s+(?:an?\s+)?exploitable",
      r"(?:sensitive\s+)?data\s+(?:exposure|disclosure)\s+without\s+(?:proof|evidence|chain)",
      r"(?:internal|server|host|ip)\s+(?:address|name|info)\s+(?:without|not)\s+(?:sensitive|exploitable)",
      r"non.?exploitable\s+information",
      r"low.?risk\s+information\s+disclosure",
  )
  ```
  These patterns should be added to Gate 2 of `_info_disc_oos_check` to cover the generalised information-disclosure OOS category used by Intigriti's default program template and similar platforms.

- **Severity of impact**: **High** — Intigriti uses a standard program template that includes these generalised info-disc OOS clauses. Any program using the default template will have a Gap G13 vulnerability. Port of Antwerp incident is a confirmed case (partial coverage by v12.5, full coverage pending).

---

### G14: Government / public platform intentional-behavior scope

- **Pattern**: Government and civic-tech platforms (DINUM, public-sector programs) intentionally omit input restrictions as an accessibility mandate. "Missing validation," "insufficient input restriction," and "rate limiting absent" findings are Won't Fix by design — not by oversight or OOS listing. No current gate checks the platform's accessibility design philosophy before allowing these finding classes to proceed.

- **Why current rule misses it**:
  `kill_gate_1` Check 1 (FEATURE CHECK) tests whether the behavior is "documented/intended" by scanning `## Known Issues` and the program's explicit OOS list. Government platform accessibility mandates are in the program's About page / mission statement, not in the security program's OOS list. Phase 0 `target-evaluator` extracts tech stack and competition data from the program page but does not fetch About/mission pages. The DINUM finding passed Check 1 because the "no input restrictions" behavior was not explicitly called out in the program rules — the accessibility mandate was implicit in the platform's mission.

- **Concrete example**:
  DINUM Démarches Simplifiées #7419-178 (YesWeHack, 2026-04-04): SIRET prefill bypass (CWE-20). Triager response: "Toutes les démarches doivent être accessibles à toutes et tous" (universal access mandate). Won't Fix. Full Phase 1–5 wasted. The DINUM mission statement on `demarches-simplifiees.fr/apropos` explicitly states accessibility-first design. Fetching this page during Phase 0 would have provided the signal needed to elevate Check 1 false-positive risk for input-validation findings.

- **Proposed rule**:
  ```python
  # target-evaluator prompt addition (Phase 0):
  GOVT_PLATFORM_INDICATORS = [
      "demarches-simplifiees", "service-public", "gouv.fr",
      "gov.uk", "gsa.gov", "digital.gov", ".gov.au", ".gov.nz",
      "civic", "open-government", "public-sector",
  ]

  def check_govt_platform(target_url: str, about_page_text: str = "") -> str:
      """
      Returns 'ACCESSIBILITY_RISK' if target is a government/civic platform
      with known accessibility-first design philosophy.
      """
      is_govt = any(ind in target_url.lower() for ind in GOVT_PLATFORM_INDICATORS)
      has_accessibility_mandate = re.search(
          r"accessib|universel|tous et toutes|all citizens|open to all|no barriers",
          about_page_text, re.IGNORECASE
      ) is not None
      if is_govt or has_accessibility_mandate:
          return "ACCESSIBILITY_RISK"
      return "PASS"

  # kill_gate_1 Check 1 elevation:
  # If ACCESSIBILITY_RISK and finding_class in [input_validation, missing_restriction,
  #   rate_limiting, missing_authentication_on_public_endpoint]:
  # → HARD_KILL unless finding demonstrates concrete security consequence
  #   (credential theft, data exfiltration, privilege escalation) beyond the restriction gap itself
  ```

- **Severity of impact**: **Medium** — government platforms are a relatively small proportion of active bounty programs. Impact is wasted Phase 1–5 work but no accuracy penalty (Won't Fix does not affect platform reputation score on YWH). The DINUM incident is the confirmed case.

---

### G15: Missing Severity Scope / Impact Scope section in program_rules_summary.md template

- **Pattern**: `program_rules_summary.md` template does not mandate `## Severity Scope` or `## Impacts in Scope` as required sections. When Phase 0.2 `rules-check` runs, it enforces verbatim presence only for sections already in the template. If these sections are absent, kill_gate_1 Check 1 (severity scope) and Check 2 (impact scope) degrade silently to WARN-only — the exact failure mode that caused the Walrus and Utix incidents.

- **Why current rule misses it**:
  Phase 0.2 `rules-check` (`bb_preflight.py` lines 416–476) validates that auto-filled verbatim sections are present. The check list corresponds to sections in the `program_rules_summary.md` template. If `## Severity Scope` or `## Impacts in Scope` are not in the template as mandatory fields, `rules-check` does not flag their absence. `kill_gate_1` Check 1 (`bb_preflight.py` lines 662–690) has a fallback path: `if not accepted_sevs: emit WARN("Severity Scope section absent")` — this WARN does not block exploiter spawn. Similarly, Check 2 fallback for missing impacts section is advisory-only WARN. The template omission effectively makes both checks optional, bypassing critical protection for every program where these sections were not populated.

- **Concrete example**:
  Any program where Phase 0.2 `rules-check` completes but `program_rules_summary.md` lacks `## Severity Scope`: `kill_gate_1` Check 1 emits WARN `"Severity Scope section missing"` and continues. The finding passes regardless of its actual severity vs program scope. The Walrus incident occurred before v12.3 added Check 7, but the root mechanism (missing section → silent pass) was the same architectural gap. Even with v12.3, a program that legitimately has no published severity table will silently skip the check for every finding.

- **Proposed rule**:
  ```python
  # bb_preflight.py rules-check: add mandatory section enforcement
  MANDATORY_SECTIONS_V13 = [
      "## In-Scope Assets",
      "## Out-of-Scope",
      "## Severity Scope",      # NEW — was optional
      "## Impacts in Scope",    # NEW — was optional
      "## Asset Scope Constraints",
      "## Submission Rules",
  ]

  def rules_check(target_dir: Path) -> int:
      """Returns 0=PASS, 1=WARN (optional sections missing), 2=FAIL (mandatory missing)."""
      rules = (target_dir / RULES_FILE).read_text()
      missing_mandatory = [s for s in MANDATORY_SECTIONS_V13 if s not in rules]
      if missing_mandatory:
          print(f"[RULES_CHECK FAIL] Missing mandatory sections: {missing_mandatory}")
          print("Fill from program page verbatim before agent spawn.")
          return 2  # FAIL — blocks Phase 1 agent spawn
      return 0

  # kill_gate_1 Check 1 and Check 2 hardening:
  # If section is absent after rules-check PASS, section is genuinely empty on the program page.
  # In this case: HARD_KILL with message "Program page has no severity/impact scope table —
  # cannot verify finding is in scope. Manual review required."
  ```
  For programs that genuinely publish no severity table, the Orchestrator must manually annotate `## Severity Scope` with "all severities accepted" to pass `rules-check`. This makes the absence explicit and intentional rather than silently unverified.

- **Severity of impact**: **Critical** — this is a meta-gap that degrades the effectiveness of multiple other checks (G04, G10). Without mandatory section enforcement, any program page where fetch-program did not extract these sections will silently skip the most important kill-gate checks. Affected programs include any Immunefi target (Impacts in Scope = critical field), Bugcrowd programs with per-asset severity tables, and programs using non-standard section headings.

---

## Prioritization Matrix

| Gap | Impact | Effort | Priority (1=highest) | US Story | Incident-backed? |
|-----|--------|--------|---------------------|----------|-----------------|
| G15 | Critical | Low | **1** | US-004 (fetcher template) + US-005 (kill-gate-1) | Okto, Walrus, Utix |
| G04 | Critical | Medium | **1** | US-004 (fetcher render.py) + US-005 | Utix #72165 |
| G09 | Critical | Medium | **1** | US-006 (kill-gate-2 AST) | Paradex ×3 + account ban |
| G08 | Critical | Medium | **2** | US-005 (kill-gate-1) + US-006 | Magic Labs bc91fc04 |
| G01 | Critical | Low | **2** | US-004 (intigriti handler) | Port of Antwerp ×2 |
| G12 | Critical | Low | **2** | US-005 (gate-1 early check) | Paradex account ban |
| G13 | High | Low | **3** | US-005 (_info_disc_oos_check extension) | Port of Antwerp ×2 (partial) |
| G10 | High | Medium | **3** | US-005 (kill-gate-1 Check 1) | Walrus |
| G11 | High | Medium | **3** | US-005 (kill-gate-1 Check 4) | Walrus |
| G05 | High | Medium | **3** | US-005 (kill-gate-1 Check 3) | YWH general |
| G06 | High | High | **3** | US-004 (HackenProof + huntr handlers) | LlamaIndex (huntr) |
| G07 | High | Medium | **4** | US-004 (fetcher + scope_in struct) + US-005 | General |
| G02 | High | Medium | **4** | US-005 (kill-gate-1 Check 3 catch-all) | DataDome (preventive) |
| G14 | Medium | Low | **4** | US-005 (target-evaluator + kill-gate-1 Check 1) | DINUM #7419-178 |
| G03 | Medium | High | **5** | US-005 (target-evaluator threat_model field) | DataDome (preventive) |

### Implementation story mapping

| US Story | Description | Gaps addressed |
|----------|-------------|----------------|
| **US-004** | `program_fetcher` handler improvements — structured OOS/impact extraction | G01, G04, G06, G07, G15 |
| **US-005** | `kill_gate_1` new checks and check hardening | G02, G03, G05, G07, G08, G10, G11, G12, G13, G14, G15 |
| **US-006** | `kill_gate_2` AST-based PoC quality checks | G08 (evidence tier), G09 |

Gaps G01 and G04 have dependencies on both US-004 (structured data extraction) and US-005 (gate
logic that consumes the structured data). US-004 must be implemented first for these gaps.

---

## Coverage Goals

### v12.5 Current State

Of 15 enumerated gaps:

| Status | Count | Gaps |
|--------|-------|------|
| Fully enforced (HARD_KILL or FAIL) | 2 | G08 (partial, Bugcrowd-specific WARN only), G09 (partial, keyword-only, no AST) |
| Partially enforced (WARN advisory) | 5 | G07 (Phase 5.7 manual only), G10 (substring scan only), G11 (WARN not HARD_KILL), G12 (Phase 5.5b only, not Gate 1), G13 (partial, 11 patterns miss generalised form) |
| Zero automated enforcement | 8 | G01, G02, G03, G04, G05, G06, G14, G15 |

**v12.5 effective coverage**: 2–3 gaps with reliable enforcement out of 15 total = **~17–20% effective coverage**

### v13 Target

After US-004, US-005, US-006 implementation:

| Status | Count | Gaps |
|--------|-------|------|
| Fully enforced (HARD_KILL or FAIL) | 10 | G01, G04, G05, G08, G09, G10, G11, G12, G13, G15 |
| Partially enforced (WARN advisory) | 3 | G02, G07, G14 (human judgment required, cannot be fully automated) |
| Zero automated enforcement | 2 | G03 (threat model inference is LLM-based, no deterministic check), G06-huntr (SECURITY.md fetch feasibility TBD) |

**v13 target coverage**: 10 fully enforced + 3 WARN-with-escalation = **~87% effective coverage**

Residual gaps G03 and G06 (huntr) require either LLM-based classification (G03) or GitHub API
rate-limit consideration (G06-huntr). These are tracked as future work beyond v13 scope.

---

## Appendix: Gap-to-Incident Cross-Reference

| Gap | Postmortem file | Pattern ref | Real $-impact |
|-----|----------------|-------------|--------------|
| G01 | `20260414-port-of-antwerp-verbose-oos.md` | P1 | €0 ×2, 2 OOS closes |
| G02 | `datadome-site-vulnerabilities-precluded.md` | P1 variant | $0 (preventive) |
| G03 | `datadome-site-vulnerabilities-precluded.md` | P1 variant | $0 (preventive) |
| G04 | `utix-impact-scope-mismatch.md` | P3 | €0, 1 OOS close |
| G05 | `_common-failure-patterns.md` P1 cross | P1 | YWH general |
| G06 | `_common-failure-patterns.md` | — | LlamaIndex (partial) |
| G07 | `okto-oos-paraphrase.md` (Phase 5.7 catch) | P2 | $0 (Phase 5.7 saved) |
| G08 | `magiclabs-client-side-only-nr.md` | P5 | $0 + −1 accuracy |
| G09 | `paradex-autoban-tryexcept.md` | P7 | Permanent Immunefi ban |
| G10 | `walrus-severity-branch-scope.md` | P4 | $0 (Phase 5.5 saved) |
| G11 | `walrus-severity-branch-scope.md` | P4 | $0 (Phase 5.5 saved) |
| G12 | `paradex-autoban-tryexcept.md` | P7 | Permanent Immunefi ban |
| G13 | `20260414-port-of-antwerp-verbose-oos.md` | P1 | €0 ×2 (partial cause) |
| G14 | `dinum-wont-fix.md` | P6 | €0, Won't Fix |
| G15 | `okto-oos-paraphrase.md`, `walrus-severity-branch-scope.md`, `utix-impact-scope-mismatch.md` | P2, P4, P3 | $0 multiple incidents (root enabler) |
