# OOS / Invalid Rejection Rule Audit (v12.5 snapshot, 2026-04-17)

---

## 1. Summary

| Category | Count |
|---|---|
| Total distinct check entry points | 15 |
| HARD_KILL-capable checks | 8 |
| WARN-only (advisory) checks | 7 |
| Gate-blocking checks (exit 2 / exit 1) | kill_gate_1: 6 HARD_KILL paths; kill_gate_2: 4 FAIL paths |
| Handlers audited | 8 (yeswehack, bugcrowd, intigriti, huntr, hackenproof, immunefi, hackerone, github_md) |
| Documented gaps (Section 8) | 10 |

### HARD_KILL checks (block exploiter/reporter spawn)

1. `kill_gate_1` Check 0 — missing or invalid `--severity` parameter
2. `kill_gate_1` Check 1 — severity not in program's accepted severity scope
3. `kill_gate_1` Check 2 — claimed impact does not match any in-scope impact (score < 0.3)
4. `kill_gate_1` Check 3.5 — info-disclosure / verbose-OOS collision without sensitivity anchor (`_info_disc_oos_check`)
5. `kill_gate_1` implicit — `program_rules_summary.md` file missing
6. `kill_gate_2` Check -1 — `strengthening_report.md` missing or has `NOT_ATTEMPTED` items
7. `kill_gate_2` Check 1 — mock/fake/simulated/dummy keyword in PoC file
8. `kill_gate_2` Check 3 — evidence tier E3 or E4 (no output file or no real target URL)

### WARN-only checks (advisory, do not block)

1. `kill_gate_1` Check 2 — impact weak match (0.3–0.6 score range)
2. `kill_gate_1` Check 2 — no in-scope impacts extractable from rules
3. `kill_gate_1` Check 3 — exclusion list keyword overlap
4. `kill_gate_1` Check 3.5 — info-disc grey-zone (sensitivity anchor present but unproven)
5. `kill_gate_1` Check 4 — branch/tag scope restriction detected
6. `kill_gate_1` Check 5 — duplicate keyword overlap with previous submission title
7. `kill_gate_2` Check 2 — weak-claim language in evidence markdown

---

## 2. kill_gate_1 Checks

**Function**: `kill_gate_1(target_dir, finding, severity, impact)` — `bb_preflight.py` line 622.
**Returns**: 0 = PASS, 1 = WARN, 2 = HARD_KILL.
**Iron Rule**: No exploiter spawn without exit 0.

### Check 0 — Severity Parameter Validation (lines 643–653)

| Item | Detail |
|---|---|
| Logic | `severity` parameter stripped and lowercased. If empty string → HARD_KILL. If not in `{critical, high, medium, low}` → HARD_KILL. |
| HARD_KILL condition | `severity == ""` OR `severity not in ("critical", "high", "medium", "low")` |
| WARN condition | None — this check only produces HARD_KILL |
| Unhandled edge cases | Aliases like "crit", "med", "P1"–"P5" are rejected without mapping. Programs that use severity labels other than the standard four (e.g. "Informational", "None") will cause false HARD_KILL unless the caller normalises before invocation. |

### Check 1 — Severity Scope Match (lines 662–690)

| Item | Detail |
|---|---|
| Logic | Reads `## Severity Scope` section from `program_rules_summary.md`. Collects accepted severities by substring scan (`"critical" in sev_body`, etc.). Special patterns: `"high+"` / `"high and above"` → `{high, critical}`; `"critical only"` → `{critical}`. If finding's severity not in accepted set → HARD_KILL. |
| HARD_KILL condition | `accepted_sevs` non-empty AND `severity not in accepted_sevs` |
| WARN condition | `## Severity Scope` section absent from rules file → advisory warning only (no kill) |
| Unhandled edge cases | Substring scan can over-match: a program whose severity section has the word "Medium" in a prose sentence (e.g. "Medium complexity only") will add "medium" to `accepted_sevs` even if it is not a bounty tier. The `"High+" / "critical only"` pattern set is incomplete — does not handle `"Critical+Severe"`, `"P1/P2 only"`, `"High and Critical"` (different word order), or Immunefi's `"Critical (Blockchain/Smart Contract)"` multi-word label. |

### Check 2 — Impact Scope Matching (lines 692–749)

| Item | Detail |
|---|---|
| Logic | Extracts in-scope impact phrases from `## In-Scope Assets` and `## Impacts? in Scope` sections using a fixed `re.findall` pattern list (25 explicit impact keywords). Splits both claimed impact and each in-scope phrase on `\W+`, filters tokens `len >= 4`, computes word overlap ratio. Score < 0.3 → HARD_KILL; 0.3–0.6 → WARN; ≥ 0.6 or no in-scope impacts extracted → pass/advisory. |
| HARD_KILL condition | `best_match_score < 0.3` (claimed impact shares fewer than 30% of word tokens with any in-scope impact phrase) |
| WARN condition | `best_match_score in [0.3, 0.6)` (weak partial match); OR `claimed_impact` is non-empty but `scope_impacts` is empty (no phrases parsed from rules) |
| Unhandled edge cases | The 25-keyword regex covers common Immunefi/Bugcrowd terms but misses: (a) YesWeHack/Intigriti prose-form impact lists, (b) Bugcrowd VRT taxonomy labels ("Broken Access Control", "Business Logic Errors"), (c) programs that list impacts only in a `## Program Summary` prose paragraph rather than a dedicated section. The word-overlap algorithm also breaks on short or single-word impact claims like "RCE" (all tokens < 4 chars are filtered out, resulting in an empty `claimed_words` set which produces score 0 → false HARD_KILL). |

### Check 3 — Exclusion List Match (lines 751–770)

| Item | Detail |
|---|---|
| Logic | Reads `## Out-of-Scope` or `## Exclusion List` section. For each non-blank, non-comment line, tokenises on `\W+` (filter len >= 4), computes word overlap with finding description. Any overlap → WARN. |
| HARD_KILL condition | None — this check only produces WARN |
| WARN condition | Finding shares one or more ≥4-char tokens with any exclusion line |
| Unhandled edge cases | (1) Verbatim phrase exclusions with no ≥4-char words (e.g. "DoS", "XSS", "SQL") never fire. (2) Prose-paragraph OOS sections that are not formatted as bullet lists survive the line-by-line split but may produce noisy overlaps on common words like "vulnerability", "exploit", "attack". (3) Semantic equivalences are not checked: "rate limiting" vs "brute force" have zero token overlap despite being functionally related OOS items. |

### Check 3.5 — Info-Disclosure / Verbose-OOS Collision (lines 772–776, delegated to `_info_disc_oos_check` at line 560)

This check was added in v12.5 (Port of Antwerp postmortem, 2026-04-14). Full implementation details are in Section 5.

| Item | Detail |
|---|---|
| Logic | Three-gate cascade: (1) Does finding title match any keyword in `_INFO_DISC_KEYWORDS`? (2) Does program OOS contain a verbose-class pattern from `_VERBOSE_OOS_PATTERNS`? (3) Does `--impact` or finding contain any `_SENSITIVITY_ANCHORS` token? |
| HARD_KILL condition | Gates 1 and 2 both pass AND Gate 3 fails (no sensitivity anchor found) |
| WARN condition | Gates 1 and 2 both pass AND Gate 3 passes (sensitivity anchor present but unproven in PoC) |
| Unhandled edge cases | Listed in Section 5. |

### Check 4 — Asset Scope Constraints / Branch–Tag (lines 778–793)

| Item | Detail |
|---|---|
| Logic | Reads `## Asset Scope Constraints` section. If any of `"mainnet tags only"`, `"testnet tags only"`, `"tagged releases only"` in the body (lowercased), checks finding description for `"main branch"` or `"main only"` strings → WARN. Always emits a WARN reminder to verify code exists in the scoped version. |
| HARD_KILL condition | None — advisory WARN only |
| WARN condition | Branch/tag restriction keyword found in constraints; optionally also when finding mentions main-only code |
| Unhandled edge cases | (1) Only three hardcoded exact phrases are checked — misses "scoped to release branch", "only the audited commit", "commit hash X", etc. (2) The finding-description check for "main branch" / "main only" is fragile — a finding on `main` that does not use those exact words will not trigger the branch warning. (3) No automated `git checkout <tag> -- <file>` validation is performed; the walrus incident required this. |

### Check 5 — Duplicate Against Previous Submissions (lines 795–816)

| Item | Detail |
|---|---|
| Logic | Globs `submission/report_*/bugcrowd_form.md` and `submission/*/bugcrowd_form.md`. For each found form, extracts the `Title:` line, tokenises (len ≥ 4), computes overlap with finding keywords. Overlap ≥ 2 tokens → WARN. |
| HARD_KILL condition | None — WARN only |
| WARN condition | Two or more shared ≥4-char tokens between finding and an existing submission title |
| Unhandled edge cases | (1) Only `bugcrowd_form.md` files are scanned — Immunefi, Intigriti, YesWeHack submissions stored as plain `report.md` are not checked. (2) Cross-target duplicates are not checked (submissions for a different target directory would be missed entirely). (3) The ≥2 token threshold produces false positives for common security terms ("injection", "bypass", "authentication") while potentially missing single-token exact matches. (4) Does not check against `knowledge/challenges/` or `knowledge/triage_objections/` for platform-level known issues. |

---

## 3. kill_gate_2 Checks

**Function**: `kill_gate_2(submission_dir)` — `bb_preflight.py` line 841.
**Returns**: 0 = PASS (with optional WARNs), 1 = FAIL (blocks reporter spawn).
**Iron Rule**: No reporter spawn without exit 0.

### Check -1 — Strengthening Report Pre-check (lines 860–871)

| Item | Detail |
|---|---|
| Logic | Calls `strengthening_check(submission_dir)` as a sub-function before all other Gate 2 checks. Expects `strengthening_report.md` to exist and have zero `NOT_ATTEMPTED` items. If `strengthening_check` returns 1 (FAIL) → Gate 2 immediately exits 1 (HARD block). If returns 2 (WARN, delta_minutes < 30) → adds advisory warning but continues. |
| FAIL condition | `strengthening_check` returns 1: `strengthening_report.md` missing, `NOT_ATTEMPTED` count > 0, or file is structurally incomplete |
| WARN condition | `strengthening_check` returns 2: Phase 2 → Gate 2 time delta < 30 minutes |
| Unhandled edge cases | (1) `strengthening_check` itself is not audited here (separate function not shown in scope), but its delta_minutes calculation depends on ISO timestamps in the report; timezone-naive timestamps may produce incorrect deltas. (2) Checklist items can be marked `NOT_APPLICABLE` with any justification string — there is no semantic validation that the justification actually makes sense for the finding type. |

### Check 0 — Severity/Scope Re-check from Submission Files (lines 873–919)

| Item | Detail |
|---|---|
| Logic | Re-reads `program_rules_summary.md` at `sdir.parent.parent / RULES_FILE`. Parses accepted severities (same logic as kill_gate_1 Check 1). Scans all `**/*.md` in submission dir for `"severity: <sev>"` or `"severity**: <sev>"` patterns. Also checks `## Asset Scope Constraints` for branch/tag restriction → WARN. |
| FAIL condition | A markdown file in the submission dir claims a severity that is not in the program's accepted severity set (e.g. `"severity: medium"` when program is critical-only) |
| WARN condition | Branch/tag restriction detected in `Asset Scope Constraints` |
| Unaudited | `RULES_FILE` path resolution uses `sdir.parent.parent` — assumes the canonical layout `targets/<target>/submission/<name>/`. If submission is placed at a different nesting depth, rules file lookup silently fails and the check is skipped. |

### Check 1 — Mock PoC Detection (lines 928–942)

| Item | Detail |
|---|---|
| Logic | Scans all `**/*.py` and `**/*.sh` files in submission dir. For each file, lowercases content and checks for any of `["mock", "simulated", "fake", "dummy"]` as substrings. Any match → FAIL. |
| FAIL condition | PoC script contains any of the four mock-indicator keywords (case-insensitive substring match) |
| WARN condition | None — this check only produces FAIL |
| Unhandled edge cases | (1) Substring match produces false positives: a PoC that imports a library named `mock` (Python's `unittest.mock`) or has a comment like `# not a mock` will fire. (2) Does not detect hardcoded return values (`return {"balance": 1000000}`), `try/except` suppression, or arithmetic simulation — the primary Paradex failure modes. (3) Scope is only `.py` and `.sh`; JavaScript/TypeScript PoCs (`.js`, `.ts`) used in Web3 testing are not checked. |

### Check 2 — Evidence Weak-Claim Language (lines 944–967)

| Item | Detail |
|---|---|
| Logic | Scans all `**/*.md` files. Empty files (0 bytes) → FAIL immediately. For non-empty files, checks for any of `["inferred", "would", "likely", "probably", "could potentially"]` as substrings → WARN. |
| FAIL condition | Any evidence `.md` file has 0 bytes |
| WARN condition | Evidence file contains weak-claim language tokens |
| Unhandled edge cases | (1) The weak-claim keyword set is narrow — "may", "might", "appears to", "seems to", "could be" are not checked. (2) The check flags every occurrence including false positives (e.g. "This would affect users who…" in a correctly written impact section). (3) Empty `.md` FAIL fires for placeholder files like `NOTES.md` or `README.md` that may legitimately be empty in some workflows. |

### Check 3 — Evidence Tier Enforcement (lines 969–1013)

| Item | Detail |
|---|---|
| Logic | Classifies evidence into E1–E4 tiers using four boolean signals: `has_poc_script` (any `.py`/`.sh` found), `has_output_file` (glob of `output_*.txt`, `evidence_*.png/txt`, `response_*.txt`, `*_evidence.*`, `race_evidence_*`), `has_real_target_url` (PoC contains `https://` or `http://` or `requests.post/get` or `cast call` or `forge test`, AND does not contain `localhost` or `127.0.0.1` or `mock`), `has_before_after` (PoC contains `before`/`after`/`diff`/`delta`/`balance_before`/`balance_after`). Tier: E1 = all four signals; E2 = first three; E3 = poc only; E4 = nothing. E3/E4 → FAIL. |
| FAIL condition | Computed tier is E3 (PoC present but no output file or no real target URL) or E4 (no PoC at all) |
| WARN condition | None for tier — tier is always printed as informational |
| Unhandled edge cases | (1) `has_real_target_url` check scans all PoC file contents for `https://` — a comment with `# see https://github.com/...` will set the flag to True even if the PoC makes no real network call. (2) `has_output_file` glob patterns are a fixed list and miss custom evidence naming like `crash_output.txt`, `txhash.txt`, `response.json`. (3) `localhost`/`127.0.0.1` exclusion in `has_real_target_url` means PoCs against a local fork (Foundry/Anvil) are always E3 — but local fork PoCs are the correct method for DeFi submissions, creating a false tier downgrade for valid DeFi submissions. |

---

## 4. exclusion_filter

**Function**: `exclusion_filter(target_dir)` — `bb_preflight.py` line 476.

### What it does

Reads `program_rules_summary.md` from `target_dir` and extracts three sections by regex:

| Section regex | Purpose | Output label |
|---|---|---|
| `## Known Issues[^\n]*\n(.*?)(?=\n##\|\Z)` | Known/acknowledged issues | `### Known Issues (already reported/acknowledged)` |
| `## Already Submitted[^\n]*\n(.*?)(?=\n##\|\Z)` | Previously submitted findings | `### Already Submitted (do NOT duplicate)` |
| `## Exclusion List[^\n]*\n(.*?)(?=\n##\|\Z)` | Program-specific OOS classes | `### Program Exclusions (out of scope)` |

### How it injects into analyst prompts

The function prints to stdout with framing markers:

```
[EXCLUSION FILTER — Skip findings matching these patterns]
### Known Issues (already reported/acknowledged):
<content>
### Already Submitted (do NOT duplicate):
<content>
### Program Exclusions (out of scope):
<content>
[END EXCLUSION FILTER]
```

The Orchestrator captures this output and places it at lines 3–5 of the analyst prompt (per context-positioning rules in `handoff_protocol.md`). The analyst is instructed to skip any candidate finding that matches any listed pattern.

### Limitations

- Relies entirely on `## Exclusion List` being correctly populated by `fetch-program`. If the underlying handler produced a HOLD result or the section is blank, the analyst receives no exclusion guidance.
- Does not merge `## Out-of-Scope` (a different section name used by some handlers) — those items are silently skipped unless the rules template was filled with the canonical heading.
- No semantic expansion: if the exclusion list says "DoS attacks" but the finding is titled "Resource exhaustion via crafted request", zero keyword overlap means the analyst is not warned.

---

## 5. _info_disc_oos_check

**Function**: `_info_disc_oos_check(finding, impact, rules_content)` — `bb_preflight.py` line 560.
Added in **v12.5** following Port of Antwerp 2026-04-14 postmortem (two OOS closes for "verbose messages without sensitive information").

### Implementation

Three-gate cascade logic:

**Gate 1 — info-disclosure class detection**

Checks whether the lowercased `finding` string contains any keyword from `_INFO_DISC_KEYWORDS` (line 518). First match short-circuits. If no match, function returns immediately (no warnings/kills).

```python
_INFO_DISC_KEYWORDS = (
    "stack trace", "stacktrace", "verbose", "error message", "error response",
    "directory listing", "banner", "version disclosure", "source map",
    "exception trace", "hostname disclosure", "pod hostname",
    "internal url", "internal host", "internal endpoint", "path disclosure",
    "server header", "debug output", "debug info", "env dump",
    "environment variable", "configuration exposure", "information disclosure",
    "information exposure", "info leak", "info disclosure",
    "exposes k8s", "k8s hostname", "kubernetes hostname",
)
```

**Gate 2 — verbose-OOS clause detection in program rules**

Regex-searches the `## Out-of-Scope` or `## Exclusion List` section body (lowercased) against `_VERBOSE_OOS_PATTERNS` (line 529). First matching pattern is recorded. If OOS section is not parseable, emits an `[INFO-DISC UNCHECKED]` warning and returns.

```python
_VERBOSE_OOS_PATTERNS = (
    r"verbose\s+(?:message|file|error)",
    r"error\s+message[^.\n]*without",
    r"stack\s*trace[^.\n]*without",
    r"banner\s+grab",
    r"version\s+disclosure",
    r"directory\s+listing",
    r"information\s+disclosure[^.\n]*without[^.\n]*sensitive",
    r"internal\s+(?:ip|hostname|url|address)[^.\n]*without",
    r"non[\s-]?sensitive\s+information",
    r"without\s+disclosing[^.\n]*sensitive",
    r"(?:missing|lack\s+of)\s+(?:security\s+)?headers?",
)
```

**Gate 3 — sensitivity anchor requirement**

Checks whether any token from `_SENSITIVITY_ANCHORS` (line 545) appears in either `impact_lower` or `finding_lower`. If no anchor found → HARD_KILL. If anchor found → WARN (grey-zone).

```python
_SENSITIVITY_ANCHORS = (
    "credential", "password", "secret", "api key", "api-key",
    "private key", "session token", "session cookie", "access token",
    "bearer token", "refresh token", "jwt", "oauth token",
    "pii", "personally identifiable", "personal data",
    "ssn", "social security", "credit card", "payment card",
    "financial data", "health record", "phi",
    "authentication bypass", "auth bypass", "credential theft",
    "account takeover", "privilege escalation",
    "rce via", "remote code execution via",
    "sql injection via", "command injection via",
    "source code leak", "source code disclosure",
)
```

### Behaviour table

| Gate 1 | Gate 2 | Gate 3 | Outcome |
|---|---|---|---|
| No keyword match | — | — | No-op, function returns |
| Match | OOS section unparseable | — | `[INFO-DISC UNCHECKED]` WARN |
| Match | No verbose-OOS pattern match | — | No-op, clean pass |
| Match | Verbose-OOS pattern match | No sensitivity anchor | `[HARD_KILL]` INFO-DISC / VERBOSE-OOS COLLISION |
| Match | Verbose-OOS pattern match | Anchor present | `[INFO-DISC GREY-ZONE]` WARN |

### Known gaps in _info_disc_oos_check

- Gate 1 keywords are English-only — a finding titled "스택 트레이스 노출" (Korean) or "Offenlegung von Stacktraces" (German) bypasses all three gates.
- Gate 2 requires the verbose-OOS clause to be in a section headed `## Out-of-Scope` or `## Exclusion List`. Programs that write OOS in a `## Restrictions`, `## Prohibited`, or prose paragraph will not trigger Gate 2.
- Gate 3 only checks `finding` and `impact` strings — it does not inspect the PoC or evidence files. An impact string can assert "credential theft" without the PoC demonstrating it, allowing a WARN to pass through where a HARD_KILL was appropriate.
- The `(?:missing|lack\s+of)\s+(?:security\s+)?headers?` pattern in `_VERBOSE_OOS_PATTERNS` (Gate 2) will fire on programs that have a standard "missing headers are OOS" clause even when the finding is about a sensitive header (`Authorization`, `Set-Cookie` with `Secure` flag on login endpoint). This can produce incorrect HARD_KILLs on legitimate header-misconfiguration findings.

---

## 6. program_fetcher 8 Handlers

### Handler Summary Table

| Platform | Primary OOS extraction field(s) | Prose paragraph parsing? | Non-qualifying fields included in scope_out? | Notes |
|---|---|---|---|---|
| **yeswehack** | `out_of_scope` (verbatim list), `non_qualifying_vulnerability` (list) | No — structured list only | Yes — `non_qualifying_vulnerability` items appended to `scope_out` at line 139 | `rules` markdown field contains qualifying_vulnerability prose; no separate "impacts in scope" extraction |
| **bugcrowd** | `data.scope[].inScope == false` groups (target-level), `data.brief.targetsOverview` HTML (via `_populate_from_react_props` fallback) | Partial — HTML `targetsOverview` is parsed for OOS targets when changelog API fails | No separate non-qualifying field; `VRT_DEFAULT_OOS` (15 items) injected as fallback when scope_out is empty | CRITICAL fix in v12.4: in-scope/OOS groups distinguished by `group.inScope` bool flag; older responses use name-heuristic fallback |
| **intigriti** | `outOfScopes[].content.content` (bullet extraction only, prose dropped), per-asset OOS bullets from `assetsCollection` | No — `_extract_bullet_items()` strips all non-bullet content from each OOS revision | No — `severityAssessments` content used only for `submission_rules`; no impact scope list | Latest-per-section dedup preserves only highest `createdAt` per `####` heading key |
| **huntr** | `HUNTR_DEFAULT_OOS` (6 synthesised items) | No — no per-repo OOS section exists on huntr; global terms synthesised | N/A — huntr has no structured non-qualifying field | `scope_out` is always synthetic; real OOS is only "the rest of the internet outside the target repo" |
| **hackenproof** | Visible text between "Out of scope" and next section markers | Yes — `_visible_text()` strips tags then `section_between()` slices raw text; no bullet parsing | Rewards/severity data embedded in row-parsing; no separate non-qualifying field | Confidence 0.8; "Program rules" section parsed from `__NUXT_DATA__` flat-reference blob or `<meta description>` |
| **immunefi** | `defaultOutOfScopeGeneral`, `defaultOutOfScopeSmartContract`, `defaultOutOfScopeBlockchain`, `defaultOutOfScopeWebAndApplications`, `customOutOfScopeInformation`, `outOfScopeAndRules` (string fields), `customProhibitedActivities`, `defaultProhibitedActivities`, `prohibitedActivites` (typo), `prohibitedActivities` (list fields) | Partial — string OOS fields are split by newline and stripped; bullet prefix stripped; but multi-sentence prose paragraphs within those fields are treated as single items | Yes — all prohibited-activities lists appended to `scope_out` | Most complete OOS extraction of all 8 handlers; confidence 0.95 for Flight path |
| **hackerone** | `structured_scopes` edges with `eligible_for_submission == false` → scope_out, plus verbatim OOS section from `policy` markdown via `_extract_oos_from_policy()` | Yes — `_extract_oos_from_policy()` uses four regex patterns to find heading-delimited OOS block, then strips bullet prefixes line-by-line | No separate non-qualifying field | OOS from `policy` markdown is bullet-stripped but **prose sentences between bullets are also stripped** (only bullet lines pass through) |
| **github_md** | `## Out of Scope` and 11 variant headings, parsed by `grab()` + `_bullets()` | No — `_bullets()` extracts only bullet-list items | N/A — contest repos rarely have a non-qualifying field | Confidence 0.85; misses prose-only OOS paragraphs entirely |

---

## 7. Phase 5.7 Live Scope Verification

**Source**: `.claude/rules/bb_pipeline_v12.md`, "Phase 5.7: Live Scope Verification" section.

Phase 5.7 is a mandatory Orchestrator-run step (not delegated to an agent) that must execute before Phase 5.8 auto-fill. Its purpose is to re-fetch the live program page and compare against `program_rules_summary.md` to catch scope changes since initial scout.

### Steps

1. **Re-fetch via `fetch-program --no-cache`**:
   ```
   python3 tools/bb_preflight.py fetch-program targets/<target>/ <program_url> --no-cache --json > /tmp/live_scope.json
   ```
   The `--no-cache` flag bypasses the 24-hour fetch cache, ensuring a live page hit. This overwrites `program_data.json` and `program_page_raw.md` in the target directory with fresh content.

2. **Extract verbatim scope** from the updated `program_rules_summary.md` and `program_page_raw.md`. In-scope asset list, out-of-scope/exclusion list, and asset scope constraints are read back with exact wording (no summarisation).

3. **3-point verification**:

   | Check | Failure verdict |
   |---|---|
   | Asset Match: affected asset (exact domain/contract/repo) listed in scope or covered by a wildcard | KILL if not found at all |
   | Scope Qualifier Check: submission asset type matches scope type qualifier ("APIs", "smart contracts", "mobile apps only") | HOLD if type mismatch — requires user decision |
   | OOS Verbatim Match: finding matches any OOS item word-for-word | KILL |

4. **Diff vs. snapshot**: If live scope differs from initial scout's `program_rules_summary.md`, update the file immediately before proceeding to Phase 5.8.

5. **Save result** as `live_scope_check.md` in the submission directory.

### Verdicts

| Verdict | Condition | Action |
|---|---|---|
| PASS | Asset and type match; no OOS match | Proceed to Phase 5.8 |
| HOLD | Scope qualifier ambiguity (e.g. "APIs" scope but finding is on web page) | Notify user with exact scope wording; user decides |
| KILL | OOS verbatim match or asset not in scope at all | Archive finding |

### Phase 5.5b Strengthening Re-check (runs before 5.7)

Before Phase 5.7, `bb_preflight.py strengthening-check` is re-run as belt-and-suspenders enforcement. Exit 1 blocks submission. Exit 2 (rushed, delta < 30 min) prompts review but does not block.

### Iron Rule

No auto-fill (Phase 5.8) without Phase 5.7 PASS or user override on HOLD. This rule exists because `program_rules_summary.md` was written at scout time (Phase 0.2) and scope changes — asset additions/removals, severity tier reductions — can occur in the weeks between scout and submission.

---

## 8. Known Unhandled Patterns (Gap Preview for US-003)

The following gaps represent cases where a finding would pass all automated OOS/invalid checks but should be killed or held. Each maps to at least one real incident.

### G01 — Prose-only OOS paragraph not parsed by Intigriti handler

**Description**: Intigriti's `_extract_bullet_items()` at `intigriti.py` line 273 strips all non-bullet content from OOS revision entries. A program that writes its OOS as a prose paragraph ("We do not accept reports about verbose error messages or missing security headers as these are considered low risk...") produces zero items in `pd.scope_out`. `kill_gate_1` Check 3 then has no exclusion entries to match against, meaning the finding passes silently.

**Example**: Port of Antwerp's verbose-messages OOS clause was a prose paragraph on Intigriti; bullet extraction missed it, contributing to the 2026-04-14 OOS close.

**Required fix**: `_extract_bullet_items()` should fall back to sentence-level extraction when zero bullets are found, or at minimum preserve multi-sentence prose paragraphs as single `scope_out` items.

---

### G02 — Semantic ambiguous OOS keyword ("Site vulnerabilities" — DataDome)

**Description**: Some programs list OOS categories using platform-specific or product-specific vocabulary that has no token overlap with standard vulnerability class names. Example: DataDome's program OOS includes "Site vulnerabilities" as a catch-all for generic web application vulnerabilities against their customer sites. A finding titled "Reflected XSS on DataDome-protected site" has zero ≥4-char token overlap with "Site vulnerabilities" and passes `kill_gate_1` Check 3 entirely.

**Required fix**: A semantic equivalence table or embedding-based similarity check in `kill_gate_1` Check 3, or a program-specific annotation in `program_rules_summary.md` that maps unusual OOS terms to canonical vulnerability classes.

---

### G03 — Program intent mismatch (DataDome anti-bot, general vuln pipeline inapplicable)

**Description**: Some programs only accept vulnerabilities within the scope of their product's specific threat model. DataDome is an anti-bot service; they only accept bypass/evasion findings against their bot-detection product. A standard web vulnerability (IDOR, SSRF) found on a DataDome-protected client website is technically OOS even if the asset domain matches a wildcard in scope. No check in the pipeline validates whether the finding type aligns with the program's stated threat model.

**Required fix**: Phase 0 `target-evaluator` should output a `threat_model_scope` field. `kill_gate_1` could check finding class against this field.

---

### G04 — Separate "Impacts in Scope" list not extracted (Immunefi severity_table vs impacts list)

**Description**: `kill_gate_1` Check 2's impact regex at line 708 looks for impact phrases in `## In-Scope Assets` and `## Impacts? in Scope` sections. Immunefi programs ship a separate `## Impacts in Scope` section that lists accepted impact categories (e.g. "Direct theft of any user funds whether at-rest or in-motion", "Temporary freezing of funds") distinct from `severity_table`. If `fetch-program` renders these into `program_rules_summary.md` under a heading that does not match `## In-Scope Assets` or the `Impacts? in Scope` regex (e.g. "## Smart Contract Bug Impacts"), `scope_impacts` will be empty and Check 2 emits only a WARN instead of performing the match.

**Required fix**: Extend the section-heading regex in Check 2 to cover Immunefi-specific heading variants, or have `render.py` normalise all impact-scope sections to a canonical heading.

---

### G05 — YesWeHack `non_qualifying_vulnerability` field not propagated to kill_gate_1

**Description**: `yeswehack.py` appends `non_qualifying_vulnerability` items to `pd.scope_out` at line 139, so `program_rules_summary.md` will contain them under `## Exclusion List`. However, kill_gate_1 Check 3 uses word-overlap (≥4-char token, any overlap → WARN). YesWeHack's non-qualifying items are often specific vulnerability class labels ("Missing CSRF token on non-sensitive forms", "Lack of rate limiting on non-critical endpoints") whose short-word composition means they rarely share ≥4-char tokens with a finding description. The check fires on the right items less than 30% of the time in practice.

**Required fix**: Non-qualifying vulnerability items from structured platform APIs should be stored in a dedicated `## Non-Qualifying Vulnerabilities` section and matched with a separate exact-string or semantic check rather than the generic word-overlap algorithm.

---

### G06 — HackenProof and huntr raw markdown prose loss

**Description**: `hackenproof.py`'s `_populate_from_html()` extracts OOS via `section_between("Out of scope", ...)` from the visible text. This preserves the raw text block verbatim, but the result is stored in `pd.scope_out` only after being passed through `parse_targets()` which expects the rigid `<name> Copy Copied <category> <severity> <reward>` row format. OOS items written as free-form prose ("We do not pay for issues related to...") do not match this row parser and are silently dropped. Similarly, `huntr.py`'s OOS is entirely synthetic (`HUNTR_DEFAULT_OOS`); any per-repo restrictions written by maintainers in the repo's `SECURITY.md` or huntr description field are not retrieved.

**Required fix**: For HackenProof, add a prose-fallback path in the OOS parser. For huntr, fetch the target repo's `SECURITY.md` via the GitHub API and merge any OOS-class keywords into `scope_out`.

---

### G07 — Ambiguous in-scope qualifier ("APIs located under *.example.com" vs web page)

**Description**: Phase 5.7 Check "Scope Qualifier Check" is specified in `bb_pipeline_v12.md` as a manual Orchestrator judgment step. There is no automated check in `kill_gate_1` or `kill_gate_2` that validates whether the finding's asset type (web page, API endpoint, mobile app) matches the type qualifier attached to the in-scope asset (e.g. "APIs", "smart contracts", "iOS apps only"). A finding on a web page under `*.example.com` passes `kill_gate_1` because the domain matches the wildcard, even though the program scopes only APIs. This was documented as the primary concern in the Phase 5.7 "HOLD" verdict definition.

**Required fix**: `kill_gate_1` should extract asset type qualifiers from `pd.scope_in` and compare the finding's implicit asset type (inferred from URL pattern or `--impact` description) against the qualifier. Mismatched qualifiers should produce a WARN or conditional HOLD.

---

### G08 — Client-side-only vulnerability N/R pattern (magiclabs PKCE incident)

**Description**: Bugcrowd's program rules for some programs include clauses such as "Client-side vulnerabilities that require the user to be on an attacker-controlled network" or "PKCE-related issues requiring user interaction on a non-HTTPS page". These are not phrased as OOS exclusions but as submission-eligibility qualifiers. No check in the pipeline tests whether the finding requires client-side preconditions that match such N/R (Not Reproducible/Not Rewarded) patterns. The magiclabs PKCE finding (Bugcrowd `bc91fc04`) was closed N/R with a -1 reputation impact because the vulnerability required the user to be in a specific client-side context that the program considers insufficient for a valid submission.

**Required fix**: Add a client-side-precondition check to `kill_gate_1` that looks for N/R qualifier phrases in `## Submission Rules` and cross-references them with the finding's stated prerequisites.

---

### G09 — try/except + hardcoded fallback PoC not auto-detected (Paradex incident)

**Description**: `kill_gate_2` Check 1 detects the keywords `mock`, `simulated`, `fake`, `dummy` in PoC files. However, the primary failure mode in the Paradex #72310 incident was not a `mock` keyword but rather: (a) `try/except` blocks that suppressed transaction failures and continued with a hardcoded fallback value, and (b) assertion statements computed from Python arithmetic rather than on-chain state reads. Neither pattern is detected by any current check. A PoC with `balance = 1_000_000` (hardcoded) or `try: result = tx.send() except: result = expected_value` will pass Gate 2 with E2 tier if it also has output files and a real target URL.

**Required fix**: Add an AST-based PoC quality check (or `ast_grep_search` pattern) to `kill_gate_2` that detects: (1) bare `except` or `except Exception` in PoC files, (2) hardcoded numeric literal assignments immediately before assertion statements, (3) assertion operands that do not reference a variable populated by a network call.

---

### G10 — Severity boundary ambiguity (walrus Critical-only scope incident)

**Description**: `kill_gate_1` Check 1 reads the `## Severity Scope` section and builds `accepted_sevs` by checking if the severity name appears as a substring of `sev_body`. A program that documents its scope as "We accept Critical severity bugs for smart contracts and High severity bugs for web components" will have both "critical" and "high" in `sev_body`, resulting in `accepted_sevs = {critical, high}`. If the intent is that High is only accepted for web assets and Critical only for smart contracts, a High-severity smart contract finding will incorrectly pass. This type of per-asset-class severity scoping is common in Immunefi programs but is not modelled by the current substring scan.

**Required fix**: Severity scope extraction should be context-aware — if the scope table has asset-class-specific rows (e.g. a table with rows for "Smart Contract" and "Website"), the per-asset-class severity limits should be stored separately and matched against both the finding's asset type and its severity.

---

## Appendix A — Check Count Reference

| Gate / Function | Check ID | Trigger | Exit code |
|---|---|---|---|
| `kill_gate_1` | Check 0 | Missing or invalid --severity | HARD_KILL (2) |
| `kill_gate_1` | Check 0b | Missing `program_rules_summary.md` | HARD_KILL (2) |
| `kill_gate_1` | Check 1 | Severity not in program scope | HARD_KILL (2) |
| `kill_gate_1` | Check 1b | Severity Scope section missing | WARN (1) |
| `kill_gate_1` | Check 2 | Impact score < 0.3 | HARD_KILL (2) |
| `kill_gate_1` | Check 2b | Impact score 0.3–0.6 | WARN (1) |
| `kill_gate_1` | Check 2c | No in-scope impacts parseable | WARN (1) |
| `kill_gate_1` | Check 3 | Exclusion list keyword overlap | WARN (1) |
| `kill_gate_1` | Check 3.5 | Info-disc + verbose-OOS + no anchor | HARD_KILL (2) |
| `kill_gate_1` | Check 3.5b | Info-disc + verbose-OOS + anchor present | WARN (1) |
| `kill_gate_1` | Check 3.5c | Info-disc, OOS section unparseable | WARN (1) |
| `kill_gate_1` | Check 4 | Branch/tag restriction | WARN (1) |
| `kill_gate_1` | Check 5 | Duplicate keyword overlap | WARN (1) |
| `kill_gate_2` | Check -1 | strengthening_report missing/incomplete | FAIL (1) |
| `kill_gate_2` | Check -1b | Phase 2→Gate 2 delta < 30 min | WARN (advisory) |
| `kill_gate_2` | Check 0 | Severity OOS in submission .md files | FAIL (1) |
| `kill_gate_2` | Check 0b | Branch/tag restriction in submission | WARN (advisory) |
| `kill_gate_2` | Check 1 | Mock/fake/simulated/dummy in PoC | FAIL (1) |
| `kill_gate_2` | Check 2 | Empty .md evidence file | FAIL (1) |
| `kill_gate_2` | Check 2b | Weak-claim language in evidence .md | WARN (advisory) |
| `kill_gate_2` | Check 3 | Evidence tier E3 or E4 | FAIL (1) |

Total: 21 distinct check outcomes across 2 gate functions (13 in kill_gate_1, 8 in kill_gate_2).
HARD_KILL / FAIL outcomes: 8. WARN / advisory outcomes: 13.
