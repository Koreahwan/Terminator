# Bug Bounty Pipeline v12 — Explore Lane + Kill Gate

Referenced from CLAUDE.md. This file contains the full phase-by-phase procedure. Supersedes v11.

## Architecture: Explore Lane + Prove Lane

v12 splits the pipeline into two lanes:
- **Explore Lane** (Phases 0–1.5): Discover, model, understand. Kill bad targets and OOS early, but keep borderline findings alive in explore_candidates.md.
- **Prove Lane** (Phases 2–6): Validate, gate, submit. Only E1/E2 evidence proceeds to submission. Kill Gate rigor preserved from v11.

```
EXPLORE LANE                                              PROVE LANE
┌─────────────────────────────────────────┐   ┌──────────────────────────────────────┐
│ Phase 0:   target-evaluator (+ novelty) │   │ ★ Gate 1: triager-sim (finding)      │
│ Phase 0.2: bb_preflight rules           │   │ Phase 2:  exploiter (E1-E4 tiers)    │
│ Phase 0.5: automated tool scan          │   │ ★ Gate 2: triager-sim (PoC)          │
│ Phase 1:   scout + analyst + threat-    │   │ Phase 3:  reporter                   │
│            modeler + patch-hunter       │   │ Phase 4:  critic + architect          │
│ Phase 1.5: workflow-auditor + web-tester│   │ Phase 4.5:triager-sim (report)       │
│ ★ Gate 1→2: coverage + workflow check   │   │ Phase 5:  reporter (finalize)        │
└─────────────────────────────────────────┘   │ Phase 6:  TeamDelete                 │
                                               └──────────────────────────────────────┘
```

---

## EXPLORE LANE

### Phase -1: Target Verification (v12.3 NEW — MANDATORY, runs BEFORE Phase 0)

**Gate before any agent is spawned.** This catches LiteLLM/Composio/ONNX-Runtime-class
failures where scout would waste hours on $0 / unlisted / URL-case-wrong targets.

```bash
python3 tools/bb_preflight.py verify-target <platform> <target_url>
# 0 = GO (program exists with live cash bounty)
# 1 = NO-GO HARD (program not found, platform unsupported, or URL unrecognized)
# 2 = NO-GO CASH ($0 / CVE-only — rerun with --cve-only to opt in)
# 3 = WARN DUPLICATE (high duplicate/informative rate in recent submissions)
```

**Enforcement**:
- Exit 1/2 → STOP. Do NOT spawn target-evaluator. Inform user, suggest alternate platform.
- Exit 3 → user decision. Duplicate risk may still be worth hunting if finding is clearly novel.
- Exit 0 → proceed to Phase 0.
- `--cve-only` opt-in required for CVE-only programs. Default behavior = cash bounty mandatory.

**huntr URL casing bug (Composio incident)**: verify-target probes multiple case variants
(`owner` + `owner.lower()`) because huntr URLs are case-insensitive but scouts frequently
hard-code the GitHub display casing and get 404.

**New-platform rule (v12.3 — IRON RULE)**: If hunting on a platform where verify-target
does NOT have an `_verify_<platform>` parser implemented, you MUST first update
`bb_preflight.py` to add that parser BEFORE launching terminator.sh on any target from
that platform. verify-target returning exit 1 ("platform not implemented") blocks the
pipeline precisely to force this. Raw scout on an unverified platform is prohibited.

Supported platforms (as of v12.3): `huntr`, `bugcrowd`, `yeswehack` (alias `ywh`),
`intigriti`, `immunefi`, `hackenproof`. Adding a new platform requires:
1. Implement `_verify_<platform>(target_url, accept_cve_only)` in `bb_preflight.py`
2. Register in `_VERIFY_DISPATCH` dict
3. Test against at least 2 known-active and 1 known-dead programs
4. Document URL pattern + bounty parse format
5. Commit + only THEN launch terminator.sh targets

### Phase 0: Target Intelligence

1. `TeamCreate("mission-<target>")`
2. **Phase 0 historical-match (v13.7 NEW — MANDATORY)**: Before spawning target-evaluator, run:
   ```bash
   python3 tools/bb_preflight.py historical-match targets/<target>/ \
     --program "<program_or_repo>" --vuln-type "<expected_class>" --platform "<platform>"
   ```
   Source DB: `knowledge/accepted_reports.db` (auto-synced weekly via `scripts/sync_bounty_writeups.sh` cron, covers Bugcrowd crowdstream + huntr per-repo + YWH hacktivity + ZDI + Pentesterland + Infosec Writeups). Result feeds into target-evaluator (IRON RULE #8). `WARN` verdict with same-program rejections → CONDITIONAL GO max; ≥3 rejections + 0 accepts → NO-GO unless reframing articulated.
3. `target-evaluator` (model=sonnet) → program analysis, competition, tech stack match, **Research Novelty Score (v12)** → `target_assessment.md`
   - **GO** (48-60): full pipeline
   - **CONDITIONAL GO** (30-47): limited scope + token budget
   - **NO-GO** (<30 or Hard NO-GO): stop immediately
   - Kill Signal = instant NO-GO (deprecated, OOS, ghost program)
   - **Fresh-Surface Exception (v12)**: Mature target with new modules/bridges/migrations in last 6 months → CONDITIONAL GO for new surface only
   - **OOS Exclusion Pre-Check (MANDATORY)**:
     - Check program "Out of Scope" items exhaustively
     - Cross-check `immunefi.com/common-vulnerabilities-to-exclude/`
     - Especially: "Incorrect data supplied by third party oracles" (oracle staleness = OOS)
     - Check Known Issues / audit tracking docs
     - If candidate vuln type matches OOS → instant NO-GO
   - **Live Bounty Status Check (v12.3 — LiteLLM $0 incident, MANDATORY for huntr)**:
     - WebFetch the per-repo bounty page (e.g. `https://huntr.com/repos/<owner>/<name>`)
     - Parse repo header: look for `$<amount>` and `CVE` tag
     - If repo shows **`$0` + `CVE` tag**: program is CVE-only, NO cash bounty → treat as NO-GO unless user explicitly opts in for CVE attribution only
     - If repo shows `$N` but recent (≤6mo) submissions show `duplicate`/`informative` for the SAME vuln class: lower effective reward probability
     - NEVER trust the program-level max (e.g. "up to $1,500") — always verify per-target active bounty
     - Record the observed value verbatim in `target_assessment.md` under "Bounty Range (live)"
   - **Recent Submission Status Scan (v12.3 — LiteLLM duplicate incident, MANDATORY)**:
     - Fetch most recent 10 reports from the target repo's submission history
     - For each: record status (accepted/duplicate/informative/spam) + date + vuln class
     - If same vuln class as your candidate was marked duplicate/informative in last 6 months → escalate to Gate 1 Q3 with calibrated duplicate risk
     - Record findings verbatim in `target_assessment.md` under "Recent Submission History"

### Phase 0.1: Program Fetch (MANDATORY — v12.4 NEW, runs BEFORE Phase 0.2)

**Verbatim scope intake gate.** Replaces hand-copy-paste + WebFetch+jina
summarization for program page extraction. See `tools/program_fetcher/`.

```bash
python3 tools/bb_preflight.py init targets/<target>/
python3 tools/bb_preflight.py fetch-program targets/<target>/ <program_url>
# Exit codes:
#   0 = PASS  — verbatim sections auto-filled from platform-specific handler
#   1 = FAIL  — no handler succeeded / page unreachable → manual fallback
#   2 = HOLD  — confidence < 0.8, artifacts written for manual review
```

**Enforcement**:
- Exit 0 → proceed to Phase 0.2 (operational sections still need live traffic)
- Exit 1 → manual program_rules_summary.md fill from the live page (same as pre-v12.4)
- Exit 2 → review `program_data.json` + `program_page_raw.md`, add `--hold-ok` if accurate

**Supported handlers** (as of v12.4):
- HackerOne — GraphQL + policy HTML (0.9/0.85 confidence)
- Bugcrowd — target_groups.json + react-props HTML (0.9/0.8)
- Immunefi — `__NEXT_DATA__` regex (0.95 — authoritative)
- Intigriti — public researcher API + Nuxt fallback (0.9/0.7)
- YesWeHack — api.yeswehack.com + HTML fallback (0.9/0.6)
- HackenProof — SSR HTML (0.8)
- huntr — `__NEXT_DATA__` + URL case variants (0.85/0.7)
- Code4rena / Sherlock / audit contests — github raw README (0.85)
- Generic (jina) — universal fallback, caps at 0.4 (HOLD only, never auto-PASS)

**Rationale**: WebFetch+jina is lossy — HackerOne collapsed `<details>` sub-sections,
Bugcrowd react-props payloads, Immunefi `__NEXT_DATA__` all get dropped or summarized.
Per-platform handlers extract verbatim text directly so Phase 0.2 can move from
"hand-fill from prose" to "verify auto-filled + fill live-traffic-only sections".

**v14 — raw-bundle layer (2026-04-18 NEW, MANDATORY)**:
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

### Phase 0.2: Program Rules Generation (MANDATORY)

Orchestrator runs directly (not agent):
```bash
# Phase 0.1 already ran fetch-program above; verbatim sections are auto-filled
# AND program_raw/bundle.md (raw-bundle layer) is populated.
# Phase 0.2 is now: VERIFY auto-filled verbatim sections are traceable to
# bundle.md substring, then fill OPERATIONAL sections from live API traffic.
python3 tools/bb_preflight.py rules-check targets/<target>/
python3 tools/bb_preflight.py verbatim-check targets/<target>/   # v14 MANDATORY
# verbatim-check exit codes:
#   0 = PASS  — every bullet in Exclusion / In-Scope / Known Issues / Severity /
#               Asset-Scope-Constraints sections is substring-matched in
#               program_raw/bundle.md (allows bullet-prefix / backtick / metadata
#               suffix variation; token fallback via backtick + URL-shaped + 0x
#               address tokens).
#   1 = FAIL  — at least one bullet is NOT in bundle.md (HARD — blocks gate).
#               Either re-run fetch-program (page changed), or paste verbatim
#               from the live page into the summary.
#   3 = ERROR — bundle.md or rules_summary missing. Run fetch-program first.
```
- **Auto-filled by fetch-program** (do not re-paraphrase): In-Scope Assets,
  Out-of-Scope / Exclusion List, Known Issues, Submission Rules, Severity Scope,
  Asset Scope Constraints.
- **Fill from live traffic** (MUST still be done manually): Auth Header Format,
  Mandatory Headers, Verified Curl Template, Already Submitted Reports.
- **VERBATIM RULE**: if a verbatim section looks summarized or reordered, rerun
  fetch-program or paste from the live page. 요약/paraphrase 절대 금지.
  한 글자라도 빠뜨리면 OOS 제출 사고 발생 (Okto incident 교훈).
- Verify auth from API traffic (Frida/mitmproxy/curl), then update operational sections.
- PASS → proceed | FAIL → fill missing sections until PASS. **No agent spawn until PASS.**

### Phase 0.5: Automated Tool Scan

scout runs Slither/Semgrep (DeFi targets):
- `slither .` → `slither_results.json`
- `myth analyze` → `mythril_results.json`
- `semgrep --config auto` → `semgrep_results.json`
- Results go to analyst — analyst starts from tool results, not code reading

**Code Path Activation Check (DeFi MANDATORY)**:
```bash
cast call <vault_addr> "decimalsOffset()(uint8)" --rpc-url $RPC_URL
cast call <pool_addr> "fee()(uint256)" --rpc-url $RPC_URL
```
- All disabled(0) → "latent bug" → severity downgrade

#### Discovery vs Exploitation Cost Principle (Anthropic Firefox)

발견 비용은 익스플로잇의 1/10 수준 (Firefox: 발견 $수백 vs 익스플로잇 $4,000).
Phase 1은 **넓고 빠르게**, Phase 2는 **좁고 깊게** 운영:

- Phase 1: analyst confidence **5/10 이상**이면 모두 후보 유지 (7+ 우선 전달, 5-6도 리스트 유지)
- Phase 1.5: 후보가 5개 미만이면 추가 analyst 라운드 (dynamic budget +2)
- Phase 2: confidence 7+ 먼저 exploiter 투입, 그 다음 5-6 순서
- **Quantity in Discovery, Quality in Exploitation** — 발견은 FP 허용, 증명은 FP 불허

#### Graphify Pre-Analysis (10K+ LOC targets — OPTIONAL)

대형 코드베이스에서 Phase 1 전에 구조 이해 가속:
```bash
graphify <target_source_dir> --no-viz   # AST + 클러스터링 → graph.json + GRAPH_REPORT.md
graphify query "authentication flow"     # 구조 쿼리 (71.5x 토큰 효율)
```
- **God Nodes**: GRAPH_REPORT.md의 최다 연결 노드 → analyst manual review 우선 대상
- **Surprising Connections**: 예상 밖 관계 → 숨겨진 공격 경로 후보
- Orchestrator가 결과를 analyst/scout 핸드오프에 포함

### Phase 1: Discovery (EXPANDED in v12)

Parallel spawn — up to 4 agents:
- `scout` (model=sonnet) → `endpoint_map.md` (risk-weighted) + `workflow_map.md` (v12) + `program_context.md`
- `analyst` (model=sonnet) → reads program_rules_summary.md + tool results → `vulnerability_candidates.md` (dynamic review budget v12)
- `threat-modeler` (model=sonnet, **v12 NEW**) → `trust_boundary_map.md`, `role_matrix.md`, `state_machines.md`, `invariants.md`
- `patch-hunter` (model=sonnet, **v12 NEW**) → `patch_analysis.md` (variant candidates from security commits)

- **Inject program rules**: `python3 tools/bb_preflight.py inject-rules targets/<target>/` output in prompt top 3 lines
- **Inject exclusion filter**: `python3 tools/bb_preflight.py exclusion-filter targets/<target>/`

### Phase 1.5: Deep Exploration (v12 NEW)

After Phase 1 artifacts are produced:
- `workflow-auditor` (model=sonnet, **v12 NEW**) → reads state_machines.md + endpoint_map.md → `workflow_map.md` (refined with anomaly flags)
- `web-tester` (model=sonnet) → request-level testing + **workflow pack testing (v12)** using workflow_map.md and invariants.md
- `analyst` parallel hunting (optional, 10K+ LOC only) — now with dynamic budget and explore lane artifacts

### Phase 1→2 Gate: Coverage + Workflow Check (EXPANDED in v12)

```bash
# Coverage check (risk-weighted in v12: HIGH endpoints count 2x)
python3 tools/bb_preflight.py coverage-check targets/<target>/
# PASS (≥80% risk-weighted) → proceed | FAIL → additional rounds

# Workflow check (v12 NEW)
python3 tools/bb_preflight.py workflow-check targets/<target>/
# PASS (workflow_map.md exists with mapped workflows) → proceed | FAIL → scout/workflow-auditor supplement

# Fresh-surface check (v12 NEW — for mature targets with CONDITIONAL GO)
python3 tools/bb_preflight.py fresh-surface-check targets/<target>/
# FOUND → confirm new surface is in scope | NONE → maintain original NO-GO
```

---

## PROVE LANE

### Kill Gate 1: Finding Viability (MANDATORY before PoC)

`triager-sim` (model=**sonnet**, mode=finding-viability) per candidate:
- Input: 1-paragraph finding summary + prerequisites (no report, no PoC)
- **Pre-check (v12)**: scan `knowledge/triage_objections/` for same program feedback → calibrate
- Pre-check: `python3 tools/bb_preflight.py kill-gate-1 targets/<target>/ --finding "<finding>" --severity <critical|high|medium|low> --impact "<claimed impact>"`
  - **v12.3**: --severity MANDATORY, --impact strongly recommended
  - **v12.5**: info-disc finding + verbose-OOS 조항 + --impact에 민감 anchor 없음 → HARD_KILL (Port of Antwerp 2건 OOS 사고)
  - Exit 0=PASS, 1=WARN (advisory), **2=HARD_KILL (blocks gate, no exploiter spawn)**

**5-Question Destruction Test:**
1. FEATURE CHECK: documented/intended behavior? → YES = KILL
2. SCOPE CHECK: Out-of-Scope per program brief? → YES = KILL
3. DUPLICATE CHECK: same root cause as previous/known CVE? → YES = KILL
4. PREREQUISITE CHECK: attacker prerequisite ≥ impact? → YES = KILL
5. LIVE PROOF CHECK: provable with live evidence? → NO = KILL

**Additional Gate 1 Checks (v12.3 — incident lessons):**
6. IMPACT SCOPE CHECK: claimed impact가 프로그램 "Impacts in Scope" 목록에 정확히 매칭되는가? 매칭 불가 → 리프레이밍 시도 → 그래도 불가 → KILL (utix incident)
7. SEVERITY SCOPE CHECK: finding severity가 프로그램 severity scope 테이블에 포함되는가? 프로그램이 Critical만 표시인데 High 제출 → 조정 필요 (walrus incident)
8. BRANCH/TAG SCOPE CHECK: affected code가 scoped branch/tag에 존재하는가? `git checkout <tag> -- <file>`로 반드시 검증. main branch에만 있고 scoped tag에 없으면 → HARD KILL (walrus incident)
9. INFO-DISC / VERBOSE-OOS COLLISION CHECK (v12.5 — Port of Antwerp 2026-04-14 incident): finding이 info-disclosure class(stack trace, hostname, banner, verbose error, env dump 등)이고 프로그램 OOS에 "verbose messages without sensitive info" 계열 조항이 있으면 → --impact에 concrete sensitivity anchor(credentials/tokens/PII/auth-bypass/RCE chain/source-code leak) 필수. 없으면 HARD KILL. 있으면 WARN (grey-zone, triager가 sensitivity claim을 실제로 테스트). `bb_preflight.py kill-gate-1`이 자동 enforce.

Verdict: GO (5/5 pass) | CONDITIONAL GO (1 uncertain) | KILL (1+ definitive fail)
**IRON RULE: No exploiter spawn without Gate 1 pass.**

### Phase 2: PoC Validation (EXPANDED in v12; CVP 적용 v13.6)

**CVP note (2026-04-17~)**: Anthropic Cyber Validation Program 승인으로 exploiter/defi-auditor/patch-hunter 등 dual-use 에이전트의 offensive PoC / exploit primitive / jailbreak payload 생성 자기-검열 제거. 이전에 safety block으로 회피했던 **exhaustive exploit harness**(예: scope 전수 audit, variant mass test, multi-claim single-URL attack 증명), **zero-validation 증명을 위한 negative control**, **공격적 framing("systemic bypass", "full profile exfiltration")** 모두 허용. 단 **대규모 데이터 유출** 은 여전히 single-record 증명으로 제한. 플랫폼 OOS는 kill-gate가 계속 enforce. 상세: `memory/project_cvp_approval_2026_04_17.md`.

`exploiter` (model=opus) → PoC development + runtime verification:
- Use auth from program_rules_summary.md (inject-rules in prompt)
- Skip Duplicate Risk HIGH findings
- **Evidence Tier classification (v12)**: E1/E2/E3/E4
  - E1/E2 → proceed to Gate 2
  - E3/E4 → log to `explore_candidates.md` → Orchestrator may re-explore
- **Evidence tier check (v12)**:
  ```bash
  python3 tools/bb_preflight.py evidence-tier-check targets/<target>/submission/<name>/
  # E1/E2 (exit 0) → Gate 2 | E3/E4 (exit 1) → explore_candidates.md
  ```
- PoC Quality: Tier 1-2 only for submission
- **PoC Quality Iron Rules (v12.3 — Paradex #72418 incident):**
  - 공격 로직에 try/except 절대 0개. 인프라 코드(devnet 시작 등)만 허용.
  - 실패 시 fallback/hardcoded 값 대체 절대 금지 — 실패하면 PoC가 실패해야 함.
  - 모든 assertion은 on-chain state read (starknet_call/eth_call 등) 기반. Python 산술 결과 사용 금지.
  - "arithmetic simulation"이 아니라 "demonstrated exploit"이어야 함.
- Post-PoC Self-Validation 8 questions (v12: includes evidence tier Q8)
- Update endpoint_map.md (VULN/SAFE/TESTED)
- **Pre-Gate-2 Strengthening LOOP (v12.3 — LiteLLM cross-user exfil + onnx variant gap lessons + v13.9 ralph enforcement, MANDATORY)**

  Strengthening is **iterative, not a single pass.** 이 루프는 **`/ralph` skill로 구동 의무** — "정말 더 이상 발전할 것 없는가?" 까지 PRD-driven persistence로 수렴.

  **Ralph invocation**:
  ```
  /ralph --critic=critic "Phase 2 maximum strengthening for <target>/<finding>:
    run 5-item strengthening checklist, apply NEW discoveries to report.md + poc +
    autofill_payload + severity, re-run checklist until NO new improvements for 2
    consecutive iterations, or all 5 items NOT_APPLICABLE/INFEASIBLE. Reviewer verifies
    each iteration's strengthening_report.md vs actual artefact integration."
  ```

  Ralph PRD stories (auto-generated):
  - Story 1: Cross-user / cross-trust-domain PoC attempted + incorporated
  - Story 2: Two-step exploitation chain attempted + incorporated
  - Story 3: E2 → E1 evidence tier upgrade attempted + incorporated
  - Story 4: Variant hunt in sibling modules attempted + LIVE evidence + incorporated
  - Story 5: Static source quote eliminates try/except
  - Story 6 (meta): No new improvements discovered in 2 consecutive iterations (convergence)
  - Each story acceptance = reviewer agent confirms strengthening_report.md item is COMPLETED/NOT_APPLICABLE/INFEASIBLE with evidence AND report.md actually reflects the new information

  Manual fallback (ralph unavailable):
  ```
  REPEAT:
    1. Run the 5-item strengthening checklist (discover phase)
    2. For each ATTEMPTED item that produced NEW information (variants, chains, evidence):
       → INCORPORATE that information into report.md, poc, autofill_payload.json, severity
    3. Re-run the checklist against the UPDATED submission
    4. If any checklist item changes status (NEW variant found, severity upgraded, etc.)
       → LOOP again
  UNTIL:
    - All 5 items either NOT_APPLICABLE/INFEASIBLE, or
    - All ATTEMPTED items are fully reflected in report.md + poc + autofill_payload
    - No new improvements discovered in 2 consecutive iterations
  ```

  **"ATTEMPTED" does NOT mean "wrote it down in strengthening_report".**
  It means **"discovered AND incorporated into the actual submission artifacts."**
  Gate 2 HARD FAILs if strengthening_report lists findings (e.g. "4 sibling variants")
  but report.md Occurrences section only contains 1 of them.

  Before calling Gate 2, you MUST write `targets/<target>/submission/<name>/strengthening_report.md`
  with the following exact structure. Gate 2 will HARD FAIL if this file is missing,
  incomplete, has any `NOT_ATTEMPTED` entry, or has ATTEMPTED items whose evidence is
  NOT reflected in the final submission artifacts.

  ```markdown
  # Strengthening Report — <finding name>

  ## Timestamps
  - phase_2_started: <ISO timestamp when exploiter spawned>
  - gate_2_started: <ISO timestamp when Gate 2 invoked>
  - delta_minutes: <gate_2 - phase_2 in minutes>

  ## Strengthening Checklist (every item: ATTEMPTED / NOT_APPLICABLE / INFEASIBLE)

  ### 1. Cross-user / cross-trust-domain PoC
  - Status: <one of ATTEMPTED|NOT_APPLICABLE|INFEASIBLE>
  - Reason: <why NOT_APPLICABLE/INFEASIBLE, or what was built>
  - Evidence: <file path to cross-user PoC, or N/A>

  ### 2. Two-step exploitation chain
  - Status: <ATTEMPTED|NOT_APPLICABLE|INFEASIBLE>
  - Reason: <...>
  - Evidence: <chain PoC file, or N/A>

  ### 3. E2 → E1 evidence tier upgrade
  - Status: <ATTEMPTED|NOT_APPLICABLE|INFEASIBLE>
  - Reason: <e.g. "no cloud account available" = INFEASIBLE; "source-review only" = NOT_APPLICABLE>
  - Evidence: <live-data PoC output, or N/A>

  ### 4. Variant hunt in sibling modules
  - Status: <ATTEMPTED|NOT_APPLICABLE|INFEASIBLE>
  - Reason: <grep/AST search done? which files?>
  - Evidence: <variant findings file, or confirmation "no variants found">

  ### 5. Static source quote to eliminate try/except
  - Status: <ATTEMPTED|NOT_APPLICABLE|INFEASIBLE>
  - Reason: <does PoC use try/except? if yes, can inspect.getsource replace it?>
  - Evidence: <updated PoC file, or "no try/except to eliminate">

  ## Verdict
  - total_NOT_ATTEMPTED: <count>
  - gate_2_ready: <true if count == 0, else false>
  ```

  **Enforcement (v12.3)**:
  - `NOT_ATTEMPTED` count > 0 → Gate 2 HARD FAIL (must write explicit status for every item)
  - `delta_minutes` < 30 → WARN (rushed) unless every item is `NOT_APPLICABLE` with justification
  - Missing file → Gate 2 HARD FAIL with message: "Phase 2 did not produce strengthening_report.md"

- PASS → Gate 2 | FAIL → explore_candidates.md or delete

#### Best@N for Exploiter (BB-specific)
When exploiter fails on a CONDITIONAL GO finding (SCONE-bench Best@N 방법론):
1. First attempt: standard exploiter with analyst's approach
2. If fail → re-spawn exploiter with different approach hint (e.g., different auth bypass, injection vector, exploit primitive)
3. Max 2 re-attempts per finding (total 3 tries). 3rd fail → archive to explore_candidates.md as "explored, not proven"
4. Each re-attempt MUST use a **different strategy** — same payload retry is forbidden

### Kill Gate 2: Pre-Report Destruction (MANDATORY before report)

`triager-sim` (model=**opus**, mode=poc-destruction):
- Input: PoC script + evidence output only (no report)
- **Pre-check (v12)**: scan `knowledge/triage_objections/` for same program → calibrate
- Pre-check: `python3 tools/bb_preflight.py kill-gate-2 targets/<target>/submission/<name>/`
  - **v12.3**: Evidence tier E3/E4 = FAIL (was advisory). Mock PoC keywords = FAIL. Severity OOS = FAIL.
- **Duplicate graph check (v12)**:
  ```bash
  python3 tools/bb_preflight.py duplicate-graph-check targets/<target>/ --finding "<desc>"
  # PASS → proceed | WARN → review duplicate candidates before submitting
  ```

**3-Section Destruction Test:**

SECTION A — Evidence Quality (any NO without fix path = KILL):
1. LIVE vs MOCK: PoC runs against REAL target?
2. PROVEN vs INFERRED: every claimed impact directly demonstrated?
3. ENVIRONMENT MATCH: test env = claimed attack target?

SECTION B — Triager Objections:
4. Top 3 objections a triager would raise
5. Hard counter in evidence for each? YES=quote line, NO=gap(STRENGTHEN)

SECTION C — Severity Reality:
6. PREREQUISITE vs IMPACT: meaningful beyond prerequisite?
7. RAW CVSS: based purely on PoC evidence

Verdict: GO | STRENGTHEN (max 2x, 3rd = auto KILL) | KILL
**IRON RULE: No reporter spawn without Gate 2 GO.**

### Phase 3: Report Writing

`reporter` → draft + CVSS + **bugcrowd_form.md (MANDATORY)**:
- Observational language ("identified in reviewed code")
- Conditional CVSS table
- Executive Conclusion 3 sentences at top
- **bugcrowd_form.md**: Title, Target, VRT, Severity, CVSS, URL/Asset, Attachments, Checklist
- **VRT from `bugcrowd.com/vulnerability-rating-taxonomy`** (WebFetch) — match root cause, not impact
- **Conservative CVSS**: no unproven metrics (A:H without benchmark → A:L)
- **"What This Report Does NOT Claim" section (MANDATORY)**
- **File Path Verification**: all `file:line` refs verified via glob/find
- **Platform Style**: reporter reads `context/report-templates/platform-style/<platform>.md` BEFORE writing
- **Writing Style**: reporter follows `context/report-templates/writing-style.md` (First 3 Sentences Rule)
- **Repo Link Verification (v12.3 — LayerZero incident)**: 모든 GitHub 링크가 공식 프로그램 repo org를 가리키는지 확인. 개인 mirror/fork 사용 절대 금지. `gh api repos/<owner>/<repo>/contents/<path>`로 모든 참조 파일 존재 확인.

#### Phase 3.5: Report Quality Loop (NEW; v13.9 — `/ralph` 구동 MANDATORY)

After reporter saves draft, automated quality gate — **`/ralph --critic=critic "Phase 3.5 report quality"`** 로 구동:
1. `python3 tools/report_scorer.py <report> --poc-dir <evidence/> --json`
2. Composite >= 75 → proceed | < 75 → ralph이 reporter re-spawn + priority_fixes 적용 → re-score (ralph auto iterates)
3. `python3 tools/report_scrubber.py <report>` — AI signatures 제거 (Unicode watermarks, em-dash overuse)
4. Ralph PRD: each priority_fix = user story, acceptance = score 해당 dimension ≥ threshold. Max 3 iterations. 수렴 못 하면 → QUALITY_GATE_FAIL → Orchestrator decides: critic escalation or KILL
**IRON RULE: No Phase 4 without quality score >= 75. Manual single-pass 금지 — ralph loop 사용.**

### Phase 4: Review Cycle

1. `critic` → fact-check only (CWE, dates, function names, line numbers, file paths)
   - Documented Feature Check + Driver/Library Match Check
   - Phase 4 fundamental KILL = Gate 2 failure → Gate 2 prompt retrospective
2. `architect` → consistency (report-PoC-evidence alignment)
3. **`codex:adversarial-review` (v12.1 NEW)** → cross-model design challenge
   - `/codex:adversarial-review --wait` on submission/ directory
   - GPT-5.4 independently challenges: threat model realism, CVSS justification, evidence gaps
   - CRITICAL ISSUE → reporter fix before Phase 4.5 | PASS → proceed
   - **AI Slop cross-check**: different model's writing patterns neutralize Claude-specific slop
4. Optional: user external review

### Phase 4.5: Triager Simulation + AI Detection (EXPANDED v12.3)

`triager-sim` (mode=report-review):
- SUBMIT → Phase 5 | STRENGTHEN → reporter fix → re-run | KILL → delete finding
- AI Slop Score check (≤2 PASS, 3-5 STRENGTHEN, >5 KILL)
- **Codex Slop cross-check (v12.1)**: `/codex:review --wait` on final report → Claude-blind patterns detected
- Evidence-Target Alignment Check
- File Path Verification
- Gate Feedback Loop: KILL here = Gate 2 bug → update Gate 2 prompt

**3-Layer AI Detection (v12.3 NEW — MANDATORY before Phase 5):**
```bash
# Layer 1: Heuristic (automatic, instant)
python3 tools/ai_detect.py heuristic targets/<target>/submission/<name>/report.md
# PASS (exit 0) → Layer 2 | WARN (exit 1) → fix then retry | FAIL (exit 2) → full rewrite

# Layer 2: Claude self-review (in-session, free)
python3 tools/ai_detect.py self-review-prompt targets/<target>/submission/<name>/report.md
# → Orchestrator runs generated prompt, evaluates score
# PASS (0-2) → Layer 3 | WARN (3-5) → reporter rewrite | FAIL (6+) → full rewrite

# Layer 3: ZeroGPT web check (Playwright MCP, free)
python3 tools/ai_detect.py zerogpt-instructions targets/<target>/submission/<name>/report.md
# → Orchestrator follows Playwright steps, reads result
# <10% AI → PASS | 10-50% → reporter rewrite | >50% → full rewrite
```
**IRON RULE: All 3 layers must PASS. Rhino.fi "AI spam" = account death.**

### Phase 5: Finalization

`reporter` → unify language, reframing, ZIP packaging
- Cluster submission (same codebase = same day)
- **VRT + Bugcrowd Form final verification checklist**
- **Pre-submit Codex review (v12.1)**: `/codex:review --wait --base main` on submission/ → final cross-model sanity check
- **Evidence Manifest (NEW)**: `python3 tools/evidence_manifest.py <target_dir>` → `evidence_manifest.json`
  - Collects all artifacts with SHA256 hashes, checkpoint state, triager-sim results, report score
  - Validates critical artifacts present (exit 1 if missing)
  - Include in submission ZIP as audit trail

#### Cluster Submission Protocol (Anthropic Firefox)
같은 타겟에 2+ finding이 Gate 2 통과 시:
1. **같은 날 제출** — 단일 리뷰 세션 가능성 높음
2. **Root cause 번들링**: 동일 root cause → 하나의 리포트로 통합 (VRT 동일)
3. **Cross-reference**: 각 리포트에 관련 finding 참조 ("See also: Report #X")
4. **제출 순서**: 가장 높은 severity 먼저 (심사관 신뢰도 확보)
5. **ZIP 단일화**: 관련 finding들은 하나의 submission/ 디렉터리에 모아 ZIP

### Phase 5.5b: Platform Safety Check + Final Strengthening Verification (v12.3 NEW — MANDATORY)

Orchestrator runs directly before Phase 5.7:

**1. Platform Safety:**
```bash
python3 tools/platform_accuracy.py check <platform>
# SAFE (exit 0) → proceed
# WARNING (exit 1) → notify user, require explicit approval
# BLOCKED (exit 2) → STOP. Do not submit. Archive finding or try different platform.
```

**2. Strengthening Report Re-verification (v12.3 — redundant enforcement):**
```bash
python3 tools/bb_preflight.py strengthening-check targets/<target>/submission/<name>/
# PASS (exit 0) → proceed
# FAIL (exit 1) → STOP. strengthening_report.md missing/incomplete. Re-run Phase 2 strengthening.
# WARN (exit 2) → rushed transition detected, review before proceeding
```
**Why redundant**: Gate 2 already checks this, but report writing between Gate 2 and Phase 5 may modify files. Re-running the check here catches tampering or regressions. This is **belt-and-suspenders enforcement**.

After submission outcome is known:
```bash
python3 tools/platform_accuracy.py record <platform> <accepted|rejected|closed|oos|spam|duplicate> --finding "<desc>"
```
**IRON RULE: No submission without platform_accuracy.py check PASS AND strengthening-check PASS.**

### Phase 5.7: Live Scope Verification (v12.2 NEW — MANDATORY)

Orchestrator runs directly (not agent). **EVERY submission must pass this before Phase 5.8.**

1. **Re-fetch live program page via fetch-program** (v12.4 — replaces jina WebFetch):
   ```bash
   python3 tools/bb_preflight.py fetch-program targets/<target>/ <program_url> --no-cache --json > /tmp/live_scope.json
   # --no-cache bypasses the 24h fetch cache so this always hits the live page.
   # Writes fresh program_data.json, program_page_raw.md to targets/<target>/.
   ```
   Read back the verbatim In-Scope Assets, Out-of-Scope, and Asset Scope Constraints
   from the updated `program_rules_summary.md` + the new `program_page_raw.md`.
2. **Extract verbatim scope**: in-scope assets list (domains, apps, contracts, repos) + out-of-scope/exclusion list — EXACT wording from the live page (no summarization; fetch-program ships structured data)
3. **3-point verification**:
   - **Asset Match**: is the affected asset (exact domain/contract/repo) listed verbatim in scope, OR covered by a wildcard? If scope says "APIs located under *.example.com" but finding is on a **web page** (not API), flag as RISK.
   - **Scope Qualifier Check**: does the scope have qualifiers like "APIs", "smart contracts", "mobile apps only"? If finding's asset type doesn't match the qualifier → **HOLD** (report back to user with exact scope wording + concern)
   - **OOS Verbatim Match**: does finding match ANY out-of-scope item verbatim? → **KILL**
4. **Compare vs program_rules_summary.md**: if live scope differs from scout's summary → update program_rules_summary.md immediately
5. **Save result**: `live_scope_check.md` in submission directory

**Verdicts**:
- **PASS** (asset + type match, no OOS match) → Phase 5.8
- **HOLD** (scope qualifier ambiguity, e.g. "APIs" vs web page) → notify user with exact wording, user decides
- **KILL** (OOS verbatim match, asset not in scope at all) → archive

**IRON RULE**: No auto-fill without Phase 5.7 PASS or user override on HOLD.

### Phase 5.7.5: User-Mediated Demo (v13.7 NEW — IRON RULE)

**MANDATORY** — Phase 5.7 PASS 후 Phase 5.8 시작 전 무조건 게이트.

에이전트 critic/verifier/triager-sim "PASS"만으로 제출 금지. 실제 인간 triager의 first impression을 사용자가 본인 눈으로 검증.

**시연 패키지 준비 (Orchestrator)**:
```bash
# targets/<target>/submission/<finding>/USER_DEMO.md 생성
```
포함 필드:
1. **PoC 실행 명령** — curl/python/playwright step-by-step (복붙 가능)
2. **핵심 evidence 파일 + 라인 번호 + 기대 결과** — 직접 cat/grep으로 확인 가능하도록
3. **Report 핵심 단락** — Executive Conclusion + Impact Primary + Honest Severity (3 단락)
4. **Autofill payload 핵심 필드 요약** — title/severity/cvss/asset/scope_check
5. **"이 finding이 OOS / Informative / N/R 처리될 위험 시나리오 3개"** — 사용자가 risk를 미리 인지하도록

**시연 방식 (사용자 직접)**:
- Playwright MCP 브라우저로 PoC URL 직접 열어 응답 확인
- report.md 첫 1페이지 사용자 직접 읽기
- evidence 파일 sed/cat으로 핵심 라인 확인

**Verdict 형식**:
- 사용자가 "직접 시연 끝났다, 제출 진행" 명확히 회신해야 Phase 5.8 진입
- 단순 "OK" 또는 묵시적 동의 금지
- 사용자가 문제 발견 → STRENGTHEN 또는 KILL → 제출 보류

**Autonomous (terminator.sh background)**: Phase 5.7.5 도달 시 `SUBMISSION_HELD` 상태로 멈춤. Interactive 세션이 시연 + 승인할 때까지 Phase 5.8 진입 금지. `targets/<target>/submission/<finding>/SUBMISSION_HELD.md` 파일 생성하고 사용자 알림.

**Audit trail**: `targets/<target>/submission/<finding>/user_demo_log.md` — append-only timestamp + 사용자 verdict + 시연 중 발견된 issue 기록.

---

### Phase 5.7.6: Objective 20-Question Stress Test (v13.8 NEW — IRON RULE)

**MANDATORY** — Phase 5.7.5 (user demo) PASS 후 Phase 5.8 진입 전 추가 게이트.

Round 1/2/3 critic·verifier·triager-sim은 **자기 evidence 검증에 편향**될 수 있음. 객관적 third-party 시각 요구 — 실제 기업/플랫폼 triager 입장에서 20 hard questions로 재검증.

**실행 (Orchestrator 직접, critic + triager-sim 2-agent 병렬 spawn)**:

```
TaskCreate("Phase 5.7.6 20-Q stress test <target>/<finding>")
Agent(critic)  → "adversarial 20-question stress test, top 3 weak points + top 3 strengthen actions + bounty re-calibration"
Agent(triager-sim) → "real platform triager persona 20-question evaluation, probability distribution + median bounty"
```

**질문 20개 필수 카테고리** (각 finding에 맞게 조정):
1. Scope legitimacy — asset 진짜 in-scope?
2. CWE classification — 정확한가, 다른 CWE가 더 맞나?
3. OOS rule collision — 해당 플랫폼 OOS 항목과 충돌?
4. Spec interpretation — "intended behavior" 반박 위험?
5. Test client realism — production에도 적용?
6. Unique impact — claimed impact가 진짜 novel?
7. Resource-server auth model — access control 위반인가, 디자인?
8. Sandbox-Production parity — grep vs live verify gap?
9. CVSS calibration — 공격적 vs 보수적?
10. Regulatory invocation — GDPR/GDPR-like claim 정당성?
11. Secondary framing bloat — 과잉 framing?
12. Systemic vs spec compliance — 진짜 systemic bug?
13. Exploitation realism — weaponize 시나리오?
14. Marginal impact — 데이터 public source에서도 확보 가능?
15. Honest disclosure vs weakness — 약점 인정이 self-damage?
16. Test data vs real data — demo가 production 반영?
17. Form-vs-report classification mismatch?
18. Pre-existing knowledge — GitHub issues/PRs 검색 수행?
19. Duplicate race — 다른 hunter 제출 가능성?
20. Bounty calibration — 기대값 정당?

**Verdict 종합 (ralph loop으로 구동)**:
- Orchestrator는 이 게이트를 `/ralph` skill로 감싼다 — self-referential loop until **양 agent가 SUBMIT-AS-IS**까지. ralph invocation:
  ```
  /ralph --critic=critic "Phase 5.7.6 stress test for <target>/<finding>: run 20-Q critic + 20-Q triager-sim in parallel, apply STRENGTHEN actions, re-run until both agents return SUBMIT verdict or MAX 3 rounds reached"
  ```
- Round loop rule:
  1. 양 agent 모두 SUBMIT-AS-IS → exit loop, Phase 5.8 진입
  2. 한쪽 이상 STRENGTHEN → ralph auto-applies STRENGTHEN list + re-spawns agents (iteration++)
  3. 양쪽 KILL → exit loop with KILL, 제출 취소
  4. Max 3 iterations — 3차까지 SUBMIT 수렴 못 하면 → user decision required (STRENGTHEN forever 방지)
- Ralph PRD는 자동 생성: 각 weak point를 user story로 변환, 각 story는 "양 agent next round에서 이 weak point 언급 안 함" = acceptance criterion
- Audit trail: 각 iteration별 `stress_test_20q_round{N}.md` — ralph이 자동 관리

**Accept probability / weighted bounty EV** 양 agent가 제공. 이 수치가 플랫폼/프로그램 실 데이터 매칭 후 업데이트됨 (feedback loop).

**IRON RULE**: Round 2/3 PASS 했어도 Phase 5.7.6 stress test 없이 Phase 5.8 진입 금지. 실제 사례 (Bugcrowd Zendesk N/A 2026-04-17 AI-RAG) 에서 self-evidence 기반 verification 만 했던 결과 N/A close. 20-Q 객관적 검증이 이 type 사고 예방.

**Audit trail**: `targets/<target>/submission/<finding>/stress_test_20q.md` — 각 agent verdict + TOP weak points + expected bounty EV 기록.

---

### Phase 5.8: MCP Auto-Fill (v12 NEW)

**Platform-specific submission entry points (MANDATORY — do not guess URLs):**
- **huntr**: `https://huntr.com/bounties/disclose` (사용자 고정 규칙 2026-04-10). 여기서 report type 선택 (Open Source Repository $1,500 또는 Model File Format $3,000) → 각 form으로 이동. `https://huntr.com/repos/<owner>/<name>/bounties` 같은 직접 URL은 404.
- **Bugcrowd**: 프로그램별 엔게이지먼트 페이지의 Submit Report 버튼
- **YesWeHack**: 프로그램 페이지의 Report 탭
- **Intigriti**: 프로그램 페이지의 Submit 버튼

Orchestrator uses MCP Playwright tools directly (NOT a standalone script):
1. Read `autofill_payload.json` from submission directory
1b. **Credential file reference**: 로그인 필요 시 아래 경로를 순서대로 참조:
   - **플랫폼 크레덴셜**: `${HOME}/.config/bounty-credentials.json` (chmod 600, 10+ 플랫폼 저장)
   - **Playwright 프로필**: `${PLAYWRIGHT_BOUNTY_PROFILE:-$HOME/.config/playwright-bounty-profile}` (세션 쿠키 유지)
   - **타겟별 테스트 계정**: `targets/<target>/test_accounts.json` (타겟 서비스 가입 계정)
   - **로그인 도우미**: `python3 tools/platform_autologin.py check|get-creds|login-steps <platform>`
   - `autofill_payload.json`에 `credential_file` 필드로 해당 경로 포함하여 interactive session이 즉시 참조 가능하게.
2. `browser_navigate(url=form_url)` → open platform submission form
3. `browser_snapshot()` → check login state → if login needed, ask user to log in manually
4. `browser_snapshot()` → get form element refs from accessibility tree
5. `browser_fill_form(fields=[...])` → fill each field using snapshot refs
6. For complex widgets (VRT search, file upload): `browser_type` + `browser_click` + `browser_file_upload`
7. `browser_take_screenshot(fullPage=true)` → save `pre_submit_screenshot.png`
8. Notify user: "Form filled. Review in browser and click Submit."

**IRON RULES**:
- **NEVER click Submit button** — human review + human click required
- **Phase 6 BLOCKED** until user confirms submission is complete

### Phase 5 Pre-Send Verification (v12.3 — Paradex incident, IRON RULE)

제출/답변/댓글에 포함하는 **모든 것**을 직접 실행·접속·검증한 후에만 전송. 예외 없음:
1. 모든 curl/python/bash 명령어를 로컬 실행 → 출력이 보고서와 정확히 일치하는지 확인
2. 파이프(`|`) 연결 명령어는 전체 파이프라인 실행 → 최종 출력 검증
3. 모든 URL을 HEAD/GET으로 접속 → 200 OK 확인. 404/403이면 수정
4. selector/hash/address 등 hex 값은 실행 결과에서 복사. 수동 입력 금지
5. "triager가 명령어를 순서대로 실행한다" 가정하고 전체 흐름 시뮬레이션. 하나라도 실패 → 전송 차단
### Phase 5.9: Submission Tracker Update (v13.6 NEW — MANDATORY)

제출 완료 직후 (Phase 5.8 auto-fill → 사용자 Submit 클릭 확인 후):
```bash
/bounty-status-sync        # Phase 4.5(JSON) + Phase 4.6(SUBMISSIONS.md) 자동
```
또는 수동: `docs/submissions.json`에 엔트리 push(`submitted: "YYYY-MM-DD"`) + `coordination/SUBMISSIONS.md` Active 테이블 상단에 행 추가.

**IRON RULE**: 제출 완료 후 Phase 6 이동 전 반드시 tracker 양쪽 갱신. JSON / Markdown 중 하나만 업데이트된 상태로 커밋/세션 종료 금지.

### Phase 6: Cleanup

TeamDelete — **only after user confirms submission done AND Phase 5.9 tracker updated**

**Test Account Rules (MANDATORY):**
- **IRON RULE: 자동 회원가입 ABSOLUTELY BANNED.** 에이전트가 signup/register 폼을 자동 제출하는 것 절대 금지. 계정 필요 시 사용자에게 요청만 가능. Interactive 세션에서 사용자가 직접 가입.
- **Trigger for cleanup**: ANY pipeline exit — Phase 6 normal completion, Gate KILL, time-box ABANDON, session crash, or manual stop
- **IRON RULE**: No session exits without checking `targets/<target>/test_accounts.json`. Test accounts MUST be deleted regardless of finding outcome.
- **BEFORE creating any account**: 회원탈퇴 경로(Settings → Delete Account URL) 먼저 확인. 탈퇴 불가능한 서비스는 계정 생성 자제.
- **password 필드 필수**: `test_accounts.json`에 반드시 password 기록. 회원탈퇴 시 로그인 필요. 누락 = 파이프라인 위반.
- **최소 계정 원칙**: 꼭 필요한 최소 계정만 생성. IDOR 테스트도 2개면 충분.
- **생성 직후 탈퇴 테스트**: 계정 만든 후 바로 Delete Account 경로 접근 가능한지 확인. 불가능하면 즉시 보고.
- **Gmail alias format**: `<base-gmail>+<target>_test_<letter>@gmail.com` (base address는 레포 외부 `${HOME}/.config/bounty-credentials.json`의 `gmail_base` 필드에서 로드 — 레포에 하드코딩 금지)
- **OAuth/소셜 로그인 금지** — 비밀번호 기반 가입만 사용.
- **세션 종료 전 반드시 탈퇴 완료**. "나중에 정리" 금지.

**Autonomous Session Rules (terminator.sh background mode):**
- Phase 5.8: No browser/Playwright access. Write `autofill_payload.json` + `submission_review.json` only. Interactive session handles auto-fill.
- `autofill_payload.json`에 `credential_file` 필드 포함: `targets/<target>/test_accounts.json` 경로 또는 플랫폼 로그인 정보 참조 경로. Interactive session이 auto-fill 시 즉시 로그인할 수 있도록.
- If submission artifacts exist at exit, log: "SUBMISSION READY: <target>/<finding> — awaiting Phase 5.8 auto-fill"

---

## Explore Lane Recycling (v12 NEW)

When the prove lane kills a finding at Gate 1, Gate 2, or Phase 4.5:
1. Archive kill reason in `knowledge/triage_objections/` (for triager-sim replay mode)
1b. Record decision in `knowledge/decisions/YYYYMMDD-<target>-gate<N>.md` using AgDR template:
    - Context: finding summary + gate number
    - Decision: GO/KILL + specific reason
    - Consequences: next action (recycle/archive/abandon)
2. Run `triager-sim` (mode=replay) to calibrate future predictions
3. If `explore_candidates.md` has remaining E3/E4 findings:
   - Orchestrator MAY re-enter explore lane for those candidates
   - Re-spawn exploiter with new context/approach (max 2 re-attempts per candidate)
4. After all recycling: finalize explore_candidates.md status (proven / archived / killed)

---

## v12 Agent Model Assignment

| Agent | Model | Phase | Role |
|-------|-------|-------|------|
| target-evaluator | sonnet | 0 | GO/NO-GO + Novelty Score |
| scout | sonnet | 1 | Surface mapping + workflow discovery |
| analyst | sonnet | 1 | Vulnerability triage (dynamic budget) |
| threat-modeler | sonnet | 1 | Trust boundary + invariant extraction |
| patch-hunter | sonnet | 1 | Variant hunting from security commits |
| workflow-auditor | sonnet | 1.5 | Workflow state transition mapping |
| web-tester | sonnet | 1.5 | Request + workflow pack testing |
| triager-sim | sonnet/opus | Gates | Gate 1=sonnet, Gate 2+=opus |
| exploiter | opus | 2 | PoC with evidence tiers |
| reporter | sonnet | 3,5 | Report + bugcrowd_form.md |
| critic | opus | 4 | Fact-check |

---

## BB Core Rules (carried from v11 + v12 additions)

- No PoC = No submit (IRON RULE)
- Phase 0 mandatory — NO-GO = stop
- No submit without triager-sim SUBMIT
- Tier 1-2 only — Tier 3-4 = auto delete (submission). E3/E4 = explore_candidates.md (v12)
- Duplicate Pre-Screen mandatory
- PoC before report (never report-only)
- Same root cause = bundle
- Check CVSS version (3.1 vs 4.0)
- No V8 prototype pollution solo claims
- No LLM echo claims
- 3-layer remediation preferred
- Anti-AI slop: target-specific details, no template language
- VRT = Priority determinant (not CVSS alone)
- bugcrowd_form.md mandatory
- Bounty table verification mandatory
- Kill Gate without pass = no report (IRON RULE)
- Gate 2 STRENGTHEN max 2x
- Phase 4.5 KILL = Gate bug → feedback loop
- **v12**: Evidence tier classification mandatory (E1-E4)
- **v12**: Triage feedback pre-check before Gates (knowledge/triage_objections/)
- **v12**: workflow_map.md required for Web/API targets
- **v12**: Risk-weighted coverage (HIGH endpoints count 2x)
- **v12**: Fresh-Surface Exception for mature targets with new modules
- **v12.2**: Phase 5.7 Live Scope Verification MANDATORY — 제출 전 반드시 프로그램 페이지 직접 확인. program_rules_summary.md는 초기 스냅샷이므로 live re-fetch 필수.
- **v12.3**: Gate hardening (Immunefi postmortem) — kill-gate-1 --severity mandatory + HARD_KILL, kill-gate-2 evidence tier enforced (E3/E4=FAIL), mock PoC=FAIL
- **v12.4**: Phase 0.1 Program Fetch MANDATORY — `tools/bb_preflight.py fetch-program` replaces WebFetch+jina for verbatim scope/OOS/severity intake. Platform-specific handlers (HackerOne GraphQL, Bugcrowd target_groups.json, Immunefi __NEXT_DATA__, Intigriti/YWH/HackenProof APIs, huntr/github_md scrapers) extract structured data; jina is last-resort fallback capped at confidence 0.4 (HOLD only).
- **v12.5**: Kill-gate-1 info-disc / verbose-OOS collision check — finding이 info-disclosure class(stack trace, hostname, banner, env dump 등)이고 프로그램 OOS에 "verbose messages without sensitive info" 계열이 있으면 --impact에 concrete sensitivity anchor(credentials/tokens/PII/auth-bypass/RCE chain/source-code leak) 필수. 없으면 HARD_KILL. Port of Antwerp 2026-04-14 2건 OOS close 사고 방지.

## Time-Box (unchanged from v11)

```
Phase 0: 45min | Phase 0.5: 30min | Phase 1: 2hr | Phase 1.5: 1hr (v12 NEW)
Phase 2: 3hr | Phase 3-5: 2hr
Total: 9hr (general, was 8hr) / 13hr (DeFi, was 12hr)
No HIGH+ signal at 2hr → ABANDON (after checklist pass)
```

### Token Efficiency Tracking Protocol (Anthropic SCONE-bench)

SCONE-bench: 세대당 중앙값 22% 토큰 감소. 파이프라인 효율 모니터링:

**기록 시점**: 각 target 완료 시 Orchestrator가 기록
**기록 방법**: `python3 tools/infra_client.py db cost-summary --target <target> --json`
**비교 기준**:
- 동일 유형 타겟 간 tokens/finding 비율
- 모델 업그레이드 전후 동일 태스크 토큰 비교
- Phase별 토큰 비율 (Discovery:Exploitation 이상적 1:3)
**ROI 계산**: (예상 보상금 / 추정 API 비용) > 5x → 효율적

## Hard NO-GO Rules (unchanged from v11)

```
3+ audits = AUTO NO-GO (unless Fresh-Surface Exception v12)
2+ reputable audits (Nethermind, OZ, ToB, Zellic, Spearbit) = AUTO NO-GO (unless Fresh-Surface Exception v12)
100+ resolved reports = AUTO NO-GO
Operating 3+ years = AUTO NO-GO (unless Fresh-Surface Exception v12)
Last commit >6mo + 2+ audits = AUTO NO-GO
Source private/inaccessible = AUTO NO-GO
Fork → original audit + fix commits all applied = AUTO NO-GO
DeFi → cast call mandatory in Phase 0
```

## Anti-AI Detection (unchanged from v11)

- Specific block number or tx hash in report
- Vary report structure each time
- Observational language ("reviewed implementation")
- Zero template phrases
- AI Slop Score ≤2/10
- At least 1 unique analysis element

## Platform Priority (unchanged from v11)

Bugcrowd (PRIMARY, 40% success) > HackenProof (Web3) > PSIRT Direct > Immunefi (<6mo+≤1audit) > Intigriti/YesWeHack > H1 (paused)

- **Immunefi queue rule**: Immunefi에 active report 1건 이상 pending이면 Immunefi 추가 제출 중단, 다른 플랫폼 우선. Immunefi는 연속 제출 시 accuracy 기반 autoban 리스크.
- **Intigriti concurrent limit**: 최대 3건 동시 triage. 3/3이면 triage 완료까지 Intigriti 제출 중단, 다른 플랫폼 우선.
