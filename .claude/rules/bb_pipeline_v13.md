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
   - **OOS Exclusion Pre-Check (MANDATORY)**: program "Out of Scope" 전수 확인 + `immunefi.com/common-vulnerabilities-to-exclude/` 교차 확인 ("Incorrect data supplied by third party oracles" = oracle staleness = OOS 주의) + Known Issues / audit tracking docs 확인. 후보 vuln type ∈ OOS → 즉시 NO-GO.
   - **Live Bounty Status Check + Recent Submission Status Scan (v12.3 — LiteLLM $0 + duplicate incidents, MANDATORY for huntr)**: `$0+CVE` tag = NO-GO (unless CVE-only opt-in). 프로그램 max 신뢰 금지, per-target active bounty 확인. 최근 10건 중 same vuln class duplicate/informative → Gate 1 Q3 escalate. 모두 `target_assessment.md`에 verbatim 기록 (Bounty Range (live) + Recent Submission History 섹션). 상세: `.claude/rules/bb/phase0_live_checks.md`.

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

**Supported handlers (v12.4+)**: HackerOne (GraphQL+policy) / Bugcrowd (target_groups+react-props) / Immunefi (`__NEXT_DATA__` 0.95 authoritative) / Intigriti (public API+Nuxt) / YesWeHack (api+HTML) / HackenProof (SSR) / huntr (`__NEXT_DATA__`+case variants) / Code4rena-Sherlock-audit (github raw README) / Generic jina (fallback cap 0.4, HOLD only). Confidence/priority 세부: `.claude/rules/bb/program_fetch_ops.md`.

**Rationale**: WebFetch+jina is lossy (collapsed `<details>`, react-props drops, `__NEXT_DATA__` summarization). Per-platform handlers extract verbatim so Phase 0.2 moves from "hand-fill prose" to "verify + fill live-only sections".

**v14 — raw-bundle layer (2026-04-18 NEW, MANDATORY)**: `fetch-program` auto-runs `raw_bundle.capture()` → `targets/<target>/program_raw/{landing,linked_NN__*,bundle}.{html,json,md}` + platform-hinted API URL injection (Intigriti/YWH/BC/H1/Immunefi/huntr). Authoritative verbatim substring source for Phase 0.2 `verbatim-check` — **not** a structured parser. **Why**: Port of Antwerp OOS x2 (2026-04-14 "verbose messages" rule) + Zendesk AI-RAG N/A (2026-04-17 AI impact clause) — handler 파싱이 non-bullet/scattered 조항 놓침. `grep -i verbose bundle.md` 같은 raw substring 검사 = zero summarisation leakage.

**Private / invitation-only SPA** (Intigriti / H1 private / BC private): `./scripts/playwright_login.sh <login-url>` 1회 로그인 → `$PLAYWRIGHT_BOUNTY_PROFILE` 세션 저장 → 이후 headless 자동. **Retrospective** (pre-v14): `./scripts/refetch_active_targets.sh [--dry-run] [--only <tag>]`. Opt-out (금기): `--no-raw-bundle`.

상세 운영 가이드 (program_raw/ 디렉토리 구조, split 로직, bundle_meta.json 인증 플래그, auth-skip 동작): `.claude/rules/bb/program_fetch_ops.md`.

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
#   0 = PASS   — 모든 bullet이 program_raw/bundle.md substring-matched (prefix/backtick/URL/0x/monetary token fallback 포함)
#   1 = FAIL   — HARD: bullet 중 하나라도 미매치 → fetch-program 재실행 또는 live page verbatim paste 필요
#   3 = ERROR  — bundle.md 또는 rules_summary 없음 → fetch-program 먼저 실행
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

대형 코드베이스에서 Phase 1 전에 `graphify` 로 AST+클러스터링 → God Nodes (최다 연결 노드) + Surprising Connections를 analyst/scout 핸드오프에 포함. 명령어 + 운영 세부: `.claude/rules/bb/graphify_preanalysis.md`.

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

**CVP note (2026-04-17~)**: Anthropic CVP 승인으로 dual-use 에이전트 자기-검열 제거 — exhaustive exploit harness / negative control / aggressive framing 허용. 대규모 데이터 유출만 여전히 single-record 증명 제한. 플랫폼 OOS는 kill-gate가 계속 enforce. 상세: `memory/project_cvp_approval_2026_04_17.md` + CLAUDE.md Rule 4.

`exploiter` (model=claude-opus-4-6[1m]) → PoC development + runtime verification:
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
- **PoC Quality Iron Rules (v12.3 — Paradex #72418)**: 공격 로직 try/except 0 (infra 코드만 허용) / 실패 시 fallback·hardcoded 대체 금지 (실패하면 PoC가 실패) / 모든 assertion은 on-chain state read (starknet_call/eth_call) 기반 (Python 산술 결과 금지) / "arithmetic simulation" 아닌 "demonstrated exploit".
- Post-PoC Self-Validation 8 questions (v12: includes evidence tier Q8)
- Update endpoint_map.md (VULN/SAFE/TESTED)
- **Pre-Gate-2 Strengthening LOOP (v12.3 — LiteLLM cross-user exfil + onnx variant gap lessons + v13.9 ralph enforcement, MANDATORY)**:
  Iterative via **`/ralph --critic=critic` 구동 의무** — "정말 더 이상 발전할 것 없는가?" 까지 PRD-driven persistence로 수렴 (2 consecutive iterations w/o new improvements, OR all 5 items NOT_APPLICABLE/INFEASIBLE).
  - **5-item checklist**: (1) Cross-user / cross-trust-domain PoC, (2) Two-step exploitation chain, (3) E2 → E1 evidence tier upgrade, (4) Variant hunt in sibling modules (LIVE evidence), (5) Static source quote eliminates try/except
  - **"ATTEMPTED" semantics** (CRITICAL): NEW information DISCOVERED **AND** INCORPORATED into report.md + poc + autofill_payload. Wrote-it-down-only = Gate 2 HARD FAIL (e.g. strengthening_report lists "4 sibling variants" but report.md Occurrences 섹션에 1개만 있으면 FAIL).
  - Before Gate 2, MUST write `targets/<target>/submission/<name>/strengthening_report.md` per canonical template. **Enforcement**: `NOT_ATTEMPTED` count > 0 → HARD FAIL. `delta_minutes` < 30 → WARN (rushed) unless all NOT_APPLICABLE. Missing file → HARD FAIL.
  - **Ralph invocation, PRD stories, manual fallback loop, full template with all 5 sections, enforcement details**: `.claude/rules/bb/strengthening_template.md`

- PASS → Gate 2 | FAIL → explore_candidates.md or delete

#### Best@N for Exploiter (BB-specific)
CONDITIONAL GO finding에서 exploiter 실패 시 SCONE-bench Best@N — Max 3 tries (첫 시도 + 2 re-spawn), 각 re-attempt는 **다른 strategy** (같은 payload retry 금지), 3번째 fail → `explore_candidates.md` 아카이브. 상세: `.claude/rules/bb/best_n_strategy.md`.

### Kill Gate 2: Pre-Report Destruction (MANDATORY before report)

`triager-sim` (model=**claude-opus-4-6[1m]**, mode=poc-destruction):
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

#### Phase 3.6: areuai Evade (NEW; Orchestrator-owned)

After Phase 3.5 passes, run rule-based areuai evasion before critic/architect
review so reviewers inspect the final rewritten text:

```bash
/home/hw/.areuai/bin/areuai.py evade targets/<target>/submission/<name>/report.md \
  --mode report --target zerogpt --quality-floor 75 --rounds 2
```

PASS(exit 0) → Phase 4. WARN(exit 1) → inspect diff/manual judgment.
FAIL(exit 2) → reporter rewrite. areuai is rule-based only and preserves
evidence, URLs, code blocks, commands, numbers, hashes, file paths, and CVSS.

### Phase 4: Review Cycle

1. `critic` → fact-check only (CWE, dates, function names, line numbers, file paths) + Documented Feature Check + Driver/Library Match Check. Phase 4 fundamental KILL = Gate 2 failure → Gate 2 prompt retrospective.
2. `architect` → consistency (report-PoC-evidence alignment)
3. **`codex:adversarial-review` (v12.1 NEW)** → `/codex:adversarial-review --wait` on submission/. GPT-5.4 challenges threat model realism / CVSS / evidence gaps. CRITICAL ISSUE → reporter fix. AI Slop cross-check (Claude-specific patterns neutralized).
4. Optional: user external review

### Phase 4.5: Triager Simulation + AI Detection (EXPANDED v12.3)

`triager-sim` (mode=report-review):
- SUBMIT → Phase 5 | STRENGTHEN → reporter fix → re-run | KILL → delete finding
- AI Slop Score check (≤2 PASS, 3-5 STRENGTHEN, >5 KILL)
- **Codex Slop cross-check (v12.1)**: `/codex:review --wait` on final report → Claude-blind patterns detected
- Evidence-Target Alignment Check
- File Path Verification
- Gate Feedback Loop: KILL here = Gate 2 bug → update Gate 2 prompt

**3-Layer AI Detection (v12.3 NEW — MANDATORY before Phase 5)**: `tools/ai_detect.py` 3-layer chain — (1) `heuristic` instant via areuai bridge, (2) `self-review-prompt` Claude in-session, (3) `zerogpt-instructions` via Playwright MCP. 전 단계 PASS 필수. Exit codes / score thresholds / 전체 bash 명령: `.claude/rules/bb/ai_detection_3layer.md`.

**IRON RULE: All 3 layers must PASS. Rhino.fi "AI spam" = account death.**

### Phase 5: Finalization

`reporter` → unify language, reframing, ZIP packaging
- Cluster submission (same codebase = same day)
- **VRT + Bugcrowd Form final verification checklist**
- **Pre-submit Codex review (v12.1)**: `/codex:review --wait --base main` on submission/ → final cross-model sanity check
- **Evidence Manifest**: `python3 tools/evidence_manifest.py <target_dir>` → `evidence_manifest.json` (SHA256 + checkpoint + triager-sim + score, exit 1 if critical missing, include in ZIP)

#### Cluster Submission Protocol (Anthropic Firefox)
같은 타겟 2+ finding Gate 2 통과 시: 같은 날 제출 → root cause 번들링 (동일 VRT 통합) → cross-reference → severity 높은 순 → ZIP 단일화. 상세: `.claude/rules/bb/cluster_submission.md`.

### Phase 5.5b: Platform Safety Check + Final Strengthening Verification (v12.3 NEW — MANDATORY)

Orchestrator runs directly before Phase 5.7:

**1. Platform Safety**: `python3 tools/platform_accuracy.py check <platform>` — SAFE(0)→proceed / WARNING(1)→user approval / BLOCKED(2)→STOP (archive or different platform).

**2. Strengthening Report Re-verification (v12.3 — redundant enforcement)**: `python3 tools/bb_preflight.py strengthening-check targets/<target>/submission/<name>/` — PASS(0)→proceed / FAIL(1)→STOP + re-run Phase 2 strengthening / WARN(2)→rushed review. Gate 2 중복 체크지만 report writing 사이 파일 변조/regression 잡기 위한 belt-and-suspenders.

After submission: `python3 tools/platform_accuracy.py record <platform> <accepted|rejected|closed|oos|spam|duplicate> --finding "<desc>"`.

**IRON RULE**: No submission without platform_accuracy.py check PASS AND strengthening-check PASS.

### Phase 5.7: Live Scope Verification (v12.2 NEW — MANDATORY)

Orchestrator runs directly (not agent). **EVERY submission must pass this before Phase 5.8.**

**절차 요약**: (1) `bb_preflight.py fetch-program --no-cache` live re-fetch → 최신 `program_data.json` + `program_page_raw.md`, (2) verbatim scope 추출 (in-scope + OOS, no summarization), (3) **3-point verification** — Asset Match (wildcard 포함) / Scope Qualifier Check ("APIs" vs web page 등) / OOS Verbatim Match, (4) live scope ≠ scout summary → `program_rules_summary.md` 즉시 갱신, (5) `live_scope_check.md` 저장.

**Verdicts**: **PASS** (asset + type match, no OOS) → Phase 5.8 | **HOLD** (qualifier ambiguity) → notify user with exact wording → user decides | **KILL** (OOS verbatim match or asset 전혀 in-scope 아님) → archive.

**IRON RULE**: No auto-fill without Phase 5.7 PASS or user override on HOLD. 상세 절차 + 3-point 구체 예시: `.claude/rules/bb/live_scope_check.md`.

### Phase 5.7.5: User-Mediated Demo (v13.7 NEW — IRON RULE)

**MANDATORY** — Phase 5.7 PASS 후 Phase 5.8 진입 전 무조건 게이트. 에이전트 critic/verifier/triager-sim "PASS"만으로 제출 금지 — 실제 인간 triager first impression을 사용자가 본인 눈으로 검증.

**시연 패키지 (Orchestrator)**: `targets/<target>/submission/<finding>/USER_DEMO.md` 생성 — (1) PoC 실행 명령 복붙 가능, (2) evidence 파일 + 라인 + 기대 결과, (3) Report 핵심 3단락 (Executive Conclusion + Impact Primary + Honest Severity), (4) Autofill payload 요약 (title/severity/cvss/asset/scope_check), (5) OOS/Informative/N/R 위험 시나리오 3개.

**Verdict**: 사용자가 "직접 시연 끝났다, 제출 진행" 명확 회신해야 Phase 5.8. 단순 "OK" 또는 묵시적 동의 금지. 문제 발견 → STRENGTHEN 또는 KILL → 제출 보류.

**Autonomous (terminator.sh)**: `SUBMISSION_HELD.md` 생성 후 interactive 세션 대기. **Audit trail**: `user_demo_log.md` append-only. 전체 시연 방식 + Autonomous 세부: `.claude/rules/bb/user_demo.md`.

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

**질문 20개 필수 카테고리** (scope legitimacy / CWE classification / OOS rule collision / spec interpretation / test client realism / unique impact / resource-server auth / sandbox-production parity / CVSS calibration / regulatory invocation / secondary framing bloat / systemic vs spec / exploitation realism / marginal impact / honest disclosure / test vs real data / form-vs-report mismatch / pre-existing knowledge / duplicate race / bounty calibration). 전체 질문 리스트 + 각 finding별 조정 방법: `.claude/rules/bb/stress_test_20q.md`.

**Verdict 종합 (ralph loop으로 구동)**: Orchestrator는 이 게이트를 `/ralph --critic=critic` 으로 감싼다 — 양 agent SUBMIT-AS-IS까지 재spawn.
- Round loop: (1) 양 agent SUBMIT-AS-IS → Phase 5.8 진입, (2) 한쪽 이상 STRENGTHEN → ralph auto-applies + re-spawn, (3) 양쪽 KILL → 제출 취소, (4) Max 3 iterations — 3차에도 수렴 못 하면 user decision (STRENGTHEN forever 방지)
- Ralph PRD 자동 생성: 각 weak point → user story, acceptance = "양 agent next round에서 이 weak point 언급 안 함"
- Accept probability / weighted bounty EV 양 agent가 제공 (실 데이터 매칭 후 feedback loop 업데이트)

**IRON RULE**: Round 2/3 PASS 했어도 Phase 5.7.6 stress test 없이 Phase 5.8 진입 금지. Bugcrowd Zendesk N/A 2026-04-17 AI-RAG 사례 (self-evidence 기반 verification 결과 N/A close) 예방.

**Audit trail**: `targets/<target>/submission/<finding>/stress_test_20q.md` + iteration별 `stress_test_20q_round{N}.md` (ralph이 자동 관리).

---

### Phase 5.8: MCP Auto-Fill (v12 NEW)

**Platform-specific submission entry points (MANDATORY — do not guess URLs):**
- **huntr**: `https://huntr.com/bounties/disclose` (사용자 고정 규칙 2026-04-10). 여기서 report type 선택 (Open Source Repository $1,500 또는 Model File Format $3,000) → 각 form으로 이동. `https://huntr.com/repos/<owner>/<name>/bounties` 같은 직접 URL은 404.
- **Bugcrowd**: 프로그램별 엔게이지먼트 페이지의 Submit Report 버튼
- **YesWeHack**: 프로그램 페이지의 Report 탭
- **Intigriti**: 프로그램 페이지의 Submit 버튼

Orchestrator uses MCP Playwright tools directly (NOT a standalone script) — reads `autofill_payload.json` + `credential_file` (→ `${HOME}/.config/bounty-credentials.json` / `$PLAYWRIGHT_BOUNTY_PROFILE` / `targets/<target>/test_accounts.json`), then executes 8-step Playwright sequence (`browser_navigate` → `browser_snapshot` login check → form ref extraction → `browser_fill_form` → complex widgets → screenshot → user notify). 전체 step 리스트 + credential 경로 상세: `.claude/rules/bb/phase58_autofill_ops.md`.

**IRON RULES**:
- **NEVER click Submit button** — human review + human click required
- **Phase 6 BLOCKED** until user confirms submission is complete

### Phase 5 Pre-Send Verification (v12.3 — Paradex incident, IRON RULE)

제출/답변/댓글 포함 **모든 것**을 직접 실행·접속·검증한 후에만 전송. 예외 없음 — (1) 모든 curl/python/bash 로컬 실행 + 출력 일치 확인, (2) pipe(`|`) 연결은 전체 파이프라인 실행 + 최종 출력 검증, (3) 모든 URL HEAD/GET 200 OK 확인 (404/403이면 수정), (4) selector/hash/address hex 값은 실행 결과에서 복사 (수동 입력 금지), (5) "triager가 명령어 순서대로 실행한다" 가정 전체 흐름 시뮬레이션 — 하나라도 실패 → 전송 차단.

### Phase 5.9: Submission Tracker Update (v13.6 NEW — MANDATORY)

제출 완료 직후 (Phase 5.8 auto-fill → 사용자 Submit 클릭 후): `/bounty-status-sync` 실행 — Phase 4.5(JSON) + Phase 4.6(SUBMISSIONS.md) 자동 갱신. 수동 시: `docs/submissions.json` 엔트리 push(`submitted: "YYYY-MM-DD"`) + `coordination/SUBMISSIONS.md` Active 테이블 상단 행 추가.

**IRON RULE**: Phase 6 이동 전 tracker 양쪽 갱신 필수. JSON/Markdown 한쪽만 업데이트된 상태로 커밋/세션 종료 금지.

### Phase 6: Cleanup

TeamDelete — **only after user confirms submission done AND Phase 5.9 tracker updated**

**Test Account Rules (MANDATORY — IRON RULES summary)**:
- **자동 회원가입 ABSOLUTELY BANNED** — 에이전트 signup/register 자동 제출 절대 금지. 계정 필요 시 사용자에게 요청만 가능.
- **Trigger for cleanup**: ANY pipeline exit (Phase 6 / Gate KILL / time-box ABANDON / crash / manual stop) — `targets/<target>/test_accounts.json` 확인 없이 세션 종료 금지.
- **BEFORE creating any account**: 회원탈퇴 경로 pre-check. 탈퇴 불가능한 서비스는 계정 생성 자제.
- **password 필드 필수**: `test_accounts.json`에 반드시 기록. 누락 = 파이프라인 위반.
- **Gmail alias**: `<base>+<target>_test_<letter>@gmail.com` (base는 `${HOME}/.config/bounty-credentials.json`의 `gmail_base`에서 로드 — 레포 하드코딩 금지). OAuth/소셜 로그인 금지.
- **세션 종료 전 반드시 탈퇴 완료**. "나중에 정리" 금지.

**Autonomous Session Rules (terminator.sh background mode)**: Phase 5.8에서 browser/Playwright 미접근. `autofill_payload.json` + `submission_review.json` 기록만. `autofill_payload.json`에 `credential_file` 필드 포함 → interactive session이 즉시 로그인 가능. Exit 시 "SUBMISSION READY: <target>/<finding>" 로그.

**전체 규칙** (최소 계정 원칙 / 생성 직후 탈퇴 테스트 / Autonomous handoff 상세): `.claude/rules/bb/test_account_rules.md`.

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
| triager-sim | sonnet/claude-opus-4-6[1m] | Gates | Gate 1=sonnet, Gate 2+=claude-opus-4-6[1m] |
| exploiter | claude-opus-4-6[1m] | 2 | PoC with evidence tiers |
| reporter | sonnet | 3,5 | Report + bugcrowd_form.md |
| critic | claude-opus-4-6[1m] | 4 | Fact-check |

---

## BB Core Rules (carried from v11 + v12 additions)

- **No PoC / No Gate PASS / Report-only = No submit (IRON RULES)** — Phase 0 NO-GO → stop. triager-sim SUBMIT + Kill Gate PASS 없이는 제출 금지.
- Tier 1-2 only submission (Tier 3-4 = auto delete). E3/E4 → `explore_candidates.md` (v12).
- Duplicate Pre-Screen mandatory. Same root cause = bundle. CVSS version check (3.1 vs 4.0).
- No V8 prototype pollution solo / No LLM echo claims. 3-layer remediation preferred.
- Anti-AI slop: target-specific details, no template language.
- VRT = Priority determinant (not CVSS alone). `bugcrowd_form.md` + bounty table verification mandatory.
- Gate 2 STRENGTHEN max 2x. Phase 4.5 KILL = Gate bug → feedback loop.
- **v12–v14 version addenda** (Evidence tier / Triage feedback pre-check / workflow_map / Risk-weighted coverage / Fresh-Surface Exception / v12.2 Phase 5.7 Live Scope / v12.3 Gate hardening + severity/impact HARD_KILL / v12.4 Phase 0.1 Program Fetch + platform handlers / v12.5 info-disc verbose-OOS collision / v13.6-v13.9 ralph-driven strengthening / v14 raw-bundle layer): 모두 위의 Phase 섹션에 세부 규정 있음. 요약 changelog: `.claude/rules/bb/core_rules_history.md`.

## Time-Box (unchanged from v11)

```
Phase 0: 45min | Phase 0.5: 30min | Phase 1: 2hr | Phase 1.5: 1hr (v12 NEW)
Phase 2: 3hr | Phase 3-5: 2hr
Total: 9hr (general, was 8hr) / 13hr (DeFi, was 12hr)
No HIGH+ signal at 2hr → ABANDON (after checklist pass)
```

### Token Efficiency Tracking (SCONE-bench)

각 target 완료 시 `python3 tools/infra_client.py db cost-summary --target <target> --json` 기록. Phase별 토큰 비율 (Discovery:Exploitation 이상적 1:3), ROI = 보상/API비용 > 5x 효율 기준. 상세: `.claude/rules/bb/token_efficiency.md`.

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
