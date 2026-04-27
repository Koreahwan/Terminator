# BB Core Rules — Version History / Changelog (v12 → v15)

Referenced from `bb_pipeline_v13.md` "BB Core Rules". These are the version addenda that accumulated over iterations. Full enforcement text lives inside the relevant Phase sections in the main file — this is the one-line summary per version.

## v12 additions

- Evidence tier classification mandatory (E1-E4)
- Triage feedback pre-check before Gates (`knowledge/triage_objections/`)
- `workflow_map.md` required for Web/API targets
- Risk-weighted coverage (HIGH endpoints count 2x)
- Fresh-Surface Exception for mature targets with new modules

## v12.2

- Phase 5.7 Live Scope Verification MANDATORY — 제출 전 반드시 프로그램 페이지 직접 확인. `program_rules_summary.md`는 초기 스냅샷이므로 live re-fetch 필수.

## v12.3 (Immunefi postmortem)

- Gate hardening — `kill-gate-1 --severity` mandatory + HARD_KILL, `kill-gate-2` evidence tier enforced (E3/E4=FAIL), mock PoC=FAIL
- LiteLLM $0 / duplicate incident → Live Bounty Status Check + Recent Submission Scan mandatory for huntr
- Paradex #72418 PoC incident → try/except 0 in attack logic, on-chain assertions only
- LayerZero incident → all GitHub links must point to official program repo org
- Platform accuracy pre-check via `tools/platform_accuracy.py`

## v12.4

- Phase 0.1 Program Fetch MANDATORY — `tools/bb_preflight.py fetch-program` replaces WebFetch+jina for verbatim scope/OOS/severity intake
- Platform-specific handlers: HackerOne GraphQL, Bugcrowd target_groups.json, Immunefi __NEXT_DATA__, Intigriti/YWH/HackenProof APIs, huntr/github_md scrapers
- jina is last-resort fallback capped at confidence 0.4 (HOLD only)

## v12.5 (Port of Antwerp 2026-04-14)

- Kill-gate-1 info-disc / verbose-OOS collision check — finding이 info-disclosure class(stack trace, hostname, banner, env dump 등)이고 프로그램 OOS에 "verbose messages without sensitive info" 계열이 있으면 --impact에 concrete sensitivity anchor 필수. 없으면 HARD_KILL.

## v13.4

- Kill Gate 1 expanded to 16 destruction checks (original 5 + v12.3-v12.6 severity/impact/info-disc/PoC-pattern/strengthening + v13.2-v13.4 semantic-OOS + Bugcrowd P5 downgrade + H1 NA/Informative prevention + AI-slop marker + scope-drift + past-incident cross-reference)

## v13.6

- Phase 5.9 Submission Tracker Update MANDATORY — `coordination/SUBMISSIONS.md` + `docs/submissions.json` 동시 갱신 via `/bounty-status-sync`
- CVP 적용 — dual-use 에이전트 자기-검열 제거 (상세: `memory/project_cvp_approval_2026_04_17.md`)

## v13.7

- Phase 0 historical-match via `knowledge/accepted_reports.db` MANDATORY (IRON RULE #8)
- Phase 5.7.5 User-Mediated Demo IRON RULE — 에이전트 verify-only 제출 절대 금지

## v13.8

- Phase 5.7.6 Objective 20-Question Stress Test IRON RULE — critic + triager-sim 2-agent 병렬 검증, ralph-driven max 3 iterations

## v13.9

- Phase 2 Pre-Gate-2 Strengthening Loop = `/ralph` skill 구동 MANDATORY (max 5 iterations)
- Phase 3.5 Report Quality Loop = `/ralph` 구동 (max 3 iterations, composite ≥ 75)
- Phase 5.7.6 20-Q Stress Test = `/ralph` 구동 (max 3 iterations until both agents SUBMIT-AS-IS)

## v14 (2026-04-18)

- Program scope verbatim-traceability IRON RULE — `program_raw/bundle.md` raw-bundle layer, Phase 0.2 `verbatim-check` HARD FAIL 시 block
- Playwright tier 4 SPA escalation + persistent login profile for invitation-only programs
- `scripts/refetch_active_targets.sh` retrospective refetch for pre-v14 targets

## v15 (2026-04-26)

- **Explore Parallel retired**: 별도 explore-only CLI는 제거. `target_discovery`로 후보를 고른 뒤 `bounty` 파이프라인에서 raw endpoint inventory + `vuln_assistant` triage를 수행.
- **Phase 4 Parallel READ**: critic + architect + codex:adversarial-review 3자 병렬 spawn (동일 artifact READ-only). KILL-trumps-all merge — ANY KILL 즉시 폐기, ALL PASS → dedup merge → reporter fix. 게이트 기준 변경 없음, 실행 구조만 직렬→병렬
