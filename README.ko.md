<div align="center">

<br>

<img src="https://img.shields.io/badge/TERMINATOR-Autonomous_Security_Agent-cc0000?style=for-the-badge&labelColor=1a1a1a" alt="Terminator">

<br><br>

**CTF 자동 풀이 및 버그바운티 취약점 탐색을 수행하는 멀티에이전트 AI 보안 시스템**

Claude Code-native 코어 + Codex/OMX + Gemini coordination 기반 — 25개 전문 에이전트, 공유 `coordination/` 상태, digest-first 컨텍스트 압축을 함께 사용

<br>

[![Claude Code](https://img.shields.io/badge/Claude_Code-Agent_Teams-7C3AED?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQyIDAtOC0zLjU4LTgtOHMzLjU4LTggOC04IDggMy41OCA4IDgtMy41OCA0LTggNHoiLz48L3N2Zz4=)](https://docs.anthropic.com/en/docs/claude-code)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Solidity](https://img.shields.io/badge/Solidity-Foundry-363636?style=flat-square&logo=solidity&logoColor=white)](https://book.getfoundry.sh/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)

<br>

| CTF 풀이 | 버그바운티 타겟 | AI 에이전트 | MCP 서버 | 파이프라인 스킬 | 지식 문서 | 보안 도구 |
|:--------:|:-------------:|:----------:|:--------:|:-------------:|:---------:|:--------:|
| **23** | **30+** | **25** | **10** | **9** | **280K+** | **40+** |

<br>

[English](README.md) | **한국어**

<sub>[R00T-Kim/Terminator](https://github.com/R00T-Kim/Terminator) 에서 fork · [@Koreahwan](https://github.com/Koreahwan) 이 유지관리 · 아래 [포크 강화 내역](#포크-강화-내역-koreahwan)</sub>

</div>

---

## 포크 강화 내역 (@Koreahwan)

업스트림 [R00T-Kim/Terminator](https://github.com/R00T-Kim/Terminator) 위에서 추가한 주요 기능. 업스트림 HEAD 대비 **142 파일 / +16,745 / −3,376 라인**.

### 파이프라인 강화 (`bb_pipeline v11 → v12.5`)
- **Explore Lane ↔ Prove Lane 분리** — 탐색(Phase 0–1.5)과 검증(Phase 2–6) 분리, 경계 발견은 `explore_candidates.md`에 보존
- **Kill Gate 1 / Kill Gate 2** + **HARD_KILL 강제** — PoC 전 + 보고서 전 destructive 테스트. `triager-sim` 시뮬 + `bb_preflight.py kill-gate-1/2` + `--severity`/`--impact` 엄격 검증
- **Evidence Tier 모델 (E1–E4)** — E1(full live exploit)/E2(live differential)만 제출 진행, E3/E4는 explore lane으로 재순환
- **Strengthening Loop** — 5-항목 iterative 체크리스트 (cross-user PoC, 2-step chain, E2→E1 승격, sibling 모듈 variant hunt, static source quote) + `strengthening_report.md` 감사 아티팩트
- **Phase 5.7 Live Scope Verification** (MANDATORY) — auto-fill 전 `fetch-program --no-cache`로 프로그램 페이지 재확인
- **v12.5 info-disc ↔ verbose-OOS 충돌 체크** — `verbose messages without sensitive info` OOS 조항이 있는 프로그램에서 info-disclosure 제출 시 구체 sensitivity anchor 필수

### 신규 도구
- **`tools/program_fetcher/`** (13개 모듈, ~4,500 라인) — 플랫폼별 verbatim scope intake:
  - HackerOne GraphQL · Bugcrowd target_groups.json · Immunefi `__NEXT_DATA__` · Intigriti / YesWeHack / HackenProof API · huntr · github raw README · jina fallback
  - 38-타겟 live benchmark (`tests/benchmarks/program_fetcher/`)
- **`bb_preflight.py`** (+1,560 라인) — `verify-target`, `fetch-program`, `rules-check`, `coverage-check`, `workflow-check`, `fresh-surface-check`, `kill-gate-1/2`, `evidence-tier-check`, `strengthening-check`, `duplicate-graph-check`
- **`terminator.sh`** (+1,347 라인) — `ai-security`, `robotics`, `supplychain` 자율 모드 추가
- **Report quality pipeline** — `report_scorer.py` (≥75 게이트), `report_scrubber.py` (Unicode watermark 제거), `evidence_manifest.py` (SHA256 감사 체인)

### 신규 에이전트
| 에이전트 | 모델 | 역할 |
|---------|-----|------|
| `ai-recon` | sonnet | LLM 엔드포인트 매핑, 모델 핑거프린팅, tool 열거 |
| `robo-scanner` | sonnet | ROS 토폴로지, 노드 열거, 펌웨어 추출 |
| `sc-scanner` | sonnet | SBOM 생성, 의존성 트리, 네임스페이스 충돌 |
| `cve-manager` | sonnet | CVE 자격 체크, GHSA / MITRE 제출 준비 |
| `submission-review` | opus | 최종 3-관점 리뷰 (Triager's Eye + Evidence Auditor + Devil's Advocate) |

### Cross-Model 통합
- **Codex GPT-5.4 adversarial-review** (Phase 4) — threat-model 현실성 / CVSS 정당성 / evidence gap 독립 교차 검토
- **Codex slop cross-check** (Phase 4.5) — Claude-blind 패턴 탐지

### AI Detection 3-레이어 (MANDATORY)
- **L1** heuristic (`ai_detect.py heuristic`)
- **L2** Claude self-review (in-session)
- **L3** ZeroGPT via Playwright MCP (<10% 임계)

### 지식 시스템 업그레이드
- **FTS5 최적화** — BM25 column weights + snippet() 적용 → `mcp__knowledge-fts` 쿼리 93–97% 토큰 절감
- **Wiki + AgDR 레이어** — `knowledge/decisions/`에 GO / KILL / 전략 변경 기록
- **Awesome-Hacking corpus** — 81 repos / 14.7K docs / 280K+ 토큰
- **Kernel-security-learning** corpus 통합
- **SQLite WAL + mmap** + PRAGMA 튜닝 + per-connect 오버헤드 수정

### 제출 워크플로
- **플랫폼별 report 템플릿** (`context/report-templates/platform-style/`) — Bugcrowd / HackerOne / Immunefi / MSRC / VendorDirect / ZDI
- **Phase 5.8 MCP auto-fill** (Playwright) — `autofill_payload.json` 계약, Submit 버튼 수동 클릭 (자동 클릭 절대 금지)
- **Cluster Submission Protocol** — 같은 codebase = 같은 날, root cause 번들링
- **Orphan Sweep** — `verifier` mode=bb-orphan-sweep, 제출물 간 stale reference / count drift 감지

### 업스트림 변경
업스트림 파이프라인(`bb_pipeline_v11.md`)은 superseded 되어 삭제. 커밋 히스토리에서 분기점 확인 가능.

---


---

## 데모

```
사용자: "pwnable.kr fd 풀어줘. SSH: fd@pwnable.kr -p2222 (pw: guest)"

Terminator:
  -> @reverser 스폰  -> 바이너리 분석, 공격 지도 생성
  -> @chain 스폰     -> 공격 지도 기반 익스플로잇 조립
  -> @critic 스폰    -> gdb로 오프셋 교차 검증
  -> @verifier 스폰  -> 로컬 3회 실행 후 원격 실행
  -> FLAG_FOUND: mama, are you prout of me?
```

```
사용자: "이뮤니파이에서 하이~크리티컬 취약점 찾을때까지 ㄱㄱ"

Terminator:
  -> @target-evaluator 스폰  -> ROI 점수화, GO 판정
  -> @scout + @analyst + @threat-modeler + @patch-hunter 스폰  -> 병렬 정찰 + CVE 매칭
  -> @workflow-auditor + @web-tester 스폰  -> 워크플로우 탐색 + 웹 테스트
  -> @exploiter 스폰         -> 작동하는 PoC 개발
  -> @critic 스폰            -> 보고서 팩트체크
  -> @triager-sim 스폰       -> 제출 전 보고서 공격
  -> SUBMIT: CWE-306 ATO chain, CVSS 7.4 High
```

---

## 작동 원리

Terminator는 단일 모델 프롬프트가 아닙니다. **25개 AI 에이전트**가 오케스트레이터를 통해 순차 파이프라인으로 조율되는 팀입니다.

- **적응형 파이프라인 선택** -- 오케스트레이터가 챌린지 유형(pwn, reversing, web, firmware, smart contract)에 따라 적절한 에이전트 시퀀스를 선택
- **구조화된 핸드오프** -- 각 에이전트가 타입이 지정된 산출물(공격 지도, 트리거 보고서, 익스플로잇 스크립트)을 생성하여 다음 단계에 전달
- **검증 우선** -- 모든 익스플로잇은 원격 실행 전 로컬 3회 테스트; 모든 버그바운티 보고서는 작동하는 PoC 필수
- **환각 방지** -- 전용 critic 에이전트가 독립적 도구 실행(gdb, Ghidra)으로 모든 주소, 오프셋, 상수를 교차 검증
- **크래시 복구** -- 체크포인트 프로토콜로 컨텍스트 압축 후에도 정확한 실패 지점부터 재개 가능
- **자동 품질 게이트 (v12 Kill Gate 포함)** -- 9개 파이프라인 스킬 + 3개 런타임 훅 + 2 Kill Gates(v12)가 OOS finding, 약한 PoC, 비현실적 위협 모델, AI 템플릿 언어를 제출 전 자동 차단
- **에이전트 튜닝** -- 에이전트별 effort 레벨(low/medium/high/max), 턴 제한, 필수 MCP 서버, 도구 제한으로 토큰 사용 최적화 및 역할 경계 강제
- **연구 기반 에이전트 패턴** -- Anthropic Frontier Red Team 연구에서 검증된 15개 기법 통합: Mythos 익스플로잇 프레임워크, GhostScript 변종 탐색, FP 반성 루프, 적응형 기법 우회, 속성 기반 PoC 검증, Best@N 병렬 재시도 등

---

## Cross-tool Runtime

이제 Terminator는 **Claude Code**, **Codex/OMX**, **Gemini**가 같은 상태 계약을 보게 해서 리더가 바뀌어도 긴 문서/로그를 다시 읽는 비용을 줄입니다.

- **`coordination/`이 공통 정본** -- manifest, digest, artifact, checkpoint, handoff를 `coordination/sessions/<session_id>/` 아래에 저장
- **Claude는 native 유지** -- `.claude/hooks/*.sh`가 세션 지식, 체크포인트, 산출물 검증을 `coordination/`으로 기록
- **Codex/OMX도 native 유지** -- `.omx/hooks/*.mjs`가 Codex 세션 bootstrap 및 `.omx/state`, notepad, plan을 같은 세션으로 미러링
- **Gemini는 helper 전용** -- `tools/context_digest.py --prefer-gemini`가 큰 파일/디렉토리/로그를 reusable digest로 압축
- **리더 전환은 구조화** -- `write-handoff` / `consume-handoff`로 freeform 재설명 대신 handoff JSON을 사용

repo 안에서 plain `omx`가 자동으로 hook plugin을 켜도록 1회 설치:

```bash
./scripts/install_omx_wrapper.sh
omx hooks status   # 이 repo 안에서는 Plugins enabled: yes
```

`.omx/hooks/` + `tools/coordination_cli.py`가 없는 다른 디렉토리에서는 wrapper가 기존 OMX 동작을 그대로 통과시킵니다.

## 실전 E2E 검증 상태

**2026년 3월 6일** 기준, 이 저장소에서 실제 `claude`, `codex`, plain `omx` 세션으로 검증했습니다.

- **Claude 커스텀 에이전트** -- `reverser`, `target-evaluator`, `triager-sim`, `fw-profiler`를 실제 spawn해 정상 완료 확인
- **Knowledge injection** -- live subagent 실행 중 `Task|Agent` hook 경로에서 `task_knowledge` digest와 `task_knowledge_injected` coordination event 생성 확인
- **Claude skills** -- native `Skill` tool로 `ctf` skill을 실제 로드해 파이프라인 지시문 반환 확인
- **Codex/OMX** -- plain `omx`가 repo hook plugin enabled 상태로 기동했고, Codex가 repo 지시를 읽어 공통 정본으로 `coordination/`을 정확히 응답
- **MCP / knowledge** -- Claude에서 `mcp__git__git_status`, `mcp__knowledge-fts__knowledge_stats`를 실제 호출해 성공 응답 확인
- **허용되는 optional 실패** -- `pentest-thinking`은 startup에서 실패할 수 있지만, **non-blocking**으로 취급하며 핵심 Terminator 워크플로를 막지 않음

---

## 아키텍처

```
                        ┌─────────────────────────┐
                        │     Claude Code CLI      │
                        │   Orchestrator (Lead)    │
                        └────────────┬────────────┘
                                     │
                  ┌──────────────────┼──────────────────┐
                  │                                      │
        ┌────────▼─────────┐                  ┌─────────▼────────┐
        │   CTF Pipeline   │                  │  Bug Bounty v12  │
        │   (Sequential)   │                  │   (Kill Gate)    │
        └────────┬─────────┘                  └─────────┬────────┘
                 │                                      │
    ┌────────────┼────────────┐          ┌──────────────┼──────────────┐
    │            │            │          │              │              │
┌───▼───┐  ┌────▼────┐  ┌───▼───┐  ┌───▼────┐  ┌─────▼─────┐  ┌────▼────┐
│Reverser│→ │ Chain/  │→ │Critic │  │ Scout  │→ │ Exploiter │→ │ Triager │
│       │  │ Solver  │  │       │  │+Analyst│  │           │  │   Sim   │
└───────┘  └─────────┘  └───┬───┘  └────────┘  └───────────┘  └─────────┘
                        ┌────▼────┐
                        │Verifier │→ FLAG_FOUND
                        └─────────┘

          ┌──────────────────────────────────────────────────────────┐
          │                  Infrastructure Layer                     │
          ├──────────┬──────────┬───────────┬──────────┬─────────────┤
          │ 10 MCP   │Knowledge │ Dashboard │ 40+      │ Runtime     │
          │ Servers  │ DB 280K+ │ (Web UI)  │ Tools    │ Hooks (3)   │
          └──────────┴──────────┴───────────┴──────────┴─────────────┘
```

에이전트들은 구조화된 산출물 전달을 통해 통신합니다 -- 단계 간 컨텍스트 손실 없음:

```
[HANDOFF from @reverser to @chain]
- Artifact: reversal_map.md
- Confidence: PASS
- Key Result: read_input()에서 BOF, 64바이트 오버플로우, canary 비활성
- Next Action: system("/bin/sh") 대상 leak + ROP 체인 구축
```

---

## 빠른 시작

### 사전 요구사항

- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) + Anthropic API 키
- Codex CLI + oh-my-codex (`omx`) for Codex-native sessions
- Python 3.10+ (pwntools, z3-solver, angr)
- gdb + pwndbg 또는 GEF
- Docker (선택사항, 전체 인프라 스택용)

### 대화형 모드

```bash
# plain `omx` wrapper 1회 설치
cd Terminator && ./scripts/install_omx_wrapper.sh

# Codex/OMX native (wrapper가 repo hook plugin 자동 활성화)
cd Terminator && omx

# Claude Code native
cd Terminator && claude

# CTF:
# "pwnable.kr fd 풀어줘. SSH: fd@pwnable.kr -p2222 (pw: guest)"

# 버그바운티:
# "이뮤니파이에서 하이~크리티컬 취약점 찾을때까지 ㄱㄱ"
```

### 자율 모드

```bash
./terminator.sh ctf /path/to/challenge.zip
./terminator.sh bounty https://target.com
./terminator.sh firmware /path/to/firmware.bin
./terminator.sh status
```

Terminator는 이제 항상 **Claude**로 시작합니다. **Codex는 spare continuation backend** 로만 사용되며, 아래 경우에만 이어받습니다:

- 토큰/쿼터 소진
- 컨텍스트 한도 소진
- Claude가 자체 retry를 다 소진한 뒤 멈춘 provider/API 장애

PostgreSQL의 `agent_runs`에 backend/parallel 메타까지 저장하려면 다음 migration을 적용하세요:

```bash
psql "$DATABASE_URL" -f scripts/migrate_agent_runs_backend.sql
```

### 대시보드

```bash
# 독립 모드 (Docker 불필요)
cd web && pip install -r requirements.txt && uvicorn app:app --port 3000

# 전체 스택 (Docker 서비스 6개)
docker compose up -d
# http://localhost:3000 접속
```

---

## 파이프라인

### CTF -- 적응형 파이프라인 선택

| 조건 | 파이프라인 | 에이전트 수 |
|:-----|:-----------|:-----------:|
| **Trivial** -- 소스 제공, 1-3줄 버그 | 직접 풀이 | 0 |
| **Reversing / Crypto** -- 수학적 역연산 필요 | `reverser -> solver -> critic -> verifier -> reporter` | 5 |
| **Pwn (명확한 취약점)** -- 명백한 오버플로우/포맷 스트링 | `reverser -> chain -> critic -> verifier -> reporter` | 5 |
| **Pwn (불명확한 취약점)** -- 크래시 탐색 필요 | `reverser -> trigger -> chain -> critic -> verifier -> reporter` | 6 |
| **Web** -- 인젝션, SSRF, 인증 우회 | `scout -> analyst -> exploiter -> reporter` | 4 |
| **Firmware** -- ARM 바이너리 diff, 에뮬레이션 PoC | `fw-profiler -> fw-inventory -> fw-surface -> fw-validator -> reporter` | 5 |

### 버그바운티 -- v12 파이프라인 (Kill Gate + 탐색 레인)

> [!IMPORTANT]
> **철칙**: Exploit 없으면, Report 없음. 작동하는 PoC 없는 발견사항은 자동 폐기.

<details>
<summary><b>Kill Gate 파이프라인 상세 (v12)</b></summary>

```
Phase 0   @target-evaluator     GO / NO-GO 평가 + Hard NO-GO 규칙
          oos-check skill       OOS 패턴 사전 스크리닝 (12개 패턴)
          --- GO gate --------------------------------------------------------
Phase 0.2 bb_preflight.py       프로그램 규칙 생성 + 검증 (MANDATORY)
Phase 0.5 @scout                자동화 도구 스캔 (Slither, Semgrep, Mythril)
Phase 1   @scout + @analyst     병렬 정찰 + finding별 OOS 교차 체크
          @threat-modeler       신뢰 경계 매핑 + 역할 매트릭스 + 불변식 추출 (병렬)
          @patch-hunter         보안 커밋 불완전 수정 + 변종 취약점 탐색 (병렬)
          coverage-gate skill   80%+ 엔드포인트 커버리지 필수
Phase 1.5 @analyst (N 병렬)    OWASP 카테고리별 병렬 헌팅 (대형 코드베이스 전용)
          @workflow-auditor      비즈니스 워크플로우 상태 전이 매핑 + 이상 탐지 (신규)
          @web-tester           웹 애플리케이션 테스트, 인증 우회, 인젝션 (신규)
★ Gate 1  @triager-sim (sonnet) Finding 생존성: 5-Question Destruction Test (KILL/GO)
          리스크 가중 커버리지 체크 + workflow-check + fresh-surface-check
Phase 2   @exploiter            PoC 개발 + poc-tier skill (Tier 1-2만 통과)
                                Evidence Tier 모델 (E1-E4) 적용
          threat-model-check    공격 전제조건 현실성 검증
★ Gate 2  @triager-sim (opus)   PoC 파괴 테스트: 증거 품질 + 트리아저 반론 (KILL/GO)
                                + duplicate-graph-check
Phase 3   @reporter             보고서 초안 + CVSS 계산 (context/report-templates/ 플랫폼 스타일 참조)
Phase 3.5 report_scorer.py      5차원 품질 게이트 (증거/임팩트/재현성/가독성/슬롭, >=75)
          report_scrubber.py    AI 시그니처 제거 (Unicode 워터마크, em-dash, 슬롭 패턴)
Phase 4   @critic               팩트체크 (경량화, Gate 2가 viability 처리)
Phase 4.5 @triager-sim          최종 정합성 검증 (여기서 KILL = Gate 버그 → feedback loop)
          slop-check skill      AI 슬롭 점수 (<=2 PASS, 3-5 STRENGTHEN, >5 KILL)
Phase 5   @reporter             최종 보고서 + ZIP 패키징 + evidence_manifest.json
Phase 6   TeamDelete            정리
```

**9개 자동 파이프라인 스킬 + 3개 런타임 훅 + 2 Kill Gates (v12):**

| 스킬 | 게이트 | 차단 조건 |
|:-----|:-------|:----------|
| `oos-check` | Phase 0 + finding별 | OOS 패턴 (oracle staleness, admin-gated 등) |
| `coverage-gate` | Phase 1->2 | 엔드포인트 커버리지 <80% (소규모는 100%) |
| `poc-tier` | Phase 2->3 | Tier 3-4 PoC (실행 캡처 없음) |
| `threat-model-check` | Phase 2 | 비현실적 공격 전제조건 (2개+ 제어 필요) |
| `slop-check` | Phase 4.5 | AI 템플릿 언어 점수 >5 |
| `checkpoint-validate` | 모든 단계 | Fake idle / fake completion 탐지 |

**추가 품질 게이트 (v12 Kill Gate 포함):**
- Phase 0 Hard NO-GO: 3+ audits, 2+ reputable audits, 100+ reports, 3년+, 소스 비공개
- Phase 0.2 프로그램 규칙 검증 통과 필수 (에이전트 스폰 전)
- Phase 4.5 triager-sim이 구조화된 JSON 출력 → reporter 자동 피드백 루프
- ★ Gate 1 + Gate 2: Kill Gate가 PoC 개발 전 + 보고서 작성 전에 finding을 차단 (v12 NEW)

</details>

---

## 에이전트

25개 전문 에이전트가 `.claude/agents/`에 정의 (~8,100줄, 레퍼런스 문서 포함).

<details>
<summary><b>CTF 에이전트 (8개)</b></summary>

| 에이전트 | 역할 | 모델 | Effort | 출력 |
|:---------|:-----|:----:|:------:|:-----|
| **reverser** | 바이너리 분석, 보호 기법 탐지, 공격 표면 매핑 | Sonnet | High | `reversal_map.md` |
| **trigger** | 크래시 탐색, 입력 최소화, 프리미티브 식별 | Sonnet | Medium | `trigger_report.md` |
| **solver** | reversing/crypto 챌린지용 역연산 | Opus | Max | `solve.py` |
| **chain** | 다단계 익스플로잇: leak -> overwrite -> shell. JIT/브라우저 Mythos 프레임워크, 적응형 기법 우회 | Opus | Max | `solve.py` |
| **critic** | Security Council 심의 (5 아키타입) + 교차 검증 | Opus | High | `critic_review.md` |
| **verifier** | 로컬 3회 재현 -> 원격 실행. BB 모드: positive/negative 테스트 검증 | Sonnet | Low | `FLAG_FOUND` |
| **reporter** | 실패한 시도 및 기법 포함 라이트업 | Sonnet | Medium | `knowledge/challenges/<name>.md` |
| **ctf-solver** | Trivial 챌린지용 레거시 단일 에이전트 | Sonnet | High | `solve.py` |

</details>

<details>
<summary><b>버그바운티 에이전트 (10개)</b></summary>

| 에이전트 | 역할 | 모델 | Effort | 출력 |
|:---------|:-----|:----:|:------:|:-----|
| **target-evaluator** | 프로그램 ROI 점수화, GO/NO-GO 판정 | Sonnet | Medium | `target_assessment.md` |
| **scout** | 정찰 + 중복 사전검증 + 자동화 도구 스캔 | Sonnet | Medium | `recon_report.json` |
| **analyst** | CVE 매칭, source->sink 추적, 신뢰도 점수화, 퍼저 도달 불가 버그에 대한 LLM-advantage 추론 | Sonnet | High | `vulnerability_candidates.md` |
| **exploiter** | PoC 개발, 품질 등급 분류 (Evidence Tier E1-E4), FP 반성 루프, 속성 기반 검증, 적응형 우회 | Opus | Max | PoC 스크립트 + 증거 |
| **triager-sim** | 적대적 트리아저 -- 3 모드: finding-viability (Gate 1), PoC-destruction (Gate 2), report-review | Sonnet/Opus | High | SUBMIT / STRENGTHEN / KILL |
| **source-auditor** | 소스코드 심층 감사, 크로스파일 taint 분석 | Opus | Max | `audit_findings.md` |
| **defi-auditor** | 스마트 컨트랙트 분석, DeFi 특화 취약점 패턴 | Opus | Max | `defi_audit.md` |
| **threat-modeler** | 신뢰 경계 매핑, 역할 매트릭스, 상태 머신 및 불변식 추출 | Sonnet | Medium | `threat_model.md` |
| **workflow-auditor** | 비즈니스 워크플로우 상태 전이 매핑 및 이상 탐지 | Sonnet | Medium | `workflow_audit.md` |
| **patch-hunter** | 보안 커밋에서 불완전 수정 및 변종 취약점 탐색 (GhostScript 3단계 패턴) | Sonnet | High | `patch_analysis.md` |

</details>

<details>
<summary><b>펌웨어 에이전트 (4개)</b></summary>

| 에이전트 | 역할 | 모델 | 출력 |
|:---------|:-----|:----:|:-----|
| **fw-profiler** | 펌웨어 이미지 프로파일링, 아키텍처 탐지 | Sonnet | `firmware_profile.md` |
| **fw-inventory** | 바이너리 인벤토리, 버전 추출, CVE 매칭 | Sonnet | `firmware_inventory.md` |
| **fw-surface** | 공격 표면 매핑, 바이너리 diff 분석 | Sonnet | `attack_surface.md` |
| **fw-validator** | QEMU 에뮬레이션, 동적 PoC 검증 | Sonnet | `validation_results.md` |

</details>

<details>
<summary><b>특화 에이전트 (3개)</b></summary>

| 에이전트 | 역할 | 모델 | 출력 |
|:---------|:-----|:----:|:-----|
| **mobile-analyst** | Android/iOS 앱 분석, API 인터셉션 | Sonnet | `mobile_findings.md` |
| **recon-scanner** | 자동 정찰, 서브도메인/포트 탐색 | Sonnet | `recon_results.json` |
| **web-tester** | 웹 애플리케이션 테스트, 인증 우회, 인젝션 | Sonnet | `web_findings.md` |

</details>

<details>
<summary><b>에이전트 복원력 -- 체크포인트 프로토콜</b></summary>

모든 작업 에이전트는 크래시/컴팩션 복구를 위한 체크포인트 프로토콜을 구현합니다:

- **checkpoint.json** -- 에이전트가 Phase 전환마다 상태/완료항목/핵심정보를 JSON으로 기록
- **Fake Idle 감지** -- Orchestrator가 checkpoint 상태 확인; `in_progress` + idle = 컨텍스트 포함 재스폰
- **재스폰 시 이어서** -- 새 에이전트가 기존 checkpoint 읽고 완료된 단계 건너뜀
- **에러 보고** -- `status: "error"` + 설명; Orchestrator가 환경 해결 후 재스폰

> [!NOTE]
> "산출물 파일 있음 = 완료"로 판단하지 마라. `checkpoint.status == "completed"`만 신뢰.

</details>

<details>
<summary><b>런타임 훅 -- 자동화된 안전 및 인텔리전스</b></summary>

3개의 런타임 훅이 프롬프트 지시가 아닌 실행 레벨에서 파이프라인 규칙을 강제합니다:

| 훅 | 트리거 | 목적 |
|:---|:-------|:-----|
| **safe_payload_hook.py** | PreToolUse (Bash) | 위험 명령(rm -rf, dd, mkfs, fork bomb) 실행 전 차단 |
| **observation_mask_hook.py** | PostToolUse (Bash/Read) | 500줄 초과 출력 파일 저장 + 100줄 이상 ASCII art/반복 텍스트 패턴 감지, 컨텍스트 오버플로우 방지 |
| **check_agent_completion.sh** | SubagentStop | FLAG 패턴 감지, 지식 추출, 체크포인트 미작성 에이전트 자동 기록 |

추가 훅: `knowledge_inject.sh` (에이전트 유형별 지식 주입), `knowledge_db_update.sh` (지식 DB 자동 재색인), `session_knowledge.sh` (세션 시작 시 글로벌 컨텍스트 로드).

</details>

---

## 지식 엔진

**280K+ 보안 문서**를 SQLite FTS5 + BM25 랭킹 + 프로그레시브 쿼리 완화로 인덱싱한 통합 검색 시스템. 외부 의존성 없음.

| 소스 | 문서 수 | 내용 |
|:-----|--------:|:-----|
| 내부 기법 | 82 | 공격 패턴, CTF 라이트업 |
| 외부 레포 (47개) | 12,896 | HackTricks, GTFOBins, PayloadsAllTheThings, how2heap, OWASP, SecLists, InternalAllTheThings + 40개 |
| ExploitDB | 46,960 | 익스플로잇 설명, 플랫폼, CVE |
| Nuclei 템플릿 | 14,871 | 심각도 포함 취약점 탐지 템플릿 |
| PoC-in-GitHub | 18,235 | CVE PoC 저장소 |
| trickest-cve | 155,121 | CVE 상세, 제품, CWE, PoC 링크 |
| 웹 아티클 | 30+ | 크롤링한 보안 블로그, 라이트업, OWASP 치트시트 |

에이전트가 `knowledge-fts` MCP 서버를 통해 검색:

```python
smart_search("QNAP buffer overflow strcpy")   # 추천: 자동 완화 (AND → OR → top-terms)
technique_search("heap tcache poisoning")      # 상위 5개 기법 문서
technique_search("IDOR")                       # "insecure direct object reference"로 자동 확장
exploit_search("CVE-2021-44228")               # CVE → trickest-cve + PoC 우선 라우팅
search_all("race condition double spend")      # 전체 7개 테이블, 크로스 테이블 랭킹
```

33개 보안 약어 자동 확장: `uaf`, `bof`, `sqli`, `ssrf`, `toctou`, `xxe`, `ssti`, `idor`, `rce`, `lpe`, `cmdinjection` 등.

<details>
<summary><b>자동 재빌드, 웹 페처, CLI</b></summary>

PostToolUse 훅이 `knowledge/techniques/` 또는 `knowledge/challenges/` 파일 변경 시 자동 재인덱싱. 전체 재빌드: ~60초. 증분 업데이트: <1초.

```bash
python tools/knowledge_indexer.py build                    # 전체 재빌드
python tools/knowledge_indexer.py smart-search "heap uaf"  # 프로그레시브 완화 검색
python tools/knowledge_indexer.py stats                    # 테이블별 문서 수

# 웹 콘텐츠 페처 (web_articles 테이블에 추가)
python tools/knowledge_fetcher.py fetch <url>              # 단일 URL (jina.ai 경유)
python tools/knowledge_fetcher.py bulk knowledge/sources/blogs.md  # URL 목록 일괄 수집
python tools/knowledge_fetcher.py update                   # 30일+ 오래된 항목 재수집
python tools/knowledge_fetcher.py stats                    # 웹 아티클 통계
```

</details>

---

## 도구 체인

### MCP 서버 -- AI 네이티브 도구 통합

10개 MCP 서버가 에이전트에게 보안 도구 직접 접근 제공.
사용자 레벨 MCP가 추가로 보일 수 있으며, `pentest-thinking`이 unavailable이어도 핵심 Terminator 파이프라인은 계속 동작합니다.

<details>
<summary><b>Core MCP Servers (10 active + 4 opt-in)</b></summary>

| 서버 | 기능 |
|:-----|:-----|
| **mcp-gdb** | 브레이크포인트, 메모리 검사, 스텝 실행, 백트레이스 |
| **ghidra-mcp** | 헤드리스 디컴파일, 구조체/열거형 분석 |
| **frida-mcp** | 동적 계측, 후킹, 프로세스 스포닝 |
| **pentest-mcp** | nmap, gobuster, nikto, john, hashcat |
| **nuclei-mcp** | 12K+ 취약점 탐지 템플릿 스캔 |
| **codeql-mcp** | 시맨틱 taint tracking, 변종 분석 |
| **semgrep-mcp** | 패턴 기반 정적 분석 |
| **context7** | 최신 라이브러리 문서 조회 |
| **graphrag-security** | 보안 지식 그래프: 익스플로잇 검색, 유사 발견사항, 드리프트 감지 |
| **knowledge-fts** | 280K+ 문서 BM25 검색 — smart_search 완화, 33 시노님, web_articles, 크로스 테이블 랭킹 |

**opt-in 서버** (필요 시 활성화): lightpanda, browser-use, opendataloader-pdf, playwright

로컬 구현 서버: `tools/mcp-servers/markitdown-mcp/`는 MarkItDown 기반 로컬 파일 문서→Markdown 변환을 제공하지만, 기본 활성 서버 목록에는 아직 연결되어 있지 않습니다.

> 거부된 서버: radare2 (Ghidra MCP로 대체). ToolAnnotations를 통해 에이전트별 MCP 서버 접근이 제한됩니다.

</details>

<details>
<summary><b>보안 도구 (40+)</b></summary>

**리버스 엔지니어링 및 익스플로잇 개발**
- 디스어셈블리: objdump, strings, readelf, nm
- 디컴파일: Ghidra (MCP), jadx
- 디버깅: gdb + pwndbg + GEF (93 commands), strace
- 심볼릭 실행: angr, unicorn, z3-solver, keystone
- 익스플로잇: pwntools, ROPgadget, ropper, one_gadget
- 암호: pycryptodome, sympy, z3-solver

**웹 보안**
- 인젝션: sqlmap, commix, dalfox (XSS)
- SSRF: SSRFmap (18+ 모듈)
- 정찰: ffuf, subfinder, katana, httpx, gau, waybackurls, arjun
- 스캔: nuclei (12K+ 템플릿), trufflehog (800+ 시크릿 타입)
- 크롤링: crawl4ai (Playwright 기반, JS 렌더링, 스텔스 모드)

**코드 분석 및 스마트 컨트랙트**
- 시맨틱: CodeQL (taint tracking, variant analysis)
- 정적: Semgrep (커스텀 룰 작성)
- 스마트 컨트랙트: Slither (100+ detectors), Mythril (EVM symbolic), Foundry 1.5.1
- AI: Gemini CLI (gemini-3-pro-preview)

**펌웨어 분석**
- QEMU ARM user-mode 에뮬레이션, rootfs 마운팅
- 펌웨어 버전간 바이너리 diff
- 아키텍처 탐지, 라이브러리 인벤토리

**참조 데이터베이스**
- ExploitDB (47K+ exploits), PoC-in-GitHub (18K+ CVE PoCs)
- PayloadsAllTheThings (70+ 취약점 카테고리), trickest-cve (154K+ CVE PoCs)
- HackTricks + GTFOBins, SecLists

</details>

<details>
<summary><b>스킬 플러그인 (Trail of Bits, Sentry, Anthropic)</b></summary>

| 플러그인 | 스킬 | 용도 |
|:---------|:-----|:-----|
| static-analysis | semgrep, codeql, sarif-parsing | 자동화 정적 분석 |
| variant-analysis | variant-analysis | CVE 변종 패턴 탐색 |
| testing-handbook | aflpp, libfuzzer, harness-writing + 12개 | 퍼징 (Trail of Bits) |
| insecure-defaults | insecure-defaults | 하드코딩 시크릿, 약한 인증 |
| sharp-edges | sharp-edges | 위험 API 탐지 |
| audit-context | audit-context-building | 감사 전 아키텍처 매핑 |
| dwarf-expert | dwarf-expert | DWARF 디버그 포맷 |
| yara-authoring | yara-rule-authoring | YARA 룰 작성 |
| differential-review | differential-review | Git diff 보안 리뷰 |
| sentry-skills | find-bugs, security-review, code-review | 버그 탐지 |

</details>

<details>
<summary><b>크로스 모델 리뷰 (Codex / GPT-5.4)</b></summary>

OpenAI Codex 플러그인(`codex@openai-codex`)으로 파이프라인 체크포인트에서 크로스 모델 검증:

| 명령어 | 용도 | 파이프라인 단계 |
|:-------|:-----|:---------------|
| `/codex:review` | 표준 코드 리뷰 | BB Phase 4.5, Phase 5 |
| `/codex:adversarial-review` | 설계 결정 챌린지 리뷰 | CTF critic 후, BB Phase 4 |
| `/codex:rescue` | GPT-5.4에 작업 위임 | CTF 듀얼 어프로치 대안 |
| `/codex:status` | 실행 중 작업 모니터링 | 전체 |

래퍼 스크립트: `tools/codex_cross_review.sh` — critic APPROVED 시 SubagentStop 훅이 자동 트리거.

</details>

---

## 실적

### CTF 챌린지 -- 20문제 풀이

| 카테고리 | 수 | 사용 기법 |
|:---------|:--:|:----------|
| Pwn (heap, stack, ROP) | 10 | pwntools, ROP chains, GOT overwrite, shellcode |
| Reversing (VM, 난독화) | 6 | GDB Oracle, DFA 추출, z3, 커스텀 VM 분석 |
| Crypto | 2 | AES-ECB, z3 제약 조건 풀이 |
| Misc (로직, 필터 우회) | 2 | 연산자 우선순위, 이진 탐색 |

### 버그바운티 -- 30+ 타겟 평가

| 지표 | 수치 |
|:-----|-----:|
| 평가한 프로그램 | 30+ |
| 플랫폼 | Immunefi, HackerOne, Bugcrowd, PSIRT |
| 카테고리 | Smart Contract (DeFi), Web App, VPN, IoT/Firmware, AI/SDK |
| 분석한 스마트 컨트랙트 | 50+ |
| 조사한 취약점 리드 | 100+ |
| 작동하는 PoC 보유 발견사항 | 15+ |

> 구체적인 타겟과 발견사항은 공개 완료 전까지 비공개 유지.

---

<details>
<summary><b>연구 기반</b></summary>

**v7 -- LLM 프롬프팅 연구 적용 (13편 논문)**

13편의 LLM 프롬프팅 연구 논문을 기반으로 에이전트 프롬프트를 체계적으로 개선. 핵심 12개 에이전트 5,391줄 → 3,515줄 (35% 감소), 고품질 추론 구조 추가:

| 기법 | 논문 | 적용 대상 | 효과 |
|:-----|:-----|:----------|:-----|
| IRON RULES primacy+recency | Lost in the Middle (Liu et al.) | 전 12개 에이전트 | 핵심 규칙을 맨 앞 + 맨 뒤 반복, recall +22%p |
| Structured Reasoning (OBSERVED/INFERRED/ASSUMED/RISK/DECISION) | Chain-of-Thought (Wei et al.) | 전 12개 에이전트 | 비구조화 Think-Before-Act 대체 |
| Self-Verification (CoVe) | Chain-of-Verification (Dhuliawala et al.) | chain, solver, exploiter, trigger | 제출 전 독립 팩트체크, 환각 -77% |
| Few-Shot 예시 | The Prompt Report + CoT | critic, reverser, triager-sim, solver | APPROVED/REJECTED, reversal_map, SUBMIT/KILL, z3 모델링 예시 |
| Tree of Thoughts 분기 | Tree of Thoughts (Yao et al.) | chain, solver | 코딩 전 Top-3 전략 평가 |
| ReAct 루프 (THOUGHT→ACTION→OBSERVATION) | ReAct (Yao et al.) | reverser, scout, trigger | 관측이 가정을 부정하면 즉시 전략 수정 |
| Self-Consistency (다중 해 탐지) | Self-Consistency (Wang et al.) | solver | under-constrained z3 모델 감지 |
| 공격적 pruning + reference 분리 | APE (Zhou et al.) | scout (-76%), analyst (-61%), exploiter (-45%) | 상세 내용을 `_reference/` 디렉토리로 분리 |

Dual-Approach 트리거 3회 → 2회 실패로 단축 (ToT가 1회차에 이미 대안 평가).

---

에이전트 정의는 또한 10+ 외부 LLM 보안 프레임워크의 패턴을 통합:

| 패턴 | 출처 | 적용 위치 |
|:-----|:-----|:----------|
| Variant Analysis -- CVE 패치 diff를 시드로 활용 | Google Big Sleep (Project Zero + DeepMind) | analyst |
| LLM-first PoV Generation | RoboDuck (AIxCC 3위) | chain, solver |
| Symbolic + Neural Hybrid | ATLANTIS (AIxCC 1위) | solver |
| No Exploit, No Report | Shannon, XBOW | Orchestrator gate |
| Iterative Context Gathering -- 3-pass 역추적 | Vulnhuntr | analyst |
| Dual-Approach Parallel -- 2회 실패 후 2전략 병행 | RoboDuck | Orchestrator |
| OWASP Parallel Hunters | Shannon | analyst (Phase 1.5) |
| PoC Quality Tier Gate (1-4) | XBOW | exploiter |
| Adversarial Triage Simulation | Internal | triager-sim |
| Prompt Injection Guardrails | CAI (300+ LLM agents) | All agents |
| 4-Layer Validation | NeuroSploit | critic, triager-sim |
| Security-Aware Compression | CyberStrikeAI | All agents (context preservation) |
| Exploit Chain Rules | NeuroSploit | exploiter (web targets) |
| Security Council (5-아키타입 심의) | Consciousness Council (K-Dense) | critic |

**Anthropic Frontier Red Team 패턴 (2026)** -- [red.anthropic.com](https://red.anthropic.com) 연구에서 검증된 15개 기법 통합:

| 패턴 | 출처 | 적용 대상 |
|:-----|:-----|:----------|
| Mythos 4단계 익스플로잇 프레임워크 (Type Confusion → Leak → Forgery → R/W) | CVE-2026-2796 역공학 | chain |
| GhostScript 3단계 변종 탐색 (Diff → Grep → 검증) | LLM 발견 0-day | patch-hunter |
| FP 반성 루프 (5개 질문) | 속성 기반 테스팅 | exploiter |
| LLM-Advantage 분석 (퍼저 도달 불가 5가지 버그 클래스) | LLM 발견 0-day | analyst |
| Task Verifier (Positive + Negative 테스트) | Firefox 파트너십 | verifier |
| Best@N 병렬 재시도 (크로스모델 + 동일모델 3-way) | Smart Contract SCONE-bench | ctf_pipeline, bb_pipeline |
| 적응형 기법 우회 (knowledge-fts 자동 검색) | 핵심 인프라 방어 | chain, exploiter |
| 속성 기반 PoC 검증 (5개 보안 불변식) | 속성 기반 테스팅 | exploiter |
| Discovery vs Exploitation 비용 원칙 (1:10 비율) | Firefox 파트너십 | bb_pipeline |
| 클러스터 제출 프로토콜 (동일일 번들) | Firefox 파트너십 | bb_pipeline |
| 토큰 효율성 추적 (타겟별 ROI) | Smart Contract SCONE-bench | bb_pipeline |
| ASCII Art / 반복 텍스트 패턴 감지 | Cyber Competitions (CCDC) | observation_mask_hook |
| 타겟별 비용 추적 (cost_tracking.json) | Smart Contract SCONE-bench | bb_preflight, infra_client |
| ToolSpec 정밀화 (parallel_class, 상세 설명) | Cyber Toolkits (Incalmo) | tools.yaml |
| Glasswing 전략 레퍼런스 (Mythos Preview 90x) | Mythos Preview 평가 | memory |

---

**환각 방지 시스템** -- `critic` 에이전트가 판정 전 5개 적대적 아키타입으로 구성된 **Security Council** 심의를 실행:

| 아키타입 | 역할 |
|:---------|:-----|
| **The Interrogator** | 적대적 트리아저 -- 모든 주장에 라이브 증거 요구 ("GDB 출력 보여줘, 아니면 안 일어난 거야") |
| **The Empiricist** | 데이터 기반 검증 -- 증거 없으면 불인정 |
| **The Architect** | 구조 분석 -- 체인 설계가 모든 조건에서 버티는지 |
| **The Triager** | 플랫폼 리뷰어 시뮬 -- "이걸 N/A로 닫을 첫 번째 이유는?" |
| **The Historian** | 지식 베이스 과거 실패 패턴 매칭 |

Interrogator는 **비대칭 거부권** 보유: 핵심 주장에 라이브 증거 없으면 자동 REJECT. 6단계 검증과 결합:

1. **증거 체크** -- 모든 주장은 구체적 출력(정확한 문자열, 헤더, 타이밍)을 인용해야 함
2. **음성 대조군** -- 기준선 비교 필수 (정상 응답 vs 페이로드 응답)
3. **실행 증명** -- 취약점 유형별: XSS는 JS 실행, SQLi는 DB 내용 추출 필수
4. **추측적 언어 감지** -- "could be", "might be", "potentially" 자동 플래그
5. **심각도 보정** -- 데이터 없는 200 OK는 High가 아님
6. **신뢰도 점수** -- 0-100, 70 미만 = REJECT

**경쟁 프레임워크 채택 패턴** -- [10개 오픈소스 보안 AI 프레임워크](knowledge/techniques/competitor_analysis.md)에서 포팅:

| 패턴 | 출처 | 구현 |
|:-----|:-----|:-----|
| Web Exploit Chain Engine | NeuroSploit | `tools/web_chain_engine.py` -- SSRF->internal, SQLi->DB-type 자동 체인 |
| Flag Pattern Detector | PentestGPT | `tools/flag_detector.py` -- 8+ regex 패턴, strict 검증 |
| Anti-Hallucination Prompts | NeuroSploit | `tools/validation_prompts.py` -- 8개 조합형 프롬프트, 0-100 신뢰도 |
| MITRE Auto-Mapping | RedAmon | `tools/mitre_mapper.py` -- 36 CWE->CAPEC->ATT&CK 매핑 |

</details>

---

<details>
<summary><b>프로젝트 구조</b></summary>

```
Terminator/
├── .claude/
│   ├── agents/              # 25개 에이전트 정의 (~8,100줄)
│   │   ├── reverser.md      #   바이너리 분석
│   │   ├── chain.md         #   익스플로잇 체인 조립
│   │   ├── critic.md        #   교차 검증 + Security Council
│   │   ├── target_evaluator.md  # GO/NO-GO + Hard NO-GO 규칙
│   │   ├── triager_sim.md   #   적대적 트리아저 + JSON 피드백
│   │   ├── threat_modeler.md    # 신뢰 경계 매핑 + 불변식 추출 (v12 NEW)
│   │   ├── workflow_auditor.md  # 비즈니스 워크플로우 이상 탐지 (v12 NEW)
│   │   ├── patch_hunter.md      # 불완전 수정 + 변종 취약점 탐색 (v12 NEW)
│   │   ├── fw_*.md          #   펌웨어 분석 (4개 에이전트)
│   │   ├── _reference/      #   공유 레퍼런스 문서 (명령어, 패턴, 도구)
│   │   │   └── bb_agent_reference.md  # BB 에이전트 공통 레퍼런스
│   │   └── ...              #   + 16개 전문가 에이전트
│   ├── rules/               # 파이프라인 규칙
│   │   ├── bb_pipeline_v13.md   # v12 Kill Gate 상세 절차
│   │   ├── bb_pipeline_v11.md   # v11 아카이브 (레퍼런스용)
│   │   ├── ctf_pipeline.md      # CTF 파이프라인 상세 절차
│   │   ├── agent_tuning.md      # 에이전트별 effort/turn/MCP 설정
│   │   └── mcp_policy.md        # MCP 서버 허용/거부 정책
│   ├── hooks/               # 런타임 훅 (파이프라인 최적화 v3.1)
│   │   ├── safe_payload_hook.py     # 위험 명령 차단 (PreToolUse)
│   │   ├── observation_mask_hook.py # 대용량 출력 마스킹 + ASCII art/반복 텍스트 감지
│   │   └── check_agent_completion.sh # FLAG 감지 + 체크포인트 (SubagentStop)
│   └── skills/              # 9개 파이프라인 스킬
│       ├── bounty/          #   버그바운티 파이프라인 조율
│       ├── ctf/             #   CTF 파이프라인 조율
│       ├── oos-check/       #   Out-of-Scope 사전 스크리닝 (12 패턴)
│       ├── poc-tier/        #   PoC 품질 분류 (Tier 1-4)
│       ├── coverage-gate/   #   엔드포인트 커버리지 게이트 (80%+)
│       ├── threat-model-check/  # 공격 전제조건 검증
│       ├── slop-check/      #   AI 슬롭 감지 (0-10 점수)
│       └── checkpoint-validate/ # 에이전트 idle/완료 검증
├── knowledge/               # 축적된 경험
│   ├── index.md             #   마스터 인덱스
│   ├── knowledge.db         #   FTS5 검색 DB (280K+ 문서, 7 테이블, ~259MB)
│   ├── sources/             #   웹 콘텐츠 URL 시드 (blogs.md, writeups.md, techniques.md)
│   ├── challenges/          #   챌린지별 라이트업
│   └── techniques/          #   재사용 가능한 공격 기법 + 경쟁 분석
├── research/                # LLM 보안 프레임워크 분석 (14개 문서)
├── tools/                   # 파이프라인 도구
│   ├── bb_preflight.py      #   파이프라인 게이트 검증 (init, rules-check, coverage-check, cost-tracking,
│   │                        #   inject-rules, exclusion-filter, kill-gate-1, kill-gate-2,
│   │                        #   workflow-check, fresh-surface-check, duplicate-graph-check,
│   │                        #   risk-weighted-coverage, --json)
│   ├── knowledge_indexer.py #   FTS5 DB 빌더 (7 테이블, smart_search, 제로 의존성)
│   ├── knowledge_fetcher.py #   웹 콘텐츠 페처 (jina.ai → web_articles 테이블)
│   ├── web_chain_engine.py  #   Web 익스플로잇 체인 엔진 (10 규칙)
│   ├── flag_detector.py     #   CTF 플래그 패턴 탐지 (8+ 포맷)
│   ├── validation_prompts.py#   환각 방지 프롬프트 라이브러리
│   ├── mitre_mapper.py      #   CVE->CWE->CAPEC->ATT&CK (36 CWEs)
│   ├── attack_graph/        #   Neo4j + 파일시스템 공격 표면 그래프
│   ├── dag_orchestrator/    #   DAG 파이프라인 스케줄링 + Claude CLI 핸들러
│   ├── sarif_generator.py   #   SARIF 2.1.0 출력
│   ├── report_scorer.py     #   5차원 보고서 품질 스코어러 (증거/임팩트/재현성/가독성/슬롭)
│   ├── report_scrubber.py   #   AI 시그니처 제거 (Unicode 워터마크, em-dash, 슬롭 플래그)
│   ├── evidence_manifest.py #   통합 증거 매니페스트 생성 (SHA256, 체크포인트, 트리아저 상태)
│   ├── toolspec/            #   에이전트별 도구 제한 명세
│   └── mcp-servers/         #   nuclei, codeql, semgrep, knowledge-fts, graphrag, markitdown
├── targets/                 # 버그바운티 작업공간 (30+ 미션)
│   └── <target>/
│       └── triage_objections/   # Gate 2 트리아저 반론 기록
├── web/                     # FastAPI + D3 대시보드 (독립 + Docker)
│   ├── app.py               #   REST API + WebSocket 백엔드
│   └── static/index.html    #   싱글페이지 대시보드 (5탭)
├── tests/                   # CTF 파일 + E2E 리플레이 벤치마크
├── CLAUDE.md                # 오케스트레이터 지침 (v12)
├── terminator.sh            # 자율 모드 런처
├── docker-compose.yml       # 전체 스택 인프라
└── README.md
```

</details>

---

## 보안 및 윤리

이 시스템은 **인가된** 보안 작업 전용으로 설계되었습니다:

- **CTF / Wargame** -- 보안 학습을 위한 연습 환경
- **버그바운티 프로그램** -- 명시적 인가가 있는 타겟만
- **보안 연구** -- 적절한 범위가 있는 제어된 환경

모든 발견사항은 책임 있는 공개 관행을 준수합니다. 프롬프트 인젝션 가드레일이 분석 대상의 악의적 코드로부터 에이전트를 보호합니다.

---

<div align="center">

MIT License

<br>

[![Star History Chart](https://api.star-history.com/svg?repos=R00T-Kim/Terminator&type=Date)](https://star-history.com/#R00T-Kim/Terminator&Date)

</div>
