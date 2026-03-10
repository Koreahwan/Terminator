<div align="center">

<br>

<img src="https://img.shields.io/badge/TERMINATOR-Autonomous_Security_Agent-cc0000?style=for-the-badge&labelColor=1a1a1a" alt="Terminator">

<br><br>

**CTF 자동 풀이 및 버그바운티 취약점 탐색을 수행하는 멀티에이전트 AI 보안 시스템**

Claude Code-native 코어 + Codex/OMX + Gemini coordination 기반 — 22개 전문 에이전트, 공유 `coordination/` 상태, digest-first 컨텍스트 압축을 함께 사용

<br>

[![Claude Code](https://img.shields.io/badge/Claude_Code-Agent_Teams-7C3AED?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQyIDAtOC0zLjU4LTgtOHMzLjU4LTggOC04IDggMy41OCA4IDgtMy41OCA0LTggNHoiLz48L3N2Zz4=)](https://docs.anthropic.com/en/docs/claude-code)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Solidity](https://img.shields.io/badge/Solidity-Foundry-363636?style=flat-square&logo=solidity&logoColor=white)](https://book.getfoundry.sh/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)

<br>

| CTF 풀이 | 버그바운티 타겟 | AI 에이전트 | MCP 서버 | 파이프라인 스킬 | 지식 문서 | 보안 도구 |
|:--------:|:-------------:|:----------:|:--------:|:-------------:|:---------:|:--------:|
| **20** | **30+** | **22** | **12** | **8** | **265K+** | **40+** |

<br>

[English](README.md) | **한국어**

</div>

---

## 데모

```
사용자: "pwnable.kr fd 풀어줘. SSH: fd@pwnable.kr -p2222 (pw: guest)"

Terminator:
  -> @reverser 스폰  -> 바이너리 분석, 공격 지도 생성
  -> @chain 스폰     -> 공격 지도 기반 익스플로잇 조립
  -> @critic 스폰    -> gdb/r2로 오프셋 교차 검증
  -> @verifier 스폰  -> 로컬 3회 실행 후 원격 실행
  -> FLAG_FOUND: mama, are you prout of me?
```

```
사용자: "이뮤니파이에서 하이~크리티컬 취약점 찾을때까지 ㄱㄱ"

Terminator:
  -> @target-evaluator 스폰  -> ROI 점수화, GO 판정
  -> @scout + @analyst 스폰  -> 병렬 정찰 + CVE 매칭
  -> @exploiter 스폰         -> 작동하는 PoC 개발
  -> @critic 스폰            -> 보고서 팩트체크
  -> @triager-sim 스폰       -> 제출 전 보고서 공격
  -> SUBMIT: CWE-306 ATO chain, CVSS 7.4 High
```

---

## 작동 원리

Terminator는 단일 모델 프롬프트가 아닙니다. **22개 AI 에이전트**가 오케스트레이터를 통해 순차 파이프라인으로 조율되는 팀입니다.

- **적응형 파이프라인 선택** -- 오케스트레이터가 챌린지 유형(pwn, reversing, web, firmware, smart contract)에 따라 적절한 에이전트 시퀀스를 선택
- **구조화된 핸드오프** -- 각 에이전트가 타입이 지정된 산출물(공격 지도, 트리거 보고서, 익스플로잇 스크립트)을 생성하여 다음 단계에 전달
- **검증 우선** -- 모든 익스플로잇은 원격 실행 전 로컬 3회 테스트; 모든 버그바운티 보고서는 작동하는 PoC 필수
- **환각 방지** -- 전용 critic 에이전트가 독립적 도구 실행(gdb, r2)으로 모든 주소, 오프셋, 상수를 교차 검증
- **크래시 복구** -- 체크포인트 프로토콜로 컨텍스트 압축 후에도 정확한 실패 지점부터 재개 가능
- **자동 품질 게이트** -- 6개 파이프라인 스킬(v6)이 OOS finding, 약한 PoC, 비현실적 위협 모델, AI 템플릿 언어를 제출 전 자동 차단

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
        │   CTF Pipeline   │                  │  Bug Bounty v6   │
        │   (Sequential)   │                  │   (7 Phases)     │
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
          │ 12 MCP   │Knowledge │ Dashboard │ 40+      │ Anti-       │
          │ Servers  │ DB 265K+ │ (Web UI)  │ Tools    │ Hallucinate │
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
- gdb + pwndbg 또는 GEF, radare2
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
./terminator.sh ctf /path/to/challenge.zip     # CTF
./terminator.sh bounty https://target.com       # 버그바운티
./terminator.sh status                          # 모니터
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

### 버그바운티 -- v6 파이프라인

> [!IMPORTANT]
> **철칙**: Exploit 없으면, Report 없음. 작동하는 PoC 없는 발견사항은 자동 폐기.

<details>
<summary><b>7단계 파이프라인 상세</b></summary>

```
Phase 0   @target-evaluator     GO / NO-GO 평가 + Hard NO-GO 규칙 (v6)
          oos-check skill       OOS 패턴 사전 스크리닝 (12개 패턴)
          --- GO gate --------------------------------------------------------
Phase 0.2 bb_preflight.py       프로그램 규칙 생성 + 검증 (MANDATORY)
Phase 0.5 @scout                자동화 도구 스캔 (Slither, Semgrep, Mythril)
Phase 1   @scout + @analyst     병렬 정찰 + finding별 OOS 교차 체크
          coverage-gate skill   80%+ 엔드포인트 커버리지 필수
Phase 1.5 @analyst (N 병렬)    OWASP 카테고리별 병렬 헌팅 (대형 코드베이스 전용)
Phase 2   @exploiter            PoC 개발 + poc-tier skill (Tier 1-2만 통과)
          threat-model-check    공격 전제조건 현실성 검증
Phase 3   @reporter             보고서 초안 + CVSS 계산
Phase 4   @critic + @architect  2라운드 리뷰: 팩트체크 -> 프레이밍 -> 증거 충실도
Phase 4.5 @triager-sim          적대적 트리아저 + JSON 피드백 루프 (최대 3회)
          slop-check skill      AI 슬롭 점수 (<=2 PASS, 3-5 STRENGTHEN, >5 KILL)
Phase 5   @reporter             최종 보고서 + ZIP 패키징
Phase 6   TeamDelete            정리
```

**6개 자동 파이프라인 스킬 (v6 NEW):**

| 스킬 | 게이트 | 차단 조건 |
|:-----|:-------|:----------|
| `oos-check` | Phase 0 + finding별 | OOS 패턴 (oracle staleness, admin-gated 등) |
| `coverage-gate` | Phase 1->2 | 엔드포인트 커버리지 <80% (소규모는 100%) |
| `poc-tier` | Phase 2->3 | Tier 3-4 PoC (실행 캡처 없음) |
| `threat-model-check` | Phase 2 | 비현실적 공격 전제조건 (2개+ 제어 필요) |
| `slop-check` | Phase 4.5 | AI 템플릿 언어 점수 >5 |
| `checkpoint-validate` | 모든 단계 | Fake idle / fake completion 탐지 |

**추가 품질 게이트:**
- Phase 0 Hard NO-GO: 3+ audits, 2+ reputable audits, 100+ reports, 3년+, 소스 비공개
- Phase 0.2 프로그램 규칙 검증 통과 필수 (에이전트 스폰 전)
- Phase 4.5 triager-sim이 구조화된 JSON 출력 → reporter 자동 피드백 루프

</details>

---

## 에이전트

22개 전문 에이전트가 `.claude/agents/`에 정의 (~8,100줄, 레퍼런스 문서 포함).

<details>
<summary><b>CTF 에이전트 (8개)</b></summary>

| 에이전트 | 역할 | 모델 | 출력 |
|:---------|:-----|:----:|:-----|
| **reverser** | 바이너리 분석, 보호 기법 탐지, 공격 표면 매핑 | Sonnet | `reversal_map.md` |
| **trigger** | 크래시 탐색, 입력 최소화, 프리미티브 식별 | Sonnet | `trigger_report.md` |
| **solver** | reversing/crypto 챌린지용 역연산 | Opus | `solve.py` |
| **chain** | 다단계 익스플로잇: leak -> overwrite -> shell | Opus | `solve.py` |
| **critic** | Security Council 심의 (5 아키타입) + 교차 검증 | Opus | `critic_review.md` |
| **verifier** | 로컬 3회 재현 -> 원격 실행 | Sonnet | `FLAG_FOUND` |
| **reporter** | 실패한 시도 및 기법 포함 라이트업 | Sonnet | `knowledge/challenges/<name>.md` |
| **ctf-solver** | Trivial 챌린지용 레거시 단일 에이전트 | Sonnet | `solve.py` |

</details>

<details>
<summary><b>버그바운티 에이전트 (7개)</b></summary>

| 에이전트 | 역할 | 모델 | 출력 |
|:---------|:-----|:----:|:-----|
| **target-evaluator** | 프로그램 ROI 점수화, GO/NO-GO 판정 | Sonnet | `target_assessment.md` |
| **scout** | 정찰 + 중복 사전검증 + 자동화 도구 스캔 | Sonnet | `recon_report.json` |
| **analyst** | CVE 매칭, source->sink 추적, 신뢰도 점수화 | Sonnet | `vulnerability_candidates.md` |
| **exploiter** | PoC 개발, 품질 등급 분류 | Opus | PoC 스크립트 + 증거 |
| **triager-sim** | 적대적 트리아저 -- 제출 전 보고서 공격 | Opus | SUBMIT / STRENGTHEN / KILL |
| **source-auditor** | 소스코드 심층 감사, 크로스파일 taint 분석 | Opus | `audit_findings.md` |
| **defi-auditor** | 스마트 컨트랙트 분석, DeFi 특화 취약점 패턴 | Opus | `defi_audit.md` |

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

---

## 지식 엔진

**265K+ 보안 문서**를 SQLite FTS5 + BM25 랭킹으로 인덱싱한 통합 검색 시스템. 외부 의존성 없음.

| 소스 | 문서 수 | 내용 |
|:-----|--------:|:-----|
| 내부 기법 | 81 | 공격 패턴, CTF 라이트업 |
| 외부 레포 (42개) | 29,565 | HackTricks, GTFOBins, PayloadsAllTheThings, how2heap, OWASP, SecLists, InternalAllTheThings + 35개 |
| ExploitDB | 46,960 | 익스플로잇 설명, 플랫폼, CVE |
| Nuclei 템플릿 | 14,871 | 심각도 포함 취약점 탐지 템플릿 |
| PoC-in-GitHub | 18,235 | CVE PoC 저장소 |
| trickest-cve | 155,121 | CVE 상세, 제품, CWE, PoC 링크 |

에이전트가 `knowledge-fts` MCP 서버를 통해 검색:

```python
technique_search("heap tcache poisoning")     # 상위 5개 기법 문서
exploit_search("apache struts rce")            # ExploitDB + nuclei + PoC
search_all("race condition double spend")      # 전체 265K 문서 랭킹
```

<details>
<summary><b>자동 재빌드 및 CLI</b></summary>

PostToolUse 훅이 `knowledge/techniques/` 또는 `knowledge/challenges/` 파일 변경 시 자동 재인덱싱. 전체 재빌드: ~4분. 증분 업데이트: 0.13초.

```bash
python tools/knowledge_indexer.py --rebuild    # 전체 재빌드
python tools/knowledge_indexer.py --search "reentrancy flash loan"
python tools/knowledge_indexer.py --stats
```

</details>

---

## 도구 체인

### MCP 서버 -- AI 네이티브 도구 통합

12개 MCP 서버가 에이전트에게 보안 도구 직접 접근 제공.
사용자 레벨 MCP가 추가로 보일 수 있으며, `pentest-thinking`이 unavailable이어도 핵심 Terminator 파이프라인은 계속 동작합니다.

<details>
<summary><b>전체 12개 MCP 서버</b></summary>

| 서버 | 기능 |
|:-----|:-----|
| **mcp-gdb** | 브레이크포인트, 메모리 검사, 스텝 실행, 백트레이스 |
| **radare2-mcp** | 디스어셈블리, 디컴파일, xrefs, 함수 분석 |
| **ghidra-mcp** | 헤드리스 디컴파일, 구조체/열거형 분석 |
| **frida-mcp** | 동적 계측, 후킹, 프로세스 스포닝 |
| **pentest-mcp** | nmap, gobuster, nikto, john, hashcat |
| **nuclei-mcp** | 12K+ 취약점 탐지 템플릿 스캔 |
| **codeql-mcp** | 시맨틱 taint tracking, 변종 분석 |
| **semgrep-mcp** | 패턴 기반 정적 분석 |
| **playwright** | 웹 익스플로잇용 브라우저 자동화 |
| **context7** | 최신 라이브러리 문서 조회 |
| **graphrag-security** | 보안 지식 그래프: 익스플로잇 검색, 유사 발견사항, 드리프트 감지 |
| **knowledge-fts** | 265K+ 문서 BM25 전문 검색 -- 기법, ExploitDB, nuclei, PoC, trickest-cve |

</details>

<details>
<summary><b>보안 도구 (40+)</b></summary>

**리버스 엔지니어링 및 익스플로잇 개발**
- 디스어셈블리: radare2, objdump, strings, readelf, nm
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
│   ├── agents/              # 22개 에이전트 정의 (~8,100줄)
│   │   ├── reverser.md      #   바이너리 분석
│   │   ├── chain.md         #   익스플로잇 체인 조립
│   │   ├── critic.md        #   교차 검증 + Security Council
│   │   ├── target_evaluator.md  # GO/NO-GO + Hard NO-GO 규칙
│   │   ├── triager_sim.md   #   적대적 트리아저 + JSON 피드백
│   │   ├── fw_*.md          #   펌웨어 분석 (4개 에이전트)
│   │   ├── _reference/      #   공유 레퍼런스 문서 (명령어, 패턴, 도구)
│   │   └── ...              #   + 16개 전문가 에이전트
│   └── skills/              # 8개 파이프라인 스킬 (v6 NEW)
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
│   ├── knowledge.db         #   FTS5 검색 DB (265K 문서, ~338MB)
│   ├── challenges/          #   챌린지별 라이트업
│   └── techniques/          #   재사용 가능한 공격 기법 + 경쟁 분석
├── research/                # LLM 보안 프레임워크 분석 (14개 문서)
├── tools/                   # 파이프라인 도구
│   ├── bb_preflight.py      #   파이프라인 게이트 검증 (규칙, 커버리지, --json)
│   ├── knowledge_indexer.py #   FTS5 DB 빌더 (6 테이블, 제로 의존성)
│   ├── web_chain_engine.py  #   Web 익스플로잇 체인 엔진 (10 규칙)
│   ├── flag_detector.py     #   CTF 플래그 패턴 탐지 (8+ 포맷)
│   ├── validation_prompts.py#   환각 방지 프롬프트 라이브러리
│   ├── mitre_mapper.py      #   CVE->CWE->CAPEC->ATT&CK (36 CWEs)
│   ├── attack_graph/        #   Neo4j + 파일시스템 공격 표면 그래프
│   ├── dag_orchestrator/    #   DAG 파이프라인 스케줄링 + Claude CLI 핸들러
│   ├── sarif_generator.py   #   SARIF 2.1.0 출력
│   └── mcp-servers/         #   nuclei, codeql, semgrep, knowledge-fts, graphrag
├── web/                     # FastAPI + D3 대시보드 (독립 + Docker)
│   ├── app.py               #   REST API + WebSocket 백엔드
│   └── static/index.html    #   싱글페이지 대시보드 (5탭)
├── targets/                 # 버그바운티 작업공간 (30+ 미션)
├── tests/                   # CTF 파일 + E2E 리플레이 벤치마크
├── CLAUDE.md                # 오케스트레이터 지침 (v6)
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
