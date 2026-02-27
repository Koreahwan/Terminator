<div align="center">

<br>

<img src="https://img.shields.io/badge/TERMINATOR-Autonomous_Security_Agent-cc0000?style=for-the-badge&labelColor=1a1a1a" alt="Terminator">

<br><br>

**CTF 자동 풀이 및 버그바운티 취약점 탐색을 수행하는 멀티에이전트 AI 보안 시스템**

[Claude Code Agent Teams](https://docs.anthropic.com/en/docs/claude-code) 기반 — 17개 전문 에이전트를 구조화된 파이프라인으로 조율

<br>

[![Claude Code](https://img.shields.io/badge/Claude_Code-Agent_Teams-7C3AED?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQyIDAtOC0zLjU4LTgtOHMzLjU4LTggOC04IDggMy41OCA4IDgtMy41OCA0LTggNHoiLz48L3N2Zz4=)](https://docs.anthropic.com/en/docs/claude-code)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Solidity](https://img.shields.io/badge/Solidity-Foundry-363636?style=flat-square&logo=solidity&logoColor=white)](https://book.getfoundry.sh/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)

<br>

| CTF 풀이 | 버그바운티 타겟 | AI 에이전트 | MCP 서버 | 지식 문서 | 보안 도구 |
|:--------:|:-------------:|:----------:|:--------:|:---------:|:--------:|
| **20** | **30+** | **17** | **12** | **242K+** | **40+** |

<br>

[English](README.md) | **한국어**

</div>

---

## 무엇을 하는가

Terminator는 단순히 취약점을 찾는 것이 아닙니다 — **검증**합니다.

- 모든 CTF 익스플로잇은 원격 실행 전 **로컬 3회 테스트**
- 모든 버그바운티 발견사항은 보고서 생성 전 **작동하는 PoC 필수**
- 모든 보고서는 제출 전 **적대적 트리아저 시뮬레이션** 통과 필수

```
사용자: "pwnable.kr fd 풀어줘. SSH: fd@pwnable.kr -p2222 (pw: guest)"

Terminator:
  → @reverser 스폰  → 바이너리 분석, 공격 지도 생성
  → @chain 스폰     → 공격 지도 기반 익스플로잇 조립
  → @critic 스폰    → gdb/r2로 오프셋 교차 검증
  → @verifier 스폰  → 로컬 3회 실행 후 원격 실행
  → FLAG_FOUND: mama, are you prout of me?
```

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
        │   CTF Pipeline   │                  │  Bug Bounty v3   │
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

          ┌──────────────────────────────────────────────┐
          │              인프라 레이어                      │
          ├──────────┬───────────┬──────────┬────────────┤
          │ 12 MCP   │ Dashboard │ 40+      │ Knowledge  │
          │ Servers  │ (Web UI)  │ Tools    │ DB (242K+) │
          └──────────┴───────────┴──────────┴────────────┘
```

### 구조화된 핸드오프

에이전트들은 구조화된 산출물 전달을 통해 통신합니다 — 단계 간 컨텍스트 손실 없음:

```
[HANDOFF from @reverser to @chain]
- Artifact: reversal_map.md
- Confidence: PASS
- Key Result: read_input()에서 BOF, 64바이트 오버플로우, canary 비활성
- Next Action: system("/bin/sh") 대상 leak + ROP 체인 구축
```

---

## 파이프라인

### CTF — 적응형 파이프라인 선택

| 조건 | 파이프라인 | 에이전트 수 |
|:-----|:-----------|:-----------:|
| **Trivial** — 소스 제공, 1-3줄 버그, one-liner exploit | 직접 풀이 | 0 |
| **Reversing / Crypto** — 수학적 역연산 필요 | `reverser → solver → critic → verifier → reporter` | 5 |
| **Pwn (명확한 취약점)** — 명백한 오버플로우/포맷 스트링 | `reverser → chain → critic → verifier → reporter` | 5 |
| **Pwn (불명확한 취약점)** — 크래시 탐색 필요 | `reverser → trigger → chain → critic → verifier → reporter` | 6 |
| **Web** — 인젝션, SSRF, 인증 우회 | `scout → analyst → exploiter → reporter` | 4 |
| **Firmware** — ARM 바이너리 diff, 에뮬레이션 PoC | `fw_profiler → fw_inventory → fw_surface → fw_validator → reporter` | 5 |

### 버그바운티 — v3 파이프라인 (7단계)

```
Phase 0   @target_evaluator     GO / NO-GO 평가 (ROI, 경쟁도, 기술스택)
          ─── GO gate ────────────────────────────────────────────────
Phase 0.5 @scout                자동화 도구 스캔 (Slither, Semgrep, Mythril)
Phase 1   @scout + @analyst     병렬 정찰 + 중복 사전검증 + CVE 매칭
Phase 1.5 @analyst (N 병렬)    OWASP 카테고리별 병렬 헌팅 (대형 코드베이스 전용)
Phase 2   @exploiter            PoC 개발 + 품질 등급 게이트 (Tier 1-2만 통과)
Phase 3   @reporter             보고서 초안 + CVSS 계산
Phase 4   @critic + @architect  2라운드 리뷰: 팩트체크 → 프레이밍
Phase 4.5 @triager_sim          적대적 트리아저 (SUBMIT / STRENGTHEN / KILL)
Phase 5   @reporter             최종 보고서 + ZIP 패키징
Phase 6   TeamDelete            정리
```

> **철칙**: Exploit 없으면, Report 없음. 작동하는 PoC 없는 발견사항은 자동 폐기.

---

## 에이전트

### CTF 에이전트

| 에이전트 | 역할 | 모델 | 출력 |
|:---------|:-----|:----:|:-----|
| **reverser** | 바이너리 분석, 보호 기법 탐지, 공격 표면 매핑 | Sonnet | `reversal_map.md` |
| **trigger** | 크래시 탐색, 입력 최소화, 프리미티브 식별 | Sonnet | `trigger_report.md` |
| **solver** | reversing/crypto 챌린지용 역연산 | Opus | `solve.py` |
| **chain** | 다단계 익스플로잇: leak → overwrite → shell | Opus | `solve.py` |
| **critic** | 오프셋, 상수, 로직 교차 검증 | Opus | `critic_review.md` |
| **verifier** | 로컬 3회 재현 → 원격 실행 | Sonnet | `FLAG_FOUND` |
| **reporter** | 실패한 시도 및 기법 포함 라이트업 | Sonnet | `knowledge/challenges/<name>.md` |

### 버그바운티 에이전트

| 에이전트 | 역할 | 모델 | 출력 |
|:---------|:-----|:----:|:-----|
| **target_evaluator** | 프로그램 ROI 점수화, GO/NO-GO 판정 | Sonnet | `target_assessment.md` |
| **scout** | 정찰 + 중복 사전검증 + 자동화 도구 스캔 | Sonnet | `recon_report.json` |
| **analyst** | CVE 매칭, source→sink 추적, 신뢰도 점수화 | Sonnet | `vulnerability_candidates.md` |
| **exploiter** | PoC 개발, 품질 등급 분류 | Opus | PoC 스크립트 + 증거 |
| **triager_sim** | 적대적 트리아저 — 제출 전 보고서 공격 | Opus | SUBMIT / STRENGTHEN / KILL |

### 펌웨어 에이전트

| 에이전트 | 역할 | 모델 | 출력 |
|:---------|:-----|:----:|:-----|
| **fw_profiler** | 펌웨어 이미지 프로파일링, 아키텍처 탐지 | Sonnet | `firmware_profile.md` |
| **fw_inventory** | 바이너리 인벤토리, 버전 추출, CVE 매칭 | Sonnet | `firmware_inventory.md` |
| **fw_surface** | 공격 표면 매핑, 바이너리 diff 분석 | Sonnet | `attack_surface.md` |
| **fw_validator** | QEMU 에뮬레이션, 동적 PoC 검증 | Sonnet | `validation_results.md` |

### 에이전트 복원력 (Checkpoint Protocol)

모든 작업 에이전트는 크래시/컴팩션 복구를 위한 **체크포인트 프로토콜**을 구현합니다:

| 메커니즘 | 목적 | 방법 |
|:---------|:-----|:-----|
| **checkpoint.json** | 컴팩션 시 상태 보존 | 에이전트가 Phase 전환마다 상태/완료항목/핵심정보를 JSON으로 기록 |
| **Fake Idle 감지** | 중간에 멈춘 에이전트 탐지 | Orchestrator가 `checkpoint.status` 확인 — `"in_progress"` + idle = fake idle, 컨텍스트 포함 재스폰 |
| **재스폰 시 이어서** | 중복 작업 방지 | 새 에이전트가 기존 checkpoint.json 읽고 완료된 단계 건너뜀 |
| **에러 보고** | 환경 블로커 | `checkpoint.status: "error"` + 설명 — Orchestrator가 해결 후 재스폰 |

**핵심 규칙**: "산출물 파일 있음 = 완료"로 판단하지 마라. `checkpoint.status == "completed"`만 신뢰.

---

## 대시보드

모든 작업을 모니터링하는 실시간 웹 UI — 외부 의존성 없이 **독립 모드**로 실행 가능.

```
┌──────────────────────────────────────────────────────────────────┐
│  TERMINATOR                                        ● WebSocket  │
├──────────┬──────────────┬──────────────┬──────────┬─────────────┤
│ CTF      │ Bug Bounty   │ Infra-       │ Findings │ Attack      │
│ Sessions │ Missions     │ structure    │          │ Graph       │
├──────────┴──────────────┴──────────────┴──────────┴─────────────┤
│                                                                  │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
│  │ 20      │  │ 30+     │  │ 114+    │  │ 16      │           │
│  │ FLAGS   │  │ TARGETS │  │ FINDINGS│  │ TOOLS   │           │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘           │
│                                                                  │
│  심각도 분포              도구 상태           라이브 로그         │
│  ████ CRITICAL  12         ● Radare2    up     [session.log     │
│  ██████ HIGH    18         ● GDB        up      tail -f ...]    │
│  ████████ MED   34         ● Nuclei     up                      │
│  ██ LOW         8          ● Slither    up                      │
│  █ INFO         42         ● CodeQL     up                      │
│                            ● Foundry    up                      │
│  D3 Force-Directed 공격 그래프                                   │
│  ┌──────────────────────────────────────────────────┐           │
│  │  (target) ──→ (finding) ──→ (technique)          │           │
│  │     ↓             ↓              ↓               │           │
│  │  (service)    (exploit)     (report)             │           │
│  └──────────────────────────────────────────────────┘           │
└──────────────────────────────────────────────────────────────────┘
```

### 5개 탭

| 탭 | 데이터 소스 | 기능 |
|:---|:-----------|:-----|
| **CTF Sessions** | `reports/` 디렉토리 | 세션 목록, 플래그, 라이트업, WebSocket 라이브 로그 |
| **Bug Bounty Missions** | `targets/` 디렉토리 | 파이프라인 단계 추적, GO/NO-GO 상태, 미션별 발견사항 |
| **Infrastructure** | 시스템 + Docker | 16+ 도구 상태, Docker 서비스 상태, RAG 통계 |
| **Findings** | 파일시스템 + DB | CVSS 자동 추출 통합 발견사항, 심각도 분포 |
| **Attack Graph** | Neo4j 또는 파일시스템 | D3 force-directed 그래프 — 타겟, 발견사항, 기법, 서비스 |

---

## 지식 검색 엔진

242K+ 보안 문서를 SQLite FTS5 + BM25 랭킹으로 인덱싱한 통합 검색 시스템.

### 인덱싱 소스

| 테이블 | 소스 | 문서 수 |
|:-------|:-----|--------:|
| `techniques` | `knowledge/techniques/` + `knowledge/challenges/` | 37+ |
| `external_techniques` | PayloadsAllTheThings, HackTricks, how2heap, GTFOBins, CTF-All-In-One 등 | 15K+ |
| `exploitdb` | ExploitDB (searchsploit) | 47K+ |
| `nuclei` | Nuclei 탐지 템플릿 | 12K+ |
| `poc_github` | PoC-in-GitHub CVE PoC 저장소 | 8K+ |

### 기능

- **FTS5 전문 검색** — porter stemming + ASCII 토크나이저로 한/영 검색
- **BM25 랭킹** — 쿼리 관련성 기반 자동 정렬
- **MCP 서버 통합** — `knowledge-fts` MCP로 에이전트가 직접 검색 가능
- **자동 재빌드** — `tools/knowledge_indexer.py` 실행으로 전체 DB 갱신
- **제로 의존성** — Python 3.12 표준 라이브러리(sqlite3)만 사용

```bash
# 인덱스 빌드 (최초 1회)
python tools/knowledge_indexer.py --rebuild

# 검색 테스트
python tools/knowledge_indexer.py --search "reentrancy flash loan"

# 통계 확인
python tools/knowledge_indexer.py --stats
```

---

## 도구 체인

### MCP 서버 — AI 네이티브 도구 통합

12개 MCP 서버가 에이전트에게 보안 도구 직접 접근 제공:

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
| **graphrag-security** | GraphRAG 보안 지식 그래프 — exploit 검색, 지식 수집, 유사 발견사항 |
| **knowledge-fts** | 242K+ 문서 BM25 전문 검색 — exploit/기법/챌린지 통합 검색 |
| **playwright** | 웹 익스플로잇용 브라우저 자동화 |
| **context7** | 최신 라이브러리 문서 조회 |

### 보안 도구

<details>
<summary><b>리버스 엔지니어링 및 익스플로잇 개발</b></summary>

| 카테고리 | 도구 |
|:---------|:-----|
| 디스어셈블리 | radare2, objdump, strings, readelf, nm |
| 디컴파일 | Ghidra (MCP), jadx |
| 디버깅 | gdb + pwndbg + GEF (93 commands), strace |
| 심볼릭 실행 | angr, unicorn, z3-solver, keystone |
| 익스플로잇 | pwntools, ROPgadget, ropper, one_gadget |
| 암호 | pycryptodome, sympy, z3-solver |

</details>

<details>
<summary><b>웹 보안</b></summary>

| 카테고리 | 도구 |
|:---------|:-----|
| 인젝션 | sqlmap, commix, dalfox (XSS) |
| SSRF | SSRFmap (18+ 모듈) |
| 정찰 | ffuf, subfinder, katana, httpx, gau, waybackurls, arjun |
| 스캔 | nuclei (12K+ 템플릿), trufflehog (800+ 시크릿 타입) |
| 업로드 | fuxploider |

</details>

<details>
<summary><b>코드 분석 및 스마트 컨트랙트</b></summary>

| 카테고리 | 도구 |
|:---------|:-----|
| 시맨틱 | CodeQL (taint tracking, variant analysis) |
| 정적 | Semgrep (커스텀 룰 작성) |
| 스마트 컨트랙트 | Slither (100+ detectors), Mythril (EVM symbolic), Foundry 1.5.1 |
| AI | Gemini CLI (gemini-3-pro-preview) |

</details>

<details>
<summary><b>펌웨어 분석</b></summary>

| 카테고리 | 도구 |
|:---------|:-----|
| 에뮬레이션 | QEMU ARM user-mode, rootfs 마운팅 |
| Diff | 펌웨어 버전간 바이너리 diff |
| 프로파일링 | 아키텍처 탐지, 라이브러리 인벤토리 |
| 검증 | 에뮬레이션 환경 동적 PoC |

</details>

<details>
<summary><b>참조 데이터베이스</b></summary>

| 데이터베이스 | 범위 |
|:------------|:-----|
| ExploitDB | 47K+ exploits |
| PoC-in-GitHub | 8K+ CVE PoCs |
| PayloadsAllTheThings | 70+ 취약점 카테고리 |
| trickest-cve | 154K+ CVE PoCs |
| SecLists | 워드리스트, 패스워드, 디스커버리 |
| protocol-vulns-index | 460 카테고리 x 31 프로토콜 타입 |

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

## 인프라

### 독립 모드 (기본값)

Docker 불필요. 대시보드가 파일시스템에서 직접 읽음:

| 소스 | 읽는 내용 |
|:-----|:----------|
| `targets/` | 30+ 미션 디렉토리 — 평가, 발견사항, 보고서 |
| `reports/` | CTF 세션 로그, 플래그, 라이트업 |
| `~/.claude/teams/` | 에이전트 팀 설정 — 실행 이력 |
| 시스템 `$PATH` | `shutil.which()`로 16개 보안 도구 자동 탐지 |

마크다운 보고서에서 CVSS를 자동 추출하여 **114+ 발견사항**을 통합. 취약점 후보, 정찰 데이터, 보고서 파일로 D3 호환 공격 그래프를 생성 — Neo4j 불필요.

### 전체 스택 모드 (선택사항)

```bash
docker compose up -d
```

| 서비스 | 포트 | 용도 |
|:-------|:----:|:-----|
| **pgvector** | 5433 | RAG 벡터 데이터베이스 |
| **ollama** | 11434 | 로컬 임베딩 모델 |
| **rag-api** | 8100 | ExploitDB/PoC 지식 검색 |
| **neo4j** | 7474 | 공격 표면 그래프 데이터베이스 |
| **litellm** | 4000 | 멀티 모델 프록시 (Claude/Gemini/DeepSeek) |
| **web-ui** | 3000 | 전체 DB 지원 대시보드 |

### 파이프라인 도구

| 도구 | 용도 |
|:-----|:-----|
| **MITRE Mapper** | CVE → CWE → CAPEC → ATT&CK 매핑 (27 CWEs) |
| **Attack Graph** | Neo4j 또는 파일시스템 기반 공격 표면 시각화 |
| **DAG Orchestrator** | 파이프라인 스케줄링 (CTF pwn/rev, bounty, firmware) |
| **Pipeline Controller** | 결정적 DAG→에이전트 실행을 위한 Claude CLI 핸들러 |
| **Knowledge Indexer** | SQLite FTS5 + BM25 — 242K+ 문서 인덱싱/검색 |
| **Web Chain Engine** | Web 취약점 체인 자동 탐색 엔진 |
| **E2E Replay Benchmark** | solve.py 자동 재실행으로 리그레션 감지 |
| **Recon Pipeline** | 6-phase 자동화 정찰 |
| **SARIF Generator** | GitHub Code Scanning 호환 출력 |
| **PDF Generator** | 보고서 PDF 생성 |

---

## 경쟁 프레임워크 패턴 채택

선도적 AI 보안 프레임워크에서 5가지 P0(최우선) 패턴을 채택:

| 채택 패턴 | 출처 | 적용 방식 |
|:----------|:-----|:----------|
| **Anti-Hallucination 6-Point Checklist** | XBOW, Shannon | critic/verifier에 구조화된 검증 체크리스트 통합 |
| **Web Vulnerability Chain Engine** | Vulnhuntr | scout→analyst 파이프라인에 자동 체인 탐색 추가 |
| **Protocol Vulnerability Index** | Internal Research | 460 카테고리 x 31 프로토콜 취약점 패턴 DB 구축 |
| **Knowledge DB Auto-Rebuild** | ATLANTIS | FTS5 인덱서 자동 재빌드로 지식 최신 상태 유지 |
| **Context Preservation Protocol** | RoboDuck | 컨텍스트 compact 시 핵심 상태를 파일에 자동 저장 |

### Anti-Hallucination 시스템

에이전트 환각(hallucination)을 방지하기 위한 6단계 검증 체크리스트:

```
1. [주소 검증] r2/GDB에서 주소/오프셋을 독립 확인했는가?
2. [상수 검증] 하드코딩된 상수가 실제 바이너리와 일치하는가?
3. [보호 기법] checksec 결과와 reversal_map이 일치하는가?
4. [로직 검증] 익스플로잇 체인의 각 단계가 논리적으로 연결되는가?
5. [재현성] 로컬에서 3회 연속 성공하는가?
6. [환경 차이] 로컬과 원격의 libc/ASLR/환경 차이를 고려했는가?
```

이 체크리스트는 critic 에이전트가 APPROVED/REJECTED 판정 전 반드시 수행하며, 1개라도 실패하면 자동 REJECTED.

---

## 실적

### CTF 챌린지 — 20문제 풀이

| 카테고리 | 수 | 사용 기법 |
|:---------|:--:|:----------|
| Pwn (heap, stack, ROP) | 10 | pwntools, ROP chains, GOT overwrite, shellcode |
| Reversing (VM, 난독화) | 6 | GDB Oracle, DFA 추출, z3, 커스텀 VM 분석 |
| Crypto | 2 | AES-ECB, z3 제약 조건 풀이 |
| Misc (로직, 필터 우회) | 2 | 연산자 우선순위, 이진 탐색 |

### 버그바운티 — 30+ 타겟 평가

| 지표 | 수치 |
|:-----|-----:|
| 평가한 프로그램 | 30+ |
| 플랫폼 | Immunefi, HackerOne, Bugcrowd |
| 카테고리 | Smart Contract (DeFi), Web App, VPN, IoT/Firmware, AI/SDK |
| 분석한 스마트 컨트랙트 | 50+ |
| 조사한 취약점 리드 | 100+ |
| 작동하는 PoC 보유 발견사항 | 15+ |

> 구체적인 타겟과 발견사항은 공개 완료 전까지 비공개 유지.

---

## 연구 기반

에이전트 정의는 10+ 외부 LLM 보안 프레임워크의 패턴을 통합:

| 패턴 | 출처 |
|:-----|:-----|
| Variant Analysis — CVE 패치 diff를 시드로 활용 | Google Big Sleep (Project Zero + DeepMind) |
| LLM-first PoV Generation | RoboDuck (AIxCC 3위) |
| Symbolic + Neural Hybrid | ATLANTIS (AIxCC 1위) |
| No Exploit, No Report | Shannon, XBOW |
| Iterative Context Gathering — 3-pass 역추적 | Vulnhuntr |
| Dual-Approach Parallel — 3회 실패 후 2전략 병행 | RoboDuck |
| OWASP Parallel Hunters | Shannon |
| PoC Quality Tier Gate (1-4) | XBOW |
| Adversarial Triage Simulation | Internal |
| Prompt Injection Guardrails | CAI (300+ LLM agents) |
| Protocol Vulnerability Taxonomy (460 categories) | Internal Research |
| Anti-Hallucination Structured Checklist | XBOW, Shannon |
| Knowledge Auto-Rebuild Pipeline | ATLANTIS |
| Context Preservation on Compact | RoboDuck |

---

## 빠른 시작

### 사전 요구사항

- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) + Anthropic API 키
- Python 3.10+ (pwntools, z3-solver, angr)
- gdb + pwndbg 또는 GEF, radare2
- Docker (선택사항, 전체 인프라 스택용)

### 대화형 모드

```bash
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

# 전체 스택
docker compose up -d
# http://localhost:3000 접속
```

---

## 프로젝트 구조

```
Terminator/
├── .claude/agents/          # 17개 에이전트 정의 (~4,300줄)
│   ├── reverser.md          #   바이너리 분석
│   ├── chain.md             #   익스플로잇 체인 조립
│   ├── critic.md            #   교차 검증
│   ├── fw_*.md              #   펌웨어 분석 (4개 에이전트)
│   └── ...                  #   + 10개 전문가 에이전트
├── knowledge/               # 축적된 경험 (20 라이트업, 17 기법)
│   ├── index.md             #   마스터 인덱스
│   ├── knowledge.db         #   SQLite FTS5 검색 DB (242K+ 문서)
│   ├── knowledge_tree.json  #   지식 트리 구조
│   ├── challenges/          #   챌린지별 라이트업
│   ├── techniques/          #   재사용 가능한 공격 기법
│   └── protocol-vulns-index/#   460 카테고리 x 31 프로토콜 취약점 패턴
├── research/                # LLM 보안 프레임워크 분석 (14개 문서)
├── tools/                   # 파이프라인 도구
│   ├── knowledge_indexer.py #   SQLite FTS5 + BM25 인덱서
│   ├── web_chain_engine.py  #   Web 취약점 체인 엔진
│   ├── mitre_mapper.py      #   CVE→CWE→CAPEC→ATT&CK
│   ├── recon_pipeline.py    #   6-phase 정찰 오케스트레이터
│   ├── attack_graph/        #   Neo4j + 파일시스템 공격 표면 그래프
│   ├── dag_orchestrator/    #   DAG 파이프라인 스케줄링 + Claude CLI 핸들러
│   ├── sarif_generator.py   #   SARIF 2.1.0 출력
│   └── mcp-servers/         #   12개 MCP 서버
│       ├── nuclei-mcp/      #     Nuclei 취약점 스캔
│       ├── codeql-mcp/      #     CodeQL 시맨틱 분석
│       ├── semgrep-mcp/     #     Semgrep 정적 분석
│       ├── graphrag-mcp/    #     GraphRAG 보안 지식 그래프
│       └── knowledge-fts/   #     FTS5 전문 검색 MCP
├── web/                     # FastAPI + D3 대시보드 (독립 + Docker)
│   ├── app.py               #   REST API + WebSocket 백엔드 (1,255줄)
│   └── static/index.html    #   싱글페이지 대시보드 (5탭, 1,231줄)
├── targets/                 # 버그바운티 작업공간 (30+ 미션)
├── tests/                   # CTF 파일 + E2E 리플레이 벤치마크
├── CLAUDE.md                # 오케스트레이터 지침
├── terminator.sh            # 자율 모드 런처
├── docker-compose.yml       # 전체 스택 인프라
└── README.md
```

---

## 학습된 기법

지식 베이스에 축적된 재사용 가능한 패턴:

| 기법 | 설명 |
|:-----|:-----|
| **GDB Oracle Reverse** | 메모리 패치 + 실행 추적으로 커스텀 VM 비선형 함수 역산 |
| **z3 Protocol Simulation** | 전체 네트워크 프로토콜을 SMT 제약으로 모델링하여 정확한 솔루션 도출 |
| **SSH Interaction Patterns** | paramiko exec → nc pipe → SSH tunnel + pwntools (신뢰성 계층) |
| **Incremental Exploit Dev** | 단계별: leak → test → overflow → test → ROP → test → combine |
| **Dual-Approach Parallel** | 3회 실패 후, 다른 전략으로 2개 solver 동시 스폰 |
| **Constant Verification** | GDB 메모리 덤프로 항상 상수 검증 (정적 분석만으로는 off-by-one 발생) |
| **Trivial Detection** | 소스 < 50줄 + 1-3줄 버그 + one-liner exploit = 에이전트 팀 건너뛰기 |

---

## 최근 업데이트 (2026-02)

- **지식 검색 엔진** — SQLite FTS5 + BM25로 242K+ 보안 문서 통합 인덱싱 및 검색
- **MCP 서버 확장** — graphrag-security + knowledge-fts 추가 (총 12개)
- **경쟁 프레임워크 채택** — XBOW/Shannon/ATLANTIS/RoboDuck에서 5가지 P0 패턴 포팅
- **Anti-Hallucination 시스템** — 에이전트 환각 방지 6단계 검증 체크리스트
- **컨텍스트 보존** — compact 발생 시 핵심 분석 상태를 파일에 자동 저장
- **자동 재빌드** — knowledge_indexer.py로 지식 DB 원커맨드 갱신
- **프로토콜 취약점 인덱스** — 460 카테고리 x 31 프로토콜 타입 패턴 DB
- **Web 체인 엔진** — Web 취약점 자동 체인 탐색 도구
- **시크릿 환경변수화** — docker-compose.yml 자격증명이 `${VAR:-default}` 패턴 사용
- **결정적 파이프라인** — DAG 엔진이 `claude_handler.py`를 통해 Claude CLI에 연결
- **E2E 리플레이 벤치마크** — solve.py 자동 재실행으로 리그레션 감지
- **Heap 익스플로잇 프로토콜** — chain.md에 allocator fingerprinting, glibc 버전별 기법 추가

---

## 설계 결정

### 왜 순차 파이프라인인가? (병렬이 아닌)

보안 분석은 **컨텍스트 축적**이 필요합니다. reverser의 공격 지도는 익스플로잇 전략을 근본적으로 형성합니다. 모든 에이전트를 병렬로 실행하면 단절되고 종종 모순되는 결과가 생성됩니다. 구조화된 핸드오프가 있는 순차 파이프라인은 각 에이전트가 검증된 이전 작업을 기반으로 구축하도록 보장합니다.

### 왜 Critic 에이전트인가?

익스플로잇 개발은 오류가 발생하기 쉽습니다 — 잘못된 오프셋, 잘못된 상수, 결함 있는 로직. critic은 익스플로잇이 verifier에 도달하기 전에 도구(r2, gdb)를 사용하여 모든 주소와 계산을 독립적으로 검증합니다. 실패한 원격 시도로 시간을 낭비하는 오류를 사전에 포착합니다.

### 왜 적대적 트리아저 시뮬레이션인가?

버그바운티 보고서는 시간 압박 하에 회의적인 트리아저에 의해 평가됩니다. triager_sim 에이전트는 리뷰어 관점에서 보고서를 공격합니다 — 누락된 PoC, 중복 겹침, 약한 프레이밍, AI 생성 보일러플레이트를 확인 — 제출 전에. 이는 거절률을 줄입니다.

### 왜 에이전트별 모델 지정인가?

모든 에이전트가 가장 강력한 모델이 필요한 것은 아닙니다. Reverser와 verifier는 Sonnet으로 충분합니다 (패턴 매칭, 실행). Solver와 critic은 Opus가 필요합니다 (복잡한 추론, 수학적 증명). 명시적 모델 할당은 품질을 희생하지 않고 토큰을 절약합니다.

---

## 보안 및 윤리

이 시스템은 **인가된** 보안 작업 전용으로 설계되었습니다:

- **CTF / Wargame** — 보안 학습을 위한 연습 환경
- **버그바운티 프로그램** — 명시적 인가가 있는 타겟만
- **보안 연구** — 적절한 범위가 있는 제어된 환경

모든 발견사항은 책임 있는 공개 관행을 준수합니다. 프롬프트 인젝션 가드레일이 분석 대상의 악의적 코드로부터 에이전트를 보호합니다.

---

<div align="center">

MIT License

</div>
