# Offensive Security AI Frameworks — Comprehensive Analysis (2026-02-24)

## Executive Summary

2026년 현재 오픈소스 공격형 AI 보안 프레임워크는 10개 이상으로 분화되었으며, 크게 세 계열로 나뉜다. **벤치마크 검증형**(PentestGPT 86.5%, Shannon 96.15%, CAI 3600x): 실제 측정치가 있는 production-grade 시스템. **아키텍처 혁신형**(PentestAgent ShadowGraph, RedAmon Neo4j, PentAGI Graphiti/Neo4j): 그래프 기반 지식 표현과 멀티에이전트 조율이 강점. **도구 커버리지형**(CyberStrikeAI 100+ YAML, HexStrike 150+ wrappers, NeuroSploit 4-layer validation): 광범위한 도구 통합이 핵심.

Terminator는 CTF+Bug Bounty 듀얼 파이프라인, MCP RE 도구 체인(r2/gdb/ghidra), critic/triager 품질 게이트, 지식 누적 시스템에서 경쟁 우위를 가진다. 반면 그래프 기반 메모리, 자동 exploit chain 엔진, 토큰 예산 관리, WAF bypass, 연속 스캔 모드는 경쟁사 대비 미구현 상태다. P0 우선순위로 NeuroSploit chain engine 포팅과 Shannon exploit verification gate 도입이 가장 ROI가 높다.

상업 플랫폼(XBOW, Xint, Pentera, NodeZero)은 Production-safe exploit, N-day exploit 라이브러리, fix verification, 컴플라이언스 리포팅에서 오픈소스 전체를 앞선다. 이 영역은 단기 추격 대상이 아니다.

---

## Framework Comparison Matrix (오픈소스 10개)

| Name | Language | Agent Model | LLM | Tool Count | Memory | Exploit Verification | Benchmark | LOC | Best For |
|------|----------|------------|-----|-----------|--------|---------------------|-----------|-----|----------|
| **PentestGPT** | Python | Single agent | Claude Code SDK | Claude bash | None | Flag regex stream | 86.5% XBOW | ~1,400 | CTF |
| **Shannon** | TypeScript | 13 isolated agents | Claude SDK (native) | 6+2 MCP | Filesystem/git | Enforced gate (mandatory) | 96.15% XBOW | ~8,000 | Web BB |
| **CAI** | Python | Agent handoff | LiteLLM 300+ | Via LiteLLM | Phoenix tracing | HITL guardrails | 3600x human | N/A | CTF+BB |
| **PentestAgent** | Python | Multi-agent crew | LiteLLM (any) | Terminal+MCP | RAG + Shadow Graph | Notes schema validation | Not published | ~3,500 | BB recon |
| **NeuroSploit** | Python+React | 3-stream parallel | Multi-provider | Per-scan Kali Docker | Cross-scan history | 4-layer pipeline | Not published | ~15,000 | Web BB |
| **RedAmon** | Python+Next.js | LangGraph ReAct | Claude (default) | 4 MCP servers | Neo4j graph | Phase gate | Not published | ~12,000 | Recon+BB |
| **PentAGI** | Go+React | 3-tier Flow→Task→Subtask | langchaingo (8 providers) | 20++6 search | pgvector+Neo4j | None (LLM judgment) | Not published | ~25,000 | Enterprise |
| **CyberStrikeAI** | Go | Single ReAct loop | OpenAI-compat | 100+ YAML | SQLite+knowledge.db | Voluntary record_vuln | Not published | ~18,000 | Web scan |
| **HexStrike** | Python | Tool server (no LLM) | None (MCP client) | 150+ subprocess | None | None | Not published | ~22,000 | Tool layer |
| **Strix** | Python | Graph of agents | GPT-5/Claude/Gemini | Caido+Playwright | None | CI/CD gate | Not published | N/A | Web BB |

---

## Open-Source Frameworks (Detailed)

### Tier 1: Production-Grade (벤치마크 검증)

#### PentestGPT
**아키텍처**: `AgentController → ClaudeCodeBackend → claude` subprocess; 5-state enum (IDLE/RUNNING/PAUSED/COMPLETED/ERROR), asyncio.Event로 pause/resume. Claude Code SDK를 실행 엔진으로 직접 사용하는 유일한 프레임워크.

**Unique Feature**: `controller.inject(text)` — 실행 중 외부 명령 주입. 다음 안전 포인트에서 멈추고 인스트럭션 큐에 삽입 후 재개. Human-in-the-loop 교정에 최적.

**Adoptable Pattern for Terminator**:
- `_detect_flags()`: 모든 TextBlock을 regex로 스트리밍 검사. verifier 에이전트에 직접 포팅 → agent가 FLAG_FOUND 선언 전에 자동 감지
- CTF system prompt 구조(`pentesting.py` 174줄): 지속성 지시문, fallback 전략 트리, self-check 질문 — Terminator chain 에이전트 프롬프트에 즉시 적용 가능
- 5-state lifecycle + EventBus: Terminator 자율 모드의 상태 관리 패턴으로 채용

#### Shannon
**아키텍처**: Temporal.io 워크플로 엔진 기반, 13개 격리된 Claude 에이전트. 5개 `vuln→queue-check→exploit` 병렬 페어. git checkpoint로 workspace resume. 50회 재시도(5분→30분 지수 백오프), 13개 non-retryable 에러 타입으로 retry storm 방지.

**Unique Feature**: `ExploitationCheckerService` — mandatory exploit verification gate. 큐가 비어있으면 exploit 에이전트 자체를 건너뜀(비용 절감). Reporter는 `*_exploitation_evidence.md` 파일만 집계 → 이론적 finding 자동 제외. 프롬프트: *"An unproven vulnerability is worse than no finding at all."*

**Adoptable Pattern for Terminator**:
- `vuln→queue-check→exploit` 패턴: Bug Bounty exploiter 스폰 전 검증 큐 체크 단계 추가
- `prompts/exploit-injection.txt`, `exploit-xss.txt`, `exploit-auth.txt`, `exploit-ssrf.txt`, `exploit-authz.txt`: web exploiter 에이전트 전문화 프롬프트로 직접 이식 가능 (AGPL-3.0)
- `repeatingDetector` 상당 로직: chain/solver 에이전트의 무한 도구 호출 루프 감지
- Temporal.io: Terminator DAG 오케스트레이터 대체 후보

#### CAI (aliasrobotics/cai)
**아키텍처**: Agent-centric, modular, agent handoff mechanism. LiteLLM으로 300+ 모델 지원. Phoenix tracing으로 전체 실행 투명성.

**Unique Feature**: 3600x over human pentesters (CTF 벤치마크), Dragos OT CTF Top-10 진입. 실제 CVSS 4.3-7.5 취약점 발견 실적. HITL guardrails 체계화.

**Adoptable Pattern for Terminator**:
- LiteLLM 300+ 모델 fallback: Terminator의 단일 Claude 의존성을 multi-provider로 확장
- Phoenix tracing: 에이전트별 토큰/실행 시간 투명성 (현재 Terminator에 없음)
- HITL guardrail 체계: 승인 게이트 구조화

---

### Tier 2: Architecturally Notable

#### PentestAgent
**아키텍처**: 3-mode (Assist/Agent/Crew). `CrewOrchestrator → WorkerPool → pa_agent`. Jinja2 템플릿으로 동적 시스템 프롬프트(환경 감지, notes 주입, RAG 결과, 도구 목록). 단계별 `finish(action=complete/skip/fail)` 강제 확인.

**Unique Feature**: **Shadow Graph** (NetworkX, 510줄) — agent notes에서 자동 공격 그래프 구성. CONNECTS_TO, HAS_SERVICE, AUTH_ACCESS, AFFECTED_BY 엣지. NetworkX `shortest_path`로 크레덴셜→호스트 멀티홉 피벗 경로 자동 발견. "We have creds for Host X but haven't explored it" 인사이트를 orchestrator에 주입.

**Adoptable Pattern for Terminator**:
- Shadow Graph 직접 포팅 → `tools/knowledge_graph.py`: reverser가 발견한 libc base를 chain이 아직 미사용이라는 크로스 에이전트 인사이트 자동 생성
- RAG engine (`knowledge/rag.py`, 547줄): `knowledge/techniques/` 인덱싱 → 에이전트 컨텍스트에 관련 기법 자동 주입 (JSON 인덱스 파일 기반)
- Structured notes schema validation: 챌린지 파일 필수 필드(vulnerability_type, offset, protections, addresses) 강제 → 그래프 구성 가능

#### NeuroSploit v3
**아키텍처**: FastAPI + React + per-scan Kali Docker (ContainerPool max 5). 3-stream 병렬 에이전트(Stream1: 정찰, Stream2: AI 우선순위 테스트, Stream3: 도구 실행). 56개 도구 레시피, on-demand 컨테이너 내 설치.

**Unique Feature**: **4-layer validation pipeline** — (1) Negative controls: 양성/빈 요청 동일 응답 → -60 confidence, (2) Proof of execution: 25+ 취약점 유형별 증명 방법, (3) AI 해석: anti-hallucination 프롬프트 12개 조합, (4) ValidationJudge: 0-100 confidence score (>=90=confirmed). **10-rule chain engine** (`chain_engine.py`, 873줄): SSRF→내부서비스, SQLi→DB타입별, Info disclosure→credential, IDOR→sibling resource 등. eager chaining — 신호 감지 즉시 연관 공격 체인 발동.

**Adoptable Pattern for Terminator**:
- `chain_engine.py` 직접 포팅 → `tools/chain_engine.py`: Bug Bounty exploiter에 연결, finding 확인 시 `chain_engine.on_finding()` 호출
- Validation judge (negative_control + proof + confidence): critic 에이전트의 주관적 검토를 체계적 0-100 점수로 대체
- TokenBudget class: XION 550K+ 토큰 초과 같은 비용 폭주 방지
- WAF detection 16 signatures + 12 bypass techniques: Bug Bounty 웹 테스트 성공률 향상

#### RedAmon
**아키텍처**: 6-phase 정찰 파이프라인 → LangGraph ReAct Orchestrator → Neo4j Attack Surface Graph. MCP Tool Servers 4개(Naabu:8000, Curl:8001, Nuclei:8002, Metasploit:8003). Phase 전환 승인 게이트(Informational→Exploitation→Post-Exploitation).

**Unique Feature**: **Neo4j Attack Surface Graph** — 17 node types(IP, domain, port, service, endpoint, credential 등), 20+ relationships. MITRE 자동 매핑(CVE→CWE→CAPEC→ATT&CK). GVM/OpenVAS 170K+ NVT 통합.

**Adoptable Pattern for Terminator**:
- Neo4j 그래프: flat `knowledge/index.md` → queryable attack surface graph로 업그레이드 (Docker Neo4j 이미 존재)
- MITRE 자동 매핑: analyst 에이전트에 CVE→CAPEC 자동 컨텍스트 주입
- 6-phase 정찰 구조: Terminator의 scout 에이전트 프롬프트 강화

#### PentAGI
**아키텍처**: Go 기반, 3-tier(Flow→Task→Subtask). 전문 서브에이전트 핸들러(Coder, Installer, Memorist, Researcher)를 `FlowProviderHandlers` 인터페이스로 주입. `repeatingDetector`로 무한 도구 호출 루프 자동 감지.

**Unique Feature**: **최고 수준의 메모리 스택** — pgvector 시맨틱 검색 + Graphiti/Neo4j 세션 간 엔티티 추적 + 설정 가능한 context 한계(16KB summarizer, 150KB generator). langchaingo fork로 extended thinking(reasoning.ContentReasoning) 지원.

**Adoptable Pattern for Terminator**:
- `repeatingDetector`: chain/solver 에이전트 무한 루프 감지 (현재 Terminator에 없음)
- Graphiti/Neo4j 통합 패턴: 기존 GraphRAG MCP 서버 보강
- Per-agent model routing(`pconfig.ProviderOptionsType`): model_router.py 개선 참조
- **BLOCKER**: Proprietary EULA — 코드 재사용 불가. 아키텍처 참조 + API 통합만 가능.

---

### Tier 3: Tool-Focused / Early Stage

#### CyberStrikeAI
**아키텍처**: Go 단일 ReAct 루프 `AgentLoopWithProgress` (maxIterations=30). 각 도구는 독립 YAML 파일(name/command/args/parameters[]). Hot-reload. Native MCP server(HTTP+stdio+SSE).

**Unique Feature**: **100+ YAML tool recipes** — 코드 변경 없이 도구 추가. 결과 50KB 초과 시 파일 저장 후 `query_execution_result`로 조회(대용량 출력 처리). Security-aware MemoryCompressor: tiktoken 정확 카운팅, 취약점/크레덴셜/실패 시도/아키텍처 인사이트를 명시적으로 보존하는 요약 프롬프트.

**Adoptable Pattern for Terminator**:
- CyberStrikeAI MCP stdio server를 Terminator MCP 스택에 외부 서버로 등록 → 즉시 100+ 웹 스캔 도구 접근
- Security-aware compressor 프롬프트: Terminator 에이전트 컨텍스트 압축 시 취약점/크레덴셜 명시적 보존
- YAML tool recipe 패턴: `tools/mcp-servers/` 도구 표준화

#### HexStrike
**아키텍처**: Flask REST API(17K LOC) + FastMCP client(5.5K LOC). AI 자체 없음 — 외부 LLM(Claude Desktop 등)이 MCP로 연결하면 도구 실행 대행. SHA256 키 LRU cache로 동일 스캔 결과 재활용.

**Unique Feature**: **단일 MCP 등록으로 150+ 도구** (nmap, masscan, gobuster, sqlmap, radare2, ghidra, angr, nuclei 등) 접근. mitmproxy 트래픽 캡처 통합.

**Adoptable Pattern for Terminator**:
- LRU cache 패턴: `recon_pipeline.py`에 동일 대상 재스캔 방지용 JSON 파일 캐시 추가
- 도구 wrapper 표준화: 파라미터 검증 + 타임아웃 + 에러 처리 + 결과 파싱 패턴 채용

#### Strix
**아키텍처**: "Graph of agents" — 비선형 에이전트 협업(DAG 기반). Caido HTTP proxy + Playwright browser + Terminal + Python runtime. LiteLLM(GPT-5/Claude/Gemini). Interactive(TUI), Headless(-n), CI/CD(GitHub Actions) 3가지 실행 모드.

**Unique Feature**: **Caido HTTP proxy 통합** — 수동/자동 프록시 트래픽 분석 결합. CI/CD GitHub Actions 통합으로 PR 자동 보안 스캐닝.

**Adoptable Pattern for Terminator**:
- CI/CD 통합 패턴: terminator.sh에 종료 코드로 취약점 발견 여부 반환
- Graph of agents 아키텍처: 현재 선형 파이프라인을 DAG 기반으로 전환하는 장기 참조

---

## Commercial Platforms

| Platform | Key Differentiator | Open-Source Gap |
|----------|-------------------|-----------------|
| **XBOW** | 104-challenge benchmark suite; continuous scanning with SLA; Jira/GitHub/Slack 통합 | 연속 모니터링 모드 없음 |
| **Xint/Theori** | Human expert review layer; SOC2/PCI-DSS 컴플라이언스 리포팅; 고객 포털 | 컴플라이언스 출력 없음 |
| **Pentera** | Production-safe payloads(아웃티지 방지); AD/Kerberos/LDAP 라테럴 무브 체인 | Production-safe 제약 없음 |
| **NodeZero** | N-day exploit 라이브러리(검증된 CVE exploits); fix verification(패치 후 자동 재테스트) | AI 생성 exploit만, 사전 검증 CVE exploit 없음 |

**Commercial-only 기능 (단기 추격 불필요)**: Safe exploitation, N-day exploit library, Fix verification, Continuous cadence, Compliance reporting, AD lateral movement at enterprise scale.

---

## Terminator vs. Competition

| 항목 | Terminator | 경쟁사 최선 |
|------|-----------|------------|
| CTF 바이너리 분석 | **MCP RE chain (r2+gdb+ghidra)** | 없음 (CTF 지원 프레임워크 없음) |
| 듀얼 파이프라인 | **CTF+Bug Bounty** | 대부분 단일 용도 |
| Quality gate | **critic + triager_sim** | Shannon ExploitationCheckerService만 유사 |
| 지식 누적 | **knowledge/challenges/ 세션 간 누적** | PentAGI pgvector만 유사 |
| LLM flexibility | Claude only (Gemini partial) | CAI 300+, PentAGI 8, CyberStrikeAI 100+ |
| 그래프 메모리 | flat markdown | PentestAgent ShadowGraph, RedAmon Neo4j, PentAGI Graphiti |
| Auto chain engine | 없음 | NeuroSploit 10-rule, PentestAgent attack path |
| 토큰 예산 | 없음 | NeuroSploit TokenBudget |
| WAF bypass | 없음 | NeuroSploit 16 signatures+12 bypass |
| 연속 스캔 | 없음 | XBOW, Pentera (commercial) |
| Benchmark 결과 | 미공개 | PentestGPT 86.5%, Shannon 96.15%, CAI 3600x |

---

## Priority Adoption Roadmap

### P0: 즉시 적용 (직접 포팅, 각 <1일)

| # | Source | Pattern | LOC 추정 | Target Component | Impact |
|---|--------|---------|---------|-----------------|--------|
| 1 | NeuroSploit | `chain_engine.py` 포팅 | 873줄 | `tools/chain_engine.py` → BB exploiter | Finding-to-finding 자동 체인 (SSRF→내부, SQLi→DB타입별) |
| 2 | PentestGPT | `_detect_flags()` 스트림 | ~30줄 | verifier 에이전트 | FLAG_FOUND 선언 전 실시간 감지 |
| 3 | NeuroSploit | Anti-hallucination prompts 12개 | ~200줄 | critic 에이전트 프롬프트 | False positive 감소, 체계적 검증 |
| 4 | CyberStrikeAI | Security-aware MemoryCompressor 프롬프트 | ~20줄 | 전체 에이전트 context 압축 | 크레덴셜/exploit primitive 압축 중 소실 방지 |
| 5 | RedAmon | MITRE 자동 매핑 | ~50줄 | analyst 에이전트 | CVE→CWE→CAPEC 컨텍스트 자동 주입 |

### P1: 단기 (1-2주)

| # | Source | Pattern | LOC 추정 | Target Component | Impact |
|---|--------|---------|---------|-----------------|--------|
| 6 | Shannon | `ExploitationCheckerService` gate | ~100줄 | BB 파이프라인 exploiter 전 단계 | 이론적 finding 기반 exploit 에이전트 비용 차단 |
| 7 | Shannon | `prompts/exploit-*.txt` 5종 이식 | 5 파일 | web exploiter 에이전트 전문화 | 웹 취약점별 프로덕션급 프롬프트 즉시 사용 |
| 8 | PentestAgent | Shadow Graph 포팅 | 510줄 | `tools/knowledge_graph.py` | 크로스 에이전트 지식 합성 자동화 |
| 9 | NeuroSploit | TokenBudget class | ~80줄 | pipeline orchestrator | 멀티에이전트 파이프라인 토큰 비용 제어 |
| 10 | CyberStrikeAI | MCP stdio server 외부 등록 | 설정만 | Terminator MCP 스택 | 즉시 100+ 웹 스캔 도구 접근 |
| 11 | PentAGI+Shannon | `repeatingDetector` 상당 로직 | ~60줄 | chain/solver 에이전트 | 무한 도구 호출 루프 감지 (현재 미구현) |

### P2: 장기 (1-2개월)

| # | Source | Pattern | LOC 추정 | Target Component | Impact |
|---|--------|---------|---------|-----------------|--------|
| 12 | PentestAgent | RAG engine | 547줄 | `knowledge/rag/` | `knowledge/techniques/` 자동 벡터 검색 주입 |
| 13 | RedAmon/PentestAgent | Neo4j Attack Surface Graph | ~500줄 | `tools/knowledge_graph.py` v2 | flat markdown → queryable graph (세션 간 지속) |
| 14 | NeuroSploit | WAF detection+bypass | ~300줄 | BB analyst/exploiter | WAF 보호 타겟 성공률 향상 |
| 15 | Shannon | Temporal.io 오케스트레이터 | 대규모 | `tools/dag_orchestrator/` 교체 | 내구성 있는 워크플로, git checkpoint resume |
| 16 | Strix | CI/CD GitHub Actions 통합 | ~100줄 | terminator.sh | PR 자동 보안 스캐닝 |

---

## Appendix: Framework Repository Paths

| Framework | Path | License | Language |
|-----------|------|---------|----------|
| PentestGPT | `~/tools/PentestGPT` | MIT | Python |
| PentestAgent | `~/tools/pentestagent` | Apache-2.0 | Python |
| HexStrike | `~/tools/hexstrike-ai` | Unspecified | Python |
| NeuroSploit | `~/tools/NeuroSploit` | Unspecified | Python+React |
| PentAGI | `~/tools/pentagi` | Proprietary EULA | Go+React |
| CyberStrikeAI | `~/tools/CyberStrikeAI` | Source-available | Go |
| Shannon | `~/tools/shannon-analysis` | AGPL-3.0 | TypeScript |
| CAI | (aliasrobotics/cai) | Apache-2.0 | Python |
| RedAmon | (samugit83/redamon) | MIT | Python+Next.js |
| Strix | (usestrix/strix) | Unspecified | Python |

---

*분석 기반: PentestGPT/PentestAgent/HexStrike/NeuroSploit — Scientist Agent 소스 레벨 분석 (2026-02-24 22:19); PentAGI/CyberStrikeAI/Shannon — Scientist Agent 소스 레벨 분석 (2026-02-24 22:28); CAI/RedAmon/Strix — awesome-ai-security 기반 이전 세션 분석*
