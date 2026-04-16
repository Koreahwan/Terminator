# New Domain Implementation Guide — AI/LLM, Robotics/ROS, Supply Chain

> 작성일: 2026-04-05
> 상태: 구현 전 설계 문서

---

## 목차

1. [아키텍처 개요](#1-아키텍처-개요)
2. [Domain 1: AI/LLM Security](#2-domain-1-aillm-security)
3. [Domain 2: Robotics/ROS Security](#3-domain-2-roboticsros-security)
4. [Domain 3: Supply Chain Security](#4-domain-3-supply-chain-security)
5. [공통 인프라 변경](#5-공통-인프라-변경)
6. [파일 생성 체크리스트](#6-파일-생성-체크리스트)
7. [검증 계획](#7-검증-계획)

---

## 1. 아키텍처 개요

### 현재 모드 구조

```
terminator.sh
├── ctf       → reverser → trigger → chain → critic → verifier → reporter
├── bounty    → target-evaluator → scout+analyst+threat-modeler+patch-hunter → exploiter → reporter
└── firmware  → fw-profiler → fw-inventory → fw-surface → fw-validator
```

### 추가할 3개 모드

```
terminator.sh
├── (기존 3개)
├── ai-security   → ai-target-evaluator → ai-recon+ai-analyst (parallel) → ai-exploiter → reporter
├── robotics      → robo-profiler → robo-scanner+robo-analyst (parallel) → robo-exploiter → reporter
└── supplychain   → sc-target-evaluator → sc-scanner+sc-analyst (parallel) → sc-exploiter → reporter
```

### 설계 원칙

1. **기존 Prove Lane 재사용** — Gate 1/2, triager-sim, reporter, critic, submission-review는 도메인 무관. 새 도메인은 Explore Lane만 신규 구현
2. **기존 에이전트 확장 > 신규 생성** — reporter, critic, triager-sim, submission-review는 그대로 사용. 도메인별 scout/analyst/exploiter만 신규
3. **bb_preflight.py 확장** — 도메인별 gate check 서브커맨드 추가
4. **DAG 파이프라인 등록** — `pipelines.py`에 3개 파이프라인 추가

---

## 2. Domain 1: AI/LLM Security

### 2.1 파이프라인 구조

```
EXPLORE LANE                                    PROVE LANE (기존 재사용)
┌──────────────────────────────────────┐   ┌──────────────────────────────────┐
│ Phase 0:  ai-target-evaluator        │   │ Gate 1: triager-sim (finding)    │
│ Phase 0.2: ai_preflight rules        │   │ Phase 2: ai-exploiter (jailbreak)│
│ Phase 0.5: automated model probing   │   │ Gate 2: triager-sim (PoC)        │
│ Phase 1:  ai-recon + ai-analyst      │   │ Phase 3-6: (기존 bounty 동일)     │
│           (parallel)                 │   └──────────────────────────────────┘
│ Phase 1.5: ai-deep-tester            │
│ Gate 1→2: coverage check             │
└──────────────────────────────────────┘
```

### 2.2 신규 에이전트 정의

#### 2.2.1 `ai-recon` (`.claude/agents/ai-recon.md`)

```yaml
---
name: ai-recon
description: Use this agent when mapping AI/LLM application attack surface — model endpoints, system prompts, tool integrations, agent workflows.
model: sonnet
color: lime
permissionMode: bypassPermissions
---
```

**Mission:** AI/LLM 애플리케이션의 전체 공격 표면을 매핑. 모델 엔드포인트, 시스템 프롬프트 추출 시도, 도구 통합 지점, 에이전트 워크플로우, RAG 파이프라인 구조를 식별.

**Iron Rules:**
1. 시스템 프롬프트 추출 시도는 Phase 0.5에서만 (passive probing)
2. Rate limit 준수 — API 호출 max 30 req/min, 429 시 즉시 중단
3. 모델 버전/파라미터 fingerprinting 먼저 수행
4. 타겟 프로그램의 "Acceptable Use Policy" 확인 필수 — AUP 위반 테스트는 OOS
5. 토큰 효율 — 대형 응답은 첫 500자만 기록, 나머지는 file save

**Strategy:**

| Phase | Action | Output |
|-------|--------|--------|
| A: Model Fingerprinting | API 응답 헤더, 모델 식별, 버전 추정, 컨텍스트 윈도우 측정 | `model_profile.json` |
| B: System Prompt Probing | 간접 추출 기법 (role-play, translation, summarize-self), 직접 추출 시도 | `system_prompt_analysis.md` |
| C: Tool/Plugin Enumeration | 사용 가능한 도구 목록, function calling schema 추출, MCP/plugin 매핑 | `tool_surface_map.md` |
| D: Agent Workflow Mapping | 멀티스텝 워크플로우 식별, 에이전트 간 handoff 포인트, memory 구조 | `agent_workflow_map.md` |
| E: RAG/Data Pipeline Analysis | RAG 소스 식별, embedding 모델 추정, retrieval 패턴 매핑 | `rag_analysis.md` |
| F: Input/Output Surface | 입력 제한 (길이, 형식, 필터링), 출력 필터링 (content filter, safety layer) | `io_surface_map.md` |

**Output Artifacts:**
- `model_profile.json` — 모델 종류, 버전, 파라미터, 컨텍스트 윈도우, temperature 범위
- `ai_endpoint_map.md` — 모든 AI 엔드포인트 + Status (UNTESTED/TESTED/VULN/SAFE) + Risk
- `tool_surface_map.md` — 도구/플러그인 목록, 권한 수준, 호출 패턴
- `agent_workflow_map.md` — 에이전트 간 데이터 흐름, 신뢰 경계
- `ai_program_context.md` — 프로그램 스코프, AUP, 바운티 테이블, 제외 항목

**Tools:**
- `garak` — LLM 취약점 스캐너 (prompt injection, data leakage, hallucination)
- `promptfoo` — LLM 평가/레드팀 프레임워크
- `rebuff` — prompt injection 탐지기 (역으로 우회 테스트에 활용)
- `python-dotenv` + `httpx` — API 직접 호출
- `knowledge-fts` MCP — OWASP LLM Top 10 참조

---

#### 2.2.2 `ai-analyst` (`.claude/agents/ai-analyst.md`)

```yaml
---
name: ai-analyst
description: Use this agent when analyzing AI/LLM vulnerabilities — prompt injection, jailbreaks, data exfiltration, agent hijacking, memory poisoning.
model: sonnet
color: chartreuse
permissionMode: bypassPermissions
---
```

**Mission:** ai-recon 결과를 기반으로 LLM 특화 취약점 후보를 분류하고 우선순위 매김.

**Iron Rules:**
1. OWASP LLM Top 10 체크리스트 먼저 대조
2. 프로그램 exclusion list에 "prompt injection" 또는 "jailbreak"이 명시적으로 OOS인지 확인
3. "Universal jailbreak"과 "target-specific bypass"를 구분 — 대부분 프로그램은 후자만 인정
4. 모든 후보에 Evidence Tier 사전 분류: E1(재현 가능) / E2(differential proof) / E3(이론적)

**Vulnerability Classes (우선순위순):**

| # | Class | OWASP LLM | 설명 | 자동화 가능성 |
|---|-------|-----------|------|-------------|
| 1 | **Indirect Prompt Injection** | LLM01 | 외부 데이터(RAG, 웹, 이메일)를 통한 agent 조작 | ★★★★★ |
| 2 | **Agent Hijacking / Tool Abuse** | LLM07 | 에이전트의 도구 호출을 조작하여 비인가 작업 수행 | ★★★★★ |
| 3 | **Memory Poisoning** | LLM01 | 장기 메모리에 악성 지시 주입 → 지속적 조작 | ★★★★☆ |
| 4 | **Data Exfiltration via LLM** | LLM06 | LLM을 통한 시스템 데이터/PII 유출 | ★★★★☆ |
| 5 | **System Prompt Extraction** | LLM01 | 시스템 프롬프트 전체 추출 (IP 유출) | ★★★★★ |
| 6 | **Insecure Output Handling** | LLM02 | LLM 출력이 downstream에서 코드로 실행 (XSS, SQLi, RCE) | ★★★★☆ |
| 7 | **Training Data Extraction** | LLM06 | 학습 데이터 중 PII/비밀 정보 추출 | ★★★☆☆ |
| 8 | **Excessive Agency** | LLM08 | LLM에 부여된 과도한 권한 (파일 삭제, 이메일 발송 등) | ★★★★☆ |
| 9 | **Denial of Service (Resource)** | LLM04 | 컨텍스트 윈도우 고갈, 무한 루프 유도, 토큰 소진 | ★★★☆☆ |
| 10 | **Model Confusion / Hallucination Exploit** | LLM09 | 할루시네이션을 이용한 사용자 기만 체인 | ★★☆☆☆ |

**Output Artifacts:**
- `ai_vulnerability_candidates.md` — 각 후보: 클래스, 설명, 증거, Evidence Tier, 공격 전제 조건
- `ai_attack_chains.md` — 다단계 공격 시나리오 (예: indirect injection → tool abuse → data exfil)

**Dynamic Review Budget (ai-recon 결과 기반):**
- Base: 3 attack vectors 심층 분석
- Bonus +1: 에이전트 워크플로우 존재 (agent hijacking 가능)
- Bonus +1: RAG 파이프라인 존재 (indirect injection 가능)
- Bonus +1: 외부 도구 3개+ 연동 (tool abuse 가능)
- Bonus +1: 장기 메모리/세션 유지 (memory poisoning 가능)
- Max: 7 vectors

---

#### 2.2.3 `ai-exploiter` (`.claude/agents/ai-exploiter.md`)

```yaml
---
name: ai-exploiter
description: Use this agent when developing PoC for AI/LLM vulnerabilities — jailbreak prompts, injection chains, agent hijack demonstrations.
model: opus
color: red
permissionMode: bypassPermissions
---
```

**Mission:** Gate 1을 통과한 AI/LLM 취약점 후보에 대해 재현 가능한 PoC 개발.

**Iron Rules:**
1. 모든 PoC는 **단일 HTTP 요청 또는 프롬프트 시퀀스**로 재현 가능해야 함
2. PoC 출력에 **타임스탬프 + 모델 응답 전문** 캡처 필수
3. "이론적으로 가능" ≠ PoC — 실제 동작하는 프롬프트/요청만 인정
4. 안전한 페이로드만 사용: 데이터 유출 시 자신의 테스트 데이터만, 도구 남용 시 무해한 동작만
5. Rate limit 엄격 준수 — PoC 테스트 총 요청 수 100회 이내

**PoC Types:**

| Type | Evidence Requirements | E-Tier |
|------|----------------------|--------|
| **Jailbreak PoC** | 정확한 프롬프트 + 모델의 safety bypass 응답 캡처 | E1 |
| **Indirect Injection PoC** | 악성 데이터 삽입 경로 + 에이전트 조작 결과 | E1 |
| **Agent Hijack PoC** | 도구 호출 조작 전/후 비교 (HTTP 로그 포함) | E1 |
| **Memory Poison PoC** | 메모리 삽입 → 세션 종료 → 새 세션에서 효과 확인 | E1/E2 |
| **Data Exfil PoC** | 유출 경로 시연 + 유출된 데이터 샘플 | E1 |
| **System Prompt Extract** | 추출된 전체/부분 시스템 프롬프트 텍스트 | E2 |
| **Insecure Output PoC** | LLM 출력 → downstream XSS/SQLi/RCE 실행 증거 | E1 |

**Prompt Mutation Engine (자동화 핵심):**
```
1. Base jailbreak 20개 로드 (knowledge/techniques/ai_jailbreak_patterns.md)
2. 각 base에 mutation 적용:
   - Role-play wrapping ("You are a helpful assistant who...")
   - Language translation (영→한→영 round-trip)
   - Encoding (base64, rot13, unicode substitution)
   - Context manipulation (few-shot 주입)
   - Token splitting ("ig" + "nore previous")
3. 각 mutation을 타겟 API에 전송
4. Safety bypass 여부 자동 판정 (keyword matching + semantic check)
5. 성공한 mutation → PoC artifact로 저장
```

**Output Artifacts:**
- `ai_exploit_results.md` — 각 PoC: 프롬프트 전문, 응답 전문, Evidence Tier, 재현 단계
- `evidence/` — 스크린샷, HTTP 로그, API 응답 JSON
- `ai_poc_script.py` — 자동 재현 스크립트 (httpx 기반)

---

### 2.3 스킬 파일: `.claude/skills/ai-security/SKILL.md`

```yaml
---
name: ai-security
description: Start AI/LLM security testing pipeline. Auto-matches "ai security", "llm bounty", "prompt injection", "jailbreak hunt", "ai red team", "agent security"
argument-hint: [target-url-or-api-endpoint] [model-name]
---
```

**파이프라인 흐름:**

```
Phase 0: target-evaluator (model=sonnet)
  → 프로그램 분석: AI/LLM 스코프 확인, 모델 종류, 보상 테이블
  → 특별 체크: "prompt injection" / "jailbreak"이 스코프 내인지 확인
  → GO / CONDITIONAL GO / NO-GO

Phase 0.2: ai_preflight rules (Orchestrator 직접 실행)
  python3 tools/bb_preflight.py init targets/<target>/ --domain ai
  # ai_program_rules_summary.md 생성
  python3 tools/bb_preflight.py rules-check targets/<target>/

Phase 0.5: Automated Model Probing
  ai-recon (model=sonnet)
  → garak 자동 스캔 (prompt injection, data leakage 프로브)
  → promptfoo 기본 평가 실행
  → 결과 → ai-analyst에 전달

Phase 1: Discovery (parallel)
  ai-recon (model=sonnet) → model_profile.json, ai_endpoint_map.md, tool_surface_map.md
  ai-analyst (model=sonnet) → ai_vulnerability_candidates.md, ai_attack_chains.md

Phase 1.5: Deep Testing (optional)
  ai-deep-tester = ai-exploiter를 sonnet 모드로 경량 실행
  → 상위 3개 후보에 대해 quick mutation test

Phase 1→2 Gate:
  python3 tools/bb_preflight.py coverage-check targets/<target>/ --domain ai
  # ai_endpoint_map.md 기준 80%+ 커버리지

Phase 2-6: 기존 Prove Lane 재사용
  Gate 1 → ai-exploiter (model=opus) → Gate 2 → reporter → critic → triager-sim → submission-review
```

**Time-Box:**
- Phase 0: 30min | Phase 0.5: 30min | Phase 1: 1.5hr | Phase 1.5: 30min | Phase 2: 2hr | Phase 3-5: 1.5hr
- Total: ~6.5hr
- No findings at 1.5hr → ABANDON

---

### 2.4 Knowledge 파일

#### `knowledge/techniques/ai_llm_security_reference.md`

내용 포함 사항:
- OWASP Top 10 for LLM Applications (2025 버전) 전체 체크리스트
- 프롬프트 인젝션 분류 체계 (direct / indirect / stored / recursive)
- 주요 AI 바운티 프로그램 목록 및 스코프 (OpenAI, Microsoft, Anthropic, Google)
- 알려진 jailbreak 패턴 20+ (DAN, AIM, STAN, developer mode 등)
- Agentic AI 공격 벡터 (memory injection, tool abuse, agent chaining)
- EU AI Act 관련 보안 요구사항 요약

#### `knowledge/techniques/ai_jailbreak_patterns.md`

내용:
- Base jailbreak 템플릿 20개 (각각 mutation 가능)
- 모델별 알려진 bypass 패턴 (GPT-4o, Claude, Gemini, Llama)
- Encoding 기반 우회 기법 (base64, unicode, token splitting)
- Multi-turn escalation 패턴
- 간접 injection 벡터 (RAG poisoning, tool response injection)

#### `knowledge/protocol-vulns-index/categories/llm/`

파일 구조:
```
llm/
├── prompt_injection.md      — 직접/간접 인젝션 체크리스트
├── agent_hijacking.md       — 에이전트 워크플로우 조작 패턴
├── memory_poisoning.md      — 장기 메모리 공격 벡터
├── data_exfiltration.md     — LLM 통한 데이터 유출 경로
├── insecure_output.md       — 출력 처리 취약점 (XSS via LLM 등)
└── excessive_agency.md      — 과도한 권한 부여 패턴
```

---

### 2.5 도구 설치

```bash
# garak — LLM 취약점 스캐너
pip install garak

# promptfoo — LLM 레드팀/평가
npm install -g promptfoo

# rebuff (옵션) — prompt injection 탐지 라이브러리
pip install rebuff
```

`knowledge/techniques/installed_tools_reference.md`에 추가:
```
## AI/LLM Security
- garak: ~/.local/bin/garak (LLM vulnerability scanner, OWASP LLM Top 10)
- promptfoo: $(which promptfoo) (LLM red-team evaluation framework)
```

---

## 3. Domain 2: Robotics/ROS Security

### 3.1 파이프라인 구조

```
EXPLORE LANE                                    PROVE LANE
┌──────────────────────────────────────┐   ┌──────────────────────────────────┐
│ Phase 0:  target-evaluator           │   │ Phase 2: robo-exploiter          │
│ Phase 0.5: ROS topology auto-scan    │   │ Phase 3-5: reporter → critic     │
│ Phase 1:  robo-scanner + robo-analyst│   │          → CVE submission        │
│           (parallel)                 │   └──────────────────────────────────┘
│ Phase 1.5: firmware extraction       │
│ Gate 1→2: surface coverage check     │
└──────────────────────────────────────┘
```

> **참고:** Robotics는 공식 바운티 프로그램이 거의 없으므로 주 수익 모델은 **CVE 발급 + Responsible Disclosure**. reporter 에이전트는 바운티 리포트 대신 CVE advisory 형식으로 출력.

### 3.2 신규 에이전트 정의

#### 3.2.1 `robo-scanner` (`.claude/agents/robo-scanner.md`)

```yaml
---
name: robo-scanner
description: Use this agent when scanning ROS-based robot systems — topic enumeration, service discovery, node mapping, firmware extraction.
model: sonnet
color: teal
permissionMode: bypassPermissions
---
```

**Mission:** ROS 기반 로봇 시스템의 전체 공격 표면 매핑. 토픽, 서비스, 액션, 파라미터 서버, 노드 간 통신 구조 식별.

**Iron Rules:**
1. **네트워크 격리 확인 필수** — 테스트 전 타겟이 프로덕션 환경과 분리되어 있는지 확인
2. **ROS Master 발견 먼저** — `rostopic list`, `rosservice list`, `rosnode list`로 토폴로지 파악
3. **물리적 안전** — 모터/액추에이터 제어 명령은 시뮬레이터에서만 테스트
4. **펌웨어 추출은 비파괴적 방법만** — binwalk, strings, readelf (dd/flash dump 금지)
5. **Observation Masking** — ROS 토픽 데이터는 대량이므로 10초 캡처 후 요약

**Strategy:**

| Phase | Action | Output |
|-------|--------|--------|
| A: ROS Discovery | ROS master URI 탐색, 노드/토픽/서비스 전체 열거 | `ros_topology.json` |
| B: Communication Analysis | 토픽 메시지 타입 분석, 인증 메커니즘 확인, TLS 사용 여부 | `ros_comm_analysis.md` |
| C: Node Dependency Mapping | 노드 간 의존성 그래프, 크리티컬 패스 식별 | `node_dependency_graph.md` |
| D: Service/Action Audit | 각 서비스의 접근 제어, 파라미터 변경 가능 여부 | `service_audit.md` |
| E: Firmware Extraction | 파일시스템 접근, 바이너리 추출, 설정 파일 수집 | `firmware_inventory.json` |
| F: Network Traffic Analysis | 포트 스캔, 프로토콜 식별, 평문 통신 탐지 | `network_analysis.md` |

**Output Artifacts:**
- `ros_topology.json` — 전체 ROS 그래프 (노드, 토픽, 서비스, 액션, 파라미터)
- `robo_endpoint_map.md` — 모든 ROS 엔드포인트 + Status + Risk
- `firmware_inventory.json` — 추출된 바이너리, 라이브러리, 설정 파일 목록
- `network_analysis.md` — 열린 포트, 프로토콜, 인증 상태

**Tools:**
- `rostopic`, `rosservice`, `rosnode`, `rosparam` — ROS CLI
- `rosbridge_suite` — WebSocket 기반 ROS 접근 (원격 테스트용)
- `wireshark` / `tcpdump` — ROS 네트워크 트래픽 캡처
- `binwalk`, `strings`, `readelf` — 펌웨어 분석
- `nmap` — 네트워크 스캔
- fw-* 에이전트 체인 — 펌웨어 심층 분석 시 재사용

---

#### 3.2.2 `robo-analyst` (`.claude/agents/robo-analyst.md`)

```yaml
---
name: robo-analyst
description: Use this agent when analyzing ROS/robotics vulnerabilities — authentication bypass, node spoofing, command injection, unsafe deserialization.
model: sonnet
color: olive
permissionMode: bypassPermissions
---
```

**Mission:** robo-scanner 결과를 기반으로 로보틱스 특화 취약점 후보 분류 및 우선순위 매김.

**Vulnerability Classes:**

| # | Class | 설명 | Severity | 자동화 |
|---|-------|------|----------|--------|
| 1 | **ROS Auth Bypass** | ROS Master에 인증 없이 접근 가능 | Critical | ★★★★★ |
| 2 | **Node Spoofing** | 악성 노드로 정상 노드 대체/오버라이드 | Critical | ★★★★★ |
| 3 | **Command Injection via Topic** | 토픽 메시지에 명령어 삽입 → 시스템 실행 | Critical | ★★★★☆ |
| 4 | **Unsafe Deserialization** | ROS 메시지 역직렬화 시 코드 실행 | High | ★★★★☆ |
| 5 | **Parameter Tampering** | rosparam으로 안전 임계값 변경 (속도, 토크 등) | High | ★★★★★ |
| 6 | **Firmware Hardcoded Credentials** | 기본 비밀번호, SSH 키, API 키 | High | ★★★★★ |
| 7 | **Unencrypted Communication** | 토픽/서비스 데이터 평문 전송 | Medium | ★★★★★ |
| 8 | **Telemetry Exfiltration** | 위치/센서 데이터 무단 외부 전송 | High | ★★★★☆ |
| 9 | **DoS via Resource Exhaustion** | 대량 토픽 publish로 노드 크래시 | Medium | ★★★★★ |
| 10 | **Safety System Bypass** | 안전 interlock/e-stop 우회 | Critical | ★★★☆☆ |

**Output Artifacts:**
- `robo_vulnerability_candidates.md` — 각 후보: 클래스, ROS 토픽/서비스 경로, 증거, 심각도
- `robo_attack_chains.md` — 다단계 시나리오 (예: auth bypass → parameter tamper → safety bypass)

---

#### 3.2.3 `robo-exploiter` (`.claude/agents/robo-exploiter.md`)

```yaml
---
name: robo-exploiter
description: Use this agent when developing PoC for robotics/ROS vulnerabilities — node injection, topic hijacking, firmware command execution.
model: opus
color: orange
permissionMode: bypassPermissions
---
```

**Mission:** 로보틱스 취약점 PoC 개발. 시뮬레이터(Gazebo) 우선, 실제 하드웨어는 승인 후에만.

**Iron Rules:**
1. **시뮬레이터 우선** — Gazebo/RViz에서 먼저 검증, 실 하드웨어 테스트는 Orchestrator 승인 필요
2. **물리적 안전** — 모터 제어 PoC는 시뮬레이터에서만. 실제 로봇에 위험한 명령 절대 금지
3. **네트워크 격리** — PoC 실행 시 타겟 네트워크 외부 통신 차단 확인
4. **증거 캡처** — ROS bag 파일 녹화, 토픽 메시지 로그, 네트워크 pcap 저장

**PoC Types:**

| Type | Method | Evidence |
|------|--------|----------|
| **Node Injection** | 악성 ROS 노드 등록 → 토픽 publish | rosbag + 토픽 모니터 로그 |
| **Topic Hijack** | 정상 토픽에 조작된 메시지 publish | 전/후 토픽 데이터 diff |
| **Service Abuse** | 비인가 서비스 호출 (파라미터 변경, 재부팅) | 서비스 응답 + 시스템 상태 변화 |
| **Firmware Exploit** | 하드코딩된 자격증명으로 SSH/Telnet 접속 | 세션 로그 + /etc/shadow 등 |
| **Network MITM** | ARP spoofing → ROS 메시지 가로채기/변조 | pcap + 변조된 메시지 비교 |

**Output Artifacts:**
- `robo_exploit_results.md` — 각 PoC 상세 (재현 단계, 명령어, 결과)
- `evidence/` — rosbag, pcap, 스크린샷, 세션 로그
- `robo_poc_script.py` — 자동 재현 스크립트 (rospy/rclpy 기반)

---

### 3.3 스킬 파일: `.claude/skills/robotics/SKILL.md`

```yaml
---
name: robotics
description: Start Robotics/ROS security testing pipeline. Auto-matches "robotics", "ROS", "robot security", "로봇 보안", "ROS2", "industrial robot"
argument-hint: [target-ip-or-ros-master-uri] [robot-model]
---
```

**파이프라인 흐름:**

```
Phase 0: target-evaluator (model=sonnet)
  → 로봇 제조사, 모델, ROS 버전, 네트워크 접근성 확인
  → CVE 기존 발급 현황 체크 (searchsploit + knowledge-fts)
  → GO / NO-GO

Phase 0.5: ROS Topology Auto-Scan
  robo-scanner (model=sonnet)
  → rostopic list + rosservice list + rosnode list
  → 네트워크 스캔 (nmap)
  → ros_topology.json 생성

Phase 1: Discovery (parallel)
  robo-scanner (model=sonnet) → robo_endpoint_map.md, firmware_inventory.json
  robo-analyst (model=sonnet) → robo_vulnerability_candidates.md

Phase 1.5: Firmware Deep Dive (optional)
  fw-profiler → fw-inventory → fw-surface (기존 체인 재사용)
  → 펌웨어 레벨 취약점 추가

Phase 1→2 Gate:
  python3 tools/bb_preflight.py coverage-check targets/<target>/ --domain robotics
  # robo_endpoint_map.md 기준 70%+ 커버리지 (로보틱스는 물리 접근 제약으로 임계값 낮춤)

Phase 2: PoC Development
  robo-exploiter (model=opus)
  → 시뮬레이터(Gazebo) 우선 검증
  → 실 하드웨어 검증 (승인 시)

Phase 3-5: CVE Submission (bounty 대신)
  reporter (model=sonnet) → CVE advisory 형식 리포트
  → cve-manager 에이전트로 CVE 발급 프로세스
  → Discoverer: "Kyunghwan Byun"
```

**Time-Box:**
- Phase 0: 30min | Phase 0.5: 30min | Phase 1: 1.5hr | Phase 1.5: 1hr | Phase 2: 2hr | Phase 3-5: 1hr
- Total: ~6.5hr

---

### 3.4 Knowledge 파일

#### `knowledge/techniques/robotics_ros_security_reference.md`

- ROS1/ROS2 아키텍처 차이 및 보안 모델
- ROS2 DDS/SROS2 보안 메커니즘 (있는 경우 우회 방법)
- 산업용 로봇 프로토콜 (MQTT, OPC-UA, Modbus over ROS bridge)
- 주요 로봇 제조사별 알려진 취약점 (Unitree, Universal Robots, MiR, ABB)
- CAI 프레임워크 연구 결과 요약
- 시뮬레이터 기반 테스트 방법론 (Gazebo, RViz)

#### `knowledge/protocol-vulns-index/categories/robotics/`

```
robotics/
├── ros_authentication.md    — ROS master 인증 부재, SROS2 설정 오류
├── node_spoofing.md         — 노드 이름 충돌, 토픽 하이재킹
├── message_injection.md     — geometry_msgs, sensor_msgs 조작
├── parameter_tampering.md   — rosparam 안전 임계값 변경
├── firmware_hardcoding.md   — 기본 자격증명, SSH 키
└── network_exposure.md      — ROS master 외부 노출, 평문 통신
```

---

### 3.5 도구 설치

```bash
# ROS2 Humble (시뮬레이터 + CLI 도구)
sudo apt install ros-humble-desktop  # 또는 docker pull ros:humble

# Gazebo 시뮬레이터
sudo apt install ros-humble-gazebo-ros-pkgs

# rosbridge (원격 ROS 접근)
sudo apt install ros-humble-rosbridge-suite

# CAI 프레임워크 (참고용)
pip install cai-framework
```

`knowledge/techniques/installed_tools_reference.md`에 추가:
```
## Robotics/ROS
- ROS2 Humble: /opt/ros/humble/ (ROS CLI + Gazebo simulator)
- rosbridge: ros-humble-rosbridge-suite (WebSocket ROS bridge)
- CAI: cai-framework (AI-driven robot security testing)
```

---

## 4. Domain 3: Supply Chain Security

### 4.1 파이프라인 구조

```
EXPLORE LANE                                      PROVE LANE
┌───────────────────────────────────────┐   ┌──────────────────────────────────┐
│ Phase 0:  sc-target-evaluator         │   │ Gate 1: triager-sim (finding)    │
│ Phase 0.2: sc_preflight rules         │   │ Phase 2: sc-exploiter (PoC)      │
│ Phase 0.5: SBOM auto-generation       │   │ Gate 2: triager-sim (PoC)        │
│ Phase 1:  sc-scanner + sc-analyst     │   │ Phase 3-6: (기존 bounty 동일)     │
│           (parallel)                  │   └──────────────────────────────────┘
│ Phase 1.5: dependency confusion scan  │
│ Gate 1→2: coverage check              │
└───────────────────────────────────────┘
```

### 4.2 신규 에이전트 정의

#### 4.2.1 `sc-scanner` (`.claude/agents/sc-scanner.md`)

```yaml
---
name: sc-scanner
description: Use this agent when scanning software supply chains — SBOM generation, dependency tree analysis, registry namespace conflicts, build pipeline inspection.
model: sonnet
color: indigo
permissionMode: bypassPermissions
---
```

**Mission:** 타겟 소프트웨어의 공급망 전체를 매핑. SBOM 생성, 의존성 트리 분석, 레지스트리 네임스페이스 충돌 탐지, 빌드 파이프라인 검사.

**Iron Rules:**
1. **SBOM 먼저** — 코드 분석 전에 syft/cdxgen으로 SBOM 자동 생성
2. **Transitive 의존성 5단계 추적** — 직접 의존성만이 아니라 간접 의존성까지 분석
3. **레지스트리 충돌 검사 자동화** — npm/PyPI/Maven 공개 레지스트리 대조
4. **빌드 파이프라인 접근 시 읽기 전용** — CI/CD 설정은 분석만, 수정 금지
5. **private 패키지명 유출 주의** — 발견한 내부 패키지명을 리포트 외부에 공개 금지

**Strategy:**

| Phase | Action | Output |
|-------|--------|--------|
| A: SBOM Generation | syft/cdxgen으로 CycloneDX/SPDX SBOM 자동 생성 | `sbom.json` (CycloneDX) |
| B: Dependency Tree Analysis | 전체 의존성 트리 구축, 버전 고정 여부, 범위 지정자 검사 | `dependency_tree.md` |
| C: Vulnerability Matching | grype로 알려진 취약점 매칭 (CVE/GHSA) | `vuln_matches.json` |
| D: Namespace Conflict Scan | npm/PyPI/Maven에서 내부 패키지명과 동일한 공개 패키지 존재 여부 | `namespace_conflicts.md` |
| E: Build Pipeline Inspection | GitHub Actions/GitLab CI/Jenkins 설정 분석 | `build_pipeline_analysis.md` |
| F: Maintainer Trust Analysis | 패키지 메인테이너 변경 이력, 2FA 미사용, 방치 패키지 | `maintainer_trust.md` |

**Output Artifacts:**
- `sbom.json` — CycloneDX 형식 SBOM
- `sc_endpoint_map.md` — 모든 의존성 + Status (SAFE/VULN/CONFLICT/STALE) + Risk
- `namespace_conflicts.md` — dependency confusion 후보 목록
- `build_pipeline_analysis.md` — CI/CD 설정 취약점

**Tools:**
- `syft` — SBOM 생성 (Anchore)
- `grype` — 취약점 매칭 (Anchore)
- `cdxgen` — CycloneDX SBOM 생성기 (대안)
- `npm audit` / `pip-audit` / `mvn dependency:tree` — 패키지 매니저 내장 감사
- `socket.dev` CLI — supply chain 위험 분석 (옵션)
- `trufflehog` — 소스코드 내 시크릿 탐지 (빌드 설정 포함)

---

#### 4.2.2 `sc-analyst` (`.claude/agents/sc-analyst.md`)

```yaml
---
name: sc-analyst
description: Use this agent when analyzing supply chain vulnerabilities — dependency confusion, typosquatting, build pipeline compromise, maintainer account hijack vectors.
model: sonnet
color: violet
permissionMode: bypassPermissions
---
```

**Mission:** sc-scanner 결과를 기반으로 공급망 특화 취약점 후보 분류 및 우선순위 매김.

**Vulnerability Classes:**

| # | Class | 설명 | Severity | 자동화 |
|---|-------|------|----------|--------|
| 1 | **Dependency Confusion** | 내부 패키지명과 동일한 공개 패키지로 코드 실행 | Critical | ★★★★★ |
| 2 | **Typosquatting** | 인기 패키지 오타 변형으로 악성 코드 배포 | High | ★★★★★ |
| 3 | **Build Pipeline RCE** | CI/CD 설정에서 코드 실행 가능 (script injection, artifact poisoning) | Critical | ★★★★☆ |
| 4 | **Unpinned Dependency** | 버전 미고정 → 악성 업데이트 자동 설치 가능 | Medium | ★★★★★ |
| 5 | **Stale/Abandoned Package** | 메인테이너 부재 패키지 → 계정 탈취 위험 | Medium | ★★★★★ |
| 6 | **Transitive Vuln Amplification** | 간접 의존성의 Critical CVE가 production path에 있는 경우 | High | ★★★★☆ |
| 7 | **CI Secret Leak** | GitHub Actions 로그에 시크릿 노출, artifact에 credential 포함 | High | ★★★★☆ |
| 8 | **Package Script Execution** | postinstall/preinstall 스크립트에서 악성 코드 실행 | Critical | ★★★★★ |
| 9 | **Lock File Manipulation** | lock 파일 변조로 의존성 바꿔치기 | High | ★★★☆☆ |
| 10 | **Registry Scope Misconfiguration** | .npmrc/.pip.conf에서 private registry 설정 오류 | Critical | ★★★★★ |

**Output Artifacts:**
- `sc_vulnerability_candidates.md` — 각 후보: 클래스, 패키지명, 영향 범위, Evidence Tier
- `sc_attack_chains.md` — 다단계 시나리오 (예: scope misconfig → dependency confusion → RCE)

---

#### 4.2.3 `sc-exploiter` (`.claude/agents/sc-exploiter.md`)

```yaml
---
name: sc-exploiter
description: Use this agent when developing PoC for supply chain vulnerabilities — dependency confusion proof, build pipeline exploitation, registry misconfiguration demonstration.
model: opus
color: crimson
permissionMode: bypassPermissions
---
```

**Mission:** 공급망 취약점 PoC 개발. 안전한 방법으로 의존성 혼동, 빌드 파이프라인 취약점 재현.

**Iron Rules:**
1. **악성 패키지 실제 배포 금지** — 네임스페이스 충돌은 존재 여부 확인만, 실제 업로드 금지
2. **안전한 PoC만** — DNS callback (Burp Collaborator/interact.sh)으로 코드 실행 증명
3. **타겟 빌드 환경 접근 시 읽기 전용** — 빌드 아티팩트 수정 금지
4. **Private 패키지명 비공개 유지** — 리포트에서 난독화 처리

**PoC Types:**

| Type | Method | Evidence |
|------|--------|----------|
| **Dependency Confusion** | 내부 패키지명으로 PyPI/npm 검색 → 충돌 증명 | 레지스트리 스크린샷 + 설정 파일 분석 |
| **Build Pipeline RCE** | CI 설정 분석 → 주입 가능한 변수/스크립트 식별 | CI 설정 스니펫 + 공격 시나리오 |
| **Typosquatting** | 인기 패키지 오타 변형 레지스트리 검색 | 기존 typosquat 패키지 존재 증거 |
| **Script Execution** | package.json postinstall 분석 → 실행 내용 추적 | 스크립트 코드 + 실행 흐름 |
| **Secret Leak** | CI 로그/artifact 내 credential 검색 | 노출된 시크릿 (마스킹 처리) + 로그 경로 |

**Output Artifacts:**
- `sc_exploit_results.md` — 각 PoC 상세
- `evidence/` — 스크린샷, CI 로그, 레지스트리 검색 결과
- `sc_poc_script.py` — 자동 검증 스크립트

---

### 4.3 스킬 파일: `.claude/skills/supplychain/SKILL.md`

```yaml
---
name: supplychain
description: Start Supply Chain security testing pipeline. Auto-matches "supply chain", "dependency confusion", "SBOM", "npm audit", "pip audit", "package security", "공급망 보안"
argument-hint: [target-repo-url-or-path] [package-manager]
---
```

**파이프라인 흐름:**

```
Phase 0: target-evaluator (model=sonnet)
  → 레포지토리 분석: 패키지 매니저 종류, 의존성 수, CI/CD 플랫폼
  → 바운티 프로그램 확인 (있으면 bounty 모드 연계, 없으면 CVE 모드)
  → GO / NO-GO

Phase 0.2: sc_preflight rules (Orchestrator 직접 실행)
  python3 tools/bb_preflight.py init targets/<target>/ --domain supplychain
  python3 tools/bb_preflight.py rules-check targets/<target>/

Phase 0.5: SBOM Auto-Generation
  sc-scanner (model=sonnet)
  → syft <repo> -o cyclonedx-json > sbom.json
  → grype sbom.json > vuln_matches.json

Phase 1: Discovery (parallel)
  sc-scanner (model=sonnet) → sc_endpoint_map.md, namespace_conflicts.md, build_pipeline_analysis.md
  sc-analyst (model=sonnet) → sc_vulnerability_candidates.md

Phase 1.5: Dependency Confusion Deep Scan
  sc-scanner가 내부 패키지명 추출 → 공개 레지스트리 대조
  → 각 충돌에 대해 version priority 분석

Phase 1→2 Gate:
  python3 tools/bb_preflight.py coverage-check targets/<target>/ --domain supplychain
  # sc_endpoint_map.md 기준 80%+ 커버리지

Phase 2-6:
  바운티 프로그램 있음 → 기존 Prove Lane (Gate 1 → sc-exploiter → Gate 2 → reporter)
  바운티 없음 → sc-exploiter → reporter (CVE advisory 형식) → cve-manager
```

**Time-Box:**
- Phase 0: 20min | Phase 0.5: 20min | Phase 1: 1hr | Phase 1.5: 30min | Phase 2: 1.5hr | Phase 3-5: 1hr
- Total: ~4.5hr (가장 빠른 파이프라인)

---

### 4.4 Knowledge 파일

#### `knowledge/techniques/supplychain_security_reference.md`

- 주요 패키지 매니저별 dependency resolution 규칙 (npm, pip, Maven, Go modules)
- Dependency confusion 공격 메커니즘 상세 (Alex Birsan 원문 참조)
- CI/CD 파이프라인별 공격 벡터 (GitHub Actions, GitLab CI, Jenkins, CircleCI)
- SBOM 형식 비교 (CycloneDX vs SPDX)
- 주요 supply chain 사고 분석 (Axios 2026, event-stream 2018, colors.js 2022, ua-parser-js 2021)
- 바운티 프로그램에서 supply chain 취약점 인정 기준

#### `knowledge/protocol-vulns-index/categories/supplychain/`

```
supplychain/
├── dependency_confusion.md   — npm/PyPI/Maven/Go scope 충돌 패턴
├── typosquatting.md          — 패키지명 오타 변형 탐지 규칙
├── build_pipeline.md         — CI/CD 설정 취약점 체크리스트
├── script_execution.md       — pre/postinstall 스크립트 위험 패턴
├── maintainer_trust.md       — 메인테이너 계정 보안 지표
└── lockfile_integrity.md     — lock 파일 변조 탐지
```

### 4.5 도구 설치

```bash
# syft — SBOM 생성
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# grype — 취약점 매칭
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# cdxgen (대안 SBOM 생성기)
npm install -g @cyclonedx/cdxgen

# pip-audit
pip install pip-audit

# socket CLI (옵션)
npm install -g @socketsecurity/cli
```

`knowledge/techniques/installed_tools_reference.md`에 추가:
```
## Supply Chain Security
- syft: /usr/local/bin/syft (SBOM generator, CycloneDX/SPDX output)
- grype: /usr/local/bin/grype (vulnerability matcher, reads SBOM input)
- cdxgen: $(which cdxgen) (CycloneDX SBOM generator)
- pip-audit: ~/.local/bin/pip-audit (Python dependency vulnerability scanner)
```

---

## 5. 공통 인프라 변경

### 5.1 terminator.sh 모드 추가

**변경 위치:** `terminator.sh` 라인 62+ (MODE 파싱), 라인 234+ (session_mode 분류), 라인 623+ (bounty case 다음)

```bash
# 라인 234 부근 — session_mode 분류 확장
case "${MODE:-}" in
  ctf-*) session_mode="ctf" ;;
  fw-*) session_mode="firmware" ;;
  ai-*) session_mode="ai-security" ;;      # 추가
  robo-*) session_mode="robotics" ;;       # 추가
  sc-*) session_mode="supplychain" ;;      # 추가
  *) session_mode="bounty" ;;
esac

# bounty case 다음에 3개 mode case 추가
ai-security)
  # TARGET = API endpoint 또는 프로그램 URL
  # SCOPE = 모델명 (optional)
  # 파이프라인: ai-recon + ai-analyst → ai-exploiter → reporter
  ...
  ;;

robotics)
  # TARGET = ROS master URI 또는 IP
  # SCOPE = 로봇 모델명 (optional)
  # 파이프라인: robo-scanner + robo-analyst → robo-exploiter → reporter
  ...
  ;;

supplychain)
  # TARGET = Git repo URL 또는 로컬 경로
  # SCOPE = 패키지 매니저 (npm/pip/maven, optional)
  # 파이프라인: sc-scanner + sc-analyst → sc-exploiter → reporter
  ...
  ;;
```

**사용법:**
```bash
./terminator.sh ai-security https://platform.openai.com "GPT-4o"
./terminator.sh robotics 192.168.1.100:11311 "Unitree-G1"
./terminator.sh supplychain https://github.com/org/repo "npm"
```

### 5.2 DAG 파이프라인 등록

**변경 파일:** `tools/dag_orchestrator/pipelines.py`

```python
def ai_security_pipeline(target_name: str = "target") -> AgentDAG:
    """AI/LLM Security pipeline: ai-recon+ai-analyst (parallel) → ai-exploiter → reporter"""
    dag = AgentDAG(name=f"ai_security_{target_name}", max_workers=2)

    # Phase 0
    dag.add_node(_make_node("target_evaluator", "target_evaluator", "sonnet",
                             "AI program analysis, model identification, scope check"))
    # Phase 1 (parallel)
    dag.add_node(_make_node("ai_recon", "ai-recon", "sonnet",
                             "Model fingerprinting, system prompt probing, tool enumeration"))
    dag.add_node(_make_node("ai_analyst", "ai-analyst", "sonnet",
                             "OWASP LLM Top 10 analysis, vulnerability classification"))
    # Phase 2
    dag.add_node(_make_node("ai_exploiter", "ai-exploiter", "opus",
                             "Jailbreak PoC, injection chains, agent hijack demos"))
    # Phase 3
    dag.add_node(_make_node("reporter", "reporter", "sonnet",
                             "Report + submission form"))
    # Phase 4
    dag.add_node(_make_node("critic", "critic", "opus",
                             "Fact-check AI-specific claims"))
    dag.add_node(_make_node("triager_sim", "triager_sim", "opus",
                             "Adversarial triage simulation"))
    # Phase 5
    dag.add_node(_make_node("reporter_final", "reporter", "sonnet",
                             "Final report"))

    # Edges
    dag.add_edge("target_evaluator", "ai_recon")
    dag.add_edge("target_evaluator", "ai_analyst")
    dag.add_edge("ai_recon", "ai_exploiter")
    dag.add_edge("ai_analyst", "ai_exploiter")
    dag.add_edge("ai_exploiter", "reporter")
    dag.add_edge("reporter", "critic")
    dag.add_edge("critic", "triager_sim")
    dag.add_edge("triager_sim", "reporter_final")
    dag.add_edge("triager_sim", "reporter", feedback=True)

    return dag


def robotics_pipeline(target_name: str = "target") -> AgentDAG:
    """Robotics/ROS pipeline: robo-scanner+robo-analyst (parallel) → robo-exploiter → reporter"""
    dag = AgentDAG(name=f"robotics_{target_name}", max_workers=2)

    dag.add_node(_make_node("target_evaluator", "target_evaluator", "sonnet",
                             "Robot model, ROS version, network accessibility"))
    dag.add_node(_make_node("robo_scanner", "robo-scanner", "sonnet",
                             "ROS topology, node enumeration, firmware extraction"))
    dag.add_node(_make_node("robo_analyst", "robo-analyst", "sonnet",
                             "Auth bypass, node spoofing, parameter tampering analysis"))
    dag.add_node(_make_node("robo_exploiter", "robo-exploiter", "opus",
                             "Node injection, topic hijack, firmware exploit PoC"))
    dag.add_node(_make_node("reporter", "reporter", "sonnet",
                             "CVE advisory report"))

    dag.add_edge("target_evaluator", "robo_scanner")
    dag.add_edge("target_evaluator", "robo_analyst")
    dag.add_edge("robo_scanner", "robo_exploiter")
    dag.add_edge("robo_analyst", "robo_exploiter")
    dag.add_edge("robo_exploiter", "reporter")

    return dag


def supplychain_pipeline(target_name: str = "target") -> AgentDAG:
    """Supply Chain pipeline: sc-scanner+sc-analyst (parallel) → sc-exploiter → reporter"""
    dag = AgentDAG(name=f"supplychain_{target_name}", max_workers=2)

    dag.add_node(_make_node("target_evaluator", "target_evaluator", "sonnet",
                             "Package manager detection, dependency count, CI/CD platform"))
    dag.add_node(_make_node("sc_scanner", "sc-scanner", "sonnet",
                             "SBOM generation, dependency tree, namespace conflicts"))
    dag.add_node(_make_node("sc_analyst", "sc-analyst", "sonnet",
                             "Dependency confusion, typosquatting, build pipeline analysis"))
    dag.add_node(_make_node("sc_exploiter", "sc-exploiter", "opus",
                             "Confusion PoC, pipeline exploitation, registry misconfig demo"))
    dag.add_node(_make_node("reporter", "reporter", "sonnet",
                             "Report or CVE advisory"))
    dag.add_node(_make_node("critic", "critic", "opus",
                             "Fact-check supply chain claims"))
    dag.add_node(_make_node("triager_sim", "triager_sim", "opus",
                             "Adversarial triage"))
    dag.add_node(_make_node("reporter_final", "reporter", "sonnet",
                             "Final report"))

    dag.add_edge("target_evaluator", "sc_scanner")
    dag.add_edge("target_evaluator", "sc_analyst")
    dag.add_edge("sc_scanner", "sc_exploiter")
    dag.add_edge("sc_analyst", "sc_exploiter")
    dag.add_edge("sc_exploiter", "reporter")
    dag.add_edge("reporter", "critic")
    dag.add_edge("critic", "triager_sim")
    dag.add_edge("triager_sim", "reporter_final")
    dag.add_edge("triager_sim", "reporter", feedback=True)

    return dag


# PIPELINES registry 확장
PIPELINES = {
    "ctf_pwn": ctf_pwn_pipeline,
    "ctf_rev": ctf_rev_pipeline,
    "bounty": bounty_pipeline,
    "firmware": firmware_pipeline,
    "ai_security": ai_security_pipeline,        # 추가
    "robotics": robotics_pipeline,               # 추가
    "supplychain": supplychain_pipeline,         # 추가
}
```

### 5.3 bb_preflight.py 확장

**추가 서브커맨드:**

```python
# --domain 파라미터 추가 (기존 서브커맨드에)
# init, rules-check, coverage-check가 domain별 다른 템플릿/임계값 사용

# 도메인별 임계값
COVERAGE_THRESHOLDS = {
    "bounty": 0.80,       # 기존
    "ai": 0.80,           # AI 엔드포인트 기준
    "robotics": 0.70,     # 물리 접근 제약으로 낮춤
    "supplychain": 0.80,  # 의존성 기준
}

# 도메인별 endpoint_map 파일명
ENDPOINT_MAP_FILES = {
    "bounty": "endpoint_map.md",
    "ai": "ai_endpoint_map.md",
    "robotics": "robo_endpoint_map.md",
    "supplychain": "sc_endpoint_map.md",
}
```

### 5.4 CLAUDE.md 업데이트

**Agent Model Assignment 테이블에 추가:**

```markdown
| ai-recon | sonnet | LLM endpoint mapping, model fingerprinting |
| ai-analyst | sonnet | OWASP LLM Top 10 analysis, vuln classification |
| ai-exploiter | opus | Jailbreak PoC, injection chains, agent hijack |
| robo-scanner | sonnet | ROS topology, node enumeration, firmware extraction |
| robo-analyst | sonnet | ROS auth bypass, node spoofing analysis |
| robo-exploiter | opus | Node injection, topic hijack, firmware exploit |
| sc-scanner | sonnet | SBOM generation, dependency tree, namespace conflicts |
| sc-analyst | sonnet | Dependency confusion, typosquatting, build pipeline |
| sc-exploiter | opus | Confusion PoC, pipeline exploit, registry misconfig |
```

**Pipeline Selection에 추가:**

```markdown
- **AI/LLM Security**: ai-recon + ai-analyst → ai-exploiter → reporter
- **Robotics/ROS**: robo-scanner + robo-analyst → robo-exploiter → reporter
- **Supply Chain**: sc-scanner + sc-analyst → sc-exploiter → reporter
```

### 5.5 settings.local.json 에이전트 등록

```json
{
  "agents": {
    "ai-recon": ".claude/agents/ai-recon.md",
    "ai-analyst": ".claude/agents/ai-analyst.md",
    "ai-exploiter": ".claude/agents/ai-exploiter.md",
    "robo-scanner": ".claude/agents/robo-scanner.md",
    "robo-analyst": ".claude/agents/robo-analyst.md",
    "robo-exploiter": ".claude/agents/robo-exploiter.md",
    "sc-scanner": ".claude/agents/sc-scanner.md",
    "sc-analyst": ".claude/agents/sc-analyst.md",
    "sc-exploiter": ".claude/agents/sc-exploiter.md"
  }
}
```

---

## 6. 파일 생성 체크리스트

> **구현 노트 (2026-04-05)**: 에이전트 수 최적화 적용 — 원래 9개 → 3개 신규 + 4개 기존 확장.
> analyst/exploiter/reporter는 `domain=` 태그로 도메인별 분기. 별도 에이전트 불필요.

### 신규 에이전트 (3개) — 도메인 전문 recon/scanner

| # | 파일 | 모델 | 색상 | 상태 |
|---|------|------|------|------|
| 1 | `.claude/agents/ai-recon.md` | sonnet | lime | ✅ 생성됨 |
| 2 | `.claude/agents/robo-scanner.md` | sonnet | teal | ✅ 생성됨 |
| 3 | `.claude/agents/sc-scanner.md` | sonnet | indigo | ✅ 생성됨 |

### 기존 에이전트 확장 (4개) — domain= 분기 추가

| # | 파일 | 추가 내용 | 상태 |
|---|------|----------|------|
| 4 | `.claude/agents/analyst.md` | domain=ai/robotics/supplychain 분석 기준 | ✅ 확장됨 |
| 5 | `.claude/agents/exploiter.md` | domain별 PoC 개발 지침 | ✅ 확장됨 |
| 6 | `.claude/agents/reporter.md` | CVE advisory 포맷 + domain별 리포트 | ✅ 확장됨 |
| 7 | `.claude/agents/triager_sim.md` | domain별 질문 세트 확장 | ✅ 확장됨 |

### 신규 스킬 (3개)

| # | 파일 | 트리거 키워드 |
|---|------|-------------|
| 10 | `.claude/skills/ai-security/SKILL.md` | ai security, llm bounty, prompt injection, jailbreak, ai red team |
| 11 | `.claude/skills/robotics/SKILL.md` | robotics, ROS, robot security, ROS2, industrial robot |
| 12 | `.claude/skills/supplychain/SKILL.md` | supply chain, dependency confusion, SBOM, npm audit, package security |

### Knowledge 파일 (6개)

| # | 파일 |
|---|------|
| 13 | `knowledge/techniques/ai_llm_security_reference.md` |
| 14 | `knowledge/techniques/ai_jailbreak_patterns.md` |
| 15 | `knowledge/techniques/robotics_ros_security_reference.md` |
| 16 | `knowledge/techniques/supplychain_security_reference.md` |
| 17 | `knowledge/protocol-vulns-index/categories/llm/` (6파일) |
| 18 | `knowledge/protocol-vulns-index/categories/robotics/` (6파일) |
| 19 | `knowledge/protocol-vulns-index/categories/supplychain/` (6파일) |

### 변경 파일 (5개)

| # | 파일 | 변경 내용 |
|---|------|----------|
| 20 | `terminator.sh` | 3개 mode case 추가, session_mode 분류 확장 |
| 21 | `tools/dag_orchestrator/pipelines.py` | 3개 파이프라인 함수 + PIPELINES 등록 |
| 22 | `tools/bb_preflight.py` | `--domain` 파라미터, 도메인별 임계값/파일명 |
| 23 | `CLAUDE.md` | Agent Model Assignment + Pipeline Selection 추가 |
| 24 | `knowledge/techniques/installed_tools_reference.md` | 도구 경로 추가 |

**총: 신규 19~31개 파일 + 변경 5개 파일**

---

## 7. 검증 계획

### 7.1 단위 테스트

```bash
# 1. 파이프라인 등록 확인
python3 -c "from tools.dag_orchestrator.pipelines import PIPELINES; print(list(PIPELINES.keys()))"
# Expected: [..., 'ai_security', 'robotics', 'supplychain']

# 2. 파이프라인 DAG 구조 검증
python3 -c "
from tools.dag_orchestrator.pipelines import get_pipeline
for name in ['ai_security', 'robotics', 'supplychain']:
    dag = get_pipeline(name, 'test')
    print(f'{name}: {len(dag.nodes)} nodes, {len(dag.edges)} edges')
"

# 3. terminator.sh dry-run
./terminator.sh --dry-run ai-security https://api.openai.com "GPT-4o"
./terminator.sh --dry-run robotics 192.168.1.100:11311 "Unitree-G1"
./terminator.sh --dry-run supplychain https://github.com/org/repo "npm"

# 4. bb_preflight domain 지원 확인
python3 tools/bb_preflight.py init targets/test/ --domain ai
python3 tools/bb_preflight.py init targets/test/ --domain robotics
python3 tools/bb_preflight.py init targets/test/ --domain supplychain
```

### 7.2 통합 테스트

```bash
# 1. AI Security — OpenAI Safety BBP 대상 dry-run
./terminator.sh --dry-run --json ai-security https://bugcrowd.com/openai "GPT-4o"

# 2. Robotics — 로컬 Gazebo 시뮬레이터 대상
# (Gazebo + turtlebot3 시뮬레이션 실행 후)
./terminator.sh --dry-run robotics localhost:11311 "turtlebot3"

# 3. Supply Chain — 공개 GitHub repo 대상
./terminator.sh --dry-run supplychain https://github.com/test/repo "npm"
```

### 7.3 도구 설치 검증

```bash
# AI/LLM
garak --help
promptfoo --version

# Robotics
ros2 --help  # 또는 docker run ros:humble ros2 --help

# Supply Chain
syft --version
grype --version
cdxgen --version
pip-audit --version
```

### 7.4 에이전트 스모크 테스트

각 에이전트를 단독으로 실행하여 기본 동작 확인:
```bash
# ai-recon 단독 테스트 (interactive 모드에서)
# → "ai-recon 에이전트로 https://api.openai.com 의 모델 프로파일링 수행"
# → model_profile.json 생성 확인

# sc-scanner 단독 테스트
# → "sc-scanner 에이전트로 https://github.com/expressjs/express SBOM 분석"
# → sbom.json + sc_endpoint_map.md 생성 확인
```
