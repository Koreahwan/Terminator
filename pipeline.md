> **Note**: The bug bounty pipeline has been upgraded to v12 (Explore Lane + Kill Gate). See `.claude/rules/bb_pipeline_v12.md` for the current procedure. This document contains historical pipeline documentation.

# 1. GPT




나의 말:
https://github.com/R00T-Kim/Terminator

아주 딥하게 이 파이프라인을 분석해봐/ 철저하게 객관적으로 / 26년 2월 22일 최신을 감안

ChatGPT의 말:

1m 4s 동안 생각함
아래 평가는 2026-02-22 기준, 공개된 R00T-Kim/Terminator 레포지토리의 README/런처 스크립트/구성 파일/에이전트 정의를 근거로 객관적으로 정리한 “파이프라인(운영 모델) 분석”입니다. 

1) 이 시스템의 “파이프라인” 정의(실체)
Terminator는 본질적으로 Claude Code Agent Teams를 “순차 파이프라인 + 산출물(artifact) 핸드오프”로 표준화한 운영체계입니다. (CTF, Bug Bounty, Firmware 등 모드별로 단계가 다름) 

CTF 파이프라인: reverser → (trigger) → chain/solver → critic → verifier → reporter 형태로 문제 타입에 따라 가변 선택 

Bug Bounty v3 (7 phases): ROI/GO-NO-GO → 자동 스캔 → 분석/헌팅 → PoC 게이트 → 리포트 → 리뷰/프레이밍 → triage simulation → 패키징 

핵심 “철칙”: “No Exploit, No Report”(PoC 없으면 버림) 

이건 단순 “에이전트 여러 개”가 아니라,

단계별 책임 분리, 2) 단계 산출물 표준화, 3) 게이트(품질/승인) 삽입, 4) 관측/대시보드/DB로 상태화까지 포함한 “운영 파이프라인”에 가깝습니다. 

2) 파이프라인의 강점(설계적으로 잘 잡힌 지점)
A. “역할 분리 + 검증 루프”가 명시적
reverser는 분석만, chain/solver는 구현/풀이만, critic은 교차검증만, verifier는 재현/원격 획득만 등 역할 경계가 문서로 강제됩니다. 

특히 reverser 에이전트 정의에 “정확한 주소/오프셋, GDB로 상수 검증” 같은 수치 정확성 강제 규칙이 들어가 있습니다. 

B. “실패 시 전략 전환(dual-approach)”을 정책화
3회 실패 시 서로 다른 접근법 병렬화, 5회 실패 시 외부 검색 강제 같은 운영 규칙이 파이프라인 레벨에 박혀 있습니다. 

→ 이건 LLM 특유의 “같은 실수 반복”을 운영정책으로 억제하려는 의도가 명확합니다.

C. Bug bounty에서 “트리아저 관점 시뮬레이션”을 파이프라인 단계로 포함
triager_sim 에이전트는 “리젝 사유를 30초 만에 찾는” 역할로 정의되어 있고, 제출 직전 게이트로 배치됩니다. 

→ 리포팅 품질(팩트/임팩트/재현성/문서 구성)을 실제로 끌어올리기 좋은 구조입니다.

3) 인프라/구현 관점에서의 파이프라인(실행·상태·저장)
A. 실행 엔트리포인트: terminator.sh (Autonomous launcher)
ctf, bounty, firmware 모드를 하나의 런처로 통합하고, 리포트 디렉터리 생성 → 백그라운드 실행 → session.log/summary.json/exit_code 생성 흐름이 있습니다. 

summary.json 자동 생성과, tools/report_generator.py로 SARIF/PDF 생성까지 자동 후처리를 시도합니다. 

B. Full-stack 모드: Docker Compose로 RAG/Graph/Proxy를 한 번에 올림
docker-compose.yml에 다음이 묶여 있습니다:

pgvector(Postgres): 벡터 DB (RAG 저장)

ollama: 로컬 임베딩/모델

rag-api: PoC/ExploitDB 등 지식 검색 API

neo4j: 공격 표면 그래프

litellm: 멀티 모델 프록시(Claude/Gemini/DeepSeek 키)

web-ui: 대시보드 

이 구성은 “에이전트 산출물을 파일로만 두지 않고, 검색/재사용 가능한 지식(벡터) + 관계 그래프(Neo4j)로 축적”하려는 방향성이 뚜렷합니다. 

4) 객관적 리스크/불일치 포인트 (중요)
A. 런처가 --permission-mode bypassPermissions 기반
CTF/버그바운티 실행이 claude ... --permission-mode bypassPermissions로 설계되어 있습니다. 

→ 이건 “도구/파일/네트워크 접근을 강하게 허용”하는 성격이라, 프롬프트 인젝션·악성 입력(CTF 파일/웹컨텐츠)이 들어왔을 때 운영환경이 털릴 위험이 커집니다.
레포는 “guardrails”를 언급하지만(윤리/보호), 강제 장치가 정책/문서 위주라면 실제 격리는 OS/컨테이너/권한분리로 보강되어야 합니다. 

B. CLAUDE.md의 “general-purpose 금지”와 런처 프롬프트의 충돌 가능성
CLAUDE.md는 general-purpose 사용 금지(커스텀 에이전트만)라고 명시합니다. 

그런데 terminator.sh 내부 프롬프트 일부는 subagent_type=general-purpose라는 문구가 보입니다. 

→ 문서 규칙과 실제 런처 템플릿이 엇갈리면, 운영 중 “규칙이 지켜진다는 착시”가 생기고 재현성이 깨집니다. (이건 품질/거버넌스 리스크입니다.)

C. Compose에 API Key/마스터키/DB 비번 등 시크릿 취급의 표준 미흡
litellm이 여러 API 키를 환경변수로 받게 되어 있고, LITELLM_MASTER_KEY 기본값도 보입니다. 

→ 실사용에서는 .env/secret manager/키 회전/권한 분리(특히 DB/Neo4j) 같은 운영 표준이 필요합니다. “연구용 로컬”이라도 기본값이 남아 있으면 사고 가능성이 커져요.

D. “CTF/버그바운티/펌웨어”가 한 레포에 공존하면서 안전 경계가 흐려질 수 있음
레포는 승인된 대상에서만 사용한다는 원칙을 명시하지만, 런처는 모드 전환만으로 강한 권한 실행을 합니다. 

→ 실수로 bounty 모드로 외부 타겟에 과격한 자동화를 돌리는 운영 사고(스코프 위반/약관 위반)가 일어나기 쉬운 구조입니다.

5) 파이프라인을 “더 강하게” 만들기 위한 개선 제안(객관식)
아래는 “기능 추가”보다 운영 안정성/검증성/안전성 관점 제안입니다.

실행 격리(샌드박스) 강제

bypassPermissions를 그대로 쓰더라도, 호스트 권한이 아니라 컨테이너/VM + 읽기전용 마운트 + 네트워크 egress 제어 같은 물리적 격리로 “최악의 경우 피해 범위”를 잘라야 합니다.

규칙-실행 템플릿 일치 테스트

CLAUDE.md 규칙(커스텀 에이전트만)을 CI에서 lint로 검사: 예) 런처 프롬프트에 general-purpose 등장 시 실패 처리.

파이프라인의 신뢰성은 “문서”가 아니라 “자동 검증”이 잡습니다.

게이트를 로그 문자열이 아니라 “구조화 이벤트”로

현재 요약은 session.log에서 [CRITICAL] 같은 문자열을 grep해서 집계합니다. 

장기적으로는 각 단계가 JSONL 이벤트(phase, claim, evidence refs)를 남기고, 대시보드/리포트가 그 이벤트를 소비하는 형태가 더 견고합니다.

PoC 품질 게이트를 더 기계적으로

“No Exploit, No Report”는 강력하지만, “exploit”의 정의가 사람/모델마다 흔들릴 수 있습니다. 

최소 기준(재현 스크립트 exit code, 증거 캡처, 대상 버전 식별, 안전 페이로드 등)을 스키마로 고정하면 triager_sim의 효용이 커집니다.

결론(한 문장)
Terminator의 파이프라인은 “에이전트 협업”을 넘어서 품질 게이트·검증 루프·지식화(RAG/Graph)·제출 전 트리아저 시뮬레이션까지 묶은 운영체계로 설계가 꽤 탄탄한 편인데, 동시에 bypassPermissions 기반 자동 실행과 문서-실행 템플릿 불일치 가능성 같은 이유로 보안 격리/거버넌스 자동검증이 없으면 운영 리스크가 커지는 구조입니다. 

원하면, 내가 레포 기준으로 (1) “CTF/BB/FW 각각의 단계별 입력·출력 아티팩트 스키마”를 재정의해서 “파이프라인 명세서(표준)” 형태로 뽑아줄게요.


나의 말:
그럼 이걸 한 차원 더 높은 수준으로 끌어올리려면 어떤게 필요할 것 같아?

ChatGPT의 말:
한 차원 더 “위”로 올린다는 걸 (1) 재현성, (2) 신뢰도(증거 기반), (3) 안전한 자동화, (4) 지식 축적/재사용, (5) 비용 대비 성과(ROI) 관점에서 보면, 지금 Terminator가 다음 5가지를 갖추면 급이 달라져요.

1) 파이프라인을 “워크플로 엔진”으로 격상
지금은 런처 + 에이전트 협업(사실상 오케스트레이션)이 중심인데, 상위 단계는 상태기계(state machine)/DAG로 승격시키는 겁니다.

각 phase를 명시적 상태로 정의: inputs → actions → outputs → acceptance_criteria → next_state

실패/재시도 정책을 코드로(문서가 아니라): retry, fallback, human-in-the-loop

“어떤 근거로 GO/NO-GO가 났는지”를 상태 전이 로그로 남김

효과: 재현성, 디버깅, 팀 협업, 품질 게이트가 다 좋아져요.

2) 증거 중심(Evidence-first) 스키마와 자동 검증
“리포트”보다 한 단계 위는 “리포트를 자동 생성할 수 있는 증거 레이크”입니다.

모든 주장(claim)을 claim_id로 만들고

각 claim에 evidence_refs(로그, 파일, 스냅샷, 트레이스, 버전 식별)를 연결

verifier/critic이 스키마 검증(필수 증거 누락 시 빌드 실패처럼 fail)

핵심은 “멋진 글”이 아니라 증거가 먼저고, 글은 증거에서 자동으로 내려오게 만드는 것.

3) 안전/격리: “bypassPermissions”를 시스템적으로 무해화
고도화된 자동화는 항상 입력(웹/파일/바이너리/트래픽)에서 인젝션이 들어와요.
상위 단계는 “프롬프트 가드”가 아니라 실행 격리로 해결합니다.

모드별 샌드박스 프로파일(CTF/BB/FW)

읽기 전용 마운트, egress 제한, 토큰/키는 최소권한+짧은 수명

위험 도구는 별도 컨테이너로 격리해서 “최악의 경우 피해 범위”를 잘라냄

효과: 파이프라인이 커질수록 필수입니다(안 하면 언젠가 터짐).

4) 평가(Evals)·벤치마크: “성능이 좋아졌다”를 숫자로 만들기
진짜 상위 레벨은 개선을 감으로 하지 않아요.

고정된 테스트셋(내부 케이스/샘플 타겟/과거 보고서)

지표: 재현 성공률, false positive 비율, triage 통과율, 평균 시간/토큰, “증거 커버리지”

변경(프롬프트/에이전트/툴/검색)할 때마다 회귀 테스트

이걸 갖추면 Terminator는 “프로젝트”에서 “제품”이 됩니다.

5) 지식 축적을 “RAG”를 넘어 “케이스 기반 추론(CBR) + 그래프”로
지금도 pgvector/neo4j 방향성이 있는데, 한 차원 위는:

케이스를 표준 객체로 저장: target_profile, attack_surface, hypotheses, failed_paths, successful_paths, indicators

다음 분석에서 “유사 케이스”를 찾아 플레이북을 자동 제안

그래프는 “멋진 시각화”가 아니라 “다음 액션 후보 생성기”로 사용

효과: 시간이 갈수록 점점 더 빨라지고 정확해지는 시스템이 됩니다(학습 곡선이 팀이 아니라 시스템에 남음).

우선순위 추천(가장 임팩트 큰 3개)
워크플로 엔진(DAG/state machine)화

Evidence-first 스키마 + 자동 게이트

실행 격리/권한 최소화

이 3개만 잡아도 “데모용 에이전트 파이프라인”에서 “운영 가능한 자동 분석 플랫폼”으로 올라갑니다.

원하면, 네 레포 구조(CTF/BB/FW)를 기준으로 Phase 스키마(JSON) + 상태 전이 규칙 + acceptance criteria 템플릿을 바로 만들어서 “표준”으로 박아줄게요.


---

# 2. Gemini

Gemini
Terminator 파이프라인 심층 분석
Gemini와의 대화
말씀하신 내용
https://github.com/R00T-Kim/Terminator



아주 딥하게 이 파이프라인을 분석해봐/ 철저하게 객관적으로 / 26년 2월 22일 최신을 감안

Gemini의 응답
제시해주신 R00T-Kim/Terminator 리포지토리의 파이프라인 아키텍처와 시스템 설계에 대해 2026년 2월 22일 최신 기술 동향을 기준으로 철저하게 객관적이고 심층적인 분석을 진행한 결과입니다.

1. 아키텍처 개요 및 설계 철학
이 시스템은 단순한 챗봇 형태나 무한 루프 방식의 자율 에이전트(AutoGPT 등)가 아닌, DAG(Directed Acyclic Graph) 기반의 순차적 파이프라인과 구조화된 핸드오프(Structured Handoffs) 를 채택한 다중 에이전트(Multi-agent) 시스템입니다.

설계적 우수성: 17개의 특화 에이전트를 역할(Reverser, Exploiter, Critic 등)별로 분리하고, Claude Code Agent Teams를 오케스트레이터로 사용하여 각 에이전트가 자신의 컨텍스트에만 집중하도록 설계되었습니다.

실용주의적 접근 ("No Exploit, No Report"): 작동하는 PoC(Proof of Concept)가 없으면 보고서를 생성하지 않도록 설계된 점은 LLM 보안 툴의 고질적인 문제인 오탐(False Positive)과 환각(Hallucination)을 물리적으로 차단하는 훌륭한 게이트웨이 역할을 합니다.

2. 도메인별 파이프라인 심층 분석
① CTF 파이프라인 (바이너리 분석 및 익스플로잇)

흐름: reverser → trigger → chain/solver → critic → verifier

객관적 평가: verifier 에이전트가 로컬 환경에서 3회 반복 검증을 거친 후 원격 실행을 수행하는 로직은 매우 견고합니다. critic을 통한 오프셋 및 로직 교차 검증은 LLM의 연산 오류를 보완합니다.

한계점: 복잡한 힙(Heap) 익스플로잇이나 커스텀 VM 리버싱의 경우, Opus 모델이라 할지라도 z3-solver나 angr 등의 심볼릭 실행 도구와 완벽하게 상호작용하기 위해서는 매우 정교한 상태 추적(State Tracking)이 필요합니다. 컨텍스트 윈도우 한계로 인해 대규모 바이너리에서는 reverser의 초기 매핑이 누락될 위험이 존재합니다.

② 버그 바운티 파이프라인

흐름: target_evaluator → scout → analyst → exploiter → triager_sim

객관적 평가: 공격 수행 전 target_evaluator로 프로그램의 ROI(투자 대비 효용)를 평가하여 리소스를 아끼고, 제출 전 triager_sim을 통해 적대적 시뮬레이션(Adversarial Triage)을 진행하는 것은 실무 해커의 워크플로우를 정확히 모델링한 것입니다.

한계점: 2026년 현재 웹 타겟의 경우 고도화된 WAF(웹 방화벽), CAPTCHA, 동적 DOM 렌더링 등으로 인해 순수 API 기반 스캐닝이나 자동화 봇 접근이 엄격히 차단됩니다. 따라서 스마트 컨트랙트나 정적 소스코드 오딧(Audit)에서는 높은 성과를 보일 수 있으나, 블랙박스 웹 바운티에서는 자동화의 한계에 부딪힐 확률이 높습니다.

③ 펌웨어 파이프라인

흐름: fw_profiler → fw_inventory → fw_surface → fw_validator

객관적 평가: 정적 아키텍처 탐지와 QEMU 기반의 동적 에뮬레이션을 결합한 접근은 IoT 및 임베디드 취약점 헌팅에 필수적인 구성을 갖추고 있습니다.

3. 인프라 및 최신 기술 스택 도입 현황 (2026년 기준)
MCP (Model Context Protocol) 지원: 외부 보안 도구(Nuclei, CodeQL, Semgrep 등)를 에이전트와 표준화된 인터페이스로 연결하는 MCP 서버 구현은 2026년 AI 기반 개발/보안 도구의 핵심 표준을 정확히 따르고 있습니다.

RAG 및 지식 그래프: 단순 벡터 DB(pgvector)를 넘어 Neo4j를 활용한 공격 표면(Attack Surface) 그래프 시각화는 취약점 간의 연계성(Chaining)을 파악하는 데 강력한 인사이트를 제공합니다.

4. ⚠️ 철저히 객관적인 시스템의 한계 및 리스크 요소
에러 전파 (Cascading Failures)의 위험성:
파이프라인이 순차적(Sequential)이기 때문에, 초기 단계(예: reverser 또는 scout)에서 핵심 공격 벡터를 놓치거나 오판할 경우 후속 에이전트들이 잘못된 단서를 바탕으로 토큰과 컴퓨팅 리소스를 소모하게 되는 '삽질' 현상이 발생할 수 있습니다.

API 비용 및 속도 문제:
오케스트레이터 및 핵심 익스플로잇 생성에 가장 무거운 모델(Opus)이 배치되어 있습니다. 자율 모드로 대규모 버그 바운티 타겟을 병렬 스캐닝할 경우, Anthropic API 토큰 비용이 기하급수적으로 발생할 수 있으며 Rate Limit에 의한 파이프라인 병목이 우려됩니다.

과도한 환경 의존성:
Docker를 활용한 Full Stack 모드가 존재하지만, Standalone 모드의 경우 gdb, radare2, pwntools, 16개의 시스템 PATH 보안 도구 등 호스트 OS의 환경에 시스템이 지나치게 강하게 결합(Tightly coupled)되어 있습니다. 실행 환경의 미세한 버전 차이가 검증 단계의 실패로 직결될 수 있습니다.

총평
Terminator 파이프라인은 Google Big Sleep, ATLANTIS 등 최신 LLM 보안 연구의 핵심 패턴(Variant Analysis, Hybrid Symbolic, Tiered Gates)을 성공적으로 엔지니어링한 A급 아키텍처입니다.

다만, 시스템의 실질적인 파괴력은 LLM의 자율성 자체보다는 연결된 로컬 보안 도구들의 정확도와 초기 프롬프트(Initial Context)의 질에 의해 결정될 것입니다. 현재 구조는 완전한 무인 자율 시스템이라기보다는, 복잡한 검증 로직을 자동화하여 전문가의 개입을 최소화하는 최상위 수준의 오펜시브 보안 코파일럿(Offensive Security Copilot) 에 가깝습니다.

말씀하신 내용
그럼 이걸 한 차원 더 높은 수준으로 끌어올리려면 어떤게 필요할 것 같아?

Gemini의 응답
현재의 Terminator 파이프라인은 이미 훌륭한 수준이지만, 이를 단순한 '고급 자동화 스크립트'를 넘어 진정한 의미의 자율형 오펜시브 AI(Autonomous Offensive AI) 로 한 차원 더 끌어올리기 위해서는 아키텍처의 근본적인 체급을 높이는 작업이 필요합니다.

철저하게 객관적이고 엔지니어링 관점에서 다음 5가지의 핵심적인 진화 방향을 제안합니다.

1. 정적(Static) 파이프라인에서 비선형 트리를 통한 상태 추적(Stateful MCTS)으로 전환
현재의 DAG(방향성 비순환 그래프) 기반 순차적 핸드오프는 이전 단계의 에러가 후속 단계로 전파되는 치명적인 단점이 있습니다.

개선 방안: 파이프라인을 몬테카를로 트리 탐색(MCTS)이나 Tree of Thoughts 방식으로 개편해야 합니다. reverser가 제시한 공격 표면(Attack Surface)이 막혔을 때 단순히 파이프라인을 종료하는 것이 아니라, 실패 상태(State)를 저장하고 이전 분기점으로 되돌아가 다른 ROP Chain이나 취약점 트리거 방식을 시도하는 자동 백트래킹(Backtracking) 로직이 필수적입니다.

2. 코어 엔진의 퍼포먼스와 동시성 극대화
현재 구조는 Python 스크립트와 쉘을 통해 제어되므로, 대규모 타겟을 병렬로 처리하거나 무거운 로컬 툴을 오케스트레이션할 때 병목 현상이 발생하기 쉽습니다.

개선 방안: 빠르고 안정적인 데이터 시스템과 강력한 클라이언트 툴링을 구축하기 위해 오케스트레이터(Orchestrator) 엔진을 Go 또는 Rust로 재작성하는 것을 고려해 볼 수 있습니다. 메모리 안전성을 챙기면서도 초당 수천 개의 상태를 비동기적으로 관리하고, 여러 에이전트 스레드를 동시다발적으로 제어하는 데 압도적인 성능을 발휘할 수 있습니다.

3. 사이버 공격 흐름 분석(Cyber Attack Flow Analysis) 및 영구적 그래프 메모리
현재 시스템은 각 세션의 결과물(Finding, Flag)을 수집하는 데 그치고 있습니다.

개선 방안: 단순한 취약점 스캐닝을 넘어, 타겟 시스템에 침투하는 전체적인 사이버 공격 흐름 분석을 수행하고 이를 에이전트의 영구적인 지식 그래프(Knowledge Graph) 메모리에 학습시켜야 합니다. 예를 들어, 한 번 성공했던 특정 라이브러리의 힙 익스플로잇 패턴이나 권한 상승 우회 기법을 시스템이 '기억'하고, 이후 유사한 바이너리 구조를 만났을 때 RAG(Retrieval-Augmented Generation)를 통해 그 공격 흐름을 즉시 꺼내어 적용할 수 있는 구조가 필요합니다.

4. 타겟 도메인의 딥-다이빙: 임베디드 및 자동차 보안(Automotive Security)
단순한 웹 바운티나 표준 Pwnable CTF는 AI 에이전트 간의 경쟁이 가장 치열한 레드오션이 될 것입니다. 시스템의 가치를 극대화하려면 물리적인 디바이스 영역으로 타겟을 넓혀야 합니다.

개선 방안: 스마트 도어벨과 같은 임베디드 기기의 펌웨어 취약점이나 어플리케이션 단의 분석, 더 나아가 차량 내부의 CAN 버스 통신 프로토콜을 분석하고 퍼징할 수 있는 특화 에이전트(예: can_analyzer, embedded_reverser)를 추가하는 것입니다. 하드웨어 에뮬레이션(QEMU)과 LLM을 결합하여 펌웨어 내부의 네트워크 프로토콜 취약점을 자동으로 식별하는 로직은 독보적인 경쟁력이 됩니다.

5. LLM과 심볼릭 실행(Symbolic Execution)의 완전한 하이브리드화
LLM은 '어디가 취약할 것 같다'는 직관을 제공하는 데는 뛰어나지만, 정확한 오프셋을 계산하거나 메모리 제약 조건을 푸는 데는 종종 환각(Hallucination)을 일으킵니다.

개선 방안: LLM이 공격의 방향성과 초기 시드(Seed)를 생성하면, angr나 z3-solver, 혹은 커스텀 fuzzer가 이 시드를 바탕으로 정확한 수학적 제약 조건을 연산하여 익스플로잇 코드를 완성하는 강결합(Tight-coupling) 구조를 만들어야 합니다. LLM은 '전략'을 짜고, 검증과 연산은 철저하게 '결정론적 도구'가 수행하도록 역할을 명확히 분리하는 것입니다.

현재 파이프라인 구조에서 가장 먼저 개선해보고 싶은 모듈이나, 더 깊게 파고들고 싶은 특정 도메인(예: 코어 엔진의 언어 마이그레이션, 혹은 임베디드/펌웨어 분석 에이전트 설계 등)이 있다면 구체적인 아키텍처 설계 초안을 함께 잡아볼까요?





Gemini는 AI이며 인물 등에 관한 정보 제공 시 실수를 할 수 있습니다. 개인 정보 보호 및 Gemini새 창에서 열기

---

# 3. Cluade

생각해보기: GitHub 저장소의 파이프라인을 객관적으로 심층 분석하기
생각해보기: GitHub 저장소의 파이프라인을 객관적으로 심층 분석하기

먼저 레포지토리 내용을 전체적으로 파악하겠습니다.


저장소 구조 파악 후 핵심 컴포넌트들을 심층 분석하려 준비했다
저장소 구조 파악 후 핵심 컴포넌트들을 심층 분석하려 준비했다


README를 확인했습니다. 이제 핵심 구현 파일들을 깊이 파악하겠습니다.


저장소를 복제하여 파이프라인을 분석하려 계획했다
저장소를 복제하여 파이프라인을 분석하려 계획했다



직접 클론해서 분석하겠습니다.


128개 파일을 체계적으로 검토하기 시작했다
128개 파일을 체계적으로 검토하기 시작했다



이제 핵심 파일들을 순차적으로 분석합니다.


심층 분석을 위해 정보를 수집하고 종합했다
심층 분석을 위해 정보를 수집하고 종합했다




















이제 충분한 데이터를 확보했습니다. 종합 분석 문서를 작성합니다.


파이프라인을 심층 분석하는 마크다운 문서 작성 결정
파이프라인을 심층 분석하는 마크다운 문서 작성 결정

분석이 완료되었습니다. 종합 분석 문서를 작성합니다.


GitHub 파이프라인을 객관적으로 분석 준비 완료
GitHub 파이프라인을 객관적으로 분석 준비 완료

Create deep analysis document of the Terminator pipeline
terminator_analysis.md
Let me present the file and give a concise summary.


Presented file
Done. Let me summarize the key findings.

완료
128개 파일, ~30,000줄을 전수 분석한 결과입니다. 핵심만 요약하면:

진짜 강한 것: 프롬프트 엔지니어링 품질이 압도적. reverser의 "r2가 ARM Thumb-2에서 2건 오분류" → Ghidra 강제 같은 교훈-주도 설계, triager_sim의 adversarial self-review, 실패 기록을 투명하게 남기고 다음 iteration에 반영하는 사이클이 프로젝트의 진정한 가치.

객관적 한계:

오케스트레이션이 프롬프트 의존: dag.py가 존재하지만 실제 에이전트 스폰은 Claude Code가 프롬프트를 따르는 것에 의존 → deterministic 보장 없음
풀이 난이도 편향: 20문제 중 easy 55%, hard pwn은 0건, custom allocator/heap 문제 전부 실패/중단
바운티 수익 $0: 28+ 타겟 평가했지만 확인된 수익 없음 (거절/duplicate/제출 미완)
firmware 파이프라인 미완성: bridge/ 스크립트들이 레포에 부재, 에이전트 정의도 합계 138줄로 빈약
테스트 코드 0%: 5,200줄 Python 도구에 unit test 없음
포지션: XBOW/ATLANTIS 같은 상용 시스템과는 거리가 있지만, 공개된 보안 멀티에이전트 시스템 중 가장 체계적인 참조 구현체. "LLM agent의 한계를 정직하게 기록한 실험 일지"로서의 가치가 가장 큼.

# Terminator Pipeline 심층 분석 보고서

**분석 일자**: 2026-02-23  
**분석 대상**: github.com/R00T-Kim/Terminator (최종 커밋: 2026-02-22)  
**분석 방법**: 전체 128개 파일, ~30,000 LOC 정적 분석 + 아키텍처 리뷰  

---

## 1. 한 줄 정의

Claude Code의 Agent Teams 기능 위에 구축된 **프롬프트 엔지니어링 중심의 멀티에이전트 보안 오케스트레이션 프레임워크**. 17개 에이전트 정의(~4,500줄 마크다운)가 핵심이고, 그 주변에 대시보드/RAG/도구 래퍼/벤치마크 인프라를 붙인 구조.

---

## 2. 아키텍처 분해

### 2.1 계층 구조

```
Layer 4  ─ CLAUDE.md (Orchestrator prompt, 648줄)
           → 파이프라인 선택 로직, 모델 매핑, handoff 프로토콜
           
Layer 3  ─ .claude/agents/*.md (17개 에이전트, 4,556줄)
           → 각 에이전트의 미션/도구/출력형식/자기점검 규칙
           
Layer 2  ─ tools/ (Python tooling, ~5,200줄)
           → DAG 오케스트레이터, MITRE 매퍼, SARIF, MCP 래퍼
           
Layer 1  ─ web/ (대시보드, ~2,500줄)
           → FastAPI + D3 + WebSocket 실시간 모니터링

Layer 0  ─ terminator.sh (런처, 924줄)
           → Autonomous 모드 진입점, nohup + claude CLI 호출
```

**핵심 통찰**: Layer 3-4(프롬프트)가 실제 파이프라인의 **두뇌**이고, Layer 0-2는 **보조 인프라**. 전통적인 소프트웨어와 달리 "핵심 로직"이 마크다운에 있다.

### 2.2 파이프라인 종류별 에이전트 흐름

| 파이프라인 | 에이전트 수 | 모델 비용 가중치 | 트리거 조건 |
|-----------|-----------|----------------|-----------|
| Trivial CTF | 1 (ctf-solver) | sonnet×1 | 소스 제공, 1-3줄 버그 |
| Pwn (명확) | 5 | sonnet×3 + opus×2 | BOF/FSB 명확 |
| Pwn (불명확) | 6 | sonnet×3 + opus×3 | crash discovery 필요 |
| Rev/Crypto | 5 | sonnet×3 + opus×2 | 역연산/수학 |
| Web | 4 | sonnet×3 + opus×1 | injection/SSRF |
| Bug Bounty v3 | 7 phases, ~8 에이전트 | 혼합 | target URL 제공 |
| Firmware | 4 | sonnet×4 | .bin 제공 |

---

## 3. 강점 분석 (객관적 기여)

### 3.1 프롬프트 엔지니어링의 교과서적 심도

에이전트 프롬프트가 단순 지시가 아니라 **교훈-주도 엔지니어링**이다. 구체적으로:

- **reverser.md**: "r2 decompiler가 ARM Thumb-2에서 2건 오분류" → Ghidra MCP를 PRIMARY로 강제하고 r2는 strings/xref 전용으로 격리. **실패 경험에서 추출한 구체적 tool policy**.

- **chain.md**: "Python forward reimplementation으로 검증하는 것은 순환 검증이다" → binary verification 강제. 이건 LLM agent의 **자기확증 편향(self-confirmation bias)** 에 대한 실질적 대응.

- **triager_sim.md**: H1 triager를 롤플레이하는 adversarial agent. "AI slop 40%+ 위기" → 10-point 체크리스트로 자체 보고서 필터링. 이 개념 자체가 연구 수준.

- **CLAUDE.md**: "Early Critic" 도입 이유로 "unibitmap에서 canary 도달 가능 오보가 1384줄 코드 폐기를 초래" 명시. **실제 실패 사례가 아키텍처 결정의 근거**.

### 3.2 연구 기반 패턴 통합 (10+ 프레임워크)

research/ 디렉토리의 14개 문서(~7,000줄)가 단순 참고가 아니라 에이전트 정의에 직접 반영:

| 원천 패턴 | 적용 위치 | 구현 수준 |
|----------|---------|---------|
| XBOW "No Exploit, No Report" | Bug Bounty Phase 2 IRON RULE | 완전 통합 |
| ATLANTIS Symbolic+Neural Hybrid | reverser.md → Solver Strategy 섹션 | 가이드라인 |
| RoboDuck Dual-Approach | CLAUDE.md 3회 실패 시 자동 트리거 | 프로토콜 정의 |
| Vulnhuntr 3-pass backtracing | analyst.md source→sink 추적 | 완전 통합 |
| CAI Prompt Injection Guardrails | CLAUDE.md 마지막 섹션 | 방어 규칙 |
| PentestGPT Never-Give-Up | chain.md 4단계 fallback | 완전 통합 |
| Devin Think-Before-Act | 전 에이전트 공통 프로토콜 | 프로토콜 정의 |
| Devin Env Issue Reporting | 전 에이전트 ENV BLOCKER 형식 | 프로토콜 정의 |

### 3.3 실증적 트랙 레코드

20개 CTF 풀이(pwnable.kr 위주 + dreamhack), 28+ 버그바운티 타겟 평가는 **실제 운영 기록**이 knowledge/에 축적됨:

- 풀이 성공 20건 (easy~hard, pwn/rev/crypto/misc)
- 실패/중단 6건 (custom allocator, 379MB 바이너리, WASM)
- 버그바운티 제출 기록 (stake.link 거절, Vercel 5건 중 2건 duplicate, CapyFi 6hr/$0)

**실패 기록의 투명한 보존**이 이 프로젝트의 가장 큰 차별점 중 하나. bugbounty_retrospective_v1.md에서 패턴을 추출해 v3 파이프라인에 반영.

### 3.4 토큰 효율성에 대한 집착

- 에이전트별 모델 강제 지정 (sonnet vs opus), 미지정 시 "파이프라인 위반"
- 500줄+ 코드 → Gemini CLI로 1차 분석 후 Claude에 전달 (토큰 절약)
- "6-agent 풀 파이프라인을 무조건 쓰지 말 것" → adaptive pipeline selection
- chain.md의 200줄 phase 제한 → 대형 exploit 한 번에 작성 방지

### 3.5 인프라 듀얼 모드

Standalone (Python + 파일시스템만)과 Full Stack (Docker 6서비스)의 분리가 **진입 장벽을 낮추면서도 확장성 확보**. 특히 filesystem.py가 마크다운에서 CVSS를 regex로 추출해 114+ findings를 집계하는 건 실용적.

---

## 4. 약점 및 한계 분석 (철저하게 객관적으로)

### 4.1 핵심 한계: "오케스트레이션" 은 프롬프트에 의존

**DAG 오케스트레이터(dag.py, 251줄)가 존재하지만 실제로 Claude Code CLI가 에이전트를 스폰하는 구조와 연결되지 않는다.**

- dag.py는 `handler: Optional[Callable]`로 노드를 실행하는 범용 DAG인데, 실제 에이전트 스폰은 `Task(subagent_type="reverser", ...)` 형태로 Claude Code가 내부적으로 처리
- agent_bridge.py(214줄)가 중개를 시도하지만, Claude Code의 sub-agent 스폰은 **프롬프트 레벨에서 지시**하는 것이지 Python API로 제어하는 게 아님
- 즉, CLAUDE.md의 "reverser → chain → critic → verifier" 순서는 **LLM이 지시를 따르는 것에 의존**. 이것이 deterministic하지 않다는 근본적 한계

**영향**: 에이전트 순서 위반, 빠뜨림, 중복 스폰이 가능하며 이를 프로그래밍적으로 방지하는 메커니즘이 없음. CLAUDE.md의 "idle recovery 프로토콜"이 이 문제의 증거.

### 4.2 벤치마크의 한계: 메타데이터 기반

benchmark.py(484줄)는 실제로 챌린지를 다시 풀지 않는다. `SOLVED_CHALLENGES` 딕셔너리에 하드코딩된 메타데이터에서 통계를 생성:

```python
"pwnablekr_fd": {
    "type": "pwn",
    "flag": "mommy! I think I know what a file descriptor is!!",
    "technique": "file descriptor manipulation",
    ...
}
```

- solve_time, token_estimate가 대부분 None → 실제 성능 메트릭 부재
- "accuracy 80% threshold" CI 체크가 있지만, writeup 파일이 없으면 SKIP 처리되어 accuracy가 과대계상될 수 있음
- **End-to-end replay 벤치마크가 아님** → 파이프라인 리그레션 감지 불가

### 4.3 CTF 난이도 분포의 편향

풀이한 20문제 중:

| 난이도 | 수량 | 비율 |
|-------|-----|------|
| Easy | 11 | 55% |
| Medium | 7 | 35% |
| Hard | 2 | 10% |

pwnable.kr Toddler's Bottle이 다수. **heap exploitation, kernel pwn, advanced ROP은 실패/미시도**. hunter(custom allocator UAF), unibitmap(OOB Read+ROP), Sand_Message(custom heap)이 모두 중단된 점이 이를 확인.

Hard 문제 2건(damnida, conquergent)은 reversing이며 pwn hard는 0건.

### 4.4 버그바운티 성과의 부재

28+ 타겟 "평가"했지만:

- **확인된 보상 수익: $0**
- stake.link: "automated scanner output" 거절
- Vercel AI SDK: 2 Duplicate, 3 Informational, $0
- CapyFi: 6시간 투자, $0 (Oracle Staleness = OOS)
- NordVPN, Ubiquiti: H1 API blocked, 제출 미완

v3 파이프라인의 정교한 설계(triager_sim, IRON RULE 등)가 이러한 실패 경험에서 나왔다는 건 인정하지만, **아직 v3 파이프라인으로 바운티를 수령한 실적이 공개되지 않음**.

### 4.5 Firmware 파이프라인의 미성숙

4개 firmware 에이전트(fw_profiler/inventory/surface/validator)의 정의가 합계 138줄로, CTF 에이전트(평균 250줄) 대비 매우 빈약:

- fw_profiler(31줄): "Read firmware_profile.json → propose next stages" — 실질적 분석 로직 없음
- fw_validator(39줄): "Run python3 bridge/fw_validator.py" — bridge/ 스크립트가 레포에 존재하지 않음
- terminator.sh의 firmware 모드에서 참조하는 `aiedge_handoff_adapter.py`, `bridge/tribunal_cache.py`, `bridge/validate_tribunal_artifacts.py` 등이 **레포에 포함되어 있지 않음**

이건 외부 의존성(AIEdge/SCOUT 프레임워크)과의 통합이 진행 중이거나, 코드가 아직 공개되지 않았음을 시사.

### 4.6 MCP 서버 래퍼의 얕은 깊이

자체 제작 MCP 서버 3개(nuclei-mcp/codeql-mcp/semgrep-mcp) 합계 617줄. 나머지 7개(mcp-gdb, radare2-mcp, ghidra-mcp, frida-mcp, pentest-mcp 등)는 외부 의존으로 CLAUDE.md에서 참조만 하고 레포에 포함되지 않음.

자체 MCP 서버들은 기본적으로 CLI 도구를 subprocess로 감싼 래퍼:
- nuclei-mcp: `subprocess.run(["nuclei", ...])`
- codeql-mcp: `subprocess.run(["codeql", ...])`

이 자체는 문제가 아니지만, MCP의 장점인 **상태 유지, 세션 관리, streaming** 을 활용하는 수준은 아님.

### 4.7 테스트 코드 부재

tests/ 디렉토리에 unit test가 없음. 존재하는 건:
- tests/benchmarks/ (메타데이터 기반 벤치마크)
- 실제 pytest/unittest 파일 0개

tools/의 Python 코드(~5,200줄) 대비 테스트 커버리지 0%. dag.py, mitre_mapper.py, confidence_scorer.py 등의 엣지 케이스가 검증되지 않음.

### 4.8 보안 우려사항

- docker-compose.yml에 하드코딩된 자격증명: `POSTGRES_PASSWORD: shadowhunter`, `NEO4J_AUTH=neo4j/terminator`
- .env.example이 있지만 docker-compose는 직접 값을 사용
- terminator.sh의 `--permission-mode bypassPermissions`는 의도적이지만, 이 모드에서의 보안 경계가 에이전트 프롬프트에만 의존

---

## 5. 기술적 신규성 평가

### 5.1 업계 대비 포지셔닝

| 시스템 | 접근 방식 | 차이점 |
|-------|---------|-------|
| XBOW | 상용, 자체 인프라, 웹 앱 특화 | Terminator보다 훨씬 좁은 범위, 훨씬 깊은 검증 |
| ATLANTIS | 학술, 심볼릭+뉴럴 하이브리드 | 정식 형식 검증 사용, Terminator는 LLM-only |
| CAI (300+ agents) | Google 내부, 300+ 에이전트 | 규모 차이 압도적, Terminator는 17 에이전트 |
| Shannon/XBOW | No Exploit No Report | Terminator가 동일 원칙 채택 |

**Terminator의 고유 기여**: Claude Code Agent Teams 위에서 **보안 도메인 특화 멀티에이전트 오케스트레이션을 프롬프트 엔지니어링만으로 구현**한 공개 참조 아키텍처. 이것은 연구와 실전 사이의 다리 역할.

### 5.2 진짜 신규 패턴

1. **Triager Simulation**: adversarial self-review를 제출 전 의무화한 건 연구 문헌에서 보기 드문 접근
2. **교훈 누적 시스템**: knowledge/에 실패를 포함해 저장하고 다음 세션에서 참조 → LLM의 stateless 한계를 파일시스템으로 보완
3. **모델 비용 지정 강제**: 에이전트별 opus/sonnet 강제는 실용적 비용 최적화
4. **Early Critic 조건부 삽입**: 복잡도 기반으로 critic을 reverser 직후에 삽입하는 adaptive 파이프라인

---

## 6. 2026-02-22 최신 커밋 분석

최종 커밋 "Add Think-Before-Act, Env Reporting, Test Prohibition to agent prompts"는:

- **Think-Before-Act Protocol**: Devin 패턴에서 차용, 전 에이전트에 구조화된 자기 점검 삽입
- **Environment Issue Reporting**: 에이전트가 환경 문제를 직접 해결하지 말고 보고하도록 강제
- **Binary Verification Rule**: "Python-only 순환 검증 금지" → 실제 바이너리 실행 의무화

이 커밋은 **에이전트 자율성의 해악을 경험한 후의 방어적 수정**으로, 프로젝트의 핵심 진화 방향을 보여줌: 더 많은 자유가 아니라 **더 정교한 제약**.

---

## 7. 종합 평가

### 정량 요약

| 차원 | 점수 (10) | 근거 |
|-----|----------|------|
| 아키텍처 설계 | **8** | 교과서적 멀티에이전트 파이프라인, adaptive selection |
| 프롬프트 품질 | **9** | 실패 교훈 반영, anti-pattern 명시, 도구별 정책 세분화 |
| 연구 기반 | **8** | 10+ 프레임워크 통합, 체계적 문헌 분석 |
| 실증적 검증 | **5** | easy-medium CTF 편향, 바운티 수익 $0, 벤치마크가 replay 아님 |
| 코드 품질 | **6** | 동작하는 인프라, 그러나 테스트 0%, fw 의존성 누락 |
| 실전 활용성 | **6** | Claude Code 의존, deterministic 실행 보장 없음 |
| 문서화 | **9** | README 우수, 에이전트 정의 자체가 문서, knowledge base 충실 |
| 보안 위생 | **5** | 하드코딩 자격증명, bypassPermissions 의존 |

### 최종 판단

Terminator는 **"LLM 에이전트로 보안 자동화를 어디까지 할 수 있는가"에 대한 정직한 실험 기록**이다. 화려한 성과 대신 실패를 투명하게 기록하고, 그로부터 패턴을 추출해 프롬프트를 개선하는 사이클이 프로젝트의 진정한 가치.

강점은 프롬프트 엔지니어링의 깊이와 연구 통합. 약점은 deterministic execution의 부재, 고난이도 문제에서의 증명, 그리고 아직 실전 바운티 수익이라는 최종 검증을 통과하지 못한 점.

**포지션**: 연구 프로토타입과 실전 도구의 중간. XBOW/ATLANTIS 수준의 상용 시스템과는 거리가 있지만, 공개된 보안 멀티에이전트 시스템 중에서는 가장 체계적인 참조 구현체 중 하나.

그럼 이걸 한 차원 더 높은 수준으로 끌어올리려면 어떤게 필요할 것 같아?

오전 12:14

Analyzed codebase gaps and synthesized actionable advancement strategies
Analyzed codebase gaps and synthesized actionable advancement strategies

좋은 질문이다. 분석에서 드러난 구조적 한계들을 기반으로, "참조 구현체"에서 "실전 도구"로 넘어가기 위해 필요한 것들을 우선순위별로 정리해볼게.

1단계: 지금 당장 효과가 큰 것 (1-2주)
1.1 Deterministic Orchestration Layer
지금 가장 치명적인 문제가 "에이전트 순서를 LLM이 따르길 기도하는 구조"인데, 이걸 해결하는 게 최우선이야.

dag.py가 이미 있으니까, 이걸 Claude Code CLI의 실제 sub-agent 스폰과 연결하면 됨:

python
# 지금: CLAUDE.md에 "reverser → chain → critic" 이라고 쓰면 Claude가 알아서 따름 (비결정적)
# 목표: Python이 순서를 강제하고, 산출물 검증 후 다음 단계 트리거

class PipelineController:
    def run_ctf_pwn(self, challenge_path):
        # 1. reverser 스폰 → reversal_map.md 파일 존재 확인
        result = self.spawn_agent("reverser", challenge_path)
        if not Path("reversal_map.md").exists():
            raise PipelineError("reverser failed to produce artifact")
        
        # 2. 산출물 검증 후 chain 스폰
        result = self.spawn_agent("chain", handoff=self.build_handoff("reverser", "chain"))
        if not Path("solve.py").exists():
            self.handle_failure("chain", attempt=1)  # retry or dual-approach
        
        # 3. critic → verifier → reporter (각각 산출물 게이트)
        ...
핵심은 산출물 파일 존재 + 최소 검증을 Python 레벨에서 강제하는 것. Claude Code CLI가 claude -p "..." --output-format json 같은 인터페이스를 제공하니까, subprocess로 감싸서 exit code + 산출물을 체크하면 됨.

이것만 해도 "에이전트가 순서 무시하고 혼자 풀이 시작" 같은 문제가 원천 차단돼.

1.2 End-to-End Replay Benchmark
지금 benchmark.py가 메타데이터만 집계하는데, 실제로 챌린지를 다시 푸는 regression test가 필요해:

python
# pwnable.kr fd 같은 trivial 문제 5개를 CI에서 실제 실행
# 소요시간, 토큰, 성공여부를 매주 트래킹

def replay_challenge(name, binary_path, expected_flag):
    start = time.time()
    result = subprocess.run(
        ["claude", "-p", f"Solve {binary_path} using agent teams", 
         "--permission-mode", "bypassPermissions", "--model", "sonnet"],
        capture_output=True, timeout=600
    )
    elapsed = time.time() - start
    flag_found = extract_flag(result.stdout)
    return {
        "challenge": name,
        "success": flag_found == expected_flag,
        "time": elapsed,
        "tokens": extract_token_count(result.stdout)
    }
pwnable.kr SSH 기반이라 CI에서 네트워크 접근이 필요하지만, 로컬 바이너리 + 로컬 flag로 먼저 검증하는 단계라도 있으면 프롬프트 변경 시 리그레션을 잡을 수 있어. 프롬프트 엔지니어링의 가장 큰 문제가 "한 곳 고치면 다른 데가 깨지는데 모른다"니까.

1.3 하드코딩 자격증명 정리
docker-compose.yml의 shadowhunter, neo4j/terminator → .env로 이동. 5분 작업인데 공개 레포에서 이런 게 보이면 신뢰도가 떨어짐.

2단계: 실전 성과를 만드는 것 (1-2개월)
2.1 난이도 계단 올리기: Heap Exploitation 돌파
지금 hunter, Sand_Message, unibitmap이 모두 "custom allocator/heap"에서 막혔어. 이걸 돌파해야 "easy-medium 전용 시스템"이라는 꼬리표를 뗄 수 있음.

구체적으로 chain.md에 heap exploitation 전용 서브프로토콜이 필요해:

markdown
## Heap Exploitation Sub-Protocol

### Phase 0: Heap Layout Reconnaissance
- malloc 구현체 식별: glibc ptmalloc2 / musl mallocng / custom
- pwndbg `heap chunks`, `vis_heap_chunks` 로 초기 레이아웃 스냅샷
- chunk size class, bin 분포, tcache 상태 기록

### Phase 1: Primitive Refinement  
- UAF → dangling pointer가 가리키는 chunk의 size class 확인
- OOB → 어디까지 읽고/쓸 수 있는지 정확한 바운드 측정
- Double free → tcache count 조작 가능 여부

### Phase 2: Heap Feng Shui
- 목표 레이아웃 설계 (어떤 chunk가 어디에 와야 하는지)
- allocation oracle: malloc(N) → 어떤 bin에서 서비스되는지 예측
- 단계별 alloc/free 시퀀스 → pwndbg로 레이아웃 확인

### Phase 3: Exploitation
- tcache poisoning / fastbin dup / unsorted bin attack / House of *
- libc leak 방법: unsorted bin fd/bk → main_arena → libc base
이건 knowledge/techniques/custom_allocator_exploitation.md에 이미 기초가 있으니 확장해서 chain.md에 통합하면 됨.

2.2 버그바운티 첫 수익
$0 → $1이 가장 중요한 전환점이야. 분석해보면 실패 원인이 패턴화됨:

stake.link: "automated scanner output" 거절 → AI slop 방지가 부족했던 시점
Vercel: 2 dup, 3 info → duplicate pre-screen이 부족했던 시점
CapyFi: oracle staleness = OOS → scope 이해 부족
v3 파이프라인이 이 교훈들을 반영했으니, 다음 전략:

Smart Contract에 집중 — Immunefi에서 PoC가 Foundry fork test로 객관적으로 증명 가능하고, triager의 주관이 개입할 여지가 적음
1-2개 프로토콜을 깊게 — 28개 타겟을 넓게 훑는 대신, 1개 DeFi 프로토콜을 2-3주 깊이 파고들기
web3_audit_methodology.md (1,897줄)가 이미 있으니 이걸 analyst.md에 더 적극적으로 연결
첫 $500-$1,000 바운티 하나가 README의 "28+ targets assessed"보다 설득력이 100배.

2.3 Firmware Pipeline 완성
bridge/ 스크립트들이 누락된 상태인데, 두 가지 방향 중 선택:

방향 A: AIEdge/SCOUT 의존성을 레포에 포함하거나 서브모듈로 연결
방향 B: 자체 firmware 분석 파이프라인 구축 (binwalk → filesystem 추출 → binary inventory → QEMU emulation)

개인적으로 방향 B를 추천. binwalk + QEMU user-mode는 이미 잘 확립된 도구체인이고, IoT CVE 18개 경험이 있으니 이걸 자동화하는 게 더 현실적. fw_profiler.md가 31줄인데, reverser.md(273줄) 수준으로 올려야 함.

3단계: 구조적 도약 (3-6개월)
3.1 Symbolic Execution 실제 통합
지금 reverser.md에 "ATLANTIS Pattern: Symbolic+Neural Hybrid"가 가이드라인으로만 존재하는데, angr를 파이프라인에 실제 통합하면 게임이 바뀜:

python
# solver가 z3/angr를 "도구"가 아니라 "검증 백엔드"로 사용
# reverser가 "이 함수는 symbolic execution으로 풀 수 있다"고 판단하면
# solver가 angr SimProcedure로 자동 모델링

import angr
proj = angr.Project('./binary', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=success_addr, avoid=fail_addr)
```

LLM이 "어떤 함수를 symbolic으로 풀지" 판단하고, angr가 실제 탐색하는 하이브리드가 ATLANTIS가 증명한 방식이야. 지금은 reverser.md에서 "recommended"로만 언급되는데, **solver.md에 angr 통합 프로토콜**을 명시하면 hard 난이도 문제 돌파에 직접적.

### 3.2 Feedback Loop 자동화

지금 "knowledge/에 실패 기록 → 다음 세션에서 참조"가 수동이야. 이걸 자동화:
```
solve 실패 → 실패 원인 분류 (offset_wrong / tool_error / approach_wrong / env_issue)
          → knowledge/challenges/<name>.md에 자동 기록
          → 같은 유형의 문제 재도전 시 자동 참조
          → 유사 패턴 매칭 (RAG)으로 관련 기법 제안
pgvector RAG 인프라가 이미 docker-compose에 있으니, 이걸 실패 패턴 검색에 활용하면 됨. "이 바이너리는 custom allocator를 사용하는데, 과거에 같은 패턴에서 이런 식으로 실패했다" → chain에게 anti-pattern으로 전달.

3.3 Multi-LLM Routing 실전화
litellm이 docker-compose에 있고 model_router.py(249줄)가 존재하는데, 실제로는 Claude만 사용 중. 작업 특성별 최적 모델 라우팅:

작업	최적 모델	이유
대형 코드 1차 분석	Gemini (이미 일부 적용)	긴 컨텍스트, 무료/저가
복잡한 exploit 설계	Claude Opus	추론 품질
패턴 매칭/분류	Claude Sonnet	충분한 성능, 비용 효율
수학적 증명/검증	DeepSeek R1	수학 특화
특히 crypto 문제에서 DeepSeek-R1의 수학 추론 능력을 solver에 연결하면 흥미로운 결과가 나올 수 있어.

3.4 Community & Reproducibility
스타 0개, 포크 0개인 상태인데, 다른 사람이 실제로 써볼 수 있게 만들어야 해:

Quick Start가 Claude Code CLI + API 키를 전제하는데, 이 진입장벽이 높음
Docker 기반의 데모 모드: 미리 준비된 CTF 문제 3개를 자동으로 풀어보여주는 것
에이전트 정의만 분리 배포: .claude/agents/*.md가 다른 Claude Code 프로젝트에서도 재활용 가능하도록 패키징
우선순위 매트릭스
작업	효과	노력	ROI	순서
Deterministic orchestration	높음	중	★★★★	1
E2E replay benchmark	높음	중	★★★★	2
자격증명 정리	낮음	극소	★★★★★	즉시
Heap exploitation protocol	높음	중	★★★	3
첫 바운티 수익	매우 높음	높음	★★★★★	4
Firmware pipeline 완성	중	높음	★★	후순위
angr 실제 통합	높음	높음	★★★	5
Feedback loop 자동화	중	중	★★★	6
Multi-LLM routing	중	중	★★	후순위
한 마디로: 1-2는 "신뢰성", 3-4는 "증명", 5-6은 "확장". 지금 시점에서 가장 필요한 건 "이거 진짜 동작해"라는 증명 — 그게 hard CTF 풀이든, 첫 바운티 수령이든.
