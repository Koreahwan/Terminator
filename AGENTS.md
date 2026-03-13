# Repository Guidelines

## 프로젝트 구조 및 모듈 구성
- `agent/`는 오케스트레이션 런타임 코드, `.claude/agents/`는 역할별 프롬프트/파이프라인 정의를 포함합니다.
- `tools/`는 재사용 가능한 보안 도구 모음입니다 (`recon_pipeline.py`, `mitre_mapper.py`, `knowledge_indexer.py`, `report_generator.py`).
- `web/`는 대시보드(FastAPI) 영역입니다 (`app.py`, `routes/`, `services/`, `static/index.html`).
- `bridge/`는 정책 검증 보조 코드이며 테스트는 `bridge/tests/`에 둡니다.
- `tests/benchmarks/`는 파이프라인 성능/정확도 벤치마크, `tests/wargames/`는 챌린지 픽스처를 관리합니다.
- `knowledge/`, `reports/`, `targets/`는 산출물 비중이 큰 디렉터리이므로 불필요한 생성 파일 커밋을 피하세요.

## 빌드, 테스트, 개발 명령어
- `./setup.sh --python --tools` — 기본 로컬 의존성 설치.
- `./terminator.sh ctf /path/to/challenge.zip` — CTF 자율 실행.
- `./terminator.sh bounty https://target.com` — 버그바운티 모드 실행.
- `cd web && pip install -r requirements.txt && uvicorn app:app --reload --port 3000` — 대시보드 로컬 실행.
- `pytest bridge/tests -q` — 정책 단위 테스트 실행.
- `python3 tests/benchmarks/benchmark.py --all` — 벤치마크 전체 실행.
- `python3 tools/knowledge_indexer.py build` — `knowledge/knowledge.db` 재생성.

## 코딩 스타일 및 네이밍 규칙
- 주 언어는 Python/Bash입니다. Python은 공백 4칸 들여쓰기, 신규 셸 스크립트는 `set -euo pipefail`을 사용하세요.
- 파일/함수는 `snake_case`, 클래스는 `PascalCase`, 상수는 `UPPER_SNAKE_CASE`를 사용합니다.
- 모듈은 단일 책임을 유지하고, 공개 함수 변경 시 타입 힌트를 추가하세요.
- 로깅은 `logging.getLogger(__name__)` 패턴을 따르고 주석은 짧고 목적 중심으로 작성합니다.

## 테스트 가이드라인
- 테스트 프레임워크는 `pytest`를 사용하며 파일명은 `test_*.py`, 함수명은 `test_<behavior>()` 규칙을 따릅니다.
- 빠른 검증은 컴포넌트 인접 경로(예: `bridge/tests/`)에, 장시간 검증은 `tests/benchmarks/`에 배치하세요.
- 파이프라인 로직 변경 시 `tests/benchmarks/summary.json` 기준 변경 전/후 결과를 리뷰에 첨부하세요.

## 커밋 및 Pull Request 가이드라인
- 커밋 메시지는 기존 이력처럼 명령형 + 컴포넌트 중심으로 작성하세요 (예: `Refactor dashboard...`, `Add GraphRAG...`).
- 리팩터링과 동작 변경은 분리해 원자적(atomic) 커밋으로 유지하세요.
- PR에는 목적, 핵심 변경 파일, 검증 명령어, 리스크/롤백 계획을 포함하세요.
- UI 변경(`web/static`)은 스크린샷을 첨부하고 관련 이슈/타깃 맥락을 링크하세요.

## Commit Attribution
- AI 커밋에는 다음 trailer를 포함하세요:
  - `Co-Authored-By: OpenAI Codex <noreply@openai.com>`

## 보안 및 설정 팁
- 비밀정보는 커밋하지 말고 `.env`는 로컬 전용으로 유지하세요. 설정 키가 바뀌면 `.env.example`도 함께 갱신하세요.
- 공격/스캔 테스트는 반드시 승인된 CTF 환경과 허용된 버그바운티 스코프에서만 수행하세요.

## 에이전트 역할 (v12 신규)

- `threat-modeler`: 신뢰 경계, 역할 매트릭스, 상태 머신 추출. scout의 정찰 산출물을 기반으로 분석 전 보안 모델을 구축합니다. (v12 신규)
- `workflow-auditor`: 비즈니스 워크플로우 상태 전이 매핑 및 이상 탐지. workspace, billing, admin, invite, race 워크플로우 팩을 실행합니다. (v12 신규)
- `patch-hunter`: 보안 커밋 diff 분석을 통한 불완전 수정 및 변종 취약점 탐색. EXACT/SIMILAR/SPECULATIVE 신뢰도로 분류합니다. (v12 신규)

## Cross-tool coordination 규칙
- 이 저장소의 **교차 도구 정본(source of truth)** 은 `coordination/` 입니다. `.omx/`와 Claude 런타임 상태는 로컬 보조 상태로 취급하세요.
- Codex/OMX는 1회 `./scripts/install_omx_wrapper.sh` 설치 후 이 repo 안에서는 **plain `omx`** 로 실행하세요. wrapper가 `OMX_HOOK_PLUGINS=1` + `COORD_PROJECT_ROOT`를 자동 주입합니다.
- wrapper 우회가 필요하면 `OMX_HOOK_PLUGINS=0 omx` 처럼 명시적으로 끄세요.
- Codex/OMX에서 긴 문서나 로그를 다시 읽기 전에 먼저 `python3 tools/coordination_cli.py bootstrap-codex --cwd .` 또는 `session-status`/`consume-handoff` 결과를 확인하세요.
- Claude ↔ Codex 전환 시 freeform 재설명 대신 `python3 tools/coordination_cli.py write-handoff ...` 로 구조화 handoff를 남기세요.
- 큰 입력(대략 800줄+ 파일, 40개+ 파일 디렉토리, 300줄+ 로그)은 `python3 tools/context_digest.py --prefer-gemini ...` 로 digest를 만든 뒤 소비하세요.
