# Terminator

Terminator는 이제 **Bug Bounty**, **AI Security**, **Client Pitch** 전용 취약점 발견 보조 시스템입니다.

목표는 endpoint를 많이 나열하는 것이 아니라, raw attack surface를 보존하면서 IDOR/BOLA, 인증 우회, API 접근제어, 비즈니스 로직, 결제/권한/workspace 흐름처럼 실제 기업이 중요하게 보는 리스크를 우선순위화하고 안전한 검증 계획 또는 영업용 제안서로 변환하는 것입니다.

## 지원 모드

```bash
./terminator.sh bounty https://target.com "*.target.com"
./terminator.sh ai-security https://app.example.com "LLM agent workflow"
./terminator.sh client-pitch https://company.com
./terminator.sh status
./terminator.sh logs
```

제거된 레거시 모드:

- `ctf`
- `firmware`
- `robotics`
- `supplychain`
- `bounty-explore`

레거시 모드는 `archive/reference-legacy-modes-pre-bounty-ai` 브랜치에 참조용으로만 보존되어 있습니다. `main`에서 실행하면 unsupported mode를 반환합니다.

## 기본 런타임

기본 실행은 **Claude-only가 아니라 `scope-first-hybrid`** 입니다.

```bash
./terminator.sh bounty https://target.com
```

위 명령은 기본적으로 다음과 같은 의미입니다.

```bash
./terminator.sh --backend hybrid --runtime-profile scope-first-hybrid bounty https://target.com
```

역할 분담:

| Backend | 담당 |
|---|---|
| Codex/OMX | target-discovery, scout, recon-scanner, source-auditor, analyst, exploiter, critic, triager-sim |
| Claude | scope-auditor, reporter, submission-review, safety/governance |

자연어 요청을 받을 때는 먼저 의도를 해석합니다.

```bash
python3 tools/runtime_intent.py "타겟 찾고 돌리자" --shell
```

명시적 override:

```bash
# Codex만 사용
./terminator.sh --backend codex --failover-to none --runtime-profile gpt-only bounty https://target.com

# Claude만 사용
./terminator.sh --backend claude --failover-to none --runtime-profile claude-only bounty https://target.com
```

## 공유 분석 파이프라인

`bounty`와 `client-pitch`는 같은 `tools/vuln_assistant` 분석 파이프라인을 공유합니다.

```text
Recon/Input
  -> Raw Endpoint Inventory
  -> Surface Normalizer
  -> Risk Classifier
  -> Vulnerability Hint Engine
  -> Business Risk Mapper
  -> Risk Score + Confidence Score
  -> Raw Endpoint Review Queue
  -> Safe Test Planner
  -> Output Router
       -> bounty
       -> client-pitch
       -> ai-security
```

raw endpoint는 버리지 않습니다. 자동 분류가 낮게 본 endpoint도 legacy API, generic state-changing endpoint, 보호되어 보이는 401/403/405 endpoint, GraphQL/gRPC/WebSocket/SSE, query parameter가 많은 static-like endpoint는 `raw_endpoint_review.md`에 남깁니다.

## IDOR/BOLA 보조 기능

Passive IDOR/BOLA 분석:

```bash
python3 -m tools.vuln_assistant idor-passive \
  --input targets/company/bounty/attack_surface.json \
  --out targets/company/idor
```

안전한 read-only IDOR/BOLA 검증은 승인된 bounty scope, 본인 소유 테스트 계정 2개, 두 계정이 각각 소유한 object ID, 명시적 scope host가 있을 때만 사용합니다. 토큰은 명령행 값으로 직접 넣지 말고 환경변수 또는 로컬 auth profile로 전달합니다.

```bash
ACCOUNT_A_TOKEN=... ACCOUNT_B_TOKEN=... \
python3 -m tools.vuln_assistant idor-verify \
  --mode bounty \
  --candidates targets/company/idor/idor_candidates.json \
  --owned-objects owned_objects.json \
  --scope-host api.example.com \
  --auth-a-env ACCOUNT_A_TOKEN \
  --auth-b-env ACCOUNT_B_TOKEN \
  --out targets/company/idor
```

## 주요 출력

- `attack_surface.json`
- `endpoint_map.md`
- `high_value_targets.md`
- `raw_endpoint_review.md`
- `vuln_hints.json`
- `manual_test_queue.md`
- `safe_pocs.md`
- `external_risk_summary.md`
- `security_assessment_pitch.md`
- `recommended_test_scope.md`
- `bug_bounty_report_draft.md`
- `ai_security_report_draft.md`
- `idor_candidates.json`
- `idor_manual_queue.md`
- `idor_verification.json`
- `idor_verification_summary.md`
- `idor_report_draft.md`

## 안전 정책

- `client-pitch`: passive signal만 사용하고 confirmed vulnerability 표현 금지.
- `bounty`: scope/program rules 확인 후 safe PoC만 생성.
- `ai-security`: AUP/scope 확인 전 probing 금지.
- metadata/internal IP SSRF payload 자동 생성 금지.
- 민감 파일 경로 payload 자동 생성 금지.
- brute force, DoS, cache poisoning, webhook replay 자동 실행 금지.
- state-changing endpoint는 자동 실행하지 않고 manual review queue로 보냅니다.
- 증거 없는 항목은 `confirmed` 또는 `submission-ready`로 표시하지 않습니다.
- `idor-passive`는 네트워크 요청을 보내지 않습니다.
- `idor-verify`는 `client-pitch`에서 거부되며, 명시적 scope host와 사용자 제공 owned object ID가 있는 `GET`/`HEAD` 요청만 사용합니다.
- IDOR/BOLA 검증은 response fingerprint만 저장하고 raw response body나 auth secret은 저장하지 않으며, 자동으로 confirmed finding을 만들지 않습니다.

## 검증

```bash
python3 -m compileall tools/vuln_assistant tools/runtime_intent.py tools/terminator_dry_run_matrix.py tools/report_scorer.py tools/validation_prompts.py
bash -n terminator.sh
./terminator.sh --dry-run --json bounty https://example.com
./terminator.sh --dry-run --json client-pitch https://example.com
./terminator.sh --dry-run ai-security https://example.com "agent workflow"
python3 tools/terminator_dry_run_matrix.py --out /tmp/terminator_dryrun.json --profiles claude-only gpt-only scope-first-hybrid --pipelines bounty ai-security client-pitch
pytest tests -q
```
