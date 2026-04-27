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

## 안전 정책

- `client-pitch`: passive signal만 사용하고 confirmed vulnerability 표현 금지.
- `bounty`: scope/program rules 확인 후 safe PoC만 생성.
- `ai-security`: AUP/scope 확인 전 probing 금지.
- metadata/internal IP SSRF payload 자동 생성 금지.
- 민감 파일 경로 payload 자동 생성 금지.
- brute force, DoS, cache poisoning, webhook replay 자동 실행 금지.
- state-changing endpoint는 자동 실행하지 않고 manual review queue로 보냅니다.
- 증거 없는 항목은 `confirmed` 또는 `submission-ready`로 표시하지 않습니다.

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
