# Explore Parallel Protocol (v15 NEW)

Referenced from `bb_pipeline_v13.md` Architecture section. 다수 타겟 Explore Lane 병렬 실행 → 최고 finding만 Prove Lane 진입.

## Why Safe

각 타겟은 `targets/<target>/` 별도 디렉토리에서 독립 실행. 공유 상태 없음:
- 별도 `program_rules_summary.md`, `endpoint_map.md`, `vulnerability_candidates.md`
- 별도 `checkpoint.json`
- 별도 agent spawn (같은 role이라도 다른 타겟 = 다른 인스턴스)
- `knowledge/` 읽기만 (쓰기는 Prove Lane 완료 후)

## Execution — Interactive Mode (Orchestrator)

### 1. 타겟 선정 (사용자 또는 target-discovery)

```
targets = [
  {"url": "https://platform.com/program-a", "platform": "bugcrowd"},
  {"url": "https://platform.com/program-b", "platform": "huntr"},
  {"url": "https://platform.com/program-c", "platform": "yeswehack"},
]
# Max 3 parallel (sonnet agent 비용 관리)
```

### 2. Phase -1 병렬 (verify-target, 수초)

```bash
# 3개 동시 — 각각 독립, 실패해도 다른 타겟에 영향 없음
python3 tools/bb_preflight.py verify-target <platform_a> <url_a> &
python3 tools/bb_preflight.py verify-target <platform_b> <url_b> &
python3 tools/bb_preflight.py verify-target <platform_c> <url_c> &
wait
# GO인 타겟만 다음 단계 진입. NO-GO는 즉시 제외.
```

### 3. Phase 0-0.2 병렬 (fetch-program + rules, 분 단위)

Orchestrator가 GO 타겟마다 동시 실행:
```bash
python3 tools/bb_preflight.py init targets/<target_a>/
python3 tools/bb_preflight.py fetch-program targets/<target_a>/ <url_a>
python3 tools/bb_preflight.py verbatim-check targets/<target_a>/
# (동시에 target_b, target_c도 동일)
```
FAIL 타겟 제외, PASS 타겟만 Phase 0.5 진입.

### 4. Phase 0.5-1.5 병렬 (agent spawn, 시간 단위)

타겟별로 독립 agent 그룹 spawn:
```
# 단일 메시지에서 병렬 Agent 호출 (최대 타겟 수 × Phase 1 agent 수)
# 타겟 A:
Agent(target-evaluator, model=sonnet, prompt="Target A: ...")
Agent(scout,            model=sonnet, prompt="Target A: ...")
Agent(analyst,          model=sonnet, prompt="Target A: ...")

# 타겟 B (동시):
Agent(target-evaluator, model=sonnet, prompt="Target B: ...")
Agent(scout,            model=sonnet, prompt="Target B: ...")
Agent(analyst,          model=sonnet, prompt="Target B: ...")

# 타겟 C (동시):
Agent(target-evaluator, model=sonnet, prompt="Target C: ...")
...
```

Phase 1 완료 후 Phase 1.5 (workflow-auditor, web-tester)도 타겟별 병렬.

### 5. 결과 비교 + Prove Lane 진입 결정

모든 타겟의 explore lane 완료 후 Orchestrator가 비교:

```
targets/<target_a>/vulnerability_candidates.md  → 후보 N개, 최고 confidence X
targets/<target_b>/vulnerability_candidates.md  → 후보 M개, 최고 confidence Y
targets/<target_c>/vulnerability_candidates.md  → 후보 K개, 최고 confidence Z
```

**Prove Lane 진입 기준** (상위 1~2 finding만):
1. Gate 1 통과 가능성 가장 높은 finding (confidence 7+)
2. Evidence tier E1/E2 달성 가능성 (source access, live target, auth available)
3. 예상 severity High+ (feedback_high_severity_only_submit 준수)
4. 동일 타겟 내 2+ finding이면 cluster submission 고려

**나머지 타겟**: `explore_candidates.md`에 아카이브 (향후 재탐색 가능).

## Execution — Autonomous Mode (terminator.sh bounty-explore)

```bash
./terminator.sh bounty-explore targets.json
# targets.json:
# [
#   {"target": "https://...", "scope": "*.example.com", "platform": "bugcrowd"},
#   {"target": "https://...", "scope": "*.other.com",   "platform": "huntr"},
#   {"target": "https://...", "scope": "api.third.com",  "platform": "ywh"}
# ]
```

- Phase -1 verify-target 전부 통과한 타겟만 explore 진입
- 각 타겟 별도 Claude session (nohup background)
- Explore Lane 완료 시 `targets/<target>/explore_summary.json` 생성:
  ```json
  {
    "target": "<url>",
    "status": "explore_complete",
    "top_findings": [
      {"name": "...", "confidence": 8, "severity": "high", "evidence_tier": "E2"}
    ],
    "gate1_recommendation": "GO|CONDITIONAL|NO-GO"
  }
  ```
- 모든 explore 완료 후 ranked summary 출력 → 사용자가 prove lane 타겟 선택

## Constraints

- **Max 3 parallel targets** — sonnet agent라도 context window × 3 = 비용 관리
- **Explore Lane ONLY** — prove lane (Phase 2+)은 절대 병렬 금지 (opus 비용 + 집중 필요)
- **knowledge/ 쓰기 금지** — explore 중 knowledge/ write는 prove lane 완료 후에만
- **동일 플랫폼 rate limit 주의** — 같은 플랫폼 3타겟이면 fetch-program 간 2초 delay
- **Time-box**: explore 전체 2시간. 2시간 내 완료 안 된 타겟 = abandon
