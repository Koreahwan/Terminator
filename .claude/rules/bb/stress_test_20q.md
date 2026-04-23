# Phase 5.7.6 — Objective 20-Question Stress Test (Detailed Spec)

Referenced from `bb_pipeline_v13.md` Phase 5.7.6. This file contains the 20 question categories, ralph loop rules, and audit-trail format.

## Purpose

Round 1/2/3 critic·verifier·triager-sim은 **자기 evidence 검증에 편향**될 수 있음. 객관적 third-party 시각 요구 — 실제 기업/플랫폼 triager 입장에서 20 hard questions로 재검증.

## Execution (Orchestrator 직접, critic + triager-sim 2-agent 병렬 spawn)

```
TaskCreate("Phase 5.7.6 20-Q stress test <target>/<finding>")
Agent(critic)  → "adversarial 20-question stress test, top 3 weak points + top 3 strengthen actions + bounty re-calibration"
Agent(triager-sim) → "real platform triager persona 20-question evaluation, probability distribution + median bounty"
```

## 20 Question Categories (각 finding에 맞게 조정)

1. Scope legitimacy — asset 진짜 in-scope?
2. CWE classification — 정확한가, 다른 CWE가 더 맞나?
3. OOS rule collision — 해당 플랫폼 OOS 항목과 충돌?
4. Spec interpretation — "intended behavior" 반박 위험?
5. Test client realism — production에도 적용?
6. Unique impact — claimed impact가 진짜 novel?
7. Resource-server auth model — access control 위반인가, 디자인?
8. Sandbox-Production parity — grep vs live verify gap?
9. CVSS calibration — 공격적 vs 보수적?
10. Regulatory invocation — GDPR/GDPR-like claim 정당성?
11. Secondary framing bloat — 과잉 framing?
12. Systemic vs spec compliance — 진짜 systemic bug?
13. Exploitation realism — weaponize 시나리오?
14. Marginal impact — 데이터 public source에서도 확보 가능?
15. Honest disclosure vs weakness — 약점 인정이 self-damage?
16. Test data vs real data — demo가 production 반영?
17. Form-vs-report classification mismatch?
18. Pre-existing knowledge — GitHub issues/PRs 검색 수행?
19. Duplicate race — 다른 hunter 제출 가능성?
20. Bounty calibration — 기대값 정당?

## Verdict 종합 (ralph loop으로 구동)

Orchestrator는 이 게이트를 `/ralph` skill로 감싼다 — self-referential loop until **양 agent가 SUBMIT-AS-IS**까지. ralph invocation:

```
/ralph --critic=critic "Phase 5.7.6 stress test for <target>/<finding>: run 20-Q critic + 20-Q triager-sim in parallel, apply STRENGTHEN actions, re-run until both agents return SUBMIT verdict or MAX 3 rounds reached"
```

### Round loop rule

1. 양 agent 모두 SUBMIT-AS-IS → exit loop, Phase 5.8 진입
2. 한쪽 이상 STRENGTHEN → ralph auto-applies STRENGTHEN list + re-spawns agents (iteration++)
3. 양쪽 KILL → exit loop with KILL, 제출 취소
4. Max 3 iterations — 3차까지 SUBMIT 수렴 못 하면 → user decision required (STRENGTHEN forever 방지)

- Ralph PRD는 자동 생성: 각 weak point를 user story로 변환, 각 story는 "양 agent next round에서 이 weak point 언급 안 함" = acceptance criterion
- Audit trail: 각 iteration별 `stress_test_20q_round{N}.md` — ralph이 자동 관리

**Accept probability / weighted bounty EV** 양 agent가 제공. 이 수치가 플랫폼/프로그램 실 데이터 매칭 후 업데이트됨 (feedback loop).

## IRON RULE

Round 2/3 PASS 했어도 Phase 5.7.6 stress test 없이 Phase 5.8 진입 금지. 실제 사례 (Bugcrowd Zendesk N/A 2026-04-17 AI-RAG) 에서 self-evidence 기반 verification 만 했던 결과 N/A close. 20-Q 객관적 검증이 이 type 사고 예방.

## Audit Trail

`targets/<target>/submission/<finding>/stress_test_20q.md` — 각 agent verdict + TOP weak points + expected bounty EV 기록.
