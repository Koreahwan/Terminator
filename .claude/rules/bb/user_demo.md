# Phase 5.7.5 — User-Mediated Demo (Detailed Spec)

Referenced from `bb_pipeline_v13.md` Phase 5.7.5. v13.7 IRON RULE. MANDATORY between Phase 5.7 PASS and Phase 5.8 entry.

에이전트 critic/verifier/triager-sim "PASS"만으로 제출 금지. 실제 인간 triager의 first impression을 사용자가 본인 눈으로 검증.

## 시연 패키지 준비 (Orchestrator)

```bash
# targets/<target>/submission/<finding>/USER_DEMO.md 생성
```

포함 필드:
1. **PoC 실행 명령** — curl/python/playwright step-by-step (복붙 가능)
2. **핵심 evidence 파일 + 라인 번호 + 기대 결과** — 직접 cat/grep으로 확인 가능하도록
3. **Report 핵심 단락** — Executive Conclusion + Impact Primary + Honest Severity (3 단락)
4. **Autofill payload 핵심 필드 요약** — title/severity/cvss/asset/scope_check
5. **"이 finding이 OOS / Informative / N/R 처리될 위험 시나리오 3개"** — 사용자가 risk를 미리 인지하도록

## 시연 방식 (사용자 직접)

- Playwright MCP 브라우저로 PoC URL 직접 열어 응답 확인
- report.md 첫 1페이지 사용자 직접 읽기
- evidence 파일 sed/cat으로 핵심 라인 확인

## Verdict 형식

- 사용자가 "직접 시연 끝났다, 제출 진행" 명확히 회신해야 Phase 5.8 진입
- 단순 "OK" 또는 묵시적 동의 금지
- 사용자가 문제 발견 → STRENGTHEN 또는 KILL → 제출 보류

## Autonomous mode (terminator.sh background)

Phase 5.7.5 도달 시 `SUBMISSION_HELD` 상태로 멈춤. Interactive 세션이 시연 + 승인할 때까지 Phase 5.8 진입 금지. `targets/<target>/submission/<finding>/SUBMISSION_HELD.md` 파일 생성하고 사용자 알림.

## Audit trail

`targets/<target>/submission/<finding>/user_demo_log.md` — append-only timestamp + 사용자 verdict + 시연 중 발견된 issue 기록.
