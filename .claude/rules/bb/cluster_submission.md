# Cluster Submission Protocol (Anthropic Firefox)

Referenced from `bb_pipeline_v13.md` Phase 5 Finalization.

같은 타겟에 2+ finding이 Gate 2 통과 시:

1. **같은 날 제출** — 단일 리뷰 세션 가능성 높음
2. **Root cause 번들링**: 동일 root cause → 하나의 리포트로 통합 (VRT 동일)
3. **Cross-reference**: 각 리포트에 관련 finding 참조 ("See also: Report #X")
4. **제출 순서**: 가장 높은 severity 먼저 (심사관 신뢰도 확보)
5. **ZIP 단일화**: 관련 finding들은 하나의 submission/ 디렉터리에 모아 ZIP
