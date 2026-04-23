# Token Efficiency Tracking Protocol (Anthropic SCONE-bench)

Referenced from `bb_pipeline_v13.md` Time-Box section.

SCONE-bench: 세대당 중앙값 22% 토큰 감소. 파이프라인 효율 모니터링:

**기록 시점**: 각 target 완료 시 Orchestrator가 기록
**기록 방법**: `python3 tools/infra_client.py db cost-summary --target <target> --json`
**비교 기준**:
- 동일 유형 타겟 간 tokens/finding 비율
- 모델 업그레이드 전후 동일 태스크 토큰 비교
- Phase별 토큰 비율 (Discovery:Exploitation 이상적 1:3)

**ROI 계산**: (예상 보상금 / 추정 API 비용) > 5x → 효율적
