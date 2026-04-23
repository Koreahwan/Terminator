# Graphify Pre-Analysis (10K+ LOC targets — OPTIONAL)

Referenced from `bb_pipeline_v13.md` Phase 0.5.

대형 코드베이스에서 Phase 1 전에 구조 이해 가속:

```bash
graphify <target_source_dir> --no-viz   # AST + 클러스터링 → graph.json + GRAPH_REPORT.md
graphify query "authentication flow"     # 구조 쿼리 (71.5x 토큰 효율)
```

- **God Nodes**: GRAPH_REPORT.md의 최다 연결 노드 → analyst manual review 우선 대상
- **Surprising Connections**: 예상 밖 관계 → 숨겨진 공격 경로 후보
- Orchestrator가 결과를 analyst/scout 핸드오프에 포함
