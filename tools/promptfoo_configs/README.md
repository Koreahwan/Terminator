# promptfoo Configs

Terminator ai-security 파이프라인용 promptfoo 설정 모음.

## 파일

- `redteam_starter.yaml` — OWASP LLM Top-10 기본 red-team 스타터. 타겟 URL과 auth만 수정하면 실행 가능.

## 사용법

`../promptfoo_run.sh` 래퍼 경유 권장:

```bash
# 버전 + 헬스 체크
tools/promptfoo_run.sh version

# 타겟 디렉터리에 스타터 복사 후 수정
tools/promptfoo_run.sh init-redteam targets/<name>/ai_recon/

# 빠른 prompt injection 스모크테스트 (ad-hoc)
tools/promptfoo_run.sh quick-injection https://target.example.com/api/chat

# OWASP LLM Top-10 풀 red-team
tools/promptfoo_run.sh redteam targets/<name>/ai_recon/promptfooconfig.yaml

# 타겟 자동 발견 (promptfoo Target Discovery Agent)
tools/promptfoo_run.sh discover targets/<name>/ai_recon/promptfooconfig.yaml

# 코드베이스 LLM 보안 취약점 스캔
tools/promptfoo_run.sh code-scan /path/to/repo
```

## Rate Limit (Terminator IRON RULE)

모든 config의 `maxConcurrency: 2` + `delay: 2100ms`는 30 req/min 룰 준수입니다. 타겟 프로그램이 더 엄격한 rate limit을 명시하면 해당 값에 맞춰 조정.

## MCP 통합

promptfoo 자체 MCP 서버(`promptfoo mcp --transport stdio`)가 `.claude/mcp.json`에 등록되어 있으므로, Claude Code 세션에서 직접 MCP tool로도 호출 가능. CLI는 결정론적 스크립트/CI용, MCP는 대화형 세션용.
