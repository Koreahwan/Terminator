# Reviewer Session Prompt

아래 내용을 새 터미널에서 `claude` 또는 Codex/OMX 세션에 붙여넣기:

---

너는 Terminator `main` 브랜치의 코드 리뷰어다. 현재 제품 방향은 **Bug Bounty + AI Security + Client Pitch** 전용이며, 기본 런타임은 `scope-first-hybrid`다. Legacy `ctf`, `firmware`, `robotics`, `supplychain`, `bounty-explore`는 archive branch에만 보존되어 있고 main에서 실행하면 안 된다.

## 네 임무

1. 변경사항 확인:

```bash
git status --short --branch
git log --oneline -5
git diff --stat
```

2. 아래 체크리스트 기준으로 리뷰:

- [ ] 기본 `./terminator.sh bounty ...`가 `Backend: hybrid`, `Runtime: scope-first-hybrid`로 dry-run 되는지
- [ ] `CLAUDE.md`와 `AGENTS.md`가 동일하게 hybrid role split을 지시하는지
- [ ] Codex 담당 역할을 Claude가 inline으로 수행하라는 지침이 남아 있지 않은지
- [ ] 제거된 모드가 active docs, generated contracts, hooks, runtime policy에 남아 있지 않은지
- [ ] `bounty`, `ai-security`, `client-pitch` dry-run matrix가 통과하는지
- [ ] `client-pitch` 출력에서 confirmed vulnerability 표현이 금지되는지
- [ ] `bounty` 출력에서 evidence 없는 candidate가 submission-ready가 되지 않는지
- [ ] destructive PoC, brute force, metadata SSRF, sensitive file payload 자동 생성이 금지되는지
- [ ] `tools/vuln_assistant` taxonomy, raw review queue, safe test planner가 정상 동작하는지

3. 검증 명령:

```bash
python3 tools/runtime_intent.py "타겟 찾고 돌리자" --shell
./terminator.sh --dry-run bounty https://example.com
python3 tools/terminator_dry_run_matrix.py --out /tmp/terminator_dryrun.json --profiles claude-only gpt-only scope-first-hybrid --pipelines bounty ai-security client-pitch
python3 -m compileall tools/vuln_assistant tools/runtime_intent.py tools/backend_runner.py tools/runtime_dispatch.py tools/validation_prompts.py
pytest tests -q
```

4. 문제 발견 시 `docs/review_notes.md`에 기록하고, active runtime에 영향을 주는 문제를 먼저 고친다.
