# Phase 5.8 — MCP Auto-Fill Operational Steps

Referenced from `bb_pipeline_v13.md` Phase 5.8. This file contains the Orchestrator Playwright MCP step sequence + credential file reference paths. The core IRON RULES (NEVER click Submit, Phase 6 BLOCKED) + platform-specific entry-point URLs remain in the main pipeline file.

## Orchestrator Playwright MCP steps

Orchestrator uses MCP Playwright tools directly (NOT a standalone script):

1. Read `autofill_payload.json` from submission directory
1b. **Credential file reference**: 로그인 필요 시 아래 경로를 순서대로 참조:
   - **플랫폼 크레덴셜**: `${HOME}/.config/bounty-credentials.json` (chmod 600, 10+ 플랫폼 저장)
   - **Playwright 프로필**: `${PLAYWRIGHT_BOUNTY_PROFILE:-$HOME/.config/playwright-bounty-profile}` (세션 쿠키 유지)
   - **타겟별 테스트 계정**: `targets/<target>/test_accounts.json` (타겟 서비스 가입 계정)
   - **로그인 도우미**: `python3 tools/platform_autologin.py check|get-creds|login-steps <platform>`
   - `autofill_payload.json`에 `credential_file` 필드로 해당 경로 포함하여 interactive session이 즉시 참조 가능하게.
2. `browser_navigate(url=form_url)` → open platform submission form
3. `browser_snapshot()` → check login state → if login needed, ask user to log in manually
4. `browser_snapshot()` → get form element refs from accessibility tree
5. `browser_fill_form(fields=[...])` → fill each field using snapshot refs
6. For complex widgets (VRT search, file upload): `browser_type` + `browser_click` + `browser_file_upload`
7. `browser_take_screenshot(fullPage=true)` → save `pre_submit_screenshot.png`
8. Notify user: "Form filled. Review in browser and click Submit."

## IRON RULES (also enforced in main pipeline file)

- **NEVER click Submit button** — human review + human click required
- **Phase 6 BLOCKED** until user confirms submission is complete
