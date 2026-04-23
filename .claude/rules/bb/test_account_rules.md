# Phase 6 — Test Account + Autonomous Session Rules

Referenced from `bb_pipeline_v13.md` Phase 6. This file contains the full Test Account cleanup protocol + Autonomous Session (terminator.sh background mode) rules.

## Test Account Rules (MANDATORY)

- **IRON RULE: 자동 회원가입 ABSOLUTELY BANNED.** 에이전트가 signup/register 폼을 자동 제출하는 것 절대 금지. 계정 필요 시 사용자에게 요청만 가능. Interactive 세션에서 사용자가 직접 가입.
- **Trigger for cleanup**: ANY pipeline exit — Phase 6 normal completion, Gate KILL, time-box ABANDON, session crash, or manual stop
- **IRON RULE**: No session exits without checking `targets/<target>/test_accounts.json`. Test accounts MUST be deleted regardless of finding outcome.
- **BEFORE creating any account**: 회원탈퇴 경로(Settings → Delete Account URL) 먼저 확인. 탈퇴 불가능한 서비스는 계정 생성 자제.
- **password 필드 필수**: `test_accounts.json`에 반드시 password 기록. 회원탈퇴 시 로그인 필요. 누락 = 파이프라인 위반.
- **최소 계정 원칙**: 꼭 필요한 최소 계정만 생성. IDOR 테스트도 2개면 충분.
- **생성 직후 탈퇴 테스트**: 계정 만든 후 바로 Delete Account 경로 접근 가능한지 확인. 불가능하면 즉시 보고.
- **Gmail alias format**: `<base-gmail>+<target>_test_<letter>@gmail.com` (base address는 레포 외부 `${HOME}/.config/bounty-credentials.json`의 `gmail_base` 필드에서 로드 — 레포에 하드코딩 금지)
- **OAuth/소셜 로그인 금지** — 비밀번호 기반 가입만 사용.
- **세션 종료 전 반드시 탈퇴 완료**. "나중에 정리" 금지.

## Autonomous Session Rules (terminator.sh background mode)

- Phase 5.8: No browser/Playwright access. Write `autofill_payload.json` + `submission_review.json` only. Interactive session handles auto-fill.
- `autofill_payload.json`에 `credential_file` 필드 포함: `targets/<target>/test_accounts.json` 경로 또는 플랫폼 로그인 정보 참조 경로. Interactive session이 auto-fill 시 즉시 로그인할 수 있도록.
- If submission artifacts exist at exit, log: "SUBMISSION READY: <target>/<finding> — awaiting Phase 5.8 auto-fill"
