# Program Rules Summary — <TARGET_NAME>

## Platform
<REQUIRED: Platform name (FindTheGap, Bugcrowd, H1, Immunefi, etc.)>

## Auth Header Format
<REQUIRED: Exact auth header format used in API requests>
Example: `IdToken: <COGNITO_ID_TOKEN>` (NOT `Authorization: Bearer`)
- Discovered by: <scout intercept / Frida / mitmproxy / manual test>
- Verified: <date, by which agent>

## Mandatory Headers
<REQUIRED: All required headers for valid requests — copy exact values>
Example:
- `bugbounty: [FindtheGap]security_test_c16508a5-ebcb-4d0f-bf7a-811668fbaa44`
- `Content-Type: application/json`

## In-Scope Assets (VERBATIM — 프로그램 페이지에서 통째로 복사, 요약 금지)
<REQUIRED: 프로그램 페이지의 in-scope 자산 목록을 한 글자도 빠짐없이 복사>
<REQUIRED: 자산 옆에 qualifier가 있으면 반드시 포함 (예: "APIs located under", "Smart contracts only", "This is not a wildcard scope")>

## Out-of-Scope / Exclusion List (VERBATIM — 프로그램 페이지에서 통째로 복사, 요약 금지)
<REQUIRED: 프로그램 페이지의 out-of-scope 및 exclusion 전체 목록을 한 글자도 빠짐없이 복사>
<REQUIRED: 번호, 불릿, 문구 모두 원본 그대로. 축약/paraphrase = 파이프라인 위반>

## Known Issues (VERBATIM — 프로그램 페이지에서 통째로 복사)
<REQUIRED: 프로그램이 이미 인지한 이슈 목록을 원문 그대로 복사>

## Already Submitted Reports (Exclude from Analysis)
<REQUIRED: List of endpoints/vulns from already-submitted reports in this engagement>
1. (Update after each submission — prevents overlap)
2.

## Submission Rules (VERBATIM — 프로그램 페이지에서 통째로 복사)
<REQUIRED: 제출 규칙 전문을 원본 그대로 복사>

## Severity Scope (VERBATIM — 프로그램 페이지에서 통째로 복사)
<REQUIRED: severity/bounty 테이블 전체를 원문 그대로 복사>
- NOTE: If scope table shows only "Critical" next to asset, findings below Critical may be OOS

## Asset Scope Constraints (VERBATIM — 프로그램 페이지에서 통째로 복사)
<REQUIRED: version/branch/tag/environment 제약사항 원문 그대로 복사>
- NOTE: Smart contract programs often scope to specific tags — verify affected code exists in scoped version BEFORE Gate 1

## Verified Curl Template
<REQUIRED: A WORKING curl command that demonstrates correct auth — copy from actual successful test>
```bash
curl -s "https://api.example.com/endpoint" \
  -H "<auth_header>: <token>" \
  -H "<mandatory_header>: <value>"
```
**This curl MUST have been tested and returned 200. All agents MUST use this format.**
