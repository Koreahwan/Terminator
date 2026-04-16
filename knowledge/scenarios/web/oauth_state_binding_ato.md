# Scenario: OAuth State Binding / PKCE → Account Takeover

> OAuth 2.0/OIDC 구현 결함으로 authorization code 또는 tokens을 공격자에게 리다이렉트.

## 1. Threat Model
- **타겟**: OAuth 2.0/OIDC 구현 (SSO, 소셜 로그인)
- **공격자**: unauthenticated, URL을 클릭할 victim 1명 필요
- **Impact**: Victim 계정 완전 탈취
- **Severity**: High–Critical

## 2. Discovery Signals
- `state` 파라미터 미검증 또는 예측 가능 (timestamp, counter)
- `code_challenge` (PKCE)가 authorization URL에는 있지만 token 교환에서 `code_verifier` 미검증
- `redirect_uri` 부분 매칭 (whitelist가 prefix only)
- `response_type=token` (implicit flow, 여전히 사용되는 곳)
- 이메일 verification 없는 자동 계정 생성

## 3. Exploit Chain

### 3.1 State binding 누락 (CSRF)
```
A. 공격자가 자기 계정으로 authorization flow 시작
B. callback URL 받기 직전 페이지에서 code 캡처
C. victim에게 해당 code 포함 callback URL 유도
D. victim 브라우저가 /callback?code=<attacker_code> 접속
E. 앱이 code 교환 → victim 세션에 공격자 소셜 계정 연동
F. 이후 공격자가 해당 소셜로 로그인 → victim 계정 접근
```

### 3.2 PKCE downgrade
```
A. 클라이언트가 code_challenge 전송
B. 서버가 token 교환 시 code_verifier 검증하지 않음
C. 공격자가 MITM (또는 redirect_uri 우회)으로 code 탈취
D. 자신의 verifier 없이도 token 교환 성공
```

### 3.3 redirect_uri 우회
```
whitelist: https://app.example/callback
공격 후보:
- https://app.example/callback/../../attacker (path traversal)
- https://app.example.attacker.com/callback (subdomain)
- https://app.example/callback#@attacker.com/ (fragment)
- https://app.example/callback?redirect=attacker (open redirect 조합)
```

## 4. PoC Template
```bash
# Step A — authorization URL
curl -L "https://idp.example/authorize?\
client_id=X&response_type=code&\
redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&\
state=anything" \
  -o /dev/null -D headers.txt

# Step B — callback 후 state 검증 여부
# 클라이언트가 서버측 session state와 비교하지 않으면 CSRF 가능

# Step C — redirect_uri 파서 차이
curl "https://idp.example/authorize?redirect_uri=https://app.example/callback/@attacker.com/"
# 일부 파서가 `@` 뒤를 authority로 해석
```

## 5. Evidence Tier
- E1: 두 개 테스트 계정 — victim이 attacker link 클릭 → victim 계정 설정에 attacker 소셜 계정 연동된 것 확인
- E2: state 미검증 단독 입증 (CSRF PoC HTML)
- E3: 구현 정적 분석만

## 6. Gate 1 / Gate 2
- [ ] `state` 없이 PoC 가능? 일부 프로그램은 "state는 클라이언트 책임" 주장
- [ ] PKCE 미구현은 점점 P3/P4 — 추가 bypass 필요
- [ ] OAuth 제공자 vs 사용 앱 — 어디에 제보? Provider 책임 vs App 책임 명확화

## 7. Variants
- **Dynamic client registration**: `client_id` 직접 생성 가능한 OIDC 프로바이더
- **Mix-up attack**: multi-IdP 환경에서 wrong IdP로 code redirect
- **Cross-account email**: 이메일 verification 없이 attacker email로 연동된 후 victim email로 변경
- **Token substitution**: access_token과 id_token 교차 사용
- **JWT+OAuth 합성**: id_token JWT kid 공격과 결합

## 8. References
- RFC 6749 (OAuth 2.0), RFC 9700 (BCP Security)
- Daniel Fett — OAuth security 연구
- Google IdP / Auth0 / Okta 공개 disclosure 다수
- PortSwigger Academy — OAuth 섹션
- `knowledge/techniques/cloud_saas_attack_patterns_2026.md` 섹션 1 (OAuth)
