# Ultimate Bug Bounty Checklist (Technical Edition)

Source: LinkedIn community checklist, mapped to Terminator pipeline

## 1. Scope & Mapping → Phase 0 (target_evaluator) + Phase 1 (scout)
- [ ] Read program rules carefully
- [ ] Enumerate subdomains (passive + active) → `subfinder`, `httpx`
- [ ] Identify tech stack (headers, JS, frameworks) → `katana`, `httpx`
- [ ] Map APIs (Swagger, GraphQL, mobile endpoints) → `ffuf`, `katana`
- [ ] Discover hidden parameters (JS analysis, param fuzzing) → `arjun`, `gau`

## 2. Recon → Phase 1 (scout)
- [ ] Subdomain takeover → `nuclei -t takeovers/`
- [ ] Open ports & exposed services → `nmap` (pentest-mcp)
- [ ] DNS misconfigs → `subfinder`, manual
- [ ] S3 / blob exposures → `nuclei -t exposures/`
- [ ] .git / .env / backup files → `ffuf`, `dirsearch`, `nuclei -t exposures/`

## 3. Authentication → Phase 1 (analyst mode=auth)
- [ ] Default creds → `nuclei -t default-logins/`
- [ ] Rate limit issues → manual testing
- [ ] MFA bypass
- [ ] OAuth misconfig → `nuclei -t misconfiguration/`
- [ ] Password reset flaws

## 4. Access Control (HIGH ROI) → Phase 1.5 (analyst mode=auth) + Phase 2 (exploiter)
- [ ] IDOR (GET/POST/PUT/DELETE) → Burp + manual
- [ ] Broken Access Control → `semgrep`
- [ ] Vertical escalation
- [ ] Horizontal escalation
- [ ] Role manipulation

## 5. Business Logic → Phase 1.5 (analyst mode=bizlogic) [NEW MODE]
- [ ] Coupon/discount abuse
- [ ] Workflow bypass
- [ ] Race conditions → `turbo intruder` pattern
- [ ] Payment tampering
- [ ] Multi-step logic flaws

## 6. XSS → Phase 1.5 (analyst mode=injection)
- [ ] Reflected → `dalfox`
- [ ] Stored
- [ ] DOM-based → `nuclei -t dast/`
- [ ] Markdown / file upload XSS
- [ ] WAF bypass attempts

## 7. Injection → Phase 1.5 (analyst mode=injection)
- [ ] SQLi (classic + blind) → `sqlmap`, `nuclei -t sqli/`
- [ ] NoSQL injection
- [ ] SSTI → `nuclei -t ssti/`
- [ ] Command injection → `commix`
- [ ] Template injection

## 8. API Testing → Phase 1 (analyst) + Phase 2 (exploiter)
- [ ] BOLA / IDOR
- [ ] Mass assignment
- [ ] Excessive data exposure
- [ ] Weak rate limits
- [ ] JWT misconfig (alg:none, weak secrets) → `nuclei -t token-spray/`

## 9. File Handling → Phase 1.5 (analyst mode=fileupload) [NEW MODE]
- [ ] LFI / RFI → `nuclei -t lfi/`
- [ ] Path traversal
- [ ] File upload → RCE → `fuxploider`
- [ ] Content-type bypass

## 10. Security Controls → Phase 1 (scout) + Phase 2 (exploiter)
- [ ] CSP bypass
- [ ] CORS misconfig → `nuclei -t misconfiguration/`
- [ ] Missing headers → `nuclei -t misconfiguration/`
- [ ] Cache poisoning
- [ ] Clickjacking

## 11. Advanced → Phase 2 (exploiter)
- [ ] SSRF (metadata/internal services) → `SSRFmap`
- [ ] Open redirect → chain → `nuclei -t redirect/`
- [ ] Prototype pollution
- [ ] Deserialization
- [ ] GraphQL abuse → `nuclei -t graphql/`

## 12. Reporting → Phase 3-5 (reporter + critic + triager_sim)
- [ ] Clear impact
- [ ] Step-by-step repro
- [ ] Solid PoC (Tier 1-2 only)
- [ ] Business impact explanation
- [ ] Remediation suggestions (3-layer)

## High ROI Focus (우리 경험 확인)
1. **Access Control / IDOR** — 가장 높은 수락률
2. **Business Logic** — 도구 못 찾음, 수동만 가능 → 경쟁 적음
3. **API flaws** — BOLA, mass assignment
4. **Chaining low → high** — Low 단독 = Informative, 체인 = High+

## New Analyst Modes Needed
- `mode=bizlogic` — 쿠폰, 결제, race condition, workflow bypass
- `mode=fileupload` — LFI/RFI, path traversal, upload→RCE, content-type bypass
