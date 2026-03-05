# Bugcrowd Vulnerability Rating Taxonomy (VRT)
**Source**: https://bugcrowd.com/vulnerability-rating-taxonomy
**Last Updated**: 2026-03-05

reporter/analyst/exploiter가 Bugcrowd 제출 시 VRT 카테고리를 정확히 선택하기 위한 참조.

---

## P1 (Critical)

| Category | Subcategory |
|:---------|:------------|
| **AI Application Security** | Model Extraction, RCE (Full System), Sensitive Info Disclosure (Cross-Tenant PII, Key Leak), Training Data Poisoning |
| **Broken Access Control** | IDOR — Modify/View Sensitive Information |
| **Broken Authentication** | Authentication Bypass |
| **Cloud Security** | Publicly Accessible IAM Credentials |
| **Insecure OS/Firmware** | Command Injection, Hardcoded Password (Privileged User) |
| **Sensitive Data Exposure** | Disclosure of Secrets (Publicly Accessible Asset) |
| **Server Security** | Exposed Admin Portal (Default Credentials) |
| **Server-Side Injection** | File Inclusion (Local), RCE, SQL Injection, XXE |
| **Smart Contract** | Reentrancy, Owner Takeover, Unauthorized Transfer of Funds, Uninitialized Variables |
| **Zero Knowledge** | Deanonymization, Improper Proof Validation |
| **Decentralized Apps** | Plaintext Private Key, Orderbook Manipulation, Signer ATO, Unauthorized Asset Transfer |

## P2 (High)

| Category | Subcategory |
|:---------|:------------|
| **AI Application Security** | DoS (App-Wide), Prompt Injection (System Prompt Leak), RCE (Sandboxed), Embedding Exfiltration |
| **Application-Level DoS** | Critical Impact and/or Easy Difficulty |
| **Broken Access Control** | IDOR — Modify Sensitive Information |
| **Cloud Security** | Overly Permissive IAM Roles, Unencrypted Sensitive Data at Rest |
| **CSRF** | Application-Wide |
| **XSS** | Stored (Non-Privileged User to Anyone) |
| **Cryptographic Weakness** | Key Reuse (Inter-Environment) |
| **Insecure OS/Firmware** | Hardcoded Password (Non-Privileged), Over-Permissioned Credentials |
| **Sensitive Data Exposure** | Token Leakage via Host Header Poisoning |
| **Server Security** | OAuth Misconfiguration (ATO), SSRF (Internal High Impact) |
| **Smart Contract** | Integer Overflow/Underflow, Unauthorized Approval |
| **Protocol-Specific** | Frontrunning-Enabled, Sandwich-Enabled |
| **Decentralized Apps** | Price/Fee Manipulation, Malicious Order Offer |

## P3 (Medium)

| Category | Subcategory |
|:---------|:------------|
| **AI Application Security** | Improper Output Handling (XSS), Semantic Indexing Weakness |
| **Application-Level DoS** | High Impact and/or Medium Difficulty |
| **Broken Access Control** | IDOR — View Sensitive Information |
| **Broken Authentication** | Session Fixation (Remote), 2FA Bypass |
| **Cloud Security** | Lack of Segmentation, Open Management Ports |
| **XSS** | Reflected (Non-Self), Stored (Privileged→Elevation, CSRF/URL-Based) |
| **Cryptographic Weakness** | Broken Crypto Primitive, Insufficient Key Space |
| **Sensitive Data Exposure** | Secrets (Internal Asset), EXIF Geolocation (Auto Enum) |
| **Server Security** | Non-Admin Portal, Mail Spoofing, Subdomain Takeover, SSRF (Internal Scan/Medium) |
| **Server-Side Injection** | iframe Injection, Response Splitting/CRLF |
| **Smart Contract** | Function-level DoS, Improper Fee, Irreversible Call, Malicious Superuser |

## P4 (Low)

| Category | Subcategory |
|:---------|:------------|
| **Broken Access Control** | Password Confirmation Bypass, IDOR (GUID/UUID), Username Enum (Non-Brute) |
| **Broken Auth/Session** | Cleartext Session Token, Failure to Invalidate (Logout/Reset), Weak Login (HTTP) |
| **XSS** | Off-Domain Data URI, Referer, Stored (No Elevation), UXSS |
| **Cryptographic Weakness** | Vulnerable Library, Insufficient Entropy, Padding Oracle, Timing, Expired Cert |
| **Insecure Data Storage** | Unencrypted External Storage, Plaintext Server Credentials |
| **Insufficient Security** | No Password Policy, Weak Reset Token, Weak 2FA |
| **Sensitive Data Exposure** | Pay-Per-Use Abuse, EXIF (Manual), Token in URL, Referer Leak, localStorage Token |
| **Server Security** | CAPTCHA Vuln, Clickjacking, DB DBA, No Rate Limit (Login/Registration/SMS), WAF Bypass |
| **Smart Contract** | Improper Decimals, Improper Modifier Use |
| **Unvalidated Redirects** | Open Redirect (GET-Based) |

## P5 (Informational)

| Category | Subcategory |
|:---------|:------------|
| **Broken Access Control** | IDOR (Non-Sensitive Info) |
| **Broken Auth/Session** | Concurrent Logins, Long Timeout, Session Fixation (Local) |
| **CSRF** | Logout, Token Not Unique, Flash-Based |
| **XSS** | Cookie-Based, Flash-Based, IE-Only, Self-XSS, TRACE |
| **External Behavior** | Autocomplete, Save Password, CSV Injection, Clipboard Leak |
| **Insecure Data Storage** | Non-Sensitive Unencrypted, Screen Caching |
| **Insufficient Security** | Lack of Notification, Weak Policy, Disposable Email |
| **Lack of Binary Hardening** | No Exploit Mitigations, No Jailbreak Detection, No Obfuscation |
| **Mobile Security** | Auto Backup, Clipboard, SSL Pinning Absent, Tapjacking |
| **Sensitive Data Exposure** | Known Public Info, GraphQL Introspection, Internal IP, Stack Trace |
| **Server Security** | Fingerprinting, Insecure SSL, Missing Headers (CSP/HSTS/X-Frame), DNS (Missing CAA/DNSSEC) |
| **Server-Side Injection** | HTML Injection, Text Injection, Homograph, RTLO |

## Varies (Severity Dependent)

| Category | Subcategory |
|:---------|:------------|
| **Broken Access Control** | Privilege Escalation |
| **Cloud Security** | Exposed Debug/Admin, Publicly Accessible Storage |
| **CSRF** | Action-Specific (Auth/Unauth) |
| **Cryptographic Weakness** | Improper Implementation, Differential Fault Analysis, Weak Hash |
| **DeFi Security** | Flash Loan Attack, Accounting Error, Governance, Oracle Manipulation |
| **Decentralized Apps** | Insufficient Signature Validation, DoS, Deposit/Withdrawal Validation |
| **Server Security** | Cache Deception/Poisoning, HTTP Smuggling, OAuth (Redirect/State), Path Traversal, Race Condition, CORS |
| **Server-Side Injection** | LDAP Injection, SSTI (Custom), Exposed Sensitive Data |
| **Smart Contract** | Bypass of Modifiers, Inaccurate Rounding |
| **Zero Knowledge** | Misconfigured Trusted Setup, Missing Constraint, Missing Range Check |

---

## 사용법

reporter가 Bugcrowd 보고서 작성 시:
1. 취약점 유형에 해당하는 VRT 카테고리 확인
2. `program_rules_summary.md`에서 프로그램의 VRT 범위 확인
3. 정확한 카테고리 + 서브카테고리로 Technical Severity 선택
4. P1-P5 기본 등급은 프로그램이 override 가능 (brief 확인 필수)
