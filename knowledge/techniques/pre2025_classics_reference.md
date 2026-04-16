# Pre-2025 Security Classics — Still-Relevant Reference

> 오래됐지만 2026에도 유효한 취약점 패턴, 도구, 기법 카탈로그.
> "고전"이 아니라 "기반". 신규 사고의 90%는 이미 아래 카테고리의 변형.

---

## 1. 여전히 헌팅 가능한 Classic CVE 패턴

### 1.1 Web / Infra
| CVE / 이름 | 연도 | 왜 아직 유효한가 |
|------------|------|------------------|
| **Shellshock** (CVE-2014-6271) | 2014 | 레거시 CGI, 내장 장비, IoT에 남음 |
| **Heartbleed** (CVE-2014-0160) | 2014 | EOL OpenSSL 이미지에서 지속 발견 |
| **Log4Shell** (CVE-2021-44228) | 2021 | JNDI lookup 패턴이 log4j 외 ClassLoader에도 존재 |
| **Spring4Shell** (CVE-2022-22965) | 2022 | Spring 구버전 + JDK9+ 조합에서 재등장 |
| **GhostCat** (CVE-2020-1938) | 2020 | Tomcat AJP, 내부 포트 노출 시 |
| **Apache Struts S2-*** | 2017+ | OGNL injection 계보, legacy Gov/Enterprise |
| **ProxyShell / ProxyLogon** | 2021 | Exchange on-prem이 여전히 존재 |
| **ImageTragick** (CVE-2016-3714) | 2016 | ImageMagick delegate 취약 — SSRF/RCE |
| **Ghostscript** (CVE-2018-16509, 2023-36664) | 반복 | PDF/PS 처리기에 장기 잔존 |
| **HTTP/2 Rapid Reset** (CVE-2023-44487) | 2023 | DoS, 다수 CDN 여전히 영향 |
| **Desync attacks** | 2019+ | PortSwigger "HTTP Request Smuggling" 계보 |

### 1.2 Smart Contract / DeFi
| 사건 | 연도 | 학습 포인트 |
|------|------|-------------|
| **The DAO** | 2016 | reentrancy 원형 |
| **Parity MultiSig Wallet** | 2017 (2회) | `initWallet` delegatecall, accidental `kill` |
| **bZx** | 2020 | flashloan + oracle 최초 대규모 |
| **Harvest Finance** | 2020 | Curve pool 조작 |
| **Poly Network** | 2021 | EthCrossChainManager access control |
| **Wormhole** | 2022 | 서명 검증 우회 + uninitialized UUPS |
| **Ronin** | 2022 | off-chain multisig signer compromise |
| **Beanstalk** | 2022 | flashloan governance 최초 |
| **Nomad Bridge** | 2022 | trusted root = 0 bypass |
| **Curve Vyper 0.2.x** | 2023 | compiler 버그로 reentrancy guard 무효 |

### 1.3 Kernel / OS
| CVE | 이름 | 교훈 |
|-----|------|------|
| CVE-2016-5195 | Dirty COW | race condition UAF → root |
| CVE-2017-5123 | waitid() | SMAP bypass |
| CVE-2022-0847 | Dirty Pipe | pipe splice → SUID overwrite |
| CVE-2021-22555 | Netfilter heap OOB | kernelCTF 고전 |
| CVE-2020-14386 | packet_rcv_fill_hole | 1-bit OOB → 권한 상승 |
| CVE-2022-2588 | cls_route UAF | 여전히 참조되는 기법 |
| CVE-2023-32233 | nf_tables UAF | 2023 기준 최근, 패치 지속 필요 |

### 1.4 Binary / Client-side
- **Hacking Team Flash exploits** (2015) — UAF + type confusion 방법론
- **EternalBlue / EternalRomance** (2017) — SMBv1 풀어지지만 OT 네트워크 잔존
- **BadAlloc** (2021) — 임베디드 RTOS 11종 메모리 관리 취약
- **Ripple20** (2020) — Treck TCP/IP stack
- **URGENT/11** — VxWorks

---

## 2. 여전히 활용하는 Classic 도구/기법

### 2.1 기법
- **ROP / JOP / COP** — 2007 Shacham 이후로 변형만
- **Heap feng shui** — Sotirov 2007, glibc/jemalloc 맞춤 변형
- **Format string attack** — 오래됐지만 임베디드/레거시에 잔존
- **Ret2dl_resolve** — ELF 동적 링커 악용 (2015 Payatu 블로그 계보)
- **GOT overwrite** — PIE 미적용 레거시 다수
- **Sigreturn-oriented programming (SROP)** — 2014 Bosman
- **TOCTOU** — 파일/lock race, 50년 된 기법

### 2.2 도구 (여전히 필수)
- `pwntools`, `gdb`, `radare2` (본 프로젝트 BANNED), `ghidra`
- `sqlmap`, `Burp Suite`
- `masscan`, `nmap`, `zmap`
- `wireshark`, `tcpdump`
- `hashcat`, `John the Ripper`
- `mimikatz` (Windows AD 고전)
- `Responder`, `Impacket`
- `Metasploit` (학습/CTF에서 여전)

### 2.3 레거시 프로토콜/포맷
- **XXE** (2000년대, 2025에도 발견)
- **XSLT** injection
- **SAML** signature wrapping
- **JNDI** (Log4Shell 이후에도 Jackson, Cassandra 등에서)
- **Serialization** (ysoserial 계보, Java/PHP/.NET 지속)

---

## 3. 읽을 가치 있는 Pre-2025 Reference

### 3.1 도서
- **Shellcoder's Handbook** (Anley 외, 2nd ed. 2007) — 기본기 여전
- **Hacking: The Art of Exploitation** (Erickson, 2008) — 입문용
- **The Web Application Hacker's Handbook** (Stuttard, 2011) — 웹 기본
- **Gray Hat Python** (Seitz, 2009) — hooking/debug 패턴
- **Practical Malware Analysis** (Sikorski, 2012)
- **The Tangled Web** (Zalewski, 2011) — 브라우저 보안
- **Real-World Bug Hunting** (Yaworski, 2019) — 바운티 입문 여전 유용
- **Black Hat Python / Go** — 시나리오 매뉴얼

### 3.2 Academic 시리즈
- **USENIX Security** archive — 2010년대 논문 다수 여전 베이스라인
- **IEEE S&P (Oakland)** archive
- **ACM CCS** archive
- **Project Zero blog** — 전체 읽어볼 가치
- **Phrack** — 고전 exploit zines (42, 49, 59번 등)

### 3.3 Writeups 저장소
- `SunWeb3Sec/DeFiHackLabs` — Foundry fork PoC 아카이브
- `reddelexc/hackerone-reports` — H1 top-by-type
- `djadmin/awesome-bug-bounty` — writeup 모음
- `swisskyrepo/PayloadsAllTheThings` — 표준 payload 모음
- `OWASP/wstg` — WSTG 테스트 가이드

---

## 4. 여전히 유효한 Web 공격 패턴 (2016-2024)

| 패턴 | 제안 연구 | 2026 유효성 |
|------|-----------|-------------|
| HTTP Request Smuggling | Kettle 2019+ | 매년 변형 신발견 |
| Web Cache Poisoning | Kettle 2018-2020 | CDN 설정 결함 여전 |
| DOM Clobbering | Heiderich 2017+ | 현대 SPA에도 |
| Prototype Pollution | Arteau 2018+ | Node 생태계 지속 |
| SSTI | Kettle 2015 | 템플릿 엔진 다수 |
| SSRF + IMDS | 2017+ | IMDSv2 강제 전 인스턴스 여전 |
| CRLF Injection | 고전 | 프록시/로드밸런서 구성 차이 |
| CORS Misconfig | 2016+ | regex-based 검증 실수 지속 |
| Open Redirect | 원형 | OAuth flow 결합 시 High |
| CSRF | 1990s | SameSite=Lax 기본값 이전 앱 |

---

## 5. 체계적 학습 경로 (신입 → 중급)

### 5.1 기초
1. OWASP WSTG 읽고 각 테스트 실습
2. PortSwigger Academy 전 과정 (web 기초)
3. HackTheBox / TryHackMe Medium 난이도 20+

### 5.2 중급
1. Real-World Bug Hunting (Yaworski) 독파
2. HackerOne hacktivity 최근 100개 읽기
3. PortSwigger Research 블로그 2019-2024 통독
4. Project Zero 블로그 샘플링

### 5.3 전문화 분기
- **Web**: PortSwigger BSCP 인증 or Burp Suite Pro 숙련
- **Web3**: Secureum bootcamp + Code4rena 참가
- **Kernel**: bsauce repo → pwn.college → kernelCTF submission
- **Mobile**: OWASP MASTG 실습
- **AI**: garak/pyrit 사용 + 대표 논문 10편 읽기

---

## 6. Terminator knowledge 통합 방식

- `knowledge/techniques/web3_audit_methodology.md` (56KB) — Web3 고전+신기법 이미 통합
- `knowledge/techniques/kernel_security_learning_main.md` (46KB) — 커널 고전
- `knowledge/techniques/web3_defi_attack_taxonomy.md` (52KB) — DeFi 패턴
- **본 문서** — 전 분야 pre-2025 "여전히 유효"한 카탈로그 + 학습 경로

### 신규 타겟 접근 시 체크 순서
1. Target 유형 식별 (web/web3/mobile/kernel/cloud/AI)
2. 본 문서 섹션 1의 해당 카테고리 classic CVE 리스트 스캔
3. 섹션 2의 classic 기법이 적용 가능한지
4. 섹션 4의 web 공격 패턴 중 타겟에 맞는 것
5. `scenarios/` 라이브러리에서 매칭되는 end-to-end 시나리오 선택

---

마지막 업데이트: 2026-04-16
