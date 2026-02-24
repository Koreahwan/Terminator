# External Repository Deep Analysis — Terminator Upgrade Plan

> 분석일: 2026-02-24
> 대상: ref.md 내 60개 GitHub 레포 + 추가 조사 8개
> 목적: Terminator 프레임워크 업그레이드를 위한 외부 자원 통합 계획

---

## 재검토 결과 (2026-02-24 Re-review)

초기 분류 이후 추가 검토를 통해 다음 변경 사항 반영:

### 승격 (Upgrades)
| 레포 | 변경 | 이유 |
|------|------|------|
| **web-check** | P2 → P1 | 33개 REST API 엔드포인트, Docker self-hostable, scout 파이프라인 직접 통합 가능 |
| **vuls** | P2 → P1 | v0.38.2 (2026년 2월), OS/패키지 CVE 열거 공백 채움, nuclei 보완 |
| **OWASP/mastg** | SKIP → P2 | 모바일 BB 방법론, Frida MCP와 페어링 시 즉시 유효 |
| **AD Exploitation Cheat Sheet** | P3 → P2 | ADCS 공격 + BloodHound 명령어 포함, AD 타겟 실전 참조 |
| **Apktool** | P3 → P2 | v3.0.1 최신, Android RE 필수 도구 |
| **sherlock** | SKIP → P3 | 400+ 플랫폼 username OSINT, scout Phase 0 정찰 활용 |
| **L1B3RT4S** | SKIP → P3 | Prompt injection 방어 레퍼런스 (Guardrails 강화) |

### 강등 (Downgrades)
| 레포 | 변경 | 이유 |
|------|------|------|
| **ropium** | P1 → P2 | 2024년 8월 이후 dormant, Python 3.10+ 에서 breakage 위험 |
| **werdlists** | P3 → SKIP | 362 stars, SecLists가 95%+ 커버 — 중복 |
| **Villain** | P3 → SKIP | CC-NC 라이선스, 상업적 BB 환경 비호환 |

### the-book-of-secret-knowledge에서 개별 도구 발굴
| 도구 | 용도 | 우선순위 |
|------|------|---------|
| **routersploit** | 임베디드 장치 exploit 프레임워크 | P2 |
| **amass** | OWASP 서브도메인 열거 (subfinder 보완) | P2 |
| **dnstwist** | 타이포스쿼팅 도메인 탐지 | P2 |

---

## Executive Summary

68개 레포 분석 결과 (재검토 반영):
- **즉시 통합 (P1)**: 13개 — CTF 파이프라인 + 도구 + 지식베이스 직접 강화
- **계획적 통합 (P2)**: 14개 — 1주 내 설정, 중간 가치
- **참조만 (P3/REF)**: 11개 — 특수 상황 참조
- **SKIP**: 36개 — 중복, 범위 밖, 교육용, 라이선스 문제

---

## P1 — 즉시 통합 (13개)

### 도구 (5개)

| 도구 | 용도 | 설치 | 대상 에이전트 |
|------|------|------|--------------|
| **Ciphey** | 50+ 암호/인코딩 자동 탐지+복호화 | `pip install ciphey` | solver |
| **RustScan** | 65535 포트 3초 스캔 (nmap 30x) | `cargo install rustscan` | scout |
| **rp++** | ARM/ARM64 + Mach-O ROP 가젯 (ROPgadget 보완) | GitHub Releases 바이너리 | chain |
| **web-check** | 33개 REST API 엔드포인트 원샷 웹 정찰, Docker self-hostable | `docker run -p 3000:3000 lissy93/web-check` | scout |
| **vuls** | v0.38.2 (2026-02), OS/패키지 CVE 자동 열거 (nuclei 보완) | `go install github.com/future-architect/vuls@latest` | scout, analyst |

### CTF 지식베이스 (4개)

| 레포 | Stars | 내용 | 보완 영역 |
|------|-------|------|-----------|
| **RPISEC/MBE** | 5.9K | 10 Labs + 15 강의 (heap/kernel/C++/format string) | heap UAF, C++ vTable, 커널 |
| **HEVD** | 2.9K | 16개 Windows 커널 취약점 유형별 소스+익스플로잇 | Windows 커널 (최대 공백) |
| **Cryptogenic/Exploit-Writeups** | 765 | PS4/FreeBSD 7단계 커널 익스플로잇 체인 라이트업 | kASLR, Heap Spray, Kernel ROP |
| **google/google-ctf** | 4.9K | 2017-2025 Google CTF 공식 문제+솔루션+Docker | Web CTF, 고급 pwn, 벤치마크 |

### 경쟁자 분석 / 프레임워크 (2개)

| 레포 | Stars | 핵심 | 차용 가능 패턴 |
|------|-------|------|----------------|
| **CAI** (aliasrobotics/cai) | 7.2K | 오픈소스 보안 AI, HTB 최상위, 3600x 성능 | MCP 기반 도구 통합, 벤치마크 방법론 |
| **Shannon** (KeygraphHQ) | 24.7K | 자율 AI 웹 펜테스터, XBOW 96%, AGPL | 웹 BB 파이프라인 교체/통합 후보 |

### Awesome List (2개)

| 레포 | Stars | 신규 가치 |
|------|-------|-----------|
| **0xor0ne/awesome-list** | 3.1K | UEFI/MTE/ICS/EDR 우회 최신 시스템 보안 연구 (2025년까지) |
| **0xricksanchez/paper_collection** | 1.4K | 200+ 퍼징/펌웨어/LLM보안 학술 논문 인덱스 |

---

## P2 — 계획적 통합 (14개)

### 도구 (9개)

| 도구 | 용도 | 대상 에이전트 | 비고 |
|------|------|--------------|------|
| **ImHex** | 패턴 언어 + YARA 바이너리 구조 분석 | reverser, fw_profiler | |
| **linux-exploit-suggester** | 커널 버전 → privesc CVE 제안 | chain, exploiter | |
| **osmedeus** | 성숙한 정찰 워크플로우 템플릿 (DAG 참고) | scout | |
| **ropium** | 시맨틱 ROP 자동 체이닝 (`"rax=rbx+8"` 쿼리) | chain | P1 → P2 강등: 2024-08 이후 dormant, Python breakage 위험 |
| **OWASP/mastg** | 모바일 BB 방법론, Frida MCP와 페어링 | exploiter (모바일) | SKIP → P2 승격 |
| **AD Exploitation Cheat Sheet** | ADCS 공격 + BloodHound 명령어, AD 타겟 실전 참조 | chain, exploiter | P3 → P2 승격 |
| **Apktool** | v3.0.1 Android APK 디컴파일/RE | reverser (Android) | P3 → P2 승격 |
| **routersploit** | 임베디드 장치 exploit 프레임워크 | chain, exploiter | the-book-of-secret-knowledge 발굴 |
| **amass** | OWASP 서브도메인 열거 (subfinder 보완) | scout | the-book-of-secret-knowledge 발굴 |
| **dnstwist** | 타이포스쿼팅 도메인 탐지 | scout | the-book-of-secret-knowledge 발굴 |

### 지식 (3개)

| 레포 | 내용 |
|------|------|
| **CTF-All-In-One** | House of X 시리즈 45개 heap 라이트업 |
| **awesome-ctf** | one_gadget, RSACTFTool, Triton 도구 목록 |
| **linux-kernel-exploitation** | kernelCTF 기법 인덱스, 방어우회 시계열 |

### 프레임워크 (2개)

| 레포 | 차용 포인트 |
|------|-------------|
| **Decepticon** | Swarm Architecture, Supervisor 패턴 |
| **Red-Teaming-Toolkit** | 단계별 레드팀 방법론 치트시트 |

---

## P3 / REF — 참조만 (11개)

| 레포 | 참조 용도 | 변경 |
|------|-----------|------|
| h4cker | 보고서 템플릿, AI보안 섹션 | |
| android-security | Knox/TrustZone/baseband (모바일 BB 진입 시) | |
| OWASP CheatSheetSeries | reporter remediation 인용 URL | |
| Hello-CTF | Web/AI CTF 입문 | |
| Reverse-Engineering | 이북 URL 북마크 | |
| fireELF | fileless RCE 증명 | |
| go-exploit | Java/네트워크 서비스 CVE PoC | |
| reverse-shell-generator | 언어별 리버스셸 레퍼런스 | |
| **sherlock** | 400+ 플랫폼 username OSINT, scout Phase 0 정찰 | SKIP → P3 승격 |
| **L1B3RT4S** | Prompt injection 방어 레퍼런스 (Guardrails 강화) | SKIP → P3 승격 |

> 참고: AD Exploitation Cheat Sheet와 Apktool은 P2로 승격되어 이 목록에서 제외됨.

---

## SKIP (36개)

중복(기존 도구 50%+), 교육용(초보자 대상), Archived, 범위 밖, 라이선스 문제로 제외:

the-book-of-secret-knowledge(208K, 70% 중복 — 단, routersploit/amass/dnstwist는 P2로 개별 발굴), Awesome-Hacking(107K, 메타인덱스), Awesome-Hacking-Resources(16.8K, 70% 중복), 90DaysOfCyberSecurity(13.5K, 초보자), hacker-roadmap(15.1K, Archived), Cheatsheet-God(5.5K, PAT 하위호환), blackhat-arsenal-tools(4.2K, Archived), Awesome-Vulnerability-Research(1.3K, 소규모), All-In-One-CyberSecurity(545, 초보자), librepods(25.5K, AirPods), x64dbg(47.8K, Windows GUI), Quivr(39K, GraphRAG 중복), hosts(29.9K, 방어도구), Android-Debug-Database(8.6K, Android 앱), Sn1per(9.4K, monolithic), PhoneSploit-Pro(5.6K, Android 기기), AllHackingTools(5.2K, 설치스크립트), Privilege-Escalation(3.5K, PAT 중복), gpt4free(xtekky, API 안정성 의문), PayloadsAllTheThings(이미 클론), nuclei-templates(이미 클론), GEF(이미 설치), chrome-devtools-mcp(이미 통합), sqlmap(이미 설치),
**werdlists**(362 stars, SecLists가 95%+ 커버, P3 → SKIP: 중복),
**Villain**(CC-NC 라이선스, 상업적 BB 환경 비호환, P3 → SKIP: 라이선스),
OWASP/mastg(P2로 승격), Sherlock(P3로 승격 — sherlock), L1B3RT4S(P3로 승격)

---

## 통합 실행 계획

### Phase 1: 즉시 (당일)

```bash
# 도구 설치 (P1 신규 포함)
pip install ciphey
cargo install rustscan || apt install rustscan
wget -O ~/tools/rp++ https://github.com/0vercl0k/rp/releases/latest/download/rp-lin-x64
chmod +x ~/tools/rp++

# web-check (Docker self-hostable)
docker pull lissy93/web-check
# 또는 REST API 직접 사용: https://web-check.xyz/api/<endpoint>

# vuls (OS/패키지 CVE 열거)
go install github.com/future-architect/vuls@latest
# 또는: pip install vulsrepo

# CTF 지식베이스 클론
git clone --depth=1 https://github.com/RPISEC/MBE ~/tools/MBE
git clone --depth=1 https://github.com/hacksysteam/HackSysExtremeVulnerableDriver ~/tools/HEVD
git clone https://github.com/Cryptogenic/Exploit-Writeups ~/tools/exploit-writeups
git clone --depth=1 --filter=blob:none https://github.com/google/google-ctf ~/tools/google-ctf

# 경쟁자 코드 클론 (분석용)
git clone --depth=1 https://github.com/aliasrobotics/cai ~/tools/cai-analysis
git clone --depth=1 https://github.com/KeygraphHQ/shannon ~/tools/shannon-analysis
```

### Phase 2: 1주 내

```bash
# 추가 도구 (P2 — 신규 포함)
apt install imhex || snap install imhex
pip install rsactftool
wget -O ~/tools/linux-exploit-suggester.sh https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x ~/tools/linux-exploit-suggester.sh

# ropium (Python breakage 위험 — 가상환경 격리 권장)
python3 -m venv ~/venvs/ropium && source ~/venvs/ropium/bin/activate && pip install ropium

# OWASP MASTG (모바일 BB 방법론)
git clone --depth=1 https://github.com/OWASP/owasp-mastg ~/tools/mastg

# AD Exploitation Cheat Sheet
git clone --depth=1 https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet ~/tools/ad-exploitation

# Apktool v3.0.1 (Android RE)
wget -O ~/tools/apktool.jar https://github.com/iBotPeaches/Apktool/releases/download/v3.0.1/apktool_3.0.1.jar
echo '#!/bin/bash\njava -jar ~/tools/apktool.jar "$@"' > ~/tools/apktool && chmod +x ~/tools/apktool

# routersploit (임베디드 장치)
git clone --depth=1 https://github.com/threat9/routersploit ~/tools/routersploit
pip install -r ~/tools/routersploit/requirements.txt

# amass (서브도메인 열거)
go install -v github.com/owasp-amass/amass/v4/...@master

# dnstwist (타이포스쿼팅 탐지)
pip install dnstwist

# sherlock (username OSINT)
git clone --depth=1 https://github.com/sherlock-project/sherlock ~/tools/sherlock
pip install -r ~/tools/sherlock/requirements.txt

# Awesome list 지식 추출
# → knowledge/techniques/systems_security_refs_2024_2025.md
# → knowledge/techniques/security_papers_index.md
# → knowledge/techniques/kernel_exploitation_refs.md

# CTF-All-In-One writeup 추출
git clone --depth=1 https://github.com/firmianay/CTF-All-In-One ~/tools/CTF-All-In-One
```

### Phase 3: knowledge/ 문서 생성

```
knowledge/techniques/heap_house_of_x.md          ← MBE Lab07 + CTF-AIO writeup
knowledge/techniques/windows_kernel_exploitation.md ← HEVD 소스 분석
knowledge/techniques/kernel_exploit_multistage.md   ← Cryptogenic PS4 라이트업
knowledge/techniques/web_ctf_techniques.md          ← Google CTF 웹 문제
knowledge/techniques/systems_security_refs_2024_2025.md ← 0xor0ne/awesome-list
knowledge/techniques/security_papers_index.md       ← paper_collection
knowledge/techniques/cpp_vtable_exploitation.md     ← MBE Lab09
knowledge/techniques/mobile_bb_methodology.md       ← OWASP MASTG + Frida MCP 통합
knowledge/techniques/ad_exploitation_ref.md         ← AD Cheat Sheet 요약
```

### Phase 4: 에이전트 프롬프트 업데이트

| 에이전트 | 추가 내용 |
|----------|-----------|
| chain | rp++ ARM 가젯 검색, MBE Lab07 UAF 패턴, ropium (격리 venv에서 시도, 실패 시 ROPgadget 폴백) |
| solver | Ciphey 자동 복호화 첫 번째 시도, RSACTFTool crypto CTF |
| scout | RustScan 포트 스캔, web-check REST API 원샷 정찰, vuls CVE 열거, amass 서브도메인, dnstwist 타이포스쿼팅, sherlock username OSINT |
| reverser | HEVD Windows 드라이버 IOCTL 패턴, Cryptogenic 커널 분석, Apktool Android APK |
| exploiter | routersploit 임베디드 장치, OWASP MASTG 모바일 테스트 절차 |
| critic | House of X 시리즈 heap 검증 기준, L1B3RT4S prompt injection 방어 참조 |

### Phase 5: CLAUDE.md "Local Security Tools" 섹션 업데이트

```
추가:
- Ciphey (50+ 암호/인코딩 자동 탐지)
- RustScan (65535 포트 3초 스캔)
- rp++ (ARM/ARM64/Mach-O ROP 가젯)
- web-check (33 REST API 엔드포인트 웹 정찰, Docker)
- vuls v0.38.2 (OS/패키지 CVE 자동 열거)
- linux-exploit-suggester (커널 privesc 자동 제안)
- RSACTFTool (RSA 취약 파라미터 공격)
- ropium (시맨틱 ROP 체이닝, venv 격리 — Python breakage 주의)
- routersploit (임베디드 장치 exploit 프레임워크)
- amass (OWASP 서브도메인 열거)
- dnstwist (타이포스쿼팅 도메인 탐지)
- sherlock (400+ 플랫폼 username OSINT)
- Apktool v3.0.1 (Android APK 디컴파일)
```

---

## 경쟁자 분석 요약

### CAI (aliasrobotics/cai) — 7.2K stars
- **아키텍처**: 300+ LLM 모델 지원, MCP 기반, pre-built 공격 도구 체인
- **성과**: HTB 최상위, Dragos OT CTF Top-10, 3600x 인간 대비
- **Terminator가 더 나은 점**: 구조화된 파이프라인(reverser→chain→critic→verifier), 에이전트별 모델 지정, HANDOFF 프로토콜, 지식 누적 시스템
- **CAI가 더 나은 점**: 300+ 모델 지원, 더 많은 벤치마크 실적, 오픈소스 커뮤니티
- **차용 포인트**: 벤치마크 방법론, MCP 도구 통합 패턴

### Shannon (KeygraphHQ) — 24.7K stars
- **아키텍처**: Claude Agent SDK, Recon→Analysis→Exploitation→Report 4단계
- **성과**: XBOW 벤치마크 96.15%, 회당 ~$50
- **Terminator 비교**: Shannon은 웹 전용, Terminator는 멀티도메인
- **차용/통합**: 웹 BB 타겟에서 Shannon Lite를 직접 사용하거나, 아키텍처 패턴 참조
- **OWASP 카테고리별 병렬 에이전트**: Terminator의 Shannon Pattern(Phase 1.5)과 동일 원리

### Decepticon (PurpleAILAB) — 808 stars
- **아키텍처**: LangChain/LangGraph + MCP, Swarm Architecture
- **상태**: Experimental, Recon+Initial Access만 구현
- **Terminator 비교**: Terminator가 더 성숙 (17 에이전트, 10 MCP 서버)
- **차용 포인트**: Swarm Architecture (peer-to-peer 에이전트 통신)

---

## AI/Security 최신 동향 (2026-02-24)

### 즉시 주목

| 항목 | 핵심 |
|------|------|
| **Claude Code Security** (Anthropic, 2/20) | Opus 4.6 기반 자동 취약점 탐지. 500+ zero-day. Enterprise preview |
| **AgentLAB** (arXiv 2602.16901) | LLM 에이전트 장기 공격 벤치마크. 공격 성공률 28-81% |
| **OpenClaw 재앙** | 180K stars → 90일 만에 보안 참사. 1,184 악성 스킬 |
| **OWASP Agentic AI Top 10** | Goal Hijack, Tool Misuse, Memory Poisoning 등 |
| **GitHub Security Lab Taskflow Agent** | LLM 기반 취약점 트리아지 자동화 |

### 반면교사
- **OpenClaw**: MCP 서버, 에이전트 설정 파일 보안 강화 필요
- **Cline 공급망 공격**: 외부 스킬/플러그인 도입 시 공급망 공격 대비
