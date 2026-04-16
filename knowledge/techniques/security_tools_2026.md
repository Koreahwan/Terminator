# Security Tools Reference (2026 Edition)

> `installed_tools_reference.md` (18KB, 기존) 와 `pipeline_tools_2026.md` (4KB) 의
> 2026-04 버전 업데이트. 추가 도구 + 최신 버전 + 추천 설치 스크립트.

---

## 1. Recon / 정찰

### 1.1 ProjectDiscovery Suite (업데이트 권장)
모두 Go-based, 빠른 실행, 조합 편리.

| 도구 | 용도 | 설치 |
|------|------|------|
| `subfinder` | 서브도메인 수집 (passive 30+ sources) | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `httpx` | HTTP probe, status/title/tech | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `naabu` | 포트 스캔 (SYN/CONNECT) | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| `katana` | Crawler (headless + JS) | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `nuclei` | 템플릿 기반 취약점 스캐너 | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `notify` | 결과를 Slack/Discord/Telegram 전송 | `go install github.com/projectdiscovery/notify/cmd/notify@latest` |
| `interactsh` | OAST (SSRF/RCE callback) | 자체 호스팅 권장 |
| `dnsx` | DNS bulk resolve | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| `shuffledns` | Massdns wrapper | `go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest` |
| `chaos-client` | Chaos dataset query | `go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest` |
| `asnmap` | ASN 정보 | `go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest` |
| `cdncheck` | CDN 판별 | `go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest` |
| `uncover` | Shodan/Censys/FOFA 통합 | `go install github.com/projectdiscovery/uncover/cmd/uncover@latest` |

**Nuclei 템플릿 최신화**:
```bash
nuclei -update-templates
nuclei -ut  # shortcut
```

### 1.2 대체/보조
- `amass` — subfinder 대체 후보 (더 깊은 source, 느림)
- `assetfinder` — 가벼운 서브도메인 수집
- `gau` / `waybackurls` / `getallurls` — URL 히스토리
- `hakrawler` — katana 대체
- `RustScan` — naabu 대체 (속도 우위, Rust)

---

## 2. Web Fuzzing / Pentest

| 도구 | 특징 | 메모 |
|------|------|------|
| `ffuf` | 사실상 표준 HTTP fuzzer | Go, 빠름 |
| `feroxbuster` | Rust 기반, 재귀 |  |
| `caido` | Burp 대체 (무료 community + 유료 Pro) | 2024-25 급성장, 매크로/프로젝트 관리 우수 |
| `Burp Suite Pro` | 업계 표준 | 연간 라이선스 |
| `ZAP` | OWASP 오픈소스 | CI/CD 통합 |
| `sqlmap` | SQL injection 자동화 | 지속 업데이트 |
| `commix` | Command injection | |
| `SSRFmap` | SSRF 자동화 | |
| `tplmap` | SSTI 자동화 | |
| `arjun` | 숨겨진 파라미터 발견 | |
| `paramspider` | URL에서 parameter 추출 | |
| `gobuster` | dir/dns bust | |
| `wpscan` | WordPress | |
| `jaeles` | signature 기반 scan | |

**Caido 권장 설정** (2026 기준):
- Projects로 타겟 분리
- HTTPQL 쿼리 저장
- Workflow (replay + assertion) 자주 쓰는 테스트 자동화

---

## 3. Secret / Credential 탐색

| 도구 | 범위 | 특징 |
|------|------|------|
| `trufflehog` | git history, filesystem, S3 | 350+ detector, validate까지 |
| `gitleaks` | git pre-commit/history | 빠름, regex 기반 |
| `noseyparker` | 대규모 repo (ML) | Rust, 속도 우위 |
| `detect-secrets` | pre-commit (Yelp) | baseline 관리 |
| `semgrep secrets` | Semgrep 공식 ruleset | AST 기반 fp 낮음 |
| `shhgit` | real-time GitHub 모니터링 | |

---

## 4. Supply Chain

| 도구 | 범위 |
|------|------|
| `osv-scanner` | 다중 lockfile + OSS-Fuzz |
| `snyk` | 상용, 언어 광범위 |
| `socket` (CLI) | npm/pypi 실시간 behavioral |
| `syft` | SBOM 생성 (여러 포맷) |
| `grype` | syft SBOM → 취약점 매칭 |
| `cyclonedx-cli` | SBOM 조작 |
| `stepsecurity/harden-runner` | GitHub Actions runtime |
| `minder` (Stacklok) | SBOM + policy |
| `dependency-track` | SBOM 관리 플랫폼 |

---

## 5. SAST / Static Analysis

| 도구 | 언어 범위 |
|------|-----------|
| `semgrep` | 30+ 언어, 커뮤니티 룰 풍부 |
| `CodeQL` | GitHub, 딥 타입 분석 |
| `Bandit` | Python |
| `gosec` | Go |
| `Brakeman` | Ruby on Rails |
| `spotbugs`/`find-sec-bugs` | Java |
| `slither` / `aderyn` | Solidity (aderyn = Rust 기반 신형) |
| `mythril` | Solidity symbolic |
| `halmos` | Foundry formal verification |
| `kontrol` | Symbolic (K Framework) |
| `wake` | Solidity 통합 프레임워크 |

**Solidity 추천 조합 (2026)**:
```bash
slither .              # 빠른 패턴 매칭
aderyn                 # 보완, Rust 속도
myth analyze           # symbolic
forge test --verbosity # PoC 검증
halmos                 # formal verification for critical paths
```

---

## 6. DAST / Fuzzing

| 도구 | 용도 |
|------|------|
| `AFL++` | 바이너리 fuzzing |
| `libFuzzer` | in-process fuzzing |
| `Jazzer` | Java fuzzing |
| `Atheris` | Python fuzzing |
| `cargo-fuzz` | Rust |
| `ityfuzz` | DeFi smart contract fuzzer |
| `medusa` | Solidity coverage-guided |
| `echidna` | Solidity property-based |
| `ffuf` | HTTP fuzzing |
| `restler-fuzzer` (Microsoft) | REST API stateful fuzzing |
| `syzkaller` | Linux kernel fuzzer |
| `LibAFL` | framework |

---

## 7. Binary / RE

### 7.1 Decompilers
| 도구 | 메모 |
|------|------|
| Ghidra | PRIMARY, 무료, MCP 플러그인 있음 |
| IDA Pro / IDA Free | 상용 |
| Binary Ninja | Python API 훌륭 |
| Cutter (Rizin) | radare2 계열 (**본 프로젝트 BANNED**) |
| Rellic / RetDec | C decompilation |
| `objdump`, `llvm-objdump` | lightweight disasm |
| `readelf`, `pefile` | ELF/PE 메타 |

### 7.2 Dynamic / Debug
- `gdb` + pwndbg + GEF + MCP
- `strace` / `ltrace`
- `rr` (record & replay debugging)
- `frida` (+ MCP)
- `x64dbg` (Windows)
- `LLDB`

### 7.3 Exploit Dev
- `pwntools`
- `ROPgadget` / `ropper`
- `angr` (symbolic execution)
- `z3` (SMT solver)
- `rp++`

---

## 8. Cloud

| 도구 | 용도 |
|------|------|
| `pacu` | AWS exploitation framework |
| `cloudmapper` | AWS viz |
| `prowler` | CSPM (AWS/GCP/Azure/K8s) |
| `ScoutSuite` | 다중 클라우드 감사 |
| `cloudsplaining` | IAM 권한 분석 |
| `pmapper` | IAM 경로 분석 |
| `checkov` | IaC static scan |
| `tfsec` / `trivy` | IaC/컨테이너 |
| `kics` | IaC multi-language |
| `kube-bench` | CIS K8s benchmark |
| `kube-hunter` | K8s pentest |
| `peirates` | K8s post-exploit |
| `stratus-red-team` | cloud TTP simulation |

---

## 9. Mobile

| 도구 | 범위 |
|------|------|
| `MobSF` | 자동 Android/iOS 분석 |
| `apktool` | APK unpack/repack |
| `jadx` | APK decompile |
| `frida` / `objection` | runtime hooking |
| `drozer` | Android IPC |
| `apkleaks` | APK secrets |
| `mob-fsftool` | iOS 파일 시스템 |
| `class-dump` / `otool` | iOS class/bin 분석 |
| `LIEF` | multi-format binary manipulation |

---

## 10. AI/LLM Security (신규 분야)

| 도구 | 용도 |
|------|------|
| `garak` (NVIDIA) | LLM vulnerability scanner | 
| `pyrit` (Microsoft) | AI red team framework |
| `promptfoo` | prompt testing / eval |
| `llm-guard` (ProtectAI) | input/output scanner |
| `LlamaGuard` | meta-safety model |
| `Rebuff` | prompt injection defense |
| `guardrails-ai` | output validation |
| `parry-guard` (자체) | prompt injection scanner |
| `NeMo Guardrails` (NVIDIA) | policy layer |
| `mindgard` | 상용 red team SaaS |

### AI 도구 설치 (추천)
```bash
pip install garak promptfoo pyrit
```

---

## 11. Smart Contract 전용 (신규/업그레이드)

| 도구 | 용도 | 버전 |
|------|------|------|
| `foundry` | 사실상 표준 | 최신 main |
| `hardhat` | JS/TS 친화 | 2.x |
| `halmos` | Foundry-based symbolic | 최신 |
| `medusa` | coverage-guided | 최신 |
| `aderyn` | Rust Solidity analyzer | 0.x → 1.0 준비 |
| `wake` | Python 프레임워크 | 개선 지속 |
| `chisel` | Foundry REPL | 포함 |
| `cast` | Foundry CLI | 포함 |

---

## 12. 펜테스트 / Red Team 플랫폼

| 도구 | 유형 |
|------|------|
| `Sliver` | C2 (Go) |
| `Mythic` | 모듈식 C2 |
| `Havoc` | 상용 C2 대체 |
| `Merlin` | Go-based C2 |
| `Nemesis` (SpecterOps) | 포스트-익스 분석 |
| `BloodHound` | AD attack paths |
| `AD Miner` | AD 분석 |
| `CrackMapExec` / `NetExec` | AD lateral (NetExec가 cme 계승) |
| `Impacket` | 프로토콜 툴박스 |
| `Responder` | LLMNR/NBT 위조 |
| `Certipy` | AD CS |
| `PetitPotam` / `Coercer` | AuthN coercion |

---

## 13. 설치 스크립트 예시

```bash
#!/bin/bash
# install_2026.sh — Terminator 2026-04 권장 도구 최신화
set -e

# Go-based ProjectDiscovery
for t in subfinder httpx naabu katana nuclei notify dnsx shuffledns asnmap cdncheck uncover; do
    go install -v github.com/projectdiscovery/$t/cmd/$t@latest 2>/dev/null || \
    go install -v github.com/projectdiscovery/$t/v2/cmd/$t@latest 2>/dev/null || \
    go install -v github.com/projectdiscovery/$t/v3/cmd/$t@latest
done
nuclei -ut  # 템플릿 업데이트

# Rust-based
cargo install ripgrep fd-find bat hyperfine noseyparker aderyn

# Python AI security
pipx install garak promptfoo

# Supply chain
curl -sSfL https://raw.githubusercontent.com/google/osv-scanner/main/scripts/install.sh | bash
npm install -g @socketsecurity/cli

# Foundry / smart contract
curl -L https://foundry.paradigm.xyz | bash && foundryup
cargo install --locked halmos

# Solidity legacy
pip install slither-analyzer mythril

# Secret
go install github.com/trufflesecurity/trufflehog/v3@latest
go install github.com/zricethezav/gitleaks/v8@latest

# Cloud
pip install prowler-cloud scoutsuite
pip install --user pacu
```

---

## 14. 2026 업그레이드 포인트 (기존 대비)

- **aderyn** 추가 (Rust Solidity analyzer)
- **halmos / kontrol** formal verification 강조
- **caido** Burp 대체 공식 추천
- **NetExec** (CrackMapExec 계승) 명시
- **garak / pyrit / promptfoo / parry-guard** AI 보안 섹션 신설
- **socket CLI** (supply chain behavioral)
- **noseyparker** (대규모 secret scan)
- **katana** (crawler)
- **stratus-red-team** (cloud TTP sim)

---

## 15. 설치 검증 체크

```bash
# 버전 일괄 확인
for cmd in subfinder httpx naabu katana nuclei ffuf caido osv-scanner semgrep \
           slither aderyn forge halmos garak promptfoo; do
    printf "%-20s " "$cmd"
    command -v $cmd >/dev/null && $cmd --version 2>&1 | head -1 || echo "NOT INSTALLED"
done
```

마지막 업데이트: 2026-04-16
> 기존 `installed_tools_reference.md` (18KB)와 `pipeline_tools_2026.md` (4KB)는 유지, 본 문서는 2026-04 기준 추가/업그레이드 델타 + 통합 참조.
