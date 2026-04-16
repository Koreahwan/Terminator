# Installed Bug Bounty & Security Tools Reference

**Updated**: 2026-02-22

## PATH Setup (every new shell)
```bash
export GOPATH=$HOME/gopath
export PATH=$HOME/go/bin:$GOPATH/bin:$HOME/.local/bin:$HOME/tools/mitmproxy:$HOME/tools/codeql:$PATH
```
Add to `~/.bashrc` as needed. New Bash tool calls need explicit PATH or absolute paths.

---

## Go-based Tools (`~/gopath/bin/`)

| Tool | Version | Command | Purpose |
|------|---------|---------|---------|
| **ffuf** | 2.1.0-dev | `~/gopath/bin/ffuf` | Web fuzzer (dirs, params, vhosts) |
| **nuclei** | 3.7.0 | `~/gopath/bin/nuclei` | Vulnerability scanner (template-based) |
| **subfinder** | 2.12.0 | `~/gopath/bin/subfinder` | Subdomain discovery (passive) |
| **katana** | 1.4.0 | `~/gopath/bin/katana` | Web crawler/spider |
| **httpx** | 1.8.1 | `~/gopath/bin/httpx` | HTTP toolkit (probe, tech detect) |
| **naabu** | latest | `~/gopath/bin/naabu` | Port scanner (needs libpcap) |
| **dalfox** | 2.12.0 | `~/gopath/bin/dalfox` | XSS scanner |
| **gau** | latest | `~/gopath/bin/gau` | Get All URLs (Wayback+OTX+CC) |
| **waybackurls** | latest | `~/gopath/bin/waybackurls` | Wayback Machine URL fetcher |
| **interactsh-client** | 1.3.0 | `~/gopath/bin/interactsh-client` | OOB interaction server (SSRF/blind tests) |
| **gh** | 2.45.0 | `/usr/bin/gh` | GitHub CLI (PRs, issues, API) |

### Quick Usage
```bash
# Subdomain enumeration
~/gopath/bin/subfinder -d target.com -o subs.txt

# Probe live hosts
cat subs.txt | ~/gopath/bin/httpx -o live.txt

# Port scan
~/gopath/bin/naabu -host target.com -p 1-10000

# Directory fuzzing
~/gopath/bin/ffuf -u https://target.com/FUZZ -w ~/SecLists/Discovery/Web-Content/common.txt

# Vulnerability scan
~/gopath/bin/nuclei -u https://target.com -t ~/nuclei-templates/

# Web crawling
~/gopath/bin/katana -u https://target.com -d 3

# XSS scanning
~/gopath/bin/dalfox url https://target.com/search?q=test

# URL collection
echo "target.com" | ~/gopath/bin/gau --o urls.txt
echo "target.com" | ~/gopath/bin/waybackurls > wayback.txt

# OOB interaction server (SSRF/blind testing)
~/gopath/bin/interactsh-client
```

---

## Python-based Tools (`~/.local/bin/` or `~/miniconda3/bin/`)

| Tool | Command | Purpose |
|------|---------|---------|
| **arjun** | `arjun` | HTTP parameter discovery |
| **dirsearch** | `dirsearch` | Directory/file bruteforcer |
| **trufflehog** | `~/gopath/bin/trufflehog` | Secret/credential scanner (v3.93.3, 800+ types, validation) |
| **commix** | `python3 ~/commix/commix.py` | Command injection exploitation |
| **SSRFmap** | `python3 ~/SSRFmap/ssrfmap.py` | SSRF exploitation (18+ modules: AWS, Redis, FastCGI) |
| **sqlmap** | `/usr/bin/sqlmap` | SQL injection automation |
| **mitmproxy** | `~/tools/mitmproxy/mitmproxy` | HTTP(S) intercept proxy (v12.2.1) |
| **fuxploider** | `python3 ~/fuxploider/fuxploider.py` | File upload vulnerability scanner/exploiter |
| **codeql** | `~/tools/codeql/codeql` | Semantic code analysis (variant hunting, taint tracking) |
| **garak** | `garak` | LLM vulnerability scanner (NVIDIA, prompt injection/jailbreak/data leak testing) v0.14.0 |
| **promptfoo** | `promptfoo` | Prompt injection testing & red teaming for LLM apps v0.120.19 |

### Quick Usage
```bash
# Parameter discovery
arjun -u https://target.com/api/endpoint

# Directory bruteforce
dirsearch -u https://target.com -w ~/SecLists/Discovery/Web-Content/common.txt

# Secret scanning in git repo (verified secrets only)
~/gopath/bin/trufflehog git https://github.com/org/repo --only-verified
~/gopath/bin/trufflehog git file://. --only-verified  # local repo

# Command injection
python3 ~/commix/commix.py -u "https://target.com/api?cmd=test"

# SSRF exploitation (18+ modules)
python3 ~/SSRFmap/ssrfmap.py -r request.txt -p url -m readfiles  # read local files
python3 ~/SSRFmap/ssrfmap.py -r request.txt -p url -m aws  # AWS metadata

# SQL injection
sqlmap -u "https://target.com/api?id=1" --batch

# HTTP proxy
~/tools/mitmproxy/mitmproxy -p 8080
~/tools/mitmproxy/mitmdump -p 8080 -w dump.flow  # headless
```

---

## Payload & CVE Reference Databases

| Collection | Path | Size | Purpose |
|-----------|------|------|---------|
| **PayloadsAllTheThings** | `~/PayloadsAllTheThings/` | 22 MB | 70+ vuln category payloads (SQLi, XSS, SSRF, XXE, etc.) |
| **trickest-cve** | `~/trickest-cve/` | 745 MB | 154K+ CVE PoC files (1999-2026, auto-updated) |
| **ExploitDB** | `~/exploitdb/` | — | 47K+ exploits (`searchsploit <query>`) |
| **PoC-in-GitHub** | `~/PoC-in-GitHub/` | — | 8K+ GitHub PoC references |
| **corkami/collisions** | `~/collisions/` | 97 MB | Hash collision techniques (MD5, SHA-1 — crypto CTF reference) |

### Quick Usage
```bash
# PayloadsAllTheThings — grab payloads for specific vuln type
cat ~/PayloadsAllTheThings/"SQL Injection"/README.md | head -100
cat ~/PayloadsAllTheThings/"SSRF"/README.md | head -100
ls ~/PayloadsAllTheThings/  # list all 70+ categories

# trickest-cve — find CVE PoCs
ls ~/trickest-cve/2025/ | grep -i <keyword>
cat ~/trickest-cve/2025/CVE-2025-NNNNN.md  # CVE details + PoC links

# ExploitDB
~/exploitdb/searchsploit <service> <version>

# PoC-in-GitHub
ls ~/PoC-in-GitHub/2025/ | grep -i <keyword>
```

---

## Wordlists

| Collection | Path | Size |
|-----------|------|------|
| **SecLists** | `~/SecLists/` | 2.5 GB |

Key wordlists:
- `~/SecLists/Discovery/Web-Content/common.txt` — general web dirs
- `~/SecLists/Discovery/Web-Content/raft-large-directories.txt` — large dir list
- `~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` — subdomain list
- `~/SecLists/Fuzzing/` — fuzzing payloads
- `~/SecLists/Passwords/` — password lists
- `~/SecLists/Payloads/` — injection payloads

---

## Nuclei Custom Template (에이전트가 직접 작성 가능)

```yaml
# ~/custom-templates/my-vuln.yaml
id: custom-ssrf-check
info:
  name: Custom SSRF Detection
  author: terminator
  severity: high
  tags: ssrf,custom

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/fetch?url=http://169.254.169.254/latest/meta-data/"
    matchers:
      - type: word
        words:
          - "ami-id"
          - "instance-id"
        condition: or
```

```bash
# 커스텀 템플릿 실행
nuclei -u https://target.com -t ~/custom-templates/ -jsonl-export results.jsonl
```

---

## Pre-existing Tools (from CTF setup)

| Tool | Purpose |
|------|---------|
| **pwntools** | Exploit development framework |
| **gdb** + pwndbg (2026.02.18) + GEF | Binary debugging (pwndbg: nearpc -f, decompiler integration, branch viz, kmem-trace, musl-ng heap; GEF: `source ~/gef/gef.py`, 93 commands) |
| **r2** (radare2) | Disassembly/decompilation |
| **angr** | Symbolic execution |
| **z3-solver** | SMT solver |
| **ROPgadget/ropper** | ROP gadget finders |
| **one_gadget** | One-shot execve gadget finder |
| **ghidra** (MCP) | Decompilation |
| **frida** (MCP) | Dynamic instrumentation |
| **jadx** | APK/DEX decompiler |
| **searchsploit** | ExploitDB search (`~/exploitdb/`) |
| **seccomp-tools** | Seccomp filter analysis |

---

## MCP Servers (Claude Code integrations)

| MCP | Tools | Purpose |
|-----|-------|---------|
| **mcp-gdb** | gdb_start, gdb_command, etc. | GDB debugging |
| **radare2-mcp** | open_file, decompile, etc. | Binary analysis |
| **pentest-mcp** | nmapScan, gobuster, nikto, john, hashcat | Network/web pentesting |
| **frida-mcp** | attach, hook, execute_in_session | Dynamic instrumentation |
| **ghidra-mcp** | list_functions, get_pseudocode | Decompilation |
| **context7** | resolve-library-id, query-docs | Documentation lookup |
| **playwright** | browser automation | Web app testing |
| **nuclei-mcp** | nuclei_scan, template_search | 12K+ 취약점 템플릿 스캔 |
| **codeql-mcp** | create_db, analyze, run_query | 시맨틱 taint tracking |
| **semgrep-mcp** | scan, rule_search | 패턴 기반 정적 분석 |

---

## GDB Enhanced Features (GEF)

GEF provides 93 additional GDB commands for exploit development:
```bash
# Load GEF (instead of default pwndbg)
gdb -q -ex "source ~/gef/gef.py" ./binary

# Key GEF commands:
# checksec          — binary protections
# vmmap             — memory layout
# heap chunks       — heap state visualization
# pattern create/search — cyclic pattern for offset finding
# rop               — ROP gadget search
# format-string-helper — format string offset finder
# got               — GOT table display
# canary            — stack canary leak helper
# shellcode         — shellcode generator
# xinfo <addr>      — what section/mapping an address belongs to
```
**Note**: GEF and pwndbg cannot load simultaneously. Use `source ~/gef/gef.py` when GEF features needed, default GDB loads pwndbg.

---

## CodeQL (Semantic Code Analysis)

```bash
# Create database from source
~/tools/codeql/codeql database create /tmp/codeql-db --language=javascript --source-root=./src

# Run security queries
~/tools/codeql/codeql database analyze /tmp/codeql-db ~/tools/codeql/qlpacks/codeql/javascript-queries --format=sarif-latest --output=results.sarif

# Run specific query
~/tools/codeql/codeql query run path/to/query.ql --database=/tmp/codeql-db
```

---

## File Upload Exploitation (Fuxploider)

```bash
# Scan for file upload vulnerabilities
python3 ~/fuxploider/fuxploider.py -u https://target.com/upload

# With custom extensions
python3 ~/fuxploider/fuxploider.py -u https://target.com/upload -e php,phtml,php5,phar
```

---

## Web3 / Smart Contract Tools

| Tool | Version | Command | Purpose |
|------|---------|---------|---------|
| **Foundry (forge)** | 1.5.1 | `~/.foundry/bin/forge` | Solidity test framework, build, deploy |
| **Foundry (cast)** | 1.5.1 | `~/.foundry/bin/cast` | Ethereum RPC CLI (call, send, decode, abi) |
| **Foundry (anvil)** | 1.5.1 | `~/.foundry/bin/anvil` | Local Ethereum node (fork mainnet) |
| **Foundry (chisel)** | 1.5.1 | `~/.foundry/bin/chisel` | Solidity REPL |
| **Slither** | latest | `~/.local/bin/slither` (pipx) | Solidity static analyzer (100+ detectors) |
| **Mythril** | latest | `~/.local/bin/myth` (pipx) | EVM bytecode symbolic execution |
| **cargo-audit** | 0.22.1 | `cargo audit` | Rust dependency vulnerability scanner (RUSTSEC DB) |
| **cargo-fuzz** | 0.13.1 | `cargo fuzz` | Rust libFuzzer integration (coverage-guided) |

### Quick Usage
```bash
# Foundry PATH (add to shell if needed)
export PATH=$HOME/.foundry/bin:$PATH

# Solidity compilation + test
forge build
forge test -vvv

# Static analysis (Slither)
slither . --detect reentrancy-eth,arbitrary-send-eth

# Symbolic execution (Mythril)
myth analyze contracts/Vulnerable.sol --execution-timeout 300

# Rust dependency audit
cd /path/to/rust-project && cargo audit

# Rust fuzz target
cargo fuzz init
cargo fuzz run <target> -- -max_total_time=300

# Anvil local fork
anvil --fork-url https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY

# Cast: read contract
cast call 0xContractAddr "balanceOf(address)" 0xUserAddr --rpc-url http://localhost:8545
```

### Slither Detectors (Bug Bounty 우선순위)
```bash
# Critical: 재진입, 임의 전송, selfdestruct
slither . --detect reentrancy-eth,reentrancy-no-eth,arbitrary-send-eth,suicidal

# High: 접근제어, 오라클 조작
slither . --detect unprotected-upgrade,controlled-delegatecall,tx-origin

# All detectors list
slither . --list-detectors
```

### Mythril Analysis Modes
```bash
# Quick scan (1-2min)
myth analyze contracts/Target.sol --execution-timeout 120

# Deep scan (10min+)
myth analyze contracts/Target.sol --execution-timeout 600 --max-depth 50

# From bytecode (on-chain)
myth analyze -a 0xContractAddress --rpc infura_url
```

## Pipeline Enhancement Tools (Sprint 2026-02-17)

### MITRE CVE→ATT&CK Mapper
```bash
# CVE 조회 → CWE → CAPEC → ATT&CK 기법 매핑
python3 tools/mitre_mapper.py CVE-2021-44228 --json
python3 tools/mitre_mapper.py CVE-2024-XXXXX          # 텍스트 출력
# 오프라인 캐시 23개 주요 CVE 내장, NVD API 2.0 fallback
```

### Neo4j Attack Surface Graph
```bash
# Neo4j 필요: docker compose up -d neo4j
# 정찰 결과 밀어넣기
python3 tools/attack_graph/cli.py ingest recon_report.json
# 공격 경로 쿼리
python3 tools/attack_graph/cli.py query attack-chains --target example.com
# 크로스세션 지식
python3 tools/attack_graph/cli.py query cross-session
# JSON 내보내기/가져오기
python3 tools/attack_graph/cli.py export --output graph_backup.json
python3 tools/attack_graph/cli.py import --input graph_backup.json
```
노드 15종: Target, Domain, Subdomain, IPAddress, Port, Service, Technology, Endpoint, Vulnerability, CAPEC, Exploit, Finding, Credential, Certificate, Agent
관계 23종: HAS_DOMAIN, RESOLVES_TO, RUNS_SERVICE, HAS_VULNERABILITY 등

### DAG Agent Orchestrator
```bash
# 파이프라인 시각화
python3 tools/dag_orchestrator/cli.py visualize ctf_pwn
python3 tools/dag_orchestrator/cli.py visualize bounty
# 사전 정의 파이프라인: ctf_pwn(6), ctf_rev(5), bounty(9), firmware(6), ai_security(10), robotics(7), supplychain(10/7)
# dry-run
python3 tools/dag_orchestrator/cli.py run ctf_pwn --dry-run
```

### 6-Phase Recon Pipeline
```bash
# 풀 스캔
python3 tools/recon_pipeline.py --target example.com --output /tmp/recon
# 특정 phase만
python3 tools/recon_pipeline.py --target example.com --phases 1,2,3
# OSS 모드 (네트워크 스캔 스킵)
python3 tools/recon_pipeline.py --target example.com --oss
# Phase: 1(Domain) → 2(Port) → 3(HTTP) → 4(Enum) → 5(Vuln) → 6(MITRE)
```

### LiteLLM Model Router
```bash
# LiteLLM 프록시 필요: docker compose up -d litellm
python3 tools/model_router.py --mode analyze --question "Is this SQL injectable?" --file src/api.py
python3 tools/model_router.py --mode triage --question "Rate severity" --role analyst
python3 tools/model_router.py --mode summarize-dir --dir ./src
# 모드: reverse, analyze, triage, summarize, protocol, bizlogic, summarize-dir, review, ask
```

### SARIF Generator (GitHub Code Scanning)
```bash
python3 tools/sarif_generator.py --input findings.json --output results.sarif
# findings.json 형식: [{"id":"...", "name":"...", "severity":"high", ...}]
# GitHub Actions에서: gh api repos/{owner}/{repo}/code-scanning/sarifs -X POST
```

### PDF Report Generator
```bash
# weasyprint 설치 시
python3 tools/pdf_generator.py --input report.md --output report.pdf
# HTML fallback (weasyprint 없을 때)
python3 tools/pdf_generator.py --input report.md --output report.html --html-only
# 템플릿: full (Executive Summary 포함), minimal (findings만)
python3 tools/pdf_generator.py --input report.md --output report.pdf --template minimal
```

### Benchmark Framework
```bash
# 전체 벤치마크 (20 CTF)
python3 tests/benchmarks/benchmark.py --run-all
# 특정 챌린지
python3 tests/benchmarks/benchmark.py --challenge dhcc
# 결과: metrics JSON + 정확도 리포트
```

### Docker Infrastructure
```bash
# 전체 기동
cd "$TERMINATOR_ROOT"   # or your local Terminator checkout
docker compose up -d

# 개별 서비스
docker compose up -d db neo4j     # DB만
docker compose up -d web-ui       # 대시보드만

# Health check
curl localhost:3000               # Web UI
curl localhost:8100/health        # RAG API
curl localhost:7474               # Neo4j Browser
curl localhost:4000/health        # LiteLLM

# 원격 접속 (Tailscale VPN 경유)
# http://100.127.216.114:3000      # Web Dashboard
# http://100.127.216.114:7474      # Neo4j Browser (neo4j / terminator)
# http://100.127.216.114:8100      # RAG API
# http://100.127.216.114:11434     # Ollama
# DB: 100.127.216.114:5433 (호스트 PG 충돌 방지로 5433)
```

---

## Web Crawling & Browser Tools

| Tool | Command | Purpose |
|------|---------|---------|
| **crawl4ai** | `crawl4ai` (pipx) | LLM-optimized web crawler — Playwright JS rendering, Markdown output, stealth mode |
| **chrome-devtools-mcp** | `npx chrome-devtools-mcp` | Chrome DevTools Protocol MCP — 26 tools: network, console, JS eval, screenshots |

### Quick Usage
```bash
# crawl4ai — LLM-friendly web crawling (Python)
python3 -c "
from crawl4ai import AsyncWebCrawler
import asyncio
async def main():
    async with AsyncWebCrawler() as crawler:
        result = await crawler.arun(url='https://target.com')
        print(result.markdown[:2000])
asyncio.run(main())
"

# chrome-devtools-mcp — registered as MCP server, use via Claude Code MCP tools
# Tools: network inspection, console messages, JS evaluation, screenshots
```

---

## Vulnerability Reference Databases (New)

| Collection | Path | Purpose |
|-----------|------|---------|
| **protocol-vulnerabilities-index** | `knowledge/protocol-vulns-index/` | 460 vulnerability categories × 31 DeFi protocol types |

### Quick Usage
```bash
# Load protocol-specific vulnerability checklist
cat knowledge/protocol-vulns-index/categories/lending.md     # DeFi Lending (17 cats)
cat knowledge/protocol-vulns-index/categories/dexes.md       # DEX/AMM (19 cats)
cat knowledge/protocol-vulns-index/categories/liquid_staking.md  # Liquid Staking (20 cats)
cat knowledge/protocol-vulns-index/categories/bridge.md      # Bridge (18 cats)
# See knowledge/techniques/protocol_vulns_index_guide.md for full mapping
```

---

## pwndbg 2026.02.18 New Features

```bash
# Branch-visualized disassembly
nearpc -f main            # full function with branch arrows
nearpc -r 20              # 20 previous instructions
nearpc -t 50              # total 50 instructions

# Decompiler integration (IDA/Ghidra/r2/rizin backends)
decompiler connect ghidra  # connect to Ghidra backend
decompile main             # pseudocode in GDB context

# Kernel heap tracing
kmem-trace                 # SLUB/buddy allocator tracking

# musl-ng heap analysis
mallocng-dump              # musl allocator state
mallocng-explain           # explain musl heap structure
mallocng-vis               # visualize musl heap

# Compact mode
set context-regs-show very # minimal register display
```

---

## AI/LLM Security

| Tool | Path | Purpose |
|------|------|---------|
| **garak** | Python module | LLM vulnerability scanner (OWASP LLM Top 10 probes) |
| **promptfoo** 0.121.3 | `~/.npm-global/bin/promptfoo` | LLM red-team evaluation framework |
| **httpx** | Python module | Async HTTP client for API probing |

## Supply Chain Security

| Tool | Path | Purpose |
|------|------|---------|
| **syft** 1.42.3 | `~/bin/syft` | SBOM generator (CycloneDX/SPDX output) |
| **grype** 0.110.0 | `~/bin/grype` | Vulnerability matcher (reads SBOM input) |
| **pip-audit** 2.10.0 | `pip-audit` | Python dependency vulnerability scanner |

## Robotics/ROS

| Tool | Path | Purpose |
|------|------|---------|
| **ROS2 Humble** | `docker run ros:humble` | ROS CLI + simulation (Docker-only) |

---

## Needs sudo

nmap, ltrace, checksec, nikto, pwndbg, MobSF(docker), naabu(libpcap)
