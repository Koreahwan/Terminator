# Challenge Index

> Terminator Knowledge Base. CTF challenges, Bug Bounty findings, techniques.

## Solved CTF Challenges (21)

| Challenge | Type | Flag | File |
|-----------|------|------|------|
| kernelCTF vulnmod LPE | Pwn (Kernel LPE) | Solved (local) | [kernelctf_vulnmod_lpe.md](challenges/kernelctf_vulnmod_lpe.md) |
| dhcc (Level10_1) | Reversing (flex/bison) | Solved | [level10_1_dhcc.md](challenges/level10_1_dhcc.md) |
| Too Many Questions | Crypto (AES-ECB) | Solved | [too_many_questions.md](challenges/too_many_questions.md) |
| Damnida | Reversing (Custom VM) | Solved | [damnida.md](challenges/damnida.md) |
| Conquergent | Reversing (retf VM) | Solved | [conquergent.md](challenges/conquergent.md) |
| pwnable.kr fd | Pwn | Solved | [pwnablekr_fd.md](challenges/pwnablekr_fd.md) |
| pwnable.kr collision | Pwn | Solved | [pwnablekr_col.md](challenges/pwnablekr_col.md) |
| pwnable.kr horcruxes | Pwn | Solved | [pwnablekr_horcruxes.md](challenges/pwnablekr_horcruxes.md) |
| pwnable.kr asm | Pwn (shellcode) | Solved | [pwnablekr_asm.md](challenges/pwnablekr_asm.md) |
| pwnable.kr memcpy | Pwn | Solved | [pwnablekr_memcpy.md](challenges/pwnablekr_memcpy.md) |
| pwnable.kr passcode | Pwn (GOT overwrite) | Solved | [pwnablekr_passcode.md](challenges/pwnablekr_passcode.md) |
| pwnable.kr cmd1 | Misc (filter bypass) | Solved | [pwnablekr_cmd1.md](challenges/pwnablekr_cmd1.md) |
| pwnable.kr cmd2 | Misc (filter bypass) | Solved | [pwnablekr_cmd2.md](challenges/pwnablekr_cmd2.md) |
| pwnable.kr random | Pwn (PRNG) | Solved | [pwnablekr_random.md](challenges/pwnablekr_random.md) |
| pwnable.kr input | Pwn (I/O) | Solved | [pwnablekr_input.md](challenges/pwnablekr_input.md) |
| pwnable.kr input2 | Pwn (I/O) | Solved | [pwnablekr_input2.md](challenges/pwnablekr_input2.md) |
| pwnable.kr leg | Reversing (ARM) | Solved | [pwnablekr_leg.md](challenges/pwnablekr_leg.md) |
| pwnable.kr lotto | Misc (logic) | Solved | [pwnablekr_lotto.md](challenges/pwnablekr_lotto.md) |
| pwnable.kr mistake | Misc (operator precedence) | Solved | [pwnablekr_mistake.md](challenges/pwnablekr_mistake.md) |
| pwnable.kr coin1 | Misc (binary search) | Solved | [pwnablekr_coin1.md](challenges/pwnablekr_coin1.md) |
| pwnable.kr blackjack | Misc (logic) | Solved | [pwnablekr_blackjack.md](challenges/pwnablekr_blackjack.md) |

## In Progress / Failed / Paused

| Challenge | Type | Status | Blocker | File |
|-----------|------|--------|---------|------|
| pwnable.kr hunter | Pwn (Heap UAF) | In Progress | Custom allocator exploit dev | [pwnablekr_hunter.md](challenges/pwnablekr_hunter.md) |
| unibitmap | Pwn (OOB Read+ROP) | Failed | reversal_map done, solve.py scrapped | [unibitmap.md](challenges/unibitmap.md) |
| Sand_Message | Pwn (Custom Heap) | Paused | trigger done, chain not started | [sand_message.md](challenges/sand_message.md) |
| ultrushawasm | Reversing (WASM) | Paused | WASI sh spawn failed | [ultrushawasm.md](challenges/ultrushawasm.md) |
| Level9_(8) | Pwn (stripped) | Failed | 4 attempts failed, interactive retry needed | [level9_8.md](challenges/level9_8.md) |
| M | Reversing | Not Started | 379MB binary, analysis pending | [m.md](challenges/m.md) |

## Techniques Learned

| Technique | File |
|-----------|------|
| DFA table extraction + BFS | [techniques/efficient_solving.md](techniques/efficient_solving.md) |
| GDB Oracle - Custom VM reverse engineering | [techniques/gdb_oracle_reverse.md](techniques/gdb_oracle_reverse.md) |
| SSH-based CTF interaction patterns | [techniques/ssh_interaction_patterns.md](techniques/ssh_interaction_patterns.md) |
| Bug Bounty report quality guidelines | [techniques/bug_bounty_report_quality.md](techniques/bug_bounty_report_quality.md) |
| Installed tools reference | [techniques/installed_tools_reference.md](techniques/installed_tools_reference.md) |
| Offensive MCP servers research | [techniques/offensive_mcp_servers.md](techniques/offensive_mcp_servers.md) |
| Exploit references (format strings, heap) | [techniques/exploit_references.md](techniques/exploit_references.md) |
| WASM challenge lessons | [techniques/wasm_challenge_lessons.md](techniques/wasm_challenge_lessons.md) |
| pwnable.kr Toddler's Bottle lessons | [techniques/toddlers_bottle_lessons.md](techniques/toddlers_bottle_lessons.md) |
| Web3: Immunefi top payouts & strategy | [techniques/web3_immunefi_top_payouts.md](techniques/web3_immunefi_top_payouts.md) |
| Web3: DeFi attack taxonomy (60+ vectors) | [techniques/web3_defi_attack_taxonomy.md](techniques/web3_defi_attack_taxonomy.md) |
| Web3: Smart contract audit methodology | [techniques/web3_audit_methodology.md](techniques/web3_audit_methodology.md) |
| Web3: Foundry fork PoC methodology | [techniques/web3_foundry_fork_poc.md](techniques/web3_foundry_fork_poc.md) |
| AI Security Agent Research (Anthropic, kritt.ai) | [techniques/ai_security_agents_research.md](techniques/ai_security_agents_research.md) |
| Competitor Analysis (CAI, RedAmon, Strix) | [techniques/competitor_analysis.md](techniques/competitor_analysis.md) |
| Firmware diff analysis (NETGEAR Orbi) | [techniques/firmware_diff_analysis.md](techniques/firmware_diff_analysis.md) |
| Bug Bounty Retrospective v1 (23 programs, v5 rules) | [techniques/bugbounty_retrospective_v1.md](techniques/bugbounty_retrospective_v1.md) |
| Moonwell $1.78M Vibe Coding Hack (AI oracle bug) | [techniques/moonwell_vibe_coding_hack.md](techniques/moonwell_vibe_coding_hack.md) |
| Immunefi Submission Form Template | [techniques/immunefi_submission_form.md](techniques/immunefi_submission_form.md) |
| Bugcrowd VRT (Vulnerability Rating Taxonomy) | [techniques/bugcrowd_vrt.md](techniques/bugcrowd_vrt.md) |
| Bugcrowd Submission Form Template | [techniques/bugcrowd_submission_form.md](techniques/bugcrowd_submission_form.md) |
| HackerOne Submission Form Template | [techniques/hackerone_submission_form.md](techniques/hackerone_submission_form.md) |
| Platform Submission Formats (Master Index) | [techniques/platform_submission_formats.md](techniques/platform_submission_formats.md) |
| Custom Allocator Exploitation (hunter, Sand_Message) | [techniques/custom_allocator_exploitation.md](techniques/custom_allocator_exploitation.md) |
| Prompt Caching & Token Efficiency | [techniques/prompt_caching_lessons.md](techniques/prompt_caching_lessons.md) |
| Pipeline Tools & Ecosystem 2026 | [techniques/pipeline_tools_2026.md](techniques/pipeline_tools_2026.md) |
| Protocol Vulnerabilities Index Guide (460 cats × 31 types) | [techniques/protocol_vulns_index_guide.md](techniques/protocol_vulns_index_guide.md) |
| Immunefi Target Candidates 2026 | [techniques/immunefi_target_candidates_2026.md](techniques/immunefi_target_candidates_2026.md) |
| Pipeline External Review (GPT/Gemini/Claude 3-model eval) | [techniques/pipeline_external_review_2026.md](techniques/pipeline_external_review_2026.md) |

## Bug Bounty Programs

| Program | Platform | Focus | Status | File |
|---------|----------|-------|--------|------|
| USX Protocol | Immunefi | Smart Contract (Scroll L2) | 2 reports ready, pending submission | [immunefi_usx.md](challenges/immunefi_usx.md) |
| stake.link | Immunefi | Smart Contract (Curve/CCIP) | CLOSED (Immunefi: "automated scanner output", AI-generated warning) | `targets/stakelink/submission/` |
| CapyFi | Immunefi | Smart Contract (Compound v2 fork) | KILLED (Oracle Staleness = OOS "third party oracle data", Whitelist = by-design). 6hr/$0 | `targets/capyfi/` |
| Vercel AI SDK | HackerOne | AI/MCP/OAuth | CLOSED (2 Dup, 3 Info, $0) | - |
| NordSecurity | HackerOne | VPN (Linux) | 1 report ready, H1 API blocked | [nordvpn_kill_switch_bypass.md](challenges/nordvpn_kill_switch_bypass.md) |
| Ubiquiti | HackerOne | EdgeRouter X | 1 report ready, H1 API blocked | [ubiquiti_edgerouter_x.md](challenges/ubiquiti_edgerouter_x.md) |
| Lovable VDP | HackerOne | Web App | Report strengthened, H1 API blocked | `targets/lovable/submission/` |
| OPPO | HackerOne | Mobile | Informative (closed) | - |
| MCP SDK/OAuth | HackerOne | SDK | 2 Informative (closed) | - |
| Symbiotic | Immunefi | Smart Contract | ABANDONED (0 Critical) | `knowledge/bugbounty/` |
| Superform | Immunefi | Smart Contract | ABANDONED (1 Medium, not Critical) | `knowledge/bugbounty/` |
| YieldNest | Immunefi | Smart Contract | ABANDONED (mitigated on-chain) | - |
| Parallel Protocol | Immunefi | Smart Contract (Angle Transmuter fork) | ABANDONED (V3 clean, all C4 fixes applied) | [parallel_protocol.md](challenges/parallel_protocol.md) |
| Veda Protocol | Immunefi | Smart Contract (DeFi vault) | KILLED (triager_sim: missing capacity restore not exploitable, theoretical only) | - |
| Olympus DAO | Immunefi | Smart Contract (OHM/gOHM) | ABANDONED (16 contracts, 22 leads, 0 HIGH/CRITICAL. Mature codebase.) | - |
| GMX V2 | Immunefi | Smart Contract (Perp DEX) | ABANDONED (all leads dead) | - |
| NETGEAR Orbi RBR750 | Bugcrowd | Firmware (ARM, httpd) | Report A **PSVR-27669 배정** (NETGEAR 내부 트래킹, 2/19). Report B **철회 완료** (Invalid). | `targets/netgear/` |
| NETGEAR RAX43 | Bugcrowd | Firmware (ARM, 30+ binaries) | **VUL-A SUBMITTED** (Bugcrowd 8fc9af65, 2/20). VUL-B~E 물리장비 필요. VUL-D 키 로테이션 확인. ~16hr/1건. | `targets/netgear-rax43/submission/` |
| Swell Network | Immunefi | Smart Contract (LST/LRT/L2) | ABANDONED (6 audits, defense-in-depth only, triager_sim KILL). 2hr/$0. | `targets/swell/` |
| CapyFi | Immunefi | Smart Contract (Compound v2 fork, Ethereum) | KILLED (both reports — OOS exclusion + by-design). 6hr/$0. | `targets/capyfi/` |
| Kiln DeFi | Immunefi | Smart Contract (ERC4626 Vault, multi-chain) | **CLOSED (Duplicate, $0)** — "offset use is OOS, not in production, already known". ~8hr/$0. | `targets/kiln-defi/` |
| Royco Protocol | Immunefi | Smart Contract (DeFi) | ABANDONED — 2x Nethermind audited, 2,563 LOC, 0 HIGH+. ~2hr/$0. | - |
| Katana Protocol | Immunefi | Smart Contract (vault-bridge) | ABANDONED — 5 audits, integration thin. 0 HIGH+. ~1.5hr/$0. | - |
| Resolv Protocol | Immunefi | Smart Contract (DeFi) | ABANDONED — core 8x audited, SimpleOFT source inaccessible. 0 HIGH+. ~1.5hr/$0. | - |
| ZKsync OS | Immunefi | Rust (EVM interpreter, 151K LOC) | **Report A SUBMITTED (2/22)** — DIFFICULTY/PREVRANDAO returns 1, docs say 0. Medium $5K. Deep dive 완료 (3-agent parallel: bootloader/circuit/precompile). Finding-B~F-8 전부 INVALIDATED. 추가 HIGH+ 없음. ~12hr/1건. | `targets/zksync-os/submission/` |
| Immutable zkEVM Bridge | Immunefi | Smart Contract (Axelar GMP bridge, 3.7K LOC) | ABANDONED — 2 audits (ToB+Perimeter 1.41B runs), 21 findings 전부 admin-gated/OOS/documented. EIP-712 0% coverage 영역도 SAFE. 0 HIGH+. ~4hr/$0. | [immutable_zkevm_bridge.md](challenges/immutable_zkevm_bridge.md) |
| Royco Dawn | Immunefi | Smart Contract (Risk-Tranching, 8.5K LOC) | ABANDONED — **CRITICAL-ONLY program** ($50K-$250K). 3 analysts, 32 findings 전부 Medium 이하. Hexens audit variant(K3 div-by-zero) cancel workaround. Admin-gated/oracle OOS. ~4hr/$0. | `targets/royco-dawn/` |
| XION Chain | Immunefi | Blockchain/DLT (Cosmos SDK, 68K LOC Go+Rust) | ABANDONED — $250K Critical, 2 audits, 9 months old. 3 analysts (auth/chain/contracts), 24 findings. Top 3 HIGH+ 전부 KILLED: (A) ZK AddVKey no gov=by design (test confirms), (B) gnark validates input count, (C) BeginBlocker panic=dead code path. JWT alg confusion=jwx rejects empty. 0 HIGH+. ~4hr/$0. | `targets/xion/` |
| QNAP QTS 5.2.7 | QNAP Security Bounty | Firmware (x86-64, 56 CGIs, thttpd) | ABANDONED — All HIGH findings DISPROVED/PATCHED/POST-AUTH. CVE-2024-27130 patched (snprintf). authLogin.cgi obfuscated (static analysis blocked). No pre-auth surface. ~10hr/$0. | [qnap_qts_5.2.7.md](challenges/qnap_qts_5.2.7.md) |
| Synology SRM 1.3.1 | Synology PSIRT | Firmware (ARM32, captiveportal.cgi) | **SUBMITTED (2/23)** — 3 findings: Script Injection (CWE-79) + CSTI (CWE-1336) + Open Redirect (CWE-601). CVSS 6.1 Medium. Pre-auth captive portal, AngularJS 1.5.5 EOL. QEMU+Playwright verified. ~6hr. 응답 ETA: 7일 (3/2). | `targets/synology-srm/disclosure-captiveportal/` |
| AXIS OS (Q3536-LVE) | Bugcrowd | Firmware (aarch64, D-Bus services) | **READY TO SUBMIT** — Systemic D-Bus Authorization Bypass (CWE-863). 5 services, 17 methods, CVSS 8.1 High. Incomplete patch of CVE-2025-0359/0360. PoC Tier 1 Gold. Critic+Architect+Triager_sim all SUBMIT. ~6hr. | `targets/axis-os/submission/` |
| T-Mobile | Bugcrowd | Web/API (54 targets, Akamai WAF) | ABANDONED (unauth surface exhausted) — 200+ subdomains probed, 4 SSRF vectors tested, Adobe Campaign XXE deep-tested. All P4-P5 info disclosure only. P1/P2 requires account registration. ~4hr/$0. | `targets/t-mobile/` |
| NAMUHX | FindTheGap | Mobile/API (Android IoT app) | **2 SUBMITTED** — #74190: CWE-306 ATO chain, CVSS 7.4 High. #74191: CWE-639 IDOR chain (3 endpoints, PII), CVSS 6.5 Medium. ~8hr total. | `targets/namuhx/` |
| Keeper Security | Bugcrowd | Password Manager/PAM (20+ targets, Electron/Java/.NET/Python) | **CONDITIONAL GO (6.2/10)** — 신규 제품 라인(Connection Manager/AD Bridge/EPM/PAM) 집중. Guacamole CVE 체인 가능. Commander CLI 오픈소스 감사. 평가 완료 (2026-03-04). | `targets/keeper-security/target_assessment.md` |

### H1 Account Status (2026-02-17)
- **API 제출 차단**: 계정 레벨 403 (모든 프로그램)
- **원인**: signal_test 스팸 3건 + informative 6건 + 0 resolved
- **복구**: H1 support 연락 필요 또는 웹 수동 제출

## Pipeline Enhancement Tools (Sprint 2026-02-17)

| Tool | Command | Purpose |
|------|---------|---------|
| **MITRE Mapper** | `python3 tools/mitre_mapper.py CVE-2024-XXXXX --json` | CVE→CWE→CAPEC→ATT&CK 자동 매핑 |
| **Attack Graph** | `python3 tools/attack_graph/cli.py ingest\|query\|export` | Neo4j 공격 표면 그래프 (15 노드, 23 관계) |
| **DAG Orchestrator** | `python3 tools/dag_orchestrator/cli.py run\|visualize <pipeline>` | DAG 기반 에이전트 오케스트레이션 |
| **Recon Pipeline** | `python3 tools/recon_pipeline.py --target <domain>` | 6-phase 자동 정찰 |
| **Model Router** | `python3 tools/model_router.py --mode <mode> --question <q>` | LiteLLM 멀티모델 라우팅 |
| **SARIF Generator** | `python3 tools/sarif_generator.py --input <json> --output <sarif>` | GitHub Code Scanning 호환 SARIF 2.1.0 |
| **PDF Generator** | `python3 tools/pdf_generator.py --input <md> --output <pdf>` | 보고서 PDF 생성 |
| **Benchmark** | `python3 tests/benchmarks/benchmark.py --run-all` | 20-CTF 파이프라인 성능 측정 |

### Docker Infrastructure (`docker compose up -d`)

| Service | Port | Purpose |
|---------|------|---------|
| db (pgvector) | 5433 | RAG 벡터 DB (호스트 PG와 충돌 방지) |
| ollama | 11434 | 로컬 임베딩 모델 |
| rag-api | 8100 | ExploitDB/PoC 지식 검색 API |
| neo4j | 7474/7687 | 공격 표면 그래프 DB |
| litellm | 4000 | 멀티모델 프록시 (Claude/Gemini/DeepSeek/Ollama) |
| web-ui | 3000 | 실시간 대시보드 (`http://100.127.216.114:3000` via Tailscale) |

### MCP Servers (10개)

| MCP | Purpose |
|-----|---------|
| mcp-gdb | GDB 디버깅 |
| radare2-mcp | 바이너리 분석/디컴파일 |
| pentest-mcp | nmap/gobuster/nikto/john/hashcat |
| frida-mcp | 동적 계측 |
| ghidra-mcp | 디컴파일 |
| context7 | 라이브러리 문서 조회 |
| playwright | 브라우저 자동화 |
| nuclei-mcp | 12K+ 취약점 템플릿 스캔 |
| codeql-mcp | 시맨틱 코드 분석 |
| semgrep-mcp | 패턴 기반 정적 분석 |

## Key Learnings Summary

- **PoC/Exploit 없으면 절대 제출 금지** (IRON RULE)
- **로컬 flag 파일은 FAKE** — remote(host, port)에서만 진짜 플래그
- **Foundry fork > Python simulation** (DeFi)
- **3라운드 리뷰 필수**: V1(팩트) → V2(프레이밍) → V3(기술약점)
- **Phase 0 Target Intelligence**: GO/NO-GO 게이트 필수
- See [techniques/bug_bounty_report_quality.md](techniques/bug_bounty_report_quality.md) for complete guidelines.

## Knowledge Tree

Hierarchical knowledge index for LLM-guided retrieval: [knowledge_tree.json](knowledge_tree.json)

Use the tree to find relevant past experience by category:
- `ctf.pwn.stack` — Stack exploitation challenges
- `ctf.pwn.heap` — Heap exploitation challenges
- `ctf.reversing.custom_vm` — Custom VM reverse engineering
- `bugbounty.web3_defi` — DeFi smart contract findings
- `bugbounty.firmware` — Firmware device findings
- `tools_and_infra.protocol_vulns` — Protocol vulnerability patterns

## External Knowledge Repos

Catalog of all cloned reference repositories: [external_repos.md](external_repos.md)

Key repos: ExploitDB (47K+), PoC-in-GitHub (8K+), nuclei-templates (12K+), PayloadsAllTheThings (70+ categories), protocol-vulns-index (460×31)

## Kernel Exploit Environments

### 설정된 연습 환경
- **fasterbox** (Google CTF 2024): seccomp escape, `~/tools/google-ctf/2024/quals/pwn-fasterbox/`
- **gatekey** (Google CTF 2020): PKU bypass, `~/tools/google-ctf/2020/quals/pwn-gatekey/`
- **LPE 연습 환경**: UAF vulnmod, `~/kernelctf/` — **COMPLETED** (kernel 6.17.0-14-generic, uid=0 achieved via ESCALATE ioctl). See [challenges/kernelctf_vulnmod_lpe.md](challenges/kernelctf_vulnmod_lpe.md)

기법 문서: [techniques/kernelctf_lpe_environment.md](techniques/kernelctf_lpe_environment.md)
