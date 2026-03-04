<div align="center">

<br>

<img src="https://img.shields.io/badge/TERMINATOR-Autonomous_Security_Agent-cc0000?style=for-the-badge&labelColor=1a1a1a" alt="Terminator">

<br><br>

**Multi-agent AI system that autonomously solves CTF challenges and hunts bug bounties.**

Built on [Claude Code Agent Teams](https://docs.anthropic.com/en/docs/claude-code) — 22 specialized agents orchestrated through sequential pipelines with structured handoffs.

<br>

[![Claude Code](https://img.shields.io/badge/Claude_Code-Agent_Teams-7C3AED?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQyIDAtOC0zLjU4LTgtOHMzLjU4LTggOC04IDggMy41OCA4IDgtMy41OCA0LTggNHoiLz48L3N2Zz4=)](https://docs.anthropic.com/en/docs/claude-code)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Solidity](https://img.shields.io/badge/Solidity-Foundry-363636?style=flat-square&logo=solidity&logoColor=white)](https://book.getfoundry.sh/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)

<br>

| CTF Solved | Bug Bounty Targets | AI Agents | MCP Servers | Knowledge Docs | Security Tools |
|:----------:|:------------------:|:---------:|:-----------:|:--------------:|:--------------:|
| **20** | **30+** | **22** | **12** | **242K+** | **40+** |

<br>

**English** | [한국어](README.ko.md)

</div>

---

## Demo

```
You: "Solve pwnable.kr fd. SSH: fd@pwnable.kr -p2222 (pw: guest)"

Terminator:
  -> spawns @reverser  -> analyzes binary, produces attack map
  -> spawns @chain     -> builds exploit from attack map
  -> spawns @critic    -> cross-verifies offsets with gdb/r2
  -> spawns @verifier  -> runs exploit 3x locally, then remote
  -> FLAG_FOUND: mama, are you prout of me?
```

```
You: "Hunt high-critical bugs on Immunefi until you find one"

Terminator:
  -> spawns @target_evaluator  -> scores ROI, returns GO
  -> spawns @scout + @analyst  -> parallel recon + CVE matching
  -> spawns @exploiter         -> develops working PoC
  -> spawns @critic            -> fact-checks report
  -> spawns @triager_sim       -> attacks report before submission
  -> SUBMIT: CWE-306 ATO chain, CVSS 7.4 High
```

---

## How It Works

Terminator is not a single model prompt. It is a **team of 22 AI agents** coordinated by an orchestrator through sequential pipelines.

- **Adaptive pipeline selection** -- the orchestrator picks the right agent sequence based on challenge type (pwn, reversing, web, firmware, smart contract)
- **Structured handoffs** -- each agent produces a typed artifact (attack map, trigger report, exploit script) that feeds into the next stage
- **Verification-first** -- every exploit is tested 3x locally before remote execution; every bug bounty report requires a working PoC
- **Anti-hallucination** -- a dedicated critic agent cross-verifies all addresses, offsets, and constants with independent tool runs (gdb, r2)
- **Crash recovery** -- checkpoint protocol lets agents resume from exact point of failure after context compaction

---

## Architecture

```
                        ┌─────────────────────────┐
                        │     Claude Code CLI      │
                        │   Orchestrator (Lead)    │
                        └────────────┬────────────┘
                                     │
                  ┌──────────────────┼──────────────────┐
                  │                                      │
        ┌────────▼─────────┐                  ┌─────────▼────────┐
        │   CTF Pipeline   │                  │  Bug Bounty v3   │
        │   (Sequential)   │                  │   (7 Phases)     │
        └────────┬─────────┘                  └─────────┬────────┘
                 │                                      │
    ┌────────────┼────────────┐          ┌──────────────┼──────────────┐
    │            │            │          │              │              │
┌───▼───┐  ┌────▼────┐  ┌───▼───┐  ┌───▼────┐  ┌─────▼─────┐  ┌────▼────┐
│Reverser│→ │ Chain/  │→ │Critic │  │ Scout  │→ │ Exploiter │→ │ Triager │
│       │  │ Solver  │  │       │  │+Analyst│  │           │  │   Sim   │
└───────┘  └─────────┘  └───┬───┘  └────────┘  └───────────┘  └─────────┘
                        ┌────▼────┐
                        │Verifier │→ FLAG_FOUND
                        └─────────┘

          ┌──────────────────────────────────────────────────────────┐
          │                  Infrastructure Layer                     │
          ├──────────┬──────────┬───────────┬──────────┬─────────────┤
          │ 12 MCP   │Knowledge │ Dashboard │ 40+      │ Anti-       │
          │ Servers  │ DB 242K+ │ (Web UI)  │ Tools    │ Hallucinate │
          └──────────┴──────────┴───────────┴──────────┴─────────────┘
```

Agents communicate through structured artifact passing -- no context is lost between stages:

```
[HANDOFF from @reverser to @chain]
- Artifact: reversal_map.md
- Confidence: PASS
- Key Result: BOF in read_input(), 64-byte overflow, canary disabled
- Next Action: Build leak + ROP chain targeting system("/bin/sh")
```

---

## Quick Start

### Prerequisites

- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) with Anthropic API key
- Python 3.10+ with pwntools, z3-solver, angr
- gdb with pwndbg or GEF, radare2
- Docker (optional, for full infrastructure stack)

### Interactive Mode

```bash
cd Terminator && claude

# CTF:
# "Solve pwnable.kr fd. SSH: fd@pwnable.kr -p2222 (pw: guest)"

# Bug Bounty:
# "Hunt high-critical bugs on Immunefi"
```

### Autonomous Mode

```bash
./terminator.sh ctf /path/to/challenge.zip     # CTF
./terminator.sh bounty https://target.com       # Bug bounty
./terminator.sh status                          # Monitor
```

### Dashboard

```bash
# Standalone (no Docker)
cd web && pip install -r requirements.txt && uvicorn app:app --port 3000

# Full stack (6 Docker services)
docker compose up -d
# Open http://localhost:3000
```

---

## Pipelines

### CTF -- Adaptive Pipeline Selection

| Condition | Pipeline | Agents |
|:----------|:---------|:------:|
| **Trivial** -- source provided, 1-3 line bug | Direct solve | 0 |
| **Reversing / Crypto** -- math inverse needed | `reverser -> solver -> critic -> verifier -> reporter` | 5 |
| **Pwn (clear vuln)** -- obvious overflow/fmt | `reverser -> chain -> critic -> verifier -> reporter` | 5 |
| **Pwn (unclear vuln)** -- crash discovery needed | `reverser -> trigger -> chain -> critic -> verifier -> reporter` | 6 |
| **Web** -- injection, SSRF, auth bypass | `scout -> analyst -> exploiter -> reporter` | 4 |
| **Firmware** -- ARM binary diff, emulated PoC | `fw_profiler -> fw_inventory -> fw_surface -> fw_validator -> reporter` | 5 |

### Bug Bounty -- v3 Pipeline

> [!IMPORTANT]
> **Iron Rule**: No Exploit, No Report. Findings without a working PoC are automatically discarded.

<details>
<summary><b>7-Phase Pipeline Details</b></summary>

```
Phase 0   @target_evaluator     GO / NO-GO assessment (ROI, competition, tech stack)
          --- GO gate --------------------------------------------------------
Phase 0.5 @scout                Automated tool scan (Slither, Semgrep, Mythril)
Phase 1   @scout + @analyst     Parallel recon + duplicate pre-screen + CVE matching
Phase 1.5 @analyst (N parallel) OWASP-category hunting (large codebases only)
Phase 2   @exploiter            PoC development + Quality Tier gate (Tier 1-2 only)
Phase 3   @reporter             Report draft + CVSS
Phase 4   @critic + @architect  2-round review: facts -> framing
Phase 4.5 @triager_sim          Adversarial triage (SUBMIT / STRENGTHEN / KILL)
Phase 5   @reporter             Final report + ZIP packaging
Phase 6   TeamDelete            Cleanup
```

**Quality gates at every transition:**
- Phase 0 GO/NO-GO prevents wasted effort on over-audited targets
- Phase 2 PoC Tier gate discards theoretical-only findings (Tier 3-4)
- Phase 4.5 triager simulation attacks the report before submission
- Coverage check ensures 80%+ endpoint testing before Phase 2

</details>

---

## Agents

22 specialized agents defined in `.claude/agents/` (~7,900 lines of definitions).

<details>
<summary><b>CTF Agents (8)</b></summary>

| Agent | Role | Model | Output |
|:------|:-----|:-----:|:-------|
| **reverser** | Binary analysis, protection detection, attack surface mapping | Sonnet | `reversal_map.md` |
| **trigger** | Crash discovery, input minimization, primitive identification | Sonnet | `trigger_report.md` |
| **solver** | Reverse computation for reversing/crypto challenges | Opus | `solve.py` |
| **chain** | Multi-stage exploit: leak -> overwrite -> shell | Opus | `solve.py` |
| **critic** | Security Council deliberation (5 archetypes) + cross-verification | Opus | `critic_review.md` |
| **verifier** | Local 3x reproduction -> remote execution | Sonnet | `FLAG_FOUND` |
| **reporter** | Writeup with failed attempts and techniques | Sonnet | `knowledge/challenges/<name>.md` |
| **ctf-solver** | Legacy single-agent for trivial challenges | Sonnet | `solve.py` |

</details>

<details>
<summary><b>Bug Bounty Agents (7)</b></summary>

| Agent | Role | Model | Output |
|:------|:-----|:-----:|:-------|
| **target_evaluator** | Program ROI scoring, GO/NO-GO gate | Sonnet | `target_assessment.md` |
| **scout** | Recon + duplicate pre-screen + automated tool scanning | Sonnet | `recon_report.json` |
| **analyst** | CVE matching, source->sink tracing, confidence scoring | Sonnet | `vulnerability_candidates.md` |
| **exploiter** | PoC development, quality tier classification | Opus | PoC scripts + evidence |
| **triager_sim** | Adversarial triage -- attacks report before submission | Opus | SUBMIT / STRENGTHEN / KILL |
| **source-auditor** | Deep source code audit, cross-file taint analysis | Opus | `audit_findings.md` |
| **defi-auditor** | Smart contract analysis, DeFi-specific vulnerability patterns | Opus | `defi_audit.md` |

</details>

<details>
<summary><b>Firmware Agents (4)</b></summary>

| Agent | Role | Model | Output |
|:------|:-----|:-----:|:-------|
| **fw_profiler** | Firmware image profiling, architecture detection | Sonnet | `firmware_profile.md` |
| **fw_inventory** | Binary inventory, version extraction, CVE matching | Sonnet | `firmware_inventory.md` |
| **fw_surface** | Attack surface mapping, binary diff analysis | Sonnet | `attack_surface.md` |
| **fw_validator** | QEMU emulation, dynamic PoC validation | Sonnet | `validation_results.md` |

</details>

<details>
<summary><b>Specialized Agents (3)</b></summary>

| Agent | Role | Model | Output |
|:------|:-----|:-----:|:-------|
| **mobile-analyst** | Android/iOS app analysis, API interception | Sonnet | `mobile_findings.md` |
| **recon-scanner** | Automated reconnaissance, subdomain/port discovery | Sonnet | `recon_results.json` |
| **web-tester** | Web application testing, auth bypass, injection | Sonnet | `web_findings.md` |

</details>

<details>
<summary><b>Agent Resilience -- Checkpoint Protocol</b></summary>

All work agents implement a checkpoint protocol for crash/compaction recovery:

- **checkpoint.json** -- Agent writes state at every phase transition (status, completed steps, critical facts)
- **Fake Idle Detection** -- Orchestrator reads checkpoint status; `in_progress` + idle = re-spawn with context
- **Resume on Re-spawn** -- New agent reads existing checkpoint, skips completed phases
- **Error Reporting** -- `status: "error"` with description; orchestrator fixes environment before re-spawn

> [!NOTE]
> Never assume "artifact exists = work complete." Only `checkpoint.status == "completed"` is trustworthy.

</details>

---

## Knowledge Engine

A unified full-text search over **242K+ security documents** -- zero external dependencies, built on SQLite FTS5 with BM25 ranking.

| Source | Documents | Content |
|:-------|----------:|:--------|
| Internal techniques | 71 | Attack patterns, CTF writeups |
| External repos (25) | 8,666 | HackTricks, GTFOBins, PayloadsAllTheThings, how2heap, OWASP MASTG |
| ExploitDB | 46,960 | Exploit descriptions, platforms, CVEs |
| Nuclei templates | 14,693 | Vulnerability detection templates with severity |
| PoC-in-GitHub | 18,077 | CVE proof-of-concept repositories |
| trickest-cve | 154,467 | CVE details with products, CWE, PoC links |

Agents query via the `knowledge-fts` MCP server:

```python
technique_search("heap tcache poisoning")     # top 5 technique docs
exploit_search("apache struts rce")            # ExploitDB + nuclei + PoC
search_all("race condition double spend")      # all 242K docs ranked
```

<details>
<summary><b>Auto-Rebuild and CLI</b></summary>

A PostToolUse hook automatically re-indexes when `knowledge/techniques/` or `knowledge/challenges/` files are modified. Full rebuild: ~4 minutes. Incremental update: 0.13 seconds.

```bash
python tools/knowledge_indexer.py --rebuild    # Full rebuild
python tools/knowledge_indexer.py --search "reentrancy flash loan"
python tools/knowledge_indexer.py --stats
```

</details>

---

## Toolchain

### MCP Servers -- AI-Native Tool Integration

12 MCP servers give agents direct programmatic access to security tools.

<details>
<summary><b>All 12 MCP Servers</b></summary>

| Server | Capability |
|:-------|:-----------|
| **mcp-gdb** | Breakpoints, memory inspection, stepping, backtrace |
| **radare2-mcp** | Disassembly, decompilation, xrefs, function analysis |
| **ghidra-mcp** | Headless decompilation, structures, enums |
| **frida-mcp** | Dynamic instrumentation, hooking, process spawning |
| **pentest-mcp** | nmap, gobuster, nikto, john, hashcat |
| **nuclei-mcp** | 12K+ vulnerability detection templates |
| **codeql-mcp** | Semantic taint tracking, variant analysis |
| **semgrep-mcp** | Pattern-based static analysis |
| **playwright** | Browser automation for web exploitation |
| **context7** | Up-to-date library documentation lookup |
| **graphrag-security** | Security knowledge graph: exploit lookup, similar findings, drift detection |
| **knowledge-fts** | 242K+ document BM25 search across techniques, ExploitDB, nuclei, PoC, trickest-cve |

</details>

<details>
<summary><b>Security Tools (40+)</b></summary>

**Reverse Engineering & Exploit Dev**
- Disassembly: radare2, objdump, strings, readelf, nm
- Decompilation: Ghidra (MCP), jadx
- Debugging: gdb + pwndbg + GEF (93 commands), strace
- Symbolic: angr, unicorn, z3-solver, keystone
- Exploit: pwntools, ROPgadget, ropper, one_gadget
- Crypto: pycryptodome, sympy, z3-solver

**Web Security**
- Injection: sqlmap, commix, dalfox (XSS)
- SSRF: SSRFmap (18+ modules)
- Recon: ffuf, subfinder, katana, httpx, gau, waybackurls, arjun
- Scanning: nuclei (12K+ templates), trufflehog (800+ secret types)
- Crawling: crawl4ai (Playwright-based, JS rendering, stealth mode)

**Code Analysis & Smart Contracts**
- Semantic: CodeQL (taint tracking, variant analysis)
- Static: Semgrep (custom rule authoring)
- Smart Contract: Slither (100+ detectors), Mythril (EVM symbolic), Foundry 1.5.1
- AI: Gemini CLI (gemini-3-pro-preview)

**Firmware Analysis**
- QEMU ARM user-mode emulation, rootfs mounting
- Binary diff across firmware versions
- Architecture detection, library inventory

**Reference Databases**
- ExploitDB (47K+ exploits), PoC-in-GitHub (18K+ CVE PoCs)
- PayloadsAllTheThings (70+ vuln categories), trickest-cve (154K+ CVE PoCs)
- HackTricks + GTFOBins, SecLists

</details>

<details>
<summary><b>Skill Plugins (Trail of Bits, Sentry, Anthropic)</b></summary>

| Plugin | Skills | Purpose |
|:-------|:-------|:--------|
| static-analysis | semgrep, codeql, sarif-parsing | Automated static analysis |
| variant-analysis | variant-analysis | CVE variant pattern search |
| testing-handbook | aflpp, libfuzzer, harness-writing + 12 more | Fuzzing (Trail of Bits) |
| insecure-defaults | insecure-defaults | Hardcoded secrets, weak auth |
| sharp-edges | sharp-edges | Dangerous API detection |
| audit-context | audit-context-building | Pre-audit architecture mapping |
| dwarf-expert | dwarf-expert | DWARF debug format |
| yara-authoring | yara-rule-authoring | YARA rule creation |
| differential-review | differential-review | Git diff security review |
| sentry-skills | find-bugs, security-review, code-review | Bug detection |

</details>

---

## Track Record

### CTF Challenges -- 20 Solved

| Category | Count | Techniques Used |
|:---------|:-----:|:----------------|
| Pwn (heap, stack, ROP) | 10 | pwntools, ROP chains, GOT overwrite, shellcode |
| Reversing (VM, obfuscation) | 6 | GDB Oracle, DFA extraction, z3, custom VM analysis |
| Crypto | 2 | AES-ECB, z3 constraint solving |
| Misc (logic, filter bypass) | 2 | Operator precedence, binary search |

### Bug Bounty -- 30+ Targets Assessed

| Metric | Count |
|:-------|------:|
| Programs assessed | 30+ |
| Platforms | Immunefi, HackerOne, Bugcrowd, PSIRT |
| Categories | Smart Contract (DeFi), Web App, VPN, IoT/Firmware, AI/SDK |
| Smart contracts analyzed | 50+ |
| Vulnerability leads investigated | 100+ |
| Findings with working PoC | 15+ |

> Specific targets and findings are kept private until disclosure is complete.

---

<details>
<summary><b>Research Foundations</b></summary>

Agent definitions incorporate patterns from 10+ LLM security frameworks:

| Pattern | Origin | Implemented In |
|:--------|:-------|:---------------|
| Variant Analysis -- CVE patch diffs as seeds | Google Big Sleep (Project Zero + DeepMind) | analyst |
| LLM-first PoV Generation | RoboDuck (AIxCC 3rd place) | chain, solver |
| Symbolic + Neural Hybrid | ATLANTIS (AIxCC 1st place) | solver |
| No Exploit, No Report | Shannon, XBOW | Orchestrator gate |
| Iterative Context Gathering -- 3-pass backtracing | Vulnhuntr | analyst |
| Dual-Approach Parallel -- 2 strategies after 3 failures | RoboDuck | Orchestrator |
| OWASP Parallel Hunters | Shannon | analyst (Phase 1.5) |
| PoC Quality Tier Gate (1-4) | XBOW | exploiter |
| Adversarial Triage Simulation | Internal | triager_sim |
| Prompt Injection Guardrails | CAI (300+ LLM agents) | All agents |
| 4-Layer Validation | NeuroSploit | critic, triager_sim |
| Security-Aware Compression | CyberStrikeAI | All agents (context preservation) |
| Exploit Chain Rules | NeuroSploit | exploiter (web targets) |
| Security Council (5-archetype deliberation) | Consciousness Council (K-Dense) | critic |

**Anti-Hallucination System** -- The `critic` agent runs a **Security Council** deliberation with 5 adversarial archetypes before any verdict:

| Archetype | Role |
|:----------|:-----|
| **The Interrogator** | Adversarial triager -- demands live evidence for every claim ("Show me the GDB output, or it didn't happen") |
| **The Empiricist** | Data-driven verification -- no evidence = no approval |
| **The Architect** | Structural analysis -- does the chain design hold under all conditions? |
| **The Triager** | Platform reviewer simulation -- "What's the first reason I'd close this?" |
| **The Historian** | Pattern matching against past failures from knowledge base |

The Interrogator has **asymmetric veto power**: any critical claim without live evidence = automatic REJECT. Combined with a 6-point validation:

1. **Evidence Check** -- Every claim must cite specific output (exact string, header, timing)
2. **Negative Controls** -- Baseline comparison mandatory (normal vs payload response)
3. **Proof of Execution** -- Per-vuln-type: XSS must fire JS, SQLi must extract DB content
4. **Speculative Language Detection** -- "could be", "might be", "potentially" auto-flagged
5. **Severity Calibration** -- 200 OK without data is not High
6. **Confidence Score** -- 0-100, below 70 = REJECT

**Competitor-Adopted Patterns** -- Ported from [10 open-source security AI frameworks](knowledge/techniques/competitor_analysis.md):

| Pattern | Source | Implementation |
|:--------|:-------|:---------------|
| Web Exploit Chain Engine | NeuroSploit | `tools/web_chain_engine.py` -- SSRF->internal, SQLi->DB-type auto-chain |
| Flag Pattern Detector | PentestGPT | `tools/flag_detector.py` -- 8+ regex patterns, strict validation |
| Anti-Hallucination Prompts | NeuroSploit | `tools/validation_prompts.py` -- 8 composable prompts, 0-100 confidence |
| MITRE Auto-Mapping | RedAmon | `tools/mitre_mapper.py` -- 36 CWE->CAPEC->ATT&CK mappings |

</details>

---

<details>
<summary><b>Project Structure</b></summary>

```
Terminator/
├── .claude/agents/          # 22 agent definitions (~7,900 lines)
│   ├── reverser.md          #   Binary analysis
│   ├── chain.md             #   Exploit chain building
│   ├── critic.md            #   Cross-verification
│   ├── defi-auditor.md      #   Smart contract / DeFi audit
│   ├── mobile-analyst.md    #   Mobile app analysis
│   ├── fw_*.md              #   Firmware analysis (4 agents)
│   └── ...                  #   + 13 more specialists
├── knowledge/               # Accumulated experience
│   ├── index.md             #   Master index
│   ├── knowledge.db         #   FTS5 search DB (242K docs, ~245MB)
│   ├── challenges/          #   Per-challenge writeups
│   └── techniques/          #   Reusable attack patterns + competitor analysis
├── research/                # LLM security framework analysis (14 docs)
├── tools/                   # Pipeline tooling
│   ├── knowledge_indexer.py #   FTS5 DB builder (6 tables, zero dependencies)
│   ├── web_chain_engine.py  #   Web exploit chain engine (10 rules)
│   ├── flag_detector.py     #   CTF flag pattern detector (8+ formats)
│   ├── validation_prompts.py#   Anti-hallucination prompt library
│   ├── mitre_mapper.py      #   CVE->CWE->CAPEC->ATT&CK (36 CWEs)
│   ├── recon_pipeline.py    #   6-phase recon orchestrator
│   ├── attack_graph/        #   Neo4j + filesystem attack surface graphs
│   ├── dag_orchestrator/    #   DAG pipeline scheduling + Claude CLI handler
│   ├── sarif_generator.py   #   SARIF 2.1.0 output
│   └── mcp-servers/         #   nuclei, codeql, semgrep, knowledge-fts, graphrag
├── web/                     # FastAPI + D3 dashboard (standalone + Docker)
│   ├── app.py               #   REST API + WebSocket backend
│   └── static/index.html    #   Single-page dashboard (5 tabs)
├── targets/                 # Bug bounty workspaces (30+ missions)
├── tests/                   # CTF files + E2E replay benchmarks
├── CLAUDE.md                # Orchestrator instructions
├── terminator.sh            # Autonomous mode launcher
├── docker-compose.yml       # Full stack infrastructure
└── README.md
```

</details>

---

## Security & Ethics

This system is designed exclusively for **authorized** security work:

- **CTF / Wargames** -- Practice environments designed for learning
- **Bug bounty programs** -- Only targets with explicit authorization
- **Security research** -- Controlled environments with proper scope

All findings follow responsible disclosure. Prompt injection guardrails protect agents from malicious code in analysis targets.

---

<div align="center">

MIT License

<br>

[![Star History Chart](https://api.star-history.com/svg?repos=R00T-Kim/Terminator&type=Date)](https://star-history.com/#R00T-Kim/Terminator&Date)

</div>
