<div align="center">

<br>

<img src="https://img.shields.io/badge/TERMINATOR-Autonomous_Security_Agent-cc0000?style=for-the-badge&labelColor=1a1a1a" alt="Terminator">

<br><br>

**Multi-agent AI system that autonomously solves CTF challenges and hunts bug bounties.**

Built on [Claude Code Agent Teams](https://docs.anthropic.com/en/docs/claude-code) — 17 specialized agents orchestrated through sequential pipelines with structured handoffs.

<br>

[![Claude Code](https://img.shields.io/badge/Claude_Code-Agent_Teams-7C3AED?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQyIDAtOC0zLjU4LTgtOHMzLjU4LTggOC04IDggMy41OCA4IDgtMy41OCA4LTggNHoiLz48L3N2Zz4=)](https://docs.anthropic.com/en/docs/claude-code)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Solidity](https://img.shields.io/badge/Solidity-Foundry-363636?style=flat-square&logo=solidity&logoColor=white)](https://book.getfoundry.sh/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)

<br>

| CTF Solved | Bug Bounty Targets | AI Agents | MCP Servers | Knowledge Docs | Security Tools |
|:----------:|:------------------:|:---------:|:-----------:|:--------------:|:--------------:|
| **20** | **30+** | **17** | **12** | **242K+** | **40+** |

<br>

**English** | [한국어](README.ko.md)

</div>

---

## What It Does

Terminator doesn't just find vulnerabilities — it **verifies** them.

- Every CTF exploit is tested **3x locally** before remote execution
- Every bug bounty finding requires a **working PoC** before report generation
- Every report passes **adversarial triage simulation** before submission

```
You: "pwnable.kr fd 풀어줘. SSH: fd@pwnable.kr -p2222 (pw: guest)"

Terminator:
  → spawns @reverser  → analyzes binary, produces attack map
  → spawns @chain     → builds exploit from attack map
  → spawns @critic    → cross-verifies offsets with gdb/r2
  → spawns @verifier  → runs exploit 3x locally, then remote
  → FLAG_FOUND: mama, are you prout of me?
```

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

### Structured Handoffs

Agents communicate through structured artifact passing — no context is lost between stages:

```
[HANDOFF from @reverser to @chain]
- Artifact: reversal_map.md
- Confidence: PASS
- Key Result: BOF in read_input(), 64-byte overflow, canary disabled
- Next Action: Build leak + ROP chain targeting system("/bin/sh")
```

---

## Pipelines

### CTF — Adaptive Pipeline Selection

| Condition | Pipeline | Agents |
|:----------|:---------|:------:|
| **Trivial** — source provided, 1-3 line bug | Direct solve | 0 |
| **Reversing / Crypto** — math inverse needed | `reverser → solver → critic → verifier → reporter` | 5 |
| **Pwn (clear vuln)** — obvious overflow/fmt | `reverser → chain → critic → verifier → reporter` | 5 |
| **Pwn (unclear vuln)** — crash discovery needed | `reverser → trigger → chain → critic → verifier → reporter` | 6 |
| **Web** — injection, SSRF, auth bypass | `scout → analyst → exploiter → reporter` | 4 |
| **Firmware** — ARM binary diff, emulated PoC | `fw_profiler → fw_inventory → fw_surface → fw_validator → reporter` | 5 |

### Bug Bounty — v3 Pipeline (7 Phases)

```
Phase 0   @target_evaluator     GO / NO-GO assessment (ROI, competition, tech stack)
          ─── GO gate ────────────────────────────────────────────────
Phase 0.5 @scout                Automated tool scan (Slither, Semgrep, Mythril)
Phase 1   @scout + @analyst     Parallel recon + duplicate pre-screen + CVE matching
Phase 1.5 @analyst (N parallel) OWASP-category hunting (large codebases only)
Phase 2   @exploiter            PoC development + Quality Tier gate (Tier 1-2 only)
Phase 3   @reporter             Report draft + CVSS
Phase 4   @critic + @architect  2-round review: facts → framing
Phase 4.5 @triager_sim          Adversarial triage (SUBMIT / STRENGTHEN / KILL)
Phase 5   @reporter             Final report + ZIP packaging
Phase 6   TeamDelete            Cleanup
```

> **Iron Rule**: No Exploit, No Report. Findings without a working PoC are automatically discarded.

---

## Agents

### CTF Agents

| Agent | Role | Model | Output |
|:------|:-----|:-----:|:-------|
| **reverser** | Binary analysis, protection detection, attack surface mapping | Sonnet | `reversal_map.md` |
| **trigger** | Crash discovery, input minimization, primitive identification | Sonnet | `trigger_report.md` |
| **solver** | Reverse computation for reversing/crypto challenges | Opus | `solve.py` |
| **chain** | Multi-stage exploit: leak → overwrite → shell | Opus | `solve.py` |
| **critic** | Cross-verification of offsets, constants, logic | Opus | `critic_review.md` |
| **verifier** | Local 3x reproduction → remote execution | Sonnet | `FLAG_FOUND` |
| **reporter** | Writeup with failed attempts and techniques | Sonnet | `knowledge/challenges/<name>.md` |

### Bug Bounty Agents

| Agent | Role | Model | Output |
|:------|:-----|:-----:|:-------|
| **target_evaluator** | Program ROI scoring, GO/NO-GO gate | Sonnet | `target_assessment.md` |
| **scout** | Recon + duplicate pre-screen + automated tool scanning | Sonnet | `recon_report.json` |
| **analyst** | CVE matching, source→sink tracing, confidence scoring | Sonnet | `vulnerability_candidates.md` |
| **exploiter** | PoC development, quality tier classification | Opus | PoC scripts + evidence |
| **triager_sim** | Adversarial triage — attacks report before submission | Opus | SUBMIT / STRENGTHEN / KILL |

### Firmware Agents

| Agent | Role | Model | Output |
|:------|:-----|:-----:|:-------|
| **fw_profiler** | Firmware image profiling, architecture detection | Sonnet | `firmware_profile.md` |
| **fw_inventory** | Binary inventory, version extraction, CVE matching | Sonnet | `firmware_inventory.md` |
| **fw_surface** | Attack surface mapping, binary diff analysis | Sonnet | `attack_surface.md` |
| **fw_validator** | QEMU emulation, dynamic PoC validation | Sonnet | `validation_results.md` |

### Agent Resilience

All work agents implement a **checkpoint protocol** for crash/compaction recovery:

| Mechanism | Purpose | How |
|:----------|:--------|:----|
| **checkpoint.json** | State persistence across compaction | Agent writes JSON at every phase transition with status, completed steps, critical facts |
| **Fake Idle Detection** | Catch agents that stopped mid-work | Orchestrator reads `checkpoint.status` — `"in_progress"` + idle = fake idle, re-spawn with context |
| **Resume on Re-spawn** | No duplicate work | New agent reads existing checkpoint.json, skips completed phases |
| **Error Reporting** | Environment blockers | `checkpoint.status: "error"` with description — Orchestrator fixes before re-spawn |

```
Orchestrator idle recovery flow:
  1. Read checkpoint.json
  2. status=="completed" + all artifacts exist → next pipeline stage
  3. status=="in_progress" → fake idle → message 1x → still idle → re-spawn with checkpoint
  4. status=="error" → fix environment → re-spawn
  5. No checkpoint → agent never started → re-spawn immediately
```

**Key Rule**: Never assume "artifact exists = work complete." Only `checkpoint.status == "completed"` is trustworthy.

---

## Dashboard

A real-time web UI for monitoring all operations — runs in **standalone mode** with zero external dependencies.

```
┌──────────────────────────────────────────────────────────────────┐
│  TERMINATOR                                        ● WebSocket  │
├──────────┬──────────────┬──────────────┬──────────┬─────────────┤
│ CTF      │ Bug Bounty   │ Infra-       │ Findings │ Attack      │
│ Sessions │ Missions     │ structure    │          │ Graph       │
├──────────┴──────────────┴──────────────┴──────────┴─────────────┤
│                                                                  │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
│  │ 20      │  │ 30+     │  │ 114+    │  │ 242K+   │           │
│  │ FLAGS   │  │ TARGETS │  │ FINDINGS│  │ KB DOCS │           │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘           │
│                                                                  │
│  Severity Distribution     Tool Health         Live Log          │
│  ████ CRITICAL  12         ● Radare2    up     [session.log     │
│  ██████ HIGH    18         ● GDB        up      tail -f ...]    │
│  ████████ MED   34         ● Nuclei     up                      │
│  ██ LOW         8          ● Slither    up                      │
│  █ INFO         42         ● CodeQL     up                      │
│                            ● Foundry    up                      │
│  D3 Force-Directed Attack Graph                                  │
│  ┌──────────────────────────────────────────────────┐           │
│  │  (target) ──→ (finding) ──→ (technique)          │           │
│  │     ↓             ↓              ↓               │           │
│  │  (service)    (exploit)     (report)             │           │
│  └──────────────────────────────────────────────────┘           │
└──────────────────────────────────────────────────────────────────┘
```

### 5 Tabs

| Tab | Data Source | Features |
|:----|:-----------|:---------|
| **CTF Sessions** | `reports/` directory | Session list, flags, writeups, live log tailing via WebSocket |
| **Bug Bounty Missions** | `targets/` directory | Pipeline phase tracker, GO/NO-GO status, findings per mission |
| **Infrastructure** | System + Docker | 16+ tool health checks, Docker service status, RAG stats |
| **Findings** | Filesystem + DB | Aggregated findings with CVSS auto-extraction, severity breakdown |
| **Attack Graph** | Neo4j or filesystem | D3 force-directed graph — targets, findings, techniques, services |

### Two Operating Modes

| Mode | Requirements | Capabilities |
|:-----|:-------------|:-------------|
| **Standalone** (default) | Python + FastAPI only | Filesystem-based findings aggregation, tool health, attack graph from markdown, agent history from team configs |
| **Full Stack** (optional) | Docker Compose | All standalone features + pgvector RAG, Neo4j graph DB, Ollama embeddings, LiteLLM multi-model proxy |

```bash
# Standalone — no Docker needed
cd web && uvicorn app:app --host 0.0.0.0 --port 3000

# Full Stack — 6 Docker services
cp .env.example .env  # Configure credentials before production use
docker compose up -d
```

---

## Toolchain

### MCP Servers — AI-Native Tool Integration

12 MCP servers give agents direct programmatic access to security tools:

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

### Security Tools

<details>
<summary><b>Reverse Engineering & Exploit Dev</b></summary>

| Category | Tools |
|:---------|:------|
| Disassembly | radare2, objdump, strings, readelf, nm |
| Decompilation | Ghidra (MCP), jadx |
| Debugging | gdb + pwndbg + GEF (93 commands), strace |
| Symbolic | angr, unicorn, z3-solver, keystone |
| Exploit | pwntools, ROPgadget, ropper, one_gadget |
| Crypto | pycryptodome, sympy, z3-solver |

</details>

<details>
<summary><b>Web Security</b></summary>

| Category | Tools |
|:---------|:------|
| Injection | sqlmap, commix, dalfox (XSS) |
| SSRF | SSRFmap (18+ modules) |
| Recon | ffuf, subfinder, katana, httpx, gau, waybackurls, arjun |
| Scanning | nuclei (12K+ templates), trufflehog (800+ secret types) |
| Upload | fuxploider |
| Crawling | crawl4ai (Playwright-based, JS rendering, stealth mode) |

</details>

<details>
<summary><b>Code Analysis & Smart Contracts</b></summary>

| Category | Tools |
|:---------|:------|
| Semantic | CodeQL (taint tracking, variant analysis) |
| Static | Semgrep (custom rule authoring) |
| Smart Contract | Slither (100+ detectors), Mythril (EVM symbolic), Foundry 1.5.1 |
| AI | Gemini CLI (gemini-3-pro-preview) |

</details>

<details>
<summary><b>Firmware Analysis</b></summary>

| Category | Tools |
|:---------|:------|
| Emulation | QEMU ARM user-mode, rootfs mounting |
| Diffing | Binary diff across firmware versions |
| Profiling | Architecture detection, library inventory |
| Validation | Dynamic PoC on emulated environment |

</details>

<details>
<summary><b>Reference Databases</b></summary>

| Database | Coverage |
|:---------|:---------|
| ExploitDB | 47K+ exploits |
| PoC-in-GitHub | 18K+ CVE PoCs |
| PayloadsAllTheThings | 70+ vuln categories |
| trickest-cve | 154K+ CVE PoCs |
| SecLists | Wordlists, passwords, discovery |
| HackTricks + GTFOBins | Privilege escalation, post-exploitation |

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

## Knowledge Search Engine

A unified full-text search over **242,934 security documents** — zero external dependencies, built on SQLite FTS5 with BM25 ranking.

| Source | Documents | Content |
|:-------|----------:|:--------|
| Internal techniques | 71 | Attack patterns, CTF writeups |
| External repos (25) | 8,666 | HackTricks, GTFOBins, PayloadsAllTheThings, how2heap, OWASP MASTG |
| ExploitDB | 46,960 | Exploit descriptions, platforms, CVEs |
| Nuclei templates | 14,693 | Vulnerability detection templates with severity |
| PoC-in-GitHub | 18,077 | CVE proof-of-concept repositories |
| trickest-cve | 154,467 | CVE details with products, CWE, PoC links |

### MCP Integration

Agents query the knowledge base via the `knowledge-fts` MCP server:

```python
technique_search("heap tcache poisoning")     # → top 5 technique docs
exploit_search("apache struts rce")            # → ExploitDB + nuclei + PoC
search_all("race condition double spend")      # → all 242K docs ranked
```

### Auto-Rebuild

A PostToolUse hook automatically re-indexes when `knowledge/techniques/` or `knowledge/challenges/` files are modified. Full rebuild: ~4 minutes. Incremental update: 0.13 seconds.

---

## Competitor-Adopted Patterns

Patterns ported from analysis of [10 open-source security AI frameworks](knowledge/techniques/competitor_analysis.md):

| Pattern | Source | Implementation | Impact |
|:--------|:-------|:---------------|:-------|
| **Web Exploit Chain Engine** | NeuroSploit | `tools/web_chain_engine.py` (820 LOC) | SSRF→internal, SQLi→DB-type, 10 auto-chain rules |
| **Flag Pattern Detector** | PentestGPT | `tools/flag_detector.py` (275 LOC) | 8+ regex patterns, strict validation, DH/FLAG/CTF/GoN/CYAI formats |
| **Anti-Hallucination Prompts** | NeuroSploit | `tools/validation_prompts.py` (486 LOC) | 8 composable prompts, speculative language detection, 0-100 confidence scoring |
| **Security-Aware Context Preservation** | CyberStrikeAI | 6 agent definitions updated | Credentials, exploit primitives, failed attempts survive context compression |
| **MITRE Auto-Mapping** | RedAmon | `tools/mitre_mapper.py` extended | 36 CWE→CAPEC→ATT&CK mappings, `get_context_for_finding()` for agent injection |

### Anti-Hallucination System

The `critic` and `triager_sim` agents enforce a 6-point validation checklist:

1. **Evidence Check** — Every claim must cite specific output (exact string, header, timing)
2. **Negative Controls** — Baseline comparison mandatory (normal vs payload response)
3. **Proof of Execution** — Per-vuln-type: XSS must fire JS, SQLi must extract DB content
4. **Speculative Language Detection** — "could be", "might be", "potentially" → auto-flag
5. **Severity Calibration** — 200 OK without data ≠ High
6. **Confidence Score** — 0-100, below 70 = REJECT

---

## Infrastructure

### Standalone Mode (Default)

No Docker required. The dashboard reads directly from the filesystem:

| Source | What It Reads |
|:-------|:-------------|
| `targets/` | 30+ mission directories with assessments, findings, reports |
| `reports/` | CTF session logs, flags, writeups |
| `~/.claude/teams/` | Agent team configs for run history |
| `knowledge/knowledge.db` | 242K+ document FTS5 search index |
| System `$PATH` | 16 security tools auto-detected via `shutil.which()` |

Aggregates **114+ findings** with automatic CVSS extraction from markdown reports. Builds D3-compatible attack graphs from vulnerability candidates, recon data, and report files — no Neo4j needed.

### Full Stack Mode (Optional)

```bash
docker compose up -d
```

| Service | Port | Purpose |
|:--------|:----:|:--------|
| **pgvector** | 5433 | RAG vector database |
| **ollama** | 11434 | Local embedding models |
| **rag-api** | 8100 | ExploitDB/PoC knowledge search |
| **neo4j** | 7474 | Attack surface graph database |
| **litellm** | 4000 | Multi-model proxy (Claude/Gemini/DeepSeek) |
| **web-ui** | 3000 | Dashboard with full DB-backed features |

### Pipeline Tooling

| Tool | Purpose |
|:-----|:--------|
| **MITRE Mapper** | CVE → CWE → CAPEC → ATT&CK mapping (36 CWEs) |
| **Knowledge FTS5 DB** | 242K+ document unified search with BM25 ranking |
| **Web Chain Engine** | Exploit chain composition (10 rules, NeuroSploit port) |
| **Validation Prompts** | Anti-hallucination prompt library (8 composable prompts) |
| **Flag Detector** | CTF flag pattern detection (8+ formats, strict mode) |
| **Attack Graph** | Neo4j or filesystem-backed attack surface visualization |
| **DAG Orchestrator** | Pipeline scheduling (CTF pwn/rev, bounty, firmware) |
| **Pipeline Controller** | Claude CLI handler for deterministic DAG→agent execution |
| **E2E Replay Benchmark** | solve.py re-execution for regression detection |
| **Recon Pipeline** | 6-phase automated reconnaissance |
| **SARIF Generator** | GitHub Code Scanning compatible output |
| **PDF Generator** | Report PDF generation |

### Recent Updates (2026-02)

- **Knowledge FTS5 DB** — 242K+ documents unified search (techniques, ExploitDB, nuclei, PoC, trickest-cve, HackTricks, GTFOBins)
- **Competitor Pattern Adoption** — 5 P0 patterns ported from NeuroSploit, PentestGPT, CyberStrikeAI, RedAmon
- **Anti-Hallucination System** — 8 composable validation prompts, speculative language detection, confidence scoring
- **Context Preservation** — Security-aware compression for 6 combat agents
- **Auto-rebuild hooks** — Knowledge DB auto-re-indexes on technique file changes
- **Secrets externalized** — All docker-compose.yml credentials use `${VAR:-default}` pattern
- **Custom agent types** — terminator.sh autonomous mode uses proper agent definitions (not generic)
- **Deterministic pipeline** — DAG engine connected to Claude CLI via `claude_handler.py`
- **E2E replay benchmark** — Automated solve.py re-execution for regression detection
- **Heap exploitation protocol** — chain.md sub-protocol for allocator fingerprinting, glibc-version-aware techniques
- **GraphRAG knowledge graph** — Exploit lookup, similar findings, drift detection via MCP

---

## Track Record

### CTF Challenges — 20 Solved

| Category | Count | Techniques Used |
|:---------|:-----:|:----------------|
| Pwn (heap, stack, ROP) | 10 | pwntools, ROP chains, GOT overwrite, shellcode |
| Reversing (VM, obfuscation) | 6 | GDB Oracle, DFA extraction, z3, custom VM analysis |
| Crypto | 2 | AES-ECB, z3 constraint solving |
| Misc (logic, filter bypass) | 2 | Operator precedence, binary search |

### Bug Bounty — 30+ Targets Assessed

| Metric | Count |
|:-------|------:|
| Programs assessed | 30+ |
| Knowledge documents indexed | 242K+ |
| Platforms | Immunefi, HackerOne, Bugcrowd, PSIRT |
| Categories | Smart Contract (DeFi), Web App, VPN, IoT/Firmware, AI/SDK |
| Smart contracts analyzed | 50+ |
| Vulnerability leads investigated | 100+ |
| Findings with working PoC | 15+ |

> Specific targets and findings are kept private until disclosure is complete.

---

## Research Foundations

Agent definitions incorporate patterns from 10+ LLM security frameworks:

| Pattern | Origin | Implemented In |
|:--------|:-------|:---------------|
| Variant Analysis — CVE patch diffs as seeds | Google Big Sleep (Project Zero + DeepMind) | analyst |
| LLM-first PoV Generation | RoboDuck (AIxCC 3rd place) | chain, solver |
| Symbolic + Neural Hybrid | ATLANTIS (AIxCC 1st place) | solver |
| No Exploit, No Report | Shannon, XBOW | Orchestrator gate |
| Iterative Context Gathering — 3-pass backtracing | Vulnhuntr | analyst |
| Dual-Approach Parallel — 2 strategies after 3 failures | RoboDuck | Orchestrator |
| OWASP Parallel Hunters | Shannon | analyst (Phase 1.5) |
| PoC Quality Tier Gate (1-4) | XBOW | exploiter |
| Adversarial Triage Simulation | Internal | triager_sim |
| Prompt Injection Guardrails | CAI (300+ LLM agents) | All agents |
| 4-Layer Validation | NeuroSploit | critic, triager_sim |
| Security-Aware Compression | CyberStrikeAI | All agents (context preservation) |
| Shadow Graph (planned P1) | PentestAgent | Cross-agent knowledge synthesis |
| Exploit Chain Rules | NeuroSploit | exploiter (web targets) |

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
# "이뮤니파이에서 하이~크리티컬 취약점 찾을때까지 ㄱㄱ"
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

# Full stack
docker compose up -d
# Open http://localhost:3000
```

---

## Project Structure

```
Terminator/
├── .claude/agents/          # 17 agent definitions (~4,300 lines)
│   ├── reverser.md          #   Binary analysis
│   ├── chain.md             #   Exploit chain building
│   ├── critic.md            #   Cross-verification
│   ├── fw_*.md              #   Firmware analysis (4 agents)
│   └── ...                  #   + 10 more specialists
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
│   ├── mitre_mapper.py      #   CVE→CWE→CAPEC→ATT&CK (36 CWEs)
│   ├── recon_pipeline.py    #   6-phase recon orchestrator
│   ├── attack_graph/        #   Neo4j + filesystem attack surface graphs
│   ├── dag_orchestrator/    #   DAG pipeline scheduling + Claude CLI handler
│   ├── sarif_generator.py   #   SARIF 2.1.0 output
│   └── mcp-servers/         #   nuclei, codeql, semgrep, knowledge-fts, graphrag
├── web/                     # FastAPI + D3 dashboard (standalone + Docker)
│   ├── app.py               #   REST API + WebSocket backend (1,255 lines)
│   └── static/index.html    #   Single-page dashboard (5 tabs, 1,231 lines)
├── targets/                 # Bug bounty workspaces (30+ missions)
├── tests/                   # CTF files + E2E replay benchmarks
├── CLAUDE.md                # Orchestrator instructions
├── terminator.sh            # Autonomous mode launcher
├── docker-compose.yml       # Full stack infrastructure
└── README.md
```

---

## Security & Ethics

This system is designed exclusively for **authorized** security work:

- **CTF / Wargames** — Practice environments designed for learning
- **Bug bounty programs** — Only targets with explicit authorization
- **Security research** — Controlled environments with proper scope

All findings follow responsible disclosure. Prompt injection guardrails protect agents from malicious code in analysis targets.

---

<div align="center">

MIT License

</div>
