<div align="center">

<br>

<img src="https://img.shields.io/badge/TERMINATOR-Autonomous_Security_Agent-cc0000?style=for-the-badge&labelColor=1a1a1a" alt="Terminator">

<br><br>

**Multi-agent AI system that autonomously solves CTF challenges and hunts bug bounties.**

Claude Code-native core with Codex/OMX + Gemini coordination — 25 specialized agents orchestrated through sequential pipelines, shared `coordination/` state, and digest-first context compaction.

<br>

[![Claude Code](https://img.shields.io/badge/Claude_Code-Agent_Teams-7C3AED?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQyIDAtOC0zLjU4LTgtOHMzLjU4LTggOC04IDggMy41OCA4IDgtMy41OCA0LTggNHoiLz48L3N2Zz4=)](https://docs.anthropic.com/en/docs/claude-code)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Solidity](https://img.shields.io/badge/Solidity-Foundry-363636?style=flat-square&logo=solidity&logoColor=white)](https://book.getfoundry.sh/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)

<br>

| CTF Solved | Bug Bounty Targets | AI Agents | MCP Servers | Pipeline Skills | Knowledge Docs | Security Tools |
|:----------:|:------------------:|:---------:|:-----------:|:--------------:|:--------------:|:--------------:|
| **23** | **30+** | **25** | **10** | **9** | **280K+** | **40+** |

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
  -> spawns @critic    -> cross-verifies offsets with gdb
  -> spawns @verifier  -> runs exploit 3x locally, then remote
  -> FLAG_FOUND: mama, are you prout of me?
```

```
You: "Hunt high-critical bugs on Immunefi until you find one"

Terminator:
  -> spawns @target-evaluator  -> scores ROI, returns GO
  -> spawns @scout + @analyst + @threat-modeler + @patch-hunter  -> parallel recon
  -> spawns @workflow-auditor + @web-tester  -> deep exploration
  -> spawns @exploiter         -> develops working PoC (effort: max)
  -> spawns @critic            -> fact-checks report
  -> spawns @triager-sim       -> attacks report before submission
  -> SUBMIT: CWE-306 ATO chain, CVSS 7.4 High
```

---

## How It Works

Terminator is not a single model prompt. It is a **team of 25 AI agents** coordinated by an orchestrator through sequential pipelines.

- **Adaptive pipeline selection** -- the orchestrator picks the right agent sequence based on challenge type (pwn, reversing, web, firmware, smart contract)
- **Structured handoffs** -- each agent produces a typed artifact (attack map, trigger report, exploit script) that feeds into the next stage
- **Verification-first** -- every exploit is tested 3x locally before remote execution; every bug bounty report requires a working PoC
- **Anti-hallucination** -- a dedicated critic agent cross-verifies all addresses, offsets, and constants with independent tool runs (gdb)
- **Crash recovery** -- checkpoint protocol lets agents resume from exact point of failure after context compaction
- **Automated quality gates** -- 9 pipeline skills + 3 runtime hooks automatically block OOS findings, weak PoCs, unrealistic threat models, dangerous payloads, and AI-generated template language before submission
- **Agent tuning** -- per-agent effort levels (low/medium/high/max), turn limits, required MCP servers, and tool restrictions optimize token usage and enforce role boundaries
- **Research-backed agent patterns** -- 15 techniques from Anthropic's Frontier Red Team research integrated into agent definitions: Mythos exploit framework, GhostScript variant hunting, FP reflection loops, adaptive technique bypass, property-based PoC validation, Best@N parallel retry, and more

---

## Cross-tool Runtime

Terminator now keeps **Claude Code**, **Codex/OMX**, and **Gemini** on the same state contract instead of re-reading the same long context on every handoff.

- **`coordination/` is the shared source of truth** -- manifests, digests, artifacts, checkpoints, and handoffs live under `coordination/sessions/<session_id>/`
- **Claude remains native** -- `.claude/hooks/*.sh` publish session knowledge, checkpoints, and artifact validation into `coordination/`
- **Codex/OMX remains native** -- `.omx/hooks/*.mjs` bootstrap Codex sessions and mirror `.omx/state`, notepad, and plans into the same session record
- **Gemini stays helper-only** -- `tools/context_digest.py --prefer-gemini` compacts large files, directories, and logs into reusable digests
- **Leader switches are structured** -- `write-handoff` / `consume-handoff` replace freeform “re-read everything” transfers

One-time install to make plain `omx` auto-enable repo hooks:

```bash
./scripts/install_omx_wrapper.sh
omx hooks status   # In this repo: Plugins enabled: yes
```

Outside repos that expose `.omx/hooks/` + `tools/coordination_cli.py`, the wrapper falls back to the real OMX binary unchanged.

## Live E2E Validation Status

Validated on **March 6, 2026** in this repository with real `claude`, `codex`, and plain `omx` sessions.

- **Claude custom agents** -- `reverser`, `target-evaluator`, `triager-sim`, and `fw-profiler` were spawned live and completed successfully
- **Knowledge injection** -- `Task|Agent` hook path produced `task_knowledge` digests and `task_knowledge_injected` coordination events during live subagent runs
- **Claude skills** -- the `ctf` skill was loaded through the native `Skill` tool and returned the expected pipeline instructions
- **Codex/OMX** -- plain `omx` booted with repo hook plugins enabled; Codex read the repo instructions and returned `coordination/` as the shared source of truth
- **MCP / knowledge** -- live `mcp__git__git_status` and `mcp__knowledge-fts__knowledge_stats` calls succeeded from Claude; Knowledge FTS responded with the indexed corpus metadata
- **Optional failure tolerated** -- `pentest-thinking` may still fail during startup, but it is treated as **non-blocking** and does not block core Terminator workflows

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
        │   CTF Pipeline   │                  │  Bug Bounty v12  │
        │   (Sequential)   │                  │   (Kill Gate)    │
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
          │ 10 MCP   │Knowledge │ Dashboard │ 40+      │ Runtime     │
          │ Servers  │ DB 280K+ │ (Web UI)  │ Tools    │ Hooks (3)   │
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
- Codex CLI + oh-my-codex (`omx`) for Codex-native sessions
- Python 3.10+ with pwntools, z3-solver, angr
- gdb with pwndbg or GEF
- Docker (optional, for full infrastructure stack)

### Interactive Mode

```bash
# One-time wrapper install for plain `omx`
cd Terminator && ./scripts/install_omx_wrapper.sh

# Codex/OMX native (wrapper auto-enables repo hook plugins)
cd Terminator && omx

# Claude Code native
cd Terminator && claude

# CTF:
# "Solve pwnable.kr fd. SSH: fd@pwnable.kr -p2222 (pw: guest)"

# Bug Bounty:
# "Hunt high-critical bugs on Immunefi"
```

### Autonomous Mode

```bash
./terminator.sh ctf /path/to/challenge.zip
./terminator.sh bounty https://target.com
./terminator.sh firmware /path/to/firmware.bin
./terminator.sh status
```

Terminator now always starts with **Claude**. **Codex is reserved as a spare continuation backend** and is only invoked when Claude stops because of:

- token/quota exhaustion
- context exhaustion
- provider/API instability after Claude has already retried and given up

If you want backend-aware `agent_runs` in PostgreSQL, apply:

```bash
psql "$DATABASE_URL" -f scripts/migrate_agent_runs_backend.sql
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
| **Firmware** -- ARM binary diff, emulated PoC | `fw-profiler -> fw-inventory -> fw-surface -> fw-validator -> reporter` | 5 |

### Bug Bounty -- v12 Pipeline (Kill Gate + Explore Lane)

> [!IMPORTANT]
> **Iron Rule**: No Exploit, No Report. Findings without a working PoC are automatically discarded.

<details>
<summary><b>Kill Gate Pipeline Details (v12)</b></summary>

```
Phase 0   @target-evaluator     GO / NO-GO assessment + Hard NO-GO rules
          oos-check skill       OOS pattern pre-screening (12 patterns)
          --- GO gate --------------------------------------------------------
Phase 0.2 bb_preflight.py       Program rules generation + validation (MANDATORY)
Phase 0.5 @scout                Automated tool scan (Slither, Semgrep, Mythril)
Phase 1   @scout + @analyst     Parallel recon + OOS cross-check per finding
          @threat-modeler       Trust boundary mapping, role matrix, state machine extraction (parallel)
          @patch-hunter         Incomplete fix + variant hunting from security commits (parallel)
          coverage-gate skill   80%+ endpoint coverage required
Phase 1.5 @analyst (N parallel) OWASP-category hunting (large codebases only)
          @workflow-auditor     Business workflow state transition mapping + anomaly detection
          @web-tester           Web application workflow pack testing
          workflow-check        Workflow state coverage validation (v12 NEW)
          fresh-surface-check   New attack surface from recent commits (v12 NEW)
★ Gate 1  @triager-sim (sonnet) Finding viability: 5-Question Destruction Test (KILL/GO)
          risk-weighted coverage + workflow-check + fresh-surface-check required
Phase 2   @exploiter            PoC development + poc-tier skill (Tier 1-2 only) + Evidence Tier (E1-E4)
          threat-model-check    Attack prerequisite validation
          evidence-tier-check   Evidence quality classification (E1-E4) (v12 NEW)
★ Gate 2  @triager-sim (opus)   PoC destruction: evidence quality + triager objections + duplicate-graph-check (KILL/GO)
          duplicate-graph-check Semantic duplicate detection via knowledge graph (v12 NEW)
Phase 3   @reporter             Report draft + CVSS (platform style from context/report-templates/)
Phase 3.5 report_scorer.py      5-dim quality gate (evidence/impact/repro/readability/slop, >=75)
          report_scrubber.py    AI signature removal (Unicode watermarks, em-dash, slop flags)
Phase 4   @critic               Fact-check (streamlined, Gate 2 handles viability)
Phase 4.5 @triager-sim          Final consistency check (KILL here = Gate bug → feedback loop)
          slop-check skill      AI slop score (<=2 PASS, 3-5 STRENGTHEN, >5 KILL)
Phase 5   @reporter             Final report + ZIP packaging + evidence_manifest.json
Phase 6   TeamDelete            Cleanup
```

**6 automated pipeline skills + 2 Kill Gates (v12):**

| Skill | Gate | Blocks |
|:------|:-----|:-------|
| `oos-check` | Phase 0 + per-finding | OOS patterns (oracle staleness, admin-gated, etc.) |
| `coverage-gate` | Phase 1->2 | <80% endpoint coverage (100% for small targets) |
| `workflow-check` | Gate 1->2 | Incomplete workflow state coverage (v12 NEW) |
| `fresh-surface-check` | Gate 1->2 | Missed attack surface from recent commits (v12 NEW) |
| `poc-tier` | Phase 2->3 | Tier 3-4 PoC (no live execution capture) |
| `evidence-tier-check` | Phase 2->3 | Evidence below E2 tier (v12 NEW) |
| `threat-model-check` | Phase 2 | Unrealistic attack prerequisites (2+ controlled) |
| `duplicate-graph-check` | Gate 2 | Semantic duplicates via knowledge graph (v12 NEW) |
| `slop-check` | Phase 4.5 | AI template language score >5 |
| `checkpoint-validate` | Any phase | Fake idle / fake completion detection |

**Additional quality gates:**
- Phase 0 Hard NO-GO: 3+ audits, 2+ reputable audits, 100+ reports, 3yr+, source inaccessible
- Phase 0.2 Program rules must pass validation before any agent spawns
- Phase 4.5 triager-sim outputs structured JSON for automated reporter feedback loop
- ★ Gate 1 + Gate 2: Kill Gates block findings before PoC dev and before report writing
- ★ v12 Explore Lane: threat-modeler + patch-hunter run parallel in Phase 1; workflow-auditor + web-tester in Phase 1.5

</details>

---

## Agents

25 specialized agents defined in `.claude/agents/` (~8,100 lines of definitions including reference docs).

<details>
<summary><b>CTF Agents (8)</b></summary>

| Agent | Role | Model | Effort | Output |
|:------|:-----|:-----:|:------:|:-------|
| **reverser** | Binary analysis, protection detection, attack surface mapping | Sonnet | High | `reversal_map.md` |
| **trigger** | Crash discovery, input minimization, primitive identification | Sonnet | Medium | `trigger_report.md` |
| **solver** | Reverse computation for reversing/crypto challenges | Opus | Max | `solve.py` |
| **chain** | Multi-stage exploit: leak -> overwrite -> shell. JIT/browser Mythos framework, adaptive technique bypass | Opus | Max | `solve.py` |
| **critic** | Security Council deliberation (5 archetypes) + cross-verification | Opus | High | `critic_review.md` |
| **verifier** | Local 3x reproduction -> remote execution. BB mode: positive/negative test verification | Sonnet | Low | `FLAG_FOUND` |
| **reporter** | Writeup with failed attempts and techniques | Sonnet | Medium | `knowledge/challenges/<name>.md` |
| **ctf-solver** | Legacy single-agent for trivial challenges | Sonnet | High | `solve.py` |

</details>

<details>
<summary><b>Bug Bounty Agents (10)</b></summary>

| Agent | Role | Model | Effort | Output |
|:------|:-----|:-----:|:------:|:-------|
| **target-evaluator** | Program ROI scoring, GO/NO-GO gate | Sonnet | Medium | `target_assessment.md` |
| **scout** | Recon + duplicate pre-screen + automated tool scanning | Sonnet | Medium | `recon_report.json` |
| **analyst** | CVE matching, source->sink tracing, confidence scoring, LLM-advantage reasoning for fuzzer-unreachable bugs | Sonnet | High | `vulnerability_candidates.md` |
| **threat-modeler** | Trust boundary mapping, role matrix, state machine and invariant extraction | Sonnet | Medium | `threat_model.md` |
| **patch-hunter** | Incomplete fix and variant vulnerability hunting from security commits (GhostScript 3-step pattern) | Sonnet | High | `patch_analysis.md` |
| **exploiter** | PoC development, quality tier classification, Evidence Tier (E1-E4), FP reflection loop, property-based validation, adaptive bypass | Opus | Max | PoC scripts + evidence |
| **workflow-auditor** | Business workflow state transition mapping and anomaly detection | Sonnet | Medium | `workflow_audit.md` |
| **triager-sim** | Adversarial triage -- 3 modes: finding-viability, PoC-destruction, report-review | Opus | High | SUBMIT / STRENGTHEN / KILL |
| **source-auditor** | Deep source code audit, cross-file taint analysis | Opus | Max | `audit_findings.md` |
| **defi-auditor** | Smart contract analysis, DeFi-specific vulnerability patterns | Opus | Max | `defi_audit.md` |

</details>

<details>
<summary><b>Firmware Agents (4)</b></summary>

| Agent | Role | Model | Output |
|:------|:-----|:-----:|:-------|
| **fw-profiler** | Firmware image profiling, architecture detection | Sonnet | `firmware_profile.md` |
| **fw-inventory** | Binary inventory, version extraction, CVE matching | Sonnet | `firmware_inventory.md` |
| **fw-surface** | Attack surface mapping, binary diff analysis | Sonnet | `attack_surface.md` |
| **fw-validator** | QEMU emulation, dynamic PoC validation | Sonnet | `validation_results.md` |

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

<details>
<summary><b>Runtime Hooks -- Automated Safety & Intelligence</b></summary>

3 runtime hooks enforce pipeline rules at the execution level, not just through prompt instructions:

| Hook | Trigger | Purpose |
|:-----|:--------|:--------|
| **safe_payload_hook.py** | PreToolUse (Bash) | Blocks dangerous commands (rm -rf, dd, mkfs, fork bombs) before execution |
| **observation_mask_hook.py** | PostToolUse (Bash/Read) | Auto-saves outputs >500 lines to file + detects ASCII art and repetitive text patterns at 100+ lines, prevents context overflow |
| **check_agent_completion.sh** | SubagentStop | FLAG pattern detection, knowledge extraction, auto-checkpoint for agents that stop without writing state |

Additional hooks: `knowledge_inject.sh` (PreToolUse: injects relevant knowledge per agent type), `knowledge_db_update.sh` (PostToolUse: auto-reindexes knowledge DB), `session_knowledge.sh` (SessionStart: loads global session context).

</details>

---

## Knowledge Engine

A unified full-text search over **280K+ security documents** -- zero external dependencies, built on SQLite FTS5 with BM25 ranking and progressive query relaxation.

| Source | Documents | Content |
|:-------|----------:|:--------|
| Internal techniques | 82 | Attack patterns, CTF writeups |
| External repos (47) | 12,896 | HackTricks, GTFOBins, PayloadsAllTheThings, how2heap, OWASP, SecLists, InternalAllTheThings + 40 more |
| ExploitDB | 46,960 | Exploit descriptions, platforms, CVEs |
| Nuclei templates | 14,871 | Vulnerability detection templates with severity |
| PoC-in-GitHub | 18,235 | CVE proof-of-concept repositories |
| trickest-cve | 155,121 | CVE details with products, CWE, PoC links |
| Web articles | 30+ | Crawled security blog posts, writeups, OWASP cheatsheets |

Agents query via the `knowledge-fts` MCP server:

```python
smart_search("QNAP buffer overflow strcpy")   # RECOMMENDED: auto-relaxes (AND → OR → top-terms)
technique_search("heap tcache poisoning")      # top 5 technique docs
technique_search("IDOR")                       # auto-expands to "insecure direct object reference"
exploit_search("CVE-2021-44228")               # CVE routed to trickest-cve + PoC first
search_all("race condition double spend")      # all 7 tables, cross-table ranked
```

33 security abbreviations auto-expand: `uaf`, `bof`, `sqli`, `ssrf`, `toctou`, `xxe`, `ssti`, `idor`, `rce`, `lpe`, `cmdinjection`, etc.

<details>
<summary><b>Auto-Rebuild, Web Fetcher, and CLI</b></summary>

A PostToolUse hook automatically re-indexes when `knowledge/techniques/` or `knowledge/challenges/` files are modified. Full rebuild: ~60 seconds. Incremental update: <1 second.

```bash
python tools/knowledge_indexer.py build                    # Full rebuild
python tools/knowledge_indexer.py smart-search "heap uaf"  # Relaxed cross-table search
python tools/knowledge_indexer.py stats                    # Row counts per table

# Web content fetcher (adds to web_articles table)
python tools/knowledge_fetcher.py fetch <url>              # Single URL via jina.ai
python tools/knowledge_fetcher.py bulk knowledge/sources/blogs.md  # Bulk from URL list
python tools/knowledge_fetcher.py update                   # Re-fetch stale (>30 days)
python tools/knowledge_fetcher.py stats                    # Web articles breakdown
```

</details>

---

## Toolchain

### MCP Servers -- AI-Native Tool Integration

10 MCP servers give agents direct programmatic access to security tools, with ToolAnnotations enabling parallel execution for read-only tools. Non-essential servers (context7, frida, browser-use, opendataloader-pdf) are available as opt-in via agent-level `requiredMcpServers`.

<details>
<summary><b>Core MCP Servers (10 active + 4 opt-in)</b></summary>

| Server | Capability |
|:-------|:-----------|
| **mcp-gdb** | Breakpoints, memory inspection, stepping, backtrace |
| **ghidra-mcp** | Headless decompilation, structures, enums |
| **pentest-mcp** | nmap, gobuster, nikto, john, hashcat |
| **nuclei-mcp** | 12K+ vulnerability detection templates |
| **codeql-mcp** | Semantic taint tracking, variant analysis |
| **semgrep-mcp** | Pattern-based static analysis |
| **playwright** | Browser automation for web exploitation |
| **graphrag-security** | Security knowledge graph: exploit lookup, similar findings, drift detection |
| **knowledge-fts** | 280K+ document BM25 search with smart_search relaxation, 33 synonyms, web_articles, cross-table ranking |
| **lightpanda** | Lightweight headless browser (9x less memory, 11x faster): page fetch, markdown, links, JS eval, semantic tree |

> **Denied by policy**: radare2 (use Ghidra instead), everything, sequential-thinking, memory, time
>
> **Opt-in** (per-agent `requiredMcpServers`): frida, browser-use, opendataloader-pdf, pentest-thinking
>
> Local repo implementation: `tools/mcp-servers/markitdown-mcp/` exposes local-file document to Markdown conversion via MarkItDown, but is not wired as an active default server.
>
> All custom MCP servers now include `ToolAnnotations` (readOnlyHint, idempotentHint) enabling concurrent execution of read-only tools.

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

<details>
<summary><b>Cross-Model Review (Codex / GPT-5.4)</b></summary>

OpenAI Codex plugin (`codex@openai-codex`) enables cross-model verification at pipeline checkpoints:

| Command | Purpose | Pipeline Stage |
|:--------|:--------|:---------------|
| `/codex:review` | Standard code review | BB Phase 4.5, Phase 5 |
| `/codex:adversarial-review` | Design challenge review | CTF post-critic, BB Phase 4 |
| `/codex:rescue` | Delegate task to GPT-5.4 | CTF dual-approach fallback |
| `/codex:status` | Monitor running jobs | Any |

Wrapper script: `tools/codex_cross_review.sh` — auto-triggered by SubagentStop hook on critic APPROVED.

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

**v7 -- LLM Prompting Research Applied (13 papers)**

Agent prompts were systematically improved based on 13 LLM prompting research papers. Core 12 agents reduced from 5,391 to 3,515 lines (35% reduction) while adding higher-quality reasoning structures:

| Technique | Paper | Applied To | Effect |
|:----------|:------|:-----------|:-------|
| IRON RULES primacy+recency | Lost in the Middle (Liu et al.) | All 12 agents | Critical rules at top + recap at bottom, +22%p recall |
| Structured Reasoning (OBSERVED/INFERRED/ASSUMED/RISK/DECISION) | Chain-of-Thought (Wei et al.) | All 12 agents | Replaces unstructured Think-Before-Act |
| Self-Verification (CoVe) | Chain-of-Verification (Dhuliawala et al.) | chain, solver, exploiter, trigger | Independent fact-check before submission, -77% hallucination |
| Few-Shot examples | The Prompt Report + CoT | critic, reverser, triager-sim, solver | APPROVED/REJECTED, reversal_map, SUBMIT/KILL, z3 modeling examples |
| Tree of Thoughts branching | Tree of Thoughts (Yao et al.) | chain, solver | Top-3 strategy evaluation before coding |
| ReAct loops (THOUGHT→ACTION→OBSERVATION) | ReAct (Yao et al.) | reverser, scout, trigger | Forced strategy updates on contradicting observations |
| Self-Consistency (multi-solution detection) | Self-Consistency (Wang et al.) | solver | Detects under-constrained z3 models |
| Aggressive pruning + reference split | APE (Zhou et al.) | scout (-76%), analyst (-61%), exploiter (-45%) | Content moved to `_reference/` directory |

Dual-Approach trigger reduced from 3 to 2 failures (ToT evaluates alternatives on first attempt).

---

Agent definitions also incorporate patterns from 10+ LLM security frameworks:

| Pattern | Origin | Implemented In |
|:--------|:-------|:---------------|
| Variant Analysis -- CVE patch diffs as seeds | Google Big Sleep (Project Zero + DeepMind) | analyst |
| LLM-first PoV Generation | RoboDuck (AIxCC 3rd place) | chain, solver |
| Symbolic + Neural Hybrid | ATLANTIS (AIxCC 1st place) | solver |
| No Exploit, No Report | Shannon, XBOW | Orchestrator gate |
| Iterative Context Gathering -- 3-pass backtracing | Vulnhuntr | analyst |
| Dual-Approach Parallel -- 2 strategies after 2 failures | RoboDuck | Orchestrator |
| OWASP Parallel Hunters | Shannon | analyst (Phase 1.5) |
| PoC Quality Tier Gate (1-4) | XBOW | exploiter |
| Adversarial Triage Simulation | Internal | triager-sim |
| Prompt Injection Guardrails | CAI (300+ LLM agents) | All agents |
| 4-Layer Validation | NeuroSploit | critic, triager-sim |
| Security-Aware Compression | CyberStrikeAI | All agents (context preservation) |
| Exploit Chain Rules | NeuroSploit | exploiter (web targets) |
| Security Council (5-archetype deliberation) | Consciousness Council (K-Dense) | critic |

**Anthropic Frontier Red Team Patterns (2026)** -- 15 techniques from [red.anthropic.com](https://red.anthropic.com) research integrated into agent definitions:

| Pattern | Source Article | Applied To |
|:--------|:------|:-----------|
| Mythos 4-Phase Exploit Framework (Type Confusion → Leak → Forgery → R/W) | CVE-2026-2796 Reverse Engineering | chain |
| GhostScript 3-Step Variant Hunt (Diff → Grep → Verify) | LLM-discovered 0-days | patch-hunter |
| False Positive Reflection Loop (5 questions) | Property-based Testing | exploiter |
| LLM-Advantage Analysis (5 fuzzer-unreachable bug classes) | LLM-discovered 0-days | analyst |
| Task Verifier (Positive + Negative Test) | Firefox Partnership | verifier |
| Best@N Parallel Retry (cross-model + same-model 3-way) | Smart Contract SCONE-bench | ctf_pipeline, bb_pipeline |
| Adaptive Technique Bypass (knowledge-fts auto-search) | Critical Infrastructure Defense | chain, exploiter |
| Property-Based PoC Validation (5 security invariants) | Property-based Testing | exploiter |
| Discovery vs Exploitation Cost Principle (1:10 ratio) | Firefox Partnership | bb_pipeline |
| Cluster Submission Protocol (same-day bundle) | Firefox Partnership | bb_pipeline |
| Token Efficiency Tracking (per-target ROI) | Smart Contract SCONE-bench | bb_pipeline |
| ASCII Art / Repetitive Text Pattern Detection | Cyber Competitions (CCDC) | observation_mask_hook |
| Per-Target Cost Tracking (cost_tracking.json) | Smart Contract SCONE-bench | bb_preflight, infra_client |
| ToolSpec Precision Enhancement (parallel_class, descriptions) | Cyber Toolkits (Incalmo) | tools.yaml |
| Glasswing Strategic Reference (Mythos Preview 90x) | Mythos Preview Assessment | memory |

---

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
├── .claude/
│   ├── agents/              # 25 agent definitions (~8,100 lines)
│   │   ├── reverser.md      #   Binary analysis
│   │   ├── chain.md         #   Exploit chain building
│   │   ├── critic.md        #   Cross-verification + Security Council
│   │   ├── target_evaluator.md  # GO/NO-GO + Hard NO-GO rules
│   │   ├── triager_sim.md   #   Adversarial triage + JSON feedback
│   │   ├── threat-modeler.md #  Trust boundary mapping, role matrix, state machine extraction
│   │   ├── workflow-auditor.md # Business workflow state transition mapping
│   │   ├── patch-hunter.md  #   Incomplete fix + variant hunting from security commits
│   │   ├── fw_*.md          #   Firmware analysis (4 agents)
│   │   ├── _reference/      #   Shared reference docs (commands, patterns, tools)
│   │   │   └── workflow_packs.md # Workflow pack definitions (v12 NEW)
│   │   └── ...              #   + 16 more specialists
│   ├── rules/               # Pipeline + protocol documents
│   │   ├── bb_pipeline_v12.md # Bug Bounty v12 Kill Gate + Explore Lane
│   │   ├── ctf_pipeline.md  #   CTF pipeline procedure
│   │   ├── agent_models.md  #   Agent model assignments
│   │   ├── handoff_protocol.md # Structured handoff format
│   │   └── checkpoint_protocol.md # Checkpoint + idle recovery
│   ├── hooks/               # 6 runtime hooks (3 safety + 3 knowledge)
│   │   ├── safe_payload_hook.py   # Dangerous command blocking
│   │   ├── observation_mask_hook.py # Large output auto-save + ASCII art/repetitive text detection
│   │   └── check_agent_completion.sh # FLAG detect + auto-checkpoint
│   └── skills/              # 9 pipeline skills
│       ├── bounty/          #   Bug bounty pipeline orchestration
│       ├── ctf/             #   CTF pipeline orchestration
│       ├── oos-check/       #   Out-of-Scope pre-screening (12 patterns)
│       ├── poc-tier/        #   PoC quality classification (Tier 1-4)
│       ├── coverage-gate/   #   Endpoint coverage gate (80%+)
│       ├── threat-model-check/  # Attack prerequisite validation
│       ├── slop-check/      #   AI slop detection (0-10 score)
│       └── checkpoint-validate/ # Agent idle/completion verification
├── knowledge/               # Accumulated experience
│   ├── index.md             #   Master index
│   ├── knowledge.db         #   FTS5 search DB (280K+ docs, 7 tables, ~259MB)
│   ├── challenges/          #   Per-challenge writeups
│   ├── techniques/          #   Reusable attack patterns + competitor analysis
│   └── triage_objections/   #   Triager objection patterns by vuln category (v12 NEW)
├── research/                # LLM security framework analysis (14 docs)
├── tools/                   # Pipeline tooling
│   ├── bb_preflight.py      #   Pipeline gate validator (rules, coverage, workflow-check, fresh-surface-check, evidence-tier-check, duplicate-graph-check, cost-tracking, --json)
│   ├── knowledge_indexer.py #   FTS5 DB builder (7 tables, smart_search, zero dependencies)
│   ├── knowledge_fetcher.py #   Web content fetcher (jina.ai → web_articles table)
│   ├── web_chain_engine.py  #   Web exploit chain engine (10 rules)
│   ├── flag_detector.py     #   CTF flag pattern detector (8+ formats)
│   ├── validation_prompts.py#   Anti-hallucination prompt library
│   ├── mitre_mapper.py      #   CVE->CWE->CAPEC->ATT&CK (36 CWEs)
│   ├── attack_graph/        #   Neo4j + filesystem attack surface graphs
│   ├── dag_orchestrator/    #   DAG pipeline scheduling + Claude CLI handler
│   ├── toolspec/            #   ToolSpec registry (10 tools, typed metadata)
│   ├── sarif_generator.py   #   SARIF 2.1.0 output
│   ├── report_scorer.py     #   5-dim report quality scorer (evidence/impact/repro/readability/slop)
│   ├── report_scrubber.py   #   AI signature remover (Unicode watermarks, em-dash, slop flags)
│   ├── evidence_manifest.py #   Unified evidence manifest generator (SHA256, checkpoint, triager state)
│   └── mcp-servers/         #   nuclei, codeql, semgrep, knowledge-fts, graphrag, markitdown
├── web/                     # FastAPI + D3 dashboard (standalone + Docker)
│   ├── app.py               #   REST API + WebSocket backend
│   └── static/index.html    #   Single-page dashboard (5 tabs)
├── targets/                 # Bug bounty workspaces (30+ missions)
├── tests/                   # CTF files + E2E replay benchmarks
├── CLAUDE.md                # Orchestrator instructions (v12)
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
