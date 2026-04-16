---
title: AI Red-Team External Frameworks — 2026 Reference Index
category: ai_security
tags: [llm, red-team, prompt-injection, jailbreak, owasp-llm-top10, agentic-security]
platform: all
---

# AI Red-Team External Frameworks — Reference Index

Curated entry points to major LLM red-teaming frameworks and references. Terminator's ai-security pipeline uses these as technique catalogs and tooling sources. This file is the searchable index; actual framework code lives outside the repo.

---

## 1. promptfoo (Integrated — MCP + CLI wrapper)

**Upstream**: https://github.com/promptfoo/promptfoo (⭐13.2k, MIT, OpenAI-owned since 2026-03)
**Integration**: First-class — MCP server + `tools/promptfoo_run.sh` wrapper
**Key modules used by Terminator**:
- `redteam init` — scaffold a red-team config
- `redteam discover` — Target Discovery Agent (purpose/limits/tools auto-probe)
- `redteam eval` — full OWASP LLM Top-10 red-team run
- `code-scans run <repo>` — static LLM security vuln scan

Built-in plugins that map to OWASP LLM Top-10:
- `prompt-injection` (LLM01)
- `pii:direct`, `pii:session` (LLM02)
- `rbac`, `hijacking` (LLM06 — excessive agency)
- `prompt-extraction` (LLM07 — system prompt leakage)
- `cross-session-leak` (LLM08 — vector/embedding weakness)
- `harmful` (safety bypass)

Strategies: `jailbreak:tree` (multi-turn), `jailbreak` (single-turn), `prompt-injection`.

**Terminator usage**: see `tools/promptfoo_configs/redteam_starter.yaml` + ai-recon agent docs.

---

## 2. deepteam (confident-ai)

**Upstream**: https://github.com/confident-ai/deepteam
**Status**: Reference only (not integrated as code — adopt techniques into ai-recon prompt)

Provides 20+ research-backed adversarial attack methods for single-turn AND multi-turn red teaming. Key differentiators:
- **Encoding-based obfuscation** — Base64, hex, ROT13, Unicode homoglyphs wrappers around malicious payloads
- **Multi-turn attack chains** — incremental payload disclosure across turns
- **Jailbreak enhancers** — combining a base attack with multiple encoding layers

### Attack taxonomy (for ai-recon reference)

| Category | Example attacks |
|----------|----------------|
| Direct | prompt injection, system prompt leak, role-play jailbreak |
| Encoding obfuscation | Base64, hex, leet-speak, Unicode homoglyph, ROT13, emoji-encoded |
| Multi-turn | context poisoning across turns, fake tool-call bait, gradual disclosure |
| Indirect | URL-embedded injection, RAG doc poisoning, tool-output injection |
| Agentic | cross-session leak, memory extraction, unintended tool invocation |
| Policy bypass | DAN-mode variants, hypothetical framing, translation layering |

**Terminator usage**: ai-recon agent should attempt at minimum: 1 direct + 1 encoding + 1 multi-turn + 1 indirect before marking a target's injection surface "scanned".

---

## 3. PyRIT (Microsoft Azure)

**Upstream**: https://github.com/Azure/PyRIT (⭐3.4k, archived 2026-03-27, read-only but installable)
**Status**: Reference only — archive means no new features, but last release is stable

Python framework for adversarial probing of GenAI systems across text/image/audio/video. Good for:
- **Automated orchestration** of long attack campaigns
- **Target/converter/scorer abstraction** — decouple target LLM from payload transforms from success scoring
- **Seed prompt datasets** shipped with the repo (harmful_behaviors, XSTest, etc.)

### Key primitives to borrow conceptually

- **PromptTarget** — abstract endpoint (OpenAI, Azure, custom HTTP)
- **PromptConverter** — transform payloads (Base64Converter, ROT13Converter, PersuasionConverter)
- **Scorer** — success detection (LLM-as-judge, regex, classifier)
- **Orchestrator** — multi-turn campaign runner

**Terminator usage**: exploiter agent on AI targets can shell out to `python3 -m pyrit` if installed, OR adopt the pattern of **target × converter × scorer** loop in the PoC design.

---

## 4. LLMSecurityGuide (requie)

**Upstream**: https://github.com/requie/LLMSecurityGuide (single 80KB README, no LICENSE)
**Status**: Reference only — concentrated OWASP GenAI Top-10 + Agentic Top-10 coverage

Key content for Terminator's ai-recon + ai-security pipeline:

### OWASP GenAI Top-10 (2025-2026)

| ID | Category | Terminator test |
|----|----------|----------------|
| LLM01 | Prompt Injection | promptfoo `prompt-injection` + deepteam multi-turn |
| LLM02 | Sensitive Info Disclosure | promptfoo `pii:direct`/`pii:session` |
| LLM03 | Supply Chain | external model / plugin source audit |
| LLM04 | Data & Model Poisoning | RAG source audit, training data review |
| LLM05 | Improper Output Handling | output parsing → sink (SQL/XSS/cmd injection chain) |
| LLM06 | Excessive Agency | `rbac` + `hijacking` (tool invocation auth) |
| LLM07 | System Prompt Leakage | `prompt-extraction` |
| LLM08 | Vector & Embedding Weaknesses | `cross-session-leak` + embedding inversion |
| LLM09 | Misinformation | fact-check / source-citation tests |
| LLM10 | Unbounded Consumption | rate-limit + token-cost DoS |

### OWASP Agentic Top-10 (2026 — ASI-prefix)

| ID | Category |
|----|----------|
| ASI01 | Memory Poisoning |
| ASI02 | Tool Misuse |
| ASI03 | Privilege Compromise |
| ASI04 | Resource Overload |
| ASI05 | Cascading Hallucination |
| ASI06 | Intent Manipulation |
| ASI07 | Misaligned Actions |
| ASI08 | Output Manipulation |
| ASI09 | Unexpected RCE |
| ASI10 | Unbounded Data Exfil |

**Terminator usage**: ai-recon Phase D (agent workflow mapping) MUST test at least ASI02, ASI03, ASI09 for any agentic target.

---

## 5. Additional Reference Curations

| Source | Content |
|--------|---------|
| https://github.com/user1342/Awesome-LLM-Red-Teaming | Curated tools/training/resources |
| https://github.com/PromptLabs/Prompt-Hacking-Resources | Jailbreak/injection payload collections |
| https://github.com/anmolksachan/AI-ML-Free-Resources-for-Security-and-Prompt-Injection | AI/ML pentesting roadmap |

---

## How to refresh this index

Every 3-6 months:
1. Check promptfoo release notes for new plugin/strategy additions
2. Check deepteam + PyRIT for new attack categories
3. Update OWASP LLM Top-10 / Agentic Top-10 if new revisions are released
4. Run `python3 tools/knowledge_indexer.py update-internal` to refresh FTS5

Last update: 2026-04-17 (Terminator feat/knowledge-ingest-redteam)
