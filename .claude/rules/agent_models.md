# Agent Model Assignment (MANDATORY)

Unspecified model = inherits parent (claude-opus-4-6[1m]) = 3-5x token waste. Pipeline violation.

### Agent Model Assignment (MANDATORY — no spawn without model)

Canonical list of all 30 agents in `.claude/agents/`. Each file MUST declare `model:` in its YAML frontmatter. `scripts/audit_mcp_config.sh` check G enforces this and flags any agent missing the declaration.

#### CTF pipeline

| Agent | Model | Reason |
|-------|-------|--------|
| reverser | sonnet | Structure analysis, pattern matching |
| trigger | sonnet | Crash search, execution-based |
| solver | claude-opus-4-6[1m] | Complex inverse computation |
| chain | claude-opus-4-6[1m] | Multi-stage exploit design |
| ctf-solver | sonnet | Trivial CTF end-to-end single-agent solve |

#### Bug Bounty pipeline

| Agent | Model | Reason |
|-------|-------|--------|
| target-evaluator | sonnet | Target ROI, GO/NO-GO |
| scout | sonnet | Recon, tool execution |
| analyst | sonnet | CVE matching, pattern search |
| threat-modeler | sonnet | Trust boundary modeling, state machine extraction |
| workflow-auditor | sonnet | Workflow state transition mapping, anomaly detection |
| patch-hunter | sonnet | Security commit diff analysis, variant search |
| web-tester | sonnet | Request-level + workflow pack testing |
| recon-scanner | sonnet | Automated broad recon sweep (hosts, ports, endpoints, JS) |
| exploiter | claude-opus-4-6[1m] | PoC development, complex exploits |
| source-auditor | claude-opus-4-6[1m] | Deep source code security review (files, data flows, business logic) |
| defi-auditor | claude-opus-4-6[1m] | Smart contract + DeFi exploit audit |
| triager-sim | sonnet/claude-opus-4-6[1m] | Gate 1=sonnet, Gate 2+report-review=claude-opus-4-6[1m] (review task) |
| submission-review | claude-opus-4-6[1m] | Final 3-perspective review panel (Phase 5.5) — review task |

#### Firmware pipeline

| Agent | Model | Reason |
|-------|-------|--------|
| fw-profiler | sonnet | Read profile artifacts, choose smallest safe next-stage subset |
| fw-inventory | sonnet | Validate firmware inventory, decide re-run necessity |
| fw-surface | sonnet | Map attack surface, build evidence bundles |
| fw-validator | sonnet | Enforce validator policy, gate unsupported confirmed findings |

#### Mobile pipeline

| Agent | Model | Reason |
|-------|-------|--------|
| mobile-analyst | sonnet | Android/iOS static + dynamic analysis |

#### Domain-specific Scanners

| Agent | Model | Reason |
|-------|-------|--------|
| ai-recon | sonnet | LLM endpoint mapping, model fingerprinting, tool enumeration |
| robo-scanner | sonnet | ROS topology, node enumeration, firmware extraction |
| sc-scanner | sonnet | SBOM generation, dependency tree, namespace conflicts |

#### Cross-pipeline

| Agent | Model | Reason |
|-------|-------|--------|
| critic | claude-opus-4-6[1m] | Cross-verification, logic error detection |
| verifier | sonnet | Execution + verification, simple judgment |
| reporter | sonnet | Documentation |
| cve-manager | sonnet | CVE eligibility, GHSA/MITRE submission prep |

---

### Total: 30 agents

### Notes

- **Filename vs agent name**: Six agent files use underscore filenames (`fw_inventory.md`, `fw_profiler.md`, `fw_surface.md`, `fw_validator.md`, `target_evaluator.md`, `triager_sim.md`) but their `name:` fields use dash (`fw-inventory`, etc). Subagent lookup uses `name:` — the `-` form is canonical. Underscore filenames are retained for Python artifact/coordination history compatibility.

- **Model choice rationale**:
  - `claude-opus-4-6[1m]` (**pinned** with 1M context): complex reasoning (exploit design, deep audit, cross-verification, multi-step review). **Why pinned**: Opus 4.6 with 1M context window — cybersecurity-specific evals 최적. Pin prevents accidental regression when Anthropic rotates the `opus` alias.
  - `sonnet` (current = Sonnet 4.6): tool execution, pattern search, documentation, simple judgment, structured scanning. Not pinned — Sonnet 4.6 is the current generation and upgrades are expected to be beneficial.
  - `sonnet/claude-opus-4-6[1m]`: variable by phase (triager-sim Gate 1 = fast sonnet; Gate 2+report = thorough claude-opus-4-6[1m]).

- **Model ID resolution**: If `claude-opus-4-6[1m]` is rejected by Claude Code at subagent spawn (invalid model ID), check Anthropic's current valid ID list. Possible alternatives: `claude-opus-4-6` (without context suffix) or `claude-opus-4-6-<YYYYMMDD>` (dated form).

- **Enforcement**: `./scripts/audit_mcp_config.sh` check G will FAIL if any agent in `.claude/agents/*.md` (excluding `_reference/`) lacks a `model:` line with one of `claude-opus-4-6[1m]|sonnet|haiku`.

- **Sync requirement**: When adding a new agent, update BOTH this file and the table in `CLAUDE.md` (they currently mirror). Consider deduplication into a single canonical source in future.
