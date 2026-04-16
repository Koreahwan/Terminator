# MCP/Agent/Skill Security Scans — Integration Audit

**Integrated**: 2026-04-17
**Branch**: feat/mcp-security-scans

Two-layer self-audit capability for Terminator's own `.claude/` + external plugin environment:

1. **Offline audit** (`scripts/audit_mcp_config.sh`) — no cloud, runs locally, 7 checks
2. **Cloud audit** (`snyk-agent-scan`, formerly invariantlabs/mcp-scan) — deeper analysis, requires SNYK_TOKEN

## Why dogfooding self-audit matters

Recent industry finding (2026): ClawHub skill marketplace audit of ~4,000 skills showed:
- 1/3+ contained at least one security flaw
- 13.4% had critical-level issues

As we pile external marketplaces/plugins into Terminator, we must continuously verify our own `.claude/` hygiene.

## Layer 1 — Offline Audit

`scripts/audit_mcp_config.sh` — 7 checks, no network:

| Check | What | Severity |
|-------|------|----------|
| A. MCP collision | Duplicate server name in project+user MCP configs | critical |
| B. MCP cmd path | Server command not found in PATH or missing at declared absolute path | warning |
| C. MCP secrets | Literal API token / secret pattern embedded in MCP config | critical |
| D. Name collision | Agent/skill name collides with installed plugin | warning |
| E. Prompt injection | "ignore instructions" / "you are now X" markers in agent/skill MDs | warning |
| F. Settings JSON validity | `~/.claude/settings.json` is valid JSON | critical |
| G. Model assignment | Terminator agents declare `model:` (IRON RULE — else opus inherits, 3-5x waste) | warning |

**Usage**:
```bash
./scripts/audit_mcp_config.sh           # text report
./scripts/audit_mcp_config.sh --json    # structured JSON output for CI/automation
# Exit: 0 clean, 1 warnings, 2 critical
```

**Current state** (2026-04-17 initial run, post 7 integrations):
- 0 critical
- 3 warnings: `analyst`, `critic`, `verifier` agent names collide with OMC plugin (pre-existing, benign — OMC plugin has differently-focused agents with same short names)

## Layer 2 — Cloud Audit (snyk-agent-scan)

```bash
# Install (already done in this feat)
uv tool install snyk-agent-scan
# Requires SNYK_TOKEN env var — get from https://app.snyk.io/account
export SNYK_TOKEN="..."
snyk-agent-scan scan .claude/mcp.json
```

snyk-agent-scan is the renamed invariantlabs/mcp-scan (acquired by Snyk in 2026 and repackaged). Provides:
- Prompt injection detection in MCP tool descriptions
- Tool poisoning analysis
- Toxic flow detection (cross-tool data leakage paths)
- Compared against Snyk's threat intel DB

**Decision**: keep installed but not mandatory in pipeline. Offline audit covers 80% of concerns without cloud dependency.

## Layer 3 — AI-Infra-Guard (Tencent, OPTIONAL)

NOT installed. Docker-based full platform (OpenClaw Security Scan + Agent Scan + Skills Scan + MCP Scan + LLM Jailbreak Eval). Useful for enterprise, overkill for single-dev CLI workflow.

**If needed later**:
```bash
git clone https://github.com/Tencent/AI-Infra-Guard.git ~/AI-Infra-Guard
cd ~/AI-Infra-Guard
docker-compose up -d
# ⚠️ Upstream warning: "lacks authentication mechanism, should not be deployed on public networks"
```

## Recurring Audit (recommended)

Add to `scripts/weekly_maintenance.sh` or a cron:
```bash
# Every Sunday 04:00 — right after PoC-in-GitHub sync
0 4 * * 0 cd /mnt/c/Users/KH/All_Projects/Terminator && ./scripts/audit_mcp_config.sh --json > ~/terminator_mcp_audit_$(date +\%Y\%m\%d).json
```

## Rollback

```bash
# Uninstall snyk-agent-scan
uv tool uninstall snyk-agent-scan
# Remove audit script (or leave — it's useful)
git checkout HEAD~1 -- scripts/audit_mcp_config.sh docs/external-integrations/mcp-security-scans-audit.md
```
