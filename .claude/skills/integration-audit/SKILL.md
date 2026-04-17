---
name: integration-audit
description: Cross-verify tool installation vs code wiring vs docs after any install/upgrade. Auto-match "integration audit", "누락 확인", "설치 후 검증", "tools wiring check". Run after `pip install`, `npm install`, `docker run`, `uv tool install` to catch drift between installed packages and documentation/wiring.
user-invocable: true
argument-hint: [--json | --write]
allowed-tools: [Bash, Read, Grep, Glob]
---

# Integration Audit

## Purpose

Detect drift between what's installed (pip / npm / docker / ~/.local/bin / git submodules) and what's referenced in `CLAUDE.md`, `.mcp.json`, `.claude/agents/*.md`, `tools/**`, and `.claude/rules/**`. Originates from 2026-04-17 firecrawl / FlareSolverr / markitdown-mcp gap: installed but not wired into CLAUDE.md or transport.py.

## Checks (tools/integration_audit.py)

| Check | Severity on fail |
|-------|-----------------|
| Submodule: gitlink in index without `.gitmodules` entry (orphan) | HIGH |
| Submodule: `.gitmodules` entry but empty directory | MEDIUM |
| `.mcp.json` registers but CLAUDE.md doesn't mention | MEDIUM |
| Running Docker container not mentioned in CLAUDE.md / tools / scripts / .claude | MEDIUM |
| Recent (3d) ~/.local/bin install not in CLAUDE.md or any agent file | LOW |
| Recent (3d) site-packages install not imported and not mentioned | LOW |
| Recent (3d) feat/install commit with 0 keyword overlap in CLAUDE.md | INFO |

## Usage

```bash
# Human-readable table
python3 tools/integration_audit.py

# Machine-readable
python3 tools/integration_audit.py --json

# Write audit artifact (docs/integration-gaps.md)
python3 tools/integration_audit.py --write
```

Exit codes: `0=PASS`, `1=medium gaps`, `2=high gaps`. Use the exit code to block commits or CI runs.

## When to invoke

- After any of: `pip install <pkg>`, `pip install --user <pkg>`, `npm install -g <pkg>`, `npm i <pkg>`, `docker run ... -d`, `docker compose up -d`, `git submodule add <repo>`, `uv tool install <pkg>`.
- Before tagging a version bump (v13.5 → v13.6).
- When the user asks "did that integration stick?", "명시 잘 됐어?", "누락 없는지 확인".

## Recommended hook

Add to `.claude/settings.json` to auto-run after installer Bash calls:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "if echo \"$CLAUDE_TOOL_INPUT\" | grep -qE '(pip install|npm install|docker run|docker compose up|uv tool install|git submodule add)'; then python3 tools/integration_audit.py 2>&1 | head -30; fi"
          }
        ]
      }
    ]
  }
}
```

This prints a short audit summary immediately after relevant installer commands so drift is visible while context is fresh.

## Output artifact

`docs/integration-gaps.md` — persistent gap table, refreshed each `--write` run. Commit this file when gaps are intentional (e.g., MCP listed in CLAUDE.md but plugin-provided, not in `.mcp.json`).

## Known false positives

- MCP servers listed in CLAUDE.md but plugin/OMC-provided (e.g., `lightpanda`, `browser-use`, `gdb`, `ghidra`, `frida`, `pentest`, `pentest-thinking`, `opendataloader-pdf`, `markitdown-mcp`, `promptfoo`) → LOW severity, expected noise.
- Dev tooling in `~/.local/bin/` (uv, uvx, git-filter-repo, watchmedo) → skiplist in `tools/integration_audit.py::_BIN_SKIP`.

## References

- **Tool**: `tools/integration_audit.py`
- **CLAUDE.md**: "MCP (inventory=18, registered=8)" + "MCP registration state" + "Web fetching tiers"
- **Prior incident**: firecrawl-py v4.22.2 + FlareSolverr (Docker :8191) installed 2026-04-17 without CLAUDE.md / transport.py / agent wiring. Found by manual inspection 4h later. This skill prevents recurrence.
