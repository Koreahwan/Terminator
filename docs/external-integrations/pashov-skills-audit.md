# Pashov Audit Group Skills — Integration Audit

**Integrated**: 2026-04-17
**Branch**: feat/pashov-skills
**Upstream**: https://github.com/pashov/skills (⭐589, MIT)
**Integration type**: git submodule (no Claude Code marketplace — pashov/skills uses natural-language invocation, not `.claude-plugin/marketplace.json`)
**Submodule path**: `external/pashov-skills/`
**Size**: 5.1 MB

## Phase 1 — Supply-Chain Audit (PASS)

| Check | Result | Notes |
|-------|--------|-------|
| 1.3 activity | ✅ | Last commit 2026-03-24 (< 6 months, active) |
| 1.4 secrets | ✅ | 0 hits |
| 1.5 malicious patterns | ✅ | 0 hits (no `curl \| sh`, `eval(base64)`, `os.popen()`) |
| 1.7 prompt injection | ✅ | 0 hits outside examples |
| 1.8 hook/settings modification | ✅ | 0 unauthorized hook modifications |
| 1.9 license | MIT | Permissive, no attribution constraints in derivatives |

## Skills Available (2)

### `solidity-auditor`
- Purpose: Fast (< 5 min) security feedback on Solidity changes during development
- Trigger: Run after Slither + Mythril + Semgrep (Tool-First Gate)
- Integration: Invoked by `defi-auditor` agent via reading `external/pashov-skills/solidity-auditor/SKILL.md`

### `x-ray`
- Purpose: Pre-audit scan — threat model, invariants, entry points, git history analysis
- Trigger: Run at the start of a DeFi target, before target-evaluator finishes Phase 0
- Integration: Orchestrator reads `external/pashov-skills/x-ray/SKILL.md` and applies to target source tree

## Integration Design

pashov/skills is designed for **natural-language invocation**:
> "Install https://github.com/pashov/skills/ and run an x-ray on the codebase"

We do NOT use this invocation pattern in Terminator (it would re-clone every session). Instead:
1. Submodule pinned to a known commit for deterministic runs
2. `defi-auditor` agent reads the skill SKILL.md files directly and applies them
3. Updates happen via `git submodule update --remote external/pashov-skills && git commit`

## Submodule Operations

```bash
# Initial clone (already done)
git submodule add --depth=1 https://github.com/pashov/skills.git external/pashov-skills

# Update to latest (periodic)
git submodule update --remote external/pashov-skills
git commit -am "chore(submodule): update pashov-skills to <new-sha>"

# Fresh clone including submodules
git clone --recurse-submodules <terminator-repo>
git submodule update --init --recursive
```

## Collision Check

- No slash-command exposure (submodule is invoked via agent reading files, not via `/plugin install`)
- No collision with existing `.claude/agents/` or `.claude/skills/` namespaces
- Submodule path `external/pashov-skills/` is isolated from project code

## Rollback

```bash
# Remove submodule
git submodule deinit -f external/pashov-skills
git rm -f external/pashov-skills
rm -rf .git/modules/external/pashov-skills
# Revert defi-auditor changes
git checkout HEAD~1 -- .claude/agents/defi-auditor.md
```

## License Attribution (MIT)

Pashov Audit Group Skills — MIT © 2024 AI Skills Contributors — https://github.com/pashov/skills
