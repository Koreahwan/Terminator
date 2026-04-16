# Trail of Bits Skills Marketplace — Integration Audit

**Integrated**: 2026-04-17
**Branch**: feat/trailofbits-skills
**Upstream**: https://github.com/trailofbits/skills (⭐4.6k, CC-BY-SA-4.0)
**Marketplace entry**: `trailofbits` (via `/plugin marketplace add trailofbits/skills`)
**Install location**: `~/.claude/plugins/marketplaces/trailofbits/`

## Phase 1 — Supply-Chain Audit (PASS)

| Check | Result | Notes |
|-------|--------|-------|
| 1.2 git signing | OK | Clone HEAD: `1efb11a` |
| 1.3 activity | ✅ | Last commit 2026-04-14 (< 6 months, active) |
| 1.4 secrets | ✅ | 0 verified secrets. 1 FP in `agentic-actions-auditor` docs example (`ghp_xxxx` demonstrating shell subshell danger) |
| 1.5 malicious patterns | ✅ | 0 hits for `curl \| sh`, `eval(base64)`, `os.popen()` |
| 1.7 prompt injection | ✅ | 0 hits for "ignore previous", "you are now" outside examples |
| 1.8 hook/settings modification | ✅ | All hook references are legitimate skill design documentation. No attempts to write `settings.local.json` |
| 1.9 license | CC-BY-SA-4.0 | Attribution-ShareAlike. Usage ok; attribution required in derivative docs |

## Plugins Available (38 total)

### Recommended for Terminator integration (HIGH ROI)

| Plugin | Why |
|--------|-----|
| **fp-check** | False-positive verification — complements Phase 4.5 triager-sim |
| **variant-analysis** | Pattern-based similar-bug search — complements `patch-hunter` agent |
| **semgrep-rule-creator** | Custom Semgrep rules — enhances existing `semgrep-mcp` |
| **semgrep-rule-variant-creator** | Port rules across languages — multiplier on existing Semgrep infra |
| **static-analysis** | Unified CodeQL + Semgrep + SARIF parser — consolidates existing MCP workflows |
| **supply-chain-risk-auditor** | Dep risk analysis — new capability for Terminator |
| **insecure-defaults** | Hardcoded creds + insecure config scan — complements `source-auditor` |
| **building-secure-contracts** | 6-blockchain SC security toolkit — enhances `defi-auditor` agent |
| **entry-point-analyzer** | SC state-changing entry point ID — enhances DeFi Phase 0.5 |
| **spec-to-code-compliance** | Spec/code audit — DeFi Phase 1 enhancement |
| **yara-authoring** | YARA rule authoring — new malware/IoC capability |
| **agentic-actions-auditor** | GitHub Actions AI agent security — unique capability |
| **audit-context-building** | Ultra-granular code context for auditing — Phase 1.5 enhancement |
| **differential-review** | Security-focused code change review — complements critic agent |
| **gh-cli** | Intercept GitHub URL fetches → authenticated gh CLI — resolves known WebFetch-on-private-repo pain |

### Utility / low-overlap

- `mutation-testing`, `property-based-testing`, `constant-time-analysis`, `zeroize-audit`, `dimensional-analysis`, `sharp-edges`, `dwarf-expert`, `firebase-apk-scanner`, `trailmark` (multi-lang call graph), `second-opinion`, `skill-improver`, `workflow-skill-design`

### Not recommended (overlap or not applicable)

- `modern-python` — Terminator already has Python conventions
- `devcontainer-setup` — we use native WSL
- `seatbelt-sandboxer` — macOS-only
- `culture-index`, `let-fate-decide` — not security
- `debug-buttercup`, `claude-in-chrome-troubleshooting` — ToB-specific infra
- `burpsuite-project-parser` — we don't use Burp projects
- `ask-questions-if-underspecified` — Terminator uses AskUserQuestion for this

## Installation (individual plugins, user-driven)

After Claude Code reload, install selectively:

```
/plugin install fp-check@trailofbits
/plugin install variant-analysis@trailofbits
/plugin install semgrep-rule-creator@trailofbits
/plugin install static-analysis@trailofbits
/plugin install supply-chain-risk-auditor@trailofbits
/plugin install gh-cli@trailofbits
/plugin install building-secure-contracts@trailofbits
/plugin install agentic-actions-auditor@trailofbits
```

**Do NOT install all 38** — name collisions + context overhead. Cherry-pick per need.

## Collision Matrix (pre-install check)

Checked against baseline `/tmp/terminator_baseline_20260417_013530/project_names.txt`:

- No name collision with Terminator agents/skills at marketplace level
- Individual plugins may introduce slash-commands like `/fp-check` — check vs `.claude/skills/` after each install
- `gh-cli` plugin hooks intercept GitHub URLs — verify no conflict with existing `tools/knowledge_fetcher.py fetch <url>` pattern

## Rollback

```bash
# Remove marketplace entry
python3 -c "
import json, pathlib
p = pathlib.Path.home()/'.claude/plugins/known_marketplaces.json'
cfg = json.loads(p.read_text())
cfg.pop('trailofbits', None)
p.write_text(json.dumps(cfg, indent=2))
"
# Remove clone
rm -rf ~/.claude/plugins/marketplaces/trailofbits
# Uninstall any installed plugins
# /plugin uninstall <name>@trailofbits
```

## Attribution (CC-BY-SA-4.0 requirement)

Trail of Bits Skills — CC-BY-SA-4.0 — https://github.com/trailofbits/skills
