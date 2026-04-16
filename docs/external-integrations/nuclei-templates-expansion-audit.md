# Nuclei Templates Expansion — Integration Audit

**Integrated**: 2026-04-17
**Branch**: feat/nuclei-templates-expansion
**Upstream**: projectdiscovery (⭐nuclei 26.9k, nuclei-templates 12.2k)

Added two complementary template repos as submodules:

| Repo | Templates | Purpose | Last commit | License |
|------|-----------|---------|-------------|---------|
| `external/nuclei-templates-ai` | 2,529 YAML | AI-generated templates for CVEs not yet in main template repo | 2024-12-10 | (No LICENSE in repo; parent org ProjectDiscovery uses MIT for Nuclei core — treat as MIT, verify before redistribution) |
| `external/fuzzing-templates` | 25 YAML | "Unknown-vulnerability" fuzz templates for Phase 1.5 web-tester | 2024-05-03 | MIT (ProjectDiscovery 2022) |

## Phase 1 — Supply-Chain Audit (PASS)

- Source: ProjectDiscovery official org (creators of Nuclei + Subfinder + httpx, widely trusted)
- No clone-time malicious patterns
- YAML templates (declarative, not executable). Worst case: poorly-written template false-positive, not code execution

## Size

- nuclei-templates-ai: 10 MB
- fuzzing-templates: 136 KB
- Total: ~10 MB on disk

## Usage Pattern

scout agent (Phase 1/1.5) after core nuclei scan:

```bash
# Extra AI-generated CVE coverage
nuclei -u <target> -t external/nuclei-templates-ai/ -silent

# Unknown-surface fuzz probe (Phase 1.5)
nuclei -u <target> -t external/fuzzing-templates/ -silent
```

Both should be run after the default nuclei scan (12K+ templates) to avoid duplication.

## Update

```bash
git submodule update --remote external/nuclei-templates-ai external/fuzzing-templates
git commit -am "chore(submodule): update nuclei templates"
```

## Rollback

```bash
for sm in external/nuclei-templates-ai external/fuzzing-templates; do
  git submodule deinit -f "$sm"
  git rm -f "$sm"
  rm -rf .git/modules/"$sm"
done
git checkout HEAD~1 -- .claude/agents/scout.md
```

## License Caveat (nuclei-templates-ai)

The upstream repo does not include a `LICENSE` file. Since it's maintained by ProjectDiscovery (same org as Nuclei core, MIT), the intent is clearly MIT-compatible. However:
- Do NOT redistribute templates as part of a commercial product without confirming license
- Usage for security testing (our use case) is clearly within intent
- Attribution to projectdiscovery/nuclei-templates-ai recommended in derivative works
