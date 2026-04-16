# External Wordlists — Integration Audit

**Integrated**: 2026-04-17
**Branch**: feat/payload-submodules
**Integration model**: external (outside Terminator repo) — follows existing `~/PayloadsAllTheThings` + `~/nuclei-templates` convention

## Repos Managed

| Repo | Path | Size | Last update | Purpose |
|------|------|------|-------------|---------|
| **danielmiessler/SecLists** (⭐70.2k, **new**) | `~/SecLists/` | 2.5 GB | 2026-04-16 (8063b41) | 6,031 wordlist files: usernames, passwords, URLs, fuzzing payloads, web shells, 2026.1 AI ethical/safety boundary wordlists |
| **swisskyrepo/PayloadsAllTheThings** (⭐, pre-existing) | `~/PayloadsAllTheThings/` | ~13 MB | 2026-04 (pulled during this session) | 70+ curated vuln category payload collections |

## Why External (not submodule)?

- **SecLists is 2.5 GB** — including as submodule would bloat Terminator clones and CI
- **Existing convention**: `~/PayloadsAllTheThings/` + `~/nuclei-templates/` are already external. Consistency.
- **Shared across projects**: Wordlists are pentest-general, not Terminator-specific — living at `~/` makes them reusable by other tools (Burp, ZAP, manual CLI)

## Phase 1 Audit

- **SecLists**: Pure text-file repo (wordlists). No executable code paths beyond ~/SecLists/Web-Shells/ sample web shells. These are intentional payload examples — **DO NOT** host them; keep on local FS only
- **PayloadsAllTheThings**: Pure markdown + text payload files. Declarative-only

Both from well-known upstreams. Supply chain risk = low (any malicious PR would be immediately caught by thousands of watchers).

## Web Shell Caveat

`~/SecLists/Web-Shells/` contains actual web shells (for upload-based testing). **DO NOT**:
- Commit these to any Terminator repo
- Upload to any scope not explicitly authorized for web shell testing
- Serve from any public HTTP endpoint on your dev machine

## Usage from web-tester agent

```bash
# Directory fuzzing
ffuf -w ~/SecLists/Discovery/Web-Content/raft-large-words.txt \
     -u https://target.example.com/FUZZ -mc 200,204,301,302

# Subdomain (DNS)
ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u https://FUZZ.target.example.com -mc 200,301,302

# Parameter discovery
ffuf -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
     -u "https://target.example.com/api?FUZZ=test" -fr "invalid parameter"

# AI LLM boundary testing (2026.1+)
ls ~/SecLists/Fuzzing/LLM/  # if present in latest release
```

## Update Script

`scripts/update_external_wordlists.sh` — pulls both repos:
```bash
./scripts/update_external_wordlists.sh         # both
./scripts/update_external_wordlists.sh seclists  # SecLists only
./scripts/update_external_wordlists.sh pat       # PayloadsAllTheThings only
```

Cadence: run quarterly or before a new major engagement.

## Rollback

```bash
# Just remove the local clones — no repo state to revert
rm -rf ~/SecLists  # hook will block; use: git worktree remove if it was that
# (Or leave — they're external. Only revert the doc changes in this branch.)
```
