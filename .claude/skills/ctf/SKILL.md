---
name: ctf
description: Start CTF challenge solving pipeline. Auto-matches "ctf", "solve challenge", "pwn", "reversing", "crypto challenge", "wargame"
argument-hint: [challenge-path] [host:port]
---

# CTF Challenge Pipeline

## CRITICAL RULES (NEVER VIOLATE)
1. **Local flag file = FAKE** — only remote(host, port) has the real flag. Never read local flag and declare FLAG_FOUND
2. **MUST use Agent Teams** — never solve by running r2/gdb/python directly (trivial exception only)
3. **Agent model MANDATORY** — reverser=sonnet, chain=opus, critic=opus, verifier=sonnet, solver=opus

## Pre-checks (auto-executed)

Challenge info:
!`if [ -n "$1" ] && [ -e "$1" ]; then file "$1" 2>/dev/null && checksec --file="$1" 2>/dev/null | head -5; elif [ -d "$ARGUMENTS" ] 2>/dev/null; then ls -la "$ARGUMENTS" 2>/dev/null | head -10; fi`

Knowledge DB prior attempts:
!`python3 /home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/tools/knowledge_indexer.py search "$ARGUMENTS" 2>/dev/null | head -10 || echo "search unavailable"`

## Pipeline Rules

**MUST solve with Agent Teams.** Do NOT solve directly.

### Step 0: Pre-analysis (Orchestrator direct)
1. Read `knowledge/index.md` — check if already solved or attempted
2. Verify binary execution: `echo "test" | ./<binary> 2>&1`
3. Cannot execute → install libraries first (`sudo apt install libc6:i386` etc.)
4. Basic analysis: `file`, `checksec`, `strings | head -20`

### Step 1: Difficulty Assessment → Pipeline Selection
```
if difficulty == "trivial" (source available, logic bug, one-liner exploit):
    ctf-solver 1-agent (model=sonnet) → reporter
elif type == "pwn" and vuln_clear:
    reverser → chain → critic → verifier → reporter  (5-agent)
elif type == "pwn" and vuln_unclear:
    reverser → trigger → chain → critic → verifier → reporter  (6-agent)
elif type == "reversing" or "crypto":
    reverser → solver → critic → verifier → reporter  (4-agent)
elif type == "web":
    scout → analyst → exploiter → reporter  (4-agent)
```

### Step 2: TeamCreate + Sequential Pipeline
```
TeamCreate("ctf-<challenge_name>")
```
All agents: `subagent_type="<role>"`, `mode="bypassPermissions"`, model MUST be specified.

### Step 3: Result Collection
- FLAG_FOUND → Orchestrator runs solve.py directly to verify
- Update `knowledge/index.md`
- TeamDelete cleanup

## Failure Protocol
- **2 failures → Dual-Approach** (two different strategies in parallel)
- **4 failures → WebSearch for writeups**

> **REMINDER**: Local flag = FAKE. Always verify via remote(host, port). Agent model parameter is mandatory.
