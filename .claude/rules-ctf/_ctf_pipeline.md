# CTF Pipeline — Detailed Procedure

Referenced from CLAUDE.md. This file contains the full step-by-step CTF solving procedure.

## Pipeline Selection (MANDATORY)

```
if trivial (source provided, logic bug visible in 1-3 lines, one-liner exploit):
    ctf-solver 1-agent (subagent_type="ctf-solver", model=sonnet) → reporter
elif type == "pwn" and vuln clear:
    reverser → chain → critic → verifier → reporter  (5-agent)
elif type == "pwn" and vuln unclear:
    reverser → trigger → chain → critic → verifier → reporter  (6-agent)
elif type == "reversing" or "crypto":
    reverser → solver → critic → verifier → reporter  (4-agent)
elif type == "web":
    scout → analyst → exploiter → reporter  (4-agent)
elif type == "firmware":
    fw-profiler → fw-inventory → fw-surface → fw-validator  (4-agent)
```
**Never use full 6-agent pipeline unconditionally.** Unnecessary agents = token waste.

## Step 0: Pre-Check (Orchestrator does directly)

```bash
echo "test" | ./binary 2>&1  # Check if binary runs
# "cannot execute" → install libs (sudo apt install libc6:i386 etc.)
file ./binary && strings ./binary | head -20
```
**If binary doesn't run, install libraries first. Prevents agent Python-only circular verification.**

## Step 1: Team Creation

```
TeamCreate("ctf-<challenge_name>")
```

## Step 2: Sequential Pipeline

### Orchestrator Role
- Break goals into rounds, dispatch tasks to agents
- Receive artifact summaries, forward to next agent
- On failure: re-run stage or feed back to previous stage

### Agent Stages

**@ reverser** (subagent_type="reverser", model=sonnet, mode=bypassPermissions):
- Binary structure, input paths, protections, key functions, observation points
- Artifact: `reversal_map.md` (attack map ready for exploiter)

**@ trigger** (subagent_type="trigger", model=sonnet, mode=bypassPermissions) [pwn only, skippable]:
- Read reversal_map.md, search for crashes/anomalies
- Minimal repro input, condition pinning, raw primitive identification
- Artifact: `trigger_report.md` + `trigger_poc.py`

**@ solver** (subagent_type="solver", model=opus, mode=bypassPermissions) [reversing/crypto only]:
- Inverse computation, constraint solving, mathematical reasoning
- Artifact: `solve.py`

**@ chain** (subagent_type="chain", model=opus, mode=bypassPermissions) [pwn only]:
- Read trigger_report.md, extend primitive
- leak → overwrite → shell/flag chain assembly
- Artifact: `chain_report.md` + `solve.py`
- **Incremental rule**: max 200 lines per phase + local test. No next phase without test.

**@ critic** (subagent_type="critic", model=opus, mode=bypassPermissions):
- Cross-verify solve.py + reversal_map.md + chain_report.md
- Independent verification of addresses/offsets/constants via GDB/Ghidra MCP
- APPROVED → **codex cross-review** → verifier | REJECTED → specific fixes back to chain/solver
- Artifact: `critic_review.md`

**@ codex cross-review** (Orchestrator runs directly, after critic APPROVED) [OPTIONAL but RECOMMENDED]:
- `/codex:adversarial-review --wait` on solve.py + chain_report.md
- Cross-model verification: GPT-5.4 independently reviews Claude's exploit
- Focus: offset correctness, gadget validity, assumption challenges
- PASS (no critical issues) → verifier | CRITICAL ISSUE → back to chain/solver with Codex feedback
- **Skip conditions**: trivial challenges, ctf-solver 1-agent pipeline, time pressure
- Artifact: Codex review output appended to `critic_review.md`

**@ verifier** (subagent_type="verifier", model=sonnet, mode=bypassPermissions):
- After critic APPROVED: local 3x reproduction (PASS/RETRY/FAIL)
- PASS → remote(host, port) execution → `FLAG_FOUND: <flag>`
- FAIL → failure analysis, Orchestrator re-runs stage 2 or 3
- **Never modify solve.py** — report issues only

**@ reporter** (subagent_type="reporter", model=sonnet, mode=bypassPermissions):
- After verification: write knowledge/challenges/<name>.md
- Include: reproduction steps, key techniques, failed attempts

## Step 3: Result Collection (Orchestrator)

- Verify FLAG_FOUND (Orchestrator MUST run solve.py directly to confirm)
- Update `knowledge/index.md`
- TeamDelete

## Early Critic Option (complex binaries)

For Full RELRO+PIE+Canary, custom allocator, stripped binaries:
```
reverser → critic(lightweight, model=sonnet) → chain/solver → critic(full) → verifier → reporter
```
Early Critic scope: fact-check reversal_map.md addresses/offsets/constants only (not full review).

## Dual-Approach Auto-Trigger & Best@N Parallel Retry (after 2 failures)

SCONE-bench 연구에서 Best@8이 Best@1 대비 2-3x 성공률 향상 검증.

When chain/solver fails 2x consecutively on same challenge:
```
Option A (Cross-Model — default):
  chain-A (Claude opus, different strategy hint)
  + codex:rescue (GPT-5.4 independent attempt, --write --background)
  First success adopted, other terminated.

Option B (Best@3 Same-Model — when codex unavailable or depth needed):
  chain-A (strategy: traditional ROP)
  + chain-B (strategy: ret2libc/one_gadget)
  + chain-C (strategy: FSOP/stack pivot)
  All 3 run in parallel. First local shell wins.
  Orchestrator picks based on: success > stability > code simplicity.
```

**Selection**: Orchestrator uses Option A by default. Option B when:
- codex plugin unavailable
- Previous dual-approach both failed (escalate to 3-way)
- Challenge type benefits from strategy diversity (heap feng shui)

Cross-model dual-approach eliminates single-model blind spots.
After 4 total failures: mandatory external writeup search (WebSearch).

## Fake Flag vs Real Flag (CRITICAL)

```
challenge.zip
├── binary          ← analysis target
├── Dockerfile      ← server env reproduction
├── flag (or flag.txt) ← FAKE FLAG
└── docker-compose.yml
```

**Local flag file = FAKE.** Real flag exists only on remote server.

### Correct Flow
1. Analyze binary locally + find vulnerability
2. Write exploit with pwntools (`process()` for local test)
3. Local test passes → switch to `remote(host, port)`
4. Execute on remote → **real flag obtained**

### solve.py Standard Pattern
```python
from pwn import *
context.binary = './binary'
# p = process('./binary')       # local test
p = remote('host.example.com', 12345)  # remote real flag
# ... exploit logic ...
p.interactive()
```

### Never Do
- Read local `flag` file and declare "FLAG_FOUND!"
- Mistake Dockerfile fake flag for real flag

## Image Processing (flag in image)

Priority: Read(multimodal) → pytesseract OCR → zbarimg(QR) → PIL pixel analysis → ask user.
On repeated API errors, switch to OCR immediately (no infinite retry).

## Orchestrator Flag Verification (MANDATORY)

When agent reports FLAG_FOUND, Orchestrator MUST run solve.py directly to verify.
- Agents can bring wrong flags from internet writeups
- Agents can make hex→decimal conversion errors
- **No FLAG_FOUND declaration without direct execution → output confirmation.**
