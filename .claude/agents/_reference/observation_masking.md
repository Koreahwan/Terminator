# Observation Masking (Context Efficiency)

Apply masking rules to SendMessage outputs. Agents must respect token budgets while maintaining evidence integrity.

## Masking Thresholds

| Output Size | Handling |
|-------------|----------|
| < 100 lines | Full inline — no masking needed |
| 100-500 lines | Key findings inline + save full to file + reference path |
| 500+ lines | **MASKING REQUIRED** — `[Obs elided. Key: "..."]` + save to file + file path |

## Implementation

### Small Output (< 100 lines) — Inline

```
I found 3 candidate gadgets:
- ROP chain #1: 0x400500 → 0x400600 → 0x400700
- Stack leak: printf @ 0x400800
- Canary bypass: heap spray method

Next: trigger agent to test chain.
```

### Medium Output (100-500 lines) — Key + File

```
Found 47 matching gadgets across .text and .rodata:

[KEY FINDINGS]
- ROP chain viable: pop rdi; ret (0x400512) + syscall gadget (0x400620)
- Stack canary required: detected via checksec
- Mitigation bypass: heap spray method (tested in similar binary)

[FULL ANALYSIS]
Saved to: /absolute/path/to/gadget_analysis.md

Next: chain agent will reference the full gadget list.
```

### Large Output (500+ lines) — Masking Required

```
[Obs elided. Key: "Binary has partial RELRO (NX on stack + .got.plt writable), no PIE. Found 12 ROP gadgets including pop-rdi-ret. Leak gadget: printf @ libc+0x640. Canary detected. Recommend heap spray or fake stack chain."]

Full analysis: /absolute/path/to/binary_analysis.md

Next: trigger agent receives path to full reversal_map.md
```

**Format**: `[Obs elided. Key: "<1-2 sentence summary>"]`

## File Saving Rules

- **Always use absolute paths** when referencing saved files
- **Confirm file exists** before referencing
- **Archive location**: Same dir as task (CTF = challenge_dir/, BB = targets/<target>/)
- **Naming**: descriptive + timestamp if multiple rounds
  ```
  gadget_analysis_round1.md
  endpoint_map_phase1.md
  vulnerability_candidates_draft.md
  ```

## HANDOFF Protocol (Agent to Agent)

Always include `[KNOWLEDGE CONTEXT]` and `[OBSERVATIONS]` sections:

```
[KNOWLEDGE CONTEXT]
1. [ReturnToLibc] — Previous solutions use libc leak + ROP chain method
2. [HeapExploit] — Heap spray variant for PIE bypass

[OBSERVATIONS]
[Obs elided. Key: "Binary full RELRO, canary present, 12 ROP gadgets found in .text, leak via printf @ offset +0x640."]
Full details: /path/to/reversal_map.md (47 lines)

[CRITICAL FACTS]
- Base address: 0x400000 (PIE off)
- Canary check at __stack_chk_fail
- Leak primitive: printf(user_input)

[NEXT ACTION]
trigger agent: reproduce crash with 300-byte input, locate canary pattern
```

## Never Do

- ❌ Paste 500+ line tool output directly into SendMessage
- ❌ Inline full decompile output (save to file)
- ❌ Inline full CodeQL results (summarize + reference)
- ❌ Repeat the same large output across multiple agents (cite file path once)

## Exception: Evidence Preservation

If output is **critical evidence** (exploit seed, core vulnerability, triager input):
- Always include full output in chat
- Also save to file for record
- Example: triager-sim destruction tests always get full PoC inline (for Gate evaluation)
