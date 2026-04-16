# Structured Reasoning (MANDATORY at Decision Points)

At every significant decision point, separate evidence layers before concluding.

## Decision Framework

```
OBSERVED: [concrete evidence from tools/execution — what you directly see/measure]
INFERRED: [logical deductions from observations — patterns, implications]
ASSUMED:  [unverified beliefs — FLAG THESE EXPLICITLY]
RISK:     [what breaks if assumptions are wrong]
DECISION: [action + brief rationale tying to observations]
```

## Examples

### Example 1: Exploit Strategy Selection
```
OBSERVED:
- Binary has partial RELRO, no PIE, 4GB PIE not used
- Stack canary present, checked via checksec
- Leak gadgets exist in .text (confirmed by ROPgadget grep)

INFERRED:
- Canary will block stack smash directly
- ASLR on heap/stack, but code base fixed
- Leak → canary overwrite is viable path

ASSUMED:
- Leak gadget ROP will work (no validation yet)
- Canary leak doesn't require bruteforce

RISK:
- If leak requires multiple attempts, might timeout on remote
- If canary check happens at exit (not return), overwrite fails

DECISION:
Attempt leak + overwrite chain. If fails, switch to heap spray / vtable overwrite.
```

### Example 2: Vulnerability Classification
```
OBSERVED:
- User input passed to strcpy() without bounds checking
- Function is exposed via HTTP endpoint
- Attacker can control 200+ byte input

INFERRED:
- Stack overflow is likely exploitable (auth not required per endpoint analysis)
- Program crash reproducible with crafted input

ASSUMED:
- No stack canary (not confirmed yet)
- No input validation upstream

RISK:
- Input might be filtered at HTTP layer (validation framework)
- Stack layout might differ on target vs. test env

DECISION:
Spawn trigger agent to reproduce crash. If crashes → chain agent. If filters block → analyze filtering logic.
```

## Usage Rules

1. **Never skip ASSUMED section** — all assumptions explicit
2. **RISK always present** — ask "what if assumptions wrong?"
3. **Evidence → conclusion order** — never reverse-engineer justification
4. **Shared with agent team** — include in HANDOFF for transparency
5. **On disagreement** — clearly mark which assumptions differ between agents

## Anti-Pattern (AVOID)

```
OBSERVED: Binary runs
INFERRED: Exploit will work
ASSUMED: ???
RISK: ???
DECISION: Go ahead with exploit

❌ This is backwards. Decision pre-made, framework used as justification cover.
```

## Correct Anti-Pattern Rewrite

```
OBSERVED: Binary crashes on input longer than 256 bytes
INFERRED: Stack buffer overflow likely
ASSUMED: Canary not present (untested); exploit will work first try
RISK: Canary present → need leak first; ROP gadgets might not chain

DECISION: reverser → verify canary via GDB → decide chain vs leak-first strategy
```
