# Report Rejection Patterns

Common reasons bug bounty reports get rejected, derived from
`knowledge/triage_objections/` feedback and industry patterns.

## Pre-Submit Checklist (check ALL before submitting)

- [ ] Finding is in scope (check program policy)
- [ ] Not a known issue (check Hacktivity/disclosed)
- [ ] Not a duplicate of own previous submission
- [ ] PoC actually works (re-run from scratch)
- [ ] Severity is calibrated (not over-claimed)

## Rejection Categories

### 1. Informative / N/A (most common)
**Cause**: Finding is by design or out of scope
**Signal**: -5 reputation on HackerOne
**Prevention**:
- Read program policy word by word
- Check "Known Issues" section
- Frame design-intent findings as "abuse risk"
- Include "honest severity expectation"

### 2. Duplicate
**Cause**: Someone reported it first
**Prevention**:
- Check Hacktivity before submitting
- `bb_preflight.py duplicate-graph-check` for known CVEs
- Submit faster — don't over-polish if finding is simple

### 3. Insufficient Evidence
**Cause**: Theoretical finding without working PoC
**Prevention**:
- Runtime-verified PoC is MANDATORY
- Include captured output with timestamps
- Video PoC for complex chains
- Self-reproduce from your own steps before submitting

### 4. Severity Over-claim
**Cause**: CVSS doesn't match actual impact
**Prevention**:
- Conditional CVSS table (min 2 scenarios)
- Conservative CVSS: when unsure, choose lower metric
- "Honest Severity Expectation" statement
- No A:H without benchmark, no PR:N without auth bypass proof

### 5. AI-Generated Slop
**Cause**: Report reads like automated template output
**Prevention**:
- AI Slop Score must be <= 2
- Every sentence needs target-specific technical detail
- No generic security advice
- Run `report_scrubber.py` before submit
- Run `report_scorer.py` — ai_slop dimension must be >= 70

### 6. Missing Root Cause (ZDI-specific)
**Cause**: Report describes symptoms, not the underlying code flaw
**Prevention**:
- Include exact function, offset, code path
- Explain WHY the code is wrong, not just WHAT happens
- Memory corruption: specify primitive type (OOB, UAF, etc.)

### 7. Scope Mismatch
**Cause**: Testing on wrong asset, wrong version, or excluded component
**Prevention**:
- Verify exact scope URL/domain
- Test on latest version
- Check exclusion list
- `bb_preflight.py exclusion-filter` before analyst phase

## Lessons from Terminator History

### BYD Atto 3 (ZDI — REJECTED)
- Auth bypass without memory corruption
- ZDI focus is binary/memory bugs
- Lesson: match finding type to platform focus

### VMware VMWARE-D5P0EHPB (Vendor Direct — PENDING)
- Guest-to-host file write via .vmx serial port
- Strong root cause + clear exploitation path
- Lesson: vendor direct requires patience + follow-up schedule
