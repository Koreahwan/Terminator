# ZDI (Zero Day Initiative) Report Style Guide

## Platform Characteristics
- **Focus**: Binary/memory corruption, 0-day, n-day
- **Taxonomy**: CVSS + internal severity
- **Preference**: Detailed root cause analysis over surface-level findings
- **PoC requirement**: Working exploit preferred; crash PoC minimum
- **Acquisition model**: ZDI buys the vuln — researcher doesn't disclose
- **Triage**: Expert binary analysts — BS detection is high
- **Rejection risk**: High for findings without clear root cause

## Preferred Format

### Title
- Pattern: `[Vendor] [Product] [Component] [VulnType] [Impact] Vulnerability`
- Example: `VMware Workstation Serial Port Arbitrary File Write Remote Code Execution Vulnerability`

### Structure (ZDI-optimized order)
1. **Vulnerability Summary**
   - Affected product + exact version
   - Root cause in 2-3 sentences (CWE + mechanism)
   - User interaction required? Authentication required?
2. **Detailed Root Cause Analysis**
   - Exact code path: function names, offsets, decompiled code
   - Memory layout diagrams if relevant
   - Data flow from input to vulnerability trigger point
   - This is THE section ZDI cares most about
3. **Exploitation**
   - Step-by-step exploitation path
   - Reliability assessment (100% vs race condition)
   - Constraints and limitations
4. **Proof of Concept**
   - Minimal crash PoC at minimum
   - Full exploit chain preferred
   - Include binary/script + instructions
5. **Impact**
   - Code execution context (user/root/SYSTEM)
   - Attack surface (local/network/internet)
   - CVSS vector with justification
6. **Affected Versions**
   - Exact versions tested
   - Likely affected range

### Tone
- Academic precision — like writing for a peer-reviewed paper
- Root cause depth is everything
- "The vulnerability exists in function X at offset Y" is acceptable (ZDI convention)
- Include disassembly/decompilation snippets
- Honest about exploitation reliability

### Root Cause Depth (ZDI differentiator)
ZDI values root cause analysis above all else. A report with:
- Clear root cause + crash PoC = likely accept
- Vague root cause + full exploit = likely reject or downgrade

Must include:
- Exact function where the bug lives
- Why the code is wrong (missing check, integer overflow, etc.)
- What input triggers the path
- Memory corruption primitive type (OOB read/write, UAF, etc.)

### Common Mistakes (ZDI-specific)
- Shallow root cause analysis (biggest rejection reason)
- Submitting known/patched vulnerabilities
- Missing version information
- PoC that only works on specific OS/config without noting it
- Submitting logic bugs to ZDI (not their focus — they want memory corruption)
- BYD Atto 3 lesson: authentication bypass without memory corruption may be declined
