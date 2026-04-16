# MSRC (Microsoft Security Response Center) Report Style Guide

## Platform Characteristics
- **Focus**: Microsoft products (Windows, Azure, Office, Edge, etc.)
- **Portal**: MSRC Researcher Portal (msrc.microsoft.com)
- **Taxonomy**: MSRC severity + CVSS
- **Bounty range**: $500 - $250,000+ (Azure/Hyper-V highest)
- **Triage**: Specialized MS engineers per product team
- **Timeline**: 90-day disclosure, CVE assignment

## Preferred Format

### Title
- Pattern: `[Product] - [Component] - [VulnType]`
- Example: `Windows Kernel - Win32k - Use-After-Free leading to LPE`

### Structure (MSRC-optimized order)
1. **Summary** (product, component, vulnerability type, impact)
2. **Affected Products** (exact build numbers, KB references)
3. **Technical Details**
   - Root cause with code references (if source available via symbols)
   - WinDbg output showing crash/corruption
   - Stack trace with symbols
4. **Reproduction Steps**
   - Environment: Windows version, build, arch, config
   - Step-by-step with exact commands
   - Expected vs actual behavior
5. **Proof of Concept**
   - Attached binary/script
   - Must work on latest patched version
   - Include compilation instructions
6. **Impact** (LPE, RCE, Info Disclosure, DoS)
7. **Suggested Fix** (optional but valued)

### Tone
- Formal, technical, precise
- Reference MSDN documentation where applicable
- Include Windows internals terminology (IRQL, MDL, pool type, etc.)
- Stack traces and WinDbg output are essential evidence

### Common Mistakes (MSRC-specific)
- Submitting against outdated/unpatched Windows version
- Missing build number (just "Windows 11" is insufficient)
- DoS-only without escalation path (low bounty or decline)
- Vulnerabilities in third-party drivers attributed to Microsoft
- Missing symbols in stack traces
