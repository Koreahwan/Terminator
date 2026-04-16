# Bugcrowd Report Style Guide

## Platform Characteristics
- **Taxonomy**: VRT (P1-P5), VRT determines severity — not CVSS
- **Post-submit edits**: NOT allowed — get it right first time
- **Video PoC**: Strongly recommended for complex chains
- **Triage speed**: 1-5 business days typical
- **Duplicate window**: First valid report wins

## Preferred Format

### Title
- Under 70 characters
- Pattern: `[VulnType] in [Component] allows [Impact]`
- Example: `IDOR in /api/users/{id}/settings allows account takeover`

### Structure (Bugcrowd-optimized order)
1. **Executive Conclusion** (3 sentences — what, how, impact)
2. **VRT Classification** with justification
3. **Affected URL/Endpoint** (exact)
4. **Steps to Reproduce** (numbered, under 10 steps)
5. **PoC** (curl commands with redacted auth, or video link)
6. **Impact** (concrete: "attacker can read all user emails" not "data exposure")
7. **Remediation** (3-layer: quick win + defense + architectural)
8. **CVSS Vector** (conditional table if ambiguous)

### Tone
- Factual, observational: "Testing revealed..." not "We discovered..."
- Respectful: assume the code was written by competent engineers
- Specific: exact endpoints, parameters, response codes
- Conservative: understate rather than overstate severity

### VRT Mapping Rules
- Map to ROOT CAUSE, not impact
- Same finding can be P1 or P2 depending on VRT selection
- When unsure between two VRT categories, choose the more conservative one
- Always reference `knowledge/techniques/bugcrowd_vrt.md`

### Common Mistakes (Bugcrowd-specific)
- Submitting before checking Hacktivity for duplicates
- Over-claiming severity without attack chain proof
- Generic titles ("XSS vulnerability found")
- Missing reproducible PoC (theoretical = instant close)
- Editing after submit (not possible — submit clean)
