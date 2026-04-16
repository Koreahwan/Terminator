# HackerOne Report Style Guide

## Platform Characteristics
- **Taxonomy**: CWE + CVSS 3.1 (program may override)
- **Post-submit edits**: Allowed (comments + updates)
- **N/A reports**: -5 reputation signal — avoid at all costs
- **Script attachments**: OK (zip with PoC scripts)
- **Mediation**: Available for disputed findings

## Preferred Format

### Title
- Under 70 characters
- Pattern: `[CWE-XXX] [VulnType] in [component] via [vector]`
- Example: `[CWE-639] IDOR in /api/v2/accounts via predictable UUID`

### Structure (HackerOne-optimized order)
1. **Summary** (2-3 sentences: vuln type, component, impact)
2. **Affected Asset** (exact URL from scope)
3. **Severity** (CVSS 3.1 vector + justification)
4. **Steps to Reproduce**
   - Numbered, specific, env details
   - Include auth setup if needed
   - Target: reproducible in 5 minutes
5. **Supporting Material/References**
   - Attached scripts, screenshots
   - Related CVEs if applicable
6. **Impact Statement** (business-specific, quantified)
7. **Remediation Recommendation**

### Tone
- Professional but direct
- First person singular acceptable ("I observed...")
- Technical precision over brevity
- Include "what I tested but was NOT vulnerable" (shows thoroughness)

### CVSS Guidelines
- Compute programmatically: `python3 -c "from cvss import CVSS3; ..."`
- Include conditional table for ambiguous findings
- Never claim A:H without benchmark evidence
- Never claim PR:N without auth bypass proof

### Common Mistakes (HackerOne-specific)
- N/A report: verify scope match before submitting
- Missing weakness type (CWE) — always include
- Duplicate of disclosed report in Hacktivity
- Self-XSS or CSP-blocked XSS submitted as valid
- Over-reliance on automated scanner output without manual verification
