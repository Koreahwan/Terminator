# Vendor Direct Report Style Guide

## Characteristics
- **Channel**: security@vendor.com, vendor PSIRT portal, or bug bounty email
- **Format**: Varies widely — no standard template
- **Triage**: Often non-security engineers first see it
- **Risk**: May be ignored, may result in legal threats, may take months
- **Advantage**: No platform middleman, direct communication

## Preferred Format

### Title (Email Subject)
- Pattern: `Security Vulnerability Report: [Product] [VulnType]`
- Keep it clear for non-security readers

### Structure (Vendor-optimized order)
1. **Opening** (identify yourself as security researcher, state good faith)
2. **Executive Summary** (3 sentences: what, impact, urgency)
3. **Affected Product/Version** (exact)
4. **Technical Description**
   - Root cause explanation accessible to developers (not just security)
   - Avoid jargon overload — vendor engineers may not know CWE numbers
5. **Reproduction Steps** (VERY detailed — assume zero security tooling)
   - Standard tools only (curl, browser, Python stdlib)
   - Screenshots for every step if possible
6. **Impact** (business terms: "customer data at risk", "service disruption")
7. **Suggested Fix** (concrete code change if possible)
8. **Disclosure Timeline** (state your intended timeline, typically 90 days)
9. **Contact Information**

### Tone
- Collaborative, not adversarial
- "I'd like to help you fix this" not "your product is broken"
- Business impact language over technical severity
- Patient — vendors may take weeks to respond

### Vendor-Specific Considerations

#### VMware (Broadcom)
- Portal: security@vmware.com or Broadcom bug bounty
- Expects detailed VMX/VMDK context for VM escape findings
- Include hypervisor version + build number
- Reference: VMWARE-D5P0EHPB (serial port arbitrary file write)

#### General PSIRT
- Use CVSS 3.1 vector (universal standard)
- Offer to sign NDA if requested
- Keep PoC minimal — don't send weaponized exploits
- Follow up at 30/60/90 day intervals

### Common Mistakes (Vendor Direct)
- Aggressive/threatening tone (triggers legal, not security)
- Sending to general support instead of security team
- No disclosure timeline stated
- Weaponized exploit in first email
- Not keeping records of communication
