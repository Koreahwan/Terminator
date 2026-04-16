# Attack Chain Plan: example.com
Generated: 2026-02-17 10:21:36

## Executive Summary
- Target: `example.com`
- CVEs identified: None from nuclei (manual scan required)
- ATT&CK techniques mapped: 10
- CRITICAL/CRITICAL+ items: 3

## Prioritized Exploit Plan

### Priority 1: [CRITICAL+] Pre-Auth RCE Chain
**ATT&CK**: `T1190+T1059` — Pre-Auth RCE Chain (chained techniques)
**TYPE**: CHAINED TECHNIQUE — highest value target
**Approach**: HIGHEST VALUE: Combine public-facing exploit with command execution — document full chain
**Tools**: `searchsploit`, `nuclei`, `commix`
**Payload Refs**: `~/PayloadsAllTheThings/Command Injection`, `~/PayloadsAllTheThings/File Inclusion`

### Priority 2: [CRITICAL] Command Injection
**ATT&CK**: `T1059` — Command and Scripting Interpreter
**Source CVEs**: CVE-2021-44228
**CAPEC**: CAPEC-242, CAPEC-586
**Approach**: Test injection points with safe payloads (id, whoami) → use commix for automation
**Tools**: `commix`, `curl`, `burpsuite`
**Payload Refs**: `~/PayloadsAllTheThings/Command Injection`

### Priority 3: [CRITICAL] Remote Code Execution / Auth Bypass
**ATT&CK**: `T1190` — Exploit Public-Facing Application
**Source CVEs**: CVE-2021-44228
**CAPEC**: CAPEC-242, CAPEC-10
**Approach**: Search for public PoC → adapt to target → verify pre-auth → capture evidence
**Tools**: `nuclei`, `searchsploit`, `curl`, `SSRFmap`
**Payload Refs**: `~/PayloadsAllTheThings/File Inclusion`, `~/PayloadsAllTheThings/SSRF`

### Priority 4: [HIGH] Client-Side Exploitation
**ATT&CK**: `T1203` — Exploitation for Client Execution
**Source CVEs**: CVE-2021-44228
**CAPEC**: CAPEC-586, CAPEC-10
**Approach**: Memory corruption → ROP chain or ret2libc → shell/flag
**Tools**: `gdb`, `pwntools`, `ROPgadget`

### Priority 5: [HIGH] XSS / JavaScript Injection
**ATT&CK**: `T1059.007` — Command and Scripting Interpreter: JavaScript
**Source CVEs**: CVE-2021-44228
**CAPEC**: CAPEC-198
**Approach**: dalfox automated scan → manual context-aware bypass → stored vs reflected
**Tools**: `dalfox`, `burpsuite`, `curl`
**Payload Refs**: `~/PayloadsAllTheThings/XSS Injection`

### Priority 6: [HIGH] Data Manipulation
**ATT&CK**: `T1565` — Data Manipulation
**Source CVEs**: CVE-2021-44228
**CAPEC**: CAPEC-153
**Approach**: SQLi → data modification → business logic manipulation → integrity violation proof
**Tools**: `curl`, `burpsuite`, `sqlmap`
**Payload Refs**: `~/PayloadsAllTheThings/SQL Injection`

### Priority 7: [MEDIUM] Drive-by Compromise
**ATT&CK**: `T1189` — Drive-by Compromise
**Source CVEs**: CVE-2021-44228
**CAPEC**: CAPEC-198
**Approach**: Stored XSS → malicious payload delivery → demonstrate cross-user impact
**Tools**: `dalfox`, `burpsuite`
**Payload Refs**: `~/PayloadsAllTheThings/XSS Injection`

### Priority 8: [MEDIUM] Obfuscated Files / Filter Bypass
**ATT&CK**: `T1027` — Obfuscated Files or Information
**Source CVEs**: CVE-2021-44228
**CAPEC**: CAPEC-3
**Approach**: Test encoding bypasses (double URL encode, null byte, extension manipulation)
**Tools**: `curl`, `burpsuite`
**Payload Refs**: `~/PayloadsAllTheThings/File Upload`

### Priority 9: [LOW] Phishing / Social Engineering
**ATT&CK**: `T1566.001` — Phishing: Spearphishing Attachment
**Source CVEs**: CVE-2021-44228
**CAPEC**: CAPEC-41
**Approach**: Phishing usually out-of-scope for bug bounty. Skip unless program explicitly includes.

### Priority 10: [LOW] Denial of Service
**ATT&CK**: `T1499` — Endpoint Denial of Service
**Source CVEs**: CVE-2021-44228, CVE-2023-44487
**CAPEC**: CAPEC-469
**Approach**: DoS usually out-of-scope. Verify program includes DoS before testing.
**Tools**: `curl`, `python3`

## Search Commands (run these first)

```bash
# ExploitDB search for each CVE

# PoC-in-GitHub search

# trickest-cve search

# Nuclei CVE-specific templates
```

## Handoff to Exploiter

Confidence score each finding with:
```bash
python3 tools/confidence_scorer.py --input vulnerability_candidates.json --mitre mitre_enrichment.json
```

Only pass findings with confidence score >= 5 to exploiter.