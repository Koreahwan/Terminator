# External Knowledge Repositories

> Cloned reference repositories available for agent use.
> Last updated: 2026-02-24

## Exploit & Vulnerability Databases

| Repo | Path | Usage | Command |
|------|------|-------|---------|
| **ExploitDB** | `~/exploitdb/` | 47K+ exploits, searchable by service/version | `~/exploitdb/searchsploit <query>` |
| **PoC-in-GitHub** | `~/PoC-in-GitHub/` | 8K+ GitHub PoCs indexed by CVE year | `ls ~/PoC-in-GitHub/<year>/CVE-*.json` |
| **trickest-cve** | `~/trickest-cve/` | 154K+ CVE PoCs and references | `find ~/trickest-cve/ -name "CVE-<year>-*"` |
| **nuclei-templates** | `~/nuclei-templates/` | 12K+ vulnerability detection templates | `nuclei -t ~/nuclei-templates/ -u <target>` |

## Payloads & Techniques

| Repo | Path | Usage | Key Dirs |
|------|------|-------|----------|
| **PayloadsAllTheThings** | `~/PayloadsAllTheThings/` | 70+ vuln categories, payloads & bypasses | `SQL Injection/`, `XSS Injection/`, `Command Injection/`, `Server Side Request Forgery/` |
| **collisions** | `~/collisions/` | MD5/SHA-1 collision techniques (corkami) | `examples/`, `scripts/`, `hashquines/` |
| **SSRFmap** | `~/SSRFmap/` | 18+ SSRF exploitation modules | `python3 ~/SSRFmap/ssrfmap.py` |
| **commix** | `~/commix/` | Command injection exploitation | `python3 ~/commix/commix.py` |
| **fuxploider** | `~/fuxploider/` | File upload vulnerability exploitation | `python3 ~/fuxploider/fuxploider.py` |

## Security Tools (Installed)

| Tool | Path | Version | Usage |
|------|------|---------|-------|
| **CodeQL** | `~/tools/codeql/` | Latest | Semantic taint tracking, variant analysis |
| **Foundry** | `~/.foundry/bin/` | 1.5.1 | forge/cast/anvil/chisel for smart contracts |
| **pwndbg** | `~/pwndbg/` | 2026.02.18 | GDB plugin with decomp2dbg 3.14.1 |
| **GEF** | `~/gef/gef.py` | Latest | GDB plugin (93 commands) |
| **Slither** | pipx | Latest | 100+ Solidity detectors |
| **Mythril** | pipx | Latest | EVM symbolic execution |
| **crawl4ai** | pipx | Latest | Playwright-based web crawling |

## Protocol & Smart Contract References

| Repo | Path | Coverage |
|------|------|----------|
| **protocol-vulns-index** | `knowledge/protocol-vulns-index/` | 460 vulnerability categories × 31 protocol types |
| **Protocol JSON data** | `knowledge/protocol-vulns-index/data/findings/protocols/` | 34 protocol type JSON files |

## AI & Research Tools

| Tool | Path | Usage |
|------|------|-------|
| **Gemini CLI** | `tools/gemini_query.sh` | gemini-3-pro-preview, modes: reverse/analyze/triage/summarize/protocol/bizlogic |
| **GraphRAG MCP** | `tools/mcp-servers/graphrag-mcp/` | Security knowledge graph with auto-injection |

## CTF Knowledge Bases

| Repo | Path | Coverage |
|------|------|----------|
| **MBE (Modern Binary Exploitation)** | `~/tools/MBE/` | RPISEC course: stack/heap/format/ROP/kernel labs |
| **HEVD** | `~/tools/HEVD/` | HackSys Extreme Vulnerable Driver: 16 Windows kernel vuln types |
| **google-ctf** | `~/tools/google-ctf/` | Google CTF challenges (2017-2025): web, crypto, pwn, reversing |
| **exploit-writeups** | `~/tools/exploit-writeups/` | Cryptogenic: PS4/FreeBSD kernel exploit chains, kASLR bypass |
| **CTF-All-In-One** | `~/tools/CTF-All-In-One/` | Chinese CTF comprehensive guide: heap/stack/crypto/web techniques |
| **how2heap** | `~/tools/how2heap/` | Shellphish: House-of-* heap exploitation examples by glibc version |
| **linux-kernel-exploitation** | `~/tools/linux-kernel-exploitation/` | Kernel exploit catalog: CVEs, techniques, container escapes |

## Security Research References

| Repo | Path | Coverage |
|------|------|----------|
| **awesome-list-systems** | `~/tools/awesome-list-systems/` | Systems security research: UEFI, MTE, EDR bypass, hypervisor |
| **paper_collection** | `~/tools/paper_collection/` | 200+ security research papers indexed by category |
| **owasp-mastg** | `~/tools/owasp-mastg/` | OWASP Mobile Application Security Testing Guide: Android/iOS |
| **ad-exploitation** | `~/tools/ad-exploitation/` | Active Directory: ADCS, Kerberoasting, BloodHound, delegation |

## Competitor Analysis

| Repo | Path | Purpose |
|------|------|---------|
| **cai** | `~/tools/cai-analysis/` | aliasrobotics CAI: Cybersecurity AI agent framework reference |
| **shannon** | `~/tools/shannon-analysis/` | Keygraph Shannon: parallel vulnerability hunting agent reference |

## Recently Added (2026-02-24)

| Repo | Path | Description |
|------|------|-------------|
| HackTricks | `~/tools/hacktricks/` | Comprehensive pentesting wiki (gitbook, ~1,500 md) |
| GTFOBins | `~/tools/GTFOBins/` | Unix binaries for privilege escalation (~400 binaries) |
| exploitdb-papers | `~/tools/exploitdb-papers/` | ExploitDB research papers |
| nuclei-templates-ai | `~/tools/nuclei-templates-ai/` | AI-enhanced nuclei detection templates |
| google-ctf-writeups | `~/tools/google-ctf-writeups/` | Third-party Google CTF writeups |
| fuzzdb | `~/tools/fuzzdb/` | Attack patterns and fuzzing payloads |
| IntruderPayloads | `~/tools/IntruderPayloads/` | Burp Suite Intruder payloads |
| awesome-ctf | `~/tools/awesome-ctf/` | CTF resources curated list |
| awesome-ctf-resources | `~/tools/awesome-ctf-resources/` | CTF resources and tools |
| Awesome-CTF | `~/tools/Awesome-CTF/` | CTF resources (Chinese) |
| CVE-PoC-in-GitHub-v2 | `~/tools/CVE-PoC-in-GitHub-v2/` | Extended CVE PoC collection |

## Additional Security Tools (Batch Install 2026-02-24)

| Tool | Path/Command | Version | Purpose | Agent |
|------|-------------|---------|---------|-------|
| **rp++** | `~/tools/rp++` | Latest | ARM64 ROP gadget finder (C++ compiled, fast) | chain |
| **RustScan** | `rustscan` | 2.3.0 | 65535-port scan in 3 seconds, nmap pipe | scout |
| **linux-exploit-suggester** | `~/tools/linux-exploit-suggester.sh` | Latest | Kernel version → privesc CVE suggestions | chain, exploiter |
| **dnstwist** | `dnstwist` | 20250130 | Domain typosquatting detection (100+ permutations) | scout |
| **sherlock** | `sherlock` | 0.16.0 | Username OSINT across 400+ sites | scout |
| **routersploit** | `~/tools/routersploit` | Latest | Router/IoT exploit framework (default creds, known CVEs) | exploiter |
| **RSACTFTool** | `~/tools/rsactftool` | Latest | RSA weak key attacks (Wiener, Boneh-Durfee, Fermat) | solver |
| **amass** | `~/gopath/bin/amass` | v4 | OWASP subdomain enumeration (40+ data sources) | scout |
| **osmedeus** | `~/gopath/bin/osmedeus` | Latest | YAML-based recon workflow engine | scout |
| **web-check** | `~/tools/web-check` (Docker) | Latest | 33 REST API checks (DNS/SSL/tech/mail), port 3001 | scout |
| **Apktool** | `apktool` | 2.11.1 | Android APK decompilation (smali, resources) | reverser |
| **ImHex** | `imhex` | 1.37.4 | Binary pattern language + YARA integration | reverser |

## How Agents Should Use These

### For CTF (reverser/chain/solver):
1. `searchsploit <service> <version>` — known exploits
2. `~/PayloadsAllTheThings/<category>/` — payload references
3. `~/collisions/` — crypto challenge collision techniques

### For Bug Bounty (scout/analyst):
1. `searchsploit` + `~/PoC-in-GitHub/` — duplicate pre-screen
2. `nuclei -t ~/nuclei-templates/` — automated scanning
3. `~/PayloadsAllTheThings/` — payload crafting
4. `~/SSRFmap/`, `~/commix/`, `~/fuxploider/` — specialized exploitation

### For Smart Contract (analyst/exploiter):
1. `knowledge/protocol-vulns-index/` — known vulnerability patterns
2. `slither .` + `myth analyze` — automated analysis
3. `forge test --fork-url` — on-chain state verification
