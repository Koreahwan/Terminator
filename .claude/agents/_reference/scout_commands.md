# Scout Commands Reference

Detailed command examples for each reconnaissance phase. Referenced from `scout.md`.

---

## Network Recon Mode

### Phase A: Domain & Subdomain Discovery + Duplicate Pre-Screen

#### A1: Duplicate Pre-Screen (MANDATORY — before ANY scanning)

```bash
# 1. Hacktivity public reports (WebFetch)
# Search: "<target> site:hackerone.com/reports" OR "<target> hacktivity"
# Capture: disclosed vuln types, dates, researchers, bounty amounts

# 2. Existing CVE full check
# Search NVD/MITRE for target's CVEs
# For OSS: check GitHub Security Advisories
gh api /repos/<owner>/<repo>/security-advisories --jq '.[].summary' 2>/dev/null

# 3. Recent security commits (OSS targets)
git log --all --oneline --grep="CVE-\|security\|fix\|patch" --since="6 months ago"
# If a CVE was recently fixed -> that exact pattern is DUPLICATE territory

# 4. Same root cause scope check
# For each known CVE: check which files were patched
# If our finding is in the SAME file with the SAME root cause -> HIGH duplicate risk
```

**Output section in `recon_notes.md`**:
```markdown
## Duplicate Risk Assessment
- Known CVEs in scope: [list with dates]
- Recently fixed security commits: [list]
- Hacktivity disclosures: [count, types]
- Duplicate Risk Level: HIGH / MEDIUM / LOW
- Safe zones: [areas NOT covered by existing CVEs]
```

#### A2: Passive Recon (NO direct contact)

```bash
# DNS records
dig ANY <domain> +noall +answer
dig <domain> MX TXT NS AAAA +short

# WHOIS
whois <domain> 2>/dev/null | head -40

# Certificate transparency (find subdomains)
curl -s "https://crt.sh/?q=%25.<domain>&output=json" | python3 -c "
import json,sys
for c in json.load(sys.stdin):
    print(c['name_value'])
" 2>/dev/null | sort -u
```

#### A3: Subdomain & URL Discovery

```bash
# Subdomain enumeration (passive, fast)
~/gopath/bin/subfinder -d <domain> -o subs.txt

# Probe live hosts from subdomain list
cat subs.txt | ~/gopath/bin/httpx -o live.txt

# URL collection from Wayback Machine + OTX + Common Crawl
echo "<domain>" | ~/gopath/bin/gau --o urls.txt
echo "<domain>" | ~/gopath/bin/waybackurls >> urls.txt
sort -u urls.txt -o urls.txt

# Parameter discovery on interesting endpoints
arjun -u https://<target>/api/endpoint
```

#### A4: Program Context (MANDATORY)

**v12.4 — use fetch-program for verbatim intake.** WebFetch+jina is banned for
scope/OOS/severity because it drops collapsed `<details>` sections, reorders
lists, and summarizes tables (Okto incident).

```bash
# 1. Fetch the program page via the deterministic per-platform handler.
python3 tools/bb_preflight.py init targets/<target>/
python3 tools/bb_preflight.py fetch-program targets/<target>/ <program_url>
# Exit 0 = PASS (verbatim sections auto-filled)
# Exit 2 = HOLD (confidence < 0.8 — review program_page_raw.md by hand)
# Exit 1 = FAIL (no handler matched — fall back to manual fill from live page)

# 2. Read the structured output:
cat targets/<target>/program_data.json    # normalized scope/OOS/severity/bounty
cat targets/<target>/program_page_raw.md  # verbatim markdown for visual review

# Captured automatically: In-scope assets + types + qualifiers, OOS verbatim,
# Known Issues, CVSS version, bounty table, submission rules.

# 3. Hacktivity analysis (still manual — hacktivity is out of fetch-program scope)
# - Count of disclosed reports (program maturity)
# - Types of vulns rewarded (what triagers accept)
# - Types of vulns rejected (what to AVOID)
# - Average time to triage
# - Top researchers active (competition level)
# WebFetch+jina is acceptable for hacktivity (no verbatim requirement).

# 4. Program policy file: check for safe harbor, testing restrictions,
#    reporting requirements (covered by fetch-program's "submission_rules").
```

#### A5: Program Rules Summary (MANDATORY)

```bash
# Verbatim sections are auto-filled by A4's fetch-program step.
# A5's job is to VERIFY them and fill OPERATIONAL sections from live traffic.

# 1. Fill OPERATIONAL sections (Auth Header Format, Mandatory Headers, Verified
#    Curl Template) by extracting from ACTUAL API traffic (Frida/mitmproxy/curl).
#    These cannot be fetched from the program page — they come from live
#    request interception.

# 2. CRITICAL: Test the auth header format
#    - Send actual API request with discovered auth format
#    - Confirm 200 response (not 401/403)
#    - Save working curl command to "Verified Curl Template" section

# 3. Verify the auto-filled VERBATIM sections match the live program page.
#    If something looks summarized/reordered, rerun fetch-program --no-cache
#    or paste from the live page by hand.

# 4. Validate completeness
python3 tools/bb_preflight.py rules-check targets/<target>/
# MUST return PASS before ANY other agent is spawned
```

#### A6: Endpoint Map Generation (MANDATORY)

```bash
# During Phase B-E recon, populate endpoint_map.md:
# For EVERY discovered endpoint:
#   | /api/path | METHOD | Auth_Required | Status | description |
# Status values: UNTESTED | TESTED | VULN | SAFE | EXCLUDED

# Verify coverage
python3 tools/bb_preflight.py coverage-check targets/<target>/
# Reports coverage % — Orchestrator checks before Phase 2
```

**Phase A Output**: `phase1_domains.json`
```json
{
  "subdomains": [],
  "live_hosts": [],
  "urls_collected": [],
  "duplicate_risk": "HIGH/MEDIUM/LOW",
  "duplicate_risk_details": {},
  "program_context_file": "program_context.md"
}
```

---

### Phase B: Port Scanning

```bash
# Fast port scan (top 1000)
nmap -sS -T4 --top-ports 1000 --min-rate 1000 <target>

# Full port scan (if time allows)
nmap -sS -p- -T4 --min-rate 2000 <target>

# Version detection on open ports
nmap -sV -sC -p <open_ports> <target>

# Alternative: RustScan (65535 ports in ~3 seconds, pipes to nmap)
rustscan -a <target>
```

**Phase B Output**: `phase2_ports.json`
```json
{
  "open_ports": [
    { "port": 80, "state": "open", "service": "http", "version": "nginx 1.18.0" }
  ],
  "interesting_ports": [],
  "total_scanned": 1000
}
```

---

### Phase C: HTTP Probing & Tech Detection

```bash
# HTTP probing + tech fingerprinting (bulk)
cat live.txt | ~/gopath/bin/httpx -tech-detect -status-code -title -o httpx_results.txt

# Web tech fingerprinting per host
curl -sI <url> | grep -iE "server|x-powered|x-aspnet|x-generator"
whatweb <url> 2>/dev/null

# WAF detection
curl -sI <url> -H "X-Scanner: test" | grep -i "cloudflare\|akamai\|incapsula\|sucuri"
```

**Phase C Output**: `phase3_http.json`
```json
{
  "live_hosts": [],
  "technologies": ["nginx", "PHP 7.4", "WordPress 5.8"],
  "waf_detected": false,
  "waf_type": null,
  "interesting_headers": [],
  "ssl_info": {}
}
```

---

### Phase D: Resource Enumeration

#### D1: Directory & Endpoint Discovery

```bash
# Directory discovery (gobuster via MCP or ffuf)
gobuster dir -u <url> -w /usr/share/wordlists/dirb/common.txt -t 20 -q

# Extended directory fuzzing
~/gopath/bin/ffuf -u https://<target>/FUZZ -w ~/SecLists/Discovery/Web-Content/common.txt -mc 200,301,302,403

# Deeper directory search
dirsearch -u https://<target> -w ~/SecLists/Discovery/Web-Content/raft-large-directories.txt

# Web crawling (follow links automatically)
~/gopath/bin/katana -u https://<target> -d 3 -silent

# Parameter discovery
arjun -u https://<target>/api/endpoint

# File upload endpoint discovery
python3 ~/fuxploider/fuxploider.py -u https://<target>/upload

# Payload references (for manual testing)
ls ~/PayloadsAllTheThings/  # 70+ vulnerability categories
```

#### D2: Secret Detection

```bash
# TruffleHog — 800+ secret types with validation
trufflehog git file://. --only-verified  # local repo, verified secrets only
trufflehog github --org=<org> --only-verified  # GitHub org scan

# trickest-cve — auto-updated CVE PoC collection (1999-2026)
ls ~/trickest-cve/2025/ ~/trickest-cve/2026/ 2>/dev/null | head -20
cat ~/trickest-cve/<year>/CVE-YYYY-NNNNN.md  # specific CVE details + PoC links
```

**Phase D Output**: `phase4_resources.json`
```json
{
  "endpoints": ["/admin", "/api/v1/", "/wp-login.php"],
  "parameters_discovered": [],
  "secrets_found": [],
  "file_upload_vulns": [],
  "crawled_urls": []
}
```

---

### Phase E: Vulnerability Scanning

```bash
# Nuclei — CVE-specific templates (fast, high signal)
nuclei -u <url> -tags cve -severity critical,high -silent -o nuclei_cve.txt
nuclei -u <url> -tags tech -silent -o nuclei_tech.txt

# Extended vuln scan (misconfigs, exposures)
nuclei -u <url> -tags misconfig,exposure -severity critical,high -silent

# Nikto scan
nikto -h <url> -Tuning 123

# XSS scan on parameterized endpoints
~/gopath/bin/dalfox url "https://<target>/search?q=test" -silence -o dalfox_xss.txt

# Secret detection (if source repo or JS files accessible)
trufflehog git file://. --only-verified 2>/dev/null | head -50
# OR for a live URL with JS:
trufflehog filesystem /tmp/js_files/ --only-verified 2>/dev/null

# SSL/TLS Analysis (if HTTPS)
openssl s_client -connect <host>:443 -servername <host> </dev/null 2>/dev/null | openssl x509 -text -noout | head -30

# Collect CVE IDs found by nuclei for Phase F
grep -oE "CVE-[0-9]{4}-[0-9]+" nuclei_cve.txt | sort -u > cve_ids_found.txt
echo "[Phase E] CVE IDs found: $(wc -l < cve_ids_found.txt)"

# AI/LLM Target Scan (if target has AI/chatbot/LLM features)
garak --model_type rest --model_name <target_api> --probes promptinject,dan,knowledgegraph 2>&1 | tee garak_results.txt
```

**Phase E Output**: `phase5_vulns.json`
```json
{
  "cves_found": ["CVE-2021-44228"],
  "misconfigs": [],
  "xss_findings": [],
  "secrets_verified": [],
  "ssl_issues": [],
  "cve_ids_file": "cve_ids_found.txt"
}
```

---

### Phase F: MITRE Enrichment + Report Assembly

#### F1: MITRE Mapping

```bash
# Enrich all found CVEs with MITRE chain (CWE -> CAPEC -> ATT&CK)
CVE_LIST=$(cat cve_ids_found.txt | tr '\n' ' ')

if [ -n "$CVE_LIST" ]; then
    python3 tools/mitre_mapper.py \
        $CVE_LIST \
        --json \
        --atlas \
        --verbose \
        > mitre_enrichment.json 2>mitre_enrichment.log

    echo "[Phase F] MITRE enrichment complete."
    python3 -c "
import json, sys
data = json.load(open('mitre_enrichment.json'))
for r in data['results']:
    cve = r['cve_id']
    score = r.get('cvss_score', 'N/A')
    cwes = [c['cwe_id'] for c in r.get('cwes', [])]
    attacks = []
    for cwe in r.get('cwes', []):
        for capec in cwe.get('capecs', []):
            for tech in capec.get('attack_techniques', []):
                attacks.append(tech['technique_id'])
    attacks = list(set(attacks))
    print(f'  {cve} (CVSS {score}): CWEs={cwes}, ATT&CK={attacks}')
"
else
    echo "[Phase F] No CVE IDs found in Phase E — skipping MITRE enrichment"
    echo '{"results": [], "note": "No CVEs found in scan"}' > mitre_enrichment.json
fi
```

**Offline fallback** (if NVD API unreachable):
```bash
python3 tools/mitre_mapper.py \
    $CVE_LIST --json --offline > mitre_enrichment.json
```

#### F2: Infrastructure Integration (Neo4j + RAG)

```bash
# Push recon results to Neo4j Attack Graph (if running)
python3 -c "
from tools.attack_graph.graph import AttackGraph
import json

g = AttackGraph('bolt://localhost:7687', 'neo4j', 'terminator')
data = json.load(open('phase6_enriched.json'))

# Ingest target
g.add_target(data.get('target', 'unknown'), program_url=data.get('program_url'), scope=data.get('scope'))

# Ingest hosts, services, vulns from recon
for host in data.get('hosts', []):
    g.add_host(host['ip'], hostname=host.get('hostname'), target_name=data.get('target'))
    for svc in host.get('services', []):
        g.add_service(host['ip'], name=svc['name'], port=svc['port'], version=svc.get('version'))
    for vuln in host.get('vulnerabilities', []):
        g.add_vulnerability(vuln['cve_id'], vuln.get('description',''), vuln.get('severity','medium'),
                          service_name=vuln.get('service'))

g.close()
print('[Phase F] Neo4j graph updated')
"

# Query RAG for known exploits
for cve in $(cat cve_ids_found.txt); do
    curl -sf -X POST http://localhost:8100/query \
        -H "Content-Type: application/json" \
        -d "{\"query\": \"$cve exploit PoC\", \"limit\": 3}" >> rag_exploit_matches.json
done
echo "[Phase F] RAG exploit lookup complete"

# Post-recon ingest
python3 tools/infra_client.py graph ingest --file recon_report.json 2>/dev/null || true
python3 tools/infra_client.py rag ingest --category "Recon" \
  --technique "Service Discovery" \
  --description "$TARGET services and attack surface" \
  --content "$(cat recon_notes.md | head -200)" 2>/dev/null || true
```

#### F3: Combined Output Assembly

```bash
# Generate combined final output
python3 -c "
import json, os

phases = {}
for i, name in [(1,'domains'),(2,'ports'),(3,'http'),(4,'resources'),(5,'vulns')]:
    fname = f'phase{i}_{name}.json'
    if os.path.exists(fname):
        with open(fname) as f:
            phases[f'phase{i}'] = json.load(f)

mitre = {}
if os.path.exists('mitre_enrichment.json'):
    with open('mitre_enrichment.json') as f:
        mitre = json.load(f)

combined = {
    'target': '<domain/ip>',
    'timestamp': '<ISO8601>',
    'pipeline_phases_completed': list(phases.keys()) + ['phase6'],
    'phases': phases,
    'mitre_enrichment': mitre
}
with open('phase6_enriched.json', 'w') as f:
    json.dump(combined, f, indent=2)
print('[Phase F] phase6_enriched.json written')
"
```

**`mitre_enrichment.json` structure**:
```json
{
  "results": [
    {
      "cve_id": "CVE-2021-44228",
      "cvss_score": 10.0,
      "cwes": [
        {
          "cwe_id": "CWE-917",
          "capecs": [
            {
              "capec_id": "CAPEC-242",
              "name": "Code Injection",
              "attack_techniques": [
                {"technique_id": "T1190", "name": "Exploit Public-Facing Application"}
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

---

## Output Format Templates

### recon_report.json (Network mode)

```json
{
  "target": "<domain/ip>",
  "timestamp": "<ISO8601>",
  "pipeline_phases_completed": ["P1","P2","P3","P4","P5","P6"],
  "dns": { "A": [], "AAAA": [], "MX": [], "TXT": [], "NS": [] },
  "subdomains": [],
  "ports": [
    { "port": 80, "state": "open", "service": "http", "version": "nginx 1.18.0" }
  ],
  "technologies": ["nginx", "PHP 7.4", "WordPress 5.8"],
  "endpoints": ["/admin", "/api/v1/", "/wp-login.php"],
  "ssl": { "issuer": "...", "expiry": "...", "grade": "..." },
  "waf_detected": false,
  "cves_found": ["CVE-2021-44228"],
  "mitre_enrichment_file": "mitre_enrichment.json",
  "phase6_enriched_file": "phase6_enriched.json",
  "potential_vectors": ["outdated WordPress", "exposed admin panel", "missing security headers"]
}
```

### recon_notes.md (Network mode)

```markdown
# Recon Notes: <target>

## Key Findings
- [HIGH] Exposed admin panel at /admin (no auth)
- [MEDIUM] Outdated nginx 1.18.0 (CVE-2021-XXXXX)
- [LOW] Missing X-Frame-Options header

## Attack Surface Summary
1-2 paragraphs: most promising attack vectors for the analyst

## Recommended Next Steps
- Priority-ordered list for the analyst agent
```

### recon_notes.md (OSS Source Code mode)

```markdown
# Source Code Recon: <target>

## Repository Overview
- Repo: <url> @ <commit/version>
- Language: TypeScript/Python/etc.
- Size: N files, M packages (monorepo? single-package?)
- Active maintainers: N (last 6 months)
- CI/CD: GitHub Actions / other

## Security Posture
- Security policy: exists/missing
- Linting rules: [list security-relevant rules]
- Dependency audit: N vulns (critical: X, high: Y)
- Recent security commits: [list CVE fixes with dates]

## Attack Surface Map
| Area | Entry Point | Interesting Because |
|------|------------|-------------------|
| API | `src/api/handler.ts` | Accepts user input, no validation |
| Serialization | `src/core/serialize.ts` | Uses devalue library, inspect inputs |
| Auth | `src/auth/token.ts` | Custom PRNG, no CSPRNG |

## Key Dependencies (Security-Relevant)
| Package | Version | Known CVEs | Notes |
|---------|---------|-----------|-------|
| devalue | 5.6.0 | CVE-2026-22774 | DoS via crafted input |

## Recommended Analysis Priorities (for analyst)
1. [HIGHEST] ...
2. [HIGH] ...
3. [MEDIUM] ...

## Program Context
- Scope: [assets list]
- Excluded: [types]
- CVSS version: 3.1 / 4.0
- Bounty range: $X-$Y
```

### recon_report.json (Smart Contract mode — extends standard)

```json
{
  "target_type": "smart_contract",
  "chain_map": {},
  "total_contracts": 0,
  "total_loc": 0,
  "proxy_type": "diamond|transparent|uups|none",
  "is_fork_of": "Angle Transmuter|null",
  "existing_audits": ["C4 2023", "Sherlock 2024"],
  "audit_fixes_applied": true,
  "scope_version": "V3",
  "scope_boundary": "Only V3 on-chain contracts. V1/V2 mimo-defi repo is OUT OF SCOPE.",
  "tvl_usd": 3000000,
  "flash_loan_available": false,
  "defi_specific": {
    "pool_type": "AMM|lending|staking",
    "oracle_type": "chainlink|custom|twap",
    "collateral_types": []
  }
}
```

---

## OSS Source Code Recon Mode

### Phase A: Repository Intelligence + Variant Analysis Seeds

```bash
# Clone and inspect
git log --oneline -30  # recent activity
git log --all --oneline --grep="security\|vuln\|fix\|CVE\|patch" | head -20  # security-related commits
git shortlog -sn --since="6 months ago"  # active maintainers

# VARIANT ANALYSIS SEEDS (Big Sleep pattern — critical for analyst)
# Extract exact diffs of security-related commits for analyst to use as seeds
for commit in $(git log --all --oneline --grep="CVE-\|security fix\|vuln" --format="%H" | head -10); do
  echo "=== $commit ==="
  git show --stat $commit | head -5
  git show $commit -- "*.ts" "*.js" "*.py" 2>/dev/null | head -50
done
# Save these diffs — analyst will use them to find unfixed variants

# Package info
cat package.json  # dependencies, scripts, versions
ls -la .github/workflows/  # CI/CD setup (security scanning?)
cat .eslintrc* biome.json 2>/dev/null  # linting rules (security rules = potential violations)
```

### Phase B: Security Configuration Audit

```bash
# What security measures exist?
cat SECURITY.md 2>/dev/null
cat CLAUDE.md 2>/dev/null  # AI-assisted projects may have security rules here
grep -r "securityLevel\|sanitize\|validate\|allowlist\|blocklist" --include="*.ts" -l src/
ls .snyk .nsprc .npmrc .vercelignore .gitignore 2>/dev/null

# Also run insecure-defaults plugin for systematic config-level vuln detection
```

### Phase C: Dependency Attack Surface

```bash
# Dependency audit
npm audit --json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'Vulns: {d.get(\"metadata\",{}).get(\"vulnerabilities\",{})}')"

# Critical deps (deserialization, crypto, network)
grep -E "devalue|serialize|crypto|jwt|oauth|fetch|axios|request" package.json

# Check specific dep versions against known CVEs
cat package-lock.json | python3 -c "
import json,sys
lock = json.load(sys.stdin)
pkgs = lock.get('packages', lock.get('dependencies', {}))
for name, info in pkgs.items():
    v = info.get('version','')
    if any(k in name for k in ['devalue','serialize','crypto','jwt','oauth']):
        print(f'{name}: {v}')
" 2>/dev/null
```

### Phase D: Architecture Mapping

```bash
# Entry points (API routes, handlers, exports)
grep -rn "export\|app\.get\|app\.post\|router\.\|handler" --include="*.ts" src/ | head -30

# Dangerous patterns (quick scan, analyst does deep dive)
grep -rn "exec\|spawn\|child_process" --include="*.ts" src/ | head -20

# Data flow: user input -> processing
grep -rn "req\.body\|req\.query\|req\.params\|process\.env\|stdin" --include="*.ts" src/ | head -20
```

---

## Smart Contract / DeFi Recon Mode

### Phase SC-A: Contract Source Fetching

```bash
# Fetch verified source from block explorer (per chain)
export PATH="$HOME/.foundry/bin:/usr/bin:$PATH"

# Ethereum
cast source <address> --chain mainnet --etherscan-api-key $ETHERSCAN_API_KEY -d contracts/eth/

# Other chains (adjust --chain and API key)
cast source <address> --chain polygon --etherscan-api-key $POLYGONSCAN_API_KEY -d contracts/polygon/
cast source <address> --chain avalanche -d contracts/avax/
cast source <address> --chain base -d contracts/base/

# If cast source fails -> try curl to explorer API directly
curl -s "https://api.etherscan.io/api?module=contract&action=getsourcecode&address=<addr>&apikey=$ETHERSCAN_API_KEY" \
  | python3 -c "import json,sys; d=json.load(sys.stdin)['result'][0]; print(d['ContractName'], len(d['SourceCode']), 'chars')"

# Count LOC per contract
find contracts/ -name "*.sol" -exec wc -l {} + | sort -n | tail -20
```

### Phase SC-B: On-Chain State Recon

```bash
# TVL & token balances
cast call <token> "totalSupply()(uint256)" --rpc-url $RPC_URL
cast call <token> "balanceOf(address)(uint256)" <pool_or_diamond> --rpc-url $RPC_URL

# Pool state (AMM targets)
cast call <pool> "getReserves()(uint112,uint112,uint32)" --rpc-url $RPC_URL 2>/dev/null
# Curve-style pools:
for i in 0 1 2; do
  cast call <pool> "balances(uint256)(uint256)" $i --rpc-url $RPC_URL 2>/dev/null
done

# Check if proxy/diamond
cast call <address> "implementation()(address)" --rpc-url $RPC_URL 2>/dev/null  # EIP-1967
cast storage <address> 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC_URL 2>/dev/null  # impl slot
cast call <address> "facets()((address,bytes4[])[])" --rpc-url $RPC_URL 2>/dev/null  # Diamond

# IMPORTANT: Immunefi-listed addresses may be IMPLEMENTATION contracts, not proxies.
# cast call facets() on implementation = REVERT. This is EXPECTED.
# For code analysis, implementation source is sufficient.
# For on-chain state queries, you need the proxy address.
```

### Phase SC-C: Automated Security Tool Scan (MANDATORY)

```bash
export PATH="$HOME/.foundry/bin:$PATH"

# 1. Slither — 100+ automated Solidity detectors
echo "[SC-C] Running Slither..."
slither . --detect reentrancy-eth,reentrancy-no-eth,arbitrary-send-eth,\
controlled-delegatecall,suicidal,unprotected-upgrade,\
incorrect-equality,unchecked-transfer,locked-ether,\
divide-before-multiply,weak-prng,tx-origin \
--json slither_results.json 2>slither_errors.log || true

# Count findings
python3 -c "
import json
try:
    data = json.load(open('slither_results.json'))
    detectors = data.get('results', {}).get('detectors', [])
    high = sum(1 for d in detectors if d.get('impact') in ['High','Medium'])
    print(f'[Slither] {len(detectors)} findings ({high} HIGH/MEDIUM)')
except: print('[Slither] Parse failed — check slither_errors.log')
" 2>/dev/null

# If Slither fails on imports:
# slither . --solc-remaps "@openzeppelin=node_modules/@openzeppelin" --json slither_results.json
# slither . --solc-remaps "@openzeppelin=lib/openzeppelin-contracts/contracts" --json slither_results.json

# 2. Mythril — EVM symbolic execution
echo "[SC-C] Running Mythril..."
find contracts/ src/ -name "*.sol" -not -path "*/interfaces/*" -not -path "*/lib/*" | head -5 | while read sol; do
    echo "  Analyzing: $sol"
    myth analyze "$sol" --execution-timeout 120 2>&1 | tee -a mythril_results.txt || true
done

# 3. Semgrep Solidity rules
echo "[SC-C] Running Semgrep..."
semgrep --config "p/solidity" contracts/ src/ --json > semgrep_sol_results.json 2>/dev/null || true
python3 -c "
import json
try:
    data = json.load(open('semgrep_sol_results.json'))
    results = data.get('results', [])
    print(f'[Semgrep] {len(results)} findings')
except: print('[Semgrep] No results')
" 2>/dev/null

# 4. Package results for analyst
mkdir -p tool_scan_results/
cp slither_results.json mythril_results.txt semgrep_sol_results.json tool_scan_results/ 2>/dev/null || true
echo "[SC-C] Tool scan complete. Results in tool_scan_results/"
```

### Phase SC-D: Audit History Discovery

```bash
# 1. Check if protocol is a FORK of a known protocol
grep -r "authorized fork\|forked from\|based on\|adapted from" contracts/ --include="*.sol" | head -10
# Common forks: Angle Transmuter, Aave, Compound, Uniswap, Curve, MakerDAO

# 2. If fork detected -> find original protocol's audits
# Search: "<original protocol> audit report C4 Sherlock OpenZeppelin"
# Key audit platforms: Code4rena (C4), Sherlock, OpenZeppelin, Trail of Bits, Spearbit

# 3. Check if ALL audit findings are fixed in fork
# Clone original repo -> find security commits -> verify patches exist in fork
git clone <original_repo> /tmp/original_check
cd /tmp/original_check
git log --oneline --grep="fix\|security\|audit\|C4\|H-\|M-" | head -20
# For each security commit: git show <hash> -- "*.sol" | head -50
# Then verify same fix exists in target fork

# 4. If all fixes applied -> target is CLEAN (low finding probability)
# If some fixes missing -> VARIANT ANALYSIS opportunity (high value!)
```

### Phase SC-E: Multi-Chain Address Mapping

```bash
# Immunefi programs often deploy across multiple chains
# Fetch Immunefi program page to get FULL address list per chain
# Map: chain -> addresses -> contract names -> LOC

# Output structure:
python3 -c "
import json
chain_map = {
    'ethereum': [{'address': '0x...', 'name': 'Swapper', 'loc': 647}],
    'polygon':  [{'address': '0x...', 'name': 'Redeemer', 'loc': 238}],
}
print(json.dumps(chain_map, indent=2))
" > chain_address_map.json
```

### Phase SC-F: Scope Boundary Verification (MANDATORY)

```bash
# CRITICAL: Verify which VERSION is in scope
# Parallel Protocol had V1/V2 (mimo-defi) and V3 (parallelizer) — only V3 was in scope
# Analyst wasted 100% of time on V1/V2 code = ALL findings OOS

# Checklist:
# 1. Read Immunefi program page -> exact assets + versions in scope
# 2. If GitHub repo has multiple versions -> identify which is in Immunefi scope
# 3. If contracts fetched from Etherscan -> verify they match scope version
# 4. Document scope boundaries in recon_notes.md:
#    "IN SCOPE: V3 contracts (Solidity 0.8.28) deployed at [addresses]"
#    "OUT OF SCOPE: V1/V2 (mimo-defi repo), admin functions, known C4 findings"
```

---

## Gemini CLI (Token-Saving Large Codebase Scan)

When the target codebase is large (5K+ lines), use Gemini for rapid first-pass scanning:

```bash
# Summarize all source files in a directory (bulk overview)
./tools/gemini_query.sh summarize-dir ./src "*.ts" > /tmp/codebase_summary.md

# Quick vulnerability triage on key files
./tools/gemini_query.sh triage src/auth/handler.ts > /tmp/triage_auth.md

# Summarize a large single file before detailed analysis
./tools/gemini_query.sh summarize src/core/crypto.ts > /tmp/crypto_summary.md
```

**Rules**:
- Gemini results are candidates only — verify with source reading before including in recon_notes.md
- Default model: `gemini-3-pro-preview` (fixed)
- Use for files > 500 lines. For small files, read directly
- If Gemini CLI fails, proceed without it (optional, not blocking)

---

## Knowledge Graph Enhancement (Phase A: Duplicate Pre-Screen)

```bash
# Use graphrag-security MCP for enhanced duplicate checking
# mcp__graphrag-security__exploit_lookup — with discovered service/version
# mcp__graphrag-security__similar_findings — check past program analysis
```

---

## All Available Tools (full list)

- **Network**: nmap (via pentest MCP or sudo), netcat, socat, curl, wget
- **Web**: gobuster (via pentest MCP), nikto (via pentest MCP), curl, whatweb
- **Web Recon (Go tools at ~/gopath/bin/)**: ffuf, subfinder, katana, httpx, dalfox, gau, waybackurls, interactsh-client
- **Web Recon (Python)**: arjun, dirsearch
- **Web Crawling**: crawl4ai (Playwright-based JS rendering + Markdown, stealth mode)
- **Scanning**: nuclei (v3.7.0, ~/nuclei-templates/ — 12K+ templates), trufflehog (v3.93.3, secret detection)
- **AI/LLM Security**: garak (v0.14.0 — LLM vulnerability scanner)
- **File Upload**: fuxploider (`python3 ~/fuxploider/fuxploider.py`)
- **DNS**: dig, nslookup, host
- **SSL**: openssl s_client, curl --cert-status
- **GitHub**: gh CLI (PRs, issues, API, repo analysis)
- **Port Scanning**: RustScan (`rustscan -a <target>` — 65535 ports in ~3 seconds)
- **Subdomain**: amass (`~/gopath/bin/amass enum -d <domain>` — 40+ sources), subfinder
- **Web OSINT**: web-check (Docker, 33 checks, port 3001)
- **Typosquatting**: dnstwist (`dnstwist <domain>` — 100+ domain permutations)
- **Username OSINT**: sherlock (`sherlock <username>` — 400+ sites)
- **Workflow**: osmedeus (YAML recon pipeline engine)
- **Reference**: ExploitDB (~/exploitdb), PoC-in-GitHub (~/PoC-in-GitHub), PayloadsAllTheThings, trickest-cve
- **Smart Contract**: Foundry (cast/forge/anvil), Slither, Mythril, Semgrep (Solidity rules)
