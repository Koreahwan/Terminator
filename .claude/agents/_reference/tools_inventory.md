# Security Tools Inventory

Comprehensive tool reference for scout and analyst agents.
Referenced from `.claude/agents/analyst.md` and `.claude/agents/scout.md`.

---

## Static Analysis

### Semgrep (Multi-language)
**Purpose**: First-pass automated vulnerability scanning. Cross-file analysis with 2000+ rules.

```bash
# Auto-detect language and rules (FIRST step in any OSS analysis)
semgrep --config auto src/ --json > semgrep_results.json

# Solidity-specific rules (DeFi targets)
semgrep --config "p/solidity" contracts/ --json > semgrep_results.json 2>/dev/null || true

# Custom rule for project-specific patterns
# Use Skill("semgrep-rule-creator:semgrep-rule-creator") to create

# Parse JSON output
python3 -c "
import json
with open('semgrep_results.json') as f:
    data = json.load(f)
for r in data.get('results', []):
    severity = r.get('extra', {}).get('severity', '?')
    rule = r.get('check_id', '?').split('.')[-1]
    file = r.get('path', '?')
    line = r.get('start', {}).get('line', '?')
    msg = r.get('extra', {}).get('message', '')[:80]
    print(f'[{severity}] {rule} — {file}:{line} — {msg}')
"
```

**Key rule packs**: `p/security-audit`, `p/owasp-top-ten`, `p/solidity`, `p/python`, `p/javascript`

### CodeQL (Deep Taint Tracking)
**Purpose**: Interprocedural, cross-file data flow analysis. Finds what grep and Semgrep miss.

```bash
# 1. Create database (once per target)
~/tools/codeql/codeql database create /tmp/codeql-db \
  --language=javascript \
  --source-root=./src \
  --overwrite 2>&1 | tail -5

# For other languages:
# --language=python | --language=go | --language=rust | --language=java

# 2. Run security query suite
~/tools/codeql/codeql database analyze /tmp/codeql-db \
  ~/tools/codeql/qlpacks/codeql/javascript-queries/*/Security/ \
  --format=sarif-latest \
  --output=/tmp/codeql-results.sarif 2>&1 | tail -5

# 3. Parse SARIF results
python3 -c "
import json
with open('/tmp/codeql-results.sarif') as f:
    sarif = json.load(f)
for run in sarif.get('runs', []):
    for result in run.get('results', []):
        rule = result.get('ruleId', '?')
        msg = result.get('message', {}).get('text', '')[:100]
        locs = result.get('locations', [{}])
        if locs:
            loc = locs[0].get('physicalLocation', {})
            file = loc.get('artifactLocation', {}).get('uri', '?')
            line = loc.get('region', {}).get('startLine', '?')
            print(f'[{rule}] {file}:{line} — {msg}')
"
```

**Key queries**: `js/sql-injection`, `js/code-injection`, `js/ssrf`, `js/prototype-polluting-assignment`, `js/unsafe-deserialization`, `js/missing-token-validation`

**When**: ALWAYS for OSS targets with >3K lines.

### Slither (Solidity Static Analysis)
**Purpose**: 100+ detectors for Solidity smart contracts. MANDATORY for DeFi targets.

```bash
# HIGH PRIORITY detectors (most likely real bugs):
slither . --detect reentrancy-eth,reentrancy-no-eth,arbitrary-send-eth,\
controlled-delegatecall,suicidal,unprotected-upgrade,\
incorrect-equality,unchecked-transfer,locked-ether,\
divide-before-multiply,weak-prng,tx-origin 2>&1 | tee slither_high.txt

# MEDIUM PRIORITY (informational, useful for attack chains):
slither . --detect shadowing-local,uninitialized-state,\
missing-zero-check,calls-loop,reentrancy-events 2>&1 | tee slither_medium.txt

# If imports fail:
slither . --solc-remaps "@openzeppelin=node_modules/@openzeppelin"

# On failure: report error to Orchestrator, fall back to Semgrep Solidity rules
```

### Mythril (EVM Symbolic Execution)
**Purpose**: EVM-level path exploration. Finds logic bugs Slither misses.

```bash
# Basic analysis (5-minute timeout)
myth analyze contracts/Target.sol --execution-timeout 300 2>&1 | tee mythril_results.txt

# For complex contracts (longer timeout):
myth analyze contracts/Target.sol --execution-timeout 600 --transaction-count 5

# Output: SWC IDs (SWC-101 = integer overflow, SWC-107 = reentrancy, etc.)
```

---

## Vulnerability Databases

### searchsploit (ExploitDB — 47K+ exploits)
```bash
# Primary search — service + version
~/exploitdb/searchsploit <service> <version>

# Broader search if specific version returns nothing
~/exploitdb/searchsploit <service>

# JSON output for parsing
~/exploitdb/searchsploit --json <service> <version>

# View exploit details
~/exploitdb/searchsploit -p <EDB-ID>
```

### PoC-in-GitHub (8K+ GitHub PoCs)
```bash
# Search by year + keyword
ls ~/PoC-in-GitHub/2024/ ~/PoC-in-GitHub/2025/ 2>/dev/null | grep -i <keyword>

# Read PoC details
cat ~/PoC-in-GitHub/<year>/CVE-YYYY-NNNNN.json
```

### trickest-cve (154K+ CVE files, auto-updated)
```bash
# Search recent years
ls ~/trickest-cve/2025/ ~/trickest-cve/2026/ 2>/dev/null | grep -i <keyword>

# Read CVE details + PoC links
cat ~/trickest-cve/<year>/CVE-YYYY-NNNNN.md
```

### Nuclei Templates (12K+ detection templates)
```bash
# Find template for specific CVE
grep -rl "<CVE-ID>" ~/nuclei-templates/ 2>/dev/null

# Run specific template against target
nuclei -t ~/nuclei-templates/http/cves/<year>/CVE-YYYY-NNNNN.yaml -u <target>

# Run all CVE templates for a year
nuclei -t ~/nuclei-templates/http/cves/2025/ -u <target>
```

### PayloadsAllTheThings (70+ vuln categories)
```bash
# Get payloads for specific vuln type
cat ~/PayloadsAllTheThings/"<Vuln Type>"/README.md | head -100
# Categories: SQL Injection, XSS, SSRF, Command Injection, Directory Traversal, etc.
```

---

## Knowledge Search (MCP + CLI)

### knowledge-fts MCP (265K+ documents)
```
# Load MCP tools first
ToolSearch("knowledge-fts")

# Search techniques
technique_search("<vulnerability type>", category="<field>")

# Search exploits (ExploitDB + nuclei + PoC combined)
exploit_search("<service version>")

# Search past CTF writeups
challenge_search("<similar challenge>")

# Full-text search across everything
search_all("<query>")

# Get specific document content
get_technique_content("<path>")
```

**NEVER use `cat knowledge/techniques/*.md`** — wastes 27-40K tokens. Always use MCP search.

### GraphRAG Security MCP
```
# Check if similar vuln was already found/rejected
mcp__graphrag-security__similar_findings

# CVE/product exploit search
mcp__graphrag-security__exploit_lookup

# Cross-corpus pattern analysis
mcp__graphrag-security__knowledge_global
```

---

## AI-Assisted Analysis

### Gemini CLI
**Location**: `./tools/gemini_query.sh`
**Model**: `gemini-3-pro-preview` (fixed, do not change)

| Mode | Purpose | When to Use |
|------|---------|-------------|
| `triage` | P1/P2/P3 vulnerability classification | Per-file first pass (files >1K lines) |
| `solidity` | DeFi-specific triage | Solidity projects (reentrancy, flash loan, oracle) |
| `summarize-dir` | Security-focused directory overview | Codebases >5K lines |
| `summarize` | Single file summary | Large decompiled output (>500 lines) |
| `analyze` | Full vulnerability analysis | Concatenated key files |
| `protocol` | Protocol/state machine analysis | Auth flows, message ordering, crypto protocols |
| `bizlogic` | Business logic flaw detection | Financial logic, access control, workflow bypass |
| `review` | Code review for PoC quality | PoC code verification |
| `ask` | Specific questions with file context | Targeted inquiries |

```bash
# Quick triage
./tools/gemini_query.sh triage src/auth/handler.ts > /tmp/triage_auth.md

# DeFi-specific
./tools/gemini_query.sh solidity contracts/Vault.sol > /tmp/triage_vault.md

# Bulk directory summary
./tools/gemini_query.sh summarize-dir ./src "*.ts" > /tmp/codebase_summary.md

# Deep protocol analysis
./tools/gemini_query.sh protocol src/auth/oauth.ts > /tmp/protocol_analysis.md

# Business logic
./tools/gemini_query.sh bizlogic src/api/transfer.ts > /tmp/bizlogic_analysis.md

# Targeted question
./tools/gemini_query.sh ask "Can attacker bypass rate limiting via X-Forwarded-For?" src/middleware/ratelimit.ts
```

**Mandatory triggers**:
| Condition | Gemini Command | Reason |
|-----------|---------------|--------|
| Codebase 5K+ lines | `summarize-dir` + `triage` | 50%+ token savings vs reading all files |
| Solidity project | `solidity` mode | DeFi-specific triage |
| Single file 1K+ lines | `triage` | Filter to P1/P2 only |

**Workflow**: Gemini triage (all files) -> Gemini protocol/bizlogic (P1/P2 files) -> Claude manual verification (Vulnhuntr 3-pass)

**Rules**: Gemini results are candidates only — always verify with source-to-sink tracing. Do NOT trust severity ratings blindly. If Gemini CLI fails, proceed with Semgrep + manual scanning.

---

## Reconnaissance Tools

### Nmap
```bash
# Quick service version detection
nmap -sV -sC -T4 <target> -oA nmap_results

# Full port scan
nmap -p- -T4 <target> -oA nmap_full

# UDP scan (top 100)
nmap -sU --top-ports 100 <target> -oA nmap_udp

# Script scan for specific vulns
nmap --script vuln <target> -oA nmap_vuln
```

### ffuf (Web Fuzzing)
```bash
# Directory bruteforce
ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Parameter fuzzing
ffuf -u https://<target>/api?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Subdomain enumeration
ffuf -u https://FUZZ.<domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fc 301,302
```

### Nuclei (Automated Scanning)
```bash
# Full scan with all templates
nuclei -u <target> -o nuclei_results.txt

# Specific severity
nuclei -u <target> -severity critical,high -o nuclei_critical.txt

# Rate limited (respect target)
nuclei -u <target> -rate-limit 10 -o nuclei_results.txt
```

---

## Web3 / DeFi Tools

### Foundry (forge/cast/anvil)
**Path**: `/home/rootk1m/.foundry/bin/`

```bash
export PATH="/home/rootk1m/.foundry/bin:$PATH"

# On-chain state verification
cast call <token_address> "totalSupply()(uint256)" --rpc-url $RPC_URL
cast call <pool_address> "balances(uint256)(uint256)" 0 --rpc-url $RPC_URL

# Check config parameters (MANDATORY for DeFi — Kiln lesson)
cast call <vault_addr> "decimalsOffset()(uint8)" --rpc-url $RPC_URL
cast call <pool_addr> "fee()(uint256)" --rpc-url $RPC_URL

# Fork testing
forge test --fork-url $RPC_URL -vvv

# Local fork for interactive testing
anvil --fork-url $RPC_URL --fork-block-number <block>
```

**Critical rule**: If vulnerability depends on a config parameter (offset, fee, oracle address), verify with `cast call` that it's actually active in production. All inactive = "latent bug" = severity downgrade.

---

## Exploitation Support

### sqlmap
```bash
# Basic test
sqlmap -u "https://<target>/api?id=1" --batch --level 3 --risk 2

# With authentication
sqlmap -u "https://<target>/api?id=1" --cookie="session=<value>" --batch

# POST request
sqlmap -u "https://<target>/api" --data="param=value" --batch
```

### TruffleHog (Secret Scanning)
```bash
# Git repo scan (verified secrets only)
trufflehog git file://. --only-verified --json 2>/dev/null | head -20

# Filesystem scan
trufflehog filesystem . --only-verified --json 2>/dev/null | head -20
```

### Dependency Auditing
```bash
# Node.js
npm audit 2>/dev/null

# Python
pip audit 2>/dev/null

# Rust
cargo audit 2>&1 | grep -E "RUSTSEC|warning|Vulnerability"
```

---

## Infrastructure Integration

### MITRE Mapper
```bash
# Map CVEs to ATT&CK techniques (with ATLAS for AI targets)
python3 /home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/tools/mitre_mapper.py \
    <CVE-IDs> --json --atlas 2>/dev/null
```

### RAG API (Past Knowledge)
```bash
# Search for similar past vulnerabilities
python3 tools/infra_client.py rag query "$SERVICE $VERSION vulnerability" --limit 5 2>/dev/null || true

# Check past findings on same target (duplicate prevention)
python3 tools/infra_client.py db search-findings "$TARGET" 2>/dev/null || true

# Check past failure patterns
python3 tools/infra_client.py db check-failures "$VULN_TYPE" 2>/dev/null || true
```

### Neo4j Attack Graph
```bash
python3 -c "
from tools.attack_graph.graph import AttackGraph
g = AttackGraph('bolt://localhost:7687', 'neo4j', 'terminator')
results = g.get_critical_vulns()
for r in results: print(dict(r))
g.close()
" 2>/dev/null
```

---

## Plugin Skills Reference

Available via `Skill()` tool. Use plugins BEFORE manual grep when possible.

| Skill | Purpose | When to Use |
|-------|---------|-------------|
| `static-analysis:semgrep` | Automated Semgrep scan | FIRST step in OSS analysis |
| `static-analysis:codeql` | CodeQL taint tracking | After Semgrep, for >3K line targets |
| `static-analysis:sarif-parsing` | Parse SARIF results | After CodeQL/Semgrep runs |
| `semgrep-rule-creator` | Custom Semgrep rules | After finding policy violations |
| `variant-analysis` | CVE variant hunting | After identifying security git commits |
| `insecure-defaults` | Hardcoded creds, weak defaults | During dangerous pattern detection |
| `sharp-edges` | Dangerous API detection | After initial scan |
| `audit-context-building` | Architectural context | Large codebases (10K+ lines) |
| `differential-review` | Git diff security analysis | Analyzing recent commits |
| `sentry-skills:find-bugs` | AI-powered bug detection | Supplementary to Semgrep |

### Recommended Plugin Workflow (OSS Bug Bounty)
```
1. Skill("audit-context-building")      -> architectural context
2. Skill("static-analysis:semgrep")     -> automated vuln scan
3. Skill("insecure-defaults")           -> config-level vulns
4. Skill("sharp-edges")                 -> dangerous API patterns
5. Manual Step A (policy violations)     -> project-specific rules
6. Skill("semgrep-rule-creator")        -> custom rules for Step A findings
7. Skill("variant-analysis")            -> CVE variant hunting
8. Manual Steps C-E                      -> dependency + bundle strategy
```

---

## Token-Saving Web Research

```bash
# USE THIS for HTML-heavy pages (80% token savings)
curl -s "https://markdown.new/<target_url>" | head -500

# Example:
curl -s "https://markdown.new/nvd.nist.gov/vuln/detail/CVE-2025-14847"

# Fallback to WebFetch only if markdown.new fails or times out
# Always use r.jina.ai prefix for WebFetch:
# WebFetch(url="https://r.jina.ai/https://example.com/page")
```
