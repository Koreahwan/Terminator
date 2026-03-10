# Analyst Patterns Reference

Detailed grep/regex patterns, source-sink traces, CWE mappings, and analysis techniques per mode.
Referenced from `.claude/agents/analyst.md` — mode-specific focus sections.

---

## Injection Patterns

### Command Injection (CWE-78)
```bash
# Dynamic code execution constructors
grep -rn "Function(" --include="*.ts" --include="*.js" src/
# Shell execution APIs
grep -rn "child_process\|execFile\|execSync\|spawn" --include="*.ts" --include="*.js" src/
# Python shell APIs
grep -rn "os\.system\|subprocess\|os\.popen\|commands\." --include="*.py" src/
```

### SQL Injection (CWE-89)
```bash
# String concatenation in queries
grep -rn "SELECT.*+\|INSERT.*+\|UPDATE.*+\|DELETE.*+" --include="*.ts" --include="*.js" --include="*.py" src/
# Template literals with user input
grep -rn '`SELECT.*\$\{' --include="*.ts" --include="*.js" src/
# Python format strings
grep -rn "f\"SELECT\|\.format.*SELECT\|%.*SELECT" --include="*.py" src/
```

### Code Injection (CWE-94, CWE-95)
```bash
# Unsafe deserialization
grep -rn "JSON.parse\|devalue\|serialize\|unserialize\|yaml\.load\b" --include="*.ts" --include="*.js" --include="*.py" src/
# Template injection (SSTI)
grep -rn "render_template_string\|Jinja2\|nunjucks\|handlebars\.compile" --include="*.py" --include="*.js" src/
# Dynamic require/import
grep -rn "require(\s*[^'\"]" --include="*.js" --include="*.ts" src/
# Python unsafe deserialization (see CWE-502 in CWE table below)
```

### Source-to-Sink Trace (Injection)
```
Source: req.body, req.query, req.params, req.headers, process.argv, stdin
  -> Intermediate: variable assignment, function parameter passing
  -> Sink: code execution function, db.query(), render()
Check: Is there parameterization, escaping, or allowlist validation between source and sink?
```

---

## SSRF Patterns

### URL Manipulation (CWE-918)
```bash
# Fetch/request with user input
grep -rn "fetch\|axios\|request\|http\.get\|urllib\|requests\.get" --include="*.ts" --include="*.js" --include="*.py" src/ | grep -v test
# URL construction from input
grep -rn "url\s*=\s*\|href\s*=\s*\|endpoint\s*=\s*" --include="*.ts" --include="*.js" src/ | grep -v test
# Download/redirect functions
grep -rn "download\|redirect\|proxy\|forward" --include="*.ts" --include="*.js" src/
```

### Open Redirect (CWE-601)
```bash
grep -rn "redirect\|location\s*=\|window\.location\|res\.redirect" --include="*.ts" --include="*.js" src/
# Check: is the redirect target validated against an allowlist?
```

### Internal Network Access Checks
```
Key targets: 169.254.169.254 (cloud metadata), 127.0.0.1, 10.x.x.x, 172.16-31.x.x, 192.168.x.x
Bypass patterns: DNS rebinding, URL encoding, IPv6 (::1), octal notation (0177.0.0.1)
Check: Is there an IP/hostname blocklist? Can it be bypassed?
```

---

## Auth Patterns

### Missing Authentication (CWE-306)
```bash
# Find all route/endpoint definitions
grep -rn "app\.get\|app\.post\|app\.put\|app\.delete\|@app\.route\|router\." --include="*.ts" --include="*.js" --include="*.py" src/
# Compare: which routes have auth middleware? Which don't?
grep -rn "authenticate\|isAuthenticated\|requireAuth\|@login_required\|authMiddleware" --include="*.ts" --include="*.js" --include="*.py" src/
# Identify gaps: endpoints without auth decorators/middleware
```

### Broken Access Control (CWE-862)
```bash
# IDOR indicators -- user ID from request used in DB query
grep -rn "req\.params\.id\|req\.query\.id\|userId.*req\." --include="*.ts" --include="*.js" src/
# Check: does it compare req.user.id with the requested resource's owner?
# Missing comparison = IDOR
```

### Token/Session Weakness (CWE-287)
```bash
# JWT without verification
grep -rn "jwt\.decode\|verify.*false\|algorithms.*none" --include="*.ts" --include="*.js" --include="*.py" src/
# Session fixation
grep -rn "session\.regenerate\|session\.destroy" --include="*.ts" --include="*.js" src/
# Check: is session regenerated after login?
```

---

## Crypto Patterns

### Weak PRNG (CWE-330)
```bash
grep -rn "Math\.random\|random\.random\|srand\|mt_rand" --include="*.ts" --include="*.js" --include="*.py" --include="*.php" src/
# Check: used for security-sensitive purposes (tokens, nonces, keys)?
# Secure alternatives: crypto.randomBytes, secrets.token_hex, /dev/urandom
```

### Hardcoded Secrets (CWE-798)
```bash
grep -rn "secret\|token\|password\|api.key\|private.key\|API_KEY\s*=" --include="*.ts" --include="*.js" --include="*.py" src/ | grep -v test
# TruffleHog for comprehensive scan:
trufflehog git file://. --only-verified --json 2>/dev/null | head -20
```

### Weak Hashing (CWE-327)
```bash
grep -rn "md5\|sha1\|MD5\|SHA1\|createHash.*md5\|createHash.*sha1" --include="*.ts" --include="*.js" --include="*.py" src/
# Check: used for authentication (password hashing) or integrity (file checksums)?
# Auth use = vulnerability. Integrity use = lower severity.
# Missing HMAC verification:
grep -rn "createHmac\|hmac\." --include="*.ts" --include="*.js" src/
```

---

## Business Logic Patterns

### Race Conditions (CWE-362)
```bash
# TOCTOU patterns -- check then act without locking
grep -rn "if.*exists.*\n.*delete\|if.*balance.*\n.*transfer\|check.*then.*update" --include="*.ts" --include="*.js" --include="*.py" src/
# Database operations without transactions
grep -rn "findOne.*update\|SELECT.*UPDATE\|read.*write" --include="*.ts" --include="*.js" src/
# Missing mutex/lock on financial operations
grep -rn "transfer\|withdraw\|deposit\|mint\|burn" --include="*.ts" --include="*.js" --include="*.sol" src/ | grep -v lock
```

### Payment/Coupon Abuse (CWE-840)
```bash
# Negative value inputs
grep -rn "amount\|quantity\|price\|discount" --include="*.ts" --include="*.js" src/
# Check: are negative values validated? Can bet = -100 cause credit?
# Integer overflow/underflow
grep -rn "parseInt\|Number\(\|parseFloat" --include="*.ts" --include="*.js" src/
# Check: is result checked for NaN, Infinity, or overflow?
```

### Workflow Bypass
```
1. Map all multi-step workflows (signup, checkout, approval)
2. Can steps be skipped? (jump from step 1 to step 3 via direct API call)
3. Can steps be reordered? (submit payment before validation)
4. What happens on partial failure? (rollback or inconsistent state?)
5. Time-of-check/time-of-use gaps in approval workflows?
```

---

## File Upload Patterns

### Unrestricted Upload (CWE-434)
```bash
# File upload handlers
grep -rn "multer\|formidable\|busboy\|FileUpload\|@UploadedFile\|request\.files" --include="*.ts" --include="*.js" --include="*.py" src/
# Extension validation
grep -rn "\.endsWith\|\.extension\|mimetype\|content-type\|fileFilter" --include="*.ts" --include="*.js" src/
# Check: server-side validation? Or only client-side?
# Bypass: double extensions (.php.jpg), null bytes (.php%00.jpg), content-type mismatch
```

### Path Traversal in Filenames (CWE-22)
```bash
grep -rn "path\.join\|path\.resolve\|filename.*req\.\|originalname" --include="*.ts" --include="*.js" src/
# Check: is filename sanitized? Can "../../../etc/passwd" be used?
# Key: does the path stay within the upload directory after resolution?
```

### Upload-to-Execute Chain
```
1. Can you upload a file with executable content? (.php, .jsp, .aspx, .py)
2. Is the file stored in a web-accessible directory?
3. Can you access the uploaded file directly via URL?
4. Is the web server configured to run the file type?
All 4 = RCE via file upload.
```

---

## CWE Mapping Reference

### Critical (RCE potential)
| CWE | Name | Detection Pattern |
|-----|------|-------------------|
| 78 | OS Command Injection | shell functions with user input |
| 89 | SQL Injection | String concat in SQL queries |
| 94 | Code Injection | dynamic code invocation with user input |
| 502 | Deserialization of Untrusted Data | Python: `pickle/shelve/marshal.loads`. JS: unserialize. PHP: unserialize |
| 434 | Unrestricted File Upload | Upload without server-side type validation |

### High (Auth bypass / Data leak)
| CWE | Name | Detection Pattern |
|-----|------|-------------------|
| 306 | Missing Authentication | Endpoints without auth middleware |
| 862 | Missing Authorization | IDOR -- no ownership check |
| 918 | SSRF | User-controlled URLs in fetch/request |
| 287 | Improper Authentication | JWT none algorithm, weak tokens |
| 22 | Path Traversal | User input in file paths without sanitization |

### Medium
| CWE | Name | Detection Pattern |
|-----|------|-------------------|
| 330 | Insufficient Randomness | Math.random for security purposes |
| 327 | Broken Crypto | MD5/SHA1 for passwords |
| 798 | Hardcoded Credentials | Secrets in source code |
| 362 | Race Condition | TOCTOU without locking |
| 601 | Open Redirect | Unvalidated redirect targets |

---

## Source-to-Sink Tracing Methodology (3-Pass)

### Pass 1: Identify Sinks
Find dangerous function calls (dynamic code invocation, query, fetch, redirect, write). Record file:line for each.

### Pass 2: Trace Callers
For each sink, trace backward: "What function calls this? Where does the argument come from?" Read the calling file. Record the data flow chain.

### Pass 3: Reach Source
Continue tracing until you reach either:
- **User-controlled input** (req.body, req.query, URL params, headers, stdin) = CONFIRMED source
- **Server-controlled constant** (config, env var, hardcoded) = NOT user-controlled, drop
- **Validation/sanitization** = PARTIALLY safe, document what bypass might work

### Pass N (if needed): Cross-File Traces
For complex codebases, continue beyond 3 passes through middleware, utility functions, and shared modules until the complete chain is mapped.

### Documentation Format
```
SOURCE: req.body.url (user input, POST /api/fetch)
  -> controllers/fetch.ts:45 -- fetchUrl(req.body.url)
  -> services/http.ts:23 -- axios.get(url)  [NO validation]
SINK: axios.get() with user-controlled URL
VERDICT: SSRF (CWE-918), Confidence 8/10
```

---

## DeFi-Specific Patterns

### Oracle Manipulation
```bash
grep -rn "latestRoundData\|latestAnswer\|getRoundData" --include="*.sol" contracts/
# CHECK EACH ORACLE CALL FOR:
# 1. answeredInRound >= roundId (stale price protection)
# 2. answer > 0 (zero/negative price)
# 3. updatedAt + heartbeat > block.timestamp (staleness window)
# 4. Deviation tolerance between oracle and spot price
# 5. Multi-oracle fallback

# TWAP manipulation:
grep -rn "observe\|consult\|getTimeWeightedAverage" --include="*.sol" contracts/
# TWAP window < 30 minutes = manipulable via flash loan

# Custom oracle patterns:
grep -rn "updateOracle\|setOracle\|oracleConfig" --include="*.sol" contracts/
```

### Flash Loan Attack Patterns
```bash
# Missing reentrancy protection
grep -rn "nonReentrant\|ReentrancyGuard\|_status" --include="*.sol" contracts/
# Missing nonReentrant on value-modifying functions = flash loan vector

# Same-block manipulation:
grep -rn "block\.number\|block\.timestamp" --include="*.sol" contracts/
# No same-block check = flash loan attack possible
```

### Fee/Rounding Exploitation
```bash
# Rounding differences
grep -rn "mulDiv\|Math\.Rounding\|Ceil\|Floor\|roundUp\|roundDown" --include="*.sol" contracts/
# Check: mint rounds UP but burn rounds DOWN? (defensive rounding -- check consistency)

# Division precision loss
grep -rn "/ BASE\|/ 1e\|/ 10\*\*" --include="*.sol" contracts/
# Division BEFORE multiplication = precision loss (divide-before-multiply)

# Normalizer/scaling patterns
grep -rn "normalizer\|normalizedStables\|BASE_27\|BASE_18" --include="*.sol" contracts/
```

### Access Control & Admin Patterns
```bash
# Admin-only functions (usually OOS for Immunefi)
grep -rn "onlyOwner\|onlyAdmin\|restricted\|onlyGovernor\|onlyGuardian" --include="*.sol" contracts/
# Focus: permissionless functions that interact with admin-set state

# Intermediate roles (may have weaker protection)
grep -rn "isTrusted\|isWhitelisted\|isKeeper\|isOperator" --include="*.sol" contracts/
```

### Cross-Collateral Contamination
```bash
# Multi-collateral systems:
grep -rn "collateralList\|for.*collateral\|getCollateralRatio" --include="*.sol" contracts/
# Pattern: getBurnOracle() takes MIN across ALL collaterals
# One bad collateral contaminates the whole system's burn price
```

---

## Variant Analysis Detailed Methodology (Big Sleep Pattern)

### Step-by-Step
```bash
# 1. Find security-related git commits
git log --all --oneline --grep="CVE-\|security\|vuln\|fix\|patch" -- "*.ts" "*.js" "*.py"

# 2. Get the exact diff of each security fix (this is the "seed")
git show <commit_hash> -- <file>

# 3. Analyze the diff -- what was the root cause? What was the fix?
# - Missing validation -> added check
# - Unsafe function -> changed to safe alternative
# - Missing auth -> added middleware

# 4. Search for the SAME unfixed pattern elsewhere
grep -rn "<vulnerable_pattern>" --include="*.ts" src/ | grep -v "<fixed_pattern>"

# 5. Check if fix was COMPLETE
# - Was only one call site fixed? Are there others?
# - Was fix applied to all branches/versions?
```

### Output Format per Variant
```
- Original CVE: CVE-YYYY-NNNNN
- Original fix: `file.ts:line` -- what changed
- Variant location: `other_file.ts:line` -- same pattern, NOT fixed
- Confidence: HIGH (exact same pattern) / MEDIUM (similar) / LOW (related logic)
```

---

## Project Policy Violation Detection

```bash
# 1. Read project's own security rules
cat CLAUDE.md SECURITY.md .eslintrc* biome.json tsconfig.json 2>/dev/null
# Look for: "Never use X", "Always sanitize Y", banned functions

# 2. Search for violations of their own rules
# Example: project says "Never use JSON.parse" -> grep for JSON.parse usage
grep -rn "JSON.parse" --include="*.ts" --include="*.js" src/

# 3. After finding violation, create Semgrep rule to scan entire codebase
# Use Skill("semgrep-rule-creator:semgrep-rule-creator") for custom rules
```

**Why highest value**: A project violating its OWN rules is the strongest evidence for a triager. It proves the vendor acknowledges the risk.
