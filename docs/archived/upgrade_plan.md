# Terminator Framework Upgrade Plan — Single-Session Execution

> Generated: 2026-02-24
> Architecture Review: Oracle (architect agent)
> Estimated Total Time: ~90-120 minutes
> Disk Required: ~8GB (175GB available)
> Python: 3.12 (compatibility issues noted per tool)

---

## Table of Contents

1. [Pre-Flight Checks](#batch-0-pre-flight-checks-2-min)
2. [Batch 1: Binary Tools (Parallel)](#batch-1-binary-tools--parallel-downloads-5-min)
3. [Batch 2: Python/Pipx Tools (Parallel)](#batch-2-pythonpipx-tools-parallel-10-min)
4. [Batch 3: Build-from-Source Tools (Sequential)](#batch-3-build-from-source-tools-sequential-15-min)
5. [Batch 4: Docker/Go Tools (Parallel)](#batch-4-dockergo-tools-parallel-10-min)
6. [Batch 5: P1 Knowledge Repos (Parallel Clones)](#batch-5-p1-knowledge-repos-parallel-clones-5-min)
7. [Batch 6: P2 Knowledge Repos (Parallel Clones)](#batch-6-p2-knowledge-repos-parallel-clones-5-min)
8. [Batch 7: Competitor Analysis Repos](#batch-7-competitor-analysis-repos-parallel-3-min)
9. [Batch 8: Verification Gate](#batch-8-verification-gate-5-min)
10. [Batch 9: Knowledge Technique Documents](#batch-9-knowledge-technique-documents-generation-20-min)
11. [Batch 10: Agent Prompt Updates](#batch-10-agent-prompt-updates-15-min)
12. [Batch 11: CLAUDE.md & external_repos.md Updates](#batch-11-claudemd--external_reposmd-updates-10-min)
13. [Batch 12: Final Verification](#batch-12-final-verification-5-min)
14. [Rollback Instructions](#rollback-instructions)
15. [Known Issues & Workarounds](#known-issues--workarounds)

---

## Batch 0: Pre-Flight Checks (2 min)

**Purpose**: Verify environment before any changes. Abort if blockers found.

```bash
# 0.1 Disk space (need 8GB free minimum)
df -h /home/rootk1m | awk 'NR==2{print "Available:", $4}'
# ABORT IF: Available < 8GB

# 0.2 Required package managers
cargo --version   # need 1.70+
pip --version     # need 24+
pipx --version    # need 1.0+
docker --version  # need 20+
go version        # need 1.21+
java --version 2>&1 | head -1  # need for Apktool

# 0.3 Required build tools
dpkg -l | grep -E "build-essential|cmake|libcapstone-dev" | awk '{print $2, $3}'
# NOTE: libcapstone-dev needed for ropium — install if missing

# 0.4 Create workspace
mkdir -p ~/tools/downloads
mkdir -p /home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/knowledge/techniques

# 0.5 Snapshot current state (for rollback)
ls ~/tools/ > /tmp/tools_before_upgrade.txt
pip list --format=freeze > /tmp/pip_before_upgrade.txt
pipx list --json > /tmp/pipx_before_upgrade.json 2>/dev/null || true
```

**Pre-requisite installs (if missing)**:
```bash
# Only run if pre-flight shows these missing
sudo apt-get update && sudo apt-get install -y \
    build-essential cmake libcapstone-dev \
    default-jre \
    whois dnsutils
```

---

## Batch 1: Binary Tools — Parallel Downloads (5 min)

**Items**: rp++ (#3), RustScan (#2), linux-exploit-suggester (#14)
**These are independent downloads — run ALL in parallel.**

### 1A: rp++ v2.1.5 (chain agent — ARM64 ROP gadgets)
```bash
# Download and install
cd ~/tools/downloads
wget -q "https://github.com/0vercl0k/rp/releases/download/v2.1.5/rp-lin-gcc.zip" -O rp-lin-gcc.zip
unzip -o rp-lin-gcc.zip -d ~/tools/
chmod +x ~/tools/rp-lin-gcc
ln -sf ~/tools/rp-lin-gcc ~/tools/rp++

# Verify
~/tools/rp++ --version 2>&1 | head -1
# EXPECT: rp++ version info
# ROLLBACK: rm ~/tools/rp++ ~/tools/rp-lin-gcc ~/tools/downloads/rp-lin-gcc.zip
```

### 1B: RustScan v2.4.1 (scout agent — 65535 port scan)
```bash
# Download .deb package (pre-built, no cargo build needed — saves 10+ min)
cd ~/tools/downloads
wget -q "https://github.com/RustScan/RustScan/releases/download/2.4.1/rustscan.deb.zip" -O rustscan.deb.zip
unzip -o rustscan.deb.zip
# The .deb file may be nested inside the zip
find . -name "*.deb" -newer rustscan.deb.zip | head -1 | xargs sudo dpkg -i

# Verify
rustscan --version 2>&1
# EXPECT: RustScan 2.4.1
# FALLBACK (if .deb fails): cargo install rustscan  # ~8 min compile
# ROLLBACK: sudo dpkg -r rustscan
```

**IMPORTANT**: If the .deb zip structure is unexpected (nested dirs), inspect with:
```bash
unzip -l rustscan.deb.zip  # list contents first
```

### 1C: linux-exploit-suggester (chain/exploiter agent — kernel privesc)
```bash
# Single script download
wget -q "https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh" \
    -O ~/tools/linux-exploit-suggester.sh
chmod +x ~/tools/linux-exploit-suggester.sh

# Verify
head -3 ~/tools/linux-exploit-suggester.sh
# EXPECT: #!/bin/bash header
# ROLLBACK: rm ~/tools/linux-exploit-suggester.sh
```

---

## Batch 2: Python/Pipx Tools (Parallel, 10 min)

**Items**: Ciphey (#1), sherlock (#18), dnstwist (#17), routersploit (#15)
**Run all pipx installs in parallel.**

### 2A: Ciphey (solver agent — auto cipher/encoding detection)

**WARNING**: Ciphey has a known dependency issue with Python 3.12 (`absl-py` fails).
**Two approaches — try A1 first, fall back to A2:**

```bash
# A1: Try pipx install (creates isolated venv — may resolve dep issues)
pipx install ciphey 2>&1 | tee /tmp/ciphey_install.log

# Verify
ciphey --help 2>&1 | head -3
# EXPECT: Usage info

# A2: FALLBACK — Docker wrapper (if pipx fails)
if ! command -v ciphey &>/dev/null; then
    echo "Ciphey pipx failed. Creating Docker wrapper..."
    docker pull remnux/ciphey:latest 2>/dev/null || \
    docker build -t ciphey-local - << 'DOCKERFILE'
FROM python:3.10-slim
RUN pip install ciphey
ENTRYPOINT ["ciphey"]
DOCKERFILE

    # Create wrapper script
    cat > ~/tools/ciphey << 'WRAPPER'
#!/bin/bash
docker run --rm -i ciphey-local "$@"
WRAPPER
    chmod +x ~/tools/ciphey
    echo "Ciphey installed via Docker wrapper at ~/tools/ciphey"
fi

# A3: LAST RESORT — Use Ares (Ciphey v2, Rust rewrite, Python 3.12 compatible)
# Only if both A1 and A2 fail
# pip install ares-decoder --break-system-packages
# OR: cargo install ares (if Rust crate exists)
# GitHub: https://github.com/bee-san/Ares (846 stars, actively maintained)

# ROLLBACK: pipx uninstall ciphey || rm ~/tools/ciphey
```

### 2B: sherlock (scout agent — username OSINT)
```bash
pipx install sherlock-project

# Verify
sherlock --version 2>&1 | head -1
# EXPECT: Version info
# ROLLBACK: pipx uninstall sherlock-project
```

### 2C: dnstwist (scout agent — typosquatting detection)
```bash
pipx install dnstwist

# Verify
dnstwist --version 2>&1 | head -1
# EXPECT: Version info
# ROLLBACK: pipx uninstall dnstwist
```

### 2D: routersploit (exploiter agent — embedded device exploitation)
```bash
# routersploit needs Python + specific deps — use pipx with venv
pipx install routersploit 2>&1 | tee /tmp/rsploit_install.log

# FALLBACK if pipx fails (common with older packages):
if ! command -v rsf &>/dev/null && ! command -v routersploit &>/dev/null; then
    echo "pipx failed, cloning manually..."
    git clone --depth=1 https://github.com/threat9/routersploit ~/tools/routersploit
    cd ~/tools/routersploit
    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt 2>&1 | tail -3
    # Create wrapper
    cat > ~/tools/rsf << 'WRAPPER'
#!/bin/bash
cd ~/tools/routersploit && .venv/bin/python3 rsf.py "$@"
WRAPPER
    chmod +x ~/tools/rsf
fi

# Verify
~/tools/rsf --help 2>&1 | head -3 || rsf --help 2>&1 | head -3
# ROLLBACK: pipx uninstall routersploit || rm -rf ~/tools/routersploit ~/tools/rsf
```

---

## Batch 3: Build-from-Source Tools (Sequential, 15 min)

**Items**: ropium (#12)
**Sequential because it requires make and may conflict with parallel builds.**

### 3A: ropium (chain agent — semantic ROP chain builder)

**PRE-REQUISITE**: libcapstone-dev must be installed (checked in Batch 0).

```bash
# Check pre-req
dpkg -l | grep libcapstone-dev || sudo apt-get install -y libcapstone-dev

# Clone and build
git clone --depth=1 https://github.com/Boyan-MILANOV/ropium ~/tools/ropium-src
cd ~/tools/ropium-src

# Build (C++ project with Makefile)
make -j$(nproc) 2>&1 | tail -5

# Test
make test 2>&1 | tail -5

# Install system-wide
sudo make install 2>&1 | tail -3

# Verify Python import works
python3 -c "from ropium import *; print('ropium OK: ARCH.X64 =', ARCH.X64)" 2>&1
# EXPECT: ropium OK: ARCH.X64 = ...

# FALLBACK: If make fails, try Docker
# docker run --rm -v $(pwd):/work -w /work python:3.10 bash -c "pip install prompt_toolkit && cd /work && make && make install"

# ROLLBACK: sudo make uninstall (if Makefile supports) || sudo rm /usr/local/lib/python*/dist-packages/ropium*
```

**IMPORTANT — Python compatibility test**:
```bash
# ropium uses a C extension — verify it loads in system Python
python3 -c "import ropium; rop = ropium.ROPium(ropium.ARCH.X64); print('ROPium initialized')" 2>&1
# If ImportError: Python version mismatch → rebuild with correct Python headers
# sudo apt-get install python3-dev && make clean && make -j$(nproc)
```

---

## Batch 4: Docker/Go Tools (Parallel, 10 min)

**Items**: web-check (#4), vuls (#5), Apktool (#13), amass (#16)
**Independent installs — run in parallel.**

### 4A: web-check (scout agent — 33 REST API recon endpoints)
```bash
# Docker install (recommended by project)
docker pull lissy93/web-check:latest 2>&1 | tail -3

# Create wrapper script
cat > ~/tools/web-check << 'WRAPPER'
#!/bin/bash
# Usage: web-check <url>
# Runs web-check API server on port 3100, queries it, then stops
CONTAINER_NAME="web-check-$$"
docker run -d --rm --name "$CONTAINER_NAME" -p 3100:3000 lissy93/web-check:latest > /dev/null 2>&1
sleep 3  # wait for startup
if [ -n "$1" ]; then
    curl -s "http://localhost:3100/api/$1" 2>/dev/null
fi
echo ""
echo "web-check API running at http://localhost:3100"
echo "Stop with: docker stop $CONTAINER_NAME"
WRAPPER
chmod +x ~/tools/web-check

# Verify
docker run --rm lissy93/web-check:latest node -e "console.log('web-check OK')" 2>&1
# EXPECT: web-check OK
# ROLLBACK: docker rmi lissy93/web-check:latest; rm ~/tools/web-check
```

**USER CONFIRMATION NEEDED**: web-check Docker image is ~500MB. Confirm disk budget is acceptable.

### 4B: vuls (scout agent — OS/package CVE enumeration)
```bash
# Go install
GOPATH=~/gopath go install github.com/future-architect/vuls/cmd/vuls@latest 2>&1 | tail -3

# Verify
~/gopath/bin/vuls --version 2>&1 | head -1 || echo "vuls not in gopath/bin — check GOPATH"
# EXPECT: vuls version info

# FALLBACK: Docker
# docker pull vuls/vuls:latest
# ROLLBACK: rm ~/gopath/bin/vuls
```

### 4C: Apktool v3.0.1 (reverser agent — Android RE)
```bash
# Download jar
mkdir -p ~/tools/apktool
wget -q "https://github.com/iBotPeaches/Apktool/releases/download/v3.0.1/apktool_3.0.1.jar" \
    -O ~/tools/apktool/apktool.jar

# Create wrapper script
cat > ~/tools/apktool << 'WRAPPER'
#!/bin/bash
java -jar ~/tools/apktool/apktool.jar "$@"
WRAPPER
chmod +x ~/tools/apktool

# Verify
~/tools/apktool --version 2>&1 | head -1
# EXPECT: 3.0.1
# ROLLBACK: rm -rf ~/tools/apktool
```

**PRE-REQUISITE**: Java Runtime (JRE 11+). Check with `java --version`.

### 4D: amass (scout agent — OWASP subdomain enumeration)
```bash
# Go install (v4)
GOPATH=~/gopath go install -v github.com/owasp-amass/amass/v4/...@master 2>&1 | tail -5

# Verify
~/gopath/bin/amass --version 2>&1 | head -1 || ~/gopath/bin/amass version 2>&1 | head -1
# EXPECT: amass version info
# ROLLBACK: rm ~/gopath/bin/amass*
```

---

## Batch 5: P1 Knowledge Repos (Parallel Clones, 5 min)

**Items**: RPISEC/MBE (#6), HEVD (#7), google-ctf (#8), Cryptogenic/Exploit-Writeups (#9)
**All independent git clones — run in parallel with `&`.**

```bash
# All clones in parallel — use --depth=1 and --filter=blob:none for large repos
(
git clone --depth=1 https://github.com/RPISEC/MBE ~/tools/MBE 2>&1 | tail -1 && echo "[OK] MBE" &
git clone --depth=1 https://github.com/hacksysteam/HackSysExtremeVulnerableDriver ~/tools/HEVD 2>&1 | tail -1 && echo "[OK] HEVD" &
git clone --depth=1 --filter=blob:none https://github.com/google/google-ctf ~/tools/google-ctf 2>&1 | tail -1 && echo "[OK] google-ctf" &
git clone --depth=1 https://github.com/Cryptogenic/Exploit-Writeups ~/tools/exploit-writeups 2>&1 | tail -1 && echo "[OK] exploit-writeups" &
wait
)
echo "Batch 5 complete"
```

**Verify**:
```bash
ls -d ~/tools/MBE ~/tools/HEVD ~/tools/google-ctf ~/tools/exploit-writeups
# EXPECT: All 4 directories exist
# SIZE CHECK:
du -sh ~/tools/MBE ~/tools/HEVD ~/tools/google-ctf ~/tools/exploit-writeups
```

**ROLLBACK**: `rm -rf ~/tools/MBE ~/tools/HEVD ~/tools/google-ctf ~/tools/exploit-writeups`

---

## Batch 6: P2 Knowledge Repos (Parallel Clones, 5 min)

**Items**: CTF-All-In-One (#19), awesome-ctf (#20), linux-kernel-exploitation (#21),
0xor0ne/awesome-list (#22), paper_collection (#23), OWASP/mastg (#24), AD Cheat Sheet (#25)

```bash
(
git clone --depth=1 https://github.com/firmianay/CTF-All-In-One ~/tools/CTF-All-In-One 2>&1 | tail -1 && echo "[OK] CTF-All-In-One" &
git clone --depth=1 https://github.com/apsdehal/awesome-ctf ~/tools/awesome-ctf 2>&1 | tail -1 && echo "[OK] awesome-ctf" &
git clone --depth=1 https://github.com/xairy/linux-kernel-exploitation ~/tools/linux-kernel-exploitation 2>&1 | tail -1 && echo "[OK] linux-kernel-exploitation" &
git clone --depth=1 https://github.com/0xor0ne/awesome-list ~/tools/awesome-list-systems 2>&1 | tail -1 && echo "[OK] awesome-list-systems" &
git clone --depth=1 https://github.com/0xricksanchez/paper_collection ~/tools/paper_collection 2>&1 | tail -1 && echo "[OK] paper_collection" &
git clone --depth=1 --filter=blob:none https://github.com/OWASP/owasp-mastg ~/tools/owasp-mastg 2>&1 | tail -1 && echo "[OK] owasp-mastg" &
git clone --depth=1 https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet ~/tools/ad-exploitation 2>&1 | tail -1 && echo "[OK] ad-exploitation" &
wait
)
echo "Batch 6 complete"
```

**Verify**:
```bash
ls -d ~/tools/CTF-All-In-One ~/tools/awesome-ctf ~/tools/linux-kernel-exploitation \
    ~/tools/awesome-list-systems ~/tools/paper_collection ~/tools/owasp-mastg ~/tools/ad-exploitation
du -sh ~/tools/CTF-All-In-One ~/tools/awesome-ctf ~/tools/linux-kernel-exploitation \
    ~/tools/awesome-list-systems ~/tools/paper_collection ~/tools/owasp-mastg ~/tools/ad-exploitation
```

**ROLLBACK**: `rm -rf ~/tools/CTF-All-In-One ~/tools/awesome-ctf ~/tools/linux-kernel-exploitation ~/tools/awesome-list-systems ~/tools/paper_collection ~/tools/owasp-mastg ~/tools/ad-exploitation`

---

## Batch 7: Competitor Analysis Repos (Parallel, 3 min)

**Items**: CAI (#10), Shannon (#11)

```bash
(
git clone --depth=1 https://github.com/aliasrobotics/cai ~/tools/cai-analysis 2>&1 | tail -1 && echo "[OK] CAI" &
git clone --depth=1 https://github.com/KeygraphHQ/shannon ~/tools/shannon-analysis 2>&1 | tail -1 && echo "[OK] Shannon" &
wait
)
echo "Batch 7 complete"
```

**Verify**:
```bash
ls -d ~/tools/cai-analysis ~/tools/shannon-analysis
```

**ROLLBACK**: `rm -rf ~/tools/cai-analysis ~/tools/shannon-analysis`

---

## Batch 8: Verification Gate (5 min)

**MANDATORY CHECKPOINT. Do NOT proceed to Batch 9+ if any tool failed.**

```bash
echo "=== TOOL VERIFICATION ==="
echo "--- P1 Tools ---"
~/tools/rp++ --version 2>&1 | head -1 || echo "[FAIL] rp++"
rustscan --version 2>&1 | head -1 || echo "[FAIL] RustScan"
(ciphey --help 2>&1 | head -1) || (~/tools/ciphey --help 2>&1 | head -1) || echo "[FAIL] Ciphey"
(python3 -c "from ropium import *; print('ropium OK')" 2>&1) || echo "[FAIL] ropium"
docker images lissy93/web-check --format "{{.Tag}}" 2>&1 | head -1 || echo "[FAIL] web-check"
(~/gopath/bin/vuls version 2>&1 | head -1) || echo "[FAIL] vuls"

echo ""
echo "--- P2 Tools ---"
(~/gopath/bin/amass version 2>&1 | head -1) || echo "[FAIL] amass"
(dnstwist --version 2>&1 | head -1) || echo "[FAIL] dnstwist"
(sherlock --version 2>&1 | head -1) || echo "[FAIL] sherlock"
(~/tools/apktool --version 2>&1 | head -1) || echo "[FAIL] Apktool"
head -1 ~/tools/linux-exploit-suggester.sh 2>&1 || echo "[FAIL] linux-exploit-suggester"
(~/tools/rsf --help 2>&1 | head -1) || (rsf --help 2>&1 | head -1) || echo "[FAIL] routersploit"

echo ""
echo "--- P1 Knowledge Repos ---"
for repo in MBE HEVD google-ctf exploit-writeups; do
    test -d ~/tools/$repo && echo "[OK] $repo" || echo "[FAIL] $repo"
done

echo ""
echo "--- P2 Knowledge Repos ---"
for repo in CTF-All-In-One awesome-ctf linux-kernel-exploitation \
            awesome-list-systems paper_collection owasp-mastg ad-exploitation; do
    test -d ~/tools/$repo && echo "[OK] $repo" || echo "[FAIL] $repo"
done

echo ""
echo "--- Competitor Repos ---"
for repo in cai-analysis shannon-analysis; do
    test -d ~/tools/$repo && echo "[OK] $repo" || echo "[FAIL] $repo"
done

echo ""
echo "=== GATE RESULT ==="
FAIL_COUNT=$(echo "rp++ rustscan ciphey ropium" | tr ' ' '\n' | while read t; do
    case $t in
        rp++) ~/tools/rp++ --version &>/dev/null || echo FAIL ;;
        rustscan) rustscan --version &>/dev/null || echo FAIL ;;
        ciphey) (ciphey --help &>/dev/null || ~/tools/ciphey --help &>/dev/null) || echo FAIL ;;
        ropium) python3 -c "from ropium import *" &>/dev/null || echo FAIL ;;
    esac
done | wc -l)
echo "P1 Tool failures: $FAIL_COUNT"
echo "NOTE: P1 tool failures should be resolved before proceeding."
echo "      P2 tool failures are acceptable — they can be retried later."
```

**Decision**:
- 0 P1 failures: Proceed to Batch 9
- 1-2 P1 failures: Note which failed, proceed (document in knowledge)
- 3+ P1 failures: STOP, debug environment issues before continuing

---

## Batch 9: Knowledge Technique Documents Generation (20 min)

**Items**: 8 technique documents extracted from cloned repos.
**These require reading repo contents and synthesizing — delegate to writer/executor agents.**

### 9A: `knowledge/techniques/heap_house_of_x.md`
**Source**: `~/tools/MBE/` (Lab07) + `~/tools/CTF-All-In-One/`
**Content to extract**:
```
- House of Force, House of Spirit, House of Einherjar, House of Lore, House of Orange
- House of Roman, House of Rabbit, House of Botcake, House of Kiwi
- For each House: precondition, primitive needed, glibc version constraints, step-by-step
- MBE Lab07 heap UAF walkthrough as worked example
- CTF-All-In-One House writeups index (with file paths)
- Practical checklist: "Given UAF on glibc X.Y, try these Houses in this order"
```
**Command**:
```bash
# Extract House-of-X index from CTF-All-In-One
find ~/tools/CTF-All-In-One -iname "*house*" -o -iname "*heap*" | head -20
# Extract MBE Lab07 content
ls ~/tools/MBE/src/lab07/ 2>/dev/null
cat ~/tools/MBE/README.md 2>/dev/null | grep -A5 -i "lab07\|heap"
```

### 9B: `knowledge/techniques/windows_kernel_exploitation.md`
**Source**: `~/tools/HEVD/`
**Content to extract**:
```
- 16 vulnerability types with brief description and driver entry point
- Stack Overflow, Integer Overflow, UAF, Type Confusion, Pool Overflow, etc.
- IOCTL dispatch table pattern
- Windows kernel exploitation primitives (token stealing, SMEP bypass)
- Link to HEVD exploits directory for each type
```
**Command**:
```bash
ls ~/tools/HEVD/Driver/HEVD/ 2>/dev/null
find ~/tools/HEVD -name "*.c" | head -20
cat ~/tools/HEVD/README.md | head -60
```

### 9C: `knowledge/techniques/kernel_exploit_multistage.md`
**Source**: `~/tools/exploit-writeups/`
**Content to extract**:
```
- PS4/FreeBSD kernel exploit chain methodology (7-stage pattern)
- kASLR bypass techniques
- Kernel heap spray patterns
- Kernel ROP chain construction
- Cross-references to linux-kernel-exploitation repo
```
**Command**:
```bash
ls ~/tools/exploit-writeups/
find ~/tools/exploit-writeups -name "*.md" | head -20
```

### 9D: `knowledge/techniques/web_ctf_techniques.md`
**Source**: `~/tools/google-ctf/`
**Content to extract**:
```
- Google CTF web challenge categories (2017-2025)
- XSS, SSRF, deserialization, prototype pollution patterns
- Notable solutions with one-liner summaries
- Index by technique for quick lookup during CTF
```
**Command**:
```bash
ls ~/tools/google-ctf/
find ~/tools/google-ctf -path "*/web/*" -name "*.md" 2>/dev/null | head -20
find ~/tools/google-ctf -name "SOLUTION*" -o -name "README*" | head -20
```

### 9E: `knowledge/techniques/systems_security_refs.md`
**Source**: `~/tools/awesome-list-systems/`
**Content to extract**:
```
- UEFI/Secure Boot research references (2024-2025)
- ARM MTE bypass papers
- ICS/SCADA security resources
- EDR bypass techniques index
- Fuzzing state-of-the-art references
```
**Command**:
```bash
cat ~/tools/awesome-list-systems/README.md | head -100
```

### 9F: `knowledge/techniques/security_papers_index.md`
**Source**: `~/tools/paper_collection/`
**Content to extract**:
```
- Index of 200+ papers organized by category
- Fuzzing papers (AFL++, LibAFL, Fuzzware)
- Firmware analysis papers
- LLM security papers
- Kernel exploitation papers
- Each entry: title, year, one-line summary, PDF link
```
**Command**:
```bash
ls ~/tools/paper_collection/
cat ~/tools/paper_collection/README.md | head -100
```

### 9G: `knowledge/techniques/mobile_testing_mastg.md`
**Source**: `~/tools/owasp-mastg/`
**Content to extract**:
```
- OWASP MASTG test categories (MASVS mapping)
- Android-specific: root detection bypass, SSL pinning bypass, Frida scripts
- iOS-specific: jailbreak detection, keychain extraction
- Quick-reference checklist for mobile bug bounty
- Tool recommendations per test category
```
**Command**:
```bash
ls ~/tools/owasp-mastg/
find ~/tools/owasp-mastg -name "*.md" -path "*/tests/*" | head -20
```

### 9H: `knowledge/techniques/ad_exploitation_reference.md`
**Source**: `~/tools/ad-exploitation/`
**Content to extract**:
```
- ADCS exploitation (ESC1-ESC8)
- BloodHound query cheat sheet
- Kerberoasting / AS-REP Roasting
- DCSync / DCShadow
- Delegation abuse (Constrained, Unconstrained, RBCD)
- Trust relationship exploitation
- Quick-reference command list for each technique
```
**Command**:
```bash
cat ~/tools/ad-exploitation/README.md | head -100
```

---

## Batch 10: Agent Prompt Updates (15 min)

**Items**: Update 5 agent definition files with new tool references.
**Each update is independent — can be done in parallel by multiple executor agents.**

### 10A: `.claude/agents/chain.md` — Add ropium, rp++, MBE heap patterns

**Additions to Tools section** (after existing ROPgadget line):
```markdown
- `ropium` (semantic ROP chain builder: `rax=rbx+8`, `[rdi+0x20]=rax`, function call ABIs, syscalls)
- `~/tools/rp++` (ARM/ARM64/Mach-O ROP gadget finder — supplements ROPgadget for firmware targets)
- `~/tools/linux-exploit-suggester.sh` (kernel version → privesc CVE suggestions)
```

**Additions to Heap Exploitation Sub-Protocol** (new subsection after Anti-Patterns):
```markdown
### House-of-X Quick Reference (from MBE Lab07 + CTF-All-In-One)
- See `knowledge/techniques/heap_house_of_x.md` for full reference
- House selection by glibc version:
  - < 2.26: Force, Spirit, Einherjar, Lore
  - 2.26-2.33: Orange, Roman, Rabbit, Botcake
  - >= 2.34: Kiwi, Apple (no hooks), FSOP variants
```

**Additions to Strategy Selection** (new row in table):
```markdown
| ARM/firmware ROP | rp++ for gadgets + ropium for chaining | ROPgadget alone (misses ARM gadgets) |
```

### 10B: `.claude/agents/solver.md` — Add Ciphey auto-decode

**Additions to Tools section** (after angr/unicorn line):
```markdown
- `ciphey` or `~/tools/ciphey` (auto cipher/encoding detection — 50+ types including base64, rot13, morse, caesar, vigenere, RSA, AES-ECB patterns)
```

**Additions to Strategy Selection** (new row at TOP of table — first attempt):
```markdown
| Unknown encoding/cipher | Ciphey auto-detect FIRST (`ciphey -t "ciphertext"`) | Manually guessing encoding type |
```

**New section after Strategy Selection**:
```markdown
## Auto-Decode First (Ciphey Protocol)
Before writing ANY manual decoder:
1. Run `ciphey -t "<ciphertext>"` or `echo "<ciphertext>" | ciphey`
2. If Ciphey solves it → done in 5 seconds, write solve.py wrapper
3. If Ciphey fails → proceed to manual z3/GDB Oracle approach
4. Ciphey handles: base64, hex, binary, morse, caesar, rot13, vigenere, XOR, AES-ECB, RSA (small), hashes, and 40+ more
**Why first**: Ciphey solves ~30% of crypto/encoding CTF challenges instantly. Skipping it wastes 30-60 min on manual work.
```

### 10C: `.claude/agents/scout.md` — Add RustScan, web-check, vuls, amass, dnstwist, sherlock

**Additions to Available Tools section** (Network subsection):
```markdown
- **Port Scanning**: RustScan (`rustscan -a <target>` — scans all 65535 ports in ~3 sec, pipes to nmap for service detection), nmap (via pentest MCP or sudo)
- **Subdomain**: amass (`~/gopath/bin/amass enum -d <domain>` — OWASP, passive+active, 40+ data sources), subfinder (existing)
- **Web Recon API**: web-check (`~/tools/web-check <url>` — Docker, 33 checks: DNS/SSL/headers/tech/cookies/redirects/ports/security.txt/robots.txt in one shot)
- **CVE Enumeration**: vuls (`~/gopath/bin/vuls scan` — OS package CVE enumeration, complements nuclei)
- **Typosquatting**: dnstwist (`dnstwist <domain>` — generates 100+ domain permutations, checks registration)
- **OSINT**: sherlock (`sherlock <username>` — searches 400+ sites for username matches)
```

**Update Phase 2: Port Scanning** to use RustScan:
```markdown
### Phase 2: Port Scanning (PARALLELIZABLE with Phase 3)
```bash
# FAST: RustScan all ports → pipe to nmap for service detection
rustscan -a <target> --ulimit 5000 -- -sV -sC -oN nmap_full.txt

# FALLBACK (if RustScan unavailable):
nmap -sS -p- -T4 --min-rate 2000 <target>
```

### 10D: `.claude/agents/reverser.md` — Add HEVD, Cryptogenic kernel patterns

**Additions to Tools section**:
```markdown
- `~/tools/HEVD/` (16 Windows kernel vulnerability types — reference for driver RE patterns, IOCTL dispatch)
- `~/tools/exploit-writeups/` (Cryptogenic PS4/FreeBSD kernel chains — multi-stage kernel exploit reference)
- `~/tools/apktool` or `~/tools/apktool/apktool.jar` (Android APK decompilation — smali/resources/manifest)
```

**New section: Windows Driver Analysis Protocol**:
```markdown
## Windows Kernel Driver Analysis (HEVD Reference)
When analyzing Windows drivers (.sys files):
1. Identify IOCTL dispatch table (`IRP_MJ_DEVICE_CONTROL`)
2. Map IOCTL codes to handler functions
3. Cross-reference vulnerability type with HEVD patterns:
   - See `~/tools/HEVD/Driver/HEVD/` for 16 vulnerability type implementations
   - See `knowledge/techniques/windows_kernel_exploitation.md` for exploitation guide
4. Check for: stack overflow, pool overflow, UAF, type confusion, integer overflow, null pointer deref, uninitialized stack/heap, double fetch, insecure object reference
```

**New section: Android RE Protocol**:
```markdown
## Android RE Protocol (Apktool)
For Android challenges or mobile bug bounty:
1. `~/tools/apktool d app.apk -o decompiled/` — decompile APK to smali + resources
2. Check `AndroidManifest.xml` for exported components, permissions, debug flags
3. Check `smali/` for crypto implementations, hardcoded keys, API endpoints
4. See `knowledge/techniques/mobile_testing_mastg.md` for OWASP MASTG checklist
```

### 10E: `.claude/agents/analyst.md` — Add OWASP/mastg, AD exploitation, linux-kernel-exploitation

**Additions to Source Code Analysis Mode** (after Step E):
```markdown
### Step F: Mobile Application Analysis (when target is Android/iOS)
- Reference: `knowledge/techniques/mobile_testing_mastg.md` (OWASP MASTG checklist)
- Reference: `~/tools/owasp-mastg/` (full test suite and guides)
- Use Apktool for APK decompilation, Frida for dynamic instrumentation
- SSL pinning bypass, root/jailbreak detection, insecure storage, intent hijacking

### Step G: Active Directory Assessment (when target includes AD)
- Reference: `knowledge/techniques/ad_exploitation_reference.md`
- Reference: `~/tools/ad-exploitation/` (full cheat sheet)
- ADCS exploitation (ESC1-ESC8), Kerberoasting, delegation abuse, DCSync

### Step H: Kernel/Privilege Escalation Assessment (when target is Linux)
- Reference: `~/tools/linux-kernel-exploitation/` (kernelCTF techniques)
- Reference: `~/tools/linux-exploit-suggester.sh` (automated kernel privesc suggestions)
- Run: `~/tools/linux-exploit-suggester.sh --kernel $(uname -r)` on target
```

---

## Batch 11: CLAUDE.md & external_repos.md Updates (10 min)

### 11A: CLAUDE.md — Update "Local Security Tools" Section

**Add after existing tool entries** (in the "Local Security Tools" section):

```markdown
- **ROP/Gadgets**: rp++ v2.1.5 (~/tools/rp++ — ARM/ARM64/Mach-O gadgets, supplements ROPgadget), ropium (~/tools/ropium-src — semantic ROP chain builder, Python API: `rax=rbx+8`)
- **Auto-Decode**: Ciphey (50+ cipher/encoding auto-detection — base64, caesar, vigenere, XOR, AES-ECB, etc.)
- **Port Scanning**: RustScan v2.4.1 (65535 ports in 3 sec, pipes to nmap)
- **Web Recon**: web-check (Docker, ~/tools/web-check — 33 REST API endpoints), amass (~/gopath/bin/amass — OWASP subdomain enum, 40+ sources), dnstwist (typosquatting detection)
- **CVE Enum**: vuls (~/gopath/bin/vuls — OS/package CVE enumeration), linux-exploit-suggester (~/tools/linux-exploit-suggester.sh — kernel privesc)
- **Embedded**: routersploit (~/tools/routersploit — embedded device exploitation framework)
- **Android**: Apktool v3.0.1 (~/tools/apktool — APK decompilation)
- **OSINT**: sherlock (username search across 400+ sites)
```

### 11B: knowledge/external_repos.md — Add All New Repos

**Add new sections**:

```markdown
## CTF Knowledge Bases

| Repo | Path | Content | Usage |
|------|------|---------|-------|
| **RPISEC/MBE** | `~/tools/MBE/` | 10 Labs + 15 lectures (heap/kernel/C++/format string) | Lab07=heap UAF, Lab09=C++ vTable |
| **HEVD** | `~/tools/HEVD/` | 16 Windows kernel vuln types with source+exploits | Driver RE patterns, IOCTL dispatch |
| **google/google-ctf** | `~/tools/google-ctf/` | 2017-2025 Google CTF official problems+solutions | Web CTF techniques, advanced pwn, benchmarks |
| **Cryptogenic/Exploit-Writeups** | `~/tools/exploit-writeups/` | PS4/FreeBSD 7-stage kernel exploit chains | kASLR bypass, kernel heap spray, kernel ROP |
| **CTF-All-In-One** | `~/tools/CTF-All-In-One/` | House of X heap writeups (45+ techniques) | Heap exploitation reference by glibc version |
| **awesome-ctf** | `~/tools/awesome-ctf/` | Tool discovery index for CTF | one_gadget, RSACTFTool, Triton references |
| **linux-kernel-exploitation** | `~/tools/linux-kernel-exploitation/` | kernelCTF techniques, defense bypass timeline | Kernel exploit technique index |

## Security Research References

| Repo | Path | Content | Usage |
|------|------|---------|-------|
| **0xor0ne/awesome-list** | `~/tools/awesome-list-systems/` | UEFI/MTE/ICS/EDR bypass research (to 2025) | Systems security research refs |
| **paper_collection** | `~/tools/paper_collection/` | 200+ fuzzing/firmware/LLM security papers | Academic paper index |
| **OWASP/mastg** | `~/tools/owasp-mastg/` | Mobile Application Security Testing Guide | Mobile BB checklist (Android/iOS) |
| **AD Exploitation** | `~/tools/ad-exploitation/` | ADCS/BloodHound/Kerberos cheat sheet | AD pentest reference |

## Competitor Analysis (Read-Only Reference)

| Repo | Path | Stars | Key Insight |
|------|------|-------|-------------|
| **CAI** | `~/tools/cai-analysis/` | 7.2K | MCP-based tool integration, HTB top, benchmark methodology |
| **Shannon** | `~/tools/shannon-analysis/` | 24.7K | Claude Agent SDK, XBOW 96%, web BB pipeline |
```

---

## Batch 12: Final Verification (5 min)

```bash
echo "========================================="
echo "  TERMINATOR UPGRADE — FINAL REPORT"
echo "========================================="
echo ""

echo "=== P1 TOOLS (6) ==="
declare -A P1_TOOLS=(
    ["Ciphey"]="ciphey --help 2>/dev/null || ~/tools/ciphey --help 2>/dev/null"
    ["RustScan"]="rustscan --version 2>/dev/null"
    ["rp++"]="~/tools/rp++ --version 2>/dev/null"
    ["web-check"]="docker images lissy93/web-check --format '{{.Tag}}' 2>/dev/null"
    ["vuls"]="~/gopath/bin/vuls version 2>/dev/null"
    ["ropium"]="python3 -c 'from ropium import *' 2>/dev/null"
)
P1_OK=0; P1_FAIL=0
for tool in "${!P1_TOOLS[@]}"; do
    if eval "${P1_TOOLS[$tool]}" &>/dev/null; then
        echo "  [OK]   $tool"
        ((P1_OK++))
    else
        echo "  [FAIL] $tool"
        ((P1_FAIL++))
    fi
done

echo ""
echo "=== P2 TOOLS (6) ==="
declare -A P2_TOOLS=(
    ["amass"]="~/gopath/bin/amass version 2>/dev/null || ~/gopath/bin/amass enum --version 2>/dev/null"
    ["dnstwist"]="dnstwist --version 2>/dev/null"
    ["sherlock"]="sherlock --version 2>/dev/null"
    ["Apktool"]="~/tools/apktool --version 2>/dev/null"
    ["linux-exploit-suggester"]="test -f ~/tools/linux-exploit-suggester.sh"
    ["routersploit"]="test -d ~/tools/routersploit || rsf --help 2>/dev/null"
)
P2_OK=0; P2_FAIL=0
for tool in "${!P2_TOOLS[@]}"; do
    if eval "${P2_TOOLS[$tool]}" &>/dev/null; then
        echo "  [OK]   $tool"
        ((P2_OK++))
    else
        echo "  [FAIL] $tool"
        ((P2_FAIL++))
    fi
done

echo ""
echo "=== KNOWLEDGE REPOS (13) ==="
REPOS=(MBE HEVD google-ctf exploit-writeups CTF-All-In-One awesome-ctf \
       linux-kernel-exploitation awesome-list-systems paper_collection \
       owasp-mastg ad-exploitation cai-analysis shannon-analysis)
REPO_OK=0; REPO_FAIL=0
for repo in "${REPOS[@]}"; do
    if test -d ~/tools/$repo; then
        echo "  [OK]   $repo"
        ((REPO_OK++))
    else
        echo "  [FAIL] $repo"
        ((REPO_FAIL++))
    fi
done

echo ""
echo "=== TECHNIQUE DOCS (8) ==="
DOCS=(heap_house_of_x windows_kernel_exploitation kernel_exploit_multistage \
      web_ctf_techniques systems_security_refs security_papers_index \
      mobile_testing_mastg ad_exploitation_reference)
DOC_OK=0; DOC_FAIL=0
KDIR="/home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/knowledge/techniques"
for doc in "${DOCS[@]}"; do
    if test -f "$KDIR/${doc}.md"; then
        echo "  [OK]   ${doc}.md"
        ((DOC_OK++))
    else
        echo "  [FAIL] ${doc}.md"
        ((DOC_FAIL++))
    fi
done

echo ""
echo "=== AGENT PROMPTS UPDATED ==="
AGENTS=(chain solver scout reverser analyst)
for agent in "${AGENTS[@]}"; do
    AFILE="/home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/.claude/agents/${agent}.md"
    if test -f "$AFILE"; then
        # Check if agent file was modified today
        if find "$AFILE" -mtime 0 2>/dev/null | grep -q .; then
            echo "  [OK]   ${agent}.md (updated today)"
        else
            echo "  [SKIP] ${agent}.md (not updated)"
        fi
    else
        echo "  [MISS] ${agent}.md (file not found)"
    fi
done

echo ""
echo "========================================="
echo "  SUMMARY"
echo "========================================="
echo "  P1 Tools:   $P1_OK OK / $P1_FAIL FAIL"
echo "  P2 Tools:   $P2_OK OK / $P2_FAIL FAIL"
echo "  Repos:      $REPO_OK OK / $REPO_FAIL FAIL"
echo "  Docs:       $DOC_OK OK / $DOC_FAIL FAIL"
echo ""
TOTAL_OK=$((P1_OK + P2_OK + REPO_OK + DOC_OK))
TOTAL=$((TOTAL_OK + P1_FAIL + P2_FAIL + REPO_FAIL + DOC_FAIL))
echo "  TOTAL: $TOTAL_OK / $TOTAL passed"
echo "========================================="
```

---

## Rollback Instructions

### Full Rollback (undo everything)
```bash
# Tools
sudo dpkg -r rustscan 2>/dev/null
pipx uninstall ciphey sherlock-project dnstwist routersploit 2>/dev/null
sudo rm /usr/local/lib/python*/dist-packages/ropium* 2>/dev/null
rm -f ~/tools/rp++ ~/tools/rp-lin-gcc ~/tools/linux-exploit-suggester.sh
rm -f ~/tools/web-check ~/tools/ciphey ~/tools/apktool ~/tools/rsf
rm -rf ~/tools/ropium-src ~/tools/routersploit ~/tools/apktool/
rm -f ~/gopath/bin/vuls ~/gopath/bin/amass
docker rmi lissy93/web-check:latest 2>/dev/null

# Knowledge repos
rm -rf ~/tools/MBE ~/tools/HEVD ~/tools/google-ctf ~/tools/exploit-writeups
rm -rf ~/tools/CTF-All-In-One ~/tools/awesome-ctf ~/tools/linux-kernel-exploitation
rm -rf ~/tools/awesome-list-systems ~/tools/paper_collection ~/tools/owasp-mastg ~/tools/ad-exploitation
rm -rf ~/tools/cai-analysis ~/tools/shannon-analysis

# Restore original files (requires git)
cd /home/rootk1m/01_CYAI_Lab/01_Projects/Terminator
git checkout -- CLAUDE.md knowledge/external_repos.md
git checkout -- .claude/agents/chain.md .claude/agents/solver.md .claude/agents/scout.md
git checkout -- .claude/agents/reverser.md .claude/agents/analyst.md

# Remove generated technique docs
rm -f knowledge/techniques/{heap_house_of_x,windows_kernel_exploitation,kernel_exploit_multistage,web_ctf_techniques,systems_security_refs,security_papers_index,mobile_testing_mastg,ad_exploitation_reference}.md
```

### Partial Rollback (single tool)
```bash
# Each tool section above has its own ROLLBACK comment — search for "ROLLBACK:"
```

---

## Known Issues & Workarounds

### Issue 1: Ciphey + Python 3.12 Incompatibility
- **Root cause**: `absl-py` dependency fails `setup.py egg_info` on Python 3.12
- **Workaround A**: pipx creates isolated venv (may resolve)
- **Workaround B**: Docker wrapper (guaranteed to work)
- **Workaround C**: Use Ares (Ciphey v2 Rust rewrite) — `https://github.com/bee-san/Ares`
- **Long-term**: Monitor Ciphey repo for Python 3.12 fix

### Issue 2: ropium Build May Fail
- **Root cause**: C++ extension with specific Python header dependency
- **Pre-req**: `sudo apt-get install libcapstone-dev python3-dev build-essential`
- **Workaround**: If `make` fails, try with explicit Python include: `CFLAGS="-I/usr/include/python3.12" make`
- **Fallback**: Use ropium Docker image if available

### Issue 3: RustScan .deb Package Structure
- **Risk**: v2.4.1 `rustscan.deb.zip` may have nested directory structure
- **Workaround**: `unzip -l` to inspect before `dpkg -i`
- **Fallback**: `cargo install rustscan` (requires ~8 min compile time)

### Issue 4: web-check Docker Image Size (~500MB)
- **Risk**: Large image, slow pull on limited bandwidth
- **Mitigation**: Pull in background while other batches run
- **Alternative**: Run web-check as Node.js app: `git clone && npm install && npm start`

### Issue 5: vuls Requires Configuration
- **Note**: vuls needs a `config.toml` for scanning — install is just the binary
- **Post-install**: Create basic config for local scanning:
  ```toml
  [servers.localhost]
  host = "localhost"
  port = "local"
  ```

### Issue 6: amass v4 Go Build Time
- **Risk**: `go install` may take 5-10 min for amass v4
- **Mitigation**: Run in background, proceed with other batches
- **Alternative**: Download pre-built binary from GitHub releases

---

## Execution Order Summary

```
Time    Batch                           Parallelism    Items
──────  ──────────────────────────────  ─────────────  ─────
0:00    Batch 0: Pre-flight checks      Sequential     Environment verification
0:02    Batch 1: Binary tools            3 parallel    rp++, RustScan, linux-exploit-suggester
0:07    Batch 2: Python/pipx tools       4 parallel    Ciphey, sherlock, dnstwist, routersploit
0:17    Batch 3: Build-from-source       Sequential    ropium (make && make install)
0:32    Batch 4: Docker/Go tools         4 parallel    web-check, vuls, Apktool, amass
0:42    Batch 5: P1 knowledge repos      4 parallel    MBE, HEVD, google-ctf, exploit-writeups
0:47    Batch 6: P2 knowledge repos      7 parallel    CTF-AIO, awesome-ctf, kernel, papers...
0:52    Batch 7: Competitor repos         2 parallel    CAI, Shannon
0:55    Batch 8: VERIFICATION GATE       Sequential    All tools + repos check
1:00    Batch 9: Technique documents     8 parallel    8 knowledge/techniques/*.md files
1:20    Batch 10: Agent prompt updates   5 parallel    chain, solver, scout, reverser, analyst
1:35    Batch 11: Config file updates    2 parallel    CLAUDE.md, external_repos.md
1:45    Batch 12: Final verification     Sequential    Full system check
──────  ──────────────────────────────  ─────────────  ─────
~1:50   DONE                                           29 items installed/created
```

**Dependency chain**:
```
Batch 0 (pre-flight)
  ├── Batch 1 (binary tools)  ──┐
  ├── Batch 2 (pipx tools)   ──┤
  ├── Batch 5 (P1 repos)     ──┤
  ├── Batch 6 (P2 repos)     ──┤── Batch 8 (verification gate)
  ├── Batch 7 (competitor)   ──┤       │
  ├── Batch 3 (ropium build) ──┤       ├── Batch 9 (technique docs) ──┐
  └── Batch 4 (Docker/Go)   ──┘       │                               ├── Batch 11 (config updates)
                                       └── Batch 10 (agent prompts) ──┘       │
                                                                               └── Batch 12 (final check)
```

**Total items: 29**
- P1 Tools: 5 (Ciphey, RustScan, rp++, web-check, vuls)
- P1 Knowledge: 6 (MBE, HEVD, google-ctf, Exploit-Writeups, CAI, Shannon)
- P2 Tools: 7 (ropium, Apktool, linux-exploit-suggester, routersploit, amass, dnstwist, sherlock)
- P2 Knowledge: 7 (CTF-AIO, awesome-ctf, kernel-exploitation, awesome-list, papers, OWASP/mastg, AD)
- Technique docs: 8
- Agent updates: 5
- Config updates: 2 (CLAUDE.md, external_repos.md)

---

## User Confirmation Needed Before Execution

1. **Docker pull ~500MB** for web-check — acceptable?
2. **cargo install rustscan** as fallback if .deb fails — acceptable ~8 min compile?
3. **sudo access** needed for: dpkg -i (RustScan), make install (ropium), apt-get (libcapstone-dev)
4. **Go install** for amass/vuls — will download Go modules (~100MB)
