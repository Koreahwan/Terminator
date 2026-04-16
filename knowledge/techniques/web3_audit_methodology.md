# Web3 Smart Contract Security Audit Methodology

**Last Updated:** 2026-02-16
**Status:** Research compilation from top audit firms and competitive platforms

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Top Audit Firm Methodologies](#top-audit-firm-methodologies)
3. [Systematic Bug Finding Process](#systematic-bug-finding-process)
4. [Tool-Specific Guides](#tool-specific-guides)
5. [Comprehensive Manual Review Checklist](#comprehensive-manual-review-checklist)
6. [Competitive Audit Insights](#competitive-audit-insights)
7. [Foundry Advanced Testing Techniques](#foundry-advanced-testing-techniques)
8. [Common Vulnerability Patterns](#common-vulnerability-patterns)
9. [References](#references)

---

## Executive Summary

This document compiles smart contract security audit methodologies from industry-leading firms (Trail of Bits, OpenZeppelin, Spearbit/Cantina, Cyfrin) and competitive audit platforms (Code4rena, Sherlock). It provides a systematic approach to finding vulnerabilities through a combination of automated tools, manual review, and advanced testing techniques.

**Key Takeaways:**
- **No single tool finds everything** — Combine static analysis, fuzzing, formal verification, and manual review
- **Fuzz/invariant tests are the new bare minimum** — Property-based testing is now expected for any serious audit
- **Context matters more than checklists** — Understanding the protocol's trust model and invariants is critical
- **Competitive audits favor depth over breadth** — Focus on one contest at a time for maximum ROI
- **PoC or it didn't happen** — Always provide working exploit code, not just theoretical vulnerabilities

---

## Top Audit Firm Methodologies

### Trail of Bits

**Philosophy:** Root cause analysis over checklist-based auditing

**Approach:**
1. **Threat Modeling** — Identify trust boundaries, privileged roles, and critical assets
2. **Automated Analysis** — Slither (93 detectors), Echidna/Medusa property-based testing
3. **Manual Review** — Focus on business logic, access control, and edge cases
4. **Documentation** — Provide nuanced, actionable insights with remediation guidance

**Key Tools:**
- **Slither:** Static analysis framework with 93 detectors, custom queries via Python API
- **Echidna/Medusa:** Property-based fuzzing tools for breaking invariants
- **Manticore:** Dynamic symbolic execution for exploring execution paths

**Notable Insights:**
- 246 findings from their audits show that **access control** and **input validation** are most common
- Machine learning with `slither-simil` helps identify similar vulnerable code patterns
- Source: [Trail of Bits Blog](https://blog.trailofbits.com/2019/08/08/246-findings-from-our-smart-contract-audits-an-executive-summary/)

---

### OpenZeppelin

**Philosophy:** Audit readiness is as important as the audit itself

**Audit Readiness Checklist:**
1. **Code Quality**
   - Clean, readable, modular code with consistent naming conventions
   - Fast and thorough test suite (auditors view test quality as a proxy for code quality)
   - Comprehensive documentation (README, inline comments, architecture diagrams)

2. **Pre-Audit Requirements**
   - Final code freeze before audit start
   - All dependencies updated and pinned
   - Clear specification of intended behavior and invariants

3. **Process**
   - Client reviews audit readiness checklist
   - OpenZeppelin reviews final code before starting
   - Audit uses static analysis + manual inspection + automated tools
   - Compliance with latest EIPs verified

**Source:** [OpenZeppelin Audit Readiness Guide](https://learn.openzeppelin.com/security-audits/readiness-guide)

---

### Cyfrin (Patrick Collins)

**Philosophy:** The best way to become a great auditor is to audit a lot

**10-Step Systematic Approach:**
1. **Read Documentation** — Understand what the protocol is supposed to do
2. **Run Tests** — Verify existing test suite passes
3. **Run Static Analysis** — Slither, Aderyn (100+ real-time detectors in VS Code)
4. **Manual Code Review** — Focus on areas static analysis flags as weak
5. **Fuzzing** — Write invariant tests for critical properties
6. **Formal Verification** — Use Certora for high-value contracts
7. **Document Findings** — Clear PoC, severity, remediation
8. **Retest After Fixes** — Verify fixes don't introduce new bugs
9. **Final Report** — Executive summary + detailed findings
10. **Post-Audit Support** — Answer questions during remediation

**Aderyn Tool (2025):**
- VS Code extension with real-time static analysis
- 100+ vulnerability detectors
- Inline diagnostics with explanatory tooltips
- Project-wide vulnerability tree view
- Fully local code analysis (no code leaves your machine)

**Key Insight:** Static analysis tools won't find unique/critical findings, but they guide where to focus manual inspection.

**Source:** [Cyfrin Audit Approach](https://www.cyfrin.io/blog/10-steps-to-systematically-approach-a-smart-contract-audit)

---

### Spearbit/Cantina

**Model:** Decentralized auditing with elite independent security researchers

**How It Works:**
1. **Vetting Process** — Researchers prove capabilities through competitive audits on Cantina
2. **Matching** — Projects matched with auditors who have expertise in their tech stack
3. **Competitive Format** — Multiple researchers compete to find maximum issues
4. **Economics** — 20-30% platform cut, rest goes to auditors (vs. 70-80% cut at traditional firms)

**Competitive Audit Advantages:**
- Higher coverage with more eyes on code
- Time-bounded reviews (fixed deadline)
- Prize pools incentivize thorough research
- Public leaderboard drives quality

**Top Auditor Traits:**
- Deep protocol knowledge (DeFi, bridges, L2s, etc.)
- Track record of high-severity discoveries
- Fast turnaround (contests are 7-14 days)
- Clear, actionable reports

**Application Process:**
- Participate in Cantina competitions and score well
- Performance on cantina.xyz/competitions is the source of truth for evaluation

**Sources:**
- [Spearbit Marketplace](https://spearbit.com/)
- [Cantina Security Reviews](https://cantina.xyz/solutions/security-reviews)

---

## Systematic Bug Finding Process

### Phase 1: Understanding (Days 1-2)

**Goal:** Build a mental model of the system

**Tasks:**
1. **Read all documentation**
   - Whitepaper, README, architecture diagrams
   - Understand intended behavior and use cases

2. **Identify trust model**
   - Who are the privileged roles? (admin, owner, operator, etc.)
   - What can they do? What shouldn't they be able to do?
   - Are there economic incentives for misbehavior?

3. **Define invariants**
   - What properties must ALWAYS hold?
   - Examples:
     - "Total supply = sum of all balances" (ERC20)
     - "Contract can never become insolvent" (vault)
     - "User A cannot spend User B's tokens" (access control)

4. **Map attack surface**
   - External/public functions
   - State-changing operations
   - Integration points with other contracts

**Output:** Architecture document with trust model, invariants, and attack surface map

---

### Phase 2: Static Analysis (Days 2-3)

**Goal:** Automated vulnerability detection

**Tools & Commands:**

```bash
# Slither (83 detectors)
slither . --exclude-dependencies

# Aderyn (100+ detectors, Rust-based)
aderyn /path/to/contract

# Mythril (symbolic execution)
myth analyze contracts/Token.sol

# For large codebases, use Gemini CLI for summarization
tools/gemini_query.sh summarize-dir /path/to/contracts
```

**What to Look For:**
- High/medium severity findings
- Patterns of repeated issues
- Areas flagged by multiple tools

**Triage Strategy:**
1. **Ignore known false positives** (e.g., Slither's "Local variable shadowing" in most cases)
2. **Prioritize high-impact findings** (access control, reentrancy, oracle manipulation)
3. **Use findings as hints** for where to focus manual review

**Expected Output:**
- Slither report with 10-50 findings
- Triage notes: confirmed bugs vs. false positives
- List of "suspicious areas" for manual review

---

### Phase 3: Manual Review (Days 3-7)

**Goal:** Find logic bugs that tools miss

**Checklist-Based Review:**
See [Comprehensive Manual Review Checklist](#comprehensive-manual-review-checklist) below

**Focus Areas:**
1. **Access Control**
   - Missing `onlyOwner` / role modifiers
   - Privilege escalation paths
   - Unprotected initialization functions

2. **Business Logic**
   - Off-by-one errors
   - Incorrect formula implementations
   - Edge cases (zero amounts, max values)

3. **External Interactions**
   - Reentrancy (external calls before state updates)
   - Untrusted input validation
   - Return value checks

4. **Economic Exploits**
   - Flash loan attacks
   - Oracle manipulation
   - MEV opportunities (front-running, sandwich attacks)

**Technique: 3-Pass Source→Sink Tracing**
For each critical operation (e.g., token transfer):
1. **Pass 1:** Trace forward from user input to state change
2. **Pass 2:** Trace backward from state change to all callers
3. **Pass 3:** Cross-check with access control and validation logic

**Example (Vulnerability Hunting):**
```solidity
// Look for this pattern:
function withdraw(uint256 amount) external {
    // RED FLAG: External call before state update
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;  // Reentrancy vulnerability!
}
```

---

### Phase 4: Dynamic Testing (Days 4-8)

**Goal:** Break invariants with fuzzing and mainnet fork tests

**Foundry Invariant Testing:**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract VaultInvariantTest is Test {
    Vault vault;

    function setUp() public {
        vault = new Vault();
        targetContract(address(vault));  // Foundry will fuzz all public functions
    }

    // Invariant: Vault should never be insolvent
    function invariant_solvency() public {
        assertGe(address(vault).balance, vault.totalDeposits());
    }

    // Invariant: Sum of balances = total supply
    function invariant_conservation() public {
        uint256 sum = 0;
        for (uint i = 0; i < vault.userCount(); i++) {
            sum += vault.balances(vault.users(i));
        }
        assertEq(sum, vault.totalSupply());
    }
}
```

**Run Fuzzing:**
```bash
# Basic fuzzing (256 runs per invariant)
forge test --match-contract Invariant

# Deep fuzzing (10,000 runs)
forge test --match-contract Invariant --fuzz-runs 10000

# Stateful fuzzing with call sequences
forge test --match-contract Invariant --fuzz-runs 1000 --fuzz-seed 42
```

**Echidna/Medusa for Advanced Fuzzing:**
```yaml
# echidna.yaml
testMode: assertion
testLimit: 50000
seqLen: 100
shrinkLimit: 5000
```

```bash
# Echidna (Haskell-based, Trail of Bits)
echidna-test contracts/Vault.sol --contract VaultTest --config echidna.yaml

# Medusa (Go-based, Trail of Bits, faster)
medusa fuzz --target contracts/Vault.sol --deployment-order Vault
```

**Fork Testing Against Mainnet:**
```solidity
contract VaultForkTest is Test {
    Vault vault;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    function setUp() public {
        // Fork Ethereum mainnet at block 18000000
        vm.createSelectFork("mainnet", 18000000);
        vault = new Vault(USDC);
    }

    function testDepositRealUSDC() public {
        address whale = 0x123...; // Known USDC whale
        vm.startPrank(whale);

        IERC20(USDC).approve(address(vault), 1000e6);
        vault.deposit(1000e6);

        assertEq(vault.balances(whale), 1000e6);
        vm.stopPrank();
    }
}
```

**Run Fork Tests:**
```bash
forge test --fork-url https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY --match-contract Fork
```

---

### Phase 5: Formal Verification (Days 5-10, Optional)

**Goal:** Mathematically prove correctness of critical properties

**When to Use:**
- High-value contracts (>$100M TVL)
- Complex mathematical operations (AMMs, option pricing)
- Critical infrastructure (bridges, governance)

**Certora Prover:**
```cvl
// Certora Verification Language (CVL)
rule totalSupplyEqualsBalances {
    env e;
    address user;

    mathint totalSupply = totalSupply(e);
    mathint sumBalances = sumAllBalances(e);

    assert totalSupply == sumBalances, "Total supply must equal sum of balances";
}

rule noBalanceChangeWithoutTransfer {
    env e;
    address user;

    uint256 balanceBefore = balanceOf(e, user);
    method f;
    calldataarg args;
    f(e, args);
    uint256 balanceAfter = balanceOf(e, user);

    assert balanceBefore != balanceAfter =>
           (f.selector == transfer.selector ||
            f.selector == transferFrom.selector),
           "Balance can only change via transfer functions";
}
```

**Run Certora:**
```bash
certoraRun contracts/Token.sol --verify Token:specs/Token.spec \
  --solc solc8.19 --msg "Verify ERC20 invariants"
```

**Halmos (Bounded Symbolic Execution):**
```solidity
contract TokenHalmosTest is Test {
    Token token;

    function check_totalSupply(address user, uint256 amount) public {
        uint256 supplyBefore = token.totalSupply();
        token.transfer(user, amount);
        uint256 supplyAfter = token.totalSupply();

        assert(supplyBefore == supplyAfter);  // Halmos proves this holds
    }
}
```

**Run Halmos:**
```bash
halmos --contract TokenHalmosTest
```

**Expected Outcome:**
- Certora proves properties hold for ALL possible inputs (unbounded)
- Halmos proves properties for bounded input space (faster, less comprehensive)
- Either tool will provide counterexamples if properties are violated

**Sources:**
- [Certora Documentation](https://docs.certora.com/en/latest/)
- [Halmos GitHub](https://github.com/a16z/halmos)

---

## Tool-Specific Guides

### Slither: Static Analysis Framework

**What It Finds:**
- Reentrancy vulnerabilities
- Uninitialized state/local/storage variables
- Dangerous delegatecall
- Incorrect ERC20/ERC721 implementations
- Access control issues
- And 88 more detectors

**What It Misses:**
- Business logic errors
- Complex reentrancy (read-only, cross-function)
- Economic exploits (flash loans, oracle manipulation)
- Protocol-specific invariant violations

**Installation:**
```bash
pip3 install slither-analyzer
# Or via pipx for isolated environment
pipx install slither-analyzer
```

**Basic Usage:**
```bash
# Run all detectors
slither .

# Exclude dependencies (node_modules, lib/)
slither . --exclude-dependencies

# Run specific detectors
slither . --detect reentrancy-eth,uninitialized-state

# Output to JSON for parsing
slither . --json slither-report.json

# Generate inheritance graph
slither . --print inheritance-graph
```

**Custom Queries (Python API):**
```python
from slither import Slither

slither = Slither('contracts/Vault.sol')

# Find all external functions
for contract in slither.contracts:
    for function in contract.functions:
        if function.visibility == 'external':
            print(f"{contract.name}.{function.name}")

# Find all state-changing functions without access control
for contract in slither.contracts:
    for function in contract.functions:
        if function.is_writing_state() and not function.is_protected():
            print(f"⚠️  {contract.name}.{function.name} modifies state without access control")
```

**Triage Workflow:**
```bash
# 1. Run Slither and save output
slither . --json slither-report.json

# 2. Filter high/medium severity
cat slither-report.json | jq '.results.detectors[] | select(.impact == "High" or .impact == "Medium")'

# 3. Manually verify each finding
#    - Confirm: Add to audit report
#    - False positive: Document why and add to .slither-ignore
```

**CI/CD Integration:**
```yaml
# .github/workflows/slither.yml
name: Slither Analysis
on: [push, pull_request]
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: crytic/slither-action@v0.3.0
        with:
          fail-on: high
```

**Sources:**
- [Slither GitHub](https://github.com/crytic/slither)
- [Slither Documentation](https://github.com/crytic/slither/wiki/Detector-Documentation)

---

### Mythril: Symbolic Execution

**What It Finds:**
- Integer overflows/underflows
- Unprotected selfdestruct
- Delegatecall to untrusted contract
- Transaction order dependence
- Denial of service (gas limit)

**What It's Good For:**
- Exploring ALL execution paths (within depth limit)
- Finding edge cases with specific input values
- Checking assertion violations

**What It's Bad For:**
- Large contracts (slow, high memory usage)
- Complex inter-contract calls
- Business logic vulnerabilities

**Installation:**
```bash
pip3 install mythril
# Or via Docker
docker pull mythril/myth
```

**Basic Usage:**
```bash
# Analyze a contract (default: 2 transactions, depth 22)
myth analyze contracts/Token.sol

# Increase transaction depth for deeper analysis
myth analyze contracts/Token.sol --max-depth 30

# Analyze multiple transactions (e.g., initialize + exploit)
myth analyze contracts/Vault.sol --transaction-count 3

# Analyze specific contract in multi-contract file
myth analyze contracts/Token.sol:MyToken

# Output JSON report
myth analyze contracts/Token.sol -o json > mythril-report.json
```

**Configuration for Large Contracts:**
```bash
# Limit execution time (default: no limit)
myth analyze contracts/Complex.sol --execution-timeout 300

# Reduce depth to speed up (trade coverage for speed)
myth analyze contracts/Complex.sol --max-depth 12

# Analyze only specific functions
myth analyze contracts/Vault.sol --transaction-count 2 --create-timeout 10
```

**Example Output:**
```
==== Integer Arithmetic Bugs ====
SWC ID: 101
Severity: High
Contract: Token
Function name: transfer(address,uint256)
PC address: 1523
Estimated Gas Usage: 3421 - 4312
The arithmetic operation can result in integer overflow.
--------------------
In file: contracts/Token.sol:45

balances[msg.sender] -= amount

--------------------
```

**Sources:**
- [Mythril GitHub](https://github.com/ConsenSys/mythril)
- [Mythril Tutorial](https://github.com/ConsenSys/mythril/wiki)

---

### Echidna & Medusa: Property-Based Fuzzing

**Philosophy:** Define what SHOULD be true, then try to break it

**Echidna (Trail of Bits, Haskell):**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VaultEchidnaTest {
    Vault vault;

    constructor() {
        vault = new Vault();
    }

    // Property: Vault should never be insolvent
    function echidna_solvency() public view returns (bool) {
        return address(vault).balance >= vault.totalDeposits();
    }

    // Property: User balance should never exceed total supply
    function echidna_balance_sanity() public view returns (bool) {
        return vault.balances(msg.sender) <= vault.totalSupply();
    }
}
```

**Echidna Configuration:**
```yaml
# echidna.yaml
testMode: property
testLimit: 50000
shrinkLimit: 5000
seqLen: 100
contractAddr: "0x00a329c0648769A73afAc7F9381E08FB43dBEA72"
deployer: "0x00a329c0648769A73afAc7F9381E08FB43dBEA72"
sender: ["0x00a329c0648769A73afAc7F9381E08FB43dBEA70", "0x00a329c0648769A73afAc7F9381E08FB43dBEA71"]
```

**Run Echidna:**
```bash
echidna-test contracts/VaultEchidnaTest.sol --contract VaultEchidnaTest --config echidna.yaml
```

**Medusa (Trail of Bits, Go, Faster):**
```solidity
contract VaultMedusaTest {
    Vault vault;

    constructor() {
        vault = new Vault();
    }

    // Same properties as Echidna, but use 'property_' prefix
    function property_solvency() public view returns (bool) {
        return address(vault).balance >= vault.totalDeposits();
    }
}
```

**Medusa Configuration:**
```json
{
  "fuzzing": {
    "workers": 10,
    "callSequenceLength": 100,
    "testLimit": 50000,
    "shrinkLimit": 5000
  }
}
```

**Run Medusa:**
```bash
medusa fuzz --target contracts/VaultMedusaTest.sol --deployment-order Vault,VaultMedusaTest
```

**When Echidna/Medusa Finds a Violation:**
```
echidna_solvency: failed!
Call sequence:
1. deposit(1000)
2. withdraw(1500)  ← This breaks solvency!

Counterexample:
  msg.sender: 0x00a329...
  block.timestamp: 1234567890
```

**Key Differences:**
| Feature | Echidna | Medusa |
|---------|---------|--------|
| Language | Haskell | Go |
| Speed | Slower | 3-5x faster |
| Memory | Higher | Lower |
| Coverage | Excellent | Excellent |
| Integration | Standalone | Can import Foundry tests |

**Sources:**
- [Echidna GitHub](https://github.com/crytic/echidna)
- [Medusa GitHub](https://github.com/crytic/medusa)
- [Trail of Bits Medusa Launch](https://blog.trailofbits.com/2025/02/14/unleashing-medusa-fast-and-scalable-smart-contract-fuzzing/)

---

### Foundry: Testing & Fuzzing Framework

**Why Foundry for Security:**
- Write tests in Solidity (no context switching)
- Fast fuzzing with configurable runs
- Mainnet forking for integration tests
- Gas profiling and optimization
- Built-in invariant testing

**Fuzzing Example:**
```solidity
contract TokenFuzzTest is Test {
    Token token;

    function setUp() public {
        token = new Token(1000000);
    }

    // Foundry will call this with random values of 'amount'
    function testFuzz_transfer(uint256 amount) public {
        // Bound amount to valid range
        amount = bound(amount, 0, token.balanceOf(address(this)));

        address recipient = address(0x123);
        uint256 balanceBefore = token.balanceOf(recipient);

        token.transfer(recipient, amount);

        assertEq(token.balanceOf(recipient), balanceBefore + amount);
    }
}
```

**Run Fuzzing:**
```bash
# Default: 256 runs
forge test --match-test testFuzz

# Deep fuzzing: 10,000 runs
forge test --match-test testFuzz --fuzz-runs 10000

# Reproducible with seed
forge test --match-test testFuzz --fuzz-seed 42
```

**Handler-Based Invariant Testing:**
```solidity
contract Handler is Test {
    Vault vault;
    uint256 public totalDeposited;

    constructor(Vault _vault) {
        vault = _vault;
    }

    function deposit(uint256 amount) public {
        amount = bound(amount, 1, 1000 ether);

        vm.deal(address(this), amount);
        vault.deposit{value: amount}();

        totalDeposited += amount;
    }

    function withdraw(uint256 amount) public {
        uint256 balance = vault.balances(address(this));
        amount = bound(amount, 0, balance);

        vault.withdraw(amount);
        totalDeposited -= amount;
    }
}

contract VaultInvariantTest is Test {
    Vault vault;
    Handler handler;

    function setUp() public {
        vault = new Vault();
        handler = new Handler(vault);

        targetContract(address(handler));  // Foundry fuzzes Handler functions
    }

    function invariant_conservationOfValue() public {
        assertEq(address(vault).balance, handler.totalDeposited());
    }
}
```

**Fork Testing Example:**
```solidity
contract UniswapForkTest is Test {
    IUniswapV2Router02 router;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    function setUp() public {
        vm.createSelectFork("mainnet", 18000000);
        router = IUniswapV2Router02(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
    }

    function testSwapOnFork() public {
        // Test actual swap on forked mainnet state
        vm.deal(address(this), 1 ether);

        address[] memory path = new address[](2);
        path[0] = WETH;
        path[1] = USDC;

        router.swapExactETHForTokens{value: 1 ether}(
            0,
            path,
            address(this),
            block.timestamp
        );

        assertTrue(IERC20(USDC).balanceOf(address(this)) > 0);
    }
}
```

**Differential Testing:**
```solidity
contract DifferentialTest is Test {
    function testDifferential_sqrt(uint256 x) public {
        // Compare your implementation vs. known-good reference
        uint256 result1 = MySqrt.sqrt(x);
        uint256 result2 = ReferenceSqrt.sqrt(x);  // e.g., from Solmate

        assertEq(result1, result2, "Implementations diverged!");
    }
}
```

**Gas Optimization Testing:**
```bash
# Generate gas snapshot
forge snapshot

# Compare gas changes
forge snapshot --diff .gas-snapshot
```

**Sources:**
- [Foundry Book](https://book.getfoundry.sh/)
- [Cyfrin Fuzzing Guide](https://www.cyfrin.io/blog/smart-contract-fuzz-testing-using-foundry)

---

## Comprehensive Manual Review Checklist

This checklist combines best practices from multiple sources, including Solodit, Solcurity, Code4rena, and Sherlock. Use this as a guide, not a rigid template.

### 1. Access Control (Most Common Vulnerability)

- [ ] **Missing Modifiers**
  - All privileged functions have `onlyOwner` / role checks?
  - Initialization functions protected (or called in constructor)?

- [ ] **Privilege Escalation Paths**
  - Can a low-privilege user upgrade to admin?
  - Are role assignments properly protected?

- [ ] **Constructor Initialization**
  - Constructor sets owner correctly?
  - For proxies: `initialize()` called only once (via `initializer` modifier)?

- [ ] **Ownership Transfer**
  - Two-step ownership transfer implemented? (propose + accept)
  - `transferOwnership` emits event?

**Example Vulnerability:**
```solidity
// BAD: Missing onlyOwner
function setFeeRecipient(address _recipient) external {
    feeRecipient = _recipient;  // Anyone can set this!
}

// GOOD: Proper access control
function setFeeRecipient(address _recipient) external onlyOwner {
    require(_recipient != address(0), "Zero address");
    feeRecipient = _recipient;
    emit FeeRecipientUpdated(_recipient);
}
```

---

### 2. Reentrancy Vulnerabilities

- [ ] **Classic Reentrancy**
  - External calls before state updates? (Checks-Effects-Interactions pattern)
  - `ReentrancyGuard` used on all state-changing functions with external calls?

- [ ] **Cross-Function Reentrancy**
  - Function A calls external → external calls Function B → inconsistent state?

- [ ] **Read-Only Reentrancy**
  - View functions read state mid-transfer (e.g., during Curve LP token transfer)?

- [ ] **ERC777 Hooks**
  - If accepting ERC777 tokens, `tokensReceived` hook breaks CEI?

**Example Vulnerability:**
```solidity
// BAD: Classic reentrancy
function withdraw() external {
    uint256 amount = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: amount}("");  // External call BEFORE state update
    require(success);
    balances[msg.sender] = 0;  // Attacker re-enters here!
}

// GOOD: Checks-Effects-Interactions
function withdraw() external nonReentrant {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;  // State update FIRST
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
```

**Cross-Function Reentrancy:**
```solidity
// BAD: Two functions share state, external call between updates
function deposit() external payable {
    (bool success, ) = externalContract.call("");  // External call
    totalDeposits += msg.value;  // State update AFTER call
}

function withdraw() external {
    uint256 share = balances[msg.sender] * address(this).balance / totalDeposits;
    // If attacker re-enters here via deposit(), totalDeposits is stale!
}
```

**Sources:**
- [Ackee Blockchain Reentrancy Guide](https://ackee.xyz/blog/complete-reentrancy-hands-on-guide/)
- [ERC777 Reentrancy Attack](https://ackee.xyz/blog/reentrancy-attack-in-erc-777/)

---

### 3. Integer Arithmetic (Solidity 0.8+)

- [ ] **Unchecked Blocks**
  - `unchecked { }` only used where overflow/underflow is impossible?
  - Justification documented?

- [ ] **Type Conversions**
  - Downcasting (e.g., `uint256` → `uint8`) checked for overflow?
  - Upcasting safely preserves value?

- [ ] **Assembly / Yul**
  - Inline assembly arithmetic manually checked for over/underflow?

**Example Vulnerability:**
```solidity
// BAD: Silent overflow in type conversion
function setSmallValue(uint256 largeValue) external {
    uint8 smallValue = uint8(largeValue);  // Truncates! 256 → 0
    config = smallValue;
}

// GOOD: Check before conversion
function setSmallValue(uint256 largeValue) external {
    require(largeValue <= type(uint8).max, "Value too large");
    config = uint8(largeValue);
}
```

**Unchecked Block Pitfall:**
```solidity
// BAD: Unchecked without justification
function calculateReward(uint256 amount) public pure returns (uint256) {
    unchecked {
        return amount * rewardMultiplier;  // Can overflow!
    }
}

// GOOD: Only use unchecked when overflow is impossible
function incrementCounter() public {
    unchecked {
        counter++;  // OK: counter is bounded by gas limit
    }
}
```

**Sources:**
- [Solidity 0.8 Overflow Protection](https://faizannehal.medium.com/how-solidity-0-8-protect-against-integer-underflow-overflow-and-how-they-can-still-happen-7be22c4ab92f)

---

### 4. External Calls & Return Values

- [ ] **Return Value Checks**
  - All ERC20 `transfer` / `transferFrom` return values checked?
  - Use `SafeERC20` for non-standard tokens (USDT, BNB)?

- [ ] **Call vs. Transfer vs. Send**
  - `call{value: }` used instead of `transfer` / `send`? (2300 gas limit issue)

- [ ] **Low-Level Call Safety**
  - `address.call()` checks return value?
  - Target address validated?

**Example Vulnerability:**
```solidity
// BAD: Ignoring return value
function transferTokens(address token, address to, uint256 amount) external {
    IERC20(token).transfer(to, amount);  // What if this returns false?
}

// GOOD: Check return value
function transferTokens(address token, address to, uint256 amount) external {
    bool success = IERC20(token).transfer(to, amount);
    require(success, "Transfer failed");
}

// BETTER: Use SafeERC20
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

function transferTokens(address token, address to, uint256 amount) external {
    SafeERC20.safeTransfer(IERC20(token), to, amount);
}
```

---

### 5. Oracle Manipulation & Price Feeds

- [ ] **Single Price Source**
  - Relying on single DEX spot price? (manipulable with flash loans)

- [ ] **TWAP Usage**
  - Time-weighted average price used for critical operations?
  - TWAP window long enough (>10 minutes)?

- [ ] **Chainlink Oracles**
  - Staleness check: `updatedAt` recent enough?
  - Circuit breaker: price change too drastic?
  - `answer > 0` checked?

- [ ] **DEX LP Token Pricing**
  - Using `reserve0 * reserve1` for price? (vulnerable to manipulation)

**Example Vulnerability:**
```solidity
// BAD: Using spot price from single DEX
function getPrice() public view returns (uint256) {
    (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
    return reserve1 * 1e18 / reserve0;  // Flash loan can manipulate this!
}

// GOOD: Using Chainlink with staleness check
function getPrice() public view returns (uint256) {
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    require(price > 0, "Invalid price");
    require(block.timestamp - updatedAt < 3600, "Stale price");
    return uint256(price);
}
```

**Sources:**
- [CertiK Oracle Manipulation](https://www.certik.com/resources/blog/oracle-wars-the-rise-of-price-manipulation-attacks)
- [Flash Loan Attack Vectors](https://www.vibraniumaudits.com/post/flash-loan-vulnerabilities-the-explosive-security-threat-to-defi-smart-contracts)

---

### 6. Flash Loan Attacks

- [ ] **Price Oracle Manipulation**
  - Can attacker use flash loan to manipulate price oracle?

- [ ] **Collateral Ratio Manipulation**
  - Can attacker temporarily inflate collateral value?

- [ ] **Governance Attacks**
  - Can attacker borrow tokens to gain voting power?

**Attack Pattern:**
1. Borrow large amount of Token A (flash loan)
2. Swap A → B on DEX (manipulates spot price)
3. Use manipulated price in vulnerable protocol (borrow more, liquidate others, etc.)
4. Reverse swap, repay flash loan, profit

**Defense:**
- Use TWAP oracles (harder to manipulate)
- Rate limiting on large deposits/withdrawals
- Require multi-block wait periods
- Use multiple independent price sources

**Sources:**
- [Flash Loan Attack Explanation](https://www.startupdefense.io/cyberattacks/flash-loan-attack)

---

### 7. Front-Running & MEV

- [ ] **Transaction Ordering Dependence**
  - Does function outcome depend on transaction order?

- [ ] **Slippage Protection**
  - `minAmountOut` parameter enforced on swaps?
  - User can set their own slippage tolerance?

- [ ] **Commit-Reveal Schemes**
  - For sensitive operations (auctions, randomness), commit-reveal used?

**Example Vulnerability (Sandwich Attack):**
```solidity
// BAD: No slippage protection
function swap(uint256 amountIn) external {
    uint256 amountOut = calculateOutput(amountIn);
    // Attacker front-runs with large buy → price goes up
    // Your swap executes at worse price
    // Attacker back-runs with sell → profit
    token.transfer(msg.sender, amountOut);
}

// GOOD: Slippage protection
function swap(uint256 amountIn, uint256 minAmountOut) external {
    uint256 amountOut = calculateOutput(amountIn);
    require(amountOut >= minAmountOut, "Slippage too high");
    token.transfer(msg.sender, amountOut);
}
```

**Defense Strategies:**
- Private RPC endpoints (Flashbots Protect)
- Batch auctions (uniform clearing price)
- Token transfer cooldowns (prevent same-block sandwich)

**Sources:**
- [MEV Protection Guide](https://www.blocknative.com/blog/mev-protection-sandwiching-frontrunning-bots)
- [Sandwich Attack Mechanics](https://medium.com/@radcipher/day-4-sandwich-attack-mevs-most-infamous-trick-0fbd61c59e22)

---

### 8. Proxy & Upgrade Patterns

- [ ] **Storage Collision**
  - Proxy and implementation storage layouts match?
  - Using EIP-1967 storage slots for proxy-specific data?

- [ ] **Initialization**
  - Implementation contract constructor doesn't set state (use `initialize`)?
  - `initialize` protected with `initializer` modifier?

- [ ] **UUPS Upgrade Safety**
  - `upgradeTo` function includes `onlyOwner` check?
  - New implementation includes `upgradeTo` function (to prevent bricking)?

- [ ] **Delegatecall to Untrusted Address**
  - `delegatecall` target address hardcoded or validated?

**Example Vulnerability (Storage Collision):**
```solidity
// Proxy contract
contract Proxy {
    address public implementation;  // Slot 0
}

// Implementation V1
contract ImplementationV1 {
    address public owner;  // Also slot 0! Collision!

    function setOwner(address _owner) external {
        owner = _owner;  // Actually overwrites implementation address in proxy!
    }
}

// GOOD: Use EIP-1967 storage slots
contract ProxySecure {
    // keccak256("eip1967.proxy.implementation") - 1
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
}
```

**UUPS Upgrade Vulnerability:**
```solidity
// BAD: New implementation missing upgradeTo
contract ImplementationV2 {
    // Missing upgradeTo function!
}
// Result: Contract bricked, can never upgrade again

// GOOD: Always include upgradeTo in new implementations
contract ImplementationV2 is UUPSUpgradeable {
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
```

**Sources:**
- [UUPS Proxy Pattern Guide](https://blog.logrocket.com/using-uups-proxy-pattern-upgrade-smart-contracts/)
- [Delegatecall Vulnerabilities](https://www.halborn.com/blog/post/delegatecall-vulnerabilities-in-solidity)
- [CertiK Proxy Security](https://www.certik.com/resources/blog/upgradeable-proxy-contract-security-best-practices)

---

### 9. ERC4626 Vault-Specific Checks

- [ ] **Inflation Attack**
  - First depositor can't manipulate share price?
  - Vault mints dead shares or enforces minimum deposit?

- [ ] **Decimal Mismatch**
  - Vault decimals match underlying asset decimals?
  - Conversion math handles different decimals correctly?

- [ ] **Rounding Issues**
  - Rounding favors vault over users (not vice versa)?
  - Dust amounts don't accumulate to meaningful value?

- [ ] **Fee-on-Transfer / Rebasing Tokens**
  - If vault accepts these tokens, balance checks before/after transfer?

- [ ] **Reentrancy on Deposit/Withdraw**
  - Deposit/withdraw functions follow CEI pattern?

**Example Vulnerability (Inflation Attack):**
```solidity
// BAD: First depositor can inflate share price
// 1. Attacker deposits 1 wei → mints 1 share
// 2. Attacker donates 1000 ETH directly to vault
// 3. Next depositor deposits 999 ETH → rounds down to 0 shares!

// GOOD: Mint dead shares on first deposit
constructor() {
    _mint(address(0xdead), 1000);  // Prevents share price manipulation
}
```

**Sources:**
- [ERC4626 Security](https://erc4626.info/security/)
- [Inflation Attack Prevention](https://medium.com/@regis-graptin/build-secure-erc-4626-vaults-mastering-inflation-attack-prevention-64169912f188)
- [Zellic ERC4626 Primer](https://www.zellic.io/blog/exploring-erc-4626/)

---

### 10. Cross-Chain Bridge Security

- [ ] **Message Verification**
  - Source chain cryptographically verified (validator signatures)?
  - Chain ID included in signed message (prevents cross-chain replay)?

- [ ] **Replay Protection**
  - Message hash tracked to prevent resubmission?
  - Nonces sequential per sender?
  - Message expiration time enforced?

- [ ] **Trusted Remote Pattern**
  - Destination chain verifies message from authorized source contract?

- [ ] **Validator Set Security**
  - Multi-sig / threshold signatures required?
  - Validator rotation mechanism secure?

**Example Vulnerability (Replay Attack):**
```solidity
// BAD: No replay protection
function processMessage(bytes memory message, bytes memory signature) external {
    require(verify(message, signature), "Invalid signature");
    // Attacker can resubmit same message multiple times!
    mintTokens(decodeRecipient(message), decodeAmount(message));
}

// GOOD: Track processed messages
mapping(bytes32 => bool) public processedMessages;

function processMessage(bytes memory message, bytes memory signature) external {
    bytes32 messageHash = keccak256(message);
    require(!processedMessages[messageHash], "Already processed");
    require(verify(message, signature), "Invalid signature");

    processedMessages[messageHash] = true;
    mintTokens(decodeRecipient(message), decodeAmount(message));
}
```

**Sources:**
- [Chainlink Bridge Vulnerabilities](https://chain.link/education-hub/cross-chain-bridge-vulnerabilities)
- [Zealynx Bridge Security Checklist](https://www.zealynx.io/blogs/cross-chain-bridge-security-checklist)

---

### 11. Gas Optimization Pitfalls

- [ ] **Unbounded Loops**
  - All loops have bounded iteration count?
  - No loops over user-controlled arrays without size limit?

- [ ] **Storage vs. Memory**
  - Frequently accessed variables cached in memory?
  - Unnecessary storage reads eliminated?

- [ ] **Denial of Service via Gas**
  - Can attacker force function to consume max gas and revert?

**Example Vulnerability:**
```solidity
// BAD: Unbounded loop (DoS attack)
address[] public users;

function distributeRewards() external {
    for (uint256 i = 0; i < users.length; i++) {  // What if users.length = 1,000,000?
        users[i].call{value: reward}("");  // Gas limit exceeded!
    }
}

// GOOD: Pagination or pull-over-push
function claimReward() external {
    uint256 reward = calculateReward(msg.sender);
    pendingRewards[msg.sender] = 0;  // Update state first
    payable(msg.sender).transfer(reward);
}
```

---

### 12. Randomness & Predictability

- [ ] **Block Variables**
  - Not using `block.timestamp` or `blockhash` for randomness?

- [ ] **Chainlink VRF**
  - If using VRF, callback function protected from re-entrancy?

- [ ] **Commit-Reveal**
  - Reveal phase enforced after commit phase?

**Example Vulnerability:**
```solidity
// BAD: Predictable randomness
function spin() external {
    uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
    if (random % 10 == 0) {
        // Winner! Attacker can predict this
    }
}

// GOOD: Use Chainlink VRF
function requestRandomNumber() external {
    requestId = COORDINATOR.requestRandomWords(...);
}

function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal override {
    // Use randomWords[0] for unpredictable randomness
}
```

---

## Competitive Audit Insights

### Code4rena vs. Sherlock: Platform Comparison

| Aspect | Code4rena | Sherlock |
|--------|-----------|----------|
| **Audience** | Beginner-friendly | Expert-focused |
| **Avg. Researchers** | 100+ per audit | 20-50 per audit |
| **Audit Duration** | 7-14 days | 7-14 days |
| **Fee Model** | Free for protocols (community-driven) | Premium ($50K-$200K) |
| **Coverage** | Security audit | Audit + exploit insurance |
| **Payout** | $10K-$150K total pot | $50K-$500K total pot |
| **Focus** | Crowdsourced security | Vetted expert auditors |

**Sources:**
- [Code4rena vs Sherlock Comparison](https://hackenproof.com/blog/for-business/code4rena-vs-sherlock-crowdsourced-audits-comparison-guide)
- [Complete Audit Competition Guide](https://medium.com/@JohnnyTime/complete-audit-competitions-guide-strategies-cantina-code4rena-sherlock-more-bf55bdfe8542)

---

### Top Auditor Strategies

**1. Focus Over Breadth**
- Concentrate on ONE contest at a time (don't spread across multiple)
- Read every line of code, don't skim

**2. Expect Bugs**
- Adopt adversarial mindset: "How can I break this?"
- Even heavily audited protocols have vulnerabilities

**3. Study Past Reports**
- Review previous audit reports for similar protocols
- Learn what HIGH severity findings look like
- Understand judging criteria

**4. Automate Triage**
- Use Slither/Aderyn to identify weak areas
- Focus manual review on flagged sections + complex logic

**5. Collaboration**
- Engage in community discussions (Discord, forums)
- Collaborate on findings (some platforms allow team submissions)

**6. Persistence**
- Becoming a top auditor takes 6-12 months
- Track personal growth, not others' rankings
- Set realistic goals (e.g., 1 valid finding per contest → 5 per contest)

**Sources:**
- [Mastering Audit Contests](https://medium.com/@JohnnyTime/mastering-auditing-contests-practical-steps-for-success-code4rena-more-1cb04c61ba0b)
- [The Auditor Book](https://theauditorbook.com/) (Code4rena + Sherlock compilation)

---

### Common High-Severity Findings in Competitive Audits

Based on analysis of Code4rena and Sherlock reports:

| Vulnerability Type | Frequency | Avg. Severity | Example |
|-------------------|-----------|---------------|---------|
| Access Control | 30% | High | Missing `onlyOwner` on critical function |
| Oracle Manipulation | 15% | Critical | Flash loan → DEX spot price manipulation |
| Reentrancy | 12% | High | External call before state update |
| Integer Overflow (unchecked) | 10% | Medium | `unchecked` block in unsafe context |
| Flash Loan Attacks | 8% | High | Borrow → manipulate → profit |
| Logic Errors | 25% | Medium-High | Off-by-one, incorrect formulas |

**Insight:** Focus audit time on access control (30% of findings) and business logic (25%) for maximum ROI.

---

### Time Management for 7-Day Contests

| Day | Focus | Time Allocation |
|-----|-------|-----------------|
| **1-2** | Understanding | 25% — Read docs, threat model, define invariants |
| **3** | Static Analysis | 10% — Slither, Aderyn, Mythril |
| **4-6** | Manual Review | 50% — Line-by-line code review, write tests |
| **7** | Reporting | 15% — Write clear findings with PoCs |

**Pro Tip:** Start writing findings from Day 4 onwards (don't wait until Day 7). Clear PoCs increase judging score.

---

## Foundry Advanced Testing Techniques

### 1. Stateful Fuzzing with Handlers

**Problem:** Foundry fuzzer generates random inputs, but doesn't understand protocol state

**Solution:** Write Handler contracts that constrain fuzzer to valid state transitions

```solidity
contract VaultHandler is Test {
    Vault vault;
    address[] public depositors;
    uint256 public ghost_depositSum;
    uint256 public ghost_withdrawSum;

    constructor(Vault _vault) {
        vault = _vault;
    }

    function deposit(uint256 amount, uint256 depositorSeed) public {
        // Bound amount to realistic range
        amount = bound(amount, 1 wei, 1000 ether);

        // Pick a depositor (or create new one)
        address depositor = depositors.length > 0
            ? depositors[depositorSeed % depositors.length]
            : address(uint160(depositors.length + 1));

        if (depositors.length == 0 || depositors[depositors.length - 1] != depositor) {
            depositors.push(depositor);
        }

        vm.deal(depositor, amount);
        vm.prank(depositor);
        vault.deposit{value: amount}();

        ghost_depositSum += amount;
    }

    function withdraw(uint256 depositorSeed) public {
        if (depositors.length == 0) return;

        address depositor = depositors[depositorSeed % depositors.length];
        uint256 balance = vault.balances(depositor);
        if (balance == 0) return;

        vm.prank(depositor);
        vault.withdraw(balance);

        ghost_withdrawSum += balance;
    }
}

contract VaultInvariantTest is Test {
    Vault vault;
    VaultHandler handler;

    function setUp() public {
        vault = new Vault();
        handler = new VaultHandler(vault);

        targetContract(address(handler));

        // Optional: configure fuzzer
        // bytes4[] memory selectors = new bytes4[](2);
        // selectors[0] = handler.deposit.selector;
        // selectors[1] = handler.withdraw.selector;
        // targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_solvency() public {
        assertGe(address(vault).balance, vault.totalDeposits());
    }

    function invariant_conservation() public {
        assertEq(
            handler.ghost_depositSum(),
            handler.ghost_withdrawSum() + vault.totalDeposits()
        );
    }
}
```

**Run:**
```bash
forge test --match-contract VaultInvariant --fuzz-runs 1000
```

---

### 2. Fork Testing Against Real Protocols

**Use Case:** Test your protocol's integration with Uniswap, Aave, Curve, etc.

```solidity
contract IntegrationForkTest is Test {
    address constant UNISWAP_V2_ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    MyStrategy strategy;

    function setUp() public {
        // Fork mainnet at specific block
        vm.createSelectFork("https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY", 18_000_000);

        strategy = new MyStrategy(UNISWAP_V2_ROUTER, USDC, WETH);
    }

    function testSwapOnRealUniswap() public {
        // Give test contract some USDC
        deal(USDC, address(this), 1000e6);

        // Test swap via your strategy
        IERC20(USDC).approve(address(strategy), 1000e6);
        strategy.swapUSDCForETH(1000e6);

        // Verify strategy received WETH
        assertTrue(IERC20(WETH).balanceOf(address(strategy)) > 0);
    }

    function testForkAtDifferentBlocks(uint256 blockNumber) public {
        // Test at different points in time
        blockNumber = bound(blockNumber, 17_000_000, 18_000_000);

        vm.createSelectFork("mainnet", blockNumber);
        // ... test logic
    }
}
```

**Impersonate Whale Accounts:**
```solidity
function testWithRealAssets() public {
    address usdcWhale = 0x123...;  // Known large USDC holder

    vm.startPrank(usdcWhale);
    IERC20(USDC).transfer(address(strategy), 1_000_000e6);
    vm.stopPrank();

    // Now test with real USDC
}
```

---

### 3. Differential Testing

**Use Case:** Compare your implementation against a known-good reference

```solidity
contract DifferentialFuzzTest is Test {
    MySqrt mySqrt;
    Solmate.FixedPointMathLib solmateMath;

    function setUp() public {
        mySqrt = new MySqrt();
    }

    function testFuzz_sqrt(uint256 x) public {
        uint256 myResult = mySqrt.sqrt(x);
        uint256 referenceResult = solmateMath.sqrt(x);

        assertEq(myResult, referenceResult, "Sqrt implementations diverged!");
    }

    function testFuzz_power(uint256 base, uint256 exponent) public {
        base = bound(base, 0, 1e18);
        exponent = bound(exponent, 0, 10);

        uint256 myResult = mySqrt.power(base, exponent);
        uint256 referenceResult = solmateMath.rpow(base, exponent, 1e18);

        assertApproxEqRel(myResult, referenceResult, 1e15, "1% tolerance");
    }
}
```

---

### 4. Gas Optimization Testing

```bash
# Generate gas snapshot
forge snapshot --snap .gas-snapshot

# After optimizations, compare
forge snapshot --diff .gas-snapshot

# Output shows gas changes:
# testDeposit() (gas: -142)  ← 142 gas saved!
# testWithdraw() (gas: +56)  ← 56 gas added
```

**Gas Profiling:**
```bash
forge test --gas-report

# Output:
# | Contract | Function | min | avg | median | max |
# |----------|----------|-----|-----|--------|-----|
# | Vault    | deposit  | 50k | 55k | 55k    | 60k |
```

---

### 5. Coverage Analysis

```bash
# Generate coverage report
forge coverage

# Generate detailed HTML report
forge coverage --report lcov
genhtml lcov.info -o coverage/

# View in browser
open coverage/index.html
```

**Identify Untested Code:**
- Red lines = never executed
- Yellow lines = partially executed (some branches)
- Green lines = fully covered

**Goal:** 90%+ coverage for critical contracts

---

## Common Vulnerability Patterns

### 1. Unprotected Selfdestruct

```solidity
// BAD
function kill() external {
    selfdestruct(payable(owner));  // Anyone can call!
}

// GOOD
function kill() external onlyOwner {
    selfdestruct(payable(owner));
}
```

---

### 2. Timestamp Dependence

```solidity
// BAD: Miner can manipulate timestamp by ~15 seconds
function lottery() external {
    if (block.timestamp % 10 == 0) {
        winner = msg.sender;
    }
}

// GOOD: Use Chainlink VRF or commit-reveal
```

---

### 3. tx.origin for Authentication

```solidity
// BAD: Phishing attack
function withdraw() external {
    require(tx.origin == owner);  // Attacker tricks owner into calling their contract
    // ...
}

// GOOD: Use msg.sender
function withdraw() external {
    require(msg.sender == owner);
}
```

---

### 4. Signature Replay

```solidity
// BAD: No nonce, signature can be reused
function executeMetaTx(bytes memory signature) external {
    address signer = recover(messageHash, signature);
    // Execute action for signer
}

// GOOD: Include nonce and chain ID
mapping(address => uint256) public nonces;

function executeMetaTx(bytes memory signature, uint256 nonce) external {
    require(nonces[signer] == nonce, "Invalid nonce");
    address signer = recover(keccak256(abi.encode(action, nonce, block.chainid)), signature);
    nonces[signer]++;
    // Execute action
}
```

---

### 5. Unchecked External Call

```solidity
// BAD
function callExternal(address target, bytes memory data) external {
    target.call(data);  // Ignores return value
}

// GOOD
function callExternal(address target, bytes memory data) external {
    (bool success, bytes memory returnData) = target.call(data);
    require(success, string(returnData));
}
```

---

### 6. ERC20 Approve Race Condition

```solidity
// Scenario: Alice approves Bob for 100 tokens, later changes to 50
// Bob front-runs the decrease → spends 100, then 50 = 150 total!

// Solution: Use increaseAllowance / decreaseAllowance
// Or require allowance = 0 before setting new value
function approve(address spender, uint256 amount) external {
    require(allowance[msg.sender][spender] == 0 || amount == 0, "Reset allowance first");
    allowance[msg.sender][spender] = amount;
}
```

---

### 7. Denial of Service (Unexpected Revert)

```solidity
// BAD: If one transfer fails, all fail
function distributeRewards(address[] memory recipients) external {
    for (uint i = 0; i < recipients.length; i++) {
        recipients[i].call{value: reward}("");  // If one reverts, all revert
    }
}

// GOOD: Pull over push pattern
mapping(address => uint256) public pendingRewards;

function claimReward() external {
    uint256 reward = pendingRewards[msg.sender];
    pendingRewards[msg.sender] = 0;
    payable(msg.sender).transfer(reward);
}
```

---

## References

### Audit Firm Resources

- [Trail of Bits Blog](https://blog.trailofbits.com/)
- [Trail of Bits Publications](https://github.com/trailofbits/publications)
- [OpenZeppelin Audit Readiness Guide](https://learn.openzeppelin.com/security-audits/readiness-guide)
- [Cyfrin Audit Approach](https://www.cyfrin.io/blog/10-steps-to-systematically-approach-a-smart-contract-audit)
- [Spearbit/Cantina](https://cantina.xyz/)

### Competitive Audit Platforms

- [Code4rena](https://code4rena.com/)
- [Sherlock](https://sherlock.xyz/)
- [The Auditor Book](https://theauditorbook.com/) (Code4rena + Sherlock findings compilation)
- [Complete Audit Competition Guide](https://medium.com/@JohnnyTime/complete-audit-competitions-guide-strategies-cantina-code4rena-sherlock-more-bf55bdfe8542)

### Tools & Documentation

- [Slither GitHub](https://github.com/crytic/slither)
- [Slither Detector Documentation](https://github.com/crytic/slither/wiki/Detector-Documentation)
- [Echidna GitHub](https://github.com/crytic/echidna)
- [Medusa GitHub](https://github.com/crytic/medusa)
- [Mythril GitHub](https://github.com/ConsenSys/mythril)
- [Certora Documentation](https://docs.certora.com/en/latest/)
- [Foundry Book](https://book.getfoundry.sh/)

### Security Checklists

- [Awesome Audit Checklists](https://github.com/TradMod/awesome-audits-checklists)
- [Smart Contract Auditor Tools](https://github.com/shanzson/Smart-Contract-Auditor-Tools-and-Techniques)
- [SmartContracts Audit Checklist](https://github.com/tamjid0x01/SmartContracts-audit-checklist)
- [Solidity Security Audit Checklist](https://medium.com/@0xmrudenko/solidity-security-audit-checklist-0bd1d566bf75)
- [47 Vulnerabilities Checklist](https://medium.com/@marcellusv2/the-complete-smart-contract-security-audit-checklist-47-vulnerabilities-i-check-before-any-c565848b6465)

### Vulnerability Databases

- [SWC Registry](https://swcregistry.io/) (Note: Not maintained since 2020)
- [EEA EthTrust Security Levels](https://entethalliance.org/specs/ethtrust-sl/) (Recommended current alternative)
- [Smart Contract Security Field Guide](https://scsfg.io/)
- [Solodit](https://solodit.xyz/) (15,500+ verified findings)

### Testing & Fuzzing Guides

- [Cyfrin Fuzzing Guide](https://www.cyfrin.io/blog/smart-contract-fuzz-testing-using-foundry)
- [Patrick Collins: Fuzz/Invariant Tests](https://patrickalphac.medium.com/fuzz-invariant-tests-the-new-bare-minimum-for-smart-contract-security-87ebe150e88c)
- [RareSkills Invariant Testing](https://rareskills.io/post/invariant-testing-solidity)
- [Foundry Fork Testing](https://book.getfoundry.sh/forge/fork-testing)

### Vulnerability-Specific Resources

- [Ackee Blockchain Reentrancy Guide](https://ackee.xyz/blog/complete-reentrancy-hands-on-guide/)
- [ERC777 Reentrancy Attack](https://ackee.xyz/blog/reentrancy-attack-in-erc-777/)
- [ERC4626 Security Guide](https://erc4626.info/security/)
- [Zellic ERC4626 Primer](https://www.zellic.io/blog/exploring-erc-4626/)
- [Chainlink Bridge Vulnerabilities](https://chain.link/education-hub/cross-chain-bridge-vulnerabilities)
- [Cross-Chain Bridge Security Checklist](https://www.zealynx.io/blogs/cross-chain-bridge-security-checklist)
- [CertiK Oracle Manipulation](https://www.certik.com/resources/blog/oracle-wars-the-rise-of-price-manipulation-attacks)
- [Flash Loan Attack Vectors](https://www.vibraniumaudits.com/post/flash-loan-vulnerabilities-the-explosive-security-threat-to-defi-smart-contracts)
- [MEV Protection Guide](https://www.blocknative.com/blog/mev-protection-sandwiching-frontrunning-bots)
- [Delegatecall Vulnerabilities](https://www.halborn.com/blog/post/delegatecall-vulnerabilities-in-solidity)
- [UUPS Proxy Pattern Guide](https://blog.logrocket.com/using-uups-proxy-pattern-upgrade-smart-contracts/)

### Educational Resources

- [Cyfrin Updraft Security Course](https://updraft.cyfrin.io/courses/security)
- [How to Become a Smart Contract Auditor](https://www.cyfrin.io/blog/how-to-become-a-smart-contract-auditor-courses-and-resources)
- [Smart Contract Auditor Roadmap 2025](https://cryptojobslist.com/blog/smart-contract-auditor-career-roadmap-patrick-collins)

---

**End of Document**

This methodology is a living document. Smart contract security is an evolving field—new attack vectors emerge regularly. Stay updated through audit firm blogs, competitive platforms, and community discussions.

For Terminator project integration, prioritize:
1. **Static analysis first** (Slither, Aderyn) — Fast, catches 30-40% of issues
2. **Invariant testing** (Foundry) — Required for any serious audit
3. **Manual review with checklist** — Where the HIGH/CRITICAL findings come from
4. **Fork testing** (if protocol has mainnet integrations)
5. **Formal verification** (Certora) — Only for high-value contracts (>$100M TVL)

**Next Steps for Terminator:**
- Integrate Slither into autonomous pipeline (analyst agent)
- Add Foundry invariant test templates for common patterns (ERC20, ERC4626, etc.)
- Create exploit templates for common vulnerabilities (reentrancy, oracle manipulation, etc.)
- Build knowledge base of past exploit PoCs (link to PoC-in-GitHub, ExploitDB)
