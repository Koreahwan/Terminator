# Immunefi Top Payouts & Bug Bounty Patterns (2023-2026)

**Research Date**: 2026-02-16
**Purpose**: Strategic intelligence for Web3 bug bounty hunting on Immunefi platform

---

## Table of Contents
1. [Top Immunefi Payouts](#1-top-immunefi-payouts)
2. [Most Common Vulnerability Categories](#2-most-common-vulnerability-categories)
3. [Immunefi-Specific Patterns](#3-immunefi-specific-patterns)
4. [Profitable Target Selection Strategy](#4-profitable-target-selection-strategy)
5. [Critical Success Factors](#5-critical-success-factors)
6. [Sources](#sources)

---

## 1. Top Immunefi Payouts

### Record-Breaking Bounties

| Rank | Protocol | Amount | Vulnerability Type | Year | Key Details |
|------|----------|--------|-------------------|------|-------------|
| 1 | **Wormhole** | **$10M** | Uninitialized Proxy | 2022 | Largest single bounty. UUPS proxy implementation not initialized after bugfix revert. Attacker could pass own Guardian set. |
| 2 | **Historical** | **$14.82M** | Critical (unspecified) | 2021 | Highest overall payout relating to same bug (January 2021). Multiple related findings. |
| 3 | **Aurora** | **$6M** | Critical | 2022 | Smart contract vulnerability. |
| 4 | **Polygon** | **$2.2M** | Critical | 2022 | Bridge/infrastructure vulnerability. |
| 5 | **Optimism** | **$2M** | Infinite Money Duplication | 2022 | L2 rollup logic bug enabling unlimited mint. |
| 6 | **Fei Protocol** | **Undisclosed (Huge)** | Flash Loan Attack | 2022 | Could have drained 60,000 ETH. Manipulated DEX pool prices via flash loan. |

### Highest Maximum Bounties Offered

| Protocol | Max Bounty | Type | Details |
|----------|------------|------|---------|
| **LayerZero** | **$15M** | Cross-chain messaging | 10% of funds at risk, up to $15M cap |
| **MakerDAO** | **$10M** | DeFi lending | Previously highest max bounty |
| **StarkNet** | **$1M** | ZK-rollup L2 | Min $50K for Critical |
| **Wormhole** | **20,000 W tokens** | Bridge | TVL-based calculation |

### Platform Statistics (2023-2025)

- **Total Payouts**: $100M+ (surpassed in 2024)
- **2023 Alone**: $65M paid for blockchain/smart contract vulnerabilities
- **Total Reports**: 3,000+ bug bounty reports processed
- **Protected TVL**: $190 billion across 330+ projects
- **Available Bounties**: $162M+ total rewards pool

---

## 2. Most Common Vulnerability Categories

### Top 10 Vulnerabilities (by frequency & payout)

#### 1. **Improper Input Validation** (Most Common)
- **Prevalence**: Leading root cause of confirmed vulnerabilities on Immunefi
- **Impact**: Manipulation of contract logic, malicious data injection, unexpected behavior
- **Why Critical**: Affects contract state transitions and fund safety

#### 2. **Oracle/Price Manipulation** (Highest Losses)
- **Prevalence**: Leading cause of on-chain DeFi exploits
- **Attack Vectors**:
  - Compromised/manipulated oracle feeds
  - Flash loan-enabled price manipulation
  - Incorrect pricing for swaps
  - Improper reward calculations
  - Collateralization ratio bypass
- **Notable Example**: Enzyme Finance price oracle manipulation (~$400K at risk, generous payout for quality report)

#### 3. **Access Control Issues** (Critical Severity)
- **H1 2025 Data**: $1.83B lost to access control exploits (59% of total losses)
- **Common Patterns**:
  - Missing privilege checks (Alchemix, Sense Finance, Enzyme examples)
  - Unprotected mint/upgrade/withdraw functions
  - Missing Trusted Forwarder validation (Gas Station Network)
  - Governance manipulation
- **Admin-Gated Caveat**: Exploits requiring admin privileges are typically rejected unless contract should have no privileged access

#### 4. **Reentrancy Attacks** (Classic but Evolving)
- **Variants**:
  - **ERC-777 reentrancy**: Transfer hooks with tokensToSend callbacks (Curve Finance hack)
  - **ERC-721 reentrancy**: safeTransferFrom → onERC721Received callback exploitation (Omni Protocol $1.4M loss)
  - Cross-function reentrancy
  - Read-only reentrancy
- **Notable Bounties**:
  - Position Exchange: $110K for ERC721 reentrancy loophole
  - Revest FNFTHandler: Active contract replacement vulnerability

#### 5. **Uninitialized Proxy Bugs** (Highest Single Payout)
- **Record**: $10M Wormhole bounty
- **Pattern**: UUPS proxy implementations not calling initialize()
- **Impact**: Attacker can initialize with malicious parameters, take control
- **Frequency**: Less common but catastrophic when present

#### 6. **Flash Loan Attacks**
- **Peak Era**: 2020-early 2021 (less common now due to better oracle integration)
- **Modern Approach**: Chainlink oracles and proper AMM integration reduced surface
- **Notable Example**: Fei Protocol 60,000 ETH at risk via flash loan price manipulation

#### 7. **Incorrect Calculations**
- **Impact**: Token balance errors, reward distribution bugs, unexpected execution results
- **Common in**: DeFi yield protocols, staking contracts, reward mechanisms

#### 8. **Integer Overflow/Underflow**
- **Pre-Solidity 0.8**: Major issue
- **Post-Solidity 0.8**: Built-in checks, but still relevant for:
  - Assembly code
  - Unchecked blocks
  - Non-Solidity languages (Move, Cairo, etc.)

#### 9. **Frontrunning/MEV Exploitation**
- **Data**: 72,000+ sandwich attacks on Ethereum, $1.4M profit extracted
- **Notable Actor**: "jaredfromsubway" - $1M in one week (PEPE/WOJAK memecoin attacks)
- **Immunefi Treatment**: Sandwich attacks with no slippage protection are in-scope
- **Severity Adjustment**: Requires other protocols for price manipulation → downgraded one level

#### 10. **Cross-Chain Bridge Vulnerabilities** (Highest Risk)
- **Why Critical**: Aggregate TVL across multiple chains
- **Common Issues**:
  - Privileged address exploitation
  - Cross-chain communication flaws
  - Custody address manipulation
- **Historical Example**: Poly Network $611M drain (August 2021)
- **Notable Bounties**: Wormhole $10M (bridge), LayerZero $15M max (messaging)

---

## 3. Immunefi-Specific Patterns

### 3.1 Severity Classification System (v2.3)

#### **Critical (Level 4)** - $10K-$15M payouts

**Smart Contracts:**
- Direct theft of user funds/NFTs (at-rest or in-motion)
- Permanent fund/NFT freezing
- Manipulation of governance vote results
- Unauthorized NFT minting
- Manipulated RNG enabling abuse
- Protocol insolvency

**Blockchain/DLT:**
- Network shutdown
- Permanent chain splits requiring hard forks
- Direct fund loss

**Websites/Apps:**
- Execute arbitrary system commands
- Retrieve sensitive data (DB passwords, blockchain keys)
- Application/NFT URI takedown
- Wallet interaction abuse

#### **High (Level 3)** - $5K-$10K average

**Smart Contracts:**
- Theft of unclaimed yield/royalties
- Permanent freezing of unclaimed assets
- Temporary fund/NFT freezing

**Blockchain/DLT:**
- Unintended chain splits
- Transaction delays >500% of average block time
- RPC API crashes affecting projects with ≥25% market cap

**Websites/Apps:**
- Persistent HTML injection (no JS)
- Confidential information disclosure
- Subdomain takeover

#### **Medium (Level 2)** - $5K-$20K range

**Smart Contracts:**
- Contract inability to deliver promised returns
- Block stuffing, griefing attacks
- Gas theft, unbounded gas consumption

**Blockchain/DLT:**
- ≥30% network node resource consumption increase
- ≥30% node shutdown (without network shutdown)

#### **Low (Level 1)** - Few thousand USD

**Smart Contracts:**
- Contract fails delivering returns without value loss

**Blockchain/DLT:**
- 10-30% network node shutdown

### 3.2 What Gets Automatically Rejected

#### **Hard Rejection Criteria:**
1. **Admin-Gated Vulnerabilities**
   - "EOA admin accounts with unlimited mint capabilities" = instant reject
   - "Centralization risks will be rejected right away"
   - Exception: Contracts explicitly designed with no privileged access

2. **Theoretical Issues Without PoC**
   - "Security researchers will have a hard time proving theoretical issues"
   - Must demonstrate real exploitability

3. **Insufficient Economic Damage**
   - Programs specifying minimum economic damage thresholds can reject below that
   - TVL-based programs: Must show % of TVL at risk

4. **Out of Scope**
   - Testing on mainnet/public testnet = permanent ban
   - Contacting projects directly about bugs = warning/ban
   - Out-of-scope assets/impacts per program page

5. **Quality Issues**
   - Spray-and-pray reports = ban
   - ChatGPT/AI/auto-generated reports = instant ban
   - Misrepresenting severity (e.g., claiming all Critical) = warning/ban
   - Incomplete/partial PoC = report closure

6. **Downgrade Triggers:**
   - Uncommon/incorrect victim action required
   - Uncommon/incorrect action by privileged user required
   - Attacker needs escalated/admin/controller/governance privileges
   - Requires manipulation of other protocols (downgrade by one severity level)

### 3.3 PoC Quality Requirements

#### **Web3 PoC (Smart Contracts):**
- **MUST**: Runnable code (Hardhat/Foundry test file, attack contract, exploit script)
- **MUST**: Functional at time of submission (no partial/incomplete PoC)
- **MUST NOT**: Exploit on mainnet/testnet (ban-worthy offense)
- **SHOULD**: Include specific line numbers from impacted code
- **SHOULD**: Provide pseudocode snippets explaining attack
- **SHOULD**: Calculate funds at risk (total tokens × average price at submission time)
- **BEST**: Use Immunefi's PoC templates (reusable, modular building blocks)

#### **Web2 PoC (Websites/Apps):**
- Video demonstration + brief text explanation acceptable
- Screenshots showing final attack acceptable
- HTTP requests acceptable
- Command line/programmable code acceptable

#### **Immunefi Resources:**
- GitHub: `immunefi-team/forge-poc-templates` (EVM vulnerability templates)
- Pre-built templates: Reentrancy, token manipulation, flash loans, oracle manipulation
- Modular "lego blocks" for building complex PoCs

### 3.4 Submission Rules (Rate Limits & Bans)

| Rule | Limit/Consequence |
|------|------------------|
| **Rate Limit** | Max 5 reports per 48 hours |
| **Multiple Accounts** | Ban all associated accounts |
| **Spray-and-Pray** | Ban (low-quality reports to many projects) |
| **AI-Generated Reports** | Instant ban (ChatGPT not trained on right data) |
| **Severity Misrepresentation** | Warning → Ban (listing all as Critical) |
| **Direct Contact** | Warning → Ban (must go through Immunefi) |
| **Mainnet Testing** | Permanent ban (zero tolerance) |

### 3.5 Reward Structure Patterns

#### **TVL-Based Programs (Most Common):**
- **Critical**: 10% of TVL at risk, capped at program max (typically $50K-$15M)
- **Scaling Standard**: Immunefi proposes 10% of potential economic damage
- **Example**: LayerZero = 10% of funds directly affected, max $15M

#### **Fixed Tiers:**
- **Critical**: $10K-$1M minimum (varies by project)
- **High**: $5K-$300K typical range
- **Medium**: $1K-$20K
- **Low**: $100-$5K

#### **Special Cases:**
- **Web/App Critical** (execute commands, steal DB keys): 2x standard amount ($10K minimum for Immunefi program)
- **Generous Payouts**: Enzyme Finance paid generously for ~$400K risk oracle bug "to incentivize future quality reports"

---

## 4. Profitable Target Selection Strategy

### 4.1 Target Category ROI Analysis

#### **Highest ROI: DeFi Smart Contracts (77.5% of total payouts)**
- **Average Critical Bounty**: $13,000+ (can go to $10M)
- **Average High Bounty**: $5,300
- **Why Best**: Direct fund theft, largest TVL, highest severity classifications
- **Best Protocols**: Lending, DEXes, yield aggregators, staking

#### **High ROI: Cross-Chain Bridges**
- **Max Bounties**: $10M-$15M (Wormhole, LayerZero)
- **Why Profitable**: Aggregate TVL across chains, high-value targets
- **Competition**: High (but fewer researchers with cross-chain expertise)
- **Common Bugs**: Privileged address exploits, message relay flaws, custody issues

#### **Medium ROI: Layer 2 Rollups**
- **Max Bounties**: $100K-$1M (zkSync $100K min/$100K max Critical, StarkNet $50K-$1M)
- **Examples**: Optimism $2M (infinite money duplication), ZKsync Era, StarkNet, Intmax
- **Why Profitable**: Novel tech, less audited, complex state transitions
- **Skill Requirement**: ZK proof systems (zkSync, StarkNet) or optimistic rollup internals (Optimism)

#### **Variable ROI: NFT Protocols**
- **Bounties**: Typically lower than DeFi (less TVL at risk)
- **Opportunity**: Underresearched compared to DeFi
- **Focus Areas**: ERC-721/1155 reentrancy, metadata manipulation, royalty enforcement

#### **Lower ROI: Blockchain/DLT (Node/Network Level)**
- **Bounties**: High for Critical (network shutdown, chain splits)
- **Challenge**: Requires deep protocol knowledge, harder to find bugs
- **Competition**: Fewer researchers, but also fewer bugs

### 4.2 New vs Established Protocols

#### **New Protocols (Higher ROI for skilled hunters):**
**Advantages:**
- Fewer researchers analyzing code (timing advantage critical)
- Less audited, more bugs present
- Projects eager to build reputation with generous payouts

**Disadvantages:**
- Lower TVL = lower max bounties
- Higher risk of project shutdown before payout
- May lack resources for timely response

**Strategy:**
- **Be Early**: "First developers to find new bounties have more time than other hunters"
- Monitor Immunefi's new program launches weekly
- Focus on novel tech (ZK proofs, account abstraction, modular blockchains)

#### **Established Protocols (Consistent but Competitive):**
**Advantages:**
- Higher max bounties ($10M-$15M range)
- Guaranteed payouts, strong reputation
- Better documentation, clearer scope

**Disadvantages:**
- Heavy competition (hundreds of researchers)
- Easy bugs already found
- Requires finding variant vulnerabilities or novel attack chains

**Strategy:**
- **Variant Analysis**: Use recent CVEs/bugs as seeds to find similar patterns
- **Deep Focus**: "Dedicate 2-3 weeks to fully study project" rather than surface scanning
- **Specialization**: Excel at one attack vector (oracle manipulation, reentrancy variants, etc.)

### 4.3 TVL Correlation Strategy

#### **TVL-Bounty Relationship:**
- **5-10% of TVL** allocated to bug bounty budgets (industry standard)
- **Critical Bounty = 10% of TVL at risk** (max cap applies)

#### **Target Selection by TVL:**

| TVL Range | Expected Critical Bounty | Competition Level | Best Strategy |
|-----------|-------------------------|-------------------|---------------|
| $1B+ | $10M-$15M (capped) | Very High | Variant analysis, novel chains |
| $100M-$1B | $1M-$10M | High | Focus on new features, upgrades |
| $10M-$100M | $100K-$1M | Medium | Deep dive, 2-3 week analysis |
| $1M-$10M | $10K-$100K | Low-Medium | **Best ROI for time invested** |
| <$1M | $1K-$10K | Low | Skip unless novel tech practice |

**Optimal Sweet Spot**: $10M-$100M TVL protocols
- Meaningful bounties ($100K-$1M for Critical)
- Less competitive than $1B+ protocols
- Mature enough for reliable payouts
- Still discoverable bugs

### 4.4 Under-Researched Target Indicators

#### **High-Value Signals:**
1. **Recent Major Upgrade/Launch** (<3 months)
   - New code paths, rushed audits
   - Example: Bedrock upgrade to OP Mainnet

2. **Novel Technology Stack**
   - Non-EVM (Move, Cairo, Rust-based)
   - New cryptographic primitives (FHE, MPC)
   - Hybrid consensus mechanisms

3. **Complex Integrations**
   - Multi-protocol composability
   - Cross-chain message passing
   - Oracle dependencies

4. **Low GitHub Star Count vs. TVL**
   - High TVL but low stars = underresearched
   - Check: GitHub stars / (TVL in millions) ratio
   - Ratio < 10 = potential goldmine

5. **First-Time Immunefi Program** (<6 months)
   - Project unfamiliar with bug bounty quality expectations
   - May have undiscovered bugs from pre-audit era

6. **Non-Solidity Smart Contracts**
   - Move (Aptos, Sui), Cairo (StarkNet), Rust (Solana, Near)
   - Fewer researchers comfortable with these languages

#### **Avoid (Over-Researched):**
- Uniswap, Aave, Compound (1,000+ researchers, picked clean)
- Anything with >10 audits and >2 years on mainnet
- Programs with >500 GitHub stars and <$50M TVL (hobbyist attention, low payout)

---

## 5. Critical Success Factors

### 5.1 Submission Quality (Make or Break)

#### **What Top Whitehats Do:**
1. **Complete PoC Before Submission**
   - Functional, runnable, reproducible
   - Use Immunefi's Forge templates as starting point
   - Include edge cases and failure modes

2. **Thorough Investigation**
   - "Invest time in thoroughly investigating the issue"
   - Root cause analysis, not just symptom
   - Map all affected functions/contracts

3. **Clear Documentation**
   - Specific line numbers from impacted code
   - Step-by-step attack narrative
   - Pseudocode + runnable code
   - Funds at risk calculation with evidence

4. **Accurate Severity Assessment**
   - Use Immunefi v2.3 classification exactly
   - Provide reasoning for severity choice
   - Reference similar past vulnerabilities

5. **Impact Demonstration**
   - Show economic damage potential
   - Screenshots/logs of exploit success
   - "Determine and provide data on amount of funds at risk"

#### **What Causes Rejection/Downgrade:**
1. Incomplete or partial PoC
2. Overinflated severity claims
3. Theoretical attack without proof
4. Requires admin privileges (unless program specifies otherwise)
5. Insufficient economic damage for program's threshold
6. Out of scope asset or impact
7. AI-generated boilerplate without customization

### 5.2 Timing & Competition Strategy

#### **First-Mover Advantage:**
- "You'll want to be one of the first developers to find the new bounties"
- **Action**: Check Immunefi homepage daily for new programs
- **Action**: Set GitHub watch on target project repos (monitor commits for new features)

#### **Focus Over Breadth:**
- "If you've chosen a target, don't jump to others"
- "Dedicate 2-3 weeks" to one protocol
- "With better understanding, higher chance of finding something"
- Deep knowledge >> surface scanning of many projects

#### **Specialization Strategy:**
- "Focus on a specific attack vector, protocol, or Web3 function, and excel at it"
- Examples:
  - Become the "reentrancy expert" (ERC-777/721 variants)
  - Specialize in oracle manipulation across all AMM types
  - Master flash loan attack construction
  - Focus on one L2 type (ZK rollups or optimistic)

#### **Platform Speed:**
- "Getting comfortable with mainnet fork testing, or quick heuristic testing with Remix will help test ideas quicker than other hunters"
- Use Foundry for fast iteration (faster than Hardhat)

### 5.3 Learning from Audit Competitions

**Key Differences (Immunefi Audit Competitions vs. Bounties):**
- Audit competitions require **feasibility and real-world impact** (stricter than open bug bounties)
- Only medium/high/critical with actionable fixes count
- Must include "clear and well-documented Proof of Concept"

**Lessons for Bounty Hunters:**
1. Focus on exploitability, not theoretical risks
2. Always include actionable remediation suggestions
3. Learn from audit competition winners' report styles
4. "Rushing submissions and failing to fully research impact" causes confusion and escalations

### 5.4 Long-Term Career Strategy

#### **Leaderboard System:**
- Top 20 whitehats ranked by cumulative accurate Critical bug reports
- Benefits: Exclusive merch, paid trips, speaking opportunities, additional rewards
- "Best way to increase rank: submit accurate, critical bug reports"

#### **Whitehat Scholarship:**
- Full-time bug hunting support program
- Requires track record of quality submissions

#### **Reputation Building:**
- Accuracy > Quantity (5 reports per 48h limit enforces this)
- One $10M bounty > 100 low-severity reports
- Projects remember quality reporters for future private invites

---

## 6. Actionable Recommendations for Terminator Project

### Immediate Actions (Week 1)

1. **Account Setup & Research:**
   - Create Immunefi whitehat account
   - Study all writeups in GitHub: `sayan011/Immunefi-bug-bounty-writeups-list`
   - Read Immunefi Top 10 Bugs article (mandatory)

2. **Tooling Setup:**
   - Clone `immunefi-team/forge-poc-templates` repo
   - Set up Foundry mainnet forking workflow
   - Configure Immunefi v2.3 severity checklist automation

3. **Target Selection (First Hunt):**
   - Filter programs: $10M-$100M TVL, <1 year on Immunefi, <6 months since major upgrade
   - Prioritize: ZK rollups (zkSync Era, StarkNet), new DeFi lending protocols
   - Avoid: Uniswap, Aave, Maker (over-researched)

### Strategic Focus Areas (Month 1-3)

1. **Master Top 3 Vulnerability Categories:**
   - **Oracle/Price Manipulation**: Study Enzyme Finance, Fei Protocol cases
   - **Access Control**: Alchemix, Sense Finance patterns
   - **Reentrancy Variants**: ERC-777 (Curve), ERC-721 (Omni, Position Exchange)

2. **Build Specialization:**
   - Choose one: Flash loan construction, cross-chain message exploits, or ZK proof bugs
   - Dedicate 80% of time to chosen specialty, 20% to general hunting

3. **Quality Over Quantity:**
   - Target: 1-2 high-quality Critical reports per quarter (better than 50 low-severity)
   - Each report: 2-3 weeks deep analysis + complete PoC + funds-at-risk calculation

### Integration with Existing Pipeline

#### **Bug Bounty Pipeline Enhancements for Immunefi:**

**Phase 0: Target Intelligence (target_evaluator):**
- Add Immunefi-specific scoring:
  - Program age on Immunefi (<6 months = +2 points)
  - TVL range ($10M-$100M sweet spot = +2 points)
  - Recent upgrade/launch (<3 months = +2 points)
  - Novel tech stack (non-EVM = +1 point)
  - GitHub star/TVL ratio (<10 = +1 point)

**Phase 1: Discovery (scout + analyst):**
- **Scout Phase 0**: Add Immunefi Hacktivity search (duplicate prevention)
- **Analyst**: Focus on Top 10 vulnerability categories first (improper input validation, oracle manipulation, access control)

**Phase 2: PoC Validation (exploiter):**
- **Mandatory**: Use Immunefi Forge templates as starting point
- **Mandatory**: Mainnet fork testing (never test on live mainnet)
- **Mandatory**: Calculate funds at risk (total tokens × price)
- **Quality Tier**: Tier 1 (Gold) requires Immunefi-style complete PoC

**Phase 4.5: Triager Simulation (triager_sim):**
- Add Immunefi v2.3 severity checklist validation
- Check for admin-gated preconditions (auto-reject)
- Verify PoC completeness (incomplete = instant close)
- Ensure no mainnet testing evidence (ban risk)

**Phase 5: Finalization (reporter):**
- Use Immunefi report template (specific line numbers, pseudocode, runnable code)
- Include funds-at-risk calculation prominently
- Reference similar past vulnerabilities from Immunefi blog
- Accurate severity justification using v2.3 criteria

### Success Metrics (6-Month Goals)

| Metric | Target | Stretch Goal |
|--------|--------|--------------|
| Critical Findings Submitted | 2-3 | 5+ |
| Total Bounty Earnings | $50K-$100K | $500K+ |
| Report Acceptance Rate | >80% | >95% |
| Average Severity | High-Critical | Critical Only |
| Time per Finding | 2-3 weeks | 1-2 weeks |
| Leaderboard Rank | Top 100 | Top 20 |

---

## Sources

### Top Payouts & Platform Statistics
- [Web3 bug bounty platform Immunefi surpasses $100 million in ethical hacker payouts | The Block](https://www.theblock.co/post/301025/web3-immunefi-ethical-hacker-payouts)
- [LayerZero, Immunefi Offer Bug Bounty With $15M Max Payout - Blockworks](https://blockworks.co/news/bug-bounty-15m-payout)
- [Smart Contract Bug Bounties Statistics 2026 | CoinLaw](https://coinlaw.io/smart-contract-bug-bounties-statistics/)

### Specific Vulnerability Examples
- [Wormhole Uninitialized Proxy Bugfix Review | Immunefi](https://medium.com/immunefi/wormhole-uninitialized-proxy-bugfix-review-90250c41a43a)
- [Blockchain bridge Wormhole pays record $10m bug bounty reward | The Daily Swig](https://portswigger.net/daily-swig/blockchain-bridge-wormhole-pays-record-10m-bug-bounty-reward)
- [Optimism Infinite Money Duplication Bugfix Review | Immunefi](https://medium.com/immunefi/optimism-infinite-money-duplication-bugfix-review-daa6597146a0)
- [Fei Protocol Flashloan Vulnerability Bugfix Review | Immunefi](https://medium.com/immunefi/fei-protocol-flashloan-vulnerability-postmortem-7c5dc001affb)
- [Enzyme Finance Price Oracle Manipulation Bug Fix | Immunefi](https://medium.com/immunefi/enzyme-finance-price-oracle-manipulation-bug-fix-postmortem-4e1f3d4201b5)

### Common Vulnerabilities & Top 10
- [Immunefi Top 10 Bugs](https://immunefi.com/immunefi-top-10/)
- [The Top 10 Most Common Vulnerabilities In Web3 | Immunefi](https://medium.com/immunefi/the-top-10-most-common-vulnerabilities-in-web3-bf7a921d489f)
- [Common Cross-Chain Bridge Vulnerabilities | Immunefi](https://medium.com/immunefi/common-cross-chain-bridge-vulnerabilities-d8c161ffaf8f)

### Reentrancy Variants
- [The Ultimate Guide To Reentrancy | Immunefi](https://immunefi.com/blog/expert-insights/ultimate-guide-to-reentrancy/)
- [The Potential Impact Of ERC-777 Tokens On DeFi Protocols | Immunefi](https://medium.com/immunefi/the-potential-impact-of-erc-777-tokens-on-defi-protocols-51cdb07be733)
- [Hack Analysis: Omni Protocol, July 2022 | Immunefi](https://medium.com/immunefi/hack-analysis-omni-protocol-july-2022-2d35091a0109)
- [Position Exchange's Re-Entrancy Loophole Explained | Amber Group](https://medium.com/amber-group/position-exchanges-re-entrancy-loophole-explained-ef176a0fd987)

### MEV & Price Manipulation
- [How To Reproduce A Simple MEV Attack | Immunefi](https://medium.com/immunefi/how-to-reproduce-a-simple-mev-attack-b38151616cb4)
- [Hack Analysis: 0xbaDc0dE MEV Bot, September 2022 | Immunefi](https://medium.com/immunefi/0xbadc0de-mev-bot-hack-analysis-30b9031ff0ba)

### Severity Classification & Guidelines
- [Immunefi Vulnerability Severity Classification System - v2.3](https://immunefi.com/immunefi-vulnerability-severity-classification-system-v2-3/)
- [Severity Classification System | Immunefi Support](https://immunefisupport.zendesk.com/hc/en-us/articles/13333032674961-Severity-Classification-System)

### PoC Requirements & Templates
- [Proof of Concept (PoC) Guidelines and Rules | Immunefi](https://immunefisupport.zendesk.com/hc/en-us/articles/9946217628561-Proof-of-Concept-PoC-Guidelines-and-Rules)
- [Immunefi PoC Templates](https://immunefi.com/blog/security-guides/immunefi-poc-templates/)
- [GitHub: immunefi-team/forge-poc-templates](https://github.com/immunefi-team/forge-poc-templates)
- [How to Submit Bug Reports That Get Paid | Immunefi](https://immunefi.com/blog/security-guides/how-to-submit-bug-reports-that-get-paid/)

### Submission Rules & Rejection Criteria
- [Bug Bounty Program and Report FAQs | Immunefi](https://immunefisupport.zendesk.com/hc/en-us/articles/7789428643217-Bug-Bounty-Program-and-Report-FAQs)
- [Summary of Resolving Reports and Closing Invalid Submissions | Immunefi](https://immunefisupport.zendesk.com/hc/en-us/articles/4419189092369-Summary-of-Resolving-Reports-and-Closing-Invalid-Submissions)
- [Immunefi Rules](https://immunefi.com/rules/)

### Whitehat Strategy & Success Tips
- [Your First Day As A Bug Bounty Hunter On Immunefi](https://immunefi.com/blog/all/first-day-bug-bounty-hunter/)
- [A Hacker's Guide to Submitting Bugs on Immunefi | Immunefi](https://medium.com/immunefi/a-hackers-guide-to-submitting-bugs-on-immunefi-1e6b7ada71a9)
- [From Audit Contests to Bug Bounties: Our Journey with Immunefi Audit Competitions](https://immunefi.com/blog/whitehat-spotlight/our-journey-with-immunefi-audit-competitions/)
- [Smart Contract Bug Bounties Statistics 2025 | SQ Magazine](https://sqmagazine.co.uk/smart-contract-bug-bounties-statistics/)

### Target Selection & ROI
- [Smart Contract Bug Hunting: 7 Strategies | Chainlink](https://blog.chain.link/smart-contract-bug-hunting/)
- [Where You'll Get the Best ROI Bughunting on Fuel's $1.3 Million Attackathon | Immunefi](https://medium.com/immunefi/where-youll-get-the-best-roi-bughunting-on-fuel-s-1-3-million-attackathon-e516f89bbfa7)

### Layer 2 & Bridge Programs
- [ZKsync Era Bug Bounties | Immunefi](https://immunefi.com/bug-bounty/zksyncera/information/)
- [Optimism Bug Bounties | Immunefi](https://immunefi.com/bug-bounty/optimism/information/)
- [StarkNet Bug Bounties | Immunefi](https://immunefi.com/bug-bounty/starknet/)
- [Wormhole Bug Bounties | Immunefi](https://immunefi.com/bug-bounty/wormhole/)
- [LayerZero Bug Bounties | Immunefi](https://immunefi.com/bug-bounty/layerzero/)

### Additional Resources
- [GitHub: Immunefi Bug Bounty Writeups List](https://github.com/sayan011/Immunefi-bug-bounty-writeups-list)
- [A DeFi Security Standard: The Scaling Bug Bounty | Immunefi](https://immunefi.com/blog/industry-trends/a-defi-security-standard-the-scaling-bug-bounty/)

---

**Last Updated**: 2026-02-16
**Next Review**: 2026-05-16 (quarterly update recommended)

---

## 7. 2025–2026 Updates

### 7.1 Verified Payouts (2024–2025, Publicly Confirmed)

| # | Protocol | Amount | Date | Vuln Type | Researcher | Source |
|---|----------|--------|------|-----------|------------|--------|
| 1 | **Raydium** (cp-swap) | **$505,000** | Mar 2025 | Liquidity drain — add_liquidity skipped token1 transfer, allowing pool drain after 18 iterations | @thel4stc0de | [Immunefi blog](https://immunefi.com/blog/all/raydium-liquidity-drain-bug-fix-review/) |
| 2 | **VeChainThor** | **50,000 USDT** | Dec 2024 | VTHO accrual bypass — self-destruct + flash loan combo allowed artificial VTHO minting | (not disclosed) | [Immunefi blog](https://immunefi.com/blog/all/vechainthor-vtho-accrual-bypass-bug-fix-review/) |
| 3 | **The Graph** | **$290,497** | Jan 2024 | Rounding error (×2) — `weightedAverage` without rounding-up caused loss of user funds/yield | @GregadETH | [Medium](https://medium.com/immunefi/the-graph-rounding-error-bugfix-review-c946ff470f65) |
| 4 | **Raydium** (AMM) | (undisclosed) | Jan 2024 | Tick manipulation — TickArrayBitmapExtension account not validated in increase_liquidity | @riproprip | [Medium](https://medium.com/immunefi/raydium-tick-manipulation-bugfix-review-c6aae4527ed6) |
| 5 | **Stacks** | **$76,011** | Nov 2023 | Critical DoS — layer-2 for Bitcoin, network-level denial of service | Catchme | [Medium](https://medium.com/immunefi/stacks-dos-bugfix-review-dc0f2a75b276) |

> **Note**: Many 2024–2025 payouts remain undisclosed per projects' Responsible Publication Policy. Amounts above are only from publicly confirmed Immunefi blog posts or official X/Twitter announcements. Unverified rumors (e.g., "$3M ily2 bounty") are excluded per policy — no official Immunefi blog post confirmed as of 2026-04-16.

### 7.2 Updated Platform Statistics (2025–2026)

| Metric | Value | As Of |
|--------|-------|-------|
| Total paid to whitehats | $110M+ | 2026 Q1 |
| Active programs | 650+ | Apr 2026 |
| Security researchers | 60,000+ | 2026 |
| Assets secured | $180B | 2026 Q1 |
| Estimated hacks prevented | $25B | 2026 |
| Available bounty pool | $162M+ | Apr 14, 2026 |

**IMU Token**: Immunefi launched its native token IMU in Jan 2026. Public sale (CoinList, Nov 2025) raised ~$5M at $0.01337/token. Trading began Jan 22, 2026 on Gate.io, Bybit, Bitget. Token utility includes staking for Magnus premium features and governance.
Source: [BlockEden](https://blockeden.xyz/blog/2026/01/25/immunefi-imu-token-web3-security-bug-bounty-platform/)

### 7.3 Current Highest Max Bounties (Active Programs, Apr 2026)

| Rank | Protocol | Max Bounty | Platform | Chain | Notes |
|------|----------|-----------|----------|-------|-------|
| 1 | **Uniswap v4** | **$15,500,000** | Immunefi | Multi | Critical: 10% TVL, $15.5M cap |
| 2 | **LayerZero** | **$15,000,000** | Immunefi | Multi | 10% of funds affected |
| 3 | **Wormhole** | **$10,000,000** | Immunefi | Multi | Bridge — historic $10M paid 2022 |
| 4 | **Sky (MakerDAO)** | **$10,000,000** | Immunefi | Multi | 10% TVL, up to $10M |
| 5 | **Usual** | **$16,000,000** | Sherlock | Multi | Largest single bounty in tech history (Mar 2026) |
| 6 | **Coinbase/Base** | **$5,000,000** | Cantina | Base/Multi | Launched Jul 2025 |
| 7 | **GMX** | **$5,000,000** | Immunefi | Arb/Avax | Perp DEX |
| 8 | **Morpho** | **$2,500,000** | Cantina | Multi | Lending |
| 9 | **Optimism** | **$2,000,042** | Immunefi | Ethereum L2 | Historic $2M paid 2022 |
| 10 | **Arbitrum** | **$2,000,000** | Immunefi | Ethereum L2 | — |
| 11 | **Lido** | **$2,000,000** | Immunefi | Multi | Staking |
| 12 | **Kamino** | **$1,500,000** | Immunefi | Solana | Active since Oct 2025 |
| 13 | **Chainlink** | **$3,000,000** | Immunefi | Multi | Oracle |
| 14 | **Olympus DAO** | **$3,333,333** | Immunefi | Multi | — |
| 15 | **Immutable** | **$1,000,000** | Immunefi | L2 | Launched with Immunefi 2025 |

Source: [Sherlock Best Web3 Bug Bounties 2026](https://sherlock.xyz/post/best-web3-bug-bounties-in-2026-the-highest-paying-programs-on-every-platform)

### 7.4 2025–2026 Trend Analysis

#### Emerging Attack Surfaces (High Research ROI)

1. **Solana native programs (non-EVM)** — Raydium cp-swap $505K payout (Mar 2025) signals underresearched Rust/Anchor programs. Fewer whitehats fluent in Solana runtime semantics vs EVM.

2. **ZK circuit constraint bugs** — ZK rollup prover/verifier logic remains the frontier. Missing constraints in ZK-SNARKs allow forged state transitions without triggering proof failure. Programs: ZKsync Era, StarkNet, Polygon zkEVM, zkVerify (new 2026).

3. **Intent/solver protocols** — New architecture (2024–2025 boom) with complex trust models between solvers, fillers, and users. Composability bugs across intent routing layers are poorly audited.

4. **Cross-chain bridge message validation** — Still high-value (Wormhole $10M precedent). LayerZero v2 endpoint logic, new bridge deployments remain active hunting ground.

5. **Liquid staking / restaking** — EigenLayer, Lido, Symbiotic restaking contracts have novel invariants around slashing, delegation, and withdrawal queues. Fresh code deployed 2024–2025.

6. **Firedancer (Solana validator client in C)** — New validator implementation. $500K max bounty active Jan 2026. Extremely underresearched — C codebase, non-Go/Rust.

#### Competitive Landscape Shift (2025–2026)

- **Sherlock stake-to-submit** model ($250 USDC deposit) reduces low-quality noise but creates friction for exploratory hunters.
- **Cantina** (Coinbase/Base $5M) now a legitimate third platform alongside Immunefi and Sherlock.
- **Immunefi Magnus** (AI triage tool, launched late 2025) uses LLM-assisted severity classification — affects how reports are initially scored before human review.
- **H1 2025 total Web3 losses**: $3B+ (worst half-year on record). Bounty hunting demand increasing proportionally.

#### Dead/Declining Targets (Remove from Pipeline)

- **Fei Protocol** — deprecated, protocol shut down.
- **Polygon PoS legacy contracts** — superseded by zkEVM; legacy scope narrowed significantly.
- **Aurora** — scope contracted after $6M payout; lower active TVL.

---

**Last Updated**: 2026-04-16
**Next Review**: 2026-07-16 (quarterly)
