# New Immunefi Target Assessment
**Date**: 2026-02-17
**Scout**: target-scout
**Mission**: Find fresh high-ROI Immunefi targets matching Sweet Spot criteria

---

## Excluded (Already Analyzed)
- Olympus DAO — ABANDONED (mature, 22 leads → 0 HIGH/CRITICAL)
- GMX V2 — ABANDONED (all leads dead)
- Symbiotic — ABANDONED (0 Critical)
- Superform — ABANDONED (1 Medium only)
- USX Protocol — 2 reports ready (do not duplicate)
- stake.link — 1 MEDIUM ready (do not duplicate)

---

## Candidate Evaluation

### Candidate 1: Granite Protocol (Bitcoin DeFi on Stacks)

| Field | Data |
|-------|------|
| **Platform** | Immunefi — https://immunefi.com/bug-bounty/granite-protocol/ |
| **Max Bounty** | $150K critical (10% of affected funds, $1M hard cap) |
| **Launch Date** | Sep 2024 (Immunefi program: ~2025 Q1) |
| **Audit Count** | 2 audits (Clarity Alliance: Feb 2025, Jul 2025) |
| **Audit Firms** | Clarity Alliance only — niche firm, not Tier-1 |
| **TVL** | ~$11M (178 sBTC collateral) — small |
| **Tech Stack** | Clarity (Stacks) + sBTC bridge — NOT Solidity |
| **Competition Level** | Very low (Stacks niche, fewer researchers) |
| **Resolved Reports** | Unknown, likely very few |

**v4 Score Breakdown**:
- Age (< 6 months scope): +1 (relatively new)
- Audit count ≤ 2: +2
- Max bounty ≥ $50K: +2
- Audit firm quality: +1 (niche firm = less thorough)
- Bonus (novel sBTC bridge mechanic): +1
- **PENALTY**: NOT Solidity — our tools (Slither/Mythril) don't support Clarity: -3

**Total Score: 4/10**

**Verdict: CONDITIONAL GO (with caveat)**
- Our tooling is Solidity-first. Clarity (Stacks) requires different analysis approach.
- Slither/Mythril won't work. Manual Clarity review needed.
- Only viable if we can adapt methodology.
- **Recommended Attack Surface**: sBTC Lockbox integration, oracle manipulation (Pyth), liquidation logic edge cases

---

### Candidate 2: Paradex (Perp DEX on Starknet Appchain)

| Field | Data |
|-------|------|
| **Platform** | Immunefi — https://immunefi.com/bug-bounty/paradex/ |
| **Max Bounty** | $500K critical (10% of funds) |
| **Launch Date** | Bounty program expanded to $500K in early 2026 (X post Feb 2026) |
| **Audit Count** | 1-2 (Cairo Security Clan: ~85% codebase audited) |
| **Audit Firms** | Cairo Security Clan — specialized Cairo/Starknet auditors |
| **TVL** | Small (appchain, not standard DeFi TVL) |
| **Tech Stack** | Cairo (Starknet appchain) — NOT Solidity |
| **Competition Level** | Low-Medium (Cairo specialists only, very niche) |
| **Resolved Reports** | IOP competition ran, some findings expected |
| **Notable Event** | Bitcoin $0 glitch → mass liquidations (Jan 2026) — indicates oracle/price feed risk |

**v4 Score Breakdown**:
- Age (bounty program expansion 2026): +2
- Audit count ≤ 2: +2
- Max bounty ≥ $50K ($500K): +3
- Novel mechanics (ZK appchain perps): +1
- **PENALTY**: Cairo language — not Solidity, our tooling doesn't apply: -3
- **PENALTY**: Jan 2026 incident may have attracted attention/patches: -1

**Total Score: 4/10**

**Verdict: CONDITIONAL GO (with caveat)**
- High bounty and low competition, but Cairo language is a major blocker for our tools.
- January 2026 BTC $0 incident shows real oracle risk exposure — potential findings if oracle/liquidation logic is investigated.
- **Recommended Attack Surface**: Oracle price feed validation, liquidation cascade logic, cross-chain settlement

---

### Candidate 3: Stargate Finance V2 (Cross-Chain Bridge)

| Field | Data |
|-------|------|
| **Platform** | Immunefi — https://immunefi.com/bug-bounty/stargate/ |
| **Max Bounty** | $15M (via LayerZero BBP, Stargate = $10M own cap) |
| **Launch Date** | March 2025 (Immunefi program) — V2 live May 2024 |
| **Audit Count** | 3+ (Zelliz, Zokyo, Quantstamp + V2 audits) |
| **Audit Firms** | Multiple Tier-1 firms |
| **TVL** | $500M+ (major cross-chain bridge) |
| **Tech Stack** | Solidity (EVM) — matches our tooling |
| **Competition Level** | HIGH (major bridge, many researchers) |
| **Resolved Reports** | Unknown but likely high (large program, $65B+ transfers) |
| **Note** | Re-acquired by LayerZero Labs Aug 2025 — potential new code |

**v4 Score Breakdown**:
- Age (V2 May 2024, but 9 months old): +1
- Audit count 3+: -3 (automatic penalty)
- Max bounty ≥ $50K: +3
- TVL: +1
- Solidity tools apply: +2
- Cross-chain complexity (bonus signals): +1
- Competition penalty: -2

**Total Score: 3/10**

**Verdict: NO-GO**
- 3+ audit firms = automatic -3 penalty. Heavy competition.
- Already heavily scrutinized. Risk/reward poor.

---

### Candidate 4: Parallel Protocol (Modular Stablecoin)

| Field | Data |
|-------|------|
| **Platform** | Immunefi — https://immunefi.com/bug-bounty/parallel/ |
| **Max Bounty** | $250K critical (10% of funds) |
| **Launch Date** | Oct 2, 2025 (very fresh!) |
| **Audit Count** | 2 (Bailsec + Certora — Jan 2025) |
| **Audit Firms** | Bailsec + Certora |
| **TVL** | Unknown (new protocol) |
| **Tech Stack** | Solidity (Ethereum + Polygon PoS) — matches our tooling |
| **Competition Level** | Low (launched Oct 2025, few reports) |
| **Resolved Reports** | Likely very few (< 4 months old) |
| **Protocol Type** | Over-collateralized stablecoin (EUR + USD) — modular design |

**v4 Score Breakdown**:
- Age (< 6 months, Oct 2025): +3
- Audit count ≤ 2: +2
- Max bounty ≥ $50K ($250K): +2
- Solidity tools fully applicable: +2
- Low competition (fresh program): +2
- Modular architecture (novel attack surface): +1
- Certora formal verification may catch some bugs: -1

**Total Score: 11/10 → capped at 10**

**Verdict: GO (8/10)**
- Fresh program (4 months old), Solidity, low competition.
- Certora did formal verification but modular/DAO plug-in architecture introduces composition bugs.
- **Recommended Attack Surface**:
  - Module interaction bugs (DAO adding/removing modules)
  - Stablecoin redemption path edge cases
  - Oracle manipulation for PAR/paUSD collateral pricing
  - Polygon PoS vs Ethereum state divergence
  - Liquidity/arbitrage between EUR and USD stablecoins

---

### Candidate 5: Folks Finance (Algorand DeFi — Wormhole NTT)

| Field | Data |
|-------|------|
| **Platform** | Immunefi — https://immunefi.com/bug-bounty/folksfinance/ |
| **Max Bounty** | $200K (Algorand Foundation matches 100%) |
| **Launch Date** | Active 2022, Wormhole NTT audit Nov 2025 |
| **Audit Count** | 3 (Runtime Verification, Coinspect, Vantage Point) |
| **Audit Firms** | Multiple firms |
| **TVL** | Unknown |
| **Tech Stack** | Algorand (AVM) + cross-chain — NOT Solidity primarily |
| **Competition Level** | Low (Algorand niche) |
| **Resolved Reports** | Multiple competitions completed |

**v4 Score Breakdown**:
- Age: 0 (mature platform since 2022)
- Audit count 3+: -3
- Max bounty ($200K): +2
- NOT Solidity (Algorand): -2
- Low competition: +1

**Total Score: -2/10**

**Verdict: NO-GO**
- Too many audits, Algorand language not our strength, mature platform.

---

### Candidate 6: USDT0 (Tether Cross-Chain via LayerZero OFT)

| Field | Data |
|-------|------|
| **Platform** | Immunefi — https://immunefi.com/bug-bounty/usdt0/ |
| **Max Bounty** | Unknown (critical = USDT redemption impact) |
| **Launch Date** | 2025 (relatively new OFT deployment) |
| **Audit Count** | Multiple (Everdawn/GitHub listed) |
| **Audit Firms** | Unknown Tier |
| **TVL** | High (USDT is major stablecoin) |
| **Tech Stack** | Solidity (LayerZero OFT v2) |
| **Competition Level** | High (Tether = major target) |
| **Resolved Reports** | Unknown |
| **Note** | Scope: Only ETH Lockbox exploitation or unbacked minting |

**v4 Score Breakdown**:
- Age (OFT deployment 2025): +1
- Audit count unknown but likely 2+: 0
- Max bounty: moderate +1
- Solidity: +2
- Competition (Tether = high-value target): -2
- Very narrow scope: -1

**Total Score: 1/10**

**Verdict: NO-GO**
- Scope is extremely narrow (only ETH Lockbox exploits qualify).
- LayerZero overlapping bounty complicates attribution.

---

### Candidate 7: zkVerify (ZK Proof Verification Protocol)

| Field | Data |
|-------|------|
| **Platform** | Immunefi — https://immunefi.com/bug-bounty/zkverify/ |
| **Max Bounty** | $50K |
| **Launch Date** | Sep 5, 2025 (fresh!) |
| **Audit Count** | 1 (implied by launch date) |
| **Audit Firms** | Unknown |
| **TVL** | N/A (infrastructure, not DeFi) |
| **Tech Stack** | ZK circuits + Substrate (Rust) — not Solidity |
| **Competition Level** | Very low (ZK circuit specialists) |
| **Protocol Type** | Modular proof verification infrastructure |

**v4 Score Breakdown**:
- Age (Sep 2025): +3
- Audit count ≤ 1: +3
- Max bounty $50K (minimum threshold): +1
- NOT Solidity (ZK circuits/Substrate): -3
- Low competition: +2

**Total Score: 6/10**

**Verdict: CONDITIONAL GO**
- Fresh program, very low competition, but max bounty only $50K and requires ZK circuit expertise.
- **Recommended Attack Surface**: Proof verifier bypass, circuit constraint violations, cross-chain proof relay

---

## Summary Ranking Table

| Rank | Protocol | Score | Verdict | Max Bounty | Age | Audit Count | Solidity? |
|------|----------|-------|---------|------------|-----|-------------|-----------|
| 1 | **Parallel Protocol** | 10/10 | **GO** | $250K | Oct 2025 (4mo) | 2 | YES |
| 2 | **Paradex** | 4/10 | COND GO | $500K | 2026 expansion | 1-2 | NO (Cairo) |
| 3 | **Granite Protocol** | 4/10 | COND GO | $150K | 2025 | 2 | NO (Clarity) |
| 4 | **zkVerify** | 6/10 | COND GO | $50K | Sep 2025 | 1 | NO (ZK/Rust) |
| 5 | Stargate V2 | 3/10 | NO-GO | $10M cap | Mar 2025 | 3+ | YES |
| 6 | USDT0 | 1/10 | NO-GO | Unknown | 2025 | 2+ | YES |
| 7 | Folks Finance | -2/10 | NO-GO | $200K | 2022 | 3+ | NO |

---

## Final Recommendation

### PRIMARY TARGET: Parallel Protocol (paUSD/PAR Stablecoin)

**Why Parallel Protocol is the best option:**
1. **Launched Oct 2, 2025** — only 4.5 months old, very low competition
2. **Solidity on Ethereum + Polygon** — all our tools (Slither, Mythril, CodeQL, Foundry fork) apply
3. **$250K max bounty** — well above $50K threshold
4. **2 audits (Bailsec + Certora)** — Certora covers formal verification of mathematical invariants, but NOT composition logic between modules
5. **Modular DAO architecture** — modules can be added/removed by DAO, creating novel attack surfaces not covered in standard audits
6. **Dual stablecoin (EUR + USD)** — cross-stablecoin arbitrage paths + oracle dependencies
7. **Low resolved reports** (< 4 months since launch)

**Recommended Focus Areas:**
- Module interaction bugs when DAO adds/removes modules mid-operation
- Stablecoin minting/redemption edge cases (especially during Polygon ↔ Ethereum bridge)
- Oracle manipulation for collateral pricing (PAR/paUSD)
- Certora-verified invariants: look for edge cases that formal spec missed (composability gaps)
- Reentrancy in modular plug-in architecture

### SECONDARY TARGET: zkVerify (if we want non-Solidity diversification)

**Why zkVerify as secondary:**
- Sep 2025 launch, very likely only 1 audit
- Extremely low competition (ZK circuit specialists needed)
- $50K max is low but risk/reward is good given near-zero competition
- Can use Semgrep + CodeQL for Rust/circuit analysis
- Novel finding potential: ZK proof verifier bypass could be a landmark report

---

## Action Items for Next Phase

1. **Parallel Protocol — Phase 0: Target Intelligence**
   - `target_evaluator` → score the program formally, fetch scope details
   - Key questions: exact audit scope, which modules are in scope, Polygon vs ETH diff

2. **Parallel Protocol — Phase 0.5: Tool Scan**
   - Clone repo: https://github.com/parallelprotocol (or docs link)
   - Run Slither on all contracts
   - Run Mythril on stablecoin minting/redemption paths
   - Semgrep for reentrancy + oracle patterns

3. **zkVerify — Optional Secondary**
   - Only pursue if Parallel Protocol shows ABANDON signals after full tool scan

---

## Sources
- [Immunefi Bug Bounty Programs](https://immunefi.com/bug-bounty/)
- [Parallel Bug Bounties | Immunefi](https://immunefi.com/bug-bounty/parallel/)
- [Granite Protocol Bug Bounties | Immunefi](https://immunefi.com/bug-bounty/granite-protocol/)
- [Paradex Bug Bounties | Immunefi](https://immunefi.com/bug-bounty/paradex/)
- [zkVerify Bug Bounties | Immunefi](https://immunefi.com/bug-bounty/zkverify/)
- [Stargate Bug Bounties | Immunefi](https://immunefi.com/bug-bounty/stargate/)
- [USDT0 Bug Bounties | Immunefi](https://immunefi.com/bug-bounty/usdt0/information/)
- [Folks Finance Bug Bounties | Immunefi](https://immunefi.com/bug-bounty/folksfinance/)
- [Granite Audits & Bug Bounty](https://docs.granite.world/protocol-information/audits-and-bug-bounty)
- [Lombard Finance Bug Bounties | Immunefi](https://immunefi.com/bug-bounty/lombard-finance/)
- [Smart Contract Bug Bounties Statistics 2026 | CoinLaw](https://coinlaw.io/smart-contract-bug-bounties-statistics/)
