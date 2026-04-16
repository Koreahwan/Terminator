# Immunefi Report Style Guide

## Platform Characteristics
- **Focus**: DeFi / Smart Contracts / Blockchain
- **Taxonomy**: Impact-based (Critical/High/Medium/Low) + CVSS
- **PoC requirement**: Secret Gist or private repo (NOT public)
- **AI detection**: Strong — highest scrutiny for AI-generated reports
- **Bounty range**: $1K - $10M+ (proportional to funds at risk)
- **Triage**: Specialized Web3 security engineers

## Preferred Format

### Title
- Pattern: `[Impact] in [Contract/Protocol] via [MechanismType]`
- Example: `Fund drainage in StakePool.sol via reentrancy in withdraw()`

### Structure (Immunefi-optimized order)
1. **Brief/Intro** (what contract, what's broken, funds at risk)
2. **Vulnerability Details**
   - Exact function, line number, contract address
   - Solidity/Vyper code snippet with vulnerability highlighted
   - Call trace showing exploitation path
3. **Impact**
   - Quantified: TVL at risk, affected users
   - On-chain evidence: `cast call` results
   - Mainnet fork reproduction
4. **Proof of Concept**
   - Foundry test or Hardhat script
   - Must work on mainnet fork: `forge test --fork-url`
   - Secret Gist link (NOT public repo)
5. **Remediation**
   - Exact code fix with before/after
   - Consider CEI pattern, reentrancy guards, access control

### Tone
- Extremely technical, zero fluff
- On-chain evidence is king
- "This test demonstrates..." not "We discovered..."
- Quantify everything: ETH amounts, block numbers, gas costs

### AI Detection Avoidance
- Immunefi has strongest AI detection among platforms
- Every sentence MUST have contract-specific detail
- No generic blockchain security advice
- Include exact storage slot values, block numbers, tx hashes
- Forge test output is the best evidence format

### Common Mistakes (Immunefi-specific)
- Public PoC (must be Secret Gist) — violates responsible disclosure
- Testing on mainnet instead of fork
- Missing funds-at-risk quantification
- Reporting known issues from audit reports
- OOS: reporting on contract not listed in scope
