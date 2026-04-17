## Program Overview
Immunefi bug bounty program for Utix — a decentralized ticketing protocol on Ethereum.
Platform: Immunefi. Rewards: $1,000–$100,000.

## Severity Scope
Critical

## In-Scope Assets
- UtixVault contract: 0x1234567890abcdef1234567890abcdef12345678 (Ethereum mainnet)
- UtixEscrow contract: 0xabcdef1234567890abcdef1234567890abcdef12 (Ethereum mainnet)
- UtixGovernance contract: 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef (Ethereum mainnet)

## Out-of-Scope
- Frontend web application vulnerabilities
- Issues requiring governance majority (51%+ token control)
- Economic attacks requiring more capital than the protocol's TVL
- Miner extractable value (MEV) attacks
- Gas griefing without fund loss
- Issues in third-party integrations (Chainlink, Uniswap)

## Asset Scope Constraints
Ethereum mainnet deployed contracts only.
Testnet-only issues are not eligible.
All findings must relate to the current mainnet deployment.

## Submission Rules
PoC must demonstrate the vulnerability on a mainnet fork.
All assertions must use on-chain state reads via eth_call or equivalent.
No mock contracts — must interact with real deployed contracts.
Coordinated disclosure mandatory.

## Impacts in Scope
- Unlocking stuck funds
- Protocol shutdown causing permanent fund loss

## Known Issues
- Minor rounding error in fee calculation (tracked, < $0.01 impact per transaction)
