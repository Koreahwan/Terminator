## Program Overview
Immunefi bug bounty program for Paradex — a decentralized perpetual exchange on StarkNet.
Platform: Immunefi. Rewards: $1,000–$100,000.

## Severity Scope
Critical, High

## In-Scope Assets
- Paradex vault contracts (StarkNet mainnet)
- ParaclearVault: 0x050d...cafe (StarkNet mainnet)
- Paraclear settlement module (StarkNet mainnet)
- Paradex price oracle integration (StarkNet mainnet)

## Out-of-Scope
- Frontend application vulnerabilities
- Mock contract testing — PoC must use real deployed contracts
- Issues requiring oracle manipulation by Paradex itself
- Theoretical price manipulation without demonstrated on-chain impact
- Gas cost increases without fund loss

## Asset Scope Constraints
StarkNet mainnet only.
All PoC must interact with real deployed contracts — no mock contracts or simulated environments.
Use starknet_call for all on-chain reads; no Python arithmetic substitution.

## Submission Rules
PoC must fork mainnet or run against live StarkNet mainnet.
All assertions must be based on starknet_call or equivalent on-chain RPC reads.
No try/except blocks in attack logic — exceptions must surface as PoC failures.
No hardcoded fallback values — if the exploit fails, the PoC must fail.
Coordinated disclosure mandatory.

## Known Issues
- Vault donate() share rounding: known precision issue, fix scheduled for Q3
