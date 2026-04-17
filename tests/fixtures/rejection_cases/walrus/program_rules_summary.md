## Program Overview
Immunefi bug bounty program for Walrus — a decentralized storage protocol on Sui.
Platform: Immunefi. Rewards: $5,000–$500,000.

## Severity Scope
Critical only

## In-Scope Assets
- Walrus storage node contracts (Sui mainnet, mainnet tags only)
- Walrus aggregator contracts (Sui mainnet, mainnet tags only)
- walrus-core module (mainnet and testnet tagged releases only)

## Out-of-Scope
- Issues present only in main branch but not in any tagged release
- Frontend and dashboard vulnerabilities
- Issues in documentation or comments only
- Gas optimization suggestions
- Theoretical attacks without PoC
- Issues requiring node operator collusion

## Asset Scope Constraints
Tagged releases only: mainnet tags and testnet tags.
Code present only in the main branch (not yet released) is explicitly out of scope.
Verify affected file exists in scoped version: git checkout <mainnet-tag> -- <file>

## Submission Rules
All submissions must include a working PoC against a tagged release.
CVSS 4.0 scoring preferred.
Move language expertise required — do not submit findings without understanding Move semantics.
Maximum response time: 7 days for Critical.

## Known Issues
- slashing.move validator penalty calculation: known edge case under investigation (not in scope for bounty)
