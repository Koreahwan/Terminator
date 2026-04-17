## Program Overview
Immunefi bug bounty program for Okto — a Web3 wallet and DeFi onboarding SDK.
Platform: Immunefi. Rewards: $500–$50,000.

## Severity Scope
Critical, High, Medium

## In-Scope Assets
- app.okto.tech (main web application)
- api.okto.tech (REST API)
- Okto smart contracts (deployed on Polygon mainnet, listed below)

## Out-of-Scope
- onboarding.okto.tech (not in scope — this is not a wildcard scope)
- Third-party SDK components not developed by Okto
- Issues requiring physical device access
- Issues in decommissioned or legacy endpoints
- Social engineering attacks
- Rate limiting without demonstrated impact

## Asset Scope Constraints
Only the specific domains listed under In-Scope Assets are covered.
Wildcard domains are NOT included — each asset must be explicitly listed.
Smart contracts: only mainnet-deployed contracts at the addresses listed in program page.

## Submission Rules
Reports must include a working proof-of-concept.
Submissions for out-of-scope assets will be immediately closed.
Do not submit reports for assets not explicitly listed as in-scope.
Include affected contract address and transaction hash for on-chain findings.

## Known Issues
- OAuth redirect on legacy login flow (tracked, fix in progress)

## Impacts in Scope
- Direct theft of any user funds
- Permanent freezing of funds
- Unauthorized minting or burning of tokens
- Manipulation of user session tokens leading to account takeover
