# Example Audit Contest

Welcome to the Example audit contest. This is a 7-day engagement.

## Scope

- contracts/Vault.sol
- contracts/Oracle.sol
- contracts/Router.sol
- 0xabcdef1234567890abcdef1234567890abcdef12

## Out of Scope

- Third-party libraries (OpenZeppelin, Solmate)
- Documentation typos
- Gas optimizations that require unsafe assumptions
- Issues in test/ and script/ directories

## Known issues

- Known: Vault.getReserves may return stale data for 1 block
- Known: Router fee calculation uses unchecked math by design

## Rules

Report all findings through the contest platform. Every finding must include a clear PoC using Foundry or Hardhat. Duplicates are resolved by timestamp. Do not publicly disclose before the contest ends. Only findings within the scope listed above are eligible.

## Rewards

- Critical: $25,000
- High: $5,000
- Medium: $1,000
- Low: $250
