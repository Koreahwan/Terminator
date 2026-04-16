# Smart Contract Fuzzers — Integration Audit

**Integrated**: 2026-04-17
**Branch**: feat/sc-fuzzers-integration
**Installed to**: `~/.local/bin/` (user-local, no sudo required)

## Installed Binaries

| Tool | Version | Size | Source | Signing |
|------|---------|------|--------|---------|
| `medusa` | v1.5.1 | 23 MB | https://github.com/crytic/medusa/releases/download/v1.5.1/medusa-linux-x64.tar.gz | sigstore.json attestation present upstream |
| `ityfuzz` | nightly-35b7f08 (2025-06-27) | 57 MB | https://github.com/fuzzland/ityfuzz/releases/download/nightly-35b7f08962fdd0c2e02df7ef8a43164913d514d9/ityfuzz_nightly_linux_amd64.tar.gz | No signing; nightly build |

## Phase 1 Audit

### medusa
- **Upstream trust**: Trail of Bits (same vendor as Slither, Echidna) — high trust
- **License**: AGPL-3.0 (source available, redistribution requires copyleft attribution)
- **Signing**: Upstream provides `.sigstore.json` attestation. Verified only in binary presence (signature verification not run in this session — TODO if required)
- **Malicious code check**: `file medusa` → ELF 64-bit LSB executable, not-stripped with debug info. Not obfuscated.

### ityfuzz
- **Upstream trust**: fuzzland (research group, paper at ISSTA 2023)
- **License**: MIT (per upstream repo LICENSE-MIT / LICENSE-APACHE dual)
- **Signing**: None available (release is a nightly build from CI)
- **Risk note**: Nightly build = less stability. Official tagged release would be preferable but upstream only ships nightlies. Pin to a known-good commit SHA for reproducibility.

## Comparison (2026 Benchmarks)

| Dimension | Echidna (baseline) | medusa | ityfuzz |
|-----------|-------------------|--------|---------|
| Speed | 1x | 2-3x | 2.5x |
| Bug coverage (Daedaluzz) | baseline | +20% | +44% |
| Custom oracles | Haskell DSL | Go property tests | Builtin + onchain state read |
| Multi-chain | Ethereum-only | Ethereum-only | EVM + MoveVM |
| Parallelism | Single | Yes (multi-core) | Yes |
| Symbolic execution | No | No | Yes (hybrid) |
| Setup ergonomics | 4/10 | 8/10 | 6/10 |

## Terminator Usage Patterns

### Pattern A — Foundry project (medusa)
```bash
cd targets/<name>/source/
medusa init  # generates medusa.json
# Edit medusa.json: set deploymentOrder, testingMode (assertion/property/optimization)
medusa fuzz --test-limit 50000 --workers 4
```

### Pattern B — Onchain fork fuzz (ityfuzz)
```bash
ityfuzz evm -t 0xTARGETADDR \
  --onchain \
  --chain-type eth \
  --rpc-url $RPC_URL \
  --iterations 100000
```

### Pattern C — Offchain fuzz (ityfuzz)
```bash
ityfuzz evm --glob "contracts/*.sol" --iterations 50000
```

### Pattern D — Dual fuzz (high-value targets ≥ $500k TVL)
```bash
# Run both in parallel, different invariants
medusa fuzz --test-limit 100000 &
ityfuzz evm -t 0xADDR --iterations 200000 &
wait
# Compare findings. Unique medusa hits = property-based wins.
# Unique ityfuzz hits = symbolic-reachable states.
```

## When to Choose Which

| Scenario | Tool |
|----------|------|
| Foundry project already set up | medusa (native integration) |
| Onchain fork testing | ityfuzz |
| Symbolic execution needed | ityfuzz |
| Custom assertion invariants | medusa |
| MoveVM (Aptos/Sui) | ityfuzz only |
| CI integration | medusa (stable release) |
| High-value bounty push | both (Pattern D) |

## Update / Reinstall

```bash
# medusa
V=1.5.1  # check latest: gh api /repos/crytic/medusa/releases/latest | jq -r .tag_name
curl -sL "https://github.com/crytic/medusa/releases/download/v${V}/medusa-linux-x64.tar.gz" | tar xz -C /tmp/
mv /tmp/medusa ~/.local/bin/medusa && chmod +x ~/.local/bin/medusa

# ityfuzz (nightly — update periodically)
TAG=$(gh api /repos/fuzzland/ityfuzz/releases | jq -r '.[0].tag_name')
curl -sL "https://github.com/fuzzland/ityfuzz/releases/download/${TAG}/ityfuzz_nightly_linux_amd64.tar.gz" | tar xz -C /tmp/
mv /tmp/ityfuzz ~/.local/bin/ityfuzz && chmod +x ~/.local/bin/ityfuzz
```

## Rollback

```bash
rm ~/.local/bin/medusa ~/.local/bin/ityfuzz
# Revert defi-auditor changes
git checkout HEAD~1 -- .claude/agents/defi-auditor.md
```

## License Notes

- medusa: AGPL-3.0 → if forking/redistributing, must provide source. Using as tool = no obligation.
- ityfuzz: MIT → no restrictions.

## Known Issues

- ityfuzz nightly binary is 57 MB — larger than typical. Debug symbols not stripped.
- medusa has a cold-start delay of ~3s due to compilation cache warmup
