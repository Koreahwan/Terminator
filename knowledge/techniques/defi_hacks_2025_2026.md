# DeFi Hacks — Root Cause Analysis (2024-2026)

> **Research / audit 참조용**. 각 사고의 공식 postmortem, Etherscan tx, 감사 보고서
> 링크가 검증되지 않은 경우 "출처 필요" 표기. Foundry fork PoC는
> `knowledge/techniques/web3_foundry_fork_poc.md` 참조.

---

## 1. 사고 요약 (2024-2026)

| 날짜 | 프로토콜 | 금액 | 체인 | 근본 원인 카테고리 | Postmortem 유효 |
|------|----------|------|------|--------------------|-----------------|
| 2024-02 | PlayDapp | ~$290M | Ethereum | 서명키 유출 (admin key) | Yes |
| 2024-05 | Sonne Finance | ~$20M | Optimism | Empty market 초기 가격 조작 | Yes (공식) |
| 2024-05 | DMM Bitcoin | ~$305M | CEX(off-chain) | 거래소 운영 실패 (참고용) | Partial |
| 2024-06 | UwU Lend | ~$20M | Ethereum | Oracle 조작 (sUSDe price) | Yes |
| 2024-07 | WazirX | ~$234M | CEX | Multisig UI 속임수 (Liminal) | Yes |
| 2024-08 | Ronin Bridge (white hat) | ~$12M 반환 | Ronin | Gas token 추출 버그 | Yes |
| 2024-09 | Penpie | ~$27M | Ethereum | Reentrancy via custom market 등록 | Yes |
| 2024-10 | Radiant Capital | ~$50M+ | Arbitrum/BSC | Multisig device compromise + front-end swap | Yes |
| 2025-02 | Bybit | ~$1.46B | CEX | Cold wallet UI phishing (Lazarus) | Yes |
| 2025-03 | Abracadabra / Magic Internet Money | ~$13M | Ethereum | 회계 오류 (collateral/borrow 불일치) | Yes |
| 2025-04 | Loopscale | ~$5.7M | Solana | 가격 피드/유동성 설계 | Yes |
| 2025-05 | Cetus Protocol | ~$220M | Sui | AMM 유동성 산식 overflow/underflow | Yes |

(참고: 최신 사고 확인 시 `rekt.news`, `slowmist.com/security-disclosure`, `defihacklabs` 교차 검증.)

---

## 2. 근본 원인별 사례 분석

### 2.1 Oracle 조작 (spot + TWAP)
**대표**: UwU Lend (2024-06)
- LP 토큰 price oracle이 단일 pool 기반 → flashloan으로 pool 편향 → oracle이 부풀린 가격 반환 → 과다 borrow
- **헌터 교훈**: LP 토큰/synthetic asset을 담보로 쓰는 lending protocol에서 price source 1개당 **manipulation cost** 계산
- 탐지 신호: `getPrice()`가 단일 pair 의존, manipulation resistant 매커니즘(TWAP, chainlink fallback) 없음

### 2.2 Empty Market / First Depositor
**대표**: Sonne Finance (2024-05, Compound v2 fork)
- 새 market 생성 직후 totalSupply=0 상태에서 소량 deposit + 대량 underlying 기부 → exchangeRate 인위적 증가 → 이후 사용자 deposit 회수 불가
- **헌터 교훈**: Compound v2 fork에서 새 시장 추가 직후 governance/multisig가 "burn minimum" step을 수행했는지 확인
- 재사용: 모든 Compound/Aave v2 fork, Morpho 구버전, Benqi

### 2.3 Reentrancy (cross-function, read-only, ERC-777)
**대표**: Penpie (2024-09)
- 공격자가 임의 Pendle market을 직접 등록할 수 있는 공개 함수 호출 → 자신의 reward receiver 계약에서 reentrant 호출 → reward 누적 오류
- **헌터 교훈**:
  - 사용자 제공 market/asset/token 주소를 신뢰 경계로 처리하는지 확인
  - ERC-777 또는 ERC-4626 기반 vault의 `onTokenTransfer`/`tokensReceived` hook
  - Read-only reentrancy: view 함수가 invariant 깨진 state 반환 (Curve Vyper 0.2.x 사고의 계보)

### 2.4 AMM Math / Invariant Break
**대표**: Cetus Protocol (2025-05)
- 집중 유동성 AMM의 tick math에서 overflow/underflow → 소액으로 거대 유동성 추출
- **헌터 교훈**: Uniswap v3, Raydium CLMM 등 fork에서 tick 연산, Q64.96/Q32.32 고정소수점 경로 audit
- 재사용: concentrated liquidity 코드에서 `toUint128` cast, `mulDiv` overflow

### 2.5 Multisig / Key Management
**대표**: Radiant Capital (2024-10), Bybit (2025-02)
- Ledger/hardware-wallet 사용자가 "blind signing" 상태에서 malicious transaction 서명
- UI는 합법적 콜데이터 표시, 실제 온체인 콜데이터는 다름 (proxy/eip1271 구조 악용)
- **헌터 교훈**: 사용자 서명 흐름의 UI vs on-chain calldata mismatch 탐지. Bounty 관점에서는 front-end/UX 버그보다는 smart contract 내부에서 signer의 의도와 실제 state 변화 간 gap 집중

### 2.6 Accounting / 상태 동기화 오류
**대표**: Abracadabra (2025-03)
- Cauldron의 collateral 잔고와 borrow 잔고 간 동기화 오류로 존재하지 않는 부채 상환/청산
- **헌터 교훈**: 다중 상태 변수(`totalSupply`, `totalBorrow`, `elastic`, `base` 등)의 update 순서 — 중간 revert 경로에서 한 변수만 업데이트 발생 여부

### 2.7 Signature / Permit 관련
- **EIP-2612 permit signature replay**: chainId 미포함, deadline 과도, nonce 재사용
- **EIP-712 도메인 분리**: cross-chain replay
- **cheap sig**: ecrecover가 0x0 주소 리턴하는 malformed sig 처리

### 2.8 Access Control Misconfig
- **Proxy admin overlap**: `upgradeTo` 호출 가능 주소 = 일반 사용자 함수 주소 범위 포함
- **Initializer missing**: `__Ownable_init` 미호출 → 누구나 owner 설정 가능 (Wormhole 2022 사고 계보)
- **Role admin 체인**: `DEFAULT_ADMIN_ROLE`의 `grantRole` 제한 없음

---

## 3. Foundry Fork PoC 템플릿

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";

interface IVictim {
    function deposit(uint256) external;
    function borrow(uint256) external;
}

contract ExploitPoC is Test {
    IVictim constant VICTIM = IVictim(0x000000000000000000000000000000000000dEaD);

    function setUp() public {
        // 사건 발생 직전 블록으로 fork
        vm.createSelectFork("mainnet", 20_123_456);
    }

    function test_exploit() public {
        // 1. 초기 상태 스냅샷
        // 2. Flashloan 또는 매니퓰레이션
        // 3. victim 함수 호출
        // 4. 결과 assertion (실제 on-chain state read, 산술 추정 금지)
        assertGt(address(this).balance, 1_000_000 ether, "exploit profit check");
    }
}
```

**IRON RULE** (from `feedback_poc_quality_ironrules.md`):
- try/except 0개 (인프라 셋업 제외)
- fallback/hardcoded 값 대체 금지
- 모든 assertion은 on-chain state read 기반
- "arithmetic simulation"이 아닌 "demonstrated exploit"

---

## 4. 헌터 탐색 가이드 (신규 타겟 적용)

### 4.1 오라클 의존성 검사 순서
1. 프로토콜의 `priceFeed`/`oracle` 변수 모두 grep
2. 각 oracle 구현의 `latestAnswer` 호출 경로 추적
3. manipulation cost 계산 (pool 깊이, TWAP window, fallback 조건)
4. 단일 pool 의존 + TWAP 없음 = P1 후보

### 4.2 Compound/Aave fork 체크
1. `comptroller.supportMarket()` 또는 유사 등록 함수의 접근 제어
2. 초기화 시 minimum liquidity burn 여부
3. Collateral factor, close factor 설정의 governance delay
4. 새 시장 추가 직후 공격 시점 존재

### 4.3 Reentrancy guard 패턴
1. `nonReentrant` modifier 범위 (cross-function reentrancy 방지 필요)
2. `view` 함수가 state 중간 변경 시점에도 정확한지 (read-only reentrancy)
3. 외부 호출 → state update 순서 (Checks-Effects-Interactions 위반)

### 4.4 Upgradeable proxy 체크
1. `__Ownable_init` 같은 initializer가 deployment tx에서 호출됐는지 Etherscan에서 확인
2. `implementation()` 주소의 `initialize()` 직접 호출 가능 여부
3. Proxy admin 과 실제 사용자 기능 라우팅 분리 검증 (UUPS 함정)

---

## 5. Evidence Tier (Foundry PoC)

| Tier | 조건 |
|------|------|
| E1 | fork mainnet에서 `forge test -vvv` 실행 시 profit assertion 성공, tx trace + state diff 로그 캡처 |
| E2 | fork에서 state 조작은 성공하지만 최종 profit 계산이 가정값 사용 |
| E3 | 수학적 모델링만 (Python/TS simulation) |
| E4 | 소스 리뷰 추정 |

---

## 6. 참조

- **Rekt** — https://rekt.news (postmortem 집계, P1 판단 기준)
- **SlowMist** — https://hacked.slowmist.io (사고 DB)
- **DeFiHackLabs** — https://github.com/SunWeb3Sec/DeFiHackLabs (Foundry PoC 아카이브)
- **BlockSec / PeckShield** — 실시간 incident alert
- **Chainalysis Crypto Crime Report** (연간)
- **Immunefi Hack Analysis** — 프로그램별 사후 분석 블로그

---

## 7. 파이프라인 연계

- **analyst(domain=defi)**: 본 문서 섹션 2의 근본 원인 체크리스트 활용
- **exploiter**: 섹션 3 Foundry PoC 템플릿 복사 후 타겟별 수정
- **critic**: 섹션 4의 헌터 가이드와 대조하여 missing check 식별
- **Gate 2**: PoC가 on-chain state read로 assertion 하는지 검증 (강제)

마지막 업데이트: 2026-04-16
> **주의**: 표의 금액/날짜/체인은 2026-04-16 기준 공개 자료 기반 요약. 제출 전 해당 postmortem URL을 직접 WebFetch(r.jina.ai)로 재검증 필수.
