# Scenario: Signature Replay (EIP-712 / Permit / Cross-chain)

> 서명 기반 권한/의도 전달 구조의 체인 간/시간 간 재사용.

## 1. Threat Model
- **타겟**: EIP-2612 permit, ERC-1271, meta-tx relayer, gasless trade, cross-chain bridge signing
- **공격자**: mempool 관찰 가능 unauthenticated + 때로는 서명 소유자의 타 체인 활동 관찰
- **Impact**: unauthorized 자금 이동, 주문 이중 체결, 권한 상승
- **Severity**: High (단일 서명), Critical (대량 replay 경로)

## 2. Discovery Signals
- `ecrecover` / `SignatureChecker.isValidSignatureNow` 직접 사용
- `DOMAIN_SEPARATOR`에 `chainid`/`verifyingContract` 누락
- Nonce 구조 부재 또는 사용자별 하나의 전역 nonce
- `deadline` 체크 없음 또는 매우 긴 값
- 같은 signed struct를 여러 체인에 배포된 동일 address 계약에서 수락
- `s` 값 malleability 체크 없음 (pre-EIP-2 지원)

## 3. Exploit Chain

### 3.1 Cross-chain replay
```
A. 체인 A에서 합법 tx 관찰 → signed message 추출 (calldata에 포함되거나 off-chain API 노출)
B. 같은 signer가 체인 B에 동일 nonce를 가질 확률 확인
C. 체인 B의 동일 contract address에 replay → 실행 성공 시 자금 이동
```

### 3.2 Nonce reuse (동일 체인 내)
```
A. 플랫폼이 nonce를 사용자 단위로 단조 증가시키지 않음
B. off-chain order book에서 cancel된 서명도 on-chain에서는 여전히 valid
C. Mempool에서 관찰 → 수락
```

### 3.3 Permit exfiltration
```
A. 사용자가 UI에서 "approve" 대신 "permit" 서명 (gas saving)
B. 서명된 permit 메시지가 dApp 서버 DB에 저장 또는 noised API 노출
C. 공격자가 DB 유출/API 접근 → permit 실행 → approve + transferFrom 조합 → 자금 탈취
```

## 4. PoC Template
```solidity
// Foundry: cross-chain replay
function test_replay() public {
    bytes memory sig = hex"...";  // 체인 A에서 캡처
    (uint8 v, bytes32 r, bytes32 s) = split(sig);

    vm.createSelectFork("polygon");
    IVictim(address(VICTIM)).executeSigned(
        SignedStruct({nonce: 0, value: 1e18, recipient: attacker}),
        v, r, s
    );
    // assertion: attacker balance increased on polygon
}
```

```python
# EIP-2612 permit 오프체인 서명 (authorized testing)
from eth_account.messages import encode_structured_data
from eth_account import Account
sig = Account.sign_message(encode_structured_data(permit_data), private_key=key)
# sig.signature → on-chain permit()에 전달
```

## 5. Evidence Tier
- **E1**: 두 개의 실제 체인 fork에서 동일 서명이 각각 executeSuccessfully → asset 이동 증명
- **E2**: 단일 체인 replay 성공 (예: cancel된 order 재사용)
- **E3**: DOMAIN_SEPARATOR 분석으로 이론적 replay 가능성만

## 6. Gate 1 / Gate 2
- [ ] chainid 포함된 EIP-712 도메인 사용? 누락 시 Critical
- [ ] nonce 단조 증가? 
- [ ] `s` low-half 체크? (EIP-2 compliance)
- [ ] Permit 서명이 UI 외부 저장되는 경로가 scope에 포함?

## 7. Variants
- **EIP-1271 smart account 서명**: validated contract code가 약한 로직일 때 모든 서명 accept
- **LayerZero / CCIP oracle replay**: DVN quorum 낮을 때 서명 조작
- **Gnosis Safe signer replay**: owners 구성 변경 전/후 pre-signed tx 재생
- **Order book cancel race**: 0x / 1inch 등에서 off-chain cancel이 on-chain 반영 전

## 8. References
- EIP-712, EIP-2612 공식 사양
- OpenZeppelin `ECDSA` 라이브러리 문서 (s malleability 방어)
- dYdX / Uniswap permit2 연구
- HackerOne: 여러 cross-chain bridge 공개 disclosure
- `knowledge/techniques/defi_hacks_2025_2026.md` 섹션 2.7
