# Scenario: Flashloan → Governance Takeover

> 거버넌스 토큰이 lending market 상장되어 있고 voting이 단일 tx snapshot 기반이면 발생.

## 1. Threat Model
- **타겟**: On-chain governance (OZ Governor, Compound GovernorBravo, custom DAO)
- **공격자**: unauthenticated, flashloan 대출 가능한 자본
- **Impact**: 악성 proposal 단독 통과 → treasury drain, protocol upgrade
- **Severity**: Critical

## 2. Discovery Signals
- 투표 voting power 계산이 `balanceOf(proposal_block)` 스냅샷
- 스냅샷 블록이 proposal 직후 1-2 블록 (제안 — 투표 — 실행이 동 블록 가능)
- Governance token이 Aave/Compound/Balancer 등에 depositable + borrowable
- Timelock 우회 가능한 `executeBatch` 함수
- Quorum 금액이 flashloan 가용 범위 내

## 3. Exploit Chain
```
A. proposal 작성 (treasury 이동 calldata)
B. Flashloan으로 governance token 대량 확보
C. 동일 tx: proposeTx + delegateToSelf + castVote
D. 투표 snapshot block이 현재 tx라면 성공
E. 즉시 execute 가능한 governance라면 treasury drain
F. Flashloan 상환
```

## 4. PoC Template
```solidity
function test_flashgov() public {
    // Aave v3 flashloan
    IPool(AAVE).flashLoanSimple(address(this), address(GOV_TOKEN), 1_000_000e18, "", 0);
}

function executeOperation(address, uint256 amt, uint256 fee, address, bytes calldata)
    external returns (bool)
{
    GOV_TOKEN.delegate(address(this));
    governor.castVote(proposalId, 1);  // vote for
    governor.execute(proposalId);
    // treasury 탈취 완료
    GOV_TOKEN.approve(AAVE, amt + fee);
    return true;
}
```

## 5. Evidence Tier
- E1: fork mainnet에서 실제 proposal+vote+execute 시뮬레이션 성공
- E2: 이론 경로 명확 + quorum cost < flashloan 수수료 계산
- E3: governance 설정 취약점 식별만

## 6. Gate 1 / Gate 2
- [ ] Proposal delay (Tally) 있음 — flashloan 1 tx 내 불가
- [ ] Timelock 있음 — execute 지연
- [ ] Voting delay + voting period 분리
- [ ] Quorum이 flashloan 가용 대비 큼?

## 7. Variants
- **Delegation sandwiching**: 정당한 voter의 delegation 이후 상태 조작
- **Vote buying**: 단일 tx 대신 다블록 전략
- **Bridge gov replay**: cross-chain voting에서 signature replay

## 8. References
- Beanstalk 2022 — $182M governance flashloan (대표 사건)
- MakerDAO MKR liquidation 연구
- Compound Bravo / OpenZeppelin Governor 문서
