# Immunefi Target Candidates — 2026-02-22

Pre-evaluated targets for next bug bounty campaigns. Based on v5 pipeline rules.

## Selection Criteria (v5 Hard NO-GO)
- 3+ audits = AUTO NO-GO
- 100+ resolved reports = AUTO NO-GO
- 3+ years operational = AUTO NO-GO
- Fork with all audit fixes applied = AUTO NO-GO

---

## Tier 1: High Priority (GO candidates)

### Ethena (NEW scope expansion)
- **Bounty**: Up to $3,000,000
- **Scope**: New contracts added recently (scope expansion)
- **Audits**: ~2 (manageable)
- **Why GO**: Fresh scope = less picked over, very high bounty ceiling
- **Risk**: High competition due to bounty size
- **Pre-check**: Verify exact new scope contracts on Immunefi page

### Alchemix V3
- **Bounty**: Up to $300,000
- **Scope**: V3 contracts (new architecture)
- **Audits**: ~1-2 on V3
- **Why GO**: New version = new code, existing V2 audits don't cover V3
- **Risk**: V2 was mature, but V3 is fresh
- **Pre-check**: Verify V3 scope is separate from V2

### BENQI
- **Bounty**: Up to $500,000
- **Scope**: Avalanche lending protocol
- **Audits**: ~2
- **Why GO**: Avalanche-specific, less competition than Ethereum L1
- **Risk**: Compound fork — check if original audit fixes applied
- **Pre-check**: Fork analysis required (check original C4/Sherlock findings)

---

## Tier 2: Moderate Priority (CONDITIONAL GO)

### Inverse Finance
- **Bounty**: Up to $100,000
- **Scope**: FiRM lending protocol
- **Audits**: ~2-3 (borderline)
- **Why CONDITIONAL**: Novel lending design (FiRM), but close to audit limit
- **Pre-check**: Count exact audits, check resolved reports

### Exactly Protocol
- **Bounty**: Up to $50,000
- **Scope**: Fixed/variable rate lending
- **Audits**: ~1-2
- **Why CONDITIONAL**: Lower bounty but less competition
- **Pre-check**: Verify LOC, check if Optimism deployment is in scope

### DeFi Saver
- **Bounty**: Up to $350,000
- **Scope**: DeFi automation (recipe system)
- **Audits**: ~2
- **Why CONDITIONAL**: Complex recipe/strategy system = larger attack surface
- **Risk**: Integration-heavy (Aave, Compound, Maker interactions)
- **Pre-check**: Verify which integrations are in scope

---

## Tier 3: Monitor (Not yet ready)

### Protocols with recent scope changes
- Monitor Immunefi announcements for new programs
- Newly listed protocols (< 1 month) have lowest competition
- Set WebSearch alert for "new immunefi program" weekly

---

## Evaluation Workflow
```
For each candidate:
1. target_evaluator Phase 0 (30 min max)
2. Check OOS exclusion list (v5 CapyFi lesson)
3. Check audit count (v5 hard NO-GO)
4. Check on-chain config (v6 Kiln lesson)
5. GO → Phase 0.5 tool scan
```

## Historical ROI Reference
| Hours Invested | Finding Rate | Revenue |
|---------------|-------------|---------|
| < 2 hours | 0% (too shallow) | $0 |
| 2-4 hours | ~5% (tool + Level 2) | Low |
| 4-8 hours | ~15% (deep Level 3-4) | Medium |
| 8+ hours | Diminishing returns | Watch time-box |

**Sweet spot**: 4-6 hours per target with tool-first gate.

---

## 2026-04 Update — 플랫폼 전환 + 신규 후보

### 주의: Immunefi ban 상태
> 사용자 계정 2026-04-09 permanent ban. 본 참조는 플랫폼 중립 정보. 실제 제출은
> 대체 플랫폼 사용: Bugcrowd Web3, HackenProof, Cantina, Code4rena, Sherlock 등.

### 대체 Web3 플랫폼 비교 (2026-04 기준)

| 플랫폼 | 범위 | 특징 | 권장 용도 |
|--------|------|------|-----------|
| **Cantina** | 컨테스트 + 지속 바운티 | Spearbit 배경, 톱 auditor 경쟁 | 큰 보상 추구 |
| **Code4rena** | 시즌제 컨테스트 | Sub-audit, warden 랭킹 | 정기 참여 |
| **Sherlock** | 컨테스트 + judging | watson 커뮤니티 | 중간 보상 + 판정 참여 |
| **HackenProof** | Web3 + Web2 혼합 | Dexalot 등 active | Web3 단발 제출 |
| **Bugcrowd Web3** | VRT 체계 + Web2와 혼합 | 운영 프로세스 안정 | 조합 제출 |
| **huntr** | AI/ML OSS 중심 | $500–$4,500 | AI/Web3 라이브러리 |
| **SubjectiveIssue / 직접** | Discord/Email | Bounty 개별 협상 | 특정 프로토콜 |

### 2026-04 Active Programs Observations (일반 정보, 제출 전 각 플랫폼 현장 확인 필수)

- **LayerZero** — 크로스체인 메시징, 여전히 large max bounty. `v2` 브릿지 로직 + DVN 구조 fresh surface
- **Wormhole** — 2022년 대형 바운티 이후 재구조화, 여전히 active
- **Starknet** — ZK-rollup, Cairo 1.0 / Cairo 2.0 전환기 surface
- **Scroll / Linea / zkSync** — ZK L2 각사, prover 경로 주의
- **Polygon zkEVM** — L2 + ZK 이중 surface
- **EigenLayer / Restaking protocols** — 2024-2025 핫, 신규 LST/AVS 모듈 지속 추가
- **Morpho** — lending 메타, 최근 Blue v2 전환 후 audit 내역 확인
- **Aave v3 / Sparkprotocol** — mature but DAO 포워드 포크 지속
- **Pendle** — 2024 Penpie 교훈 이후 custom market 관리 엄격화, 신규 통합 주의

### 체크리스트 (실제 제출 전)

1. 플랫폼이 실제로 cash bounty 지급 중인가 (CVE-only vs cash)
2. 최근 100개 제출의 dup/informative 비율
3. Fresh-surface 조건: 최근 6개월 신규 모듈/브리지/체인 확장
4. `tools/bb_preflight.py verify-target <platform> <target>` — v12.3 이후 지원 플랫폼
5. `fetch-program`으로 verbatim scope/OOS 추출 (v12.4)
6. Severity scope 테이블 + branch/tag scope 사전 검증 (walrus 교훈)

---

마지막 업데이트: 2026-04-16

