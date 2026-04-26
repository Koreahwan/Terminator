# Discovery Platforms — Canonical Target Search List

Referenced from `bb_pipeline_v13.md` Phase 0 / Explore Lane. target-discovery 에이전트가 참조.

## Tier 1 — Custom Parser (program_fetcher handler + verify-target parser)

| Platform | URL | Handler | Specialty |
|----------|-----|---------|-----------|
| huntr | huntr.com | huntr.py | Open source repos, AI/ML, $125-$3000 |
| Bugcrowd | bugcrowd.com | bugcrowd.py | Web2 SaaS, enterprise, P1-P5 VRT |
| Intigriti | app.intigriti.com | intigriti.py | European enterprise, government, €500-€15K |
| YesWeHack | yeswehack.com | yeswehack.py | French/EU gov, enterprise, €500-€15K |
| HackenProof | hackenproof.com | hackenproof.py | Web3/DeFi, smart contracts |
| HackerOne | hackerone.com | hackerone.py | Largest platform, all categories |
| Immunefi | immunefi.com | immunefi.py | **BANNED** — skip entirely |

## Tier 2 — Generic Parser (detect_platform + generic fallback + raw_bundle)

| Platform | URL Pattern | Key | Specialty | Notes |
|----------|------------|-----|-----------|-------|
| Hackrate | hckrt.com, hackrate.com | hackrate | Small but fast payout | Newer, low competition |
| Compass Security | bugbounty.compass-security.com | compass | Swiss companies | Multiple public programs |
| Inspectiv | app.inspectiv.com | inspectiv | Mixed programs | Newer platform |
| Yogosha | yogosha.com | yogosha | French, PtaaS + bounty | EU focus like YWH |
| Cobalt | cobalt.io | cobalt | PTaaS + bounty | Structured engagements |
| Synack | synack.com | synack | Invite-only, high payout | Requires vetting/application |
| GoBugFree | gobugfree.com | gobugfree | Swiss companies, banks, government | 매우 낮은 경쟁, 소규모 연구자 풀 |

## Tier 3 — Aggregators (discovery source only, not submission platforms)

| Source | URL | Use |
|--------|-----|-----|
| BBRadar | bbradar.io | All-platform program aggregator, filter by bounty/wildcard |
| BugBountyDirectory | bugbountydirectory.com | Curated list outside H1/BC |
| BugBountyHunt | bugbountyhunt.com/platforms | Platform directory with 50+ platforms |

## Tier 4 — Direct / Non-platform Programs

| Program | URL | Specialty |
|---------|-----|-----------|
| 0din | 0din.ai | AI/LLM security bounties |
| Google VRP | bughunters.google.com | Google products |
| Microsoft MSRC | msrc.microsoft.com/bounty | Microsoft products |
| GitHub Security Lab | github.com/security | OSS responsible disclosure |
| Code4rena | code4rena.com | DeFi audit competitions |
| Sherlock | audits.sherlock.xyz | DeFi audit contests |
| Cantina | cantina.xyz | Security marketplace |

## Anti-Hallucination Rules (IRON — applies to ALL tiers)

1. **Tier 1**: program_fetcher handler + raw_bundle + verbatim-check 3중 보호
2. **Tier 2**: generic handler (confidence 0.4 HOLD) + raw_bundle 필수. **절대 scope/OOS 요약 금지** — raw_bundle.md의 verbatim substring만 신뢰
3. **Tier 3**: 발견 용도만. 실제 scope는 반드시 원본 프로그램 페이지에서 fetch-program으로 추출
4. **Tier 4**: github_md handler 또는 generic 사용. 직접 프로그램 페이지에서 verbatim 추출

### Tier 2 플랫폼 scope 페치 절차

```bash
# 1. init + fetch-program (generic handler + raw_bundle 자동)
python3 tools/bb_preflight.py init targets/<target>/
python3 tools/bb_preflight.py fetch-program targets/<target>/ <program_url>
# → generic handler가 jina로 페치 (confidence 0.4 = HOLD)
# → raw_bundle이 landing page HTML/text를 program_raw/bundle.md에 저장

# 2. HOLD이므로 수동 검증 필수
# program_data.json + program_raw/bundle.md 열어서 scope 항목 직접 확인
# 누락/변형 발견 시 → 프로그램 페이지에서 직접 복사 paste

# 3. verbatim-check
python3 tools/bb_preflight.py verbatim-check targets/<target>/
# generic HOLD 상태에서도 bundle.md 대조는 실행됨
```

## Discovery 실행 주기

- **주간**: 모든 Tier 1-3 플랫폼 대상 target-discovery 에이전트 병렬 실행
- **BBRadar 우선**: 모든 플랫폼 통합 검색 → 개별 플랫폼 상세 확인
- **Fresh program 감지**: 최근 2주 내 신규/업데이트 프로그램 우선
