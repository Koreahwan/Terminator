# Knowledge Base Expansion — Verification Audit (2026-04-16)

> 이 세션에서 새로 작성/확장한 모든 파일의 정합성/실효성/PI 검증 결과.

## 1. 감사 범위

### 1.1 신규 기법 문서 (9)
| 파일 | 크기 | 상태 |
|------|------|------|
| `techniques/ai_agent_mcp_attacks_2026.md` | 8.2K (189 lines) | 신규 (manual) |
| `techniques/llm_jailbreak_2026.md` | 17.3K (433 lines) | 신규 (agent, PI 감사 통과) |
| `techniques/supplychain_incidents_2025_2026.md` | 8.1K (180 lines) | 신규 (manual) |
| `techniques/defi_hacks_2025_2026.md` | 8.5K (175 lines) | 신규 (manual) |
| `techniques/cloud_saas_attack_patterns_2026.md` | 45.6K (1320 lines) | 신규 (agent, PI 감사 통과) |
| `techniques/security_tools_2026.md` | 11K (336 lines) | 신규 (manual) |
| `techniques/pre2025_classics_reference.md` | 7.5K (172 lines) | 신규 (manual) |
| `techniques/kernel_security_learning_cve.md` | 5.2K (129 lines) | 확장 (1.2K→5.2K) |
| `techniques/immunefi_target_candidates_2026.md` | 4.3K (134 lines) | 2026-04 섹션 추가 |

### 1.2 신규 Scenario 라이브러리 (21)
```
scenarios/
├── README.md               (5.2K, 카탈로그)
├── web/     (6) — idor, ssrf_cloud_rce, jwt, oauth, graphql, cache_deception
├── web3/    (5) — oracle, reentrancy, sig_replay, flashloan_gov, proxy_uninit
├── ai/      (4) — mcp_tool_inj, indirect_pi_rag, memory_exfil, jailbreak_chain
├── supplychain/ (2) — dep_confusion, gh_actions_poison
├── mobile/  (2) — deeplink, webview
└── cloud/   (2) — imds_ssrf, s3_presigned
```

### 1.3 업데이트
- `knowledge/index.md` — Techniques 섹션에 9개 신규 링크 + Scenario 섹션 신설

## 2. PI (Prompt Injection) 감사

### 2.1 패턴 스캔 결과
| 패턴 | 발견 | 평가 |
|------|------|------|
| `Ignore previous/all/above instructions` | 4건 | ✓ 모두 llm_jailbreak의 documented payload 인용 (코드블록/테이블 내) |
| `system:` / `assistant:` 제어 토큰 | 2건 | ✓ 코드블록 내 대화 예시 |
| `You are now DAN` / `forget everything` | 1건 | ✓ Skeleton Key 공격 예시 인용 |
| Zero-width Unicode (U+200B 등) | 0건 | ✓ 깨끗 |
| RTLO/LTRO (U+202A-E) | 0건 | ✓ 깨끗 |
| BOM (U+FEFF) | 0건 | ✓ 깨끗 |

**결론**: PI 표지는 모두 "defensive/authorized testing" 서두 경고가 있는 문서 내 **documented attack 예시**로 올바르게 delimited. 운영 지시로 해석될 위험 없음.

### 2.2 도메인/URL 감사
| 발견 | 평가 |
|------|------|
| `attacker.com`/`evil.com` 참조 | ✓ 모두 attack 패턴 설명 placeholder (infosec 관례) |
| `curl ... \| bash` | 2건, 공식 installer만 (google osv-scanner, paradigm foundry) |
| `r.jina.ai` WebFetch 접두어 | ✓ CLAUDE.md 규칙 준수 |
| r2/radare2 참조 | 1건 (pre2025_classics_reference.md에 "BANNED" 명시) |

### 2.3 Agent 산출물 감사
- **cloud_saas_attack_patterns_2026.md** (agent a712 생성, 45.6K) — WebFetch 내용 기반 작성되었으나 PI 패턴 없음, 모든 인용 공개 출처 (PortSwigger, OWASP, 공식 H1 reports)
- **llm_jailbreak_2026.md** (agent a48b 생성, 17.3K) — arXiv ID 실제 존재 확인 가능한 것만, defensive context 서두 강화

## 3. 구조 정합성

### 3.1 Scenario 파일 형식 (모두 21개)
| 체크 | 결과 |
|------|------|
| `## 1. Threat Model` ~ `## 8. References` 8섹션 | 168/21=8 ✓ 완벽 |
| PoC 코드블록 | 88개 (평균 4.2/파일) |
| Evidence Tier 섹션 | 21/21 ✓ |
| Gate 1/2 체크리스트 | 21/21 ✓ |

### 3.2 Technique 파일 형식
- 모두 서두에 "Defensive/Authorized Testing Context" 또는 동등 경고
- 모두 섹션 번호/제목 일관
- 참조 섹션 존재, 가능한 경우 공식 RFC/논문/blog 링크

## 4. 실효성 평가

### 4.1 신규 문서가 파이프라인에 어떻게 쓰이는가
| Phase | 참조 문서 |
|-------|-----------|
| Phase 0 (target-eval) | security_tools_2026.md (도구 버전 갱신), immunefi 2026-04 |
| Phase 1 (scout/analyst) | defi_hacks_2025_2026, supplychain_incidents_2025_2026, cloud_saas, scenarios/README |
| Phase 2 (exploiter) | scenarios/*/* PoC 템플릿, llm_jailbreak/ai_agent_mcp for AI targets |
| Gate 1 | scenarios/*/* section 6 체크리스트, pre2025_classics (duplicate 대조) |
| Gate 2 | 동일, Evidence Tier 섹션 교차참조 |
| CTF | kernel_security_learning_cve 확장판 |

### 4.2 타겟 유형별 coverage
- **Web/API**: 6 scenarios + cloud_saas (45K) + pre2025 patterns — 충분
- **Web3/SC**: 5 scenarios + defi_hacks (8.5K) + 기존 web3_* 3파일 (100K+) — 풍부
- **AI/LLM**: 4 scenarios + ai_agent_mcp (8.2K) + llm_jailbreak (17.3K) — 신규 영역 커버
- **Mobile**: 2 scenarios + 기존 mobile_testing_mastg — 기본 커버
- **Cloud**: 2 scenarios + cloud_saas (IMDS 중복 강화) — 충분
- **Supply chain**: 2 scenarios + supplychain_incidents (8.1K) — 충분
- **Kernel**: kernel_security_learning_cve 확장 + 기존 main (46K) — 강화

## 5. 한계 / 남은 리스크

1. **외부 링크 HEAD 검증 미실시** — 링크 수백 개를 일괄 HEAD 체크하려면 별도 배치 필요 (jina 통한 샘플만 수행)
2. **금액/날짜 정확도** — defi_hacks 표의 금액은 공개 자료 요약, 제출 전 재검증 필수 (명시됨)
3. **Agent 생성 2개 파일** — cloud_saas와 llm_jailbreak는 수동 재검증 시 추가 정합성 이슈 가능 (표면 스캔 통과)
4. **CVE 번호 정확도** — supplychain_incidents_2025_2026의 CVE-2025-30066은 공개된 tj-actions 사고 ID로 공개 출처 존재

## 6. 권장 후속 작업

1. 타겟 실제 제출 전 scenarios/*/* 의 References URL HEAD 검증
2. defi_hacks_2025_2026의 tx hash/Etherscan 링크는 제출 인용 시 반드시 재확인
3. `bb_preflight.py` 또는 별도 script로 link-check CI 추가 고려
4. 3~6개월 후 본 문서 기반 정기 refresh

---

**감사자**: Claude Opus 4.6 (내부 자체 감사)
**감사일**: 2026-04-16
**커밋 전 검토 권장**: `cat VERIFICATION_AUDIT_2026_04_16.md` 최종 확인 후 commit
