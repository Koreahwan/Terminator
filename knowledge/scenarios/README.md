# Attack Scenario Library

> End-to-end 공격 시나리오 템플릿. 각 파일은 실제 해킹/버그바운티 사례에서 추출한
> 재현 가능한 exploit chain + PoC skeleton + Gate 1/2 체크리스트를 제공한다.

## 구조

```
scenarios/
├── web/           # Web/API 버그바운티 패턴
├── web3/          # Smart contract / DeFi 패턴
├── ai/            # LLM / MCP agent 공격
├── mobile/        # Android / iOS
└── cloud/         # AWS / GCP / Azure / SaaS
```

## 파일 포맷 (공통)

각 시나리오 파일은 아래 8개 섹션을 따른다 — Terminator 파이프라인 Gate 호환:

1. **Threat Model** — 타겟 유형, 공격자 전제, 예상 impact, VRT 매핑
2. **Discovery Signals** — scout/analyst 단계에서 이 패턴을 의심할 단서
3. **Exploit Chain** — step-by-step 공격 흐름 (escalation pivot 포함)
4. **PoC Template** — 실행 가능한 starter code (curl/python/foundry/solidity)
5. **Evidence Tier** — E1/E2/E3/E4 달성 조건 (bb_pipeline_v13)
6. **Gate 1 / Gate 2 체크** — 제출 전 kill risk 검증 포인트
7. **Variants / Chains** — 같은 root cause에서 파생되는 변형
8. **References** — 공개 writeup, CVE, blog, H1/Bugcrowd disclosure URL

## 카탈로그 (2026-04-16 기준)

### Web / API (bugcrowd/h1/intigriti)
| 시나리오 | 파일 | 심각도 밴드 |
|----------|------|-------------|
| IDOR → admin privesc | [web/idor_to_privesc.md](web/idor_to_privesc.md) | Medium–Critical |
| SSRF → cloud IAM → RCE | [web/ssrf_to_cloud_rce.md](web/ssrf_to_cloud_rce.md) | High–Critical |
| JWT kid / alg confusion | [web/jwt_kid_injection.md](web/jwt_kid_injection.md) | High |
| OAuth state binding ATO | [web/oauth_state_binding_ato.md](web/oauth_state_binding_ato.md) | High–Critical |
| GraphQL batching auth bypass | [web/graphql_batching_auth.md](web/graphql_batching_auth.md) | Medium–High |
| Web cache deception/poisoning | [web/cache_deception.md](web/cache_deception.md) | Medium–High |

### Web3 / Smart Contract (immunefi/hackenproof/cantina)
| 시나리오 | 파일 | 심각도 밴드 |
|----------|------|-------------|
| Oracle manipulation (TWAP + spot) | [web3/oracle_manipulation_twap.md](web3/oracle_manipulation_twap.md) | Critical |
| Reentrancy (cross-fn / read-only / ERC-777) | [web3/reentrancy_patterns.md](web3/reentrancy_patterns.md) | High–Critical |
| Signature replay (EIP-712 cross-chain) | [web3/signature_replay_eip712.md](web3/signature_replay_eip712.md) | High |
| Flashloan → governance takeover | [web3/flashloan_governance.md](web3/flashloan_governance.md) | Critical |
| Uninitialized proxy / admin front-run | [web3/proxy_uninitialized.md](web3/proxy_uninitialized.md) | Critical |

### AI / LLM (huntr/anthropic/openai)
| 시나리오 | 파일 | 심각도 밴드 |
|----------|------|-------------|
| MCP tool description poisoning | [ai/mcp_tool_injection.md](ai/mcp_tool_injection.md) | High |
| Indirect prompt injection via RAG | [ai/indirect_prompt_injection_rag.md](ai/indirect_prompt_injection_rag.md) | Medium–High |
| Agent memory / conversation exfil | [ai/agent_memory_exfil.md](ai/agent_memory_exfil.md) | High |
| Multi-turn jailbreak chain | [ai/jailbreak_chain.md](ai/jailbreak_chain.md) | Medium |

### Mobile (android/ios bounty)
| 시나리오 | 파일 | 심각도 밴드 |
|----------|------|-------------|
| Insecure deeplink / universal link hijack | [mobile/insecure_deeplink_universal.md](mobile/insecure_deeplink_universal.md) | Medium–High |
| Android WebView file:// origin escape | [mobile/android_webview_filesystem.md](mobile/android_webview_filesystem.md) | High |

### Cloud / SaaS
| 시나리오 | 파일 | 심각도 밴드 |
|----------|------|-------------|
| IMDS SSRF → cloud key exfil | [cloud/imds_ssrf_escalation.md](cloud/imds_ssrf_escalation.md) | Critical |
| S3 presigned URL abuse | [cloud/s3_signed_url_abuse.md](cloud/s3_signed_url_abuse.md) | Medium–High |

## 사용 가이드

1. **타겟 assessment 단계** — 시나리오 카탈로그에서 타겟 유형에 맞는 후보 선별
2. **scout/analyst 단계** — Discovery Signals 섹션을 추가 체크리스트로 사용
3. **exploiter 단계** — PoC Template를 starter로 사용, 타겟 전용 context로 수정
4. **Gate 1/2** — Gate 체크 섹션을 pre-submit validator와 cross-check
5. **reporter** — References의 유사 공개 writeup을 톤/포맷 레퍼런스로 참조

## 기여 규칙

- 실제 공개된 취약점 패턴만 문서화 (제보된 공개 writeup, CVE, GHSA, audit report)
- 0-day 미공개 이슈는 해당 프로그램 제보 완료 후에만 추가
- PoC Template은 **authorized testing** 컨텍스트 기반 — 타겟 명시 필수
- 모든 참조 URL은 작성 시점에 접근 가능한 것만

마지막 업데이트: 2026-04-16
