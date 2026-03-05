# Bug Bounty Platform Submission Format Index
**Last Updated**: 2026-03-05

reporter 에이전트가 플랫폼별 올바른 제출 형식을 사용하기 위한 마스터 인덱스.

---

## 플랫폼별 참조 파일

| Platform | Template File | Taxonomy | Key Difference |
|:---------|:-------------|:---------|:---------------|
| **Bugcrowd** | `bugcrowd_submission_form.md` | VRT (P1-P5) | 제출 후 수정 불가, 시그널 패널티 없음 |
| **HackerOne** | `hackerone_submission_form.md` | CWE + CVSS 3.1 | 제출 후 수정 가능, N/A = -5 signal |
| **Immunefi** | `immunefi_submission_form.md` | Impact 기반 + CVSS | Secret Gist 필수, AI 탐지 강력 |
| **FindTheGap** | *(아래 Quick Ref)* | CVSS 3.1 | 스페인 기반, 한국어/영어, UUID 태그 |
| **HackenProof** | *(아래 Quick Ref)* | Severity 기반 | Web3 특화, 경쟁 적음 |
| **PSIRT Direct** | *(아래 Quick Ref)* | CVE 연동 | 이메일 기반, 긴 응답시간 |

---

## 플랫폼별 Quick Reference

### Bugcrowd
```
Title:     구체적 (유형 + 위치 + 영향)
Severity:  VRT 카테고리 선택 (bugcrowd_vrt.md 참조)
Body:      Overview → Steps to Reproduce → Evidence → Impact
Attach:    20개 파일, 개당 400MB
PoC:       비디오 강력 권장
특이사항:   제출 후 수정 불가, Informative = 패널티 0
```

### HackerOne
```
Title:     [CWE] in [Component] allows [Impact]
Weakness:  CWE 드롭다운 선택
Severity:  CVSS 3.1 Calculator
Body:      Summary → Description → Steps → Impact → References
Attach:    파일 개당 50MB
PoC:       스크립트 직접 첨부 가능
특이사항:   제출 후 수정 가능, N/A = -5 signal (치명적)
```

### Immunefi
```
Title:     [취약점] in [함수/컴포넌트] leads to [영향]
Asset:     컨트랙트 주소 + 체인 선택
Severity:  Impact 목록에서 선택 → Critical/High/Medium/Low
Body:      Brief → Vulnerability Details → Impact Details → PoC
PoC:       Secret Gist (gh gist create) + Foundry/Hardhat 테스트
Attach:    이미지 20개 (8MB), ZIP 불가 → Gist 사용
특이사항:   AI 탐지 강력, specific block/tx 필수, 밴 위험
```

### FindTheGap
```
Title:     구체적 (영어 또는 한국어)
Severity:  CVSS 3.1 (수동 입력)
Body:      자유 형식 (Markdown)
PoC:       필수 — 스크린샷 + curl 명령어
Auth:      bugbounty UUID 태그 필수 (program_rules_summary.md에서 확인)
특이사항:   IdToken (Cognito) 사용, Authorization: Bearer 아님
```

### HackenProof
```
Title:     구체적
Severity:  Critical/High/Medium/Low
Body:      Description → Steps → Impact → PoC
PoC:       필수 (코드 + 결과 캡처)
특이사항:   Web3 특화, 경쟁 적음, 빠른 트리아지
```

### PSIRT Direct (벤더 직접 제출)
```
형식:      이메일 (security@vendor.com 또는 PSIRT 포털)
Title:     CVE 스타일 — "[Product] [Version] [Vulnerability Type]"
Body:      Executive Summary → Technical Details → PoC → Remediation Suggestion
Severity:  CVSS 3.1 벡터 포함
특이사항:   응답 느림 (2-8주), CVE 발급 가능, 공식 크레딧
```

---

## reporter 에이전트 규칙

1. **`program_rules_summary.md`에서 플랫폼 확인** → 해당 템플릿 파일 참조
2. **Taxonomy 일치**: Bugcrowd=VRT, H1=CWE, Immunefi=Impact
3. **PoC 형식 일치**: Bugcrowd=비디오, H1=스크립트, Immunefi=Gist
4. **Severity 전략**: 보수적 > 공격적 (트리아저가 올려주는 건 OK)
5. **AI 슬롭**: 모든 플랫폼에서 `slop-check` 통과 필수
6. **제출 후 수정**: Bugcrowd=불가(완벽 후 제출), H1=가능(빠른 제출 후 보강)

---

## CVSS vs VRT vs Impact 매핑 (대략적)

| CVSS | H1 Severity | Bugcrowd VRT | Immunefi |
|:-----|:------------|:-------------|:---------|
| 9.0-10.0 | Critical | P1 | Critical |
| 7.0-8.9 | High | P2 | High |
| 4.0-6.9 | Medium | P3 | Medium |
| 0.1-3.9 | Low | P4 | Low |
| 0.0 | None | P5 | Informational |

*실제 매핑은 프로그램마다 다름 — brief/policy 확인 필수*
