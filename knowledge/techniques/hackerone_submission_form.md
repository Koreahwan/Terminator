# HackerOne Bug Report Submission Form Template
**Last Updated**: 2026-03-05 (경험 기반 + 공개 문서 종합)

---

## 양식 구조

### 1. Program (필수)
- 타겟 프로그램 선택 (검색/드롭다운)
- 프로그램의 Policy 페이지에서 scope 확인 필수

### 2. Asset (필수)
- 영향받는 자산 선택 (도메인, 앱, 소스코드 등)
- scope에 명시된 자산 중 선택
- 자산이 목록에 없으면 "Other" + 설명

### 3. Weakness (필수)
- **CWE 기반 Weakness Taxonomy** 사용
- 드롭다운에서 검색 가능
- 예: CWE-79 (XSS), CWE-89 (SQLi), CWE-306 (Missing Auth), CWE-639 (IDOR)
- 정확한 CWE 선택이 트리아지 속도에 영향

### 4. Severity (필수)
- **CVSS 3.1** 기반 (일부 프로그램은 CVSS 4.0)
- CVSS Calculator 내장 — 벡터 선택하면 점수 자동 계산
- 또는 None/Low/Medium/High/Critical 직접 선택
- **프로그램의 severity table** 확인 (CVSS와 다를 수 있음)

### 5. Title (필수)
- 간결하고 구체적
- 형식: `[Weakness Type] in [Component] allows [Impact]`
- 예: "Stored XSS in user profile bio leads to session hijacking"
- 예: "IDOR in /api/users/{id}/settings allows unauthorized profile modification"

### 6. Description (필수, Markdown 지원)
**H1 권장 구조**:
```markdown
## Summary
1-2 문장 요약. 취약점 유형, 위치, 영향.

## Description
취약점의 기술적 세부사항.
- Root cause 분석
- 영향받는 코드/엔드포인트
- 공격 시나리오

## Steps To Reproduce
1. [환경/도구 설정]
2. [첫 번째 동작]
3. [두 번째 동작]
4. [취약점 확인 방법]

## Impact
공격자가 달성 가능한 최대 영향.
영향받는 사용자/데이터 범위.

## Supporting Material/References
- [스크린샷/비디오 링크]
- [관련 CVE/CWE 참조]
```

### 7. Impact (선택적 별도 필드)
- Description 내 Impact 섹션 외에 별도 임팩트 필드
- 비즈니스 관점 영향 기술

### 8. Attachments (선택)
- 이미지, 비디오, PoC 스크립트
- **최대 파일 크기**: 개당 50MB (Bugcrowd 400MB보다 작음)
- PoC 코드는 `.py`, `.sh`, `.js` 등으로 직접 첨부 가능

### 9. Submit Report
- "Submit Report" 클릭
- **제출 후 수정 가능** (Bugcrowd와 다른 점!)

---

## H1 특화 규칙

### Signal & Reputation
- **Signal**: -10 ~ +7 범위
- **Informative**: 0 signal (중립)
- **N/A (Not Applicable)**: **-5 signal** (가장 위험)
- **Duplicate**: -2 signal
- **Resolved**: +7 signal
- **⚠️ signal_test 절대 금지**: 저품질 제출 누적 → 시그널 최하위 → API 403

### Severity Ranges (일반적)
| Severity | CVSS | 일반 보상 |
|:---------|:-----|:----------|
| Critical | 9.0-10.0 | $10,000 - $100,000+ |
| High | 7.0-8.9 | $2,500 - $30,000 |
| Medium | 4.0-6.9 | $500 - $5,000 |
| Low | 0.1-3.9 | $100 - $1,000 |
| None | 0.0 | Informational |

*프로그램마다 다름 — policy의 reward table 확인 필수*

### Mediation
- 프로그램과 의견 불일치 시 H1 Mediation 요청 가능
- Mediation은 시그널에 영향 없음

### Disclosure
- 프로그램 동의 후 Limited/Full Disclosure 요청 가능
- 기본 90일 대기 후 자동 공개 옵션

---

## reporter 에이전트용 체크리스트

```
□ Asset이 in-scope인가? (policy 확인)
□ CWE Weakness가 정확한가?
□ CVSS 벡터가 보수적인가? (과대 주장 → 신뢰 하락)
□ Title이 [Weakness] in [Component] allows [Impact] 형식인가?
□ Steps to Reproduce가 독립적으로 재현 가능한가?
□ Impact가 비즈니스 관점으로 기술되어 있는가?
□ PoC 첨부 (50MB 이하)?
□ AI 슬롭 표현 없음? (slop-check 통과)
□ 이전 제출과 다른 보고서 구조?
□ ⚠️ signal 위험 평가: N/A 가능성이 있다면 제출하지 마라
```
