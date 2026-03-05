# Bugcrowd Bug Report Submission Form Template
**Source**: https://docs.bugcrowd.com/researchers/reporting-managing-submissions/reporting-a-bug/
**Last Updated**: 2026-03-05

---

## 양식 구조

### 1. Summary Title (필수)
- **형식**: 취약점 유형 + 위치 + 영향
- **25,000자 이내**
- 예: "Remote File Inclusion in Resume Upload Form allows remote code execution"
- 예: "IDOR in /api/v2/users/{id} allows unauthorized access to PII"
- **BAD**: "RFI Injection found", "Bug in API" (너무 모호)

### 2. Target (필수)
- 드롭다운에서 영향받는 타겟 선택
- 목록에 없으면 "Other" 선택
- **주의**: OOS 타겟 제출 시 **-1 point** 페널티

### 3. Technical Severity (필수)
- **VRT(Vulnerability Rating Taxonomy)** 기반 선택
- 드롭다운에서 타이핑으로 필터링 가능
- VRT 카테고리: `knowledge/techniques/bugcrowd_vrt.md` 참조
- P1(Critical) ~ P5(Informational)
- 프로그램이 VRT 기본 등급을 override 가능 → brief 확인 필수

### 4. URL / Location (선택)
- 취약점이 발견된 정확한 URL 또는 위치
- 비워둘 수 있지만 채우는 것이 트리아지에 도움

### 5. Description (필수)
Markdown 지원. 이미지/비디오 드래그앤드롭 가능.

**권장 구조**:
```markdown
## Overview
1-2 문장. 취약점 유형 + 영향 요약.

## Steps to Reproduce
1. [환경 설정 — 브라우저, 도구, 버전]
2. [첫 번째 동작]
3. [두 번째 동작]
4. [취약점 트리거 확인]

## Vulnerability Evidence
[스크린샷, 비디오, 응답 캡처]
- 정상 요청 vs 악성 요청 비교 (음성 대조군)
- 실제 서버 응답 캡처

## Demonstrated Impact
- 공격자가 달성할 수 있는 것
- 영향받는 사용자/자산 범위
- 비즈니스 영향
```

### 6. Attachments (선택)
- **최대 20개 파일**
- **개당 400MB 이하**
- 모든 파일 타입 허용
- 비디오 PoC 강력 권장 (스크린샷보다 선호)

### 7. Collaborate (선택)
- 공동 연구자 사용자명 추가
- 보상 분배율 설정

### 8. Confirmation (필수)
- 프로그램 brief 준수 + Bugcrowd T&C 동의 체크박스
- "Report Vulnerability" 클릭

---

## 제출 후 주의사항

- **제출 후 수정 불가** — 제출 전 반드시 리뷰
- **자동 저장**: 30초마다 드래프트 저장
- **중복**: Duplicate → P5 처리, 시그널에는 영향 없음 (H1과 다른 점)
- **OOS 제출**: **-1 point** 페널티 (반드시 brief의 scope 확인)

---

## Bugcrowd 특화 규칙

### Signal 시스템 (Bugcrowd = 시그널 없음)
- Informative/Duplicate → **계정 영향 0** (H1과 달리 시그널 패널티 없음)
- 따라서 Bugcrowd가 가장 "안전한" 플랫폼

### Priority vs Severity
- **Technical Severity** = 연구자가 VRT로 선택
- **Priority** (P1-P5) = Bugcrowd 트리아저가 최종 결정
- 프로그램 brief의 reward table이 Priority 기준

### Reward Range (일반적)
| Priority | 일반 범위 |
|:---------|:----------|
| P1 | $5,000 - $50,000+ |
| P2 | $2,000 - $20,000 |
| P3 | $500 - $5,000 |
| P4 | $150 - $1,000 |
| P5 | $0 (Informational) |

*프로그램마다 다름 — brief의 reward table 확인 필수*

---

## reporter 에이전트용 체크리스트

```
□ Summary Title이 구체적인가? (유형 + 위치 + 영향)
□ Target이 in-scope인가? (brief 확인)
□ VRT 카테고리가 정확한가? (bugcrowd_vrt.md 대조)
□ Steps to Reproduce가 재현 가능한가?
□ 증거에 음성 대조군(정상 응답)이 포함되어 있는가?
□ Demonstrated Impact가 비즈니스 영향을 명시하는가?
□ 스크린샷/비디오가 첨부되어 있는가?
□ AI 슬롭 표현이 없는가? (slop-check skill 통과)
□ 제출 후 수정 불가 — 최종 확인 완료?
```
