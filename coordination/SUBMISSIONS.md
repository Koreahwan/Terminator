# Bug Bounty + CVE Submissions — Canonical Tracker

**Last updated**: 2026-04-23 (magiclabs N/R close + ProConnect Under Review)
**Source of truth**: this file (markdown) + `docs/submissions.json` (dashboard feed)
**Sync command**: `/bounty-status-sync` (updates both)

This file replaces scattered status fields in `memory/project_*.md`. Memory files
now keep **lessons/patterns only**; live status lives here.

---

## Active (Pending / Triage)

| Platform | Target | Title | Sev | Bounty | Status | Submitted | Last Check | Note |
|---|---|---|---|---|---|---|---|---|
| huntr | llamaindex | OpenCypher Injection (CAND-01) | High | est $750–900 | Pending | 2026-04-06 | 2026-04-18 | ⚠ historical-match WARN: 27 same-program rejected (sandbox/deser duplicate 패턴), 12+일 pending → duplicate close risk 상승 |
| huntr | onnx | sampleSize OOM (dc57e727) | Medium | est $125 (up to $450) | Pending | 2026-04-10 | 2026-04-18 | ⚠ historical-match WARN: 14 same-program rejected (path traversal/RCE duplicate), 8일 pending |
| huntr | kubeflow | seaweedfs-iam (bbc04031) | High | est $750 | Pending | 2026-04-10 | 2026-04-18 | Cross-repo entry-point strategy |
| YesWeHack | Qwant | #16-705 SSRF/K8s FQDN leak | Medium | — (awaiting) | **Accepted** | 2026-04-05 | 2026-04-18 | 바운티 금액 미확정, 후속 문의 고려 |
| YesWeHack | ProConnect Identité | CAND-01 OIDC `claims` scope bypass (#YWH-PGM8338-167) | Medium (CVSS 6.5) | est €500 (Medium grid) | **Under Review** | 2026-04-18 | 2026-04-23 | 4/18 Under Review 전환 (5일만). Impact=PII Leak. |
| Intigriti | HRS Group | HRSGROUP-15EA62KR Unauth PCI card capture | Medium | — | Triage | 2026-04-05 | 2026-04-18 | 13일 triage 0 activity, slot 1/3 |
| GHSA | Fast-DDS | sampleSize OOM — GHSA-wv5q-wgv8-qh6v | Medium | CVE | Triage | 2026-04-13 | 2026-04-18 | eProsima Fast-DDS |
| GHSA | Fast-DDS | DynamicData seqlen OOM — GHSA-93m4-rx65-p7rj | Medium | CVE | Triage | 2026-04-13 | 2026-04-18 | eProsima Fast-DDS |
| HackenProof | Dexalot | auctionPrice=0 LIMIT-IOC bypass (CAND-01) | High | — | Hold | 2026-04-13 | 2026-04-18 | reputation 80/100 부족, 제출 hold |
| HackenProof | Dexalot | executeDelayedTransfer address(0) (NEW-02) | Medium | — | Hold | 2026-04-13 | 2026-04-18 | reputation 80/100 부족, 제출 hold |
| Direct | MITRE | CVE Request #2020275 | — | CVE | Pending | 2026-04-04 | 2026-04-18 | 배정 대기 |
| Direct | MITRE | CVE Request #2019598 | — | CVE | Pending | 2026-04-03 | 2026-04-18 | 배정 대기 |

## Resolved (Accepted / Rejected / Closed)

| Platform | Target | Title | Sev | Bounty | Status | Submitted | Resolved | Memory Lesson |
|---|---|---|---|---|---|---|---|---|
| YesWeHack | DINUM | #7419-178 SIRET prefill bypass | Low | — | Won't fix | 2026-04-04 | 2026-04-13 | [project_ywh_submissions](../memory/project_ywh_submissions_2026_04_07.md) — program-level disabled 04-15 |
| Intigriti | Port of Antwerp | Info disclosure #1 | Low | — | OOS | 2026-04-13 | 2026-04-14 | verbose-msgs rule → [kill-gate-1 v12.5](../.claude/rules/bb_pipeline_v13.md) |
| Intigriti | Port of Antwerp | Info disclosure #2 | Low | — | OOS | 2026-04-13 | 2026-04-14 | 동일 verbose-msgs rule |
| Bugcrowd | Zendesk | AI RAG Poisoning (633829d6) | P2 | — | **Not Applicable** | 2026-04-09 | 2026-04-17 | [project_zendesk](../memory/project_zendesk_submission_2026_04_09.md) — impact 입증 부족 학습 |
| Bugcrowd | magiclabs | loginWithPopup postMessage (ed68b74d) | Low | — | **Not Reproducible** | 2026-04-03 | 2026-04-23 | [project_magiclabs_nr](../memory/project_magiclabs_nr_2026_04_13.md) — N/R close, Bugcrowd accuracy -1pt 추가 타격 |
| Bugcrowd | magiclabs | PKCE codeVerifier localStorage (bc91fc04) | P4 | — | N/R (-1pt) | 2026-04-03 | 2026-04-13 | [project_magiclabs_nr](../memory/project_magiclabs_nr_2026_04_13.md) — client-side-only 패턴 |
| Immunefi | Paradex | #72759 Vault donate() share inflation | Critical | — | Closed (autoban) | 2026-04-09 | 2026-04-09 | [project_paradex_resubmit](../memory/project_paradex_resubmit_2026_04_09.md) — 12분 autoban, appeal 진행 |

## Appeals / Escalations In Flight

| Case | Platform | Route | Status | Next Action |
|---|---|---|---|---|
| Paradex #72759 autoban | Immunefi | Zendesk form (이메일 inbox deprecated 2026-04-16) | 2차 appeal 이메일 무응답 6일 → 자동 티켓 #9046 생성 | Zendesk form에 공식 escalation 재제출 |
| Immunefi account permaban | Immunefi | Zendesk form | 티켓 #9046 (VLD33V-W6Z05) | 위와 동일 티켓에 context 보강 or 신규 티켓 |
| DINUM #7419-178 Won't fix | YWH | 대시보드 사유 확인 → appeal 초안 | 보류 | YWH 대시보드에서 사유 문구 확인 후 판단 |

## Statistics

**Active: 12**
- Pending: 5 (llamaindex, onnx, kubeflow, MITRE #2020275, MITRE #2019598)
- Under Review / Triage: 4 (ProConnect CAND-01, Intigriti HRS, Fast-DDS GHSA ×2)
- Accepted (bounty 미확정): 1 (Qwant)
- Hold (reputation): 2 (Dexalot ×2)

**Resolved: 7**
- Won't fix: 1 (DINUM)
- OOS: 2 (Port of Antwerp ×2)
- Not Applicable: 1 (Zendesk)
- Not Reproducible: 1 (magiclabs loginWithPopup)
- N/R: 1 (magiclabs PKCE)
- Closed (autoban): 1 (Paradex)

## Platform-level Notes

- **Immunefi**: 계정 permaban (2026-04-09), 이메일 inbox deprecated (2026-04-16) → Zendesk form만
- **YesWeHack / DINUM 프로그램**: 전체 disabled 2026-04-15 ~ 2026-04-30 (program-level)
- **HackenProof**: reputation 80/100 필요, 신규 제출 자격 미달
- **Intigriti**: concurrent submission limit 3 slots, 현재 1/3
- **Bugcrowd**: magiclabs 2건 연속 N/R (PKCE -1pt + loginWithPopup Not Reproducible), accuracy 점수 하락 주의. Zendesk N/A 포함 3연속 미수락

## 사용 규칙

1. 상태 변경 시 `/bounty-status-sync` 실행 → 이 파일 + `docs/submissions.json` 동시 갱신
2. 신규 제출은 **Active** 상단에 추가
3. Resolved 항목은 **Resolved** 섹션으로 이동 (삭제 금지 — 패턴 학습용)
4. 상세 lesson은 `memory/project_*.md`에만 기록 (상태/바운티 금액은 이 파일만)
