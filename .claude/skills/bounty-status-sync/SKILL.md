---
name: bounty-status-sync
description: Sync bug bounty + CVE submission status across all platforms. Auto-matches "submission status", "제출 상태", "update bounty", "status sync", "track submissions", "cve 상태"
argument-hint: [full|quick|discover-missed]
context: fork
effort: medium
model: sonnet
---

# Bounty + CVE Status Sync

하나의 workflow로 MEMORY.md 에 기록된 active 제출의 상태를 실제 플랫폼에서 재검증하고,
놓친 제출(full sweep) + CVE 공개 상태까지 동기화.

## 모드

| 모드 | 용도 | 실행 시간 |
|------|------|-----------|
| `quick` (default) | MEMORY.md 기록된 active 항목만 체크 | 5-10분 |
| `full` | quick + 각 플랫폼 전체 submission 목록 스윕 + CVE sweep | 20-40분 |
| `discover-missed` | MEMORY.md에 없는 새 제출/CVE만 탐색 (신규 추가) | 15분 |

사용자 입력이 없으면 `quick` 기본.

---

## Phase 1 — Tracked Submissions Scan

Orchestrator (직접 실행, agent 불필요):

```bash
MEMORY_DIR="${HOME}/.claude/projects/$(pwd | sed 's|/|-|g')/memory"
grep -lE '(Pending|Triage|N/R|Won.t fix|Accepted|closed|Awaiting|제출)' "$MEMORY_DIR"/project_*.md
```

각 매칭 파일에서 다음 필드 추출 (regex 또는 직접 read):
- **Platform**: huntr / Bugcrowd / YesWeHack / Intigriti / HackenProof / HackerOne / Cantina / Immunefi / GHSA / NVD / Direct
- **Submission ID** or URL (e.g., huntr 8자리 id, h1 report #, GHSA-*-*-*)
- **Title**
- **Date submitted**
- **Last recorded status**
- **Last check date** (명시된 경우)

출력: `/tmp/bounty_sync_tracked.json` (platform별 그룹화)

---

## Phase 2 — Platform State Fetch (3-tier 접근)

**전략 순서** (가장 빠르고 정확한 것부터):
1. Email MCP (Gmail + NaverWorks) — 플랫폼 알림으로 즉시 감지
2. 공개 API/URL (gh, WebFetch)
3. Playwright (로그인 필수 플랫폼)

### 2.1 Email MCP (1st line, 로그인 불필요, 빠름)

#### Gmail (MCP `mcp__gmail__search_emails`)
```
# 플랫폼별 병렬 검색 (최근 14일)
from:(huntr.com OR @huntr.com) newer_than:14d
from:(bugcrowd.com) newer_than:14d
from:(yeswehack.com) newer_than:14d
from:(intigriti.com) newer_than:14d
from:(immunefi.com OR hackenproof.com OR hackerone.com) newer_than:14d
(huntr OR paradex OR hackenproof OR cantina OR sherlock) newer_than:14d
(subject:("security advisory" OR GHSA OR CVE) OR from:noreply@github.com OR from:notifications@github.com) newer_than:14d
from:mitre.org newer_than:30d  # MITRE CVE Request 응답 트래킹
```
추출: sender, subject, date → status 라벨 매핑 (예: "status updated to Accepted" / "status updated to Won't fix" / "account disabled" / "Thank you for your submission" etc)

#### NaverWorks (개인 secondary 이메일)
MCP 미지원 → Playwright 로그인 필요:
- `https://common.worksmobile.com/proxy/my` 경유 `auth.worksmobile.com`
- huntr 알림이 Gmail에 도달하지 않는 경우 주로 여기 있음 (확인 필수)
- 로그인 세션은 Playwright 프로필에 유지
- 본 레포 외부 `~/.config/bounty-credentials.json` 또는 별도 secret store에서 주소 로드

### 2.2 공개 API/URL (Playwright 불필요)
- **GHSA**: `gh api repos/<owner>/<repo>/security-advisories --paginate | jq -r '.[] | "\(.ghsa_id) | \(.cve_id // "NO-CVE") | \(.state) | \(.severity) | \(.published_at // "unpublished") | \(.summary)"'`
  - 핵심 포인트: **CAND-N 타이틀로 summary 매칭**하여 GHSA ID/CVE 확보
- **NVD**: `curl https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE-ID>`
- **huntr public pages**: `https://huntr.com/bounties/<id>` — WebFetch 해도 `"This report is not public"` 반환되므로 실질적으로 Playwright 필요 (public = 최종 disclosure 후에만)
- **MITRE CVE Request**: Gmail에서 `CVE Request NNNNNN` 구독 번호 확인 → `cveform.mitre.org/lookup/<request_id>` 수동 조회

### 2.3 로그인 필수 (Playwright MCP)
프로필: `${PLAYWRIGHT_BOUNTY_PROFILE:-$HOME/.config/playwright-bounty-profile}`

| 플랫폼 | URL | Login 상태 확인 힌트 |
|--------|-----|---------------------|
| huntr | `https://huntr.com/bounties/<id>` | `[aria-label="Profile avatar"]` 또는 body text 25KB+ 렌더링 |
| Bugcrowd | `https://bugcrowd.com/submissions` | avatar dropdown |
| HackerOne | `https://hackerone.com/reports` | filtered by state |
| YesWeHack | `https://yeswehack.com/programs/<prog>/reports` | |
| Intigriti | `https://app.intigriti.com/researcher/submissions` | |
| HackenProof | `https://hackenproof.com/profile` | |
| Cantina | `https://cantina.xyz/u/<user>/reports` | |
| Immunefi | `https://bugs.immunefi.com/reports` | account 상태 확인 필수 (ban/disable) |

#### huntr 전용 추출 패턴 (검증됨 2026-04-16)
```js
// browser_evaluate에 전달
() => {
  const text = document.body.innerText;
  const get = (label) => {
    const idx = text.indexOf(label);
    if (idx < 0) return null;
    return text.slice(idx + label.length, idx + label.length + 80)
      .split('\n').filter(x => x.trim()).slice(0, 2).join(' | ');
  };
  return {
    h1: document.querySelector('h1')?.innerText,
    status: get('Status'),                      // "Awaiting review | ..."
    disclosureBounty: get('Disclosure Bounty'),  // "$750 to $900 | ..."
    fixBounty: get('Fix Bounty'),
    relativeTimes: [...new Set(text.match(/\d+ (minute|hour|day|week|month)s? ago/g) || [])],
    reportedOn: (text.match(/Reported on [^\n]+/) || [''])[0],
    unprovenFlag: text.includes('UNPROVEN'),
    provenFlag: text.includes('VALIDATED'),
    closedOrRejected: /\b(Rejected|Invalid|Duplicate|Not applicable)\b/.exec(text)?.[0]
  };
}
```

### 2.4 Playwright 규칙 (IRON)
1. `browser_navigate` → `browser_evaluate`로 body text/status 추출 (snapshot보다 정확)
2. 미로그인 시 사용자에게 수동 로그인 요청 (자동 가입/로그인 **금지**)
3. 상태 텍스트 추출만 — Comment 추가, 버튼 클릭 등 **쓰기 작업 절대 금지**
4. 페이지당 1회 fetch — 과잉 traffic 회피
5. 다른 플랫폼: 순차 (동시 4개 초과 자제), 같은 플랫폼: 순차 (rate limit)

### 2.5 Direct Platform Rotation (사용자 요청 시)
Email MCP로 못 잡는 세부 정보(예: 댓글 타임라인, bounty 금액 확정, VRT 변경, triager 내부 메모)가 필요할 때 실행:

실행 순서 (Playwright 순차, 미로그인 감지 시 사용자에게 수동 로그인 요청):
1. **huntr** — `https://huntr.com/bounties/<id>` 각 submission 순회 → 섹션 2.3의 추출 패턴 재사용
2. **Bugcrowd** — `https://bugcrowd.com/submissions` 에서 list view → 각 row 상태/state change 스크래핑 (필요 시 개별 URL drill-in)
3. **YesWeHack** — `https://yeswehack.com/programs` → 본인 제출 필터
4. **Intigriti** — `https://app.intigriti.com/researcher/submissions` → state 칼럼
5. **HackenProof** — `https://hackenproof.com/profile` 에서 submission 탭
6. **Immunefi** — `https://bugs.immunefi.com/reports` (account 살아있을 때만)

각 플랫폼에서 수집:
- 상태 label (Pending / Triage / Accepted / Won't fix / Duplicate / etc.)
- bounty 금액 (Pending이면 `—`, Paid면 정확한 `$X`)
- last update 날짜
- 최근 triager/maintainer 댓글 요약 (1-2줄)

결과는 `/tmp/bounty_sync_rotation.json`에 기록 → Phase 3 diff에 통합.

**주의**:
- 로그인 세션이 끊긴 플랫폼은 `AWAITING_USER_LOGIN` 상태로 표시 후 스킵, 다음 플랫폼으로 진행
- 세션 유지된 플랫폼은 즉시 추출
- 같은 submission에 대해 Email MCP 결과와 rotation 결과가 다르면 rotation 우선 (더 최신)

출력: `/tmp/bounty_sync_observed.json`

---

## Phase 3 — Diff Report

`tracked.json` vs `observed.json` 비교:

```
| Platform | ID | Title | 기록 상태 | 실제 상태 | 변경 |
|----------|----|----|-----------|-----------|------|
| huntr | dc57e727 | onnx CAND-A | Pending | Triaging | ⚠️ |
| YWH | #16-705 | Qwant SSRF | Accepted | Paid $500 | 💰 |
| ... |
```

- 변경 있으면 ⚠️ 또는 💰/❌/✅ 이모지
- 없으면 ✓
- Stale (14일+ 변동 없음) 경우 ⏰ 플래그

---

## Phase 4 — MEMORY.md Update (사용자 confirm 필수)

변경된 항목에 대해서만:
1. 해당 `project_*.md` 파일 Read
2. 기존 상태 라인을 새 상태로 Edit (덮어쓰지 말고 timeline append 권장)
3. `### Timeline` 섹션 있으면 하단에 `- YYYY-MM-DD: <old> → <new>` 추가
4. 없으면 파일 하단에 Timeline 섹션 신규 생성

MEMORY.md 인덱스 entry 1줄 요약도 최신 상태 반영 (예: "Pending 11일" → "N/R -1점").

**IRON RULE**: 사용자가 "update 진행" 명시하기 전 **절대 자동 patch 금지**. 반드시 diff 리포트 → 확인 → patch.

---

## Phase 4.5 — Dashboard Sync (`docs/submissions.json`)

Phase 4 의 MEMORY.md 업데이트가 confirm되면 **동일한 변경을 `docs/submissions.json`에도 반영**.
이 파일은 `.gitignore` 에 등록된 로컬 전용 대시보드 데이터이며, `overview_server.py` watcher 가
즉시 감지해 브라우저가 자동 새로고침됨.

### 스키마 (array of object)
```json
{
  "platform":  "huntr | Bugcrowd | YesWeHack | Intigriti | HackenProof | HackerOne | Immunefi | Cantina | GHSA | Direct",
  "target":    "repo or program name",
  "title":     "vuln title + optional ID",
  "severity":  "Critical | High | Medium | Low | P1-P5 | —",
  "bounty":    "est $X-Y | $X (paid) | CVE | —",
  "status":    "Pending | Triage | Accepted | Won't fix | N/R | OOS | Submitted | Closed",
  "submitted": "YYYY-MM-DD",
  "note":      "1-line context (appeal / feedback / link)"
}
```

### 업데이트 규칙
1. **기존 항목 변경**: `target + title` (or submission ID) 매칭 → status / bounty / note 덮어쓰기
2. **신규 항목**: 배열 선두(index 0)에 push — 최신순 정렬 유지
3. **삭제 금지**: Closed / N/R / Won't fix 도 기록 유지 (track record 보존)
4. **null 필드**: `"—"` 사용 (빈 문자열 금지)
5. **Bounty 표기**:
   - Pending: `"est $X"` 또는 `"est $X-Y"` (범위면 en-dash `–`)
   - Accepted/Paid: `"$X paid"`
   - CVE only: `"CVE"`
6. **파일 없으면 생성**: `{"generated_at": "YYYY-MM-DD", "submissions": [...]}` 형식

### 실행 명령 (사용자 confirm 후)
```
Read  docs/submissions.json
Edit  — 변경 엔트리 또는 신규 push
```

`docs/submissions.json` 이 없으면 `.gitignore` 에 이미 등록되어 있음 — 새로 Write 해도 커밋되지 않음.

### 자동 반영 확인
- 서버 watcher: `docs/` 변경 감지 (1.5s polling)
- SSE broadcast → 브라우저 auto refresh
- Submissions 섹션의 카드/테이블/Cmd-K 검색 인덱스 모두 동기화

---

## Phase 5 (full/discover-missed 모드만) — Missed Submissions Sweep

### 5.1 플랫폼별 전체 submission 목록 수집
각 플랫폼의 "My reports / My submissions" 페이지 전체 페이지네이션 순회:
- `observed_full.json`: {platform, id, title, date, status}
- MEMORY.md에 기록된 ID 집합과 diff → **새로 발견된 제출** 리스트

### 5.2 CVE / Advisory sweep
- **GitHub GHSA by repo** (제출자 기준 조회 어려움 → 타겟 repo별 scan):
  ```bash
  # 제출 target repos 순회
  for repo in eProsima/Fast-DDS run-llama/llama_index onnx/onnx kubeflow/kubeflow; do
    gh api repos/$repo/security-advisories --paginate 2>/dev/null \
      | jq -r '.[] | select(.state != "published" or (.published_at | fromdate) > (now - 86400*30)) | "\(.ghsa_id) | \(.cve_id // "NO-CVE") | \(.state) | \(.summary)"'
  done
  ```
- **MITRE CVE Request 상태**:
  - Gmail에서 `from:mitre.org newer_than:30d` 검색 → "CVE Request NNNNNN" 번호 추출
  - 각 번호에 대한 후속 "CVE assigned" / "information needed" 이메일 확인
  - Manual lookup: `https://cveform.mitre.org/lookup/<request_id>` (MITRE form 로그인 필요)
- **NVD by discoverer name** (공개 CVE 후):
  - WebFetch(r.jina.ai) `https://nvd.nist.gov/vuln/search/results?query=%22Kyunghwan+Byun%22`
  - 특정 CVE ID 직접: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-NNNNN`
- **GHSA Credit 필드**: 각 advisory JSON의 `credits` 필드에서 researcher 확인
- **벤더 advisory RSS** (해당 시): Cisco PSIRT, Siemens, Schneider, ROS PSIRT 등

Discoverer 이름: `feedback_cve_discoverer_realname.md` 참조 — "Kyunghwan Byun".

### 5.3 결과 통합
- 신규 발견 항목을 `[NEW]` 플래그로 diff 리포트에 추가
- 사용자 confirm 후 해당 플랫폼/카테고리에 맞는 `project_<name>_<date>.md` 신규 생성 가이드 (파일 생성은 사용자 지시 후)

---

## Phase 6 — 최종 요약 출력

```
## Status Sync Report (YYYY-MM-DD)
- Tracked: N items checked
- Changed: M items (A accepted, B closed, C pending-longer)
- Stale (>14d): D items → follow-up 추천
- Newly discovered: E items (full 모드)
- CVE updates: F published / G pending
- Dashboard: docs/submissions.json updated (K entries modified, L added)
- Errors: any platform login issue
```

패턴별 후속 action 제안:
- **Won't fix / N/R**: appeal 가능한지 확인 (feedback_ywh_appeal_workflow 등)
- **Stale Pending 14일+**: platform-specific nudge 정책 (feedback_platform_direct_check.md)
- **Accepted but unpaid**: payout timeline 확인

---

## 안전/제한

- 자동 로그인, 자동 회원가입, 자동 comment/submit 모든 것 **금지** (CLAUDE.md 전역 규칙)
- 쓰기 작업은 **MEMORY.md / project_*.md 파일 edit 한정** (사용자 confirm 후)
- 플랫폼 rate limit 준수 — 초당 2 request 미만
- 세션 만료/차단 감지 시 즉시 사용자에게 알림, skill은 중단

---

## 실행 예시

```
/bounty-status-sync               # quick mode
/bounty-status-sync full          # full sweep + CVE
/bounty-status-sync discover-missed  # 놓친 제출만 탐색
```

호출 시 Orchestrator는 위 Phase 1→5 순으로 진행, Phase 3 diff 보고 후 사용자 응답 대기.
