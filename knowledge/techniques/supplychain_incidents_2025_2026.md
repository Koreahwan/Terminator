# Supply Chain Security — Incidents & Attack Patterns (2025-2026)

> **Authorized testing context**. 아래 PoC는 자체 소유 registry, CI/CD sandbox,
> 또는 해당 프로그램(`GitHub Security Lab`, `npm/pypi security`)의 bounty scope에서만 사용.

---

## 1. 최근 대형 사고 (2024-2026)

### 1.1 tj-actions/changed-files 오염 (2025-03)
- **CVE**: CVE-2025-30066
- **영향**: `tj-actions/changed-files` GitHub Action이 임의 시점 태그(`v35`, `v44` 등) 모두 오염된 커밋을 가리키도록 변경 → 사용 워크플로 23,000+ 건에서 secrets (OIDC, AWS, NPM token) 로그 유출 위험
- **Root cause**: Third-party action의 mutable tag 의존, public repo fork가 secrets에 접근할 수 있는 `pull_request_target` 등 위험 패턴
- **영향 기간**: 2025-03-14 ~ 03-15 (신속 롤백)
- **후속**: `reviewdog/action-*` 등 연관 actions도 유사 공격 (CVE-2025-30154)

### 1.2 Shai-Hulud npm 자기복제 웜 (2025-09)
- **영향**: `chalk`, `debug` 등 수백 개 인기 npm 패키지가 공격자가 게재한 악성 버전으로 교체
- **Mechanism**: 감염된 maintainer 계정의 2FA bypass phishing → postinstall 스크립트가 로컬 npm 토큰 수집 및 다른 owned 패키지 재배포 (자기복제)
- **확산**: 500+ 패키지로 전파 추정
- **탐지**: 비정상 postinstall, 원격 eval, base64 blob, bundle에 포함된 tokens.txt 스캔

### 1.3 ua-parser-js 계보 (지속적)
원래 2021 사건 이후 2023-2025까지 유사 계정 탈취 사고 반복. 교훈: 의존성 트리 깊이 3+ 이상에서는 수동 감사 불가 → SBOM + 실시간 모니터링 필수.

### 1.4 xz-utils 백도어 (CVE-2024-3094)
- **영향**: 장기간 신뢰 쌓은 maintainer 계정(`Jia Tan`)이 liblzma에 back door 삽입
- **교훈**: 사회공학적 maintainer takeover는 code-review만으로 탐지 불가, reproducible build + 다수 검증자 필요

### 1.5 PyPI typosquat / install-script 웜 (지속)
2024-2025 동안 주기적으로 대량 등록/삭제. 대표 패턴:
- `requests` → `reqeusts`, `urllib3` → `urllib-3`
- `discord.py` API 훔치는 `discordpy`
- 공격 vector: `setup.py` 안의 임의 파이썬 실행, `__init__.py` import 시점 실행

### 1.6 GhostAction 류 GitHub Actions 체인
Third-party action이 내부에서 또 다른 third-party action을 `uses:`로 호출하는 깊은 의존성 → 최상단만 pin 해도 하위 action이 tag mutable로 교체됨.

### 1.7 기타 언급 가치 있는 사고
- Ledger Connect Kit 사고 (2023-12, 교훈 지속 유효)
- `colors.js`/`faker.js` maintainer의 자발적 악성 커밋 (2022, 공급망 신뢰 붕괴 고전 사례)
- `event-stream` / flatmap-stream 장기 공격 (고전)

---

## 2. 공격 벡터 분류

### 2.1 Typosquatting / Dependency Confusion
- **Namespace collision**: 내부 private 패키지와 동일 이름을 public registry에 등록. `npm install`/`pip install`이 public에서 최신 버전을 자동으로 가져감
- **스코프 혼동**: `@company/util` vs `company-util`
- **Cross-registry confusion**: 사내 nexus/artifactory 설정 오류로 public→private 우선순위 뒤집힘

### 2.2 Maintainer Account Takeover
- 2FA 없음, 약한 비밀번호, phishing to maintainer 이메일
- OAuth 앱 악용 (npm `npm token create --oidc`)
- Session token 탈취 via compromised dev machine

### 2.3 Install-time Code Execution
- npm `postinstall`, `preinstall`, `prepublish` hooks
- PyPI `setup.py` (PEP 517 전환 중 일부 패키지 여전)
- Cargo `build.rs`
- Maven `@Mojo`

### 2.4 CI/CD 워크플로 남용
- `pull_request_target` + `actions/checkout@v4 { ref: ${{github.event.pull_request.head.ref}} }` — untrusted PR 코드를 trusted secrets 컨텍스트에서 실행
- `workflow_run` 위장
- GitHub Actions OIDC sub claim 조작으로 잘못된 AWS role trust 획득

### 2.5 Build-time SSRF / 설정 유출
- Private registry 호스트로 SSRF
- `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials.toml` 파일 읽기
- `.git/config` 내 token

### 2.6 Lockfile Injection / Integrity Mismatch
- `package-lock.json`의 `resolved` URL만 변조 → 다른 registry에서 가져오기
- `yarn.lock` integrity 필드 누락
- pnpm/npm의 workspace alias trick

### 2.7 Binary / Wheel Signing Weaknesses
- PyPI Trusted Publishers 미설정 상태의 upload key 유출
- conda-forge/anaconda의 binary 검증 gap

---

## 3. PoC 스니펫 (authorized)

### 3.1 Dependency Confusion Probe (scope: own org)
```bash
# 1. 내부에서만 쓰이는 패키지 이름 수집
grep -rE "@yourorg/[a-z0-9-]+" package.json package-lock.json
# 2. public registry에 같은 이름 존재 여부
curl -s https://registry.npmjs.org/@yourorg/utility | jq '.name,.versions | keys'
# 3. 존재하지 않으면 squatting 가능 — 내부 policy에 따라 pre-register 또는 private-only flag 필요
```

### 3.2 GitHub Actions — pull_request_target 진단
```bash
# repo에서 위험 패턴 감지
grep -RnE 'on:\s*\n.*pull_request_target' .github/workflows/
# 위험: ref를 PR head로 잡고 runtime에 npm ci / pip install 실행
```

### 3.3 OSV-Scanner / Socket.dev 자동 스캔
```bash
# 프로젝트 의존성 트리 전체 CVE 스캔
osv-scanner --lockfile=package-lock.json
osv-scanner --lockfile=poetry.lock
osv-scanner --lockfile=Cargo.lock

# Socket CLI (npm supply chain specific)
npx @socketsecurity/cli npm install <pkg>  # 설치 전 위험 평가
```

### 3.4 Lockfile integrity 검증
```bash
# npm — resolved URL이 공식 registry인지
jq '.packages|to_entries[]|select(.value.resolved|test("registry.npmjs.org|registry.yarnpkg.com")|not)' package-lock.json
```

---

## 4. 탐지 도구 카탈로그 (2026-04 기준)

| 도구 | 범위 | 특징 |
|------|------|------|
| `osv-scanner` | 다중 lockfile | OSV DB + OSS-Fuzz |
| `socket.dev` CLI | npm/pypi | 실시간 behavioral risk |
| `snyk` | 언어 광범위 | 상용, FP 낮음 |
| `stepsecurity/harden-runner` | GH Actions | egress-policy, 실시간 차단 |
| `trufflehog` | git/filesystem | secret 탐지 (팀에서 다년간 사용) |
| `gitleaks` | git history | pre-commit hook 조합 |
| `noseyparker` | 대규모 repo | 메모리 효율, fast scan |
| `semgrep` + supply-chain rules | 코드 패턴 | `setup.py` 악성 패턴 탐지 |
| `grype` / `syft` | 컨테이너 이미지 | SBOM 생성 + 취약점 매칭 |
| `cyclonedx-cli` | SBOM | ISO 표준 형식 |
| `guac` (OpenSSF) | SBOM 그래프 | 의존성 체인 시각화 |

---

## 5. Evidence Tier 매핑 (bb_pipeline_v13)

| Tier | 조건 |
|------|------|
| E1 | 실제 public registry에 악성 패키지 업로드 (self-test) + 타겟 CI가 install까지 진행하는 스크린샷. Secret 유출은 본인 dummy secret만 |
| E2 | 타겟 CI가 untrusted PR의 코드를 trusted secret 컨텍스트로 실행하는 워크플로 설정 발견 + 실행 로그. 실제 exfil 없이 경로만 증명 |
| E3 | `pull_request_target` + secrets 노출 가능성 분석, 코드리뷰만 |
| E4 | SBOM/의존성 지표 기반 추론 |

---

## 6. 바운티 프로그램

- **GitHub Security Lab** — Actions ecosystem, OSS 전반
- **npm Security** — 악성 패키지 제보 + 계정 탈취
- **PyPI Security** — 동일
- **Snyk Vulnerability Disclosure** — 클라이언트 응용 범위
- **HackerOne IBB** — 크리티컬 OSS 공용 바운티
- 개별 프로그램 (Shopify, GitHub, GitLab)의 `supply_chain.*` VRT 카테고리

---

## 7. 파이프라인 연계

- **sc-scanner** agent: SBOM + 의존성 트리 + namespace collision probe
- **analyst(domain=supplychain)**: 본 문서의 "공격 벡터 분류" 리스트로 체크
- **Gate 1**: 프로그램이 `supply_chain.*` scope 포함 여부 — 생각보다 많은 프로그램이 OOS로 분류
- **Gate 2**: 실제 install/build 실행 증거 필수 — 정적 분석만으로는 E3

---

## 8. 참조

- CISA advisory: tj-actions/changed-files incident (2025-03)
- GitHub Security blog — GitHub Actions security best practices
- StepSecurity — https://www.stepsecurity.io/incidents (사고 목록 유지)
- OpenSSF Supply Chain Framework (S2C2F)
- SLSA v1.0 (Supply chain Levels for Software Artifacts)
- Sonatype State of the Software Supply Chain (연간 리포트)

마지막 업데이트: 2026-04-16
