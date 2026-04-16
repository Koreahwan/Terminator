# Supply Chain Security Reference

## Dependency Resolution Rules by Package Manager

| Manager | Resolution Rule | Confusion Risk |
|---------|----------------|----------------|
| npm | Highest version wins (public > private if higher) | HIGH — namespace squatting |
| pip | Latest version from configured index | HIGH — `--extra-index-url` adds public |
| Maven | First repo in settings.xml wins | MEDIUM — repo ordering |
| Go modules | Module path = import path (no registry conflict) | LOW — path-based |
| NuGet | Highest version from any configured source | HIGH — source priority |

## Top Vulnerability Classes

| # | Class | CWE | Severity | Automation |
|---|-------|-----|----------|------------|
| 1 | Dependency Confusion | CWE-427 | Critical | High — registry search |
| 2 | Typosquatting | CWE-494 | High | High — name generation |
| 3 | Build Pipeline RCE | CWE-94 | Critical | Medium — CI config analysis |
| 4 | Unpinned Dependencies | CWE-829 | Medium | High — lockfile check |
| 5 | Stale/Abandoned Package | CWE-1104 | Medium | High — metadata check |
| 6 | CI Secret Leak | CWE-200 | High | Medium — log/artifact search |
| 7 | Package Script Execution | CWE-94 | Critical | High — manifest analysis |
| 8 | Lock File Manipulation | CWE-345 | High | Low — integrity check |
| 9 | Registry Scope Misconfig | CWE-16 | Critical | High — config file check |

## Dependency Confusion Attack Flow

```
1. Attacker discovers internal package name (README, error logs, CI output)
2. Registers same name on public registry (npm/PyPI) with higher version
3. Target's build system resolves public package (higher version wins)
4. Malicious postinstall/setup.py executes on build server
5. Evidence: DNS callback from build server to attacker's domain
```

**Safe PoC method**: Do NOT upload. Instead:
- Show registry search proving name is available
- Show .npmrc/.pip.conf proving public registry is consulted
- Show version resolution logic proving public would win
- Demonstrate with DNS callback in hypothetical scenario

## CI/CD Attack Vectors

| Platform | Vector | Evidence |
|----------|--------|---------|
| GitHub Actions | `${{ github.event.issue.title }}` script injection | Workflow YAML snippet |
| GitLab CI | Unprotected variables in merge request pipelines | .gitlab-ci.yml analysis |
| Jenkins | Groovy sandbox escape in shared libraries | Jenkinsfile + library code |
| CircleCI | Forked PR access to secrets | config.yml analysis |

## Key Tools

- `syft` — SBOM generation (CycloneDX/SPDX output)
- `grype` — Vulnerability matching against SBOM
- `cdxgen` — Alternative SBOM generator
- `pip-audit` / `npm audit` — Built-in vulnerability scanning
- `trufflehog` — Secret detection in repos and CI configs
- `socket.dev` CLI — Supply chain risk analysis

## Notable Supply Chain Incidents

| Year | Incident | Vector | Impact |
|------|----------|--------|--------|
| 2021 | ua-parser-js | Maintainer account compromise | Cryptominer in 7M+ weekly downloads |
| 2021 | Dependency Confusion (Birsan) | Namespace collision | 35+ major companies affected |
| 2022 | colors.js/faker.js | Maintainer sabotage | Infinite loop in production apps |
| 2023 | PyTorch nightly | Dependency confusion on PyPI | Exfiltrated env vars from CI/CD |
| 2024 | xz-utils | Social engineering + backdoor | SSH auth bypass in Linux distros |

## References

- Alex Birsan "Dependency Confusion": https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- SLSA Framework: https://slsa.dev/
- OpenSSF Scorecard: https://securityscorecards.dev/
