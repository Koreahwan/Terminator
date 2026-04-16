---
name: supplychain
description: Start Supply Chain security testing pipeline. Auto-matches "supply chain", "dependency confusion", "SBOM", "npm audit", "pip audit", "package security"
argument-hint: [target-repo-url-or-path] [package-manager]
---

Launch Supply Chain Security pipeline via terminator.sh:

```bash
./terminator.sh supplychain <repo-url-or-path> [npm|pip|maven]
```

Pipeline: `supplychain` from `tools/dag_orchestrator/pipelines.py` (bounty/CVE auto-detect)
- Phase 0: target-evaluator (pkg manager, dep count, CI/CD, bounty program check)
- Phase 0.2: `python3 tools/bb_preflight.py init targets/<target>/ --domain supplychain`
- Phase 0.5: sc-scanner (SBOM via syft, grype vuln matching)
- Phase 1: sc-scanner + analyst(domain=supplychain) in parallel
- Phase 1.5: Dependency confusion deep scan (internal names vs public registry)
- Bounty track (if program exists): Gate 1 → exploiter → Gate 2 → reporter → critic → triager → final
- CVE track (no program): exploiter → reporter(CVE advisory) → critic → cve-manager

IRON RULES: NEVER upload packages to registries. Namespace conflict = existence check only.
Domain config: `--domain supplychain` (threshold 80%, sc_endpoint_map.md)
Time-box: ~4.5hr (fastest pipeline). No findings at 1hr → ABANDON.
