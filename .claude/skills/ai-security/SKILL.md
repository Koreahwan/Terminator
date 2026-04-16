---
name: ai-security
description: Start AI/LLM security testing pipeline. Auto-matches "ai security", "llm bounty", "prompt injection", "jailbreak hunt", "ai red team", "agent security"
argument-hint: [target-url-or-api-endpoint] [model-name]
---

Launch AI/LLM Security pipeline via terminator.sh:

```bash
./terminator.sh ai-security <target-url> [model-name]
```

Pipeline: `ai_security` from `tools/dag_orchestrator/pipelines.py`
- Phase 0: target-evaluator (AI program analysis, AUP check, scope verification)
- Phase 0.2: `python3 tools/bb_preflight.py init targets/<target>/ --domain ai`
- Phase 0.5: ai-recon (model fingerprinting, garak/promptfoo automated probes)
- Phase 1: ai-recon + analyst(domain=ai) in parallel
- Phase 1.5: Quick mutation test on top 3 candidates
- Gate 1: triager-sim(domain=ai) — universal vs target-specific check
- Phase 2: exploiter(domain=ai) — jailbreak PoC, injection chains
- Gate 2: triager-sim(domain=ai) — PoC destruction + determinism check
- Phase 3-5: reporter → critic → triager-sim → final report

Domain config: `--domain ai` (threshold 80%, ai_endpoint_map.md, ai_program_rules_summary.md)
Time-box: ~6.5hr. No findings at 1.5hr → ABANDON.
