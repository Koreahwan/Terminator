# Research: LLM-Based Security Agent Patterns

Terminator의 Agent Teams 아키텍처를 개선하기 위해 분석한 외부 프레임워크 및 학술 연구 모음.

## Status

**연구 완료, 에이전트 정의에 통합됨.** 아래 연구에서 도출된 패턴들은 `.claude/agents/*.md`와 `CLAUDE.md`에 직접 반영되었으며, 별도의 Python 코드 구현 없이 Claude Code Agent Teams의 프롬프트 및 워크플로우로 적용됨.

## Documents

### Core Research (2026-02)

| File | Lines | Purpose |
|------|-------|---------|
| **FINDINGS.md** | 472 | Executive summary: 6 actionable patterns from PentestGPT/try-harder |
| **quick_reference.md** | 404 | Top 3 patterns + code templates (prompting, idle recovery) |
| **llm_pentesting_patterns.md** | 709 | PentestGPT architecture (USENIX 2024) deep analysis |
| **integration_guide.md** | 676 | Implementation walkthrough (before/after comparisons) |

### Extended Research (2026-02)

| File | Lines | Purpose |
|------|-------|---------|
| **llm_bug_bounty_sota_2024_2026.md** | 1099 | XBOW (#1 H1), Shannon, Vulnhuntr, Big Sleep SOTA analysis |
| **bug_bounty_triage_insights_2024_2026.md** | 1446 | H1 triager patterns, AI slop crisis, rejection reasons |
| **multi_agent_orchestration_patterns_2024_2026.md** | 1115 | AIxCC winners (ATLANTIS/RoboDuck), A2A, structured handoffs |

### Target-Specific Research

| File | Purpose |
|------|---------|
| **doordash_technical_profile.md** | DoorDash BB technical stack analysis |
| **doordash_quick_reference.md** | DoorDash quick reference |
| **vpn_client_attack_techniques.md** | VPN client attack surface (NordSecurity) |
| **ORCHESTRATION_QUICK_REF.md** | Multi-agent orchestration quick reference |
| **RESEARCH_STAGE4_SUMMARY.md** | Research stage 4 summary |

## Key Findings Applied

| Finding | Source | Applied To |
|---------|--------|-----------|
| Never-Stop Prompting | PentestGPT | chain.md, solver.md (persistence language) |
| Idle Recovery Protocol | PentestGPT | CLAUDE.md (orchestrator rules) |
| Session Persistence | PentestGPT | knowledge/ system (file-based state) |
| PoC Quality Tier (1-4) | XBOW | exploiter.md (Tier 3-4 = auto-DROPPED) |
| Duplicate Pre-Screen | H1 triage insights | scout.md (Phase 0 mandatory) |
| Adversarial Triage Sim | H1 triage insights | triager_sim.md (SUBMIT/STRENGTHEN/KILL) |
| Confidence Questionnaire | Shannon | analyst.md (10-point checklist) |
| Structured Handoffs (CAI) | CAI/Shannon | CLAUDE.md (handoff protocol) |
| Variant Analysis Seeds | Big Sleep | scout.md (CVE diff → seed) |
| Dual-Approach Parallel | RoboDuck | CLAUDE.md (3 failures → 2 parallel) |
| Pipeline Skills (v6) | Internal retrospective | `.claude/skills/` (6 automated gates: oos-check, poc-tier, coverage-gate, threat-model-check, slop-check, checkpoint-validate) |
| Hard NO-GO Rules (v6) | 37-case retrospective | target_evaluator.md (3+ audits, 2+ reputable, 100+ reports = auto block) |
| Triager JSON Feedback Loop | Internal retrospective | triager_sim.md → reporter.md (max 3 iterations) |
| Kill Gate Integration (v11→v12) | 9-case rejection retrospective | triager_sim.md (3 modes: finding-viability, poc-destruction, report-review), CLAUDE.md (Gate 1+2 pipeline phases), bb_preflight.py (advisory gate checks). Pipeline upgraded to v12 (Explore Lane + Kill Gate) — see `.claude/rules/bb_pipeline_v12.md`. |

## Reading Guide

- **5 min**: `FINDINGS.md` (executive summary)
- **15 min**: + `quick_reference.md` (patterns)
- **60 min**: + extended research docs (deep dive)

## External References

- **PentestGPT**: USENIX Security 2024 - LLM-based penetration testing
- **try-harder**: OSCP game-based learning approach
- **Shannon**: Claude Agent SDK-based security agent (96% success)
- **XBOW**: H1 #1 AI researcher ($28K+ bounties)
- **ATLANTIS**: AIxCC 1st ($5M) - symbolic+neural hybrid
- **RoboDuck**: AIxCC 3rd ($1.5M) - dual-approach parallel
- **Big Sleep**: Google P0 + DeepMind - variant analysis
- **Vulnhuntr**: Python source → sink 3-pass analysis
- **CAI**: 300+ LLM coordination framework with guardrails

---

*Research Date: 2026-02-15*
