# Typed Knowledge Routing

Date: 2026-04-28
Status: accepted

## Context

The repository has several high-volume reference stores: rules, knowledge notes,
scenario checklists, submissions, triage objections, decision records, reports,
external security corpora, CVE/PoC databases, and agent/session memory. Treating
all of them as one broad search space increases recall, but it also increases
noise and can contaminate phase-specific reasoning.

## Decision

Use typed retrieval by default. Pipeline agents should call
`routed_search(role, query, phase, program)` before broad `smart_search`.

Source classes have separate jobs:

- Rules: hard constraints; do not treat as optional reference material.
- Techniques/scenarios/protocol indexes: discovery and analysis context.
- Exploit/CVE/PoC sources: duplicate checks and exploit feasibility checks.
- Triage objections: Gate, critic, triager-sim, and target-evaluator calibration.
- Decisions: past GO/KILL rationale and strategy change memory.
- Submissions/reports: reporting and review examples, not discovery evidence.
- Session memory: handoff/debug context, not vulnerability corpus.
- llm-wiki sources: agent knowledge organization and AI/LLM workflow references.

## Role Routing

- `target-evaluator`: rules, triage objections, decisions, submissions.
- `scout`: scenarios, protocol checklists, techniques, known exploit signals.
- `analyst`: scenarios, protocol checklists, internal/external techniques.
- `ai-recon`: AI scenarios, OWASP/Agentic refs, llm-wiki sources.
- `exploiter`: CVE/PoC/exploit sources, bypass alternatives, evidence patterns.
- `reporter`: submissions, platform/report quality notes, triage objections.
- `critic` / `triager-sim`: triage objections, decisions, submissions.

## Consequences

Broad search remains available, but it is a fallback. Agents must avoid pulling
submission style examples into discovery and must avoid using CVE/PoC matches as
evidence unless the component and version are verified in scope.
