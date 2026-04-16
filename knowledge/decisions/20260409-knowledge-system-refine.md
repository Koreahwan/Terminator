# [20260409] Knowledge System Refinement

## Context
Audit of 10 knowledge/storage systems revealed: 3 dead (Wiki, RAG, GraphRAG),
search gaps (triage_objections not in FTS5, explore_candidates not indexed),
root orphan files (37 at root), and missing decision tracking.

## Decision
Phase approach on dev/structure-refine branch:
- P0: Clean root orphans, archive dead systems (rag_system)
- P1: Add triage_objections FTS5 + search dedup + candidate-index
- P2: Expand scaffold (2->5 files)
- Activate OMC Wiki for decisions/patterns/debugging knowledge
- Add AgDR (Agent Decision Records) in knowledge/decisions/
- Do NOT implement RAG/GraphRAG (overkill for current scale)
- File structure verdict: REFINE (not RESTRUCTURE) due to 29 hardcoded paths

## Alternatives Considered
- Full RESTRUCTURE (rejected: 29 hardcoded paths, migration cost > benefit)
- Letta/Mem0 (rejected: overlaps with existing auto-memory, extra infra)
- RAG with pgvector (rejected: FTS5 covers 80%, remaining 20% not worth PostgreSQL setup)

## Consequences
- 3 dead systems archived, cleaner project root
- triage_search enables Gate pre-checks against past kills
- Wiki accumulates session knowledge across conversations
- AgDR provides auditable decision trail for future postmortems
- P0-3 (NO-GO target archive) deferred to main (gitignored data)

## Status
accepted
