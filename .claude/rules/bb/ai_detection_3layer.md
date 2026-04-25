# Phase 4.5 — 3-Layer AI Detection (Detailed Spec)

Referenced from `bb_pipeline_v13.md` Phase 4.5. v12.3 MANDATORY before Phase 5. All 3 layers must PASS. Rhino.fi "AI spam" = account death.

## Layer 1: areuai Bridge Heuristic (automatic, instant)

```bash
python3 tools/ai_detect.py heuristic targets/<target>/submission/<name>/report.md
# PASS (exit 0) → Layer 2 | WARN (exit 1) → fix then retry | FAIL (exit 2) → full rewrite
```

`tools/ai_detect.py heuristic` delegates to `tools/areuai_bridge.py`, which
uses the global `~/.areuai` taxonomy/engine and falls back to an inline snapshot
if the CLI is unavailable. Direct equivalent:

```bash
/home/hw/.areuai/bin/areuai.py analyze targets/<target>/submission/<name>/report.md --mode report --lang auto --json
```

## Layer 2: Claude self-review (in-session, free)

```bash
python3 tools/ai_detect.py self-review-prompt targets/<target>/submission/<name>/report.md
# → Orchestrator runs generated prompt, evaluates score
# PASS (0-2) → Layer 3 | WARN (3-5) → reporter rewrite | FAIL (6+) → full rewrite
```

## Layer 3: ZeroGPT web check (Playwright MCP, free)

```bash
python3 tools/ai_detect.py zerogpt-instructions targets/<target>/submission/<name>/report.md
# → Orchestrator follows Playwright steps, reads result
# <10% AI → PASS | 10-50% → reporter rewrite | >50% → full rewrite
```

## IRON RULE

All 3 layers must PASS before Phase 5. Rhino.fi "AI spam" account-death precedent.
