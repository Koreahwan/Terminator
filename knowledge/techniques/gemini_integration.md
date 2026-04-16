# Gemini CLI Integration

- Model: `gemini-3-pro-preview` (fixed)
- Location: `tools/gemini_query.sh`
- Modes: reverse, analyze, triage, summarize, protocol, bizlogic, summarize-dir, review, ask

| Agent | When | Mode |
|-------|------|------|
| scout | Large codebase (5K+ LOC) initial scan | summarize-dir, summarize |
| analyst | P1/P2 candidate selection + deep analysis | triage → protocol/bizlogic → analyze |
| reverser | Large decompile output (500+ lines) | reverse, summarize |
| exploiter | PoC code review | review |
