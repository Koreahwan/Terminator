# Structured Handoff Protocol

### Structured Handoff Protocol

```
[HANDOFF from @<agent> to @<next_agent>]
- Finding/Artifact: <filename>
- Confidence: <1-10> (BB) or <PASS/PARTIAL/FAIL> (CTF)
- Key Result: <1-2 sentence core result>
- Next Action: <specific task for next agent>
- Blockers: <if any, else "None">
```

### Context Positioning (Lost-in-Middle Prevention)

```
[Lines 1-2] Critical Facts — key addresses, offsets, vuln type, FLAG conditions
[Lines 3-5] Program Rules — auth format, exclusion list (BB only, inject-rules output)
[Middle]    Agent definition (auto-loaded)
[End]       HANDOFF detail (full context, previous failure history)
```
