# Knowledge Search Protocol

Use `ToolSearch("knowledge-fts")` to load MCP tools. Never `cat knowledge/techniques/*.md` or read files directly.

## Tool Access

```python
# Load MCP tools
ToolSearch("knowledge-fts")

# Available functions (auto-loaded):
# - smart_search(query)
# - technique_search(vuln_type)
# - exploit_search(service_or_cve)
# - challenge_search(name)
```

## Preferred Search Order

1. **smart_search(query)** — DEFAULT. Auto-relaxes on fail (AND → OR → top-terms)
   ```
   smart_search("QNAP buffer overflow")
   # Tries: exact match → partial relaxation → top keywords separately
   ```

2. **technique_search(vuln_type)** — Vulnerability abbreviations
   ```
   technique_search("UAF")  # expands to Use-After-Free
   technique_search("IDOR")  # expands to Insecure Direct Object Reference
   ```
   Auto-expands: RCE, SSRF, XXE, SSTI, TOCTOU, LFI, Prototype Pollution, etc.

3. **exploit_search(service_or_cve)** — ExploitDB + nuclei + PoC + trickest-cve 155K + web_articles
   ```
   exploit_search("CVE-2021-44228")
   exploit_search("Apache Struts RCE")
   ```

4. **challenge_search(name)** — Past CTF/BB solutions
   ```
   challenge_search("ret2libc")
   challenge_search("HeapExploit")
   ```

5. **OR syntax** — Combine related terms
   ```
   smart_search("ret2libc OR ret2csu OR ret2syscall")
   technique_search("UAF OR heap spray")
   ```

## Query Rules

- **2-3 keywords max** — Brevity increases recall
- ✅ `"QNAP buffer overflow"`
- ❌ `"QNAP QTS wfm2_save_file buffer overflow strcpy"`
- ✅ `"ret2libc"` or `"ret2libc OR ret2csu"`
- ❌ `"return-to-libc gadget chaining with printf leak"`

## Result Summary

- Capture **top 3-5 results** from each search
- Include in HANDOFF `[KNOWLEDGE CONTEXT]` section (always present, even if empty)
- Format:
  ```
  [KNOWLEDGE CONTEXT]
  1. [Source] — <1 sentence key finding>
  2. [Source] — <1 sentence key finding>
  (No match if search returned 0 results)
  ```

## Web Content Integration

For articles/writeups:
```bash
python3 tools/knowledge_fetcher.py fetch <url>
# Or manually:
python3 tools/knowledge_fetcher.py bulk knowledge/sources/<name>.md
```
Adds to `web_articles` table in knowledge.db.

## Error Handling

- **0 results** → Try relaxed query (remove most specific term)
- **Too many results** → Add constraint (`"service AND version"`)
- **Citation needed** → `challenge_search()` → `exploit_search()` → `WebSearch()` (last resort)
