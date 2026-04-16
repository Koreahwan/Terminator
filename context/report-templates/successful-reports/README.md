# Successful Reports

Place sanitized copies of accepted bug bounty reports here for style learning.

## How to Add

1. Copy the accepted report (remove sensitive details: auth tokens, internal URLs)
2. Name: `[platform]-[vuln-type]-[date].md` (e.g., `bugcrowd-idor-2026-03.md`)
3. Add a frontmatter block:

```yaml
---
platform: bugcrowd|hackerone|immunefi|zdi|msrc|vendor
vuln_type: IDOR|XSS|SSRF|RCE|etc
severity: critical|high|medium|low
accepted: true
bounty: $X,XXX (optional)
date: YYYY-MM-DD
---
```

## What Reporter Learns From These

- Tone and language that passed triage
- Level of technical detail expected
- Evidence format that was sufficient
- How severity was justified
- Structure and section ordering

## Privacy

- Redact all auth tokens, API keys, internal URLs
- Replace target names with `[TARGET]` if under NDA
- Keep technical details intact — that's what matters for learning
