# AI/LLM Security Reference

## OWASP Top 10 for LLM Applications (2025)

| # | Category | Attack Vector | Detection |
|---|----------|---------------|-----------|
| LLM01 | Prompt Injection | Direct/Indirect/Stored/Recursive | Input validation, output filtering |
| LLM02 | Insecure Output Handling | XSS/SQLi/RCE via LLM output | Output sanitization, sandboxing |
| LLM03 | Training Data Poisoning | Manipulated training data | Data provenance, validation |
| LLM04 | Model Denial of Service | Context window exhaustion, infinite loops | Rate limiting, input size caps |
| LLM05 | Supply Chain Vulnerabilities | Compromised models/plugins | Model verification, SBOM |
| LLM06 | Sensitive Information Disclosure | PII/secret extraction from model | Output filtering, differential privacy |
| LLM07 | Insecure Plugin Design | Tool abuse via manipulated calls | Least privilege, input validation |
| LLM08 | Excessive Agency | Over-privileged LLM actions | Permission boundaries, human-in-loop |
| LLM09 | Overreliance | Hallucination exploitation | Grounding, fact-checking |
| LLM10 | Model Theft | Model extraction/replication | Rate limiting, watermarking |

## Prompt Injection Taxonomy

- **Direct**: Explicit instruction override in user input
- **Indirect**: Malicious instructions in retrieved data (RAG, web, email)
- **Stored**: Persistent injection via memory/conversation history
- **Recursive**: Self-replicating injection across agent chains

## Key AI Bounty Programs

| Program | Platform | Model Scope | Notable Rules |
|---------|----------|-------------|---------------|
| OpenAI | Bugcrowd | GPT-4o, o1, DALL-E | Universal jailbreaks OOS, target-specific only |
| Microsoft | MSRC | Copilot, Bing Chat | Security impact required, not just bypass |
| Google | Google VRP | Gemini, Bard | Novel attacks preferred, known prompts excluded |
| Anthropic | Direct | Claude | Responsible disclosure policy |

## Agentic AI Attack Vectors

- **Memory Injection**: Poison long-term memory → persistent manipulation
- **Tool Abuse**: Manipulate function calling → unauthorized actions
- **Agent Chaining**: Exploit handoff between agents → privilege escalation
- **Context Manipulation**: Overflow context window → instruction amnesia

## References

- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- AI Red Team playbook (NIST): https://csrc.nist.gov/pubs/ai/600-1/final
- Garak scanner: https://github.com/leondz/garak
- Promptfoo: https://github.com/promptfoo/promptfoo
