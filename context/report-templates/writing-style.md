# Vulnerability Report Writing Style Guide

## Core Principle

Write for the triager who has 50 reports in their queue today.
They will spend 30 seconds deciding if yours is worth reading.

## Observational Language (MANDATORY)

| DO NOT write | WRITE instead |
|-------------|---------------|
| "We discovered a vulnerability" | "Testing revealed that the endpoint responds with..." |
| "The vulnerability exists in" | "The reviewed implementation at file:line performs..." |
| "We found that" | "Analysis of the response indicates..." |
| "This proves" | "The observed behavior demonstrates..." |
| "Obviously" | (delete — if it's obvious, show it) |
| "Trivially exploitable" | "Exploitation requires [N] steps with [preconditions]" |
| "Critical vulnerability" | "The observed behavior allows [specific impact]" |

## First 3 Sentences Rule

A triager decides in 10 seconds. Your first 3 sentences must answer:
1. **What** is broken (component + vulnerability type)
2. **How** it's exploited (1-sentence attack path)
3. **Why** it matters (concrete impact, not abstract risk)

Example:
> The `/api/v2/users/{id}/settings` endpoint returns full user profile data
> for any authenticated user regardless of the `{id}` parameter value.
> An attacker with a basic account can enumerate and read settings for all
> 12,000+ users by iterating the sequential ID.
> This exposes email addresses, API keys, and billing information.

## Specificity Rules

| Vague (reject) | Specific (accept) |
|----------------|-------------------|
| "sensitive data" | "email, API key, billing address" |
| "many users affected" | "all 12,000+ registered users" |
| "recent version" | "v2.4.1 (released 2026-03-15)" |
| "significant impact" | "attacker reads all user API keys" |
| "the application" | "`auth-service` at `api.target.com:443`" |

## Structure Balance

- 60-70% prose (technical narrative)
- 20-30% structured data (code blocks, tables, lists)
- < 10% boilerplate (headers, metadata)

Avoid all-list reports — they read like automated scanner output.
Avoid all-prose reports — they're hard to scan.

## Sentence Construction

- Average: 15-20 words per sentence
- Mix short declarative ("The endpoint lacks authorization.") with
  longer technical ("When an authenticated user sends a GET request to
  `/api/v2/users/999/settings` with their own session token, the server
  returns a 200 response containing the target user's full profile.")
- Active voice > 80%
- One idea per paragraph, 2-4 sentences max

## Words to Avoid (AI Slop)

comprehensive, robust, seamless, leverage, utilize, holistic, paradigm,
cutting-edge, state-of-the-art, game-changing, synergy, furthermore,
moreover, nevertheless, notwithstanding, it should be noted, needless to say,
in today's landscape, at the end of the day, going forward, in order to,
due to the fact that

## Severity Language

- Never say "critical" unless CVSS confirms it
- Frame ambiguous findings as "abuse risk" not "vulnerability"
- "Regardless of design intent, the observed behavior creates operational
  risk because..." — when finding might be intended behavior
- Include honest severity expectation: "We expect triager to rate this
  MEDIUM because the attack requires authenticated access"
