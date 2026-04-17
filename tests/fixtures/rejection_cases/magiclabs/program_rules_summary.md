## Program Overview
Bugcrowd bug bounty program for Magic Labs — a Web3 authentication and wallet SDK provider.
Platform: Bugcrowd. Rewards: $150–$5,000.

## Severity Scope
Critical, High, Medium, Low

## In-Scope Assets
- app.magic.link (main authentication application)
- api.magic.link (REST and WebSocket API)
- dashboard.magic.link (developer dashboard)
- *.magic.link subdomains (authenticated application surfaces)

## Out-of-Scope
- Self-XSS requiring victim interaction with attacker-controlled page
- Findings in third-party dependencies not introduced by Magic Labs
- Issues in decommissioned SDK versions (< 10.x)
- Social engineering
- Phishing and UI redressing without technical vulnerability

## Asset Scope Constraints
SDK behavior tested in isolation without a live Magic Labs endpoint interaction is not eligible.
All findings must be reproducible against production app.magic.link or api.magic.link.

## Submission Rules
Client-side only vulnerabilities are not eligible for a bounty award.
Findings must have a demonstrated server-side impact or cross-origin attacker-controlled exploitation.
All reports must include step-by-step reproduction on the live production target.
Theoretical findings or SDK-isolated demonstrations without a live end-to-end exploit will be closed as Not Reproducible.
Evidence must show an attacker-controlled session or attacker-accessible data exfiltration.

## Known Issues
- PKCE flow uses localStorage for codeVerifier in SDK versions < 21.x (documented behavior, upgrading to sessionStorage in v22)
