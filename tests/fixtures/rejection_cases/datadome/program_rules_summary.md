## Program Overview
Bugcrowd bug bounty program for DataDome — a bot protection and fraud prevention platform.
Platform: Bugcrowd. Rewards: $200–$10,000.

## Severity Scope
Critical, High

## In-Scope Assets
- *.datadome.co (DataDome management API and dashboard)
- device-link.datadome.com (device fingerprinting service)
- js.datadome.com (JavaScript challenge delivery CDN)
- api.datadome.com (integration API)

## Out-of-Scope
- Site vulnerabilities
- Issues in customer websites protected by DataDome (not developed by DataDome)
- Third-party component vulnerabilities (nginx, Redis, AWS configurations)
- Theoretical vulnerability chains without working PoC
- Denial-of-service attacks
- Rate limiting on public endpoints

## Asset Scope Constraints
Only DataDome's own infrastructure and product is in scope.
Vulnerabilities in DataDome customer deployments are not covered by this program.
Findings must relate to the bot detection or fraud prevention product functionality.

## Submission Rules
The goal of this program is to report ways around DataDome protection by implementing a scraping bot,
or to find vulnerabilities in DataDome's own product infrastructure.
Generic web application vulnerabilities on DataDome-adjacent domains are out of scope unless they
directly affect the bot-detection product or DataDome customer data.
All reports must include a working proof-of-concept.
CVSS 3.1 scoring required.

## Known Issues
- CAPTCHAs can be bypassed with certain ML-based solvers (acknowledged, hardening in progress)
