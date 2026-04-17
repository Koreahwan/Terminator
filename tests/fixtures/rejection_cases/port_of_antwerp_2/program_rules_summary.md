## Program Overview
Intigriti bug bounty program for the Port of Antwerp-Bruges NV digital infrastructure.
Platform: Intigriti. Rewards: €100–€5,000 based on CVSS severity.

## Severity Scope
Critical, High, Medium, Low

## In-Scope Assets
- app.portofantwerp.com
- api.portofantwerp.com
- portal.portofantwerp.com
- *.portofantwerp.be (web applications only)

## Out-of-Scope
- Verbose messages/files/directory listings without disclosing any sensitive information
- Missing security headers (X-Frame-Options, CSP, HSTS without demonstrated impact)
- Clickjacking on pages without authentication or sensitive actions
- Self-XSS (only exploitable by the victim themselves)
- Scanner-generated reports without manual validation
- Theoretical vulnerabilities without proof-of-concept
- Physical security findings
- Social engineering

## Asset Scope Constraints
Web applications and APIs under the listed domains only.
Mobile applications are out of scope.
Staging / development environments are out of scope.

## Submission Rules
All reports must include a working proof-of-concept.
CVSS 3.1 scoring required.
Coordinated disclosure — do not publish until patched or 90 days elapsed.
English language preferred; Dutch accepted.

## Known Issues
- HTTP to HTTPS redirect on legacy subdomain api-legacy.portofantwerp.com (tracked internally)
- Rate limiting not yet applied to public vessel search endpoint (known, low priority)
