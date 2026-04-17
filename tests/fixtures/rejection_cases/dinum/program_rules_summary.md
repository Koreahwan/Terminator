## Program Overview
YesWeHack bug bounty program for DINUM — Démarches Simplifiées, the French government's
online administrative procedure platform. Operated by the Direction Interministérielle du Numérique.
Platform: YesWeHack. Rewards: €50–€2,000.

## Severity Scope
Critical, High, Medium, Low

## In-Scope Assets
- demarches-simplifiees.fr (main platform)
- api.demarches-simplifiees.fr (REST API)
- instructeurs.demarches-simplifiees.fr (instructor interface)

## Out-of-Scope
- Informational findings without exploitable impact
- Rate limiting without demonstrated account takeover or data loss
- Missing security headers without demonstrated impact
- Issues in third-party integrations (France Connect, ProConnect)
- Denial-of-service attacks
- Social engineering

## Asset Scope Constraints
Production environment only.
Staging environments are excluded.
Test accounts must be self-registered — do not use real citizen data.

## Submission Rules
This is a government public platform accessibility program. We ensure accessibility for all citizens.
All procedures must be accessible to all users regardless of input format or validation constraints.
Reports must be written in French or English.
Coordinated disclosure: notify DINUM before any public disclosure.
CVSS 3.1 scoring required.

## Known Issues
- SIRET prefill accepts non-validated input (intentional: accessibility requirement)
- No maximum length enforcement on free-text fields (intentional: universal access design)
