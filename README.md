# Terminator

Terminator is now focused on **Bug Bounty**, **AI Security**, and **Client Pitch**
workflows. The product goal is not to list every endpoint; it is to preserve raw
surface inventory, identify high-value risk signals, and translate those signals
into safe testing plans or client-ready assessment pitches.

## Modes

```bash
./terminator.sh bounty https://target.com "*.target.com"
./terminator.sh ai-security https://app.example.com "LLM agent workflow"
./terminator.sh client-pitch https://company.com
./terminator.sh status
./terminator.sh logs
```

Removed legacy modes:

- `ctf`
- `firmware`
- `robotics`
- `supplychain`

Running a removed mode returns an unsupported-mode error.

## Shared Pipeline

`bounty` and `client-pitch` share the same risk engine:

```text
Recon/Input
  -> Raw Endpoint Inventory
  -> Surface Normalizer
  -> Risk Classifier
  -> Vulnerability Hint Engine
  -> Business Risk Mapper
  -> Risk Score + Confidence Score
  -> Raw Endpoint Review Queue
  -> Safe Test Planner
  -> Output Router
       -> bounty
       -> client-pitch
       -> ai-security
```

The raw endpoint inventory is never discarded. Low-scoring endpoints can still
land in `raw_endpoint_review.md` when they look like legacy APIs, generic
state-changing workflows, protected-but-existing endpoints, GraphQL/gRPC/
WebSocket surfaces, or ambiguous parameterized routes.

## Vulnerability Assistant

Standalone usage:

```bash
python3 -m tools.vuln_assistant analyze \
  --mode client-pitch \
  --domain web \
  --input recon_output/recon_report.json \
  --endpoint-map targets/company/endpoint_map.md \
  --out targets/company/client_pitch
```

Passive IDOR/BOLA analysis:

```bash
python3 -m tools.vuln_assistant idor-passive \
  --input targets/company/bounty/attack_surface.json \
  --out targets/company/idor
```

Safe read-only IDOR/BOLA verification requires authorized bounty scope, two
owned test accounts, owned object IDs for both accounts, and exact scope hosts.
Secrets should be passed through environment variables or local auth profiles,
not raw command-line values:

```bash
ACCOUNT_A_TOKEN=... ACCOUNT_B_TOKEN=... \
python3 -m tools.vuln_assistant idor-verify \
  --mode bounty \
  --candidates targets/company/idor/idor_candidates.json \
  --owned-objects owned_objects.json \
  --scope-host api.example.com \
  --auth-a-env ACCOUNT_A_TOKEN \
  --auth-b-env ACCOUNT_B_TOKEN \
  --out targets/company/idor
```

Supported inputs:

- gau/wayback/katana URL lists
- httpx JSON
- Burp XML/HAR
- OpenAPI/Swagger JSON/YAML
- GraphQL schema/introspection text
- Postman collection JSON
- raw `endpoint_map.md`
- AI recon artifacts such as `model_profile.json`, `tool_surface_map.md`, and
  `agent_workflow_map.md`

Outputs:

- `attack_surface.json`
- `endpoint_map.md`
- `high_value_targets.md`
- `raw_endpoint_review.md`
- `vuln_hints.json`
- `manual_test_queue.md`
- `safe_pocs.md`
- `external_risk_summary.md`
- `security_assessment_pitch.md`
- `recommended_test_scope.md`
- `bug_bounty_report_draft.md`
- `ai_security_report_draft.md`
- `idor_candidates.json`
- `idor_manual_queue.md`
- `idor_verification.json`
- `idor_verification_summary.md`
- `idor_report_draft.md`

## Risk Taxonomy

The classifier uses 17 top-level categories:

1. Access Control
2. Authentication / Session
3. API Security
4. Business Logic
5. Admin / Internal Exposure
6. SSRF / Webhook / Integration
7. File / Upload / Download
8. Data Exposure / Privacy
9. Rate Limit / Abuse Protection
10. Sensitive Account Operations
11. Browser Trust Boundary
12. Realtime / WebSocket / Event API
13. Cache / CDN / Routing Confusion
14. Cloud / SaaS Exposure
15. Webhook / Integration Integrity
16. Audit / Logging / Non-Repudiation
17. AI / LLM Security

Each candidate receives:

```text
method
url/path
params
source
raw_rank
authorization_level
risk_categories
possible_vulns
business_risk
sales_angle
bug_bounty_angle
safe_next_step
risk_score: 1-10
confidence_score: 0-100
status: signal | candidate | needs_verification | confirmed | rejected
mode_allowed: bounty | client-pitch | ai-security
review_bucket: high_value | raw_review | low_priority | excluded
```

`risk_score` measures potential impact. `confidence_score` measures evidence.
A refund endpoint can be risk 10 and confidence 20 until it is actually tested.

## Safety

- `client-pitch` is passive-only and must not claim confirmed vulnerabilities.
- `bounty` requires scope/program rules before safe PoC generation.
- `ai-security` requires AUP/scope confirmation before probing.
- No automatic brute force, DoS, cache poisoning, webhook replay, metadata SSRF,
  sensitive file payloads, or destructive state-changing requests.
- State-changing endpoints are placed in the manual review queue.
- Evidence-free items stay `candidate` or `needs_verification`.
- `idor-passive` sends no network requests.
- `idor-verify` is refused in `client-pitch` mode and only uses `GET`/`HEAD`
  against explicit scope hosts with user-provided owned object IDs.
- IDOR/BOLA verification stores response fingerprints only, never raw response
  bodies or auth secrets, and outputs `needs_manual_confirmation` rather than
  automatic confirmed findings.

## Verification

Useful smoke checks:

```bash
python3 -m compileall tools/vuln_assistant tools/runtime_intent.py tools/terminator_dry_run_matrix.py tools/report_scorer.py tools/validation_prompts.py
bash -n terminator.sh
./terminator.sh --dry-run --json bounty https://example.com
./terminator.sh --dry-run --json client-pitch https://example.com
./terminator.sh --dry-run ai-security https://example.com "agent workflow"
python3 tools/terminator_dry_run_matrix.py --out /tmp/terminator_dryrun.json --profiles claude-only --pipelines bounty ai-security client-pitch
```
