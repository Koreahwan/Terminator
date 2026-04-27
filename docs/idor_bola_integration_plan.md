# IDOR/BOLA Integration Plan

## Existing Files To Extend

- `tools/vuln_assistant/models.py`: add IDOR/BOLA object-reference, candidate, response fingerprint, and verification result models.
- `tools/vuln_assistant/cli.py`: keep `analyze` intact and add `idor-passive` / `idor-verify` subcommands. Add optional passive IDOR output for `analyze`.
- `tools/vuln_assistant/normalizer.py`: reuse existing `SurfaceItem` parsing. When reading `attack_surface.json`, reconstruct items from `raw_inventory` only to avoid recursive self-parsing.
- `tools/vuln_assistant/output_router.py` and `reporter.py`: keep existing artifacts and add IDOR/BOLA outputs when requested.

## New Files

- `tools/vuln_assistant/idor_analyzer.py`: passive object-reference detection, scoring, and markdown/JSON output.
- `tools/vuln_assistant/response_fingerprint.py`: redacted response fingerprinting without body storage.
- `tools/vuln_assistant/idor_verifier.py`: gated read-only two-owned-account verification.
- `integrations/burp_bridge_server.py`: localhost passive Burp metadata receiver.
- `integrations/burp_extension/README.md`: Montoya extension design and build notes.

## CLI Commands

```bash
python3 -m tools.vuln_assistant idor-passive \
  --input targets/acme/bounty/attack_surface.json \
  --out targets/acme/idor

python3 -m tools.vuln_assistant idor-verify \
  --mode bounty \
  --candidates targets/acme/idor/idor_candidates.json \
  --owned-objects owned_objects.json \
  --scope-host api.example.com \
  --auth-a-env ACCOUNT_A_TOKEN \
  --auth-b-env ACCOUNT_B_TOKEN \
  --out targets/acme/idor
```

Raw auth secrets must not be required as command-line values. Environment-variable or local profile based input is preferred to avoid shell history and process-list leakage.

## Expected Outputs

- `idor_candidates.json`
- `idor_manual_queue.md`
- `idor_verification.json`
- `idor_verification_summary.md`
- `idor_report_draft.md`

Existing outputs such as `attack_surface.json`, `endpoint_map.md`, `manual_test_queue.md`, and `safe_pocs.md` remain unchanged unless passive IDOR output is explicitly enabled.

## Safety Assumptions

- Passive analysis sends no network traffic.
- Verification is refused in `client-pitch` mode.
- Verification requires explicit allowed scope hosts, two auth profiles, and two user-provided owned object IDs.
- Verification only uses `GET` and `HEAD`.
- Verification never enumerates, guesses `id+1`, scans ranges, mutates state, follows redirects by default, or stores raw response bodies.
- Results are phrased as `possible IDOR/BOLA` and `needs_manual_confirmation` unless a human later confirms the issue outside this module.

## Tests To Add

- `tests/test_idor_analyzer.py`
- `tests/test_response_fingerprint.py`
- `tests/test_idor_verifier.py`
- `tests/test_burp_bridge_server.py`

Coverage must include object-reference detection, unsafe-method rejection, client-pitch verification rejection, scope enforcement, auth secret redaction, no body storage, conservative report wording, and Burp bridge metadata redaction.
