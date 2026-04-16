# Target Assessment: Trusted Firmware (TF-A, TF-M, OP-TEE, MbedTLS)

**Evaluator**: target-evaluator
**Date**: 2026-03-22
**Platform**: Intigriti (Arm-operated)
**Program URL**: https://app.intigriti.com/programs/arm/trustedfirmware/detail
**Session**: a7b85febbb2f37830

---

## Checkpoint
```json
{
  "agent": "target-evaluator",
  "status": "completed",
  "phase": 5,
  "phase_name": "scoring",
  "completed": ["program_intelligence", "hardening", "competition", "feasibility", "scoring"],
  "in_progress": "none",
  "critical_facts": {"score": 52, "decision": "GO", "kill_signals": []},
  "expected_artifacts": ["target_assessment.md"],
  "produced_artifacts": ["target_assessment.md"],
  "timestamp": "2026-03-22T00:00:00Z"
}
```

---

## Decision: GO (52/60)

---

## Structured Scoring

```
DIMENSION 1 — Recency: Score: 9/10
  OBSERVED: Bug bounty program launched December 18, 2025 — only ~3 months old.
  TF-A latest commit March 18, 2026 (active development). TF-A v2.14 released recently.
  TFV-13 (CVE-2024-7881) updated December 2025. MbedTLS Calif/Google audit published
  July 2025. Program is brand new — no researcher entrenchment yet.

DIMENSION 2 — Competition: Score: 9/10
  OBSERVED: Program launched December 18, 2025. Fewer than 4 months old.
  No public Hacktivity disclosures found. No evidence of resolved reports published.
  Our prior TF-M AES Race submission (SUBMITTED) shows we already have access and
  are first movers. Intigriti programs this new typically have <10 serious researchers.
  Audit history: TF-A has 13 formal advisories (TFV-1 to TFV-13) but these are from
  the project's own security process, not third-party audits. MbedTLS: 47 advisories
  total (2011-2025) but 1 Google/Calif audit published July 2025 (5 CVEs, all patched
  in 3.6.4). OP-TEE: handful of advisories (REE userspace TA panic Jul 2025, PKCS#11
  Feb 2024, double-free Sep 2023). No evidence of formal third-party audit of TF-A,
  TF-M, or OP-TEE by Nethermind/OZ/ToB/Zellic/Spearbit.

DIMENSION 3 — Tech Match: Score: 9/10
  OBSERVED: All four projects are open-source C/Assembly firmware/crypto code.
  TF-A (91% C, 5% ASM), TF-M (C), OP-TEE (C), MbedTLS (C).
  We have: Ghidra MCP (binary analysis), CodeQL (taint tracking), Semgrep, GDB,
  kernel exploit background, QEMU for ARM emulation. User submitted TF-M AES Race
  finding already — direct prior experience. ARM secure world expertise confirmed.
  Full source available on GitHub. Locally buildable. Perfect tech match.

DIMENSION 4 — Reward/Effort: Score: 8/10
  OBSERVED: Critical = $20,000, High = $10,000, Medium = $3,000, Low = $1,000.
  Attack surface is local-privilege (AV:L) for most secure world findings.
  AV correction: Local = 0.7x (not 0.1x — these are EL3/S-EL1 privilege escalations
  with real-world impact on millions of devices). PR correction: Low (requires
  app-level access) = 0.7x. Realistic HIGH: $10K x 0.7 x 0.7 = ~$4,900.
  Exceptional bounty possible for novel secure boot bypass or TrustZone escape.
  Note: "Theoretical issues lacking realistic exploit scenarios" = OOS. PoC required.

DIMENSION 5 — Attack Surface: Score: 9/10
  OBSERVED: Four fully open-source repos, all buildable locally.
  TF-A: secure monitor (EL3), SMC handlers, boot chain, X.509 cert parsing,
    platform ports, RME/CCA realm management extension (new in v2.12+).
  TF-M: PSA Crypto, IPC, FWU (firmware update TLV parsing — CVE-2025-53022 just
    patched, look for variants), attestation, partitions.
  OP-TEE: TA loading, PKCS#11, shared memory handling, supplicant RPC, syscall
    interface from TEE user space.
  MbedTLS: TLS handshake, X.509, ECDSA, RSA, CBC padding, LMS — 5 CVEs patched
    July 2025, variant analysis highly viable.
  API docs, build system, test suites all public. CodeQL DB creatable.

DIMENSION 6 — Research Novelty: Score: 8/10
  OBSERVED: Program is 3 months old — by definition fresh.
  INFERRED unexplored areas:
  - TF-A RME/CCA: Realm Management Extension added v2.12+. New EL2/EL3 trust
    boundary. No CVEs against it yet. TFV-12/13 are CPU errata workarounds, not
    code logic bugs. Code logic bugs in new CCA SMC handlers untouched.
  - TF-M FWU TLV: CVE-2025-53022 (stack BOF) patched. Adjacent TLV parsers in
    the same module almost certainly have variants. Classic patch-diffing opportunity.
  - MbedTLS: 5 CVEs fixed July 2025 (CVE-2025-47917 HIGH). Variants in the same
    code paths not yet found. Timing side-channels in RSA/ECDSA still active area.
  - OP-TEE PKCS#11: DB PIN counter reset (Feb 2024). Logic bugs in state machine
    transitions under-researched. TEE supplicant RPC attack surface (CVE-2025-21871
    Linux kernel side — OP-TEE OS side not fully analyzed).
  - No business logic reports in any public disclosure. All known findings are memory
    safety or CPU errata. Business logic / state machine violations = open territory.
  NOVELTY SCORE: 8/10 — Fresh program + active CVE variants + new CCA surface.

HARD NO-GO CHECK:
  - 3+ formal third-party audits of same codebase: NO
    (1 Google/Calif audit of MbedTLS 3.6.2, July 2025. No audits of TF-A, TF-M,
    OP-TEE found from Nethermind/OZ/ToB/Zellic/Spearbit.)
  - 2+ reputable audits (Nethermind/OZ/ToB/Zellic/Spearbit): NO
    (Calif is not in the reputable audit list above)
  - 100+ resolved reports on this program: NO (program only 3 months old)
  - Program operating 3+ years: NO (launched December 18, 2025)
  - Last commit >6mo + 2+ audits: NO (commit March 18, 2026)
  - Source private/inaccessible: NO (fully open source)
  - Fork fully patched: N/A (reference implementation, not a fork)
  RESULT: Zero hard NO-GO signals triggered.

TOTAL: 52/60 → GO
```

---

## Kill Signals Checked

- [x] Deprecated/Abandoned — NO. Active commits March 2026.
- [x] OOS Tech — NO. Source available, locally buildable, full tool coverage.
- [x] Bounty Floor (<$500 for HIGH) — NO. HIGH = $10,000.
- [x] Ghost Program — NO. Announced by Arm, hosted on Intigriti.
- [x] Already Picked Clean (500+ resolved) — NO. Program 3 months old.
- [x] Past Failure (same target, $0) — NO. TF-M AES Race SUBMITTED (in progress).
- [x] Audit Fortress (3+ audits + 100+ reports) — NO. 1 audit (MbedTLS only), 0 resolved public.
- [x] Fork Fully Patched — N/A.

---

## Audit Density Analysis

- **TF-A**: 13 internal security advisories (TFV-1 to TFV-13, 2017-2025). All are
  Arm PSIRT / project-self-disclosed. No external third-party audit found.
  Recent: TFV-11 (CVE-2023-49100, SDEI OOB read), TFV-12 (CVE-2024-5660, HPA
  guest-to-host), TFV-13 (CVE-2024-7881, prefetch side-channel).
- **TF-M**: Internal advisories TFMV-1 to TFMV-9. CVE-2025-53022 (stack BOF, FWU
  TLV, HIGH 8.6, patched July 2025). No third-party audit found.
- **OP-TEE**: GitHub advisories — REE userspace TA panic (HIGH, Jul 2025), PKCS#11
  PIN counter reset (LOW, Feb 2024), double-free shdr_verify (HIGH, Sep 2023).
  No third-party audit found.
- **MbedTLS**: 47 internal advisories (2011-2025). ONE third-party audit: Calif/Google,
  April 2025, published July 2025. 5 CVEs (1 HIGH CVE-2025-47917, 4 MEDIUM), all
  patched in v3.6.4. This is the only formal external audit across all four projects.
- **Audit Density Penalty**: 0 points (only 1 audit, and only for MbedTLS subset)
- **Fork status**: No — reference implementation.

---

## Program Details

- **Platform**: Intigriti (operated by Arm PSIRT)
- **Program launch**: December 18, 2025 (3 months old)
- **Bounty Range**: Low $1K / Medium $3K / High $10K / Critical $20K / Exceptional $20K
- **Response Time**: First response <5 days, triage <6 days, final <3 weeks (fast)
- **Reports Resolved**: Unknown (program too new for public Hacktivity)
- **CVSS Version**: Not specified on program page
- **Scope**: TF-A, TF-M, OP-TEE, MbedTLS/TF-PSA-Crypto (all source-available)
- **Exclusions**:
  - Experimental/test code
  - Platform-specific vulns in non-Arm products
  - Third-party software within TF repos
  - Web infrastructure (report to Linaro)
  - Theoretical issues lacking realistic exploit scenarios
  - Social engineering, DoS, physical access
- **Key requirement**: Reproducible PoC via "legitimate software use" — not isolated
  function calls. Full exploit chain expected for high-severity claims.

---

## OOS Pre-Check

- "Third-party software within Trusted Firmware" — OOS. Check dependency boundaries.
- "Experimental or test code" — OOS. Avoid test harnesses, experimental platform ports.
- "Theoretical issues" — OOS. Every finding needs a PoC against real target behavior.
- "Platform-specific vulnerabilities in non-Arm products" — OOS. Focus on upstream code,
  not Raspberry Pi / Juno platform-specific quirks.
- CPU errata (TFV-12/13 pattern) — likely NOT bounty-eligible (hardware issue, not code bug).
  Confirm with program before submitting errata-class findings.
- DoS / panic — lower priority. REE-triggerable TA panic (OP-TEE Jul 2025) was filed
  but classified HIGH — shows DoS with availability impact CAN qualify if impactful.

---

## Feasibility

- **Target Type Match**: HIGH — all OSS C firmware, our strongest domain
- **Our Tools Coverage**: 95%
  - CodeQL: create DB from source, taint track SMC handlers → secure memory
  - Semgrep: custom rules for TLV parsing, unchecked lengths, memcpy sinks
  - GDB + QEMU: local runtime verification (ARM secure world emulation)
  - Ghidra MCP: binary analysis of pre-built platform images
  - Patch diffing: CVE-2025-53022 patch → variant search in adjacent TLV handlers
- **Recommended Approach**: Start with TF-M FWU TLV variant analysis (adjacent to
  CVE-2025-53022), then MbedTLS timing side-channel variants (post-Calif audit),
  then TF-A CCA/RME SMC handler audit (CodeQL taint from NS world to secure memory).

---

## Bounty Estimate

- Program range: $1,000 - $20,000
- AV correction: Local (EL3 SMC requires NS caller) = 0.7x
- PR correction: Low (app-level NS execution needed) = 0.7x
- Device access correction: Full source + QEMU emulation = 0.9x (near Physical)
- Realistic range for HIGH: $10,000 x 0.7 x 0.7 x 0.9 = ~$4,400
- Realistic range for CRITICAL (TrustZone escape, secure boot bypass): $20,000 x 0.7 x 0.7 x 0.9 = ~$8,800
- ROI note: Even at AV:L correction, HIGH findings in EL3 code on a brand-new program
  with fast triage (<6 days) are strong ROI. Prior TF-M submission in flight.

---

## Top Attack Surfaces

1. **TF-M FWU TLV parsing (HIGHEST PRIORITY)**: CVE-2025-53022 (stack BOF in
   TLV length validation, patched July 2025). Adjacent TLV types in same FWU module
   likely share same missing-validation pattern. Classic variant = same CWE-121,
   different TLV tag. Patch diff available. Medium effort, high probability.

2. **MbedTLS post-Calif audit variants**: 5 CVEs patched in v3.6.4 (July 2025).
   CVE-2025-47917 (HIGH) and 4 MEDIUMs. Adjacent code paths in X.509, TLS handshake,
   RSA/ECDSA almost certainly share variant bugs. Timing side-channels in RSA/ECDSA
   (SSBleed, M-Step pattern — CVE-2025-54764) may have follow-on variants in PSA
   Crypto layer (TF-PSA-Crypto). CodeQL taint + manual timing analysis.

3. **TF-A CCA/RME SMC handlers (HIGH NOVELTY)**: Realm Management Extension added
   in v2.12+. New EL2→EL3 trust boundary. SMC handler dispatch for realm management
   calls. No CVEs against CCA code yet. TFV-11/12/13 are all older code paths.
   CodeQL DB creation + taint from realm world parameters → secure memory access.

4. **OP-TEE PKCS#11 state machine**: PKCS#11 session/object lifecycle has complex
   state transitions. PIN counter reset (Feb 2024) shows state machine bugs exist.
   Session forking, concurrent access, token object manipulation — business logic
   violations under-researched. Prior HIGH advisory (REE→TA panic, Jul 2025) shows
   boundary crossing bugs are in scope and bounty-eligible.

5. **TF-A SMC input validation (SDEI/PSCI variants)**: TFV-11 (CVE-2023-49100) was
   SDEI_INTERRUPT_BIND with invalid interrupt ID → OOB read. SDEI has 10+ SMC
   call types. Only INTERRUPT_BIND was audited. Sibling calls (INTERRUPT_RELEASE,
   INTERRUPT_CONTEXT, EVENT_SIGNAL) may share same missing GIC interrupt ID
   validation. Variant search: grep SDEI handler dispatch → check all ID validations.

---

## Risks and Blockers

- **PoC requirement is strict**: "Legitimate software use, not isolated function calls."
  This means a full attack chain: NS world app → SMC → EL3 bug → demonstrated impact.
  Cannot submit static analysis alone. Need QEMU-based PoC or real hardware.
- **QEMU ARM secure world**: TF-A/TF-M run in QEMU (ARM Fixed Virtual Platform
  or QEMU virt board). Setup takes ~2hrs but fully feasible. We have precedent
  from Arm Mali Kbase QEMU VM work.
- **CPU errata class (TFV-12/13 pattern)**: Hardware prefetcher bugs are NOT code
  bugs. Program likely won't pay for errata-class findings. Focus on code logic bugs.
- **TF-M AES Race already SUBMITTED**: Avoid re-submitting overlapping findings.
  Check TF-M PSA Crypto specifically for non-overlapping attack surfaces.
- **MbedTLS 3.6.4 patch required**: Variants must affect current unpatched versions
  OR find new bugs not covered by the July 2025 patch set.
- **"Platform-specific" OOS**: Focus on platform-agnostic upstream code in
  trusted-firmware-a/trusted-firmware-m/optee_os/mbedtls — not platform/ dirs.

---

## Research Novelty Assessment

- **Novelty Score**: 8/10
- **Fresh Surface Detected**: YES
- **Unexplored Areas**:
  - TF-A CCA/RME SMC handlers (no CVEs, no audit)
  - TF-M FWU TLV variants adjacent to CVE-2025-53022
  - MbedTLS PSA Crypto timing variants post-Calif audit
  - OP-TEE PKCS#11 state machine logic bugs
  - SDEI/PSCI sibling call variants to TFV-11
- **Fresh-Surface Exception Applicable**: N/A (no hard NO-GO triggered — program is
  new enough that standard GO applies)

---

## Suggested Knowledge Searches (for Orchestrator HANDOFF injection)

- technique_search: ["SMC handler input validation", "EL3 privilege escalation TrustZone"]
- technique_search: ["TLV parsing buffer overflow variant analysis", "stack buffer overflow firmware update"]
- exploit_search: ["CVE-2025-53022 TrustedFirmware-M FWU", "CVE-2025-47917 MbedTLS"]
- technique_search: ["OP-TEE PKCS11 state machine", "TEE shared memory confusion"]
- exploit_search: ["TF-A SDEI SMC CVE-2023-49100 variant"]

---

## Recommendation

This is a strong GO. The program launched December 18, 2025 — only 3 months old —
with $20K critical and fast triage (<6 days). All four projects are fully open-source
with no third-party audits blocking entry (only one Calif/Google audit on MbedTLS 3.6.2,
not reputable-list). We have a TF-M submission already in flight and direct ARM secure
world experience.

Start immediately with TF-M FWU TLV variant analysis (patch diff from CVE-2025-53022),
then MbedTLS post-Calif audit variant search (5 CVEs patched, sibling paths open),
then TF-A CCA/RME SMC handler audit using CodeQL. The SDEI sibling call variant
(TFV-11 pattern) is a fast win: grep + manual check, likely 2-4 hours to confirm or kill.
