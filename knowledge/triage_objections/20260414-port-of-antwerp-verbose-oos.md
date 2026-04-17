# Port of Antwerp Verbose Info-Disc OOS Postmortem

**Date / Platform / Finding**: 2026-04-14 / Intigriti / Stack trace + K8s hostname disclosure (2 reports)
**Report IDs**: PORTOFANTWERP-7TS0VZVW (K8s pod hostname), PORTOFANTWERP-56QI3QB6 (Java stack trace, 6 endpoints)
**Reward Outcome**: OOS close, €0 / €0. Triager: 0day_pilot.

## 1. Root Cause

Program OOS verbatim: **"Verbose messages/files/directory listings without disclosing any sensitive information"**

Both findings were information-disclosure class (K8s pod hostname, internal URL, Java stack trace) but contained no credentials, tokens, PII, or auth-bypass chain. The triager classified them as "verbose messages without sensitive info" — exactly matching the OOS clause. Our submission claimed these leaks constituted "sensitive information" but provided no concrete sensitivity anchor (no exploit chain showing credential extraction, auth bypass, or data exfiltration).

## 2. Expected Gate Behavior

**kill-gate-1, Check 9 (v12.5 info-disc / verbose-OOS collision check)** should have blocked both findings before exploiter spawn.

Trigger condition: finding class = info-disclosure AND program OOS contains "verbose messages without sensitive info" variant AND `--impact` lacks a concrete sensitivity anchor (credentials / tokens / PII / auth-bypass / RCE chain / source-code leak).

Expected verdict: **HARD_KILL** — both reports were submitted as CVSS 5.3 Medium with no demonstrated exploit chain beyond passive information exposure.

## 3. Actual Gate Behavior

At submission time (2026-04-04), kill-gate-1 only had 5 original destruction checks + the early v12.3 additions (severity, branch/tag). Check 9 (info-disc / verbose-OOS collision) did not yet exist.

The exclusion filter (`bb_preflight.py exclusion-filter`) performed keyword-based OOS matching. "verbose messages" token did not overlap with finding keywords "hostname", "stack trace", "K8s" — so the filter returned no match. The gate passed both reports.

**Implementation gap**: exclusion-filter used token-overlap matching between finding description and OOS items. Semantic category matching (info-disc class → verbose-OOS clause) was absent.

## 4. Fix Path

v12.5 implemented the fix: `bb_preflight.py kill-gate-1` now detects info-disc findings (stack trace, hostname, banner, verbose error, env dump) and checks for "verbose messages without sensitive info" OOS variants. If found and `--impact` has no concrete sensitivity anchor → exit 2 (HARD_KILL).

Concrete regex to catch OOS variants (add to `_check_info_disc_verbose_oos()`):
```
r'verbose\s+(messages?|errors?|output|logs?|files?|directory)'
r'without\s+(disclosing|exposing|sensitive|PII)'
r'information\s+disclosure\s+without\s+impact'
```
For grey-zone cases where sensitivity is arguable: require `--impact` to cite a specific exploit consequence before allowing WARN instead of HARD_KILL.
