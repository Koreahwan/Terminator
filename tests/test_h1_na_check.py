"""Tests for kill_gate_1 Check 13 — HackerOne Informative/NA prevention (v13.2 — W4).

5 cases:
  1. Subdomain drift → HARD_KILL (rc==2)
  2. Wildcard scope, in-scope host → no drift HARD_KILL
  3. Hypothetical language → WARN (rc==1)
  4. no_poc language → WARN (rc==1)
  5. Platform=immunefi + subdomain drift → Check 13 skipped (regression guard)
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from bb_preflight import kill_gate_1

RULES_FILE = "program_rules_summary.md"


def _make_h1_rules(target_dir: Path, in_scope: str = "- app.example.com") -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / RULES_FILE).write_text(
        f"""\
## Platform
HackerOne

## Severity Scope
Critical, High, Medium, Low

## In-Scope Assets
{in_scope}

## Impacts in Scope
- Remote code execution
- SQL injection
- Authentication bypass
- Privilege escalation
- Data exposure
- Account takeover

## Out-of-Scope
- None specific

## Asset Scope Constraints
None

## Submission Rules
Standard HackerOne responsible disclosure.

## Known Issues
None
"""
    )


def _make_immunefi_rules(target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / RULES_FILE).write_text(
        """\
## Platform
Immunefi

## Severity Scope
Critical, High, Medium, Low

## In-Scope Assets
- protocol.example.com

## Impacts in Scope
- Direct theft of funds
- Privilege escalation
- Remote code execution
- Authentication bypass

## Out-of-Scope
- None specific

## Asset Scope Constraints
None

## Submission Rules
Standard Immunefi responsible disclosure.

## Known Issues
None
"""
    )


# ── Case 1: Subdomain drift → HARD_KILL ──────────────────────────────────────

def test_h1_subdomain_drift_hard_kill(tmp_path):
    """Finding mentions a host NOT in scope — Check 13 fires HARD_KILL."""
    _make_h1_rules(tmp_path, in_scope="- app.example.com")
    rc = kill_gate_1(
        target_dir=str(tmp_path),
        finding="SQL injection on admin.other.com allows data exfiltration",
        severity="high",
        impact="Full database read on admin.other.com",
    )
    assert rc == 2, f"Expected HARD_KILL (2) for subdomain drift, got {rc}"


# ── Case 2: Wildcard scope, in-scope host → no drift ─────────────────────────

def test_h1_wildcard_scope_no_drift(tmp_path):
    """Host covered by wildcard entry — subdomain drift check must NOT fire."""
    _make_h1_rules(tmp_path, in_scope="- *.example.com")
    rc = kill_gate_1(
        target_dir=str(tmp_path),
        finding="SQL injection on api.example.com allows data exfiltration",
        severity="high",
        impact="Full database read on api.example.com leading to authentication bypass",
    )
    # Should not HARD_KILL due to subdomain drift (may still be 0 or 1 from other checks)
    assert rc != 2, f"Expected no HARD_KILL for wildcard-covered host, got {rc}"


# ── Case 3: Hypothetical language → WARN ─────────────────────────────────────

def test_h1_hypothetical_warn(tmp_path):
    """Speculative 'may allow' language triggers WARN."""
    _make_h1_rules(tmp_path, in_scope="- app.example.com")
    rc = kill_gate_1(
        target_dir=str(tmp_path),
        finding="XSS on app.example.com may allow session hijacking",
        severity="medium",
        impact="Authentication bypass via stolen session token",
    )
    # WARN (rc==1) expected; HARD_KILL (rc==2) would also expose the trigger
    assert rc >= 1, f"Expected at least WARN (1) for hypothetical language, got {rc}"


# ── Case 4: no_poc language → WARN ───────────────────────────────────────────

def test_h1_no_poc_warn(tmp_path):
    """Explicit 'no PoC' in finding/impact triggers WARN."""
    _make_h1_rules(tmp_path, in_scope="- app.example.com")
    rc = kill_gate_1(
        target_dir=str(tmp_path),
        finding="IDOR on app.example.com exposes user data, no PoC provided yet",
        severity="high",
        impact="Data exposure of PII — proof of concept not provided",
    )
    assert rc >= 1, f"Expected at least WARN (1) for no_poc language, got {rc}"


# ── Case 5: Immunefi platform + subdomain drift → Check 13 skipped ───────────

def test_immunefi_platform_skips_check13(tmp_path):
    """Check 13 is HackerOne-only; Immunefi finding with OOD host must NOT
    get a HARD_KILL from Check 13 (Check 11 Immunefi exclusions may still fire)."""
    _make_immunefi_rules(tmp_path)
    # Use a finding that would trigger subdomain drift if Check 13 ran on Immunefi,
    # but keep it away from Immunefi exclusion categories to isolate the test.
    rc = kill_gate_1(
        target_dir=str(tmp_path),
        finding="SQL injection on admin.other.com leading to authentication bypass",
        severity="high",
        impact="Authentication bypass via SQL injection on admin.other.com",
    )
    # Check 13 must NOT produce a HARD_KILL for non-HackerOne platforms.
    # Inspect output: if rc==2, ensure it's NOT due to Check 13 subdomain drift.
    # We verify by checking rc is not 2 solely from Check 13 firing.
    # Since Immunefi exclusion patterns won't match "sql injection auth bypass",
    # the result should be 0 (PASS) or 1 (WARN from other checks), never 2 from drift.
    assert rc != 2, (
        f"Check 13 must not fire on Immunefi platform (subdomain drift is H1-only), got rc={rc}"
    )
