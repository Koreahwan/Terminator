"""Tests for kill_gate_1 Check 12 — Bugcrowd VRT-P5 severity downgrade gate (US-W3)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from bb_preflight import kill_gate_1


def _make_rules(tmp_path: Path, platform: str, oos_body: str = "") -> Path:
    """Create a minimal program_rules_summary.md fixture."""
    (tmp_path / "program_rules_summary.md").write_text(
        f"""# Program Rules Summary

## Platform
{platform}

## In-Scope Assets
- https://target.com

## Severity Scope
- Critical | $5000
- High | $2500
- Medium | $1000
- Low | $250

## Out-of-Scope
{oos_body or '(none)'}

## Submission Rules
Standard Bugcrowd submission rules apply.

## Asset Scope Constraints
No version/branch restrictions.

## Known Issues
None documented.
"""
    )
    return tmp_path


def test_bc_p5_autocomplete_medium_hard_kill(tmp_path, capsys):
    _make_rules(tmp_path, "Bugcrowd")
    exit_code = kill_gate_1(
        str(tmp_path),
        finding="Autocomplete enabled on the login form",
        severity="medium",
        impact="an attacker near the victim could read stored credentials",
    )
    out = capsys.readouterr().out
    assert exit_code == 2, f"expected HARD_KILL, got {exit_code}\nOUT: {out}"
    assert "BUGCROWD P5 SEVERITY MISMATCH" in out


def test_bc_p5_autocomplete_low_warn(tmp_path, capsys):
    _make_rules(tmp_path, "Bugcrowd")
    exit_code = kill_gate_1(
        str(tmp_path),
        finding="Autocomplete enabled on the login form",
        severity="low",
        impact="browser stores form data",
    )
    out = capsys.readouterr().out
    assert exit_code in (0, 1), f"expected PASS or WARN, got {exit_code}\nOUT: {out}"
    assert "BUGCROWD P5 INFO" in out


def test_bc_p5_clickjacking_static_high_hard_kill(tmp_path, capsys):
    _make_rules(tmp_path, "Bugcrowd")
    exit_code = kill_gate_1(
        str(tmp_path),
        finding="Clickjacking on static informational public page",
        severity="high",
        impact="attacker could trick user with iframe overlay",
    )
    out = capsys.readouterr().out
    assert exit_code == 2
    assert "BUGCROWD P5 SEVERITY MISMATCH" in out


def test_bc_p5_ssl_tls_cipher_medium_hard_kill(tmp_path, capsys):
    _make_rules(tmp_path, "Bugcrowd")
    exit_code = kill_gate_1(
        str(tmp_path),
        finding="SSL/TLS cipher suite weak config on main domain",
        severity="medium",
        impact="downgrade to weaker cipher possible on MITM network",
    )
    out = capsys.readouterr().out
    assert exit_code == 2
    assert "BUGCROWD P5 SEVERITY MISMATCH" in out
    assert "ssl_tls_config" in out


def test_bc_not_p5_reflected_xss_session_pass(tmp_path, capsys):
    _make_rules(tmp_path, "Bugcrowd")
    exit_code = kill_gate_1(
        str(tmp_path),
        finding="Reflected XSS on search page steals other users' session tokens",
        severity="medium",
        impact="XSS affecting other users can steal authentication session tokens",
    )
    out = capsys.readouterr().out
    # Check 12 must NOT fire for this (not a P5 pattern)
    assert "BUGCROWD P5 SEVERITY MISMATCH" not in out
    assert "BUGCROWD P5 INFO" not in out


def test_bc_check12_skipped_when_platform_not_bugcrowd(tmp_path, capsys):
    _make_rules(tmp_path, "Immunefi")
    exit_code = kill_gate_1(
        str(tmp_path),
        finding="Autocomplete enabled on the login form",
        severity="medium",
        impact="browser stores form data",
    )
    out = capsys.readouterr().out
    # Check 12 Bugcrowd-gate must not fire on Immunefi platform
    assert "BUGCROWD P5 SEVERITY MISMATCH" not in out
    assert "BUGCROWD P5 INFO" not in out
