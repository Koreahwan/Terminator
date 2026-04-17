"""Tests for kill_gate_1 Check 16 — past-incident cross-reference (v13.4).

Verifies that findings resembling historical rejection cases (Port of Antwerp,
Paradex, magiclabs, etc.) raise a PAST INCIDENT warning so the user sees the
repeat-risk before burning exploiter cycles.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from bb_preflight import kill_gate_1, _match_past_incidents, _load_incident_cache


def _make_rules(tmp_path: Path, platform: str = "Intigriti", oos_body: str = "(empty)") -> None:
    (tmp_path / "program_rules_summary.md").write_text(
        f"""# Program Rules Summary

## Platform
{platform}

## In-Scope Assets
- https://target.com

## Severity Scope
- Critical, High, Medium, Low

## Out-of-Scope
{oos_body}

## Submission Rules
Standard.

## Asset Scope Constraints
None.

## Known Issues
None.
"""
    )


def test_incident_cache_loads_eight_postmortems():
    cache = _load_incident_cache()
    assert len(cache) >= 8, f"expected >= 8 postmortems, got {len(cache)}"
    case_names = {c["case"] for c in cache}
    assert any("port-of-antwerp" in c for c in case_names)
    assert any("paradex" in c for c in case_names)
    assert any("magiclabs" in c for c in case_names)


def test_port_of_antwerp_pattern_matches():
    hits = _match_past_incidents(
        "information disclosure verbose error stack trace hostname without sensitive",
        "intigriti",
    )
    assert hits, "expected Port of Antwerp match"
    assert "port-of-antwerp" in hits[0]["case"]
    assert len(hits[0]["overlap"]) >= 3


def test_clean_sqli_no_false_positive():
    hits = _match_past_incidents(
        "sql injection in user search endpoint via UNION SELECT payload",
        "bugcrowd",
    )
    # Normal SQLi should not match any historical OOS/NR postmortem
    assert not hits, f"unexpected false-positive: {[h['case'] for h in hits]}"


def test_check16_port_of_antwerp_in_kill_gate_1(tmp_path, capsys):
    _make_rules(
        tmp_path,
        platform="Intigriti",
        oos_body="- verbose messages without sensitive info",
    )
    kill_gate_1(
        str(tmp_path),
        finding="Stack trace and hostname disclosure via verbose error on public endpoint",
        severity="low",
        impact="information disclosure — internal hostnames exposed",
    )
    out = capsys.readouterr().out
    assert "PAST INCIDENT" in out
    assert "port-of-antwerp" in out.lower()


def test_check16_paradex_pattern_in_kill_gate_1(tmp_path, capsys):
    _make_rules(tmp_path, platform="Immunefi")
    kill_gate_1(
        str(tmp_path),
        finding="arithmetic simulation PoC with try except fallback to hardcoded literal in starknet drain",
        severity="critical",
        impact="token drain through reentrancy",
    )
    out = capsys.readouterr().out
    assert "PAST INCIDENT" in out, "expected paradex-like past incident warning"


def test_check16_clean_finding_no_warning(tmp_path, capsys):
    _make_rules(tmp_path, platform="Bugcrowd")
    kill_gate_1(
        str(tmp_path),
        finding="SSRF in profile avatar upload endpoint",
        severity="high",
        impact="attacker can request internal AWS metadata from victim host",
    )
    out = capsys.readouterr().out
    assert "PAST INCIDENT" not in out
