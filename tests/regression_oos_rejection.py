"""Regression test suite for 9 historical OOS / invalid rejection cases.

Each case maps a real bug bounty rejection incident to the automated gate check
that should have blocked submission. The suite verifies that kill_gate_1 and
kill_gate_2 produce the correct exit codes for each fixture.

Cases:
  port_of_antwerp_1  — HARD_KILL @ Check 3.5 (info-disc + verbose-OOS, no sensitivity anchor)
  port_of_antwerp_2  — HARD_KILL @ Check 3.5 (same pattern, stack trace variant)
  okto               — HARD_KILL @ Check 3   (exclusion keyword match on OOS asset)
  utix               — HARD_KILL @ Check 2   (impact not in Immunefi impacts-in-scope list)
  walrus             — HARD_KILL @ Check 1   (severity 'high' on critical-only program)
  magiclabs          — HARD_KILL @ Check 9   (client-side-only N/R pattern)
  dinum              — WARN      @ Check 10  (government accessibility platform)
  paradex            — HARD_KILL @ kill_gate_2 poc_pattern_check (try/except + hardcoded fallback)
  datadome           — HARD_KILL @ Check 6   (site vulnerabilities catch-all + XSS finding)

Run:
  cd /mnt/c/Users/KH/All_Projects/Terminator
  PYTHONPATH=. python3 -m pytest tests/regression_oos_rejection.py -v
"""
import json
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "rejection_cases"

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from bb_preflight import kill_gate_1, kill_gate_2, poc_pattern_check, strengthening_check  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RULES_FILE = "program_rules_summary.md"

# Minimal valid strengthening_report.md that satisfies strengthening_check().
# All 5 items are NOT_APPLICABLE so the check passes without delta-minutes WARN.
_STRENGTHENING_REPORT_TEMPLATE = """\
# Strengthening Report — {finding_name}

## Timestamps
- phase_2_started: 2026-01-01T00:00:00Z
- gate_2_started: 2026-01-01T01:00:00Z
- delta_minutes: 60

## Strengthening Checklist (every item: ATTEMPTED / NOT_APPLICABLE / INFEASIBLE)

### 1. Cross-user / cross-trust-domain PoC
- Status: NOT_APPLICABLE
- Reason: Single-user exploit path, no cross-user surface
- Evidence: N/A

### 2. Two-step exploitation chain
- Status: NOT_APPLICABLE
- Reason: Single-step exploit sufficient to demonstrate impact
- Evidence: N/A

### 3. E2 → E1 evidence tier upgrade
- Status: NOT_APPLICABLE
- Reason: Source-review finding, no cloud account available
- Evidence: N/A

### 4. Variant hunt in sibling modules
- Status: NOT_APPLICABLE
- Reason: No sibling modules with same pattern
- Evidence: N/A

### 5. Static source quote to eliminate try/except
- Status: NOT_APPLICABLE
- Reason: PoC does not use try/except
- Evidence: N/A

## Verdict
- total_NOT_ATTEMPTED: 0
- gate_2_ready: true
"""


def _copy_rules(src_fixture: Path, dest_dir: Path) -> None:
    """Copy program_rules_summary.md from fixture into dest_dir."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    src = src_fixture / RULES_FILE
    (dest_dir / RULES_FILE).write_text(src.read_text())


def _make_paradex_submission(submission_dir: Path, poc_content: str) -> None:
    """Set up a kill_gate_2-testable submission directory for the Paradex case."""
    submission_dir.mkdir(parents=True, exist_ok=True)
    (submission_dir / "poc.py").write_text(poc_content)
    # Write a valid strengthening_report.md so strengthening_check() passes,
    # letting poc_pattern_check produce the HARD_KILL we are testing.
    (submission_dir / "strengthening_report.md").write_text(
        _STRENGTHENING_REPORT_TEMPLATE.format(finding_name="paradex-vault-inflation")
    )


# ---------------------------------------------------------------------------
# Parametrised cases
# ---------------------------------------------------------------------------

CASES = [
    ("port_of_antwerp_1", "HARD_KILL", "3.5"),
    ("port_of_antwerp_2", "HARD_KILL", "3.5"),
    ("okto",              "HARD_KILL", "3"),
    ("utix",              "HARD_KILL", "2"),
    ("walrus",            "HARD_KILL", "1"),
    ("magiclabs",         "HARD_KILL", "9"),
    ("dinum",             "WARN",      "10"),
    ("paradex",           "HARD_KILL", "kg2"),
    ("datadome",          "HARD_KILL", "6"),
]

# Cases where current kill_gate_1 logic produces WARN instead of HARD_KILL.
# The gate behaviour is correct per spec — the HARD_KILL requires a different
# upstream mechanism (e.g. Phase 5.7 live scope re-fetch for okto).
# These are marked xfail to document the gap, not as broken tests.
XFAIL_CASES = {
    "okto": (
        "kill_gate_1 Check 3 (exclusion match) is advisory WARN (exit 1), not HARD_KILL. "
        "The Okto incident was caught by Phase 5.7 live scope re-fetch, not kill_gate_1. "
        "HARD_KILL at gate would require Check 3 escalation for explicit OOS asset names "
        "(G15 gap — prose/structured OOS asset list not yet enforced at HARD_KILL level)."
    ),
}


@pytest.mark.parametrize("case,expected_verdict,expected_check", CASES)
def test_rejection_case(case, expected_verdict, expected_check, tmp_path, capsys):
    """Each historical rejection case must produce the expected gate verdict."""
    if case in XFAIL_CASES:
        pytest.xfail(XFAIL_CASES[case])

    src = FIXTURES_DIR / case
    if not src.exists():
        pytest.skip(f"Fixture directory not found: {src}")

    meta_path = src / "finding_meta.json"
    if not meta_path.exists():
        pytest.skip(f"finding_meta.json missing for case: {case}")

    meta = json.loads(meta_path.read_text())

    # -----------------------------------------------------------------------
    # Paradex — kill_gate_2 scenario (PoC static pattern check)
    # -----------------------------------------------------------------------
    if expected_check == "kg2":
        target_dir = tmp_path / case
        sub = target_dir / "submission" / "paradex-vault"
        _copy_rules(src, target_dir)

        poc_content = meta.get("poc_content", "")
        assert poc_content, "paradex fixture must have 'poc_content' in finding_meta.json"
        _make_paradex_submission(sub, poc_content)

        # poc_pattern_check is the specific sub-check we are testing
        warns, kills = poc_pattern_check(str(sub))
        captured = capsys.readouterr()

        assert kills, (
            f"[{case}] Expected poc_pattern_check HARD_KILL for try/except+fallback pattern, "
            f"got no kills.\nwarn={warns}\nstdout={captured.out}"
        )
        assert any("POC PATTERN" in k for k in kills), (
            f"[{case}] Expected 'POC PATTERN' in kills, got: {kills}"
        )
        return

    # -----------------------------------------------------------------------
    # All other cases — kill_gate_1
    # -----------------------------------------------------------------------
    target_dir = tmp_path / case
    _copy_rules(src, target_dir)

    exit_code = kill_gate_1(
        str(target_dir),
        finding=meta["finding"],
        severity=meta.get("severity", ""),
        impact=meta.get("impact", ""),
    )
    captured = capsys.readouterr()

    if expected_verdict == "HARD_KILL":
        assert exit_code == 2, (
            f"[{case}] Expected HARD_KILL (exit 2), got {exit_code}.\n"
            f"Check {expected_check} should have fired.\n"
            f"stdout:\n{captured.out}"
        )
    elif expected_verdict == "WARN":
        assert exit_code == 1, (
            f"[{case}] Expected WARN (exit 1), got {exit_code}.\n"
            f"Check {expected_check} should have fired.\n"
            f"stdout:\n{captured.out}"
        )
    else:
        assert exit_code == 0, (
            f"[{case}] Expected PASS (exit 0), got {exit_code}.\n"
            f"stdout:\n{captured.out}"
        )
