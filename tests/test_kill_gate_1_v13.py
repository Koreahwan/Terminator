"""Tests for kill_gate_1 Checks 6-10 (v13 — semantic OOS checks).

Covers:
  Check 6  — Ambiguous OOS keyword semantic (G02, G05, G13)
  Check 7  — Program intent mismatch (G03)
  Check 8  — Separate Impacts in Scope list (G04)
  Check 9  — Client-side-only N/R pattern (G08)
  Check 10 — Government/public platform intentional behavior (G14)

Plus regression: v12.5 info-disc/verbose-OOS HARD_KILL still fires.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from bb_preflight import kill_gate_1

RULES_FILE = "program_rules_summary.md"


def _make_rules(target_dir: Path, content: str) -> None:
    """Write a minimal program_rules_summary.md into target_dir."""
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / RULES_FILE).write_text(content)


# ---------------------------------------------------------------------------
# Check 6 — Test 1: "Site vulnerabilities" catch-all + web-app finding → HARD_KILL
# ---------------------------------------------------------------------------
def test_check6_site_vulnerabilities_hard_kill(tmp_path):
    """scope_out contains 'Site vulnerabilities' + finding is XSS → HARD_KILL."""
    _make_rules(
        tmp_path,
        """\
## Severity Scope
Critical, High

## In-Scope Assets
- *.datadome.co

## Out-of-Scope
- Site vulnerabilities
- Third-party integrations

## Asset Scope Constraints
None

## Submission Rules
Standard responsible disclosure.

## Known Issues
None
""",
    )
    rc = kill_gate_1(str(tmp_path), "Reflected XSS in search parameter", severity="high")
    assert rc == 2, f"Expected HARD_KILL (2), got {rc}"


# ---------------------------------------------------------------------------
# Check 6 — Test 2: "hypothetical flaw" OOS + speculative finding → HARD_KILL
# ---------------------------------------------------------------------------
def test_check6_hypothetical_flaw_speculative_hard_kill(tmp_path):
    """scope_out has 'hypothetical flaw' + finding uses 'could potentially' → HARD_KILL."""
    _make_rules(
        tmp_path,
        """\
## Severity Scope
Critical, High

## In-Scope Assets
- api.example.com

## Out-of-Scope
- Hypothetical flaw without a working PoC
- Self-XSS

## Asset Scope Constraints
None

## Submission Rules
Submissions must include a working proof-of-concept.

## Known Issues
None
""",
    )
    rc = kill_gate_1(
        str(tmp_path),
        "Could potentially allow RCE via unsafe deserialization",
        severity="critical",
    )
    assert rc == 2, f"Expected HARD_KILL (2), got {rc}"


# ---------------------------------------------------------------------------
# Check 7 — Test 3: DataDome-style program intent mismatch → HARD_KILL
# ---------------------------------------------------------------------------
def test_check7_datadome_intent_mismatch(tmp_path):
    """Submission rules declare narrow scope (bot bypass); generic XSS finding → HARD_KILL."""
    _make_rules(
        tmp_path,
        """\
## Severity Scope
Critical, High

## In-Scope Assets
- *.datadome.co

## Out-of-Scope
- Findings outside bot-detection scope

## Asset Scope Constraints
None

## Submission Rules
The goal of this program is to report ways around DataDome protection by implementing a scraping bot.

## Known Issues
None
""",
    )
    rc = kill_gate_1(str(tmp_path), "Reflected XSS in login form", severity="high")
    assert rc == 2, f"Expected HARD_KILL (2), got {rc}"


# ---------------------------------------------------------------------------
# Check 8 — Test 4: Impact scope list present, claimed impact missing → HARD_KILL
# ---------------------------------------------------------------------------
def test_check8_impact_scope_list_mismatch(tmp_path):
    """'## Smart Contract Bug Impacts' section present; claimed impact is not in list → HARD_KILL."""
    _make_rules(
        tmp_path,
        """\
## Severity Scope
Critical

## In-Scope Assets
- Vault contract

## Smart Contract Bug Impacts
- Direct theft of any user funds
- Permanent freezing of funds
- Unauthorized minting of tokens

## Out-of-Scope
- Governance attacks requiring 51%

## Asset Scope Constraints
None

## Submission Rules
All submissions must include PoC.

## Known Issues
None
""",
    )
    rc = kill_gate_1(
        str(tmp_path),
        "Price oracle manipulation via flash loan",
        severity="critical",
        impact="temporary price deviation without fund loss",
    )
    assert rc == 2, f"Expected HARD_KILL (2), got {rc}"


# ---------------------------------------------------------------------------
# Check 9 — Test 5: Client-side-only finding + submission rules exclusion → HARD_KILL
# ---------------------------------------------------------------------------
def test_check9_client_side_only(tmp_path):
    """Submission rules exclude client-side-only vulns; finding is client-side PKCE → HARD_KILL."""
    _make_rules(
        tmp_path,
        """\
## Severity Scope
Critical, High, Medium

## In-Scope Assets
- app.magiclabs.com

## Out-of-Scope
- Self-XSS

## Asset Scope Constraints
None

## Submission Rules
Client-side only vulnerabilities are not eligible for a bounty award.
Findings must have a demonstrated server-side impact.

## Known Issues
None
""",
    )
    rc = kill_gate_1(
        str(tmp_path),
        "PKCE client-side only bypass via localStorage codeVerifier extraction",
        severity="medium",
    )
    assert rc == 2, f"Expected HARD_KILL (2), got {rc}"


# ---------------------------------------------------------------------------
# Check 10 — Test 6: Government platform + input-validation finding → WARN
# ---------------------------------------------------------------------------
def test_check10_govt_platform_input_limit(tmp_path):
    """Program rules indicate government/public platform; finding is input validation → WARN."""
    _make_rules(
        tmp_path,
        """\
## Severity Scope
Critical, High, Medium

## In-Scope Assets
- demarches-simplifiees.fr

## Out-of-Scope
- Informational findings

## Asset Scope Constraints
None

## Submission Rules
This is a government public platform accessibility program. We ensure accessibility for all citizens.

## Known Issues
None
""",
    )
    rc = kill_gate_1(
        str(tmp_path),
        "Missing input length validation on SIRET prefill field",
        severity="medium",
    )
    assert rc == 1, f"Expected WARN (1), got {rc}"


# ---------------------------------------------------------------------------
# Regression — Test 7: v12.5 info-disc/verbose-OOS HARD_KILL still fires
# ---------------------------------------------------------------------------
def test_existing_v12_5_info_disc_verbose_still_hard_kill(tmp_path):
    """v12.5 check: info-disc finding + verbose-OOS clause + no sensitivity anchor → HARD_KILL."""
    _make_rules(
        tmp_path,
        """\
## Severity Scope
Critical, High, Medium

## In-Scope Assets
- app.portofantwerp.com

## Out-of-Scope
- Verbose messages/files/directory listings without disclosing any sensitive information
- Missing security headers

## Asset Scope Constraints
None

## Submission Rules
Standard responsible disclosure.

## Known Issues
None
""",
    )
    rc = kill_gate_1(
        str(tmp_path),
        "Stack trace disclosure in error response",
        severity="medium",
        impact="exposes internal stack trace",
    )
    assert rc == 2, f"Expected HARD_KILL (2) for v12.5 info-disc regression, got {rc}"
