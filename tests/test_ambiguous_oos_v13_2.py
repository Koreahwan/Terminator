"""Tests for _AMBIGUOUS_OOS_PATTERNS 2026-04-17 additions (US-W8).

Covers 8 new patterns added to Check 6:
  1. un-prompted user actions       → explicit_oos_sentence
  2. theoretical impacts            → speculative
  3. captcha bypass via OCR         → explicit_oos_sentence
  4. social engineering             → prohibited_activity
  5. reflected plain text injection → explicit_oos_sentence
  6. clickjacking on static page    → explicit_oos_sentence
  7. logout/login csrf              → explicit_oos_sentence
  8. non-sensitive api key          → info_disc_no_impact
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from bb_preflight import kill_gate_1

RULES_FILE = "program_rules_summary.md"


def _make_rules(target_dir: Path, oos_items: str) -> None:
    """Write a minimal program_rules_summary.md with given OOS lines."""
    target_dir.mkdir(parents=True, exist_ok=True)
    content = f"""\
## Severity Scope
Critical, High, Medium

## In-Scope Assets
- *.example.com

## Out-of-Scope
{oos_items}

## Asset Scope Constraints
None

## Submission Rules
Standard responsible disclosure.
"""
    (target_dir / RULES_FILE).write_text(content)


# kill_gate_1 returns an int exit code: 0=PASS, 1=WARN, 2=HARD_KILL
HARD_KILL = 2


# ---------------------------------------------------------------------------
# 1. un-prompted user actions → explicit_oos_sentence HARD_KILL
# ---------------------------------------------------------------------------
def test_unprompted_user_actions_hard_kill(tmp_path):
    """OOS='Impacts caused by vulnerabilities requiring un-prompted, in-app user actions'
    + finding='attack requires victim to click link' → HARD_KILL."""
    _make_rules(
        tmp_path,
        "- Impacts caused by vulnerabilities requiring un-prompted user actions",
    )
    rc = kill_gate_1(
        str(tmp_path),
        finding="attack requires victim to click link to trigger the vulnerability",
        severity="medium",
        impact="user data exposure",
    )
    assert rc == HARD_KILL, f"Expected HARD_KILL (2), got {rc}"


# ---------------------------------------------------------------------------
# 2. theoretical impacts → speculative HARD_KILL
# ---------------------------------------------------------------------------
def test_theoretical_impacts_speculative(tmp_path):
    """OOS='Theoretical impacts without any proof' + speculative finding → HARD_KILL."""
    _make_rules(
        tmp_path,
        "- Theoretical impacts without any proof of concept",
    )
    rc = kill_gate_1(
        str(tmp_path),
        finding="This could potentially allow an attacker to escalate privileges",
        severity="high",
        impact="privilege escalation",
    )
    assert rc == HARD_KILL, f"Expected HARD_KILL (2), got {rc}"


# ---------------------------------------------------------------------------
# 3. captcha bypass via OCR → explicit_oos_sentence HARD_KILL
# ---------------------------------------------------------------------------
def test_captcha_bypass_ocr_hard_kill(tmp_path):
    """OOS='Captcha bypass using OCR without impact demonstration' → HARD_KILL."""
    _make_rules(
        tmp_path,
        "- Captcha bypass using OCR without impact demonstration",
    )
    rc = kill_gate_1(
        str(tmp_path),
        finding="Bypass captcha via OCR to automate account registration",
        severity="medium",
        impact="automated account creation",
    )
    assert rc == HARD_KILL, f"Expected HARD_KILL (2), got {rc}"


# ---------------------------------------------------------------------------
# 4. social engineering → prohibited_activity HARD_KILL
# ---------------------------------------------------------------------------
def test_social_engineering_hard_kill(tmp_path):
    """OOS='Social engineering of staff or contractors' + phishing finding → HARD_KILL."""
    _make_rules(
        tmp_path,
        "- Social engineering of staff or contractors",
    )
    rc = kill_gate_1(
        str(tmp_path),
        finding="Phishing email to employee to harvest credentials",
        severity="high",
        impact="credential theft",
    )
    assert rc == HARD_KILL, f"Expected HARD_KILL (2), got {rc}"


# ---------------------------------------------------------------------------
# 5. reflected plain text injection → explicit_oos_sentence HARD_KILL
# ---------------------------------------------------------------------------
def test_reflected_plain_text_hard_kill(tmp_path):
    """OOS='Reflected plain text injection' + matching finding → HARD_KILL."""
    _make_rules(
        tmp_path,
        "- Reflected plain text injection without XSS or security impact",
    )
    rc = kill_gate_1(
        str(tmp_path),
        finding="Plain text echo in URL parameter reflecting user input",
        severity="medium",
        impact="content injection via plain text reflection",
    )
    assert rc == HARD_KILL, f"Expected HARD_KILL (2), got {rc}"


# ---------------------------------------------------------------------------
# 6. clickjacking on static/informational page → explicit_oos_sentence HARD_KILL
# ---------------------------------------------------------------------------
def test_clickjacking_static_hard_kill(tmp_path):
    """OOS='Clickjacking on static page' + informational page finding → HARD_KILL."""
    _make_rules(
        tmp_path,
        "- Clickjacking on static or informational pages",
    )
    rc = kill_gate_1(
        str(tmp_path),
        finding="Clickjacking on informational page allows UI redressing",
        severity="medium",
        impact="UI redress attack on informational page",
    )
    assert rc == HARD_KILL, f"Expected HARD_KILL (2), got {rc}"


# ---------------------------------------------------------------------------
# 7. logout CSRF → explicit_oos_sentence HARD_KILL
# ---------------------------------------------------------------------------
def test_logout_csrf_hard_kill(tmp_path):
    """OOS='Logout CSRF' + finding='CSRF on logout endpoint' → HARD_KILL."""
    _make_rules(
        tmp_path,
        "- Logout CSRF with no additional security impact",
    )
    rc = kill_gate_1(
        str(tmp_path),
        finding="CSRF on logout endpoint forces user session termination",
        severity="medium",
        impact="forced logout of authenticated users",
    )
    assert rc == HARD_KILL, f"Expected HARD_KILL (2), got {rc}"


# ---------------------------------------------------------------------------
# 8. non-sensitive API key → info_disc_no_impact HARD_KILL
# ---------------------------------------------------------------------------
def test_non_sensitive_api_key_hard_kill(tmp_path):
    """OOS='Non-sensitive API key leak (Etherscan)' + info_disc finding → HARD_KILL."""
    _make_rules(
        tmp_path,
        "- Non-sensitive API key disclosures (e.g. Etherscan, Google Maps public keys)",
    )
    rc = kill_gate_1(
        str(tmp_path),
        finding="Etherscan API key information disclosure in client-side JavaScript bundle",
        severity="medium",
        impact="non-sensitive API key disclosure",
    )
    assert rc == HARD_KILL, f"Expected HARD_KILL (2), got {rc}"
