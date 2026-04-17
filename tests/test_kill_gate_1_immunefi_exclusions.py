"""Tests for kill_gate_1 Check 11 — Immunefi 41-category exclusion gate (US-W2+W5).

Covers all 41 Immunefi common-exclusion categories.
Expected outcomes:
  - HARD_KILL (rc==2) for the 38 categories where require_sensitivity_anchor=False
    or where anchor is absent despite require_sensitivity_anchor=True
  - WARN (rc==1) for the 3 categories where require_sensitivity_anchor=True AND
    an anchor IS present (cat 21 headers, cat 32 scanner, cat 33 UI-UX)
  - Non-Immunefi platform → no Check 11 fires (regression guard)
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from bb_preflight import kill_gate_1, _detect_platform

RULES_FILE = "program_rules_summary.md"


def _make_immunefi_rules(target_dir: Path, extra_sections: str = "") -> None:
    """Minimal Immunefi program_rules_summary.md with valid severity + platform."""
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / RULES_FILE).write_text(
        f"""\
## Platform
Immunefi

## Severity Scope
Critical, High, Medium, Low

## In-Scope Assets
- protocol.example.com

## Impacts in Scope
- Direct theft of funds
- Permanent freezing of funds
- Unauthorized minting of tokens
- Governance manipulation
- Privilege escalation
- Remote code execution
- SQL injection
- Authentication bypass
- Data exposure

## Out-of-Scope
- None specific (Immunefi common exclusions apply)

## Asset Scope Constraints
None

## Submission Rules
Standard Immunefi responsible disclosure.

## Known Issues
None
{extra_sections}
"""
    )


def _make_other_platform_rules(target_dir: Path, platform: str = "Bugcrowd") -> None:
    """Minimal rules for a non-Immunefi platform."""
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / RULES_FILE).write_text(
        f"""\
## Platform
{platform}

## Severity Scope
Critical, High, Medium, Low

## In-Scope Assets
- *.example.com

## Out-of-Scope
None

## Asset Scope Constraints
None

## Submission Rules
Standard responsible disclosure.

## Known Issues
None
"""
    )


# ---------------------------------------------------------------------------
# _detect_platform unit tests
# ---------------------------------------------------------------------------

def test_detect_platform_immunefi():
    assert _detect_platform("## Platform\nImmunefi\n") == "immunefi"

def test_detect_platform_immunefi_case():
    assert _detect_platform("## Platform\nIMMUNEFI\n") == "immunefi"

def test_detect_platform_bugcrowd():
    assert _detect_platform("Platform: Bugcrowd\n") == "bugcrowd"

def test_detect_platform_hackerone():
    assert _detect_platform("## Platform\nHackerOne\n") == "hackerone"

def test_detect_platform_yeswehack():
    assert _detect_platform("## Platform\nYesWeHack\n") == "yeswehack"

def test_detect_platform_intigriti():
    assert _detect_platform("## Platform\nIntigriti\n") == "intigriti"

def test_detect_platform_huntr():
    assert _detect_platform("## Platform\nhuntr\n") == "huntr"

def test_detect_platform_unknown():
    assert _detect_platform("## Severity Scope\nHigh\n") == "unknown"


# ---------------------------------------------------------------------------
# Parametrized: all 41 categories → HARD_KILL
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cat_num,finding,severity,impact", [
    # --- General (1-8) ---
    (1,  "Exploit reusing my previously-exploited attack vector",            "high",   "fund loss from already exploited route"),
    (2,  "Accessing system using leaked admin API key from public repo",      "high",   "full account takeover via leaked credentials"),
    (3,  "Attack requiring access to privileged governance wallet",           "high",   "drain treasury via governance key access"),
    (4,  "Price manipulation relying on depegging of an external stablecoin", "high",   "vault insolvency"),
    (5,  "API keys and private keys exposed and found in github commits",     "medium", "secret exposed in git history"),
    (6,  "Best practice recommendation for key rotation policy",              "low",    "improve security posture"),
    (7,  "Feature request: add multi-sig support to withdrawal flow",         "low",    "no direct security impact"),
    (8,  "Only affects test files and configuration files in test suite",     "low",    "impacts test configuration file"),
    # --- Smart Contracts (9-13) ---
    (9,  "Incorrect data supplied by third party oracle causes price error",  "high",   "stale oracle data leads to wrong price"),
    (10, "51% attack on the network governance mechanism",                    "critical","chain reorg via basic governance attack"),
    (11, "Lack of liquidity impact causes vault to be undercollateralized",   "medium", "insufficient liquidity impact"),
    (12, "Sybil attack via multiple fake identities inflates voting power",   "high",   "governance manipulation via sybil"),
    (13, "Centralization risk: owner key can pause protocol indefinitely",    "medium", "over-centralized admin control"),
    # --- Websites/Apps (14-34) ---
    (14, "Theoretical impact without any proof or demonstration of exploit",  "medium", "potentially drain funds theoretically"),
    (15, "Exploit requires physical device access to victim machine",         "high",   "keylogger installed via physical access"),
    (16, "Attack from local network via ARP spoofing on same LAN segment",   "medium", "local network attack vector"),
    (17, "Reflected plain text injection in URL parameter echoes attacker text","low",  "harmless echo of input"),
    (18, "Self-XSS in profile field executes script in own browser session",  "low",   "XSS only affects attacker own session"),
    (19, "Captcha bypass using OCR without any additional impact",            "low",   "automated captcha solve via OCR"),
    (20, "CSRF without state modification — logout CSRF on sign-out endpoint","low",   "logout CSRF non-state-changing"),
    # cat 21 (headers) without anchor → HARD_KILL
    (21, "Missing HTTP security headers X-Frame-Options not set",             "low",   "clickjacking risk no impact shown"),
    (22, "Server-side non-confidential information disclosure exposes server name","low","discloses internal ip address without impact"),
    (23, "User enumeration via timing difference on login endpoint",          "low",   "username enumeration possible"),
    (24, "Un-prompted in-app user action required before exploit triggers",   "medium","requires victim to manually click in-app action"),
    (25, "SSL/TLS best practices: server uses TLS 1.0 configuration",        "low",   "weak TLS configuration recommendation"),
    (26, "The only impact is a DDoS attack denial-of-service only",          "medium","the only possible impact is a ddos"),
    (27, "UI/UX disruption without material disruption cosmetic issue",       "low",   "visual cosmetic ui bug without security impact"),
    (28, "Browser plugin defect as primary cause of vulnerability",           "low",   "caused by browser bug primary cause"),
    (29, "Non-sensitive Etherscan API key leak in frontend source",           "low",   "rate-limited etherscan api key exposed"),
    (30, "Exploit dependent on a browser exploitation bug as precondition",   "medium","only exploitable via browser exploit vulnerability"),
    (31, "SPF DMARC misconfigured: SPF record missing from domain",          "low",   "missing spf dmarc record allows spoofing"),
    # cat 32 (scanner) without anchor → HARD_KILL
    (32, "Automated scanner report without demonstrated impact from Burp",    "low",   "tool-generated scan output without manual verification"),
    # cat 33 (UI/UX best practice) without anchor → HARD_KILL
    (33, "UI/UX best practice recommendation to improve user experience",     "low",   "improving the ux without security impact recommendation"),
    (34, "Non-future-proof NFT rendering compatibility issue",                "low",   "NFT rendering not future-proof display support issue"),
    # --- Prohibited (35-41) ---
    (35, "Testing on mainnet performed on the live mainnet network",          "high",  "mainnet exploit conducted on mainnet"),
    (36, "Tested a third-party oracle contract exploiting chainlink data",    "high",  "exploited third-party oracle contract protocol"),
    (37, "Social engineering phishing attack against admin user",             "high",  "phishing via social engineering"),
    (38, "Attack testing a third-party system infrastructure component",      "high",  "third-party system testing attack"),
    (39, "DDoS attack on project assets flooding protocol with requests",     "high",  "launching a ddos attack on protocol assets"),
    (40, "Generating excessive traffic large volume of requests sent",        "medium","high volume requests excessive traffic generation"),
    (41, "Public disclosure of embargoed bounty before fix is deployed",      "high",  "discloses an embargoed vulnerability early public disclosure"),
])
def test_immunefi_exclusion_hard_kill(tmp_path, cat_num, finding, severity, impact):
    """Each of the 41 Immunefi exclusion categories triggers HARD_KILL (rc==2)."""
    _make_immunefi_rules(tmp_path)
    rc = kill_gate_1(str(tmp_path), finding, severity=severity, impact=impact)
    assert rc == 2, (
        f"Category {cat_num}: expected HARD_KILL (2), got {rc}. "
        f"finding={finding!r}, impact={impact!r}"
    )


# ---------------------------------------------------------------------------
# Categories with require_sensitivity_anchor=True: anchor present → WARN (rc==1)
# ---------------------------------------------------------------------------

def test_cat21_missing_headers_with_anchor_warn(tmp_path):
    """Cat 21: missing security headers + anchor 'credential' in impact → WARN not HARD_KILL.
    Impact uses 'authentication bypass' to score against Impacts in Scope so Check 2/8
    doesn't HARD_KILL before Check 11 can fire its WARN."""
    _make_immunefi_rules(tmp_path)
    rc = kill_gate_1(
        str(tmp_path),
        "Missing HTTP security headers Content-Security-Policy not set",
        severity="medium",
        impact="authentication bypass and credential theft via clickjacking on login form",
    )
    assert rc == 1, f"Expected WARN (1) with anchor, got {rc}"


def test_cat32_scanner_report_with_anchor_warn(tmp_path):
    """Cat 32: automated scanner report + anchor 'access token' in in-scope impact → WARN."""
    _make_immunefi_rules(tmp_path)
    rc = kill_gate_1(
        str(tmp_path),
        "Automated scanner report without demonstrated impact flagged by tool",
        severity="medium",
        impact="authentication bypass via access token leakage confirmed in scanner output",
    )
    assert rc == 1, f"Expected WARN (1) with anchor, got {rc}"


def test_cat33_ui_ux_best_practice_with_anchor_warn(tmp_path):
    """Cat 33: UI/UX best practice + anchor 'private key' → WARN not HARD_KILL from Check 11.
    Impact uses 'data exposure' to score against Impacts in Scope + 'private key' anchor."""
    _make_immunefi_rules(tmp_path)
    rc = kill_gate_1(
        str(tmp_path),
        "Improving the UX without security impact on withdrawal screen",
        severity="low",
        impact="data exposure: private key briefly visible in UI transition",
    )
    # rc==1: Check 11 cat 33 fires as WARN (anchor 'private key' present)
    assert rc == 1, f"Expected WARN (1) with anchor, got {rc}"


# ---------------------------------------------------------------------------
# Non-Immunefi platform: Check 11 must NOT fire
# ---------------------------------------------------------------------------

def test_non_immunefi_bugcrowd_no_check11(tmp_path):
    """Bugcrowd platform: self-XSS finding should NOT trigger Check 11 HARD_KILL."""
    _make_other_platform_rules(tmp_path, platform="Bugcrowd")
    rc = kill_gate_1(
        str(tmp_path),
        "Self-XSS in profile field executes script in own browser session",
        severity="low",
        impact="execute script in own session",
    )
    # Should be PASS or WARN (from other checks), never HARD_KILL from Check 11
    # (self-XSS on Bugcrowd is not auto-killed by Check 11)
    assert rc != 2, f"Check 11 must not fire for non-Immunefi platform, got rc={rc}"


def test_non_immunefi_unknown_platform_no_check11(tmp_path):
    """Unknown platform: sybil attack finding should NOT trigger Check 11."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / RULES_FILE).write_text(
        """\
## Severity Scope
Critical, High, Medium, Low

## In-Scope Assets
- example.com

## Out-of-Scope
None

## Asset Scope Constraints
None

## Submission Rules
Standard.

## Known Issues
None
"""
    )
    rc = kill_gate_1(
        str(tmp_path),
        "Sybil attack via multiple fake identities inflates voting power",
        severity="medium",
        impact="governance manipulation",
    )
    assert rc != 2, f"Check 11 must not fire for unknown platform, got rc={rc}"


# ---------------------------------------------------------------------------
# Immunefi platform: valid finding (no exclusion match) → PASS
# ---------------------------------------------------------------------------

def test_immunefi_valid_finding_passes(tmp_path):
    """Immunefi platform with a valid, non-excluded finding → PASS (rc==0)."""
    _make_immunefi_rules(tmp_path)
    rc = kill_gate_1(
        str(tmp_path),
        "Reentrancy vulnerability in withdraw() allows fund drain",
        severity="critical",
        impact="direct theft of funds via reentrancy",
    )
    assert rc == 0, f"Expected PASS (0) for valid finding, got {rc}"


def test_immunefi_valid_sqli_passes(tmp_path):
    """Immunefi platform with SQL injection finding → no HARD_KILL (rc<=1).
    rc==1 is acceptable — weak impact match may produce advisory WARN from Check 2/8,
    but Check 11 must NOT HARD_KILL a legitimate sqli finding."""
    _make_immunefi_rules(tmp_path)
    rc = kill_gate_1(
        str(tmp_path),
        "SQL injection in search endpoint allows database exfiltration",
        severity="high",
        impact="unauthorized access to sensitive user data via sqli",
    )
    assert rc <= 1, f"Expected PASS or WARN (<=1) for valid sqli finding, got {rc}"
