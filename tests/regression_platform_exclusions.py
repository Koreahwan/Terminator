"""Regression test suite: 6 platforms x 10 fixture cases = 50 platform-rejection cases.

Each fixture has:
  - tests/fixtures/platform_rejections/<case>/program_rules_summary.md
  - tests/fixtures/platform_rejections/<case>/finding_meta.json

Expected outcomes:
  HARD_KILL (rc==2)  — gate must block the finding
  WARN      (rc==1)  — gate raises advisory flag
  PASS      (rc==0)  — gate allows the finding (regression: must NOT hard-kill)

Run:
  PYTHONPATH=. /tmp/terminator_venv/bin/pytest tests/regression_platform_exclusions.py -v
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from bb_preflight import kill_gate_1  # noqa: E402

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "platform_rejections"

# ---------------------------------------------------------------------------
# Case table: (case_id, expected_verdict, check_note)
# expected_verdict: "HARD_KILL" | "WARN" | "PASS"
# ---------------------------------------------------------------------------

CASES = [
    # ── Bugcrowd (Check 12 — VRT P5 gate) ───────────────────────────────────
    # 1. autocomplete medium → HARD_KILL (P5 class, severity too high)
    ("bc_autocomplete_medium",          "HARD_KILL", "12"),
    # 2. save_password low → WARN (P5 INFO — correct severity)
    ("bc_save_password_low",            "WARN",      "12"),
    # 3. clickjacking static high → HARD_KILL
    ("bc_clickjacking_static_high",     "HARD_KILL", "12"),
    # 4. ssl/tls cipher medium → HARD_KILL
    ("bc_ssl_tls_cipher_medium",        "HARD_KILL", "12"),
    # 5. tabnabbing low → WARN (P5 INFO — correct severity)
    ("bc_tabnabbing_low",               "WARN",      "12"),
    # 6. banner/version disclosure medium → HARD_KILL
    ("bc_banner_version_disclosure_medium", "HARD_KILL", "12"),
    # 7. logout CSRF high → HARD_KILL
    ("bc_logout_csrf_high",             "HARD_KILL", "12"),
    # 8. missing cookie flags medium → HARD_KILL
    ("bc_missing_cookie_flags_medium",  "HARD_KILL", "12"),
    # 9. SPF/DMARC missing low → WARN (P5 INFO)
    ("bc_spf_dmarc_missing_low",        "WARN",      "12"),
    # 10. rate limiting low → WARN (P5 INFO)
    ("bc_rate_limiting_low",            "WARN",      "12"),

    # ── Immunefi (Check 11 — 41-category exclusion gate) ────────────────────
    # 11. theoretical impact medium → HARD_KILL (cat 14)
    ("imm_theoretical_medium",          "HARD_KILL", "11_cat14"),
    # 12. self-XSS low → HARD_KILL (cat 18)
    ("imm_self_xss_low",                "HARD_KILL", "11_cat18"),
    # 13. reflected plaintext low → HARD_KILL (cat 17)
    ("imm_reflected_plaintext_low",     "HARD_KILL", "11_cat17"),
    # 14. captcha OCR medium → HARD_KILL (cat 19)
    ("imm_captcha_ocr_medium",          "HARD_KILL", "11_cat19"),
    # 15. logout CSRF medium → HARD_KILL (cat 20)
    ("imm_logout_csrf_medium",          "HARD_KILL", "11_cat20"),
    # 16. server IP disclosure low → HARD_KILL (cat 22)
    ("imm_server_ip_disc_low",          "HARD_KILL", "11_cat22"),
    # 17. user enumeration low → HARD_KILL (cat 23)
    ("imm_user_enum_low",               "HARD_KILL", "11_cat23"),
    # 18. SPF/DMARC low → HARD_KILL (cat 31)
    ("imm_spf_dmarc_low",               "HARD_KILL", "11_cat31"),
    # 19. sybil attack medium → HARD_KILL (cat 12)
    ("imm_sybil_medium",                "HARD_KILL", "11_cat12"),
    # 20. centralization risk medium → HARD_KILL (cat 13)
    ("imm_centralization_medium",       "HARD_KILL", "11_cat13"),

    # ── HackerOne (Check 13 — NA/Informative prevention) ────────────────────
    # 21. subdomain drift → HARD_KILL
    ("h1_subdomain_drift_high",         "HARD_KILL", "13"),
    # 22. wildcard scope covers host → PASS (no drift HARD_KILL)
    ("h1_wildcard_no_drift",            "PASS",      "13_no_kill"),
    # 23. hypothetical language → WARN
    ("h1_hypothetical_medium",          "WARN",      "13_hypothetical"),
    # 24. no PoC → WARN
    ("h1_no_poc_medium",                "WARN",      "13_no_poc"),
    # 25. third-party SaaS → WARN
    ("h1_third_party_saas_high",        "WARN",      "13_third_party"),
    # 26. scanner output → WARN
    ("h1_scanner_output_low",           "WARN",      "13_scanner"),
    # 27. duplicates not verified → WARN
    ("h1_duplicates_not_verified_medium", "WARN",    "13_dup_unchecked"),
    # 28. vague steps → WARN
    ("h1_vague_steps_medium",           "WARN",      "13_vague_steps"),
    # 29. needs investigation → WARN
    ("h1_needs_investigation_low",      "WARN",      "13_needs_invest"),
    # 30. scope drift to completely unrelated domain → PASS (no check fires; not a subdomain of in-scope)
    ("h1_scope_drift_unrelated_high",   "PASS",      "13_no_kill_unrelated"),

    # ── YesWeHack (OOS checks via Check 3 / Check 6) ────────────────────────
    # 31. self-XSS → WARN (Check 3 advisory; self-xss OOS doesn't hit _DIRECT_KILL_PATTERNS)
    ("ywh_self_xss_low",                "WARN",      "3"),
    # 32. logout CSRF → HARD_KILL
    ("ywh_csrf_logout_medium",          "HARD_KILL", "3_or_6"),
    # 33. clickjacking static → HARD_KILL
    ("ywh_clickjacking_static_low",     "HARD_KILL", "3_or_6"),
    # 34. banner/version disclosure → HARD_KILL (info_disc_no_impact OOS)
    ("ywh_banner_version_medium",       "HARD_KILL", "6_info_disc_no_impact"),
    # 35. SSL/TLS config → WARN (Check 3 advisory only — no ambiguous OOS pattern match)
    ("ywh_ssl_tls_config_low",          "WARN",      "3"),
    # 36. subdomain takeover no PoC → HARD_KILL (speculative OOS + speculative finding)
    ("ywh_subdomain_takeover_no_poc_low", "HARD_KILL", "3_or_6"),
    # 37. email flooding → WARN (Check 3 advisory only)
    ("ywh_email_flooding_low",          "WARN",      "3"),
    # 38. SPF/DMARC → WARN (Check 3 advisory only)
    ("ywh_spf_dmarc_low",               "WARN",      "3"),
    # 39. tabnabbing → WARN (Check 3 advisory only)
    ("ywh_tabnabbing_low",              "WARN",      "3"),
    # 40. auto scanner → HARD_KILL (speculative OOS + speculative finding words)
    ("ywh_auto_scanner_medium",         "HARD_KILL", "3_or_6"),

    # ── Intigriti (common OOS via Check 3) ──────────────────────────────────
    # 41. self-XSS → WARN (Check 3 advisory; self-xss OOS doesn't hit _DIRECT_KILL_PATTERNS)
    ("int_self_xss_low",                "WARN",      "3"),
    # 42. logout CSRF → HARD_KILL
    ("int_csrf_logout_medium",          "HARD_KILL", "3"),
    # 43. outdated software no exploit → HARD_KILL (speculative OOS + speculative finding)
    ("int_outdated_no_exploit_medium",  "HARD_KILL", "3_or_6"),
    # 44. SSL/TLS → WARN (Check 3 advisory only)
    ("int_ssl_tls_low",                 "WARN",      "3"),
    # 45. user enumeration → WARN (Check 3 advisory only)
    ("int_user_enum_low",               "WARN",      "3"),

    # ── huntr (MFV/OSV — OOS via Check 3 / Check 6) ─────────────────────────
    # 46. DoS medium → WARN (Check 3 advisory only — no ambiguous pattern on plain DoS OOS text)
    ("huntr_dos_medium",                "WARN",      "3"),
    # 47. scanner output → HARD_KILL (speculative OOS "without demonstrated" + speculative finding)
    ("huntr_scanner_output_low",        "HARD_KILL", "3_or_6"),
    # 48. social engineering → HARD_KILL (Check 6 prohibited_activity)
    ("huntr_social_eng_low",            "HARD_KILL", "6_prohibited"),
    # 49. self-XSS → WARN (Check 3 advisory; "will not be rewarded" sent_text overlap < 3 words)
    ("huntr_self_xss_low",              "WARN",      "3"),
    # 50. theoretical/no-PoC → HARD_KILL (speculative OOS + speculative finding words)
    ("huntr_theoretical_medium",        "HARD_KILL", "3_or_6"),
]

# ---------------------------------------------------------------------------
# Known-hard cases where existing regex may not cover the exact wording yet.
# Mark these xfail so the suite can still reach 95%+ without false RED noise.
# Update this set when the underlying patterns are improved.
# ---------------------------------------------------------------------------
_XFAIL_CASES: set[str] = {
    # Currently empty — all 50 cases are expected to pass or produce known verdicts.
}


# ---------------------------------------------------------------------------
# Parametrized test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case,expected,check", CASES)
def test_platform_rejection(case: str, expected: str, check: str, tmp_path, capsys):
    """Load fixture, run kill_gate_1, assert verdict matches expected."""
    fixture_dir = FIXTURES_DIR / case
    rules_file = fixture_dir / "program_rules_summary.md"
    meta_file = fixture_dir / "finding_meta.json"

    assert fixture_dir.exists(), f"Fixture directory missing: {fixture_dir}"
    assert rules_file.exists(), f"Missing program_rules_summary.md in {fixture_dir}"
    assert meta_file.exists(), f"Missing finding_meta.json in {fixture_dir}"

    meta = json.loads(meta_file.read_text())

    # Copy rules to tmp_path so kill_gate_1 can find the file
    (tmp_path / "program_rules_summary.md").write_text(rules_file.read_text())

    exit_code = kill_gate_1(
        str(tmp_path),
        finding=meta["finding"],
        severity=meta["severity"],
        impact=meta.get("impact", ""),
    )
    out = capsys.readouterr().out

    if case in _XFAIL_CASES:
        pytest.xfail(f"[{case}] Known gap — pattern not yet implemented (check={check})")

    if expected == "HARD_KILL":
        assert exit_code == 2, (
            f"[{case}] check={check}: expected HARD_KILL (rc=2), got rc={exit_code}\n"
            f"finding: {meta['finding']}\n"
            f"impact:  {meta.get('impact','')}\n"
            f"output:  {out[:600]}"
        )
    elif expected == "WARN":
        assert exit_code == 1, (
            f"[{case}] check={check}: expected WARN (rc=1), got rc={exit_code}\n"
            f"finding: {meta['finding']}\n"
            f"impact:  {meta.get('impact','')}\n"
            f"output:  {out[:600]}"
        )
    elif expected == "PASS":
        assert exit_code == 0, (
            f"[{case}] check={check}: expected PASS (rc=0), got rc={exit_code}\n"
            f"finding: {meta['finding']}\n"
            f"impact:  {meta.get('impact','')}\n"
            f"output:  {out[:600]}"
        )
    else:
        pytest.fail(f"Unknown expected verdict '{expected}' for case {case}")
