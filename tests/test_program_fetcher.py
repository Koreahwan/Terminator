"""Unit + integration tests for tools/program_fetcher.

Runs entirely offline — every test reads from tests/fixtures/program_fetcher/
and monkey-patches tools.program_fetcher.transport.http_get so no network
calls happen. The dispatcher, validator, renderer, cache, and every platform
handler have at least one test.

Run:
    python3 -m pytest tests/test_program_fetcher.py -v
Or (no pytest):
    python3 tests/test_program_fetcher.py
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Make the repo root importable when running directly.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.program_fetcher import (
    Asset,
    FAIL,
    FetchResult,
    HOLD,
    PASS,
    ProgramData,
    SeverityRow,
    detect_platform,
)
from tools.program_fetcher import bugcrowd, cache, dispatch, generic, github_md
from tools.program_fetcher import hackenproof, hackerone, huntr, immunefi
from tools.program_fetcher import intigriti, render, validator, yeswehack

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "program_fetcher"


# ---------------------------------------------------------------------------
# Dispatch routing
# ---------------------------------------------------------------------------


class TestDispatch(unittest.TestCase):
    def test_detect_platform_hackerone(self) -> None:
        self.assertEqual(detect_platform("https://hackerone.com/security"), "hackerone")
        self.assertEqual(detect_platform("https://www.hackerone.com/security/policy"), "hackerone")

    def test_detect_platform_bugcrowd(self) -> None:
        self.assertEqual(detect_platform("https://bugcrowd.com/tesla"), "bugcrowd")

    def test_detect_platform_immunefi(self) -> None:
        self.assertEqual(detect_platform("https://immunefi.com/bug-bounty/lido/"), "immunefi")

    def test_detect_platform_intigriti(self) -> None:
        self.assertEqual(detect_platform("https://app.intigriti.com/programs/demo"), "intigriti")
        self.assertEqual(detect_platform("https://intigriti.com/programs/demo"), "intigriti")

    def test_detect_platform_yeswehack(self) -> None:
        self.assertEqual(detect_platform("https://yeswehack.com/programs/example"), "yeswehack")

    def test_detect_platform_hackenproof(self) -> None:
        self.assertEqual(detect_platform("https://hackenproof.com/example"), "hackenproof")

    def test_detect_platform_huntr(self) -> None:
        self.assertEqual(detect_platform("https://huntr.com/repos/foo/bar"), "huntr")

    def test_detect_platform_github(self) -> None:
        self.assertEqual(detect_platform("https://github.com/org/contest"), "github_md")

    def test_detect_platform_generic(self) -> None:
        self.assertEqual(detect_platform("https://example.com/bug-bounty"), "generic")
        self.assertEqual(detect_platform("notaurl"), "generic")


# ---------------------------------------------------------------------------
# Per-platform handler extraction
# ---------------------------------------------------------------------------


class TestImmunefi(unittest.TestCase):
    def test_extracts_all_required_fields(self) -> None:
        html = (FIXTURES / "immunefi_lido_next_data.html").read_text()
        pd = immunefi.parse_html(html, "https://immunefi.com/bug-bounty/lido/")
        self.assertEqual(pd.platform, "immunefi")
        self.assertEqual(pd.handle, "lido")
        self.assertEqual(pd.name, "Lido")
        self.assertEqual(len(pd.scope_in), 3)
        # Verbatim: the asset ID is byte-equal to the fixture.
        self.assertIn("0xae7ab96520de3a18e5e111b5eaab095312d7fe84",
                      [a.identifier for a in pd.scope_in])
        self.assertGreaterEqual(len(pd.scope_out), 4)
        self.assertIn("Incorrect data supplied by third party oracles", pd.scope_out)
        self.assertEqual(len(pd.known_issues), 2)
        self.assertGreaterEqual(len(pd.severity_table), 3)
        self.assertTrue(pd.bounty_range)
        self.assertEqual(pd.bounty_range["currency"], "USD")
        self.assertEqual(pd.confidence, 0.95)  # authoritative


class TestHackerOne(unittest.TestCase):
    def test_extracts_policy_html_verbatim(self) -> None:
        html = (FIXTURES / "hackerone_security_policy.html").read_text()
        pd = hackerone.parse_html(html, "https://hackerone.com/security/policy")
        self.assertEqual(pd.platform, "hackerone")
        self.assertEqual(pd.handle, "security")
        # Wildcard scope must NOT be stripped to ".hackerone.com".
        self.assertIn("*.hackerone.com", [a.identifier for a in pd.scope_in])
        # Collapsed <details> Out of Scope got extracted.
        self.assertIn("Denial of Service (DoS/DDoS) attacks", pd.scope_out)
        # Collapsed <details> Known Issues got extracted (not as OOS).
        self.assertEqual(len(pd.known_issues), 2)
        self.assertGreaterEqual(len(pd.severity_table), 4)
        self.assertGreaterEqual(pd.confidence, 0.8)


class TestBugcrowd(unittest.TestCase):
    def test_extracts_react_props(self) -> None:
        html = (FIXTURES / "bugcrowd_tesla_page.html").read_text()
        pd = bugcrowd.parse_html(html, "https://bugcrowd.com/tesla")
        self.assertEqual(pd.platform, "bugcrowd")
        self.assertEqual(pd.handle, "tesla")
        self.assertEqual(pd.name, "Tesla")
        self.assertEqual(len(pd.scope_in), 2)
        self.assertIn("*.tesla.com", [a.identifier for a in pd.scope_in])
        self.assertGreaterEqual(len(pd.scope_out), 2)
        self.assertGreaterEqual(len(pd.severity_table), 3)
        self.assertEqual(len(pd.known_issues), 2)


class TestYesWeHack(unittest.TestCase):
    def test_extracts_api_json(self) -> None:
        data = json.loads((FIXTURES / "yeswehack_example.json").read_text())
        pd = yeswehack.parse_json(data, "https://yeswehack.com/programs/example-corp")
        self.assertEqual(pd.name, "Example Corp")
        self.assertEqual(len(pd.scope_in), 2)
        # YWH handler merges `out_of_scope` + `non_qualifying_vulnerability`
        # into scope_out since both reject those vuln classes.
        self.assertGreaterEqual(len(pd.scope_out), 3)
        self.assertGreaterEqual(len(pd.severity_table), 3)
        self.assertTrue(pd.bounty_range)
        self.assertEqual(pd.bounty_range["currency"], "EUR")
        # Authoritative API + full data (scope + oos + rewards + rules) → 0.95.
        self.assertEqual(pd.confidence, 0.95)
        # Non-qualifying items must carry the "(non-qualifying) " prefix.
        nq_items = [x for x in pd.scope_out if x.startswith("(non-qualifying) ")]
        self.assertGreaterEqual(len(nq_items), 1,
                                "expected at least one (non-qualifying) prefixed item")


class TestIntigriti(unittest.TestCase):
    def test_extracts_api_json(self) -> None:
        data = json.loads((FIXTURES / "intigriti_example.json").read_text())
        pd = intigriti.parse_api(data, "https://app.intigriti.com/programs/demo/demo")
        self.assertEqual(pd.name, "Demo Intigriti Program")
        self.assertEqual(len(pd.scope_in), 3)
        self.assertIn("*.example.com", [a.identifier for a in pd.scope_in])
        self.assertEqual(len(pd.scope_out), 3)
        self.assertGreaterEqual(len(pd.severity_table), 3)
        # Authoritative public API with scope + oos + bounty → 0.95.
        self.assertEqual(pd.confidence, 0.95)
        # Verbatim scope markdown passed through assetsCollection qualifier.
        self.assertTrue(pd.bounty_range)
        self.assertEqual(pd.bounty_range["currency"], "EUR")


class TestHackenProof(unittest.TestCase):
    def test_extracts_html_sections(self) -> None:
        html = (FIXTURES / "hackenproof_example.html").read_text()
        pd = hackenproof.parse_html(html, "https://hackenproof.com/programs/example")
        # The Copy-Copied parser extracts each scope row.
        self.assertGreaterEqual(len(pd.scope_in), 3)
        identifiers = [a.identifier for a in pd.scope_in]
        self.assertTrue(any("*.example.com" in i for i in identifiers))
        self.assertTrue(any("0xabcdef" in i for i in identifiers))
        self.assertGreaterEqual(len(pd.scope_out), 3)
        self.assertGreaterEqual(len(pd.severity_table), 3)
        # Bounty range extracted from "Range of bounty $500 - $5,000"
        self.assertTrue(pd.bounty_range)
        self.assertEqual(pd.bounty_range["max"], "$5,000")


class TestHuntr(unittest.TestCase):
    def test_extracts_next_data(self) -> None:
        html = (FIXTURES / "huntr_example.html").read_text()
        pd = huntr.parse_html(html, "https://huntr.com/repos/example-org/example-repo")
        # Next.js Flight parser pulls fullName "example-org/example-repo".
        self.assertEqual(pd.name, "example-org/example-repo")
        self.assertEqual(len(pd.scope_in), 1)
        self.assertEqual(pd.scope_in[0].type, "repo")
        self.assertTrue(pd.bounty_range)
        # huntr formats the bounty as "$1,500".
        self.assertIn("1,500", pd.bounty_range["max"])


class TestGithubMd(unittest.TestCase):
    def test_extracts_audit_readme(self) -> None:
        md = (FIXTURES / "github_md_example.md").read_text()
        pd = github_md.parse_markdown(md, "https://github.com/example-org/example-contest")
        self.assertIn("Vault.sol", " ".join(a.identifier for a in pd.scope_in))
        self.assertGreaterEqual(len(pd.scope_out), 3)
        self.assertEqual(len(pd.known_issues), 2)
        self.assertGreaterEqual(len(pd.severity_table), 3)


# ---------------------------------------------------------------------------
# Generic fallback
# ---------------------------------------------------------------------------


class TestGeneric(unittest.TestCase):
    def test_parses_jina_style_markdown(self) -> None:
        md = """# Example Program

## In Scope
- https://api.example.com
- https://app.example.com

## Out of Scope
- Phishing
- Social engineering

## Rules of Engagement
Please report vulnerabilities through the platform. Do not publicly disclose before resolution. Provide clear PoC.

## Rewards
- Critical: $5,000
- High: $1,500
- Medium: $500
"""
        pd = generic.fetch_from_text(md, "https://example.com/policy")
        self.assertEqual(pd.name, "Example Program")
        self.assertEqual(len(pd.scope_in), 2)
        self.assertEqual(len(pd.scope_out), 2)
        self.assertGreaterEqual(len(pd.severity_table), 3)
        # Generic caps at 0.4 so it never auto-PASSes.
        self.assertEqual(pd.confidence, 0.4)


# ---------------------------------------------------------------------------
# Validator thresholds
# ---------------------------------------------------------------------------


class TestValidator(unittest.TestCase):
    def _full_pd(self, handler_cap: float = 0.95) -> ProgramData:
        return ProgramData(
            platform="immunefi",
            handle="demo",
            name="Demo",
            scope_in=[Asset(type="smart_contract", identifier="0x123")],
            scope_out=["Phishing"],
            known_issues=["None"],
            submission_rules="Report via platform. " * 10,
            severity_table=[SeverityRow(severity="High", reward="$1000")],
            raw_markdown="x" * 800,
            confidence=handler_cap,
        )

    def test_empty_fails(self) -> None:
        v, c, m, _ = validator.validate(ProgramData())
        self.assertEqual(v, FAIL)
        self.assertEqual(c, 0.0)

    def test_full_authoritative_passes(self) -> None:
        v, c, m, _ = validator.validate(self._full_pd(0.95))
        self.assertEqual(v, PASS)
        self.assertEqual(m, [])

    def test_generic_cap_holds_even_with_full_fields(self) -> None:
        pd = self._full_pd(0.4)
        v, c, m, _ = validator.validate(pd)
        self.assertEqual(v, HOLD)
        self.assertLessEqual(c, 0.41)

    def test_missing_name_downgrades_to_hold_or_worse(self) -> None:
        pd = self._full_pd(0.95)
        pd.name = ""
        v, c, _m, _ = validator.validate(pd)
        self.assertIn(v, (HOLD, FAIL))


# ---------------------------------------------------------------------------
# Renderer — verbatim sections only, operational sections left alone
# ---------------------------------------------------------------------------


class TestRenderer(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pf_render_"))
        # Start from the project's init template so we patch in place.
        shutil.copy(
            REPO_ROOT / "tools" / "templates" / "program_rules_summary.md",
            self.tmp / "program_rules_summary.md",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pd(self) -> ProgramData:
        return ProgramData(
            platform="immunefi",
            handle="demo",
            name="Demo",
            scope_in=[Asset(type="smart_contract", identifier="0xabc")],
            scope_out=["Phishing", "MEV"],
            known_issues=["Known A"],
            submission_rules="Report via platform. Provide PoC.",
            severity_table=[SeverityRow(severity="Critical", reward="$100000")],
            raw_markdown="x" * 800,
            confidence=0.95,
            source="immunefi.__NEXT_DATA__",
        )

    def test_patches_verbatim_sections(self) -> None:
        pd = self._pd()
        out_path = render.render_to_target(pd, self.tmp)
        text = out_path.read_text()
        # Verbatim sections replaced
        self.assertIn("- `0xabc`", text)
        self.assertIn("- Phishing", text)
        self.assertIn("- MEV", text)
        self.assertIn("- Known A", text)
        self.assertIn("Report via platform. Provide PoC.", text)
        self.assertIn("| Critical |", text)

    def test_operational_sections_untouched(self) -> None:
        pd = self._pd()
        out_path = render.render_to_target(pd, self.tmp)
        text = out_path.read_text()
        # These stay as <REQUIRED: ...> placeholders — scout fills them from
        # live traffic.
        self.assertIn("<REQUIRED: Exact auth header format", text)
        self.assertIn("<REQUIRED: All required headers", text)
        self.assertIn("<REQUIRED: A WORKING curl command", text)

    def test_write_artifacts_produces_expected_files(self) -> None:
        pd = self._pd()
        result = FetchResult(data=pd, verdict=PASS, confidence=0.95)
        written = render.write_artifacts(result, self.tmp)
        self.assertIn("program_data.json", written)
        self.assertIn("program_page_raw.md", written)
        self.assertIn("fetch_meta.json", written)
        # Parseable JSON
        data = json.loads((self.tmp / "program_data.json").read_text())
        self.assertEqual(data["handle"], "demo")


# ---------------------------------------------------------------------------
# Cache layer
# ---------------------------------------------------------------------------


class TestCache(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pf_cache_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_save_and_load_roundtrip(self) -> None:
        pd = ProgramData(platform="test", handle="x", name="X", raw_markdown="y" * 600)
        pd.scope_in = [Asset(identifier="a")]
        pd.scope_out = ["b"]
        result = FetchResult(data=pd, verdict=HOLD, confidence=0.5)
        cache.save("https://example.com", result, str(self.tmp))
        loaded = cache.load("https://example.com", str(self.tmp))
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.data.handle, "x")
        self.assertEqual(loaded.verdict, HOLD)

    def test_load_missing_returns_none(self) -> None:
        self.assertIsNone(cache.load("https://nope", str(self.tmp)))

    def test_ttl_expiry(self) -> None:
        pd = ProgramData(name="X", raw_markdown="y" * 600)
        result = FetchResult(data=pd, verdict=PASS, confidence=0.95)
        cache.save("https://example.com", result, str(self.tmp))
        # Force immediate expiry via ttl=0
        loaded = cache.load("https://example.com", str(self.tmp), ttl_seconds=0)
        self.assertIsNone(loaded)


# ---------------------------------------------------------------------------
# CLI: bb_preflight.py fetch-program
# ---------------------------------------------------------------------------


class TestBBPreflightFetchProgram(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pf_cli_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _stub_dispatch_with(self, pd: ProgramData) -> None:
        """Replace tools.program_fetcher.fetch with a stub returning `pd`."""
        v, c, m, _ = validator.validate(pd)
        stub_result = FetchResult(
            data=pd, verdict=v, confidence=c, missing_fields=m,
        )

        def stub(url: str, use_cache: bool = True, cache_dir: str = "") -> FetchResult:
            return stub_result

        import tools.program_fetcher as pf_mod
        self._orig_fetch = pf_mod.fetch
        pf_mod.fetch = stub

    def _restore_dispatch(self) -> None:
        import tools.program_fetcher as pf_mod
        if hasattr(self, "_orig_fetch"):
            pf_mod.fetch = self._orig_fetch

    def test_cli_pass_writes_artifacts(self) -> None:
        from tools.bb_preflight import init, fetch_program
        init(str(self.tmp))

        pd = ProgramData(
            platform="immunefi", handle="lido", name="Lido",
            scope_in=[Asset(type="smart_contract", identifier="0xabc")],
            scope_out=["Phishing", "MEV"],
            known_issues=["Known A"],
            submission_rules="Report via Immunefi dashboard. Provide reproducible PoC.",
            severity_table=[SeverityRow(severity="Critical", reward="$2000000")],
            raw_markdown="x" * 800,
            confidence=0.95,
            source="immunefi.__NEXT_DATA__",
            fetched_at="2026-04-10T10:00:00Z",
        )
        self._stub_dispatch_with(pd)
        try:
            ret = fetch_program(str(self.tmp), "https://immunefi.com/bug-bounty/lido/")
        finally:
            self._restore_dispatch()

        self.assertEqual(ret, 0)
        self.assertTrue((self.tmp / "program_data.json").exists())
        self.assertTrue((self.tmp / "program_page_raw.md").exists())
        self.assertTrue((self.tmp / "fetch_meta.json").exists())

        rules_text = (self.tmp / "program_rules_summary.md").read_text()
        self.assertIn("- `0xabc`", rules_text)
        self.assertIn("- Phishing", rules_text)
        self.assertIn("Report via Immunefi dashboard", rules_text)

        # Checkpoint recorded the fetch.
        ckpt = json.loads((self.tmp / "checkpoint.json").read_text())
        self.assertIn("program_fetch", ckpt)
        self.assertEqual(ckpt["program_fetch"]["verdict"], PASS)

    def test_cli_hold_exit_code(self) -> None:
        from tools.bb_preflight import init, fetch_program
        init(str(self.tmp))

        # Build a thin PD that will HOLD (generic-like confidence).
        pd = ProgramData(
            platform="generic", handle="demo", name="Demo",
            scope_in=[Asset(identifier="https://x.example.com")],
            scope_out=["Phishing"],
            submission_rules="Report via platform. " * 3,
            severity_table=[SeverityRow(severity="High", reward="$100")],
            raw_markdown="x" * 800,
            confidence=0.4,  # generic cap
        )
        self._stub_dispatch_with(pd)
        try:
            ret_default = fetch_program(str(self.tmp), "https://example.com")
            ret_hold_ok = fetch_program(str(self.tmp), "https://example.com", hold_ok=True)
        finally:
            self._restore_dispatch()

        self.assertEqual(ret_default, 2)  # HOLD
        self.assertEqual(ret_hold_ok, 0)  # HOLD accepted

    def test_cli_fail_no_writes(self) -> None:
        from tools.bb_preflight import init, fetch_program
        init(str(self.tmp))

        # Force FAIL by returning a result with no data.
        pd = ProgramData(platform="generic", confidence=0.0)
        self._stub_dispatch_with(pd)
        try:
            ret = fetch_program(str(self.tmp), "https://example.com")
        finally:
            self._restore_dispatch()

        self.assertEqual(ret, 1)
        # No program_data.json on FAIL.
        self.assertFalse((self.tmp / "program_data.json").exists())


# ---------------------------------------------------------------------------
# US-004: Handler upgrade tests
# ---------------------------------------------------------------------------


class TestYwhMergesNonQualifying(unittest.TestCase):
    """YWH non_qualifying_vulnerability items appear in scope_out with prefix."""

    def test_ywh_merges_non_qualifying_into_scope_out(self) -> None:
        data = {
            "title": "Test Corp",
            "scopes": [
                {"scope": "https://app.test.com", "scope_type": "web-application",
                 "scope_type_name": "Web application", "asset_value": "HIGH"},
            ],
            "out_of_scope": ["Phishing attacks"],
            "non_qualifying_vulnerability": [
                "Self-XSS without impact",
                "CSRF on logout",
            ],
            "rules": "Report via platform. Provide reproducible PoC. Do not exfiltrate data.",
            "bounty_reward_min": 100,
            "bounty_reward_max": 1000,
            "reward_grid_default": {"bounty_low": 100, "bounty_medium": 500,
                                    "bounty_high": 1000, "bounty_critical": None},
        }
        pd = yeswehack.parse_json(data, "https://yeswehack.com/programs/test-corp")
        # Both non-qualifying items must be present with prefix.
        self.assertIn("(non-qualifying) Self-XSS without impact", pd.scope_out)
        self.assertIn("(non-qualifying) CSRF on logout", pd.scope_out)
        # Hard OOS item must also be present without prefix.
        self.assertIn("Phishing attacks", pd.scope_out)
        # Total: 1 hard OOS + 2 non-qualifying.
        self.assertEqual(len(pd.scope_out), 3)


class TestIntigritiParsesProse(unittest.TestCase):
    """Intigriti outOfScopes prose paragraphs with OOS keywords land in scope_out."""

    def test_intigriti_parses_prose_oos(self) -> None:
        data = {
            "handle": "demo",
            "companyHandle": "demo",
            "name": "Demo Program",
            "inScopes": [
                {"content": {"content": "* https://app.demo.com", "attachments": []},
                 "createdAt": 1700000000},
            ],
            "outOfScopes": [
                {
                    "content": {
                        "content": (
                            "- CSRF on logout\n"
                            "Please refrain from testing the admin panel.\n"
                            "Vulnerabilities in third-party libraries will not be accepted."
                        ),
                        "attachments": [],
                    },
                    "createdAt": 1700000000,
                }
            ],
            "rulesOfEngagements": [],
            "severityAssessments": [],
            "assetsCollection": [],
            "bountyTables": [],
            "cvssVersion": "3.1",
        }
        pd = intigriti.parse_api(data, "https://app.intigriti.com/programs/demo/demo")
        # Bullet item extracted normally (no prefix).
        self.assertIn("CSRF on logout", pd.scope_out)
        # Prose sentences with OOS keywords extracted with "(prose) " prefix.
        prose_items = [x for x in pd.scope_out if x.startswith("(prose) ")]
        self.assertGreaterEqual(len(prose_items), 2,
                                f"expected 2+ prose items, got: {pd.scope_out}")
        self.assertIn(
            "(prose) Please refrain from testing the admin panel.", pd.scope_out
        )
        self.assertIn(
            "(prose) Vulnerabilities in third-party libraries will not be accepted.",
            pd.scope_out,
        )


class TestHuntrExtractsOosFromMarkdown(unittest.TestCase):
    """huntr raw markdown with an OOS section header populates scope_out."""

    def test_huntr_extracts_oos_from_markdown(self) -> None:
        # Simulate a huntr page whose visible text contains an OOS markdown section.
        # We call the helper directly since parse_html requires a full HTML fixture.
        from tools.program_fetcher.huntr import _extract_oos_from_markdown

        raw_md = (
            "Some intro text about the repository.\n\n"
            "## Out of Scope\n\n"
            "Distributed attacks are not eligible\n"
            "- Automated scanner output without manual verification\n"
            "Social engineering against maintainers\n\n"
            "## Rules\n\n"
            "Report via huntr.com platform.\n"
        )
        items = _extract_oos_from_markdown(raw_md)
        self.assertIn("Distributed attacks are not eligible", items)
        self.assertIn("Automated scanner output without manual verification", items)
        self.assertIn("Social engineering against maintainers", items)
        # Items from the ## Rules section must NOT be included.
        self.assertNotIn("Report via huntr.com platform.", items)


if __name__ == "__main__":
    unittest.main(verbosity=2)
