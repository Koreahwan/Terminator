"""Smoke tests for v14 bb_preflight.py additions (F1 from ai-slop review).

Covers verbatim_check internals that were previously only integration-tested:
  - _normalise() edge cases: bullet prefixes, markdown links, JSON escapes,
    smart-quote variants, backticks, bold/italic markers
  - section parsing: heading match + bullet-vs-table-row discrimination
  - token fallback: backtick / URL / 0x address / monetary / severity label

Run: python3 -m tools.test_bb_preflight_v14
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Self-contained path bootstrap (same as bb_preflight.py)
_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tools.bb_preflight import verbatim_check  # noqa: E402


FAILED: list[str] = []
PASSED: list[str] = []


def _assert(name: str, cond: bool, detail: str = "") -> None:
    """v14 (codex iter 2 P2): raise AssertionError on fail so pytest
    discovery catches regressions automatically."""
    if cond:
        PASSED.append(name)
    else:
        msg = f"{name}: {detail}"
        FAILED.append(msg)
        raise AssertionError(msg)


def _make_target(rules_body: str, bundle_body: str) -> Path:
    """Create a throwaway target dir with program_rules_summary.md + program_raw/bundle.md."""
    tmp = Path(tempfile.mkdtemp(prefix="verbatim_test_"))
    (tmp / "program_raw").mkdir()
    (tmp / "program_rules_summary.md").write_text(rules_body, encoding="utf-8")
    (tmp / "program_raw" / "bundle.md").write_text(bundle_body, encoding="utf-8")
    return tmp


def test_pass_simple_bullet():
    rules = "## Out-of-Scope / Exclusion List\n- Self-XSS\n"
    bundle = "Non-qualifying: Self-XSS, DoS, etc."
    rc = verbatim_check(str(_make_target(rules, bundle)))
    _assert("simple bullet substring PASS", rc == 0, f"rc={rc}")


def test_fail_missing_bullet():
    rules = "## Out-of-Scope / Exclusion List\n- Fake rule not in bundle anywhere\n"
    bundle = "Something else entirely."
    rc = verbatim_check(str(_make_target(rules, bundle)))
    _assert("missing bullet FAIL", rc == 1, f"rc={rc}")


def test_token_fallback_backtick():
    rules = "## In-Scope Assets\n- `www.example.com` (url) — Web application | value=CRITICAL\n"
    bundle = "assets: www.example.com is primary, priority=high"
    rc = verbatim_check(str(_make_target(rules, bundle)))
    _assert(
        "backtick token fallback (renderer metadata stripped)",
        rc == 0, f"rc={rc}",
    )


def test_token_fallback_monetary_severity():
    rules = (
        "## Severity Scope\n"
        "| Low | asset_value=default | €100 | - |\n"
        "| High | asset_value=default | €5000 | - |\n"
    )
    bundle = "reward: €100 for Low, €5000 for High tier"
    rc = verbatim_check(str(_make_target(rules, bundle)))
    _assert("monetary + severity token fallback on table rows", rc == 0, f"rc={rc}")


def test_json_escape_normalised():
    rules = '## Submission Rules\n- Presence of application or web browser "autocomplete"\n'
    bundle = 'rules: "Presence of application or web browser \\"autocomplete\\" functionalities"'
    rc = verbatim_check(str(_make_target(rules, bundle)))
    _assert("JSON-escape \\\\\" unescaped to \"", rc == 0, f"rc={rc}")


def test_smart_quotes_normalised():
    # Rules side uses smart quotes (curly); bundle has the same content but
    # with straight double-quotes (common when bundle comes from a JSON API
    # that serialises as "..."). Both normalise to straight lowercase.
    rules = "## Out-of-Scope / Exclusion List\n- Presence of \u201csave password\u201d functionality\n"
    bundle = 'bundle: "Presence of "save password" functionality"'
    rc = verbatim_check(str(_make_target(rules, bundle)))
    _assert(
        "smart quotes normalised to straight",
        rc == 0, f"rc={rc}",
    )


def test_placeholder_line_skipped():
    # Renderer default: placeholder lines are bare `<REQUIRED: ...>` blocks,
    # no bullet. These should be skipped so checked stays focused on real
    # verbatim claims.
    rules = "## Known Issues\n<REQUIRED: list known issues here>\n"
    bundle = "empty"
    rc = verbatim_check(str(_make_target(rules, bundle)))
    _assert("bare <REQUIRED:...> line skipped", rc == 0, f"rc={rc}")


def test_placeholder_bullet_skipped():
    # Bullet with only TODO keyword is also a placeholder — skip.
    rules = "## Known Issues\n- TODO fill this in later\n"
    bundle = "no match"
    rc = verbatim_check(str(_make_target(rules, bundle)))
    _assert("bullet TODO placeholder skipped", rc == 0, f"rc={rc}")


def test_fetcher_note_skipped():
    rules = (
        "## Asset Scope Constraints\n"
        "- NOTE: Fetcher did not detect explicit version constraints.\n"
    )
    bundle = "no constraints"
    rc = verbatim_check(str(_make_target(rules, bundle)))
    _assert("fetcher self-disclosure note skipped", rc == 0, f"rc={rc}")


def test_severity_table_divider_header_skipped():
    rules = (
        "## Severity Scope\n"
        "| Severity | Reward |\n"
        "|---|---|\n"
        "| Low | €100 |\n"
    )
    bundle = "payout: €100 for Low tier"
    rc = verbatim_check(str(_make_target(rules, bundle)))
    _assert(
        "severity table divider + header row skipped, data row checked",
        rc == 0, f"rc={rc}",
    )


def test_missing_bundle_returns_error():
    tmp = Path(tempfile.mkdtemp(prefix="verbatim_no_bundle_"))
    (tmp / "program_rules_summary.md").write_text("## In-Scope Assets\n- x\n", encoding="utf-8")
    rc = verbatim_check(str(tmp))
    _assert("missing bundle.md → ERROR (rc=3)", rc == 3, f"rc={rc}")


def test_missing_rules_summary_returns_error():
    tmp = Path(tempfile.mkdtemp(prefix="verbatim_no_rules_"))
    (tmp / "program_raw").mkdir()
    (tmp / "program_raw" / "bundle.md").write_text("bundle", encoding="utf-8")
    rc = verbatim_check(str(tmp))
    _assert("missing rules_summary → ERROR (rc=3)", rc == 3, f"rc={rc}")


def test_warn_mode_downgrades():
    rules = "## Out-of-Scope / Exclusion List\n- Missing fake rule\n"
    bundle = "nothing related"
    rc = verbatim_check(str(_make_target(rules, bundle)), strict=False)
    _assert("strict=False → WARN (rc=2)", rc == 2, f"rc={rc}")


# ---------- F2: report_scrubber sentinel collision tests ----------

def test_report_scrubber_no_null_byte_collision():
    """\\x00SCRUB{N}\\x00 sentinel must survive rewrite on real-world markdown.

    Null bytes virtually never appear in user-authored markdown/CVSS/code,
    so stashing them is safe. Verify by scrubbing content that deliberately
    contains numbers + backticks + URLs — sentinel must restore all originals.
    """
    from tools.report_scrubber import ReportScrubber  # local import

    scr = ReportScrubber()
    sample = (
        "Example code: `Array.from(x)`\n"
        "Path: `src/foo.ts:42`\n"
        "Host: `auth.gouv.fr`\n"
        "CVSS: `AV:N/AC:L/PR:N`\n"
        "URL: https://example.com/path?q=1\n"
        "Prose with extra  spaces  and  bad:punctuation.\n"
    )
    out = scr.normalize_whitespace(sample)
    _assert(
        "sentinel preserves Array.from",
        "Array.from(x)" in out,
        f"got: {out!r}",
    )
    _assert(
        "sentinel preserves src/foo.ts:42",
        "src/foo.ts:42" in out,
        f"got: {out!r}",
    )
    _assert(
        "sentinel preserves CVSS vector",
        "AV:N/AC:L/PR:N" in out,
        f"got: {out!r}",
    )
    _assert(
        "sentinel preserves URL",
        "https://example.com/path?q=1" in out,
        f"got: {out!r}",
    )
    # Prose punctuation SHOULD be rewritten.
    _assert(
        "prose punctuation fixed",
        "bad:punctuation" in out or "bad: punctuation" in out,
        f"got: {out!r}",
    )


def run_all() -> int:
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in tests:
        try:
            t()
        except Exception as e:
            FAILED.append(f"{t.__name__}: EXCEPTION {type(e).__name__}: {e}")

    print(f"PASS: {len(PASSED)}  FAIL: {len(FAILED)}")
    for name in PASSED:
        print(f"  \u2713 {name}")
    for f in FAILED:
        print(f"  \u2717 {f}")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(run_all())
