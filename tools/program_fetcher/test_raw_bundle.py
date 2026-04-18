"""Smoke tests for v14 raw_bundle layer.

Run: python3 -m tools.program_fetcher.test_raw_bundle

Tests only pure functions + offline fixture behaviour — no network.
Full end-to-end against real platforms is covered by Phase 0.1 of each
target run.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from .raw_bundle import (
    html_to_text,
    render_by_content_type,
    enumerate_scope_links,
    slugify,
    platform_hints,
    accept_for_url,
)


FAILED: list[str] = []
PASSED: list[str] = []


def _assert(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
    else:
        FAILED.append(f"{name}: {detail}")


def test_html_to_text_anchor_preserved():
    out = html_to_text('<p>Visit <a href="/scope">scope</a> page</p>')
    _assert(
        "html_to_text anchor → [text](url)",
        "[scope](/scope)" in out,
        f"got: {out!r}",
    )


def test_html_to_text_entities():
    out = html_to_text("<p>5 &lt; 10 &amp; 3 &gt; 1</p>")
    _assert(
        "html_to_text entity decoding",
        "5 < 10 & 3 > 1" in out,
        f"got: {out!r}",
    )


def test_html_to_text_drops_scripts():
    out = html_to_text("<p>keep</p><script>bad = 'no';</script><p>me</p>")
    _assert(
        "html_to_text drops <script>",
        "bad = 'no'" not in out and "keep" in out and "me" in out,
        f"got: {out!r}",
    )


def test_render_json_indented():
    out = render_by_content_type('{"foo": "bar", "n": 42}', "application/json")
    _assert(
        "render_by_content_type JSON indented",
        '"foo"' in out and "bar" in out and "\n" in out,
        f"got: {out!r}",
    )


def test_render_html_fallback():
    out = render_by_content_type("<p>hello</p>", "text/html")
    _assert(
        "render_by_content_type HTML path",
        "hello" in out,
        f"got: {out!r}",
    )


def test_render_json_autodetect_no_ct():
    out = render_by_content_type('{"detected": true}', "")
    _assert(
        "render_by_content_type JSON autodetect (no content-type)",
        '"detected"' in out,
        f"got: {out!r}",
    )


def test_enumerate_scope_links_same_origin():
    html = """
    <a href="https://example.com/scope">scope page</a>
    <a href="/rules">rules</a>
    <a href="https://other.com/scope">off-origin</a>
    <a href="#anchor">anchor</a>
    <a href="javascript:void(0)">js</a>
    <a href="https://example.com/blog">unrelated</a>
    """
    links = enumerate_scope_links(html, "https://example.com/programs/foo")
    _assert(
        "enumerate_scope_links same-origin only",
        "https://example.com/scope" in links and "https://example.com/rules" in links,
        f"got: {links!r}",
    )
    _assert(
        "enumerate_scope_links drops off-origin",
        "https://other.com/scope" not in links,
        f"got: {links!r}",
    )
    _assert(
        "enumerate_scope_links drops fragment/js",
        not any(l.endswith("#anchor") or "javascript:" in l for l in links),
        f"got: {links!r}",
    )
    _assert(
        "enumerate_scope_links drops unrelated",
        "https://example.com/blog" not in links,
        f"got: {links!r}",
    )


def test_slugify_safe():
    _assert(
        "slugify replaces unsafe chars",
        slugify("https://example.com/a/b?q=1&x=y") == "a_b_q_1_x_y"
        or "a_b" in slugify("https://example.com/a/b?q=1&x=y"),
        f"got: {slugify('https://example.com/a/b?q=1&x=y')!r}",
    )


def test_platform_hints_intigriti():
    hints = platform_hints("https://app.intigriti.com/programs/foo/bar")
    _assert(
        "platform_hints Intigriti public API",
        any("api/core/public/programs/foo/bar" in h for h in hints),
        f"got: {hints!r}",
    )


def test_platform_hints_hackerone():
    hints = platform_hints("https://hackerone.com/some-program")
    _assert(
        "platform_hints HackerOne policy+scopes",
        any("policy" in h for h in hints) and any("scopes" in h for h in hints),
        f"got: {hints!r}",
    )


def test_platform_hints_bugcrowd():
    hints = platform_hints("https://bugcrowd.com/engagements/tesla")
    _assert(
        "platform_hints Bugcrowd target_groups",
        any("target_groups" in h for h in hints),
        f"got: {hints!r}",
    )


def test_platform_hints_yeswehack():
    hints = platform_hints("https://yeswehack.com/programs/qwant")
    _assert(
        "platform_hints YesWeHack api",
        any("api.yeswehack.com/programs/qwant" in h for h in hints),
        f"got: {hints!r}",
    )


def test_platform_hints_unknown_empty():
    hints = platform_hints("https://example.com/some-page")
    _assert(
        "platform_hints unknown host empty",
        hints == [],
        f"got: {hints!r}",
    )


def test_accept_for_url_api():
    _assert(
        "accept_for_url /api/ → JSON",
        accept_for_url("https://app.intigriti.com/api/core/public/programs/foo") == "application/json",
    )
    _assert(
        "accept_for_url api. subdomain → JSON",
        accept_for_url("https://api.yeswehack.com/programs/foo") == "application/json",
    )
    _assert(
        "accept_for_url regular page → HTML",
        "text/html" in accept_for_url("https://hackerone.com/some-program"),
    )


def test_accept_for_url_json_suffix():
    _assert(
        "accept_for_url .json suffix → JSON",
        accept_for_url("https://bugcrowd.com/engagements/foo/target_groups.json") == "application/json",
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
        print(f"  ✓ {name}")
    for f in FAILED:
        print(f"  ✗ {f}")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(run_all())
