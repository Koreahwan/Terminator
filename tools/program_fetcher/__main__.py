"""CLI entry point: python3 -m tools.program_fetcher <url> [--out DIR]

Usage:
    python3 -m tools.program_fetcher https://immunefi.com/bug-bounty/lido/
    python3 -m tools.program_fetcher <url> --out /tmp/target_dir
    python3 -m tools.program_fetcher --fixture tests/fixtures/.../foo.html --out /tmp/fx
    python3 -m tools.program_fetcher <url> --json

Exit codes match bb_preflight.py verify-target subcommand:
    0 = PASS
    1 = FAIL (unhandled/all handlers exhausted)
    2 = HOLD (confidence below PASS threshold; artifacts still written)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .base import FAIL, HOLD, PASS, FetchResult, ProgramData
from .dispatch import fetch
from .render import render_to_target, write_artifacts


def _load_fixture(path: Path) -> FetchResult:
    """Run the generic handler against a local file for offline testing."""
    from .generic import fetch_from_text

    if not path.exists():
        print(f"error: fixture not found: {path}", file=sys.stderr)
        sys.exit(1)
    text = path.read_text(encoding="utf-8", errors="replace")
    data = fetch_from_text(text, str(path))
    from .validator import validate

    verdict, confidence, missing, _ = validate(data)
    return FetchResult(
        data=data,
        verdict=verdict,
        confidence=confidence,
        missing_fields=missing,
        handlers_tried=[{"handler": "fixture", "status": "ok", "confidence": confidence}],
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="program_fetcher",
        description="Fetch a bug bounty program page and extract verbatim scope.",
    )
    p.add_argument("url", nargs="?", help="program URL")
    p.add_argument("--out", help="target dir to write artifacts into")
    p.add_argument("--fixture", help="path to a local file (bypasses network)")
    p.add_argument("--json", action="store_true", help="print the FetchResult as JSON to stdout")
    p.add_argument("--no-cache", action="store_true", help="bypass the disk cache")
    p.add_argument("--hold-ok", action="store_true",
                   help="exit 0 on HOLD (still write artifacts)")
    args = p.parse_args(argv)

    if not args.url and not args.fixture:
        p.print_usage(sys.stderr)
        print("error: either URL or --fixture required", file=sys.stderr)
        return 1

    if args.fixture:
        result = _load_fixture(Path(args.fixture))
    else:
        cache_dir = ""
        if args.out and not args.no_cache:
            cache_dir = str(Path(args.out) / ".cache" / "program_fetch")
        result = fetch(args.url, use_cache=not args.no_cache, cache_dir=cache_dir)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))

    if args.out:
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        write_artifacts(result, out_dir)
        render_to_target(result.data, out_dir)

    # Exit code.
    if result.verdict == PASS:
        print(f"PASS: {result.data.platform} {result.data.handle} conf={result.confidence:.2f}")
        return 0
    if result.verdict == HOLD:
        missing = ", ".join(result.missing_fields) or "unknown"
        print(
            f"HOLD: {result.data.platform} {result.data.handle} "
            f"conf={result.confidence:.2f} missing={missing}"
        )
        if args.hold_ok:
            return 0
        return 2
    # FAIL
    print(f"FAIL: {result.error or 'no handler succeeded'}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
