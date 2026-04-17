#!/usr/bin/env python3
"""tools/fetch.py — CLI wrapper around tools.program_fetcher.transport.http_get.

Auto-escalates through urllib -> FlareSolverr -> firecrawl-py. Agents invoke
this instead of raw curl / WebFetch(r.jina.ai) for Cloudflare-protected
listings (huntr, Intigriti KB, YWH help-center, Bugcrowd auth-gated).

Resolves the v13.5 PYTHONPATH drift where agents running `python3 -c "from
tools.program_fetcher.transport import http_get"` from non-root CWD failed
with ModuleNotFoundError. This wrapper inserts the repo root on sys.path so
it works from any CWD.

Usage:
    python3 tools/fetch.py <url>              # print body to stdout
    python3 tools/fetch.py <url> --head       # print status + resp headers only
    python3 tools/fetch.py <url> --status     # print HTTP status only
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.program_fetcher.transport import http_get, TransportError  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("url", help="URL to fetch")
    ap.add_argument("--head", action="store_true", help="print status + response headers only")
    ap.add_argument("--status", action="store_true", help="print HTTP status only")
    args = ap.parse_args()

    try:
        status, body, headers = http_get(args.url)
    except TransportError as e:
        print(f"TransportError {e.status} {e.url}: {e.message}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        return 2

    if args.status:
        print(status)
    elif args.head:
        print(f"HTTP {status}")
        for k, v in headers.items():
            print(f"{k}: {v}")
    else:
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
