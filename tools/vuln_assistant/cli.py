#!/usr/bin/env python3
"""CLI for Terminator's bounty/client-pitch vulnerability assistant."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .hint_engine import build_candidates
from .normalizer import load_inputs
from .output_router import write_outputs

VALID_MODES = {"bounty", "client-pitch", "ai-security"}
VALID_DOMAINS = {"web", "api", "ai"}


def analyze(args: argparse.Namespace) -> int:
    mode = args.mode
    domain = args.domain
    if mode not in VALID_MODES:
        print(f"unsupported mode: {mode}", file=sys.stderr)
        return 2
    if domain not in VALID_DOMAINS:
        print(f"unsupported domain: {domain}", file=sys.stderr)
        return 2

    inputs = [Path(p) for p in args.input or []]
    endpoint_map = Path(args.endpoint_map) if args.endpoint_map else None
    items = load_inputs(inputs, endpoint_map=endpoint_map)
    candidates = build_candidates(items, mode=mode, domain="ai" if mode == "ai-security" else domain)
    paths = write_outputs(Path(args.out), items, candidates, mode=mode, domain=domain)
    print(f"[vuln_assistant] raw_items={len(items)} candidates={len(candidates)} out={args.out}")
    for name, path in sorted(paths.items()):
        print(f"{name}: {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    analyze_parser = sub.add_parser("analyze", help="Analyze recon artifacts and write risk-ranked outputs")
    analyze_parser.add_argument("--mode", required=True, choices=sorted(VALID_MODES))
    analyze_parser.add_argument("--domain", default="web", choices=sorted(VALID_DOMAINS))
    analyze_parser.add_argument("--input", action="append", default=[], help="Recon artifact path. May be repeated.")
    analyze_parser.add_argument("--endpoint-map", default="", help="Existing endpoint_map.md path")
    analyze_parser.add_argument("--out", required=True, help="Output directory")
    analyze_parser.set_defaults(func=analyze)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
