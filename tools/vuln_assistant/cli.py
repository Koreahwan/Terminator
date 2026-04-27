#!/usr/bin/env python3
"""CLI for Terminator's bounty/client-pitch vulnerability assistant."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .hint_engine import build_candidates
from .idor_analyzer import build_idor_candidates, write_idor_passive_outputs
from .idor_verifier import verify_candidates, write_verification_outputs
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
    if args.enable_idor_passive:
        idor_candidates = build_idor_candidates(items)
        paths.update(write_idor_passive_outputs(Path(args.out), idor_candidates))
    print(f"[vuln_assistant] raw_items={len(items)} candidates={len(candidates)} out={args.out}")
    for name, path in sorted(paths.items()):
        print(f"{name}: {path}")
    return 0


def idor_passive(args: argparse.Namespace) -> int:
    inputs = [Path(p) for p in args.input or []]
    endpoint_map = Path(args.endpoint_map) if args.endpoint_map else None
    items = load_inputs(inputs, endpoint_map=endpoint_map)
    candidates = build_idor_candidates(items)
    paths = write_idor_passive_outputs(Path(args.out), candidates)
    print(f"[vuln_assistant] idor_passive raw_items={len(items)} idor_candidates={len(candidates)} out={args.out}")
    for name, path in sorted(paths.items()):
        print(f"{name}: {path}")
    return 0


def _load_json(path: str) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _auth_from_env(env_name: str, *, header_name: str, prefix: str) -> dict[str, str]:
    token = os.environ.get(env_name)
    if not token:
        raise ValueError(f"missing environment variable: {env_name}")
    return {header_name: f"{prefix}{token}"}


def _auth_from_profile(path: str) -> dict[str, str]:
    data = _load_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("headers"), dict):
        raise ValueError("auth profile must be JSON object with a headers object")
    return {str(k): str(v) for k, v in data["headers"].items()}


def _load_auth(args: argparse.Namespace, *, side: str) -> dict[str, str]:
    profile = getattr(args, f"auth_profile_{side}")
    env_name = getattr(args, f"auth_{side}_env")
    if profile:
        return _auth_from_profile(profile)
    if env_name:
        return _auth_from_env(env_name, header_name=args.auth_header_name, prefix=args.auth_prefix)
    raise ValueError(f"missing auth profile for account {side.upper()}; use --auth-{side}-env or --auth-profile-{side}")


def idor_verify(args: argparse.Namespace) -> int:
    if args.mode == "client-pitch":
        print("idor-verify is refused in client-pitch mode; client-pitch is passive-only", file=sys.stderr)
        return 2
    try:
        candidates_data = _load_json(args.candidates)
        owned_objects = _load_json(args.owned_objects)
        if not isinstance(candidates_data, list):
            print("candidates file must contain a JSON list", file=sys.stderr)
            return 2
        if not isinstance(owned_objects, dict):
            print("owned objects file must contain a JSON object", file=sys.stderr)
            return 2
        auth_a = _load_auth(args, side="a")
        auth_b = _load_auth(args, side="b")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"idor-verify input error: {exc}", file=sys.stderr)
        return 2
    results = verify_candidates(
        candidates_data,
        owned_objects=owned_objects,
        auth_a=auth_a,
        auth_b=auth_b,
        allowed_scope_hosts=set(args.scope_host or []),
        mode=args.mode,
        delay_seconds=args.delay_seconds,
    )
    paths = write_verification_outputs(Path(args.out), results)
    print(f"[vuln_assistant] idor_verify results={len(results)} out={args.out}")
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
    analyze_parser.add_argument("--enable-idor-passive", action="store_true", help="Also write passive IDOR/BOLA candidate outputs. Sends no network requests.")
    analyze_parser.set_defaults(func=analyze)

    idor_passive_parser = sub.add_parser("idor-passive", help="Passive IDOR/BOLA candidate analysis. Sends no network requests.")
    idor_passive_parser.add_argument("--input", action="append", default=[], help="Recon artifact path or attack_surface.json. May be repeated.")
    idor_passive_parser.add_argument("--endpoint-map", default="", help="Existing endpoint_map.md path")
    idor_passive_parser.add_argument("--out", required=True, help="Output directory")
    idor_passive_parser.set_defaults(func=idor_passive)

    idor_verify_parser = sub.add_parser(
        "idor-verify",
        help="Safe read-only IDOR/BOLA verification. Requires authorization, scope, two owned test accounts, and owned object IDs.",
    )
    idor_verify_parser.add_argument("--mode", required=True, choices=sorted(VALID_MODES), help="client-pitch is refused because it is passive-only.")
    idor_verify_parser.add_argument("--candidates", required=True, help="idor_candidates.json path")
    idor_verify_parser.add_argument("--owned-objects", required=True, help="Owned object ID pair JSON")
    idor_verify_parser.add_argument("--scope-host", action="append", required=True, help="Allowed exact host. Repeat for multiple hosts.")
    idor_verify_parser.add_argument("--auth-a-env", default="", help="Environment variable containing Account A token/key. Raw secrets are not accepted as CLI values.")
    idor_verify_parser.add_argument("--auth-b-env", default="", help="Environment variable containing Account B token/key. Raw secrets are not accepted as CLI values.")
    idor_verify_parser.add_argument("--auth-profile-a", default="", help="Local JSON auth profile for Account A: {\"headers\": {...}}")
    idor_verify_parser.add_argument("--auth-profile-b", default="", help="Local JSON auth profile for Account B: {\"headers\": {...}}")
    idor_verify_parser.add_argument("--auth-header-name", default="Authorization", help="Header name for env token auth")
    idor_verify_parser.add_argument("--auth-prefix", default="Bearer ", help="Prefix for env token auth")
    idor_verify_parser.add_argument("--delay-seconds", type=float, default=0.2, help="Small delay between read-only requests")
    idor_verify_parser.add_argument("--out", required=True, help="Output directory")
    idor_verify_parser.set_defaults(func=idor_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
