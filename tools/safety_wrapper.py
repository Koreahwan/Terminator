#!/usr/bin/env python3
"""Deterministic safety wrapper for live-target action requests."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.scope_contract import validate_contract


OFFICIAL_BOUNTY_HOSTS = {
    "yeswehack.com",
    "api.yeswehack.com",
    "hackerone.com",
    "bugcrowd.com",
    "immunefi.com",
    "app.intigriti.com",
    "intigriti.com",
    "huntr.com",
    "hackenproof.com",
}
ALLOW_ACTIONS_WITHOUT_CONTRACT = {"public_program_fetch", "public_repo_read", "local_fixture_poc", "raw_bundle_analysis"}
BLOCK_ACTION_TYPES = {
    "scan",
    "crawl",
    "fuzz",
    "login",
    "account_creation",
    "submit",
    "autofill",
    "idor_mutation",
    "payment",
    "kyc",
    "real_user_data",
    "bot_bypass",
    "authenticated_request",
    "destructive_test",
    "bruteforce",
}
SENSITIVE_PAYLOAD_CLASSES = {
    "idor",
    "auth_bypass",
    "credential",
    "payment",
    "kyc",
    "pii",
    "real_user_data",
    "bot_bypass",
    "dos",
    "fuzz",
}


def load_action(path: Path | None) -> dict[str, Any]:
    text = sys.stdin.read() if path is None else path.read_text(encoding="utf-8")
    return json.loads(text)


def host_of(value: str) -> str:
    parsed = urlparse(value)
    return (parsed.hostname or "").lower().strip(".")


def is_public_host(host: str) -> bool:
    if not host or host in {"localhost", "127.0.0.1", "::1"}:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return "." in host


def official_bounty_url(url: str) -> bool:
    host = host_of(url)
    return host in OFFICIAL_BOUNTY_HOSTS or any(host.endswith("." + allowed) for allowed in OFFICIAL_BOUNTY_HOSTS)


def github_repo_url(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return host == "github.com" and len([p for p in parsed.path.split("/") if p]) >= 2


def load_contract(path: Path | None) -> tuple[dict[str, Any] | None, list[str]]:
    if path is None:
        return None, ["scope_contract_missing"]
    rc, validation = validate_contract(path)
    if rc != 0:
        return None, [f"scope_contract_invalid:{','.join(validation.get('failures', [])) or validation.get('reason', 'unknown')}"]
    target = path / "scope_contract.json" if path.is_dir() else path
    return json.loads(target.read_text(encoding="utf-8")), []


def hostname_matches_identifier(host: str, identifier: str) -> bool:
    ident = identifier.strip().lower()
    if not ident:
        return False
    if ident.startswith("http://") or ident.startswith("https://"):
        parsed = urlparse(ident)
        ident_host = (parsed.hostname or "").lower()
        return host == ident_host
    if ident.startswith("*."):
        suffix = ident[2:]
        return host.endswith("." + suffix) and host != suffix
    if ident.startswith("."):
        return host.endswith(ident)
    return host == ident.strip(".")


def in_scope(host: str, contract: dict[str, Any]) -> bool:
    for asset in contract.get("scope_in", []) or []:
        ident = str(asset.get("identifier") or "")
        if hostname_matches_identifier(host, ident):
            return True
    return False


def forbidden_by_text(action: dict[str, Any], contract: dict[str, Any]) -> list[str]:
    haystack = " ".join(
        str(action.get(key, ""))
        for key in ("action_type", "url_or_asset", "method", "payload_class", "purpose")
    ).lower()
    hits = []
    for item in contract.get("forbidden_actions", []) or []:
        category = str(item.get("category") or "")
        if category and category in haystack:
            hits.append(category)
    return sorted(set(hits))


def verdict(action: dict[str, Any], *, contract_path: Path | None = None) -> dict[str, Any]:
    reasons: list[str] = []
    action_type = str(action.get("action_type") or "").strip().lower()
    url_or_asset = str(action.get("url_or_asset") or "").strip()
    method = str(action.get("method") or "GET").strip().upper()
    payload_class = str(action.get("payload_class") or "").strip().lower()
    auth_required = bool(action.get("auth_required", False))
    source_sha = str(action.get("scope_contract_sha256") or "").strip()

    if not action_type:
        return {"verdict": "BLOCK", "reasons": ["missing_action_type"], "llm_override_allowed": False}

    if action_type in BLOCK_ACTION_TYPES:
        return {"verdict": "BLOCK", "reasons": [f"blocked_action_type:{action_type}"], "llm_override_allowed": False}

    if payload_class in SENSITIVE_PAYLOAD_CLASSES:
        return {"verdict": "BLOCK", "reasons": [f"blocked_payload_class:{payload_class}"], "llm_override_allowed": False}

    if action_type == "public_program_fetch":
        if url_or_asset.startswith("https://") and official_bounty_url(url_or_asset):
            return {"verdict": "ALLOW", "reasons": ["official_public_program_fetch"], "llm_override_allowed": False}
        return {"verdict": "BLOCK", "reasons": ["public_program_fetch_requires_official_bounty_url"], "llm_override_allowed": False}

    if action_type == "public_repo_read":
        if url_or_asset.startswith("https://") and github_repo_url(url_or_asset):
            return {"verdict": "ALLOW", "reasons": ["public_github_repo_read"], "llm_override_allowed": False}
        return {"verdict": "BLOCK", "reasons": ["public_repo_read_requires_github_repo_url"], "llm_override_allowed": False}

    if action_type == "local_fixture_poc":
        path = Path(url_or_asset)
        if not url_or_asset or re.match(r"^[a-zA-Z]+://", url_or_asset):
            return {"verdict": "BLOCK", "reasons": ["local_fixture_poc_requires_local_path"], "llm_override_allowed": False}
        return {"verdict": "ALLOW", "reasons": ["local_fixture_execution_only"], "llm_override_allowed": False}

    if action_type == "raw_bundle_analysis":
        return {"verdict": "ALLOW", "reasons": ["offline_raw_bundle_analysis"], "llm_override_allowed": False}

    contract, contract_errors = load_contract(contract_path)
    if contract_errors:
        return {"verdict": "BLOCK", "reasons": contract_errors, "llm_override_allowed": False}
    assert contract is not None

    contract_sha = str(contract.get("scope_contract_sha256") or "")
    if source_sha and source_sha != contract_sha:
        return {
            "verdict": "BLOCK",
            "reasons": ["stale_scope_contract_sha256"],
            "expected_scope_contract_sha256": contract_sha,
            "provided_scope_contract_sha256": source_sha,
            "llm_override_allowed": False,
        }

    if action_type in {"live_http_request", "browser_navigate", "api_request"}:
        host = host_of(url_or_asset)
        if not is_public_host(host):
            reasons.append("non_public_or_invalid_host")
        if not in_scope(host, contract):
            reasons.append("url_not_in_scope_contract")
        if method not in {"GET", "HEAD", "OPTIONS"}:
            reasons.append("non_readonly_method")
        if auth_required:
            reasons.append("auth_required")
        policy = contract.get("policy_status", {}) or {}
        if policy.get("automation") == "unknown":
            reasons.append("automation_policy_unknown")
        if forbidden := forbidden_by_text(action, contract):
            reasons.append("forbidden_category:" + ",".join(forbidden))
        return {
            "verdict": "BLOCK",
            "reasons": reasons or ["live_target_action_disabled_without_explicit_unlock"],
            "scope_contract_sha256": contract_sha,
            "llm_override_allowed": False,
        }

    return {
        "verdict": "BLOCK",
        "reasons": [f"unknown_action_type:{action_type}"],
        "llm_override_allowed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action-json", type=Path, help="action request JSON; stdin when omitted")
    parser.add_argument("--contract", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    action = load_action(args.action_json)
    payload = verdict(action, contract_path=args.contract)
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"{payload['verdict']}: {', '.join(payload.get('reasons', []))}")
    return 0 if payload["verdict"] == "ALLOW" else 2 if payload["verdict"] == "NEEDS_REVIEW" else 1


if __name__ == "__main__":
    raise SystemExit(main())
