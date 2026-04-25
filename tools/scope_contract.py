#!/usr/bin/env python3
"""Create and validate scope_contract.json for scope-first bounty execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_FILE = "scope_contract.json"
REQUIRED_INPUTS = [
    "program_data.json",
    "program_rules_summary.md",
    "program_raw/bundle.md",
    "fetch_meta.json",
]
FORBIDDEN_PATTERNS = {
    "dos": r"\b(dos|ddos|denial of service|degradation|interruption)\b",
    "social_engineering": r"\b(phishing|vishing|smishing|social engineering)\b",
    "account_creation": r"\b(create|creating|multiple)\s+accounts?\b|\baccount creation\b",
    "real_user_data": r"\b(real users?|customer data|user data|pii|personal data|privacy violations?)\b",
    "payment": r"\b(payment|transaction|purchase|checkout|investment|funds?)\b",
    "kyc": r"\b(kyc|know your customer|identity verification)\b",
    "healthcare": r"\b(patient|medical|health data|healthcare)\b",
    "automation": r"\b(automated scanners?|automation|crawler|crawling|fuzz|fuzzing|brute force|rate limit)\b",
    "bot_bypass": r"\b(bot bypass|anti[- ]?bot|bot traffic|scraping|scraper)\b",
    "submit": r"\b(submit|submission|reporting)\b",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(data: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run_verbatim_check(target_dir: Path) -> dict[str, Any]:
    proc = subprocess.run(
        ["python3", str(PROJECT_ROOT / "tools" / "bb_preflight.py"), "verbatim-check", str(target_dir), "--json"],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
    )
    payload: dict[str, Any]
    try:
        payload = json.loads(proc.stdout.strip() or "{}")
    except json.JSONDecodeError:
        payload = {
            "verdict": "ERROR",
            "exit_code": proc.returncode,
            "stdout": proc.stdout[-2000:],
            "stderr": proc.stderr[-2000:],
        }
    payload.setdefault("exit_code", proc.returncode)
    return payload


def extract_policy_status(text: str, category: str) -> str:
    lowered = text.lower()
    if category == "automation":
        if re.search(r"\b(no|do not|don't|forbidden|prohibited|not allowed|refrain from)\b.{0,80}\b(automated|automation|scanner|crawl|fuzz|brute force|rate)", lowered):
            return "forbidden"
        if re.search(r"\b(automated|automation|scanner|crawl|fuzz|rate)\b.{0,80}\b(allowed|permitted|in scope)", lowered):
            return "allowed"
        return "unknown"
    if category == "account":
        if re.search(r"\b(no|do not|don't|forbidden|prohibited|not allowed|refrain from)\b.{0,80}\b(account|login|signup|sign-up)", lowered):
            return "forbidden"
        if re.search(r"\b(test accounts?|own accounts?|accounts? you own|create test)\b", lowered):
            return "limited"
        return "unknown"
    if category == "data":
        if re.search(r"\b(no|do not|don't|forbidden|prohibited|not allowed)\b.{0,80}\b(real user|customer|pii|personal data|privacy)", lowered):
            return "forbidden"
        if re.search(r"\b(redact|obfuscate|stop testing|own account|test data)\b", lowered):
            return "limited"
        return "unknown"
    return "unknown"


def find_forbidden_actions(text: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for category, pattern in FORBIDDEN_PATTERNS.items():
        for match in re.finditer(pattern, text, re.IGNORECASE):
            start = max(0, match.start() - 120)
            end = min(len(text), match.end() + 160)
            excerpt = re.sub(r"\s+", " ", text[start:end]).strip()
            hits.append({"category": category, "match": match.group(0), "excerpt": excerpt})
            break
    return hits


def normalize_assets(data: dict[str, Any]) -> list[dict[str, Any]]:
    assets = []
    for asset in data.get("scope_in", []) or []:
        if not isinstance(asset, dict):
            continue
        ident = str(asset.get("identifier") or "").strip()
        if not ident:
            continue
        assets.append(
            {
                "type": str(asset.get("type") or "other"),
                "identifier": ident,
                "qualifier": str(asset.get("qualifier") or ""),
                "in_scope_versions": list(asset.get("in_scope_versions") or []),
            }
        )
    return assets


def create_contract(target_dir: Path, *, allow_hold: bool = False, skip_verbatim: bool = False) -> tuple[int, dict[str, Any]]:
    missing = [name for name in REQUIRED_INPUTS if not (target_dir / name).exists()]
    if missing:
        return 1, {"status": "fail", "reason": "missing_required_inputs", "missing": missing}

    data = load_json(target_dir / "program_data.json")
    meta = load_json(target_dir / "fetch_meta.json")
    bundle_path = target_dir / "program_raw" / "bundle.md"
    rules_path = target_dir / "program_rules_summary.md"
    bundle_text = bundle_path.read_text(encoding="utf-8", errors="replace")
    rules_text = rules_path.read_text(encoding="utf-8", errors="replace")
    combined_policy_text = "\n\n".join(
        [
            rules_text,
            data.get("submission_rules") or "",
            "\n".join(str(item) for item in data.get("scope_out", []) or []),
            "\n".join(str(item) for item in data.get("known_issues", []) or []),
        ]
    )

    confidence = float(meta.get("confidence", data.get("confidence", 0.0)) or 0.0)
    verdict = str(meta.get("verdict") or "").upper()
    if verdict == "HOLD" and not allow_hold:
        return 1, {
            "status": "fail",
            "reason": "program_fetch_hold_requires_review",
            "verdict": verdict,
            "confidence": confidence,
        }
    if verdict == "FAIL":
        return 1, {"status": "fail", "reason": "program_fetch_failed", "verdict": verdict}

    verbatim = {"verdict": "SKIPPED", "exit_code": 0} if skip_verbatim else run_verbatim_check(target_dir)
    if int(verbatim.get("exit_code", 1)) != 0:
        return 1, {"status": "fail", "reason": "verbatim_check_failed", "verbatim_check": verbatim}

    scope_in = normalize_assets(data)
    scope_out = [str(item) for item in data.get("scope_out", []) or [] if str(item).strip()]
    if not scope_in:
        return 1, {"status": "fail", "reason": "empty_in_scope_assets"}
    if not scope_out:
        return 1, {"status": "fail", "reason": "empty_out_of_scope_rules"}

    contract: dict[str, Any] = {
        "schema_version": "scope-contract/1",
        "status": "active",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "program": {
            "platform": data.get("platform") or "",
            "handle": data.get("handle") or "",
            "name": data.get("name") or "",
            "program_url": data.get("program_url") or "",
            "policy_url": data.get("policy_url") or data.get("program_url") or "",
            "fetched_at": data.get("fetched_at") or "",
            "source": data.get("source") or "",
            "source_confidence": confidence,
            "fetch_verdict": verdict or "UNKNOWN",
        },
        "scope_in": scope_in,
        "scope_out": scope_out,
        "known_issues": [str(item) for item in data.get("known_issues", []) or []],
        "severity_bounty_table": data.get("severity_table") or [],
        "bounty_range": data.get("bounty_range") or {},
        "submission_requirements": data.get("submission_rules") or "",
        "policy_status": {
            "automation": extract_policy_status(combined_policy_text, "automation"),
            "account": extract_policy_status(combined_policy_text, "account"),
            "data": extract_policy_status(combined_policy_text, "data"),
        },
        "forbidden_actions": find_forbidden_actions(combined_policy_text),
        "provenance": {
            "program_data_sha256": sha256_file(target_dir / "program_data.json"),
            "program_rules_summary_sha256": sha256_file(rules_path),
            "raw_bundle_sha256": sha256_file(bundle_path),
            "fetch_meta_sha256": sha256_file(target_dir / "fetch_meta.json"),
            "verbatim_check": verbatim,
        },
        "hard_gates": {
            "phase_1_requires_contract": True,
            "agent_artifacts_require_scope_contract_sha256": True,
            "unknown_automation_blocks_live_actions": True,
            "llm_override_allowed": False,
        },
    }
    contract["scope_contract_sha256"] = sha256_json(contract)
    (target_dir / CONTRACT_FILE).write_text(json.dumps(contract, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0, {"status": "pass", "scope_contract": str(target_dir / CONTRACT_FILE), "scope_contract_sha256": contract["scope_contract_sha256"]}


def validate_contract(path: Path) -> tuple[int, dict[str, Any]]:
    if path.is_dir():
        path = path / CONTRACT_FILE
    if not path.exists():
        return 1, {"status": "fail", "reason": "scope_contract_missing", "path": str(path)}
    try:
        data = load_json(path)
    except json.JSONDecodeError as exc:
        return 1, {"status": "fail", "reason": "invalid_json", "error": str(exc)}
    expected = data.get("scope_contract_sha256")
    if not expected:
        return 1, {"status": "fail", "reason": "missing_scope_contract_sha256"}
    copy = dict(data)
    copy.pop("scope_contract_sha256", None)
    actual = sha256_json(copy)
    failures = []
    if actual != expected:
        failures.append("scope_contract_sha256_mismatch")
    for key in ("scope_in", "scope_out", "program", "provenance", "hard_gates"):
        if not data.get(key):
            failures.append(f"missing_{key}")
    status = "pass" if not failures else "fail"
    return (0 if not failures else 1), {
        "status": status,
        "path": str(path),
        "scope_contract_sha256": expected,
        "computed_sha256": actual,
        "failures": failures,
        "policy_status": data.get("policy_status", {}),
    }


def check_artifact(path: Path, contract_path: Path) -> tuple[int, dict[str, Any]]:
    rc, validation = validate_contract(contract_path)
    if rc != 0:
        return rc, validation
    contract_sha = validation["scope_contract_sha256"]
    if not path.exists():
        return 1, {"status": "fail", "reason": "artifact_missing", "path": str(path)}
    text = path.read_text(encoding="utf-8", errors="ignore")
    if contract_sha not in text:
        return 1, {
            "status": "fail",
            "reason": "missing_or_stale_scope_contract_sha256",
            "artifact": str(path),
            "expected_scope_contract_sha256": contract_sha,
        }
    return 0, {"status": "pass", "artifact": str(path), "scope_contract_sha256": contract_sha}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="create scope_contract.json in target dir")
    create.add_argument("target_dir", type=Path)
    create.add_argument("--allow-hold", action="store_true", help="allow program_fetch HOLD artifacts")
    create.add_argument("--skip-verbatim", action="store_true", help="test-only escape hatch")
    create.add_argument("--json", action="store_true")

    validate = sub.add_parser("validate", help="validate scope_contract.json")
    validate.add_argument("path", type=Path)
    validate.add_argument("--json", action="store_true")

    artifact = sub.add_parser("check-artifact", help="verify artifact carries current contract hash")
    artifact.add_argument("artifact", type=Path)
    artifact.add_argument("--contract", type=Path, required=True)
    artifact.add_argument("--json", action="store_true")

    args = parser.parse_args()
    if args.command == "create":
        rc, payload = create_contract(args.target_dir, allow_hold=args.allow_hold, skip_verbatim=args.skip_verbatim)
    elif args.command == "validate":
        rc, payload = validate_contract(args.path)
    else:
        rc, payload = check_artifact(args.artifact, args.contract)

    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        status = payload.get("status", "fail").upper()
        detail = payload.get("reason") or payload.get("scope_contract") or payload.get("path") or ""
        print(f"{status}: {detail}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
