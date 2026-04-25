#!/usr/bin/env python3
"""Deterministic arbiter for GPT/Claude debate artifacts."""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Any


FINAL_VERDICTS = {"BLOCK", "NEEDS_EVIDENCE", "NEEDS_REPRO", "REPORTABLE"}
SCOPE_RISK_RE = re.compile(r"\b(oos|out[- ]of[- ]scope|scope unknown|unknown scope|forbidden|not allowed|prohibited|policy unknown)\b", re.I)
REPRO_RISK_RE = re.compile(r"\b(not reproducible|cannot reproduce|repro unknown|flaky|unverified|no output|not tested)\b", re.I)
EVIDENCE_RISK_RE = re.compile(r"\b(missing evidence|no evidence|insufficient evidence|no logs|no poc|no screenshot|no artifact)\b", re.I)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def text_of(*objects: Any) -> str:
    return "\n".join(json.dumps(obj, ensure_ascii=False) if not isinstance(obj, str) else obj for obj in objects)


def arbiter(proposal: dict[str, Any], objection: dict[str, Any], response: dict[str, Any] | None, *, scope_contract_sha256: str = "") -> dict[str, Any]:
    response = response or {}
    combined = text_of(proposal, objection, response)
    reasons: list[str] = []

    proposal_scope = str(proposal.get("scope_verdict") or proposal.get("scope_basis") or "")
    objection_scope = str(objection.get("scope_objection") or objection.get("scope_verdict") or "")
    if SCOPE_RISK_RE.search(combined) or proposal_scope.upper() == "BLOCK" or objection_scope.upper() in {"BLOCK", "OOS"}:
        reasons.append("scope_or_policy_risk")

    if proposal.get("safety_wrapper_verdict") == "BLOCK" or response.get("safety_wrapper_verdict") == "BLOCK":
        reasons.append("safety_wrapper_block")

    evidence_refs = proposal.get("evidence_refs") or proposal.get("evidence") or []
    if not evidence_refs or EVIDENCE_RISK_RE.search(combined):
        reasons.append("missing_or_insufficient_evidence")

    poc_plan = proposal.get("poc_plan") or response.get("poc_plan")
    repro_status = str(response.get("repro_status") or proposal.get("repro_status") or "")
    if not poc_plan or REPRO_RISK_RE.search(combined) or repro_status.upper() in {"UNKNOWN", "FAIL", "UNTESTED"}:
        reasons.append("reproducibility_gap")

    if "scope_or_policy_risk" in reasons or "safety_wrapper_block" in reasons:
        verdict = "BLOCK"
    elif "missing_or_insufficient_evidence" in reasons:
        verdict = "NEEDS_EVIDENCE"
    elif "reproducibility_gap" in reasons:
        verdict = "NEEDS_REPRO"
    else:
        verdict = "REPORTABLE"

    return {
        "schema_version": "debate-gate/1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verdict": verdict,
        "reasons": sorted(set(reasons)),
        "scope_contract_sha256": scope_contract_sha256,
        "inputs": {
            "gpt_proposal": proposal,
            "claude_objection": objection,
            "gpt_response": response,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proposal", type=Path, required=True)
    parser.add_argument("--objection", type=Path, required=True)
    parser.add_argument("--response", type=Path)
    parser.add_argument("--scope-contract-sha256", default="")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    payload = arbiter(
        load_json(args.proposal),
        load_json(args.objection),
        load_json(args.response) if args.response else {},
        scope_contract_sha256=args.scope_contract_sha256,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(args.out)
    return 0 if payload["verdict"] == "REPORTABLE" else 2 if payload["verdict"].startswith("NEEDS_") else 1


if __name__ == "__main__":
    raise SystemExit(main())
