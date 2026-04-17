#!/usr/bin/env python3
"""Build evidence packs from dispatch results or artifact references.

Canonical interface:
    python3 tools/build_evidence_pack.py --profile <profile> --dispatch-result <json>

Debug/manual fallback:
    python3 tools/build_evidence_pack.py --profile <profile> --artifact-ref <path> [--artifact-ref <path>...]

Source resolution order (per spec v3.4 §6.1):
    1. Explicit artifact refs
    2. Coordination artifact index / session manifests
    3. Production-path targets/<target>/... convention paths
    4. DAG-specific conventions (parity mode only)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PROJECT_ROOT / "config" / "evidence_pack_schema.json"

# Per-profile required artifacts and iron-list files
PROFILE_REQUIREMENTS: dict[str, dict[str, list[str]]] = {
    "gate1": {
        "required": ["vulnerability_candidates.md", "finding_summary.md"],
        "iron_list": ["program_rules_summary.md"],
    },
    "gate2": {
        "required": ["poc.py", "poc_output.txt", "strengthening_report.md"],
        "iron_list": ["program_rules_summary.md"],
    },
    "critic_review": {
        "required": ["report.md", "poc.py"],
        "iron_list": ["program_rules_summary.md"],
    },
    "report_review": {
        "required": ["report.md", "poc.py", "bugcrowd_form.md"],
        "iron_list": ["program_rules_summary.md"],
    },
    "submission_review": {
        "required": ["report.md", "poc.py", "autofill_payload.json", "strengthening_report.md"],
        "iron_list": ["program_rules_summary.md", "live_scope_check.md"],
    },
}


def _load_dispatch_result(path: str) -> dict:
    """Load a dispatch result JSON file."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _resolve_artifacts(dispatch_result: dict | None, explicit_refs: list[str],
                       profile: str) -> list[dict]:
    """Resolve artifacts using the canonical source order."""
    inventory: list[dict] = []
    seen_paths: set[str] = set()

    # 1. Explicit refs
    for ref in explicit_refs:
        p = Path(ref)
        if p.exists() and str(p) not in seen_paths:
            role = _classify_artifact_role(p.name, profile)
            inventory.append({
                "path": str(p),
                "role": role,
                "description": f"Explicit ref: {p.name}",
            })
            seen_paths.add(str(p))

    # 2. Dispatch result artifacts
    if dispatch_result:
        for artifact_path in dispatch_result.get("artifacts", []):
            p = Path(artifact_path)
            if p.exists() and str(p) not in seen_paths:
                role = _classify_artifact_role(p.name, profile)
                inventory.append({
                    "path": str(p),
                    "role": role,
                    "description": f"From dispatch: {p.name}",
                })
                seen_paths.add(str(p))

    # 3. Convention paths — scan work_dir if available
    work_dir = dispatch_result.get("work_dir") if dispatch_result else None
    if work_dir:
        reqs = PROFILE_REQUIREMENTS.get(profile, {})
        for filename in reqs.get("required", []) + reqs.get("iron_list", []):
            # Search in common locations
            for search_dir in [Path(work_dir), Path(work_dir) / "submission"]:
                candidate = search_dir / filename
                if candidate.exists() and str(candidate) not in seen_paths:
                    role = _classify_artifact_role(filename, profile)
                    inventory.append({
                        "path": str(candidate),
                        "role": role,
                        "description": f"Convention path: {filename}",
                    })
                    seen_paths.add(str(candidate))

    return inventory


def _classify_artifact_role(filename: str, profile: str) -> str:
    """Classify an artifact as primary, supporting, or iron_list."""
    reqs = PROFILE_REQUIREMENTS.get(profile, {})
    if filename in reqs.get("iron_list", []):
        return "iron_list"
    if filename in reqs.get("required", []):
        return "primary"
    return "supporting"


def build_pack(profile: str, dispatch_result: dict | None = None,
               explicit_refs: list[str] | None = None,
               iteration: int = 1) -> dict:
    """Build an evidence pack manifest."""
    pack_id = f"pack-{profile}-{int(time.time())}-{uuid.uuid4().hex[:8]}"

    source_role = ""
    dispatch_id = None
    if dispatch_result:
        source_role = dispatch_result.get("role", "")
        dispatch_id = dispatch_result.get("dispatch_id")

    artifact_inventory = _resolve_artifacts(
        dispatch_result, explicit_refs or [], profile
    )

    manifest = {
        "schema_version": "2.4",
        "profile": profile,
        "pack_id": pack_id,
        "iteration": iteration,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_role": source_role,
        "dispatch_id": dispatch_id,
        "artifact_inventory": artifact_inventory,
        "validation_status": "pending",
    }

    return manifest


def write_pack(manifest: dict, output_dir: str | None = None) -> Path:
    """Write the pack manifest to disk."""
    if output_dir:
        out = Path(output_dir)
    else:
        out = PROJECT_ROOT / "evidence_packs" / manifest["pack_id"]
    out.mkdir(parents=True, exist_ok=True)

    manifest_path = out / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return manifest_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build evidence packs from dispatch results."
    )
    parser.add_argument("--profile", required=True,
                        choices=list(PROFILE_REQUIREMENTS.keys()),
                        help="Evidence pack profile")
    parser.add_argument("--dispatch-result", help="Path to dispatch result JSON")
    parser.add_argument("--artifact-ref", action="append", default=[],
                        help="Explicit artifact path (debug/manual mode)")
    parser.add_argument("--iteration", type=int, default=1,
                        help="Convergence loop iteration number")
    parser.add_argument("--output-dir", help="Override output directory")

    args = parser.parse_args()

    dispatch_result = None
    if args.dispatch_result:
        try:
            dispatch_result = _load_dispatch_result(args.dispatch_result)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"ERROR: Cannot load dispatch result: {e}", file=sys.stderr)
            return 1

    manifest = build_pack(
        profile=args.profile,
        dispatch_result=dispatch_result,
        explicit_refs=args.artifact_ref,
        iteration=args.iteration,
    )

    manifest_path = write_pack(manifest, args.output_dir)
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f"\nManifest written to: {manifest_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
