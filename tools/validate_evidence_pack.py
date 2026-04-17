#!/usr/bin/env python3
"""Validate evidence packs against schema and profile requirements.

Validator v1 enforces (per spec v3.4 §6.6):
  - Schema validity (required fields, types, enum values)
  - Profile completeness (all required artifacts for the profile)
  - File existence (every inventory path exists on disk)
  - Line-range existence (referenced line ranges are within file bounds)
  - Anchor consistency (anchor strings found in referenced files)
  - IRON-LIST file presence (iron_list artifacts exist)
  - IRON-LIST non-empty / basic sanity (iron_list files are non-trivial)
  - Iteration consistency (reject stale iterations)

Design note (v1 vs v2):
  v1 uses hardcoded validation checks rather than loading config/evidence_pack_schema.json
  via a jsonschema library. This avoids adding a runtime dependency (jsonschema is not in
  stdlib) while covering all spec-required checks. v2 should add schema-driven validation
  using jsonschema once the dependency is accepted.

Usage:
    python3 tools/validate_evidence_pack.py validate <manifest.json>
    python3 tools/validate_evidence_pack.py validate-dir <pack_directory>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

VALID_PROFILES = {"gate1", "gate2", "critic_review", "report_review", "submission_review"}
VALID_TIERS = {"E1", "E2", "E3", "E4"}
VALID_ROLES = {"primary", "supporting", "iron_list"}
VALID_STATUSES = {"pending", "valid", "invalid", "partial"}

REQUIRED_MANIFEST_FIELDS = {
    "schema_version", "profile", "pack_id", "iteration",
    "created_at", "source_role", "artifact_inventory", "validation_status",
}

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

# Minimum bytes for iron-list files to pass sanity check
IRON_LIST_MIN_BYTES = 50


class ValidationResult:
    """Accumulates validation errors and warnings."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    @property
    def valid(self) -> bool:
        return len(self.errors) == 0

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "errors": self.errors,
            "warnings": self.warnings,
        }


def validate_manifest(manifest: dict, base_dir: Path | None = None,
                      latest_iteration: int | None = None) -> ValidationResult:
    """Run all v1 validation checks on a manifest dict."""
    result = ValidationResult()

    # ── 1. Schema validity ─────────────────────────────────────────
    missing_fields = REQUIRED_MANIFEST_FIELDS - set(manifest.keys())
    if missing_fields:
        result.error(f"Missing required fields: {sorted(missing_fields)}")
        return result  # Cannot continue without structure

    if manifest.get("schema_version") != "2.4":
        result.error(f"Unsupported schema_version: {manifest.get('schema_version')}")

    profile = manifest.get("profile", "")
    if profile not in VALID_PROFILES:
        result.error(f"Invalid profile: {profile}")

    if not isinstance(manifest.get("iteration"), int) or manifest["iteration"] < 1:
        result.error(f"Invalid iteration: {manifest.get('iteration')}")

    if manifest.get("validation_status") not in VALID_STATUSES:
        result.error(f"Invalid validation_status: {manifest.get('validation_status')}")

    inventory = manifest.get("artifact_inventory", [])
    if not isinstance(inventory, list):
        result.error("artifact_inventory must be a list")
        return result

    # ── 2. Artifact inventory validation ───────────────────────────
    inventory_filenames: set[str] = set()
    for i, item in enumerate(inventory):
        if not isinstance(item, dict):
            result.error(f"artifact_inventory[{i}]: not a dict")
            continue
        if "path" not in item:
            result.error(f"artifact_inventory[{i}]: missing 'path'")
            continue
        if "role" not in item:
            result.error(f"artifact_inventory[{i}]: missing 'role'")
        elif item["role"] not in VALID_ROLES:
            result.error(f"artifact_inventory[{i}]: invalid role '{item['role']}'")

        artifact_path = Path(item["path"])
        inventory_filenames.add(artifact_path.name)

        # ── 3. File existence ──────────────────────────────────────
        if not artifact_path.is_absolute() and base_dir:
            artifact_path = base_dir / artifact_path
        if not artifact_path.exists():
            result.error(f"File not found: {item['path']}")
            continue

        # ── 4. Line-range existence ────────────────────────────────
        if "line_range" in item and item["line_range"]:
            lr = item["line_range"]
            start = lr.get("start", 0)
            end = lr.get("end", 0)
            if start > 0 and end > 0:
                try:
                    lines = artifact_path.read_text(encoding="utf-8").splitlines()
                    if end > len(lines):
                        result.error(
                            f"Line range {start}-{end} exceeds file length "
                            f"({len(lines)} lines): {item['path']}"
                        )
                except (OSError, UnicodeDecodeError):
                    result.warn(f"Cannot read file for line-range check: {item['path']}")

        # ── 5. Anchor consistency ──────────────────────────────────
        if "anchor" in item and item["anchor"]:
            try:
                content = artifact_path.read_text(encoding="utf-8")
                if item["anchor"] not in content:
                    result.error(
                        f"Anchor '{item['anchor'][:50]}...' not found in: {item['path']}"
                    )
            except (OSError, UnicodeDecodeError):
                result.warn(f"Cannot read file for anchor check: {item['path']}")

        # ── 6/7. IRON-LIST checks ─────────────────────────────────
        if item.get("role") == "iron_list":
            try:
                size = artifact_path.stat().st_size
                if size == 0:
                    result.error(f"IRON-LIST file is empty: {item['path']}")
                elif size < IRON_LIST_MIN_BYTES:
                    result.warn(
                        f"IRON-LIST file suspiciously small ({size} bytes): {item['path']}"
                    )
            except OSError:
                result.error(f"Cannot stat IRON-LIST file: {item['path']}")

    # ── 2b. Profile completeness ───────────────────────────────────
    if profile in PROFILE_REQUIREMENTS:
        reqs = PROFILE_REQUIREMENTS[profile]
        for req_file in reqs.get("required", []):
            if req_file not in inventory_filenames:
                result.error(f"Profile '{profile}' requires '{req_file}' but not in inventory")
        for iron_file in reqs.get("iron_list", []):
            if iron_file not in inventory_filenames:
                result.error(f"Profile '{profile}' IRON-LIST '{iron_file}' not in inventory")

    # ── 8. Iteration consistency ───────────────────────────────────
    if latest_iteration is not None:
        pack_iter = manifest.get("iteration", 0)
        if pack_iter < latest_iteration:
            result.error(
                f"Stale iteration: pack is iteration {pack_iter}, "
                f"but latest is {latest_iteration}"
            )

    return result


def validate_file(manifest_path: str, latest_iteration: int | None = None) -> ValidationResult:
    """Validate a manifest.json file."""
    path = Path(manifest_path)
    if not path.exists():
        result = ValidationResult()
        result.error(f"Manifest file not found: {manifest_path}")
        return result

    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        result = ValidationResult()
        result.error(f"Invalid JSON: {e}")
        return result

    return validate_manifest(manifest, base_dir=path.parent,
                            latest_iteration=latest_iteration)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate evidence packs."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    val = sub.add_parser("validate", help="Validate a manifest.json file")
    val.add_argument("manifest", help="Path to manifest.json")
    val.add_argument("--latest-iteration", type=int, default=None,
                     help="Latest known iteration (for staleness check)")

    vd = sub.add_parser("validate-dir", help="Validate a pack directory")
    vd.add_argument("directory", help="Path to evidence pack directory")
    vd.add_argument("--latest-iteration", type=int, default=None)

    args = parser.parse_args()

    if args.command == "validate":
        result = validate_file(args.manifest, args.latest_iteration)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return 0 if result.valid else 1

    if args.command == "validate-dir":
        manifest_path = Path(args.directory) / "manifest.json"
        if not manifest_path.exists():
            print(json.dumps({
                "valid": False,
                "error_count": 1,
                "errors": [f"No manifest.json in {args.directory}"],
                "warnings": [],
            }, indent=2))
            return 1
        result = validate_file(str(manifest_path), args.latest_iteration)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return 0 if result.valid else 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
