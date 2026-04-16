#!/usr/bin/env python3
"""Evidence Manifest Generator for Terminator Bug Bounty Pipeline.

Scans a target directory to collect all pipeline artifacts and produces
a unified evidence manifest JSON. Runs at Phase 5 (finalization) to
create a single source of truth for all evidence in a submission.

Usage:
    python3 tools/evidence_manifest.py <target_dir>
    python3 tools/evidence_manifest.py <target_dir> --output manifest.json
    python3 tools/evidence_manifest.py <target_dir> --validate

Exit: 0=success, 1=incomplete (missing critical artifacts)
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Artifact registry — what we expect from each pipeline phase
# ---------------------------------------------------------------------------
ARTIFACT_REGISTRY = {
    "explore_lane": {
        "target_assessment.md": {"phase": "0", "agent": "target-evaluator", "critical": False},
        "program_rules_summary.md": {"phase": "0.2", "agent": "orchestrator", "critical": True},
        "endpoint_map.md": {"phase": "1", "agent": "scout", "critical": True},
        "recon_notes.md": {"phase": "1", "agent": "scout", "critical": False},
        "vulnerability_candidates.md": {"phase": "1", "agent": "analyst", "critical": True},
        "trust_boundary_map.md": {"phase": "1", "agent": "threat-modeler", "critical": False},
        "role_matrix.md": {"phase": "1", "agent": "threat-modeler", "critical": False},
        "state_machines.md": {"phase": "1", "agent": "threat-modeler", "critical": False},
        "invariants.md": {"phase": "1", "agent": "threat-modeler", "critical": False},
        "patch_analysis.md": {"phase": "1", "agent": "patch-hunter", "critical": False},
        "workflow_map.md": {"phase": "1.5", "agent": "workflow-auditor", "critical": False},
        "web_test_report.md": {"phase": "1.5", "agent": "web-tester", "critical": False},
        "source_audit_report.md": {"phase": "1", "agent": "source-auditor", "critical": False},
    },
    "prove_lane": {
        "exploit_results.md": {"phase": "2", "agent": "exploiter", "critical": True},
        "explore_candidates.md": {"phase": "2", "agent": "exploiter", "critical": False},
    },
    "review": {
        "critic_review.md": {"phase": "4", "agent": "critic", "critical": False},
    },
    "report": {
        "report.md": {"phase": "3", "agent": "reporter", "critical": True},
        "bugcrowd_form.md": {"phase": "3", "agent": "reporter", "critical": True},
    },
}

# Structured JSON artifacts
JSON_ARTIFACTS = [
    "checkpoint.json",
    "triager_sim_result.json",
    "cost_tracking.json",
    "mitre_enrichment.json",
]

# Evidence subdirectories
EVIDENCE_DIRS = ["evidence", "submission", "h1_reports"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_target(target_dir: Path) -> dict:
    manifest = {
        "version": "1.0.0",
        "generator": "Terminator/evidence_manifest.py",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_dir": str(target_dir),
        "target_name": target_dir.name,
        "artifacts": {},
        "evidence_files": [],
        "json_data": {},
        "summary": {
            "total_artifacts": 0,
            "found": 0,
            "missing_critical": [],
            "missing_optional": [],
            "evidence_file_count": 0,
            "total_size_bytes": 0,
        },
    }

    # Scan registered artifacts
    for lane, files in ARTIFACT_REGISTRY.items():
        for filename, meta in files.items():
            filepath = target_dir / filename
            entry = {
                "filename": filename,
                "lane": lane,
                "phase": meta["phase"],
                "agent": meta["agent"],
                "critical": meta["critical"],
                "found": filepath.exists(),
            }

            manifest["summary"]["total_artifacts"] += 1

            if filepath.exists():
                stat = filepath.stat()
                entry["size_bytes"] = stat.st_size
                entry["modified"] = datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).isoformat()
                entry["sha256"] = sha256_file(filepath)
                entry["word_count"] = len(filepath.read_text(encoding="utf-8", errors="ignore").split())
                manifest["summary"]["found"] += 1
                manifest["summary"]["total_size_bytes"] += stat.st_size
            else:
                if meta["critical"]:
                    manifest["summary"]["missing_critical"].append(filename)
                else:
                    manifest["summary"]["missing_optional"].append(filename)

            manifest["artifacts"][filename] = entry

    # Scan JSON artifacts
    for jfile in JSON_ARTIFACTS:
        jpath = target_dir / jfile
        if jpath.exists():
            try:
                data = json.loads(jpath.read_text(encoding="utf-8"))
                # Store summary, not full content
                if jfile == "checkpoint.json":
                    manifest["json_data"]["checkpoint"] = {
                        "agent": data.get("agent", "unknown"),
                        "status": data.get("status", "unknown"),
                        "phase": data.get("phase", "unknown"),
                        "completed": data.get("completed", []),
                        "produced_artifacts": data.get("produced_artifacts", []),
                    }
                elif jfile == "triager_sim_result.json":
                    manifest["json_data"]["triager_sim"] = {
                        "decision": data.get("decision", "unknown"),
                        "slop_score": data.get("slop_score", None),
                        "poc_tier": data.get("poc_tier", None),
                        "quality_rating": data.get("quality_rating", None),
                        "bounty_estimate": data.get("bounty_estimate", None),
                        "issue_count": len(data.get("issues", [])),
                    }
                elif jfile == "cost_tracking.json":
                    manifest["json_data"]["cost"] = {
                        "total_cost": data.get("total_cost", 0),
                        "phases": {k: v for k, v in data.items()
                                   if k not in ("target", "created", "total_cost")},
                    }
                else:
                    manifest["json_data"][jfile] = {"found": True, "keys": list(data.keys())[:10]}
            except (json.JSONDecodeError, KeyError):
                manifest["json_data"][jfile] = {"found": True, "parse_error": True}

    # Scan evidence directories
    for edir_name in EVIDENCE_DIRS:
        edir = target_dir / edir_name
        if edir.exists() and edir.is_dir():
            for fpath in sorted(edir.rglob("*")):
                if fpath.is_file():
                    stat = fpath.stat()
                    manifest["evidence_files"].append({
                        "path": str(fpath.relative_to(target_dir)),
                        "size_bytes": stat.st_size,
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                        "sha256": sha256_file(fpath),
                    })
                    manifest["summary"]["evidence_file_count"] += 1
                    manifest["summary"]["total_size_bytes"] += stat.st_size

    # Scan for report scorer results
    scorer_path = target_dir / "report_score.json"
    if scorer_path.exists():
        try:
            score_data = json.loads(scorer_path.read_text(encoding="utf-8"))
            manifest["json_data"]["report_score"] = {
                "composite": score_data.get("composite", 0),
                "passed": score_data.get("passed", False),
                "dimensions": {k: score_data.get(k, 0) for k in [
                    "evidence_completeness", "impact_clarity",
                    "reproducibility", "triage_readability", "ai_slop",
                ]},
            }
        except (json.JSONDecodeError, KeyError):
            pass

    return manifest


def validate_manifest(manifest: dict) -> bool:
    missing = manifest["summary"]["missing_critical"]
    if missing:
        print(f"FAIL: {len(missing)} critical artifact(s) missing:", file=sys.stderr)
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        return False
    return True


def print_human(manifest: dict) -> None:
    s = manifest["summary"]
    print(f"\n{'=' * 60}")
    print(f"Evidence Manifest: {manifest['target_name']}")
    print(f"{'=' * 60}")
    print(f"\n  Artifacts: {s['found']}/{s['total_artifacts']} found")
    print(f"  Evidence files: {s['evidence_file_count']}")
    print(f"  Total size: {s['total_size_bytes'] / 1024:.1f} KB")

    if s["missing_critical"]:
        print(f"\n  MISSING CRITICAL ({len(s['missing_critical'])}):")
        for m in s["missing_critical"]:
            print(f"    - {m}")

    if s["missing_optional"]:
        print(f"\n  Missing optional ({len(s['missing_optional'])}):")
        for m in s["missing_optional"]:
            print(f"    - {m}")

    # Pipeline state
    if "checkpoint" in manifest["json_data"]:
        cp = manifest["json_data"]["checkpoint"]
        print(f"\n  Pipeline state: agent={cp['agent']}, status={cp['status']}, phase={cp['phase']}")

    if "triager_sim" in manifest["json_data"]:
        ts = manifest["json_data"]["triager_sim"]
        print(f"  Triager decision: {ts['decision']}, slop={ts['slop_score']}, "
              f"quality={ts['quality_rating']}, bounty={ts['bounty_estimate']}")

    if "report_score" in manifest["json_data"]:
        rs = manifest["json_data"]["report_score"]
        status = "PASS" if rs["passed"] else "FAIL"
        print(f"  Report score: {rs['composite']}/100 [{status}]")

    if "cost" in manifest["json_data"]:
        cost = manifest["json_data"]["cost"]
        print(f"  Cost: ${cost.get('total_cost', 0):.2f}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Generate unified evidence manifest from target directory"
    )
    parser.add_argument("target_dir", help="Path to target directory")
    parser.add_argument("-o", "--output", help="Output JSON file (default: <target>/evidence_manifest.json)")
    parser.add_argument("--validate", action="store_true",
                        help="Validate completeness (exit 1 if critical artifacts missing)")
    parser.add_argument("--json", action="store_true",
                        help="Output JSON to stdout")
    args = parser.parse_args()

    target = Path(args.target_dir)
    if not target.exists():
        print(f"Error: Target directory not found: {args.target_dir}", file=sys.stderr)
        sys.exit(1)

    manifest = scan_target(target)

    if args.json:
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
    else:
        print_human(manifest)

    # Write manifest file
    if not args.json:
        out_path = Path(args.output) if args.output else target / "evidence_manifest.json"
        out_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"  Manifest written to: {out_path}")

    if args.validate:
        if not validate_manifest(manifest):
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
