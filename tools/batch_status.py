#!/usr/bin/env python3
"""
Batch Status — Accurate target status from checkpoint.json (not stale candidate files).

Usage:
  python3 tools/batch_status.py                  # All targets summary
  python3 tools/batch_status.py --actionable     # Only submission-ready or human-action-required
  python3 tools/batch_status.py --target <name>  # Single target detail
"""

import json
import sys
from pathlib import Path

TARGETS_DIR = Path(__file__).parent.parent / "targets"

# Skip archived/old targets
SKIP_PREFIXES = ("_archive_", "2025-", "2026-01", "2026-02")


def load_checkpoint(target_dir: Path) -> dict:
    cp = target_dir / "checkpoint.json"
    if cp.exists():
        try:
            return json.loads(cp.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def classify_target(name: str, cp: dict) -> dict:
    """Classify target into actionable categories based on checkpoint truth."""
    status = cp.get("status", "unknown")
    phase = str(cp.get("phase", cp.get("current_phase", "?")))
    submission_ready = cp.get("submission_ready", False)
    human_action = cp.get("human_action_required", "")

    # Check for submission-ready findings
    submissions = cp.get("submissions", [])
    if not isinstance(submissions, list):
        submissions = []
    findings = cp.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    ready_findings = []

    for s in submissions:
        if s.get("status") in ("awaiting_phase_5.8_autofill", "submission_ready", "ready"):
            ready_findings.append({
                "id": s.get("finding", "?"),
                "title": s.get("title", "?")[:80],
                "severity": s.get("severity", "?"),
                "platform": s.get("platform", "?"),
                "rejection_prob": s.get("rejection_probability", "?"),
            })

    for f in findings:
        if f.get("status") in ("submission_ready", "ready"):
            if not any(r["id"] == f.get("id") for r in ready_findings):
                ready_findings.append({
                    "id": f.get("id", "?"),
                    "title": f.get("title", "?")[:80],
                    "severity": f.get("severity", "?"),
                    "platform": "",
                    "rejection_prob": "?",
                })

    # Determine findings that were killed
    findings_summary = cp.get("findings_summary", {})
    killed = []
    if isinstance(findings_summary, dict):
        for fid, desc in findings_summary.items():
            desc_lower = str(desc).lower()
            if any(kw in desc_lower for kw in ("kill", "block", "e4", "no-go", "abandon")):
                killed.append(f"{fid}: {str(desc)[:80]}")
    elif isinstance(findings_summary, list):
        for item in findings_summary:
            desc = str(item)
            if any(kw in desc.lower() for kw in ("kill", "block", "e4", "no-go", "abandon")):
                killed.append(desc[:80])

    # Category
    if ready_findings:
        category = "SUBMIT_READY"
    elif human_action:
        category = "HUMAN_ACTION"
    elif status == "completed" and not ready_findings:
        category = "EXHAUSTED"
    elif status in ("running", "in_progress"):
        category = "RUNNING"
    else:
        category = "DONE_NO_FINDINGS"

    return {
        "name": name,
        "status": status,
        "phase": phase,
        "category": category,
        "ready_findings": ready_findings,
        "killed": killed,
        "human_action": human_action,
        "submission_ready": submission_ready,
    }


def print_summary(targets: list[dict]):
    # Group by category
    submit_ready = [t for t in targets if t["category"] == "SUBMIT_READY"]
    human_action = [t for t in targets if t["category"] == "HUMAN_ACTION"]
    running = [t for t in targets if t["category"] == "RUNNING"]
    exhausted = [t for t in targets if t["category"] in ("EXHAUSTED", "DONE_NO_FINDINGS")]

    if submit_ready:
        print("=" * 70)
        print("SUBMIT READY — Phase 5.8 auto-fill 대기")
        print("=" * 70)
        for t in submit_ready:
            for f in t["ready_findings"]:
                rej = f"rej={f['rejection_prob']}%" if f["rejection_prob"] != "?" else ""
                plat = f"({f['platform']})" if f["platform"] else ""
                print(f"  [{t['name']}] {f['id']}: {f['title']}")
                print(f"    {f['severity'].upper()} {plat} {rej}")
        print()

    if human_action:
        print("=" * 70)
        print("HUMAN ACTION REQUIRED")
        print("=" * 70)
        for t in human_action:
            print(f"  [{t['name']}] {t['human_action'][:120]}")
        print()

    if running:
        print(f"RUNNING: {len(running)} targets")
        for t in running:
            print(f"  [{t['name']}] phase={t['phase']}")
        print()

    print(f"EXHAUSTED (no submittable findings): {len(exhausted)} targets")
    if "--verbose" in sys.argv:
        for t in exhausted:
            killed_str = f" | killed: {len(t['killed'])}" if t["killed"] else ""
            print(f"  [{t['name']}] phase={t['phase']}{killed_str}")
    print()

    # Stats
    total = len(targets)
    print(f"--- Total: {total} | Submit: {len(submit_ready)} | "
          f"Human: {len(human_action)} | Running: {len(running)} | "
          f"Exhausted: {len(exhausted)} ---")


def print_detail(name: str, cp: dict, result: dict):
    print(f"=== {name} ===")
    print(f"Status: {result['status']} | Phase: {result['phase']} | Category: {result['category']}")
    print()

    if result["ready_findings"]:
        print("READY FINDINGS:")
        for f in result["ready_findings"]:
            print(f"  {f['id']}: {f['title']}")
            print(f"    severity={f['severity']}, platform={f['platform']}, rejection={f['rejection_prob']}%")

    if result["human_action"]:
        print(f"\nHUMAN ACTION: {result['human_action']}")

    if result["killed"]:
        print(f"\nKILLED ({len(result['killed'])}):")
        for k in result["killed"]:
            print(f"  {k}")

    completed = cp.get("completed", [])
    if completed:
        print(f"\nCOMPLETED PHASES ({len(completed)}):")
        for c in completed:
            print(f"  {c}")


def main():
    single_target = None
    actionable_only = "--actionable" in sys.argv

    for i, arg in enumerate(sys.argv):
        if arg == "--target" and i + 1 < len(sys.argv):
            single_target = sys.argv[i + 1]

    targets = []
    for target_dir in sorted(TARGETS_DIR.iterdir()):
        if not target_dir.is_dir():
            continue
        name = target_dir.name
        if any(name.startswith(p) for p in SKIP_PREFIXES):
            continue

        if single_target and name != single_target:
            continue

        cp = load_checkpoint(target_dir)
        if not cp:
            continue

        result = classify_target(name, cp)
        targets.append(result)

    if single_target and targets:
        cp = load_checkpoint(TARGETS_DIR / single_target)
        print_detail(single_target, cp, targets[0])
    elif actionable_only:
        actionable = [t for t in targets if t["category"] in ("SUBMIT_READY", "HUMAN_ACTION", "RUNNING")]
        if actionable:
            print_summary(actionable)
        else:
            print("No actionable targets.")
    else:
        print_summary(targets)


if __name__ == "__main__":
    main()
