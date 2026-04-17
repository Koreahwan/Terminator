#!/usr/bin/env python3
"""
Submission Queue Manager
Scans targets/ for Phase 5.5 GO findings ready for Phase 5.8 auto-fill.

Immunefi has a 24h/1 submit rate limit → managed as a priority queue.
Other platforms have no limit → submitted immediately (no queue needed).

Usage:
  python3 tools/submission_queue.py scan                        # All ready submissions
  python3 tools/submission_queue.py immunefi                    # Immunefi priority queue (High+ only)
  python3 tools/submission_queue.py other                       # Non-Immunefi (submit immediately)
  python3 tools/submission_queue.py next                        # Next Immunefi submission to send
  python3 tools/submission_queue.py mark-done <target> <finding>  # Mark as submitted
  python3 tools/submission_queue.py discard <target> <finding> <reason>  # Discard (Medium/Low etc)
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

TARGETS_DIR = Path(__file__).parent.parent / "targets"
QUEUE_FILE = Path(__file__).parent.parent / ".submission_queue.json"

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}


def scan():
    """Scan all targets for Phase 5.5 GO submissions ready for auto-fill."""
    ready = []

    for target_dir in sorted(TARGETS_DIR.iterdir()):
        if not target_dir.is_dir():
            continue
        submission_dir = target_dir / "submission"
        if not submission_dir.is_dir():
            continue

        for cand_dir in sorted(submission_dir.iterdir()):
            if not cand_dir.is_dir():
                continue

            payload_file = cand_dir / "autofill_payload.json"
            if not payload_file.exists():
                continue

            review_file = cand_dir / "submission_review.json"
            if not review_file.exists():
                continue

            # Check Phase 5.5 verdict
            try:
                review = json.loads(review_file.read_text())
                verdict = (review.get("decision") or review.get("verdict")
                          or review.get("overall_verdict") or review.get("overall"))
                if verdict not in ("GO", "SUBMIT"):
                    continue
            except (json.JSONDecodeError, KeyError):
                continue

            # Check if already submitted or discarded
            if (cand_dir / "pre_submit_screenshot.png").exists():
                continue
            queue = _load_queue()
            queue_key = f"{target_dir.name}/{cand_dir.name}"
            entry = queue.get(queue_key, {})
            if entry.get("status") in ("submitted", "discarded"):
                continue

            try:
                payload = json.loads(payload_file.read_text())
            except json.JSONDecodeError:
                continue

            # Extract rejection_probability and severity from review (check multiple field names)
            rej_prob = review.get("rejection_probability",
                      review.get("overall_rejection_probability", "?"))
            review_severity = (review.get("severity")
                              or review.get("severity_assessed")
                              or review.get("recommended_submitted_severity", ""))

            ready.append({
                "target": target_dir.name,
                "finding": cand_dir.name,
                "path": str(cand_dir),
                "payload_file": str(payload_file),
                "platform": payload.get("platform", "unknown"),
                "title": (payload.get("submission", {}).get("step3", {}).get("title")
                         or payload.get("fields", {}).get("title", "Unknown")),
                "severity": (payload.get("submission", {}).get("step2", {}).get("severity")
                            or payload.get("fields", {}).get("severity")
                            or payload.get("severity")
                            or review_severity
                            or "Unknown"),
                "rejection_probability": rej_prob,
            })

    return ready


def immunefi_queue():
    """Immunefi priority queue: High+ only, sorted by severity then rejection probability."""
    all_ready = scan()
    immunefi = [x for x in all_ready if x["platform"] == "immunefi"]

    # Filter High+ only
    high_plus = [x for x in immunefi
                 if x["severity"] in ("Critical", "High")]

    # Sort: severity desc (Critical first), then rejection_probability asc
    def sort_key(item):
        sev = SEVERITY_ORDER.get(item["severity"], 99)
        rej = item["rejection_probability"] if isinstance(item["rejection_probability"], (int, float)) else 50
        return (sev, rej)

    high_plus.sort(key=sort_key)

    # Medium/Low findings that should be discarded or rerouted
    medium_low = [x for x in immunefi
                  if x["severity"] not in ("Critical", "High")]

    return {"queue": high_plus, "medium_low_to_reroute": medium_low}


def other_platforms():
    """Non-Immunefi submissions — no rate limit, submit immediately."""
    all_ready = scan()
    return [x for x in all_ready if x["platform"] != "immunefi"]


def next_immunefi():
    """Get the next Immunefi submission to send."""
    result = immunefi_queue()
    if result["queue"]:
        return result["queue"][0]
    return None


def mark_done(target: str, finding: str):
    """Mark a submission as submitted."""
    queue = _load_queue()
    queue[f"{target}/{finding}"] = {
        "status": "submitted",
        "timestamp": datetime.now().isoformat()
    }
    _save_queue(queue)
    print(f"Marked {target}/{finding} as submitted")


def discard(target: str, finding: str, reason: str):
    """Discard a submission (Medium/Low, OOS, etc)."""
    queue = _load_queue()
    queue[f"{target}/{finding}"] = {
        "status": "discarded",
        "reason": reason,
        "timestamp": datetime.now().isoformat()
    }
    _save_queue(queue)
    print(f"Discarded {target}/{finding}: {reason}")


def _load_queue() -> dict:
    if QUEUE_FILE.exists():
        try:
            return json.loads(QUEUE_FILE.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def _save_queue(queue: dict):
    QUEUE_FILE.write_text(json.dumps(queue, indent=2))


def _print_table(items, label=""):
    if label:
        print(f"\n{label}")
        print("-" * 80)
    if not items:
        print("  (empty)")
        return
    for i, item in enumerate(items, 1):
        rej = item['rejection_probability']
        rej_str = f"{rej}%" if isinstance(rej, (int, float)) else "?"
        print(f"  {i}. [{item['severity']}] {item['target']}/{item['finding']} — rej={rej_str}")
        print(f"     {item['title'][:80]}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} scan|immunefi|other|next|mark-done|discard")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "scan":
        results = scan()
        if not results:
            print("No submissions ready.")
        else:
            print(json.dumps(results, indent=2))

    elif cmd == "immunefi":
        result = immunefi_queue()
        _print_table(result["queue"], "IMMUNEFI QUEUE (High+ only, priority order)")
        _print_table(result["medium_low_to_reroute"], "MEDIUM/LOW — reroute to other platform or discard")

    elif cmd == "other":
        results = other_platforms()
        _print_table(results, "OTHER PLATFORMS (submit immediately)")

    elif cmd == "next":
        n = next_immunefi()
        if n:
            print(json.dumps(n, indent=2))
        else:
            print("Immunefi queue empty.")

    elif cmd == "mark-done":
        if len(sys.argv) < 4:
            print(f"Usage: {sys.argv[0]} mark-done <target> <finding>")
            sys.exit(1)
        mark_done(sys.argv[2], sys.argv[3])

    elif cmd == "discard":
        if len(sys.argv) < 5:
            print(f"Usage: {sys.argv[0]} discard <target> <finding> <reason>")
            sys.exit(1)
        discard(sys.argv[2], sys.argv[3], " ".join(sys.argv[4:]))

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
