#!/usr/bin/env python3
"""Platform Accuracy Tracker & Submission Circuit Breaker.

Immunefi postmortem (2026-04-07): autoban at 0% accuracy across 5 submissions.
This tool prevents the same from happening on ANY platform.

Usage:
    platform_accuracy.py record <platform> <status> [--finding "<desc>"]  Record submission outcome
    platform_accuracy.py check <platform>                                 Pre-submission safety check
    platform_accuracy.py status [--all]                                   Show accuracy per platform
    platform_accuracy.py reset <platform>                                 Reset platform stats (with confirmation)

Status values for 'record': accepted, rejected, closed, duplicate, oos, spam, pending

Exit codes for 'check':
    0 = SAFE to submit
    1 = WARNING (accuracy declining, proceed with caution)
    2 = BLOCKED (circuit breaker tripped — DO NOT SUBMIT)

Circuit breaker rules:
    - 2 consecutive rejections on same platform → WARNING
    - 3 consecutive rejections → BLOCKED (cooldown: 7 days or 1 accepted elsewhere)
    - Any "spam" marking → INSTANT BLOCK on that platform (permanent)
    - Accuracy < 33% after 3+ submissions → BLOCKED
    - First submission on new platform → extra caution advisory

Created: 2026-04-07 (Immunefi postmortem — never again)
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta

TRACKER_FILE = Path(__file__).parent.parent / "data" / "platform_accuracy.json"


def _load_tracker() -> dict:
    """Load or initialize tracker data."""
    if TRACKER_FILE.exists():
        return json.loads(TRACKER_FILE.read_text())
    return {"platforms": {}, "version": "1.0", "created": datetime.now().isoformat()}


def _save_tracker(data: dict):
    """Save tracker data."""
    TRACKER_FILE.parent.mkdir(parents=True, exist_ok=True)
    data["last_updated"] = datetime.now().isoformat()
    TRACKER_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def _get_platform(data: dict, platform: str) -> dict:
    """Get or create platform entry."""
    if platform not in data["platforms"]:
        data["platforms"][platform] = {
            "submissions": [],
            "spam_blocked": False,
            "total": 0,
            "accepted": 0,
            "rejected": 0,
            "pending": 0,
            "consecutive_rejections": 0,
            "blocked_until": None,
            "block_reason": None,
        }
    return data["platforms"][platform]


# Rejection statuses (count against accuracy)
REJECTION_STATUSES = {"rejected", "closed", "oos", "spam", "duplicate"}
POSITIVE_STATUSES = {"accepted"}
NEUTRAL_STATUSES = {"pending"}


def record(platform: str, status: str, finding: str = "") -> int:
    """Record a submission outcome."""
    status = status.lower().strip()
    valid = REJECTION_STATUSES | POSITIVE_STATUSES | NEUTRAL_STATUSES
    if status not in valid:
        print(f"ERROR: Invalid status '{status}'. Valid: {', '.join(sorted(valid))}")
        return 1

    data = _load_tracker()
    plat = _get_platform(data, platform)

    entry = {
        "status": status,
        "finding": finding,
        "date": datetime.now().isoformat(),
    }
    plat["submissions"].append(entry)
    plat["total"] += 1

    if status in POSITIVE_STATUSES:
        plat["accepted"] += 1
        plat["consecutive_rejections"] = 0
        # Accepted submission clears block (except spam block)
        if not plat["spam_blocked"] and plat.get("blocked_until"):
            plat["blocked_until"] = None
            plat["block_reason"] = None
            print(f"  [UNBLOCKED] Acceptance cleared cooldown block on {platform}")
    elif status in NEUTRAL_STATUSES:
        plat["pending"] += 1
    else:
        plat["rejected"] += 1
        plat["consecutive_rejections"] += 1

        # Spam = instant permanent block
        if status == "spam":
            plat["spam_blocked"] = True
            plat["block_reason"] = f"SPAM marking on {datetime.now().strftime('%Y-%m-%d')}. PERMANENT BLOCK."
            print(f"  [PERMANENT BLOCK] Spam marking on {platform} — NEVER submit to this platform again")

        # 3 consecutive rejections = 7-day cooldown
        elif plat["consecutive_rejections"] >= 3:
            block_until = (datetime.now() + timedelta(days=7)).isoformat()
            plat["blocked_until"] = block_until
            plat["block_reason"] = (
                f"3 consecutive rejections. Cooldown until {block_until[:10]}. "
                f"This is how Immunefi autoban started."
            )
            print(f"  [BLOCKED] 3 consecutive rejections on {platform} — 7-day cooldown")

    # Show current accuracy
    decided = plat["accepted"] + plat["rejected"]
    accuracy = (plat["accepted"] / decided * 100) if decided > 0 else 0
    print(f"Recorded: {platform} | {status} | accuracy: {accuracy:.0f}% ({plat['accepted']}/{decided})")
    print(f"  consecutive_rejections: {plat['consecutive_rejections']}")

    _save_tracker(data)
    return 0


def check(platform: str) -> int:
    """Pre-submission safety check. Must pass before any submission."""
    data = _load_tracker()
    plat = _get_platform(data, platform)

    issues = []
    block = False

    # Check 1: Spam block (permanent)
    if plat.get("spam_blocked"):
        issues.append(f"[PERMANENT BLOCK] Platform marked you as spam. {plat.get('block_reason', '')}")
        block = True

    # Check 2: Cooldown block (time-based)
    if plat.get("blocked_until"):
        block_dt = datetime.fromisoformat(plat["blocked_until"])
        if datetime.now() < block_dt:
            remaining = (block_dt - datetime.now()).days
            issues.append(
                f"[COOLDOWN BLOCK] {plat.get('block_reason', '')} "
                f"Remaining: {remaining} days"
            )
            block = True
        else:
            # Cooldown expired, clear it
            plat["blocked_until"] = None
            plat["block_reason"] = None
            _save_tracker(data)

    # Check 3: Accuracy below threshold after 3+ decided submissions
    decided = plat["accepted"] + plat["rejected"]
    accuracy = (plat["accepted"] / decided * 100) if decided > 0 else 100

    if decided >= 3 and accuracy < 33:
        issues.append(
            f"[ACCURACY BLOCK] {accuracy:.0f}% accuracy ({plat['accepted']}/{decided}) — "
            f"below 33% threshold after 3+ submissions. "
            f"Immunefi autobanned at 0% after 5 submissions."
        )
        block = True

    # Check 4: 2 consecutive rejections (warning)
    if plat["consecutive_rejections"] >= 2 and not block:
        issues.append(
            f"[WARNING] {plat['consecutive_rejections']} consecutive rejections. "
            f"One more = 7-day cooldown block. Only submit if 100% confident."
        )

    # Check 5: Declining accuracy (warning)
    if decided >= 2 and accuracy < 50 and not block:
        issues.append(
            f"[WARNING] Accuracy at {accuracy:.0f}% ({plat['accepted']}/{decided}). "
            f"Trending toward autoban territory."
        )

    # Check 6: First submission on platform (advisory)
    if plat["total"] == 0:
        issues.append(
            f"[ADVISORY] First submission on {platform}. "
            f"Extra validation recommended — first impressions set accuracy baseline."
        )

    # Report
    if block:
        print(f"BLOCKED: Cannot submit to {platform}")
        for issue in issues:
            print(f"  {issue}")
        print("  → Fix accuracy or wait for cooldown before submitting.")
        return 2

    if issues:
        print(f"WARNING: {platform} — proceed with caution")
        for issue in issues:
            print(f"  {issue}")
        return 1

    print(f"SAFE: {platform} — accuracy {accuracy:.0f}% ({plat['accepted']}/{decided}), "
          f"{plat['consecutive_rejections']} consecutive rejections")
    return 0


def status(show_all: bool = False) -> int:
    """Show accuracy status for all platforms."""
    data = _load_tracker()

    if not data["platforms"]:
        print("No submission data recorded yet.")
        print("Use: platform_accuracy.py record <platform> <status> --finding '<desc>'")
        return 0

    print(f"{'Platform':<15} {'Acc%':>5} {'Accept':>7} {'Reject':>7} {'Pend':>5} {'ConsecRej':>10} {'Status':<20}")
    print("-" * 80)

    for name, plat in sorted(data["platforms"].items()):
        decided = plat["accepted"] + plat["rejected"]
        accuracy = (plat["accepted"] / decided * 100) if decided > 0 else 0

        if plat.get("spam_blocked"):
            pstatus = "SPAM BLOCKED"
        elif plat.get("blocked_until"):
            block_dt = datetime.fromisoformat(plat["blocked_until"])
            if datetime.now() < block_dt:
                pstatus = f"COOLDOWN ({(block_dt - datetime.now()).days}d)"
            else:
                pstatus = "OK (cooldown expired)"
        elif decided >= 3 and accuracy < 33:
            pstatus = "ACCURACY BLOCK"
        elif plat["consecutive_rejections"] >= 2:
            pstatus = "WARNING"
        else:
            pstatus = "OK"

        print(f"{name:<15} {accuracy:>4.0f}% {plat['accepted']:>7} {plat['rejected']:>7} "
              f"{plat['pending']:>5} {plat['consecutive_rejections']:>10} {pstatus:<20}")

    if show_all:
        print("\nSubmission history:")
        for name, plat in sorted(data["platforms"].items()):
            if plat["submissions"]:
                print(f"\n  {name}:")
                for sub in plat["submissions"][-10:]:  # Last 10
                    print(f"    {sub['date'][:10]} | {sub['status']:<10} | {sub.get('finding', '')[:60]}")

    return 0


def reset(platform: str) -> int:
    """Reset platform stats (dangerous — requires confirmation token)."""
    data = _load_tracker()
    if platform not in data["platforms"]:
        print(f"Platform '{platform}' not found in tracker.")
        return 1

    # Safety: require --confirm flag
    if "--confirm" not in sys.argv:
        plat = data["platforms"][platform]
        print(f"WARNING: About to reset {platform} stats:")
        print(f"  Total: {plat['total']}, Accepted: {plat['accepted']}, Rejected: {plat['rejected']}")
        print(f"  Add --confirm to proceed.")
        return 1

    del data["platforms"][platform]
    _save_tracker(data)
    print(f"Reset: {platform} stats cleared.")
    return 0


def backfill_immunefi() -> int:
    """Backfill Immunefi history for the record (banned platform)."""
    data = _load_tracker()
    plat = _get_platform(data, "immunefi")

    # Only backfill if empty
    if plat["total"] > 0:
        print("Immunefi already has records. Skipping backfill.")
        return 0

    history = [
        {"status": "spam", "finding": "rhino.fi depositWithId pause bypass (Low)", "date": "2026-03-27T00:00:00"},
        {"status": "oos", "finding": "daimo-pay startIntent() 1-wei dust freeze (Medium)", "date": "2026-04-03T00:00:00"},
        {"status": "oos", "finding": "utix setFinalizeAgent lock + isSane() deadlock (Critical)", "date": "2026-04-04T00:00:00"},
        {"status": "rejected", "finding": "paradex #72310 vault donate() inflation — mock PoC (Critical)", "date": "2026-04-05T00:00:00"},
        {"status": "closed", "finding": "paradex #72418 vault donate() inflation — account banned (Critical)", "date": "2026-04-07T00:00:00"},
    ]

    for entry in history:
        plat["submissions"].append(entry)
        plat["total"] += 1
        if entry["status"] in POSITIVE_STATUSES:
            plat["accepted"] += 1
        elif entry["status"] in NEUTRAL_STATUSES:
            plat["pending"] += 1
        else:
            plat["rejected"] += 1

    plat["consecutive_rejections"] = 5
    plat["spam_blocked"] = True
    plat["block_reason"] = "ACCOUNT PERMANENTLY BANNED (autoban 2026-04-07). Spam marking on rhino.fi."

    _save_tracker(data)
    print("Backfilled Immunefi history: 5 submissions, 0 accepted, PERMANENTLY BLOCKED")
    return 0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "record":
        if len(sys.argv) < 4:
            print("Usage: platform_accuracy.py record <platform> <status> [--finding '<desc>']")
            sys.exit(1)
        platform = sys.argv[2].lower()
        rec_status = sys.argv[3].lower()
        finding = ""
        if "--finding" in sys.argv:
            idx = sys.argv.index("--finding")
            if idx + 1 < len(sys.argv):
                finding = sys.argv[idx + 1]
        sys.exit(record(platform, rec_status, finding))

    elif cmd == "check":
        if len(sys.argv) < 3:
            print("Usage: platform_accuracy.py check <platform>")
            sys.exit(1)
        sys.exit(check(sys.argv[2].lower()))

    elif cmd == "status":
        show_all = "--all" in sys.argv
        sys.exit(status(show_all))

    elif cmd == "reset":
        if len(sys.argv) < 3:
            print("Usage: platform_accuracy.py reset <platform> --confirm")
            sys.exit(1)
        sys.exit(reset(sys.argv[2].lower()))

    elif cmd == "backfill-immunefi":
        sys.exit(backfill_immunefi())

    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
