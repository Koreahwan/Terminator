"""Tests for the compiled ops wiki builder."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(REPO_ROOT))

from tools.ops_wiki import (
    build_ops_wiki,
    load_tracker_context,
    parse_first_table,
    split_sections,
)


TRACKER_FIXTURE = """\
# Bug Bounty + CVE Submissions — Canonical Tracker

**Last updated**: 2026-04-23

## Active (Pending / Triage)

| Platform | Target | Title | Sev | Bounty | Status | Submitted | Last Check | Note |
|---|---|---|---|---|---|---|---|---|
| Bugcrowd | Acme | Report #1234 — Origin issue | Medium | — | Pending | 2026-04-01 | 2026-04-05 | stale pending |
| YesWeHack | Qwant | Report #16-705 — SSRF leak | Medium | — (awaiting) | Accepted | 2026-04-05 | 2026-04-18 | payout unknown |

## Resolved (Accepted / Rejected / Closed)

| Platform | Target | Title | Sev | Bounty | Status | Submitted | Resolved | Memory Lesson |
|---|---|---|---|---|---|---|---|---|
| Intigriti | Port | Info disclosure #1 | Low | — | OOS | 2026-04-13 | 2026-04-14 | verbose-msgs rule |

## Appeals / Escalations In Flight

| Case | Platform | Route | Status | Next Action |
|---|---|---|---|---|
| Paradex #72759 autoban | Immunefi | Zendesk form | waiting | resubmit escalation |

## Platform-level Notes

- **Bugcrowd**: recent accuracy pressure
- **Immunefi**: email inbox deprecated
"""


SUBMISSIONS_FIXTURE = {
    "generated_at": "2026-04-23",
    "submissions": [
        {
            "platform": "Bugcrowd",
            "target": "Acme",
            "title": "Report #1234 — Origin issue",
            "severity": "Medium",
            "bounty": "—",
            "status": "Pending",
            "submitted": "2026-04-01",
            "note": "awaiting first triage",
        },
        {
            "platform": "YesWeHack",
            "target": "Qwant",
            "title": "Report #16-705 — SSRF leak",
            "severity": "Medium",
            "bounty": "—",
            "status": "Accepted",
            "submitted": "2026-04-05",
            "note": "accepted but payout unknown",
        },
        {
            "platform": "Immunefi",
            "target": "Paradex",
            "title": "Report #72759 — vault issue",
            "severity": "Critical",
            "bounty": "—",
            "status": "Closed",
            "submitted": "2026-04-09",
            "note": "appeal in flight",
        },
    ],
}


GMAIL_FIXTURE = {
    "report_statuses": {
        "Acme/#1234": {
            "target": "Acme",
            "finding": "#1234",
            "status": "message_received",
            "updated_at": "2026-04-08T10:00:00",
        }
    },
    "response_drafts": [
        {
            "target": "Paradex",
            "finding": "#72759",
            "subject": "Appeal follow-up",
            "created_at": "2026-04-16T12:00:00",
            "sent": False,
        }
    ],
    "bounty_payments": {
        "Qwant/#16-705": {
            "target": "Qwant",
            "finding": "#16-705",
            "amount": 500,
            "currency": "EUR",
            "platform": "YesWeHack",
        }
    },
}


class TestTrackerParsing(unittest.TestCase):
    def test_split_sections_and_table_parse(self) -> None:
        sections = split_sections(TRACKER_FIXTURE)
        self.assertIn("Appeals / Escalations In Flight", sections)
        rows = parse_first_table(sections["Appeals / Escalations In Flight"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["Platform"], "Immunefi")

    def test_load_tracker_context(self) -> None:
        with tempfile.TemporaryDirectory(prefix="opswiki_tracker_") as td:
            tracker = Path(td) / "SUBMISSIONS.md"
            tracker.write_text(TRACKER_FIXTURE, encoding="utf-8")
            ctx = load_tracker_context(tracker)
            self.assertEqual(ctx.last_updated, "2026-04-23")
            self.assertEqual(len(ctx.appeals), 1)
            self.assertEqual(len(ctx.platform_notes), 2)


class TestOpsWikiBuild(unittest.TestCase):
    def test_build_generates_expected_pages(self) -> None:
        with tempfile.TemporaryDirectory(prefix="opswiki_build_") as td:
            root = Path(td)
            submissions_json = root / "submissions.json"
            tracker_md = root / "SUBMISSIONS.md"
            gmail_json = root / "gmail.json"
            out_dir = root / "out"

            submissions_json.write_text(json.dumps(SUBMISSIONS_FIXTURE), encoding="utf-8")
            tracker_md.write_text(TRACKER_FIXTURE, encoding="utf-8")
            gmail_json.write_text(json.dumps(GMAIL_FIXTURE), encoding="utf-8")

            build_ops_wiki(
                submissions_json=submissions_json,
                tracker_md=tracker_md,
                gmail_state_path=gmail_json,
                out_dir=out_dir,
                today=date(2026, 4, 23),
            )

            self.assertTrue((out_dir / "index.md").exists())
            self.assertTrue((out_dir / "followups.md").exists())
            self.assertTrue((out_dir / "appeals.md").exists())
            self.assertTrue((out_dir / "platforms" / "bugcrowd.md").exists())
            self.assertTrue((out_dir / "submissions").exists())

            followups = (out_dir / "followups.md").read_text(encoding="utf-8")
            self.assertIn("Urgent", followups)
            self.assertIn("Origin issue", followups)
            self.assertIn("accepted but payout not confirmed", followups)

            paradex_files = list((out_dir / "submissions").glob("*paradex*"))
            self.assertEqual(len(paradex_files), 1)
            paradex_page = paradex_files[0].read_text(encoding="utf-8")
            self.assertIn("Appeal follow-up", paradex_page)

            qwant_files = list((out_dir / "submissions").glob("*qwant*"))
            self.assertEqual(len(qwant_files), 1)
            qwant_page = qwant_files[0].read_text(encoding="utf-8")
            self.assertIn("Payment tracked: 500 EUR", qwant_page)

    def test_build_without_gmail_state_still_succeeds(self) -> None:
        with tempfile.TemporaryDirectory(prefix="opswiki_nogmail_") as td:
            root = Path(td)
            submissions_json = root / "submissions.json"
            tracker_md = root / "SUBMISSIONS.md"
            out_dir = root / "out"

            submissions_json.write_text(json.dumps(SUBMISSIONS_FIXTURE), encoding="utf-8")
            tracker_md.write_text(TRACKER_FIXTURE, encoding="utf-8")

            build_ops_wiki(
                submissions_json=submissions_json,
                tracker_md=tracker_md,
                gmail_state_path=root / "missing.json",
                out_dir=out_dir,
                today=date(2026, 4, 23),
            )

            index_text = (out_dir / "index.md").read_text(encoding="utf-8")
            self.assertIn("Operations Wiki", index_text)


if __name__ == "__main__":
    unittest.main()
