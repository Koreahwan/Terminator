"""Tests for Gmail search-result ingestion into local monitor state."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(REPO_ROOT))

from tools import gmail_monitor


SUBMISSIONS_FIXTURE = {
    "submissions": [
        {
            "platform": "YesWeHack",
            "target": "ProConnect Identité",
            "title": "OIDC `claims` parameter bypasses per-client scope authorization (CAND-01) — #YWH-PGM8338-167",
            "severity": "Medium",
            "bounty": "est €500",
            "status": "Under Review",
            "submitted": "2026-04-18",
            "note": "tracker fixture",
        },
        {
            "platform": "Bugcrowd",
            "target": "magiclabs",
            "title": "loginWithPopup postMessage origin (ed68b74d)",
            "severity": "Low",
            "bounty": "—",
            "status": "Not Reproducible",
            "submitted": "2026-04-03",
            "note": "tracker fixture",
        },
    ]
}


YWH_EMAIL = {
    "id": "mail-ywh-1",
    "from_": "YesWeHack noreply@yeswehack.com",
    "subject": "[YesWeHack] Report #YWH-PGM8338-167 status updated to Under Review",
    "snippet": "The status of report #YWH-PGM8338-167 has been updated to Under Review",
    "email_ts": "2026-04-18T11:21:08+02:00",
}

BUGCROWD_EMAIL = {
    "id": "mail-bc-1",
    "from_": "The Bugcrowd Team support@bugcrowd.com",
    "subject": "[magiclabs-mbb-og] Missing origin check in loginWithPopup() postMessage handler in @magic-ext/oauth2@15.5.2",
    "snippet": "relic_bugcrowd changed Missing origin check in loginWithPopup() postMessage handler in @magic-ext/oauth2@15.5.2 to not reproducible",
    "email_ts": "2026-04-23T04:17:50+00:00",
}

ACCOUNT_EMAIL = {
    "id": "mail-immunefi-1",
    "from_": "Immunefi noreply@bugs.immunefi.com",
    "subject": "Your Immunefi account has been disabled",
    "snippet": "Your Immunefi account has been disabled",
    "email_ts": "2026-04-09T07:17:15+00:00",
}


class TestGmailMonitorSync(unittest.TestCase):
    def setUp(self) -> None:
        self.state = gmail_monitor.load_state()

    def test_build_mail_event_matches_ywh_submission_by_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gmail_sub_idx_") as td:
            sub_path = Path(td) / "submissions.json"
            sub_path.write_text(json.dumps(SUBMISSIONS_FIXTURE), encoding="utf-8")
            with patch.object(gmail_monitor, "CANONICAL_SUBMISSIONS_JSON", sub_path):
                index = gmail_monitor._load_submission_index()
                event = gmail_monitor._build_mail_event(YWH_EMAIL, index)

        self.assertEqual(event["status"], "under_review")
        self.assertTrue(event["matched_submission"])
        self.assertEqual(event["target"], "ProConnect Identité")
        self.assertEqual(event["finding"], "YWH-PGM8338-167")

    def test_build_mail_event_matches_bugcrowd_submission_by_target_and_title(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gmail_sub_idx_") as td:
            sub_path = Path(td) / "submissions.json"
            sub_path.write_text(json.dumps(SUBMISSIONS_FIXTURE), encoding="utf-8")
            with patch.object(gmail_monitor, "CANONICAL_SUBMISSIONS_JSON", sub_path):
                index = gmail_monitor._load_submission_index()
                event = gmail_monitor._build_mail_event(BUGCROWD_EMAIL, index)

        self.assertEqual(event["status"], "not_reproducible")
        self.assertTrue(event["matched_submission"])
        self.assertEqual(event["target"], "magiclabs")
        self.assertEqual(event["finding"], "ED68B74D")

    def test_sync_search_results_updates_report_state_and_marks_seen(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gmail_sub_idx_") as td:
            sub_path = Path(td) / "submissions.json"
            sub_path.write_text(json.dumps(SUBMISSIONS_FIXTURE), encoding="utf-8")
            with patch.object(gmail_monitor, "CANONICAL_SUBMISSIONS_JSON", sub_path):
                summary = gmail_monitor.sync_search_results(
                    self.state,
                    {"emails": [YWH_EMAIL, BUGCROWD_EMAIL]},
                    mark_seen_flag=True,
                    force=False,
                )

        self.assertEqual(summary["processed"], 2)
        self.assertEqual(summary["updated_reports"], 2)
        self.assertIn("mail-ywh-1", self.state["seen_emails"])
        self.assertIn("ProConnect Identité/YWH-PGM8338-167", self.state["report_statuses"])
        self.assertEqual(
            self.state["report_statuses"]["ProConnect Identité/YWH-PGM8338-167"]["status"],
            "under_review",
        )

    def test_sync_search_results_records_unmatched_account_event(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gmail_sub_idx_") as td:
            sub_path = Path(td) / "submissions.json"
            sub_path.write_text(json.dumps(SUBMISSIONS_FIXTURE), encoding="utf-8")
            with patch.object(gmail_monitor, "CANONICAL_SUBMISSIONS_JSON", sub_path):
                summary = gmail_monitor.sync_search_results(
                    self.state,
                    {"emails": [ACCOUNT_EMAIL]},
                    mark_seen_flag=False,
                    force=False,
                )

        self.assertEqual(summary["updated_reports"], 0)
        self.assertEqual(summary["events_recorded"], 1)
        self.assertEqual(self.state["mail_events"]["mail-immunefi-1"]["status"], "account_disabled")
        self.assertNotIn("mail-immunefi-1", self.state["seen_emails"])


if __name__ == "__main__":
    unittest.main()
