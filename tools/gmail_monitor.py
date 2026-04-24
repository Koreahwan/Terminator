#!/usr/bin/env python3
"""
Gmail Monitor — State management for Gmail MCP automations.

Tracks seen emails, parsed statuses, and triggers for the bounty pipeline.
Gmail MCP calls happen in Claude's context; this tool manages local state.

Usage:
  python3 tools/gmail_monitor.py status                     # Show all tracked state
  python3 tools/gmail_monitor.py mark-seen <email_id>       # Mark email as processed
  python3 tools/gmail_monitor.py is-seen <email_id>         # Check if already processed
  python3 tools/gmail_monitor.py update-report <target> <finding> <status> [details] [--email-id=ID]
  python3 tools/gmail_monitor.py list-reports               # Show all tracked report statuses
  python3 tools/gmail_monitor.py add-cve <cve_id> <status> [details]
  python3 tools/gmail_monitor.py list-cves                  # Show CVE tracking state
  python3 tools/gmail_monitor.py add-target-alert <program> <platform> <url>
  python3 tools/gmail_monitor.py list-target-alerts         # Show new target alerts
  python3 tools/gmail_monitor.py save-draft <target> <finding> <subject> <body_file> [--gmail-draft-id=ID]
  python3 tools/gmail_monitor.py list-drafts                # Show pending response drafts
  python3 tools/gmail_monitor.py pending-confirmations      # Show submitted but unconfirmed (24h+)
  python3 tools/gmail_monitor.py add-payment <target> <finding> <amount> <currency> <platform>
  python3 tools/gmail_monitor.py payment-summary            # Revenue by platform/month/severity
  python3 tools/gmail_monitor.py sync-search <json_or_-> [--refresh-ops-wiki]
  python3 tools/gmail_monitor.py label-ids                  # Show stored label IDs
  python3 tools/gmail_monitor.py filter-ids                 # Show stored filter IDs
  python3 tools/gmail_monitor.py queries                    # Show search query templates
"""

import copy
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
STATE_FILE = PROJECT_ROOT / ".gmail_monitor_state.json"
LABEL_IDS_FILE = PROJECT_ROOT / ".gmail_label_ids.json"
FILTER_IDS_FILE = PROJECT_ROOT / ".gmail_filter_ids.json"
CANONICAL_SUBMISSIONS_JSON = PROJECT_ROOT / "docs" / "submissions.json"
SUBMISSIONS_DIR = PROJECT_ROOT / "knowledge" / "submissions"
TRIAGE_DIR = PROJECT_ROOT / "knowledge" / "triage_objections"


# --- Label Taxonomy ---

LABEL_HIERARCHY = {
    "BountyPipeline": None,
    "BountyPipeline/Platform-Alerts": None,
    "BountyPipeline/Submissions": None,
    "BountyPipeline/Submissions/Pending": None,
    "BountyPipeline/Submissions/Confirmed": None,
    "BountyPipeline/Submissions/Triaged": None,
    "BountyPipeline/Submissions/Resolved": None,
    "BountyPipeline/Submissions/Duplicate": None,
    "BountyPipeline/Submissions/Closed": None,
    "BountyPipeline/Triager-Questions": None,
    "BountyPipeline/Triager-Questions/Awaiting-Reply": None,
    "BountyPipeline/Triager-Questions/Replied": None,
    "BountyPipeline/CVE": None,
    "BountyPipeline/CVE/Requested": None,
    "BountyPipeline/CVE/Assigned": None,
    "BountyPipeline/CVE/Published": None,
    "BountyPipeline/New-Programs": None,
    "BountyPipeline/Bounty-Payments": None,
    "BountyPipeline/Processed": None,
}

# Status → label mapping for cron automations
STATUS_LABEL_MAP = {
    "confirmed": "BountyPipeline/Submissions/Confirmed",
    "triaged": "BountyPipeline/Submissions/Triaged",
    "accepted": "BountyPipeline/Submissions/Resolved",
    "wont_fix": "BountyPipeline/Submissions/Closed",
    "oos": "BountyPipeline/Submissions/Closed",
    "not_applicable": "BountyPipeline/Submissions/Closed",
    "not_reproducible": "BountyPipeline/Submissions/Closed",
    "resolved": "BountyPipeline/Submissions/Resolved",
    "duplicate": "BountyPipeline/Submissions/Duplicate",
    "closed": "BountyPipeline/Submissions/Closed",
    "informative": "BountyPipeline/Submissions/Closed",
    "paid": "BountyPipeline/Bounty-Payments",
    "under_review": "BountyPipeline/Submissions/Pending",
    "message_received": "BountyPipeline/Submissions/Pending",
}

# Filter definitions for setup-filters
FILTER_DEFINITIONS = [
    {
        "name": "Bugcrowd",
        "criteria": {"from": "bugcrowd.com"},
        "label": "BountyPipeline/Platform-Alerts",
    },
    {
        "name": "Immunefi",
        "criteria": {"from": "immunefi.com"},
        "label": "BountyPipeline/Platform-Alerts",
    },
    {
        "name": "HackenProof",
        "criteria": {"from": "hackenproof.com"},
        "label": "BountyPipeline/Platform-Alerts",
    },
    {
        "name": "YesWeHack",
        "criteria": {"from": "yeswehack.com"},
        "label": "BountyPipeline/Platform-Alerts",
    },
    {
        "name": "Intigriti",
        "criteria": {"from": "intigriti.com"},
        "label": "BountyPipeline/Platform-Alerts",
    },
    {
        "name": "HackerOne",
        "criteria": {"from": "hackerone.com"},
        "label": "BountyPipeline/Platform-Alerts",
    },
    {
        "name": "MITRE CVE",
        "criteria": {"from": "mitre.org", "subject": "CVE"},
        "label": "BountyPipeline/CVE/Requested",
    },
    {
        "name": "Bounty Payments",
        "criteria": {"subject": "bounty OR reward OR payment OR payout"},
        "label": "BountyPipeline/Bounty-Payments",
    },
]


def load_state() -> dict:
    if STATE_FILE.exists():
        state = json.loads(STATE_FILE.read_text())
        # Migrate: ensure new sections exist
        state.setdefault("bounty_payments", {})
        state.setdefault("mail_events", {})
        state["stats"].setdefault("payments_tracked", 0)
        state["stats"].setdefault("total_revenue_usd", 0)
        state["stats"].setdefault("mail_events_synced", 0)
        return state
    return {
        "seen_emails": {},
        "report_statuses": {},
        "cve_tracking": {},
        "target_alerts": [],
        "response_drafts": [],
        "bounty_payments": {},
        "mail_events": {},
        "last_check": {},
        "stats": {
            "total_processed": 0,
            "platform_alerts": 0,
            "cve_updates": 0,
            "status_changes": 0,
            "new_targets": 0,
            "drafts_created": 0,
            "payments_tracked": 0,
            "total_revenue_usd": 0,
            "mail_events_synced": 0,
        },
    }


def save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2, default=str))


def load_label_ids() -> dict:
    if LABEL_IDS_FILE.exists():
        return json.loads(LABEL_IDS_FILE.read_text())
    return {}


def save_label_ids(ids: dict):
    LABEL_IDS_FILE.write_text(json.dumps(ids, indent=2))


def load_filter_ids() -> dict:
    if FILTER_IDS_FILE.exists():
        return json.loads(FILTER_IDS_FILE.read_text())
    return {}


def save_filter_ids(ids: dict):
    FILTER_IDS_FILE.write_text(json.dumps(ids, indent=2))


def get_label_id(label_name: str) -> str:
    """Get label ID by name. Returns empty string if not found."""
    ids = load_label_ids()
    return ids.get(label_name, "")


def get_label_for_status(status: str) -> str:
    """Get the label name for a given report status."""
    return STATUS_LABEL_MAP.get(status, "")


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


def _compact_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", _normalize_text(value))


def _extract_identifiers(text: str) -> set[str]:
    patterns = [
        r"(YWH-[A-Z0-9-]+)",
        r"(GHSA-[\w-]+)",
        r"(CVE-\d{4}-\d+)",
        r"(HRSGROUP-[A-Z0-9]+)",
        r"(PORTOFANTWERP-[A-Z0-9]+)",
        r"(#YWH-[A-Z0-9-]+)",
        r"(#\d{1,}-\d{2,})",
        r"(#\d{4,})",
        r"\b([a-f0-9]{8})\b",
    ]
    out: set[str] = set()
    for pattern in patterns:
        for match in re.findall(pattern, text, re.IGNORECASE):
            out.add(match.upper().lstrip("#"))
    return out


def _platform_key(value: str) -> str:
    lowered = _normalize_text(value)
    if "bugcrowd" in lowered:
        return "bugcrowd"
    if "yeswehack" in lowered:
        return "yeswehack"
    if "intigriti" in lowered:
        return "intigriti"
    if "immunefi" in lowered:
        return "immunefi"
    if "hackerone" in lowered:
        return "hackerone"
    if "hackenproof" in lowered:
        return "hackenproof"
    if "huntr" in lowered:
        return "huntr"
    if "github" in lowered or "ghsa" in lowered:
        return "ghsa"
    if "mitre" in lowered:
        return "mitre"
    return "unknown"


def _load_submission_index() -> list[dict]:
    if not CANONICAL_SUBMISSIONS_JSON.exists():
        return []
    payload = json.loads(CANONICAL_SUBMISSIONS_JSON.read_text(encoding="utf-8"))
    out = []
    for item in payload.get("submissions", []):
        title = item.get("title", "")
        note = item.get("note", "")
        target = item.get("target", "")
        out.append(
            {
                "platform": item.get("platform", ""),
                "platform_key": _platform_key(item.get("platform", "")),
                "target": target,
                "target_compact": _compact_text(target),
                "title": title,
                "title_compact": _compact_text(title),
                "identifiers": _extract_identifiers(f"{title} {note}"),
                "finding": next(iter(_extract_identifiers(title)), title),
            }
        )
    return out


def _match_submission(email: dict, submission_index: list[dict]) -> dict | None:
    subject = email.get("subject", "")
    snippet = email.get("snippet", "")
    full_text = f"{subject}\n{snippet}"
    full_compact = _compact_text(full_text)
    bracket_match = re.search(r"\[([^\]]+)\]", subject)
    bracket_compact = _compact_text(bracket_match.group(1)) if bracket_match else ""
    identifiers = _extract_identifiers(full_text)
    platform = _platform_key(f"{email.get('from_', '')} {subject}")
    candidates = [item for item in submission_index if item["platform_key"] == platform] or submission_index

    if identifiers:
        for item in candidates:
            if identifiers & item["identifiers"]:
                return item

    target_matches = []
    for item in candidates:
        target_compact = item["target_compact"]
        if not target_compact:
            continue
        if target_compact in full_compact or (bracket_compact and target_compact in bracket_compact):
            target_matches.append(item)
    if len(target_matches) == 1:
        return target_matches[0]

    title_matches = []
    subject_after_bracket = subject.split("]", 1)[1] if "]" in subject else subject
    subject_words = {
        word
        for word in re.findall(r"[a-z0-9]{4,}", _normalize_text(subject_after_bracket))
        if word not in {"report", "submission", "status", "updated", "review"}
    }
    for item in target_matches or candidates:
        title_words = set(re.findall(r"[a-z0-9]{4,}", _normalize_text(item["title"])))
        overlap = len(subject_words & title_words)
        if overlap >= 2:
            title_matches.append((overlap, item))
    if title_matches:
        title_matches.sort(key=lambda pair: pair[0], reverse=True)
        return title_matches[0][1]
    return None


def _classify_status(subject: str, snippet: str) -> tuple[str, str]:
    text = _normalize_text(f"{subject}\n{snippet}")
    patterns = [
        ("under_review", [r"status updated to under review", r"changed to under review"]),
        ("wont_fix", [r"status updated to won't fix", r"changed to won't fix", r"\bwon't fix\b"]),
        ("not_reproducible", [r"changed .* to not reproducible", r"\bnot reproducible\b"]),
        ("not_applicable", [r"changed .* to not applicable", r"\bnot applicable\b"]),
        ("duplicate", [r"changed .* to duplicate", r"\bduplicate\b"]),
        ("oos", [r"out of scope", r"\boos\b"]),
        ("accepted", [r"status updated to accepted", r"changed to accepted"]),
        ("closed", [r"status changed from .* to closed", r"\bclosed by auto-ban\b", r"\bclosed\b"]),
        ("message_received", [r"thank you for your submission", r"you've successfully submitted", r"\bwe have received\b", r"\brequest received\b"]),
        ("program_disabled", [r"bug bounty .* has been disabled", r"program has been disabled"]),
        ("account_disabled", [r"your immunefi account has been disabled", r"account disabled"]),
        ("account_enabled", [r"account has been re-enabled"]),
        ("mention", [r"you have been mentioned"]),
        ("comment", [r"commented on"]),
    ]
    for status, regexes in patterns:
        for regex in regexes:
            if re.search(regex, text):
                return status, regex
    return "unknown", ""


def _build_mail_event(email: dict, submission_index: list[dict]) -> dict:
    subject = email.get("subject", "")
    snippet = email.get("snippet", "")
    platform = _platform_key(f"{email.get('from_', '')} {subject}")
    matched = _match_submission(email, submission_index)
    status, classifier = _classify_status(subject, snippet)
    identifiers = sorted(_extract_identifiers(f"{subject}\n{snippet}"))
    event = {
        "email_id": email.get("id", ""),
        "platform": platform,
        "subject": subject,
        "email_ts": email.get("email_ts", ""),
        "status": status,
        "classifier": classifier,
        "identifiers": identifiers,
        "matched_submission": bool(matched),
        "from": email.get("from_", ""),
    }
    if matched:
        event["target"] = matched["target"]
        event["finding"] = matched["finding"]
        event["canonical_title"] = matched["title"]
    elif identifiers:
        event["finding"] = identifiers[0]
        event["target"] = subject.split("]", 1)[0].strip("[] ") if subject.startswith("[") else platform
    else:
        event["target"] = subject.split("]", 1)[0].strip("[] ") if subject.startswith("[") else platform
        event["finding"] = subject
    event["details"] = snippet[:240]
    return event


def _record_report_status(state: dict, target: str, finding: str, status: str,
                          details: str = "", email_id: str = "") -> None:
    key = f"{target}/{finding}"
    prev = state["report_statuses"].get(key, {}).get("status", "unknown")
    entry = {
        "target": target,
        "finding": finding,
        "status": status,
        "details": details,
        "updated_at": datetime.now().isoformat(),
        "previous_status": prev,
    }
    if email_id:
        entry["confirmation_email_id"] = email_id
    state["report_statuses"][key] = entry
    state["stats"]["status_changes"] += 1


def _record_mail_event(state: dict, event: dict) -> None:
    email_id = event.get("email_id", "")
    if not email_id:
        return
    state["mail_events"][email_id] = event
    state["stats"]["mail_events_synced"] += 1


def _read_json_payload(path_or_dash: str) -> dict:
    if path_or_dash == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(path_or_dash).read_text(encoding="utf-8")
    return json.loads(raw)


def sync_search_results(state: dict, payload: dict, *, mark_seen_flag: bool = True, force: bool = False) -> dict:
    submission_index = _load_submission_index()
    emails = payload.get("emails", payload if isinstance(payload, list) else [])
    summary = {"processed": 0, "skipped_seen": 0, "updated_reports": 0, "events_recorded": 0}
    for email in emails:
        email_id = email.get("id", "")
        if email_id and not force and email_id in state["seen_emails"]:
            summary["skipped_seen"] += 1
            continue

        event = _build_mail_event(email, submission_index)
        _record_mail_event(state, event)
        summary["events_recorded"] += 1

        if event["status"] in {
            "under_review",
            "wont_fix",
            "not_reproducible",
            "not_applicable",
            "duplicate",
            "oos",
            "accepted",
            "closed",
            "message_received",
        }:
            _record_report_status(
                state,
                event["target"],
                event["finding"],
                event["status"],
                details=f"{event['subject']} | {event['details']}",
                email_id=email_id,
            )
            summary["updated_reports"] += 1

        if mark_seen_flag and email_id:
            state["seen_emails"][email_id] = {
                "seen_at": datetime.now().isoformat(),
                "category": f"gmail_sync:{event['status']}",
            }
            state["stats"]["total_processed"] += 1

        summary["processed"] += 1
    return summary


def refresh_ops_wiki() -> dict:
    """Best-effort refresh of the compiled ops wiki after Gmail state changes."""
    ops_wiki = PROJECT_ROOT / "tools" / "ops_wiki.py"
    if not ops_wiki.exists():
        return {"action": "skipped", "reason": "ops_wiki_missing"}
    try:
        result = subprocess.run(
            ["python3", str(ops_wiki), "sync"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return {"action": "failed", "reason": type(exc).__name__}

    payload_text = result.stdout.strip() or result.stderr.strip()
    if result.returncode != 0:
        return {"action": "failed", "reason": f"rc_{result.returncode}", "detail": payload_text[:200]}
    try:
        data = json.loads(payload_text)
        return {"action": "ok", "detail": data}
    except json.JSONDecodeError:
        return {"action": "ok", "detail": payload_text[:200]}


# --- Core commands ---

def mark_seen(state: dict, email_id: str, category: str = "general"):
    state["seen_emails"][email_id] = {
        "seen_at": datetime.now().isoformat(),
        "category": category,
    }
    state["stats"]["total_processed"] += 1
    save_state(state)
    print(f"Marked {email_id} as seen ({category})")


def is_seen(state: dict, email_id: str) -> bool:
    seen = email_id in state["seen_emails"]
    print(f"{'SEEN' if seen else 'NEW'}: {email_id}")
    return seen


def update_report(state: dict, target: str, finding: str, status: str,
                  details: str = "", email_id: str = ""):
    key = f"{target}/{finding}"
    prev = state["report_statuses"].get(key, {}).get("status", "unknown")
    entry = {
        "target": target,
        "finding": finding,
        "status": status,
        "details": details,
        "updated_at": datetime.now().isoformat(),
        "previous_status": prev,
    }
    if email_id:
        entry["confirmation_email_id"] = email_id
    state["report_statuses"][key] = entry
    state["stats"]["status_changes"] += 1

    SUBMISSIONS_DIR.mkdir(parents=True, exist_ok=True)
    sub_file = SUBMISSIONS_DIR / f"{target}_{finding}.md"
    sub_file.write_text(
        f"# {target} / {finding}\n\n"
        f"- **Status**: {status}\n"
        f"- **Previous**: {prev}\n"
        f"- **Updated**: {datetime.now().isoformat()}\n"
        f"- **Details**: {details}\n"
        + (f"- **Confirmation Email**: {email_id}\n" if email_id else "")
    )
    save_state(state)

    # Print label hint for cron automations
    label = get_label_for_status(status)
    label_id = get_label_id(label) if label else ""
    if label_id:
        print(f"Updated: {key} → {status} (was: {prev}) [LABEL: {label} = {label_id}]")
    else:
        print(f"Updated: {key} → {status} (was: {prev})")


def list_reports(state: dict):
    reports = state.get("report_statuses", {})
    if not reports:
        print("No tracked reports.")
        return
    print(f"{'Target/Finding':<50} {'Status':<15} {'Updated':<20}")
    print("-" * 85)
    for key, info in sorted(reports.items(), key=lambda x: x[1].get("updated_at", ""), reverse=True):
        print(f"{key:<50} {info['status']:<15} {info.get('updated_at', '?')[:19]}")


def pending_confirmations(state: dict):
    """Show submissions that are submitted but not yet confirmed (24h+ warning)."""
    reports = state.get("report_statuses", {})
    now = datetime.now()
    pending = []
    for key, info in reports.items():
        status = info.get("status", "")
        if status in ("submitted", "message_received", "under_review"):
            updated = info.get("updated_at", "")
            if updated:
                try:
                    dt = datetime.fromisoformat(updated)
                    age = now - dt
                    pending.append((key, status, age))
                except ValueError:
                    pending.append((key, status, timedelta(0)))

    if not pending:
        print("No pending confirmations. All submissions confirmed or no active submissions.")
        return

    print(f"{'Target/Finding':<50} {'Status':<15} {'Age':<15} {'Alert'}")
    print("-" * 95)
    for key, status, age in sorted(pending, key=lambda x: x[2], reverse=True):
        hours = age.total_seconds() / 3600
        alert = "WARNING: 24h+" if hours >= 24 else ""
        print(f"{key:<50} {status:<15} {hours:.1f}h          {alert}")


def add_cve(state: dict, cve_id: str, status: str, details: str = ""):
    state["cve_tracking"][cve_id] = {
        "status": status,
        "details": details,
        "updated_at": datetime.now().isoformat(),
    }
    state["stats"]["cve_updates"] += 1
    save_state(state)
    print(f"CVE {cve_id}: {status}")


def list_cves(state: dict):
    cves = state.get("cve_tracking", {})
    if not cves:
        print("No tracked CVEs.")
        return
    print(f"{'CVE ID':<25} {'Status':<20} {'Updated':<20}")
    print("-" * 65)
    for cve_id, info in sorted(cves.items()):
        print(f"{cve_id:<25} {info['status']:<20} {info.get('updated_at', '?')[:19]}")


def add_target_alert(state: dict, program: str, platform: str, url: str):
    state["target_alerts"].append({
        "program": program,
        "platform": platform,
        "url": url,
        "detected_at": datetime.now().isoformat(),
        "evaluated": False,
    })
    state["stats"]["new_targets"] += 1
    save_state(state)
    print(f"New target alert: {program} ({platform})")


def list_target_alerts(state: dict):
    alerts = state.get("target_alerts", [])
    if not alerts:
        print("No target alerts.")
        return
    for a in alerts:
        status = "EVALUATED" if a.get("evaluated") else "PENDING"
        print(f"[{status}] {a['program']} ({a['platform']}) — {a['url']} — {a['detected_at'][:10]}")


def save_draft_entry(state: dict, target: str, finding: str, subject: str,
                     body_file: str, gmail_draft_id: str = ""):
    body = Path(body_file).read_text() if Path(body_file).exists() else body_file
    entry = {
        "target": target,
        "finding": finding,
        "subject": subject,
        "body_preview": body[:200],
        "body_file": body_file,
        "created_at": datetime.now().isoformat(),
        "sent": False,
    }
    if gmail_draft_id:
        entry["gmail_draft_id"] = gmail_draft_id
    state["response_drafts"].append(entry)
    state["stats"]["drafts_created"] += 1
    save_state(state)
    if gmail_draft_id:
        print(f"Draft saved: {subject} [Gmail Draft ID: {gmail_draft_id}]")
    else:
        print(f"Draft saved: {subject}")


def list_drafts(state: dict):
    drafts = state.get("response_drafts", [])
    if not drafts:
        print("No pending drafts.")
        return
    for d in drafts:
        status = "SENT" if d.get("sent") else "PENDING"
        gmail = f" [Gmail: {d['gmail_draft_id']}]" if d.get("gmail_draft_id") else ""
        print(f"[{status}] {d['target']}/{d['finding']} — {d['subject']} — {d['created_at'][:10]}{gmail}")


# --- Bounty Payment Tracking (Feature #4) ---

def add_payment(state: dict, target: str, finding: str, amount: str,
                currency: str, platform: str):
    key = f"{target}/{finding}"
    amount_val = float(amount)
    state["bounty_payments"][key] = {
        "target": target,
        "finding": finding,
        "amount": amount_val,
        "currency": currency,
        "platform": platform,
        "detected_at": datetime.now().isoformat(),
    }
    state["stats"]["payments_tracked"] += 1
    # Rough USD conversion for stats
    usd_amount = amount_val  # assume USD if USD/USDC/USDT
    if currency.upper() in ("EUR",):
        usd_amount = amount_val * 1.1
    elif currency.upper() in ("ETH",):
        usd_amount = amount_val * 2000  # rough estimate
    state["stats"]["total_revenue_usd"] += usd_amount

    # Also update report status to paid
    if key in state.get("report_statuses", {}):
        state["report_statuses"][key]["status"] = "paid"
        state["report_statuses"][key]["previous_status"] = state["report_statuses"][key].get("status", "unknown")
        state["report_statuses"][key]["updated_at"] = datetime.now().isoformat()
        state["report_statuses"][key]["details"] = f"Bounty: {amount} {currency} via {platform}"

    save_state(state)
    print(f"Payment: {key} → {amount} {currency} ({platform})")


def payment_summary(state: dict):
    payments = state.get("bounty_payments", {})
    if not payments:
        print("No bounty payments tracked yet.")
        return

    # By platform
    by_platform = {}
    by_month = {}
    total = 0
    for key, info in payments.items():
        p = info["platform"]
        amt = info["amount"]
        cur = info["currency"]
        detected = info.get("detected_at", "")[:7]  # YYYY-MM

        by_platform.setdefault(p, {"count": 0, "total": 0, "currency": cur})
        by_platform[p]["count"] += 1
        by_platform[p]["total"] += amt

        by_month.setdefault(detected, {"count": 0, "total": 0})
        by_month[detected]["count"] += 1
        by_month[detected]["total"] += amt

        total += amt

    print("=== Bounty Payment Summary ===\n")

    print("By Platform:")
    print(f"  {'Platform':<20} {'Count':<8} {'Total':<15}")
    print(f"  {'-'*43}")
    for p, info in sorted(by_platform.items(), key=lambda x: x[1]["total"], reverse=True):
        print(f"  {p:<20} {info['count']:<8} {info['total']:,.2f} {info['currency']}")

    print(f"\nBy Month:")
    print(f"  {'Month':<12} {'Count':<8} {'Total':<15}")
    print(f"  {'-'*35}")
    for m, info in sorted(by_month.items()):
        print(f"  {m:<12} {info['count']:<8} {info['total']:,.2f}")

    print(f"\nTotal: {total:,.2f}")
    print(f"Estimated USD: {state['stats'].get('total_revenue_usd', 0):,.2f}")


# --- Label/Filter Management ---

def print_setup_labels_instructions():
    """Print the label names that need to be created via MCP."""
    print("=== Gmail Labels to Create ===")
    print("Run these mcp__gmail__get_or_create_label calls and save returned IDs:\n")
    for label_name in LABEL_HIERARCHY:
        print(f"  mcp__gmail__get_or_create_label(name=\"{label_name}\")")
    print(f"\nTotal: {len(LABEL_HIERARCHY)} labels")
    print(f"Save IDs to: {LABEL_IDS_FILE}")
    print("\nAfter creating, run: python3 tools/gmail_monitor.py save-label-id <name> <id>")


def save_label_id(name: str, label_id: str):
    ids = load_label_ids()
    ids[name] = label_id
    save_label_ids(ids)
    print(f"Saved: {name} = {label_id}")


def show_label_ids():
    ids = load_label_ids()
    if not ids:
        print("No label IDs stored. Run setup-labels first.")
        return
    print(f"{'Label Name':<50} {'ID'}")
    print("-" * 70)
    for name, lid in sorted(ids.items()):
        print(f"{name:<50} {lid}")


def print_setup_filters_instructions():
    """Print the filter definitions that need to be created via MCP."""
    ids = load_label_ids()
    print("=== Gmail Filters to Create ===\n")
    for filt in FILTER_DEFINITIONS:
        label = filt["label"]
        label_id = ids.get(label, "<RUN setup-labels FIRST>")
        criteria_str = json.dumps(filt["criteria"])
        print(f"  [{filt['name']}]")
        print(f"    Criteria: {criteria_str}")
        print(f"    Action: addLabelIds=[{label_id}]  ({label})")
        print()
    print(f"Total: {len(FILTER_DEFINITIONS)} filters")
    print(f"Save IDs to: {FILTER_IDS_FILE}")


def save_filter_id(name: str, filter_id: str):
    ids = load_filter_ids()
    ids[name] = filter_id
    save_filter_ids(ids)
    print(f"Saved filter: {name} = {filter_id}")


def show_filter_ids():
    ids = load_filter_ids()
    if not ids:
        print("No filter IDs stored. Run setup-filters first.")
        return
    print(f"{'Filter Name':<30} {'ID'}")
    print("-" * 50)
    for name, fid in sorted(ids.items()):
        print(f"{name:<30} {fid}")


# --- Status & Queries ---

def show_status(state: dict):
    print("=== Gmail Monitor Status ===")
    print(f"Emails processed: {state['stats']['total_processed']}")
    print(f"Platform alerts:  {state['stats']['platform_alerts']}")
    print(f"CVE updates:      {state['stats']['cve_updates']}")
    print(f"Status changes:   {state['stats']['status_changes']}")
    print(f"New targets:      {state['stats']['new_targets']}")
    print(f"Drafts created:   {state['stats']['drafts_created']}")
    print(f"Payments tracked: {state['stats'].get('payments_tracked', 0)}")
    print(f"Mail events sync: {state['stats'].get('mail_events_synced', 0)}")
    print(f"Total revenue:    ${state['stats'].get('total_revenue_usd', 0):,.2f}")
    print()
    print(f"Tracked reports:  {len(state.get('report_statuses', {}))}")
    print(f"Tracked CVEs:     {len(state.get('cve_tracking', {}))}")
    print(f"Target alerts:    {len(state.get('target_alerts', []))}")
    print(f"Pending drafts:   {len([d for d in state.get('response_drafts', []) if not d.get('sent')])}")
    print(f"Bounty payments:  {len(state.get('bounty_payments', {}))}")
    print(f"Mail events:      {len(state.get('mail_events', {}))}")
    print()

    # Label/filter setup status
    label_count = len(load_label_ids())
    filter_count = len(load_filter_ids())
    print(f"Gmail labels:     {label_count}/{len(LABEL_HIERARCHY)} configured")
    print(f"Gmail filters:    {filter_count}/{len(FILTER_DEFINITIONS)} configured")
    print()

    for check_name, ts in state.get("last_check", {}).items():
        print(f"Last {check_name}: {ts}")


def update_last_check(state: dict, check_name: str):
    state["last_check"][check_name] = datetime.now().isoformat()
    save_state(state)


SEARCH_QUERIES = {
    "platform_alerts": (
        "from:bugcrowd.com OR from:immunefi.com OR from:hackenproof.com "
        "OR from:yeswehack.com OR from:intigriti.com OR from:hackerone.com"
    ),
    "cve_responses": "from:mitre.org subject:CVE",
    "submission_confirm": (
        "(from:bugcrowd.com OR from:immunefi.com OR from:hackenproof.com "
        "OR from:yeswehack.com OR from:intigriti.com) "
        "subject:(submission OR received OR confirmed OR thank)"
    ),
    "report_status": (
        "(from:bugcrowd.com OR from:immunefi.com OR from:hackenproof.com "
        "OR from:yeswehack.com OR from:intigriti.com) "
        "subject:(triaged OR resolved OR duplicate OR informative OR closed OR accepted OR bounty OR reward)"
    ),
    "triager_questions": (
        "(from:bugcrowd.com OR from:immunefi.com OR from:hackenproof.com "
        "OR from:yeswehack.com OR from:intigriti.com) "
        "subject:(question OR clarification OR additional OR more information OR update)"
    ),
    "new_programs": (
        "(from:bugcrowd.com OR from:immunefi.com OR from:hackenproof.com "
        "OR from:yeswehack.com OR from:intigriti.com) "
        "subject:(new program OR launched OR invitation OR invited OR private)"
    ),
    "bounty_payments": (
        "(from:bugcrowd.com OR from:immunefi.com OR from:hackenproof.com "
        "OR from:yeswehack.com OR from:intigriti.com) "
        "subject:(bounty OR reward OR payment OR payout OR paid)"
    ),
}


def show_queries():
    for name, query in SEARCH_QUERIES.items():
        print(f"\n[{name}]")
        print(f"  {query}")


# --- CLI ---

def parse_flag(args: list, flag: str) -> str:
    """Extract --flag=value from args, return value or empty string."""
    for a in args:
        if a.startswith(f"--{flag}="):
            return a.split("=", 1)[1]
    return ""


def has_flag(args: list, flag: str) -> bool:
    return any(a == f"--{flag}" for a in args)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    state = load_state()
    cmd = sys.argv[1]

    if cmd == "status":
        show_status(state)
    elif cmd == "mark-seen":
        category = sys.argv[3] if len(sys.argv) > 3 else "general"
        mark_seen(state, sys.argv[2], category)
    elif cmd == "is-seen":
        is_seen(state, sys.argv[2])
    elif cmd == "update-report":
        details = sys.argv[5] if len(sys.argv) > 5 and not sys.argv[5].startswith("--") else ""
        email_id = parse_flag(sys.argv, "email-id")
        update_report(state, sys.argv[2], sys.argv[3], sys.argv[4], details, email_id)
    elif cmd == "list-reports":
        list_reports(state)
    elif cmd == "pending-confirmations":
        pending_confirmations(state)
    elif cmd == "add-cve":
        details = sys.argv[4] if len(sys.argv) > 4 else ""
        add_cve(state, sys.argv[2], sys.argv[3], details)
    elif cmd == "list-cves":
        list_cves(state)
    elif cmd == "add-target-alert":
        add_target_alert(state, sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "list-target-alerts":
        list_target_alerts(state)
    elif cmd == "save-draft":
        gmail_draft_id = parse_flag(sys.argv, "gmail-draft-id")
        save_draft_entry(state, sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], gmail_draft_id)
    elif cmd == "list-drafts":
        list_drafts(state)
    elif cmd == "add-payment":
        add_payment(state, sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
    elif cmd == "payment-summary":
        payment_summary(state)
    elif cmd == "setup-labels":
        print_setup_labels_instructions()
    elif cmd == "save-label-id":
        save_label_id(sys.argv[2], sys.argv[3])
    elif cmd == "label-ids":
        show_label_ids()
    elif cmd == "setup-filters":
        print_setup_filters_instructions()
    elif cmd == "save-filter-id":
        save_filter_id(sys.argv[2], sys.argv[3])
    elif cmd == "filter-ids":
        show_filter_ids()
    elif cmd == "queries":
        show_queries()
    elif cmd == "update-check":
        update_last_check(state, sys.argv[2])
    elif cmd == "sync-search":
        payload = _read_json_payload(sys.argv[2])
        work_state = copy.deepcopy(state) if has_flag(sys.argv, "dry-run") else state
        summary = sync_search_results(
            work_state,
            payload,
            mark_seen_flag=not has_flag(sys.argv, "no-mark-seen"),
            force=has_flag(sys.argv, "force"),
        )
        if has_flag(sys.argv, "refresh-ops-wiki"):
            summary["ops_wiki"] = (
                {"action": "skipped", "reason": "dry_run"}
                if has_flag(sys.argv, "dry-run")
                else refresh_ops_wiki()
            )
        print(json.dumps(summary, indent=2))
        if not has_flag(sys.argv, "dry-run"):
            save_state(work_state)
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)


if __name__ == "__main__":
    main()
