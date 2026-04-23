#!/usr/bin/env python3
"""Build a small compiled operations wiki from canonical submission trackers.

The ops wiki is intentionally narrow:
- Canonical status comes from `docs/submissions.json`
- Human-only operational context comes from `coordination/SUBMISSIONS.md`
- Optional local Gmail enrichment comes from `.gmail_monitor_state.json`

Default output is local/regeneratable: `coordination/cache/ops_wiki/`
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SUBMISSIONS_JSON = PROJECT_ROOT / "docs" / "submissions.json"
DEFAULT_TRACKER_MD = PROJECT_ROOT / "coordination" / "SUBMISSIONS.md"
DEFAULT_GMAIL_STATE = PROJECT_ROOT / ".gmail_monitor_state.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "coordination" / "cache" / "ops_wiki"

ACTIVE_STATUSES = {"pending", "triage", "under review", "accepted", "hold", "ready-to-submit"}
RESOLVED_STATUSES = {
    "won't fix",
    "oos",
    "not applicable",
    "n/r",
    "not reproducible",
    "closed",
    "duplicate",
    "paid",
}


@dataclass
class SubmissionEntry:
    platform: str
    target: str
    title: str
    severity: str
    bounty: str
    status: str
    submitted: str
    note: str
    last_check: str = ""
    resolved: str = ""
    memory_lesson: str = ""
    source_refs: list[str] = field(default_factory=list)
    gmail_matches: dict = field(default_factory=dict)
    followup_priority: str = "none"
    followup_reason: str = ""
    followup_action: str = ""

    @property
    def slug(self) -> str:
        return slugify(f"{self.platform}-{self.target}-{identifier_or_title(self.title)}")

    @property
    def platform_slug(self) -> str:
        return slugify(self.platform)


@dataclass
class AppealEntry:
    case: str
    platform: str
    route: str
    status: str
    next_action: str


@dataclass
class TrackerContext:
    last_updated: str = ""
    active_rows: dict[str, dict] = field(default_factory=dict)
    resolved_rows: dict[str, dict] = field(default_factory=dict)
    appeals: list[AppealEntry] = field(default_factory=list)
    platform_notes: list[str] = field(default_factory=list)


def slugify(value: str) -> str:
    lowered = value.lower()
    lowered = re.sub(r"[`*_#]", "", lowered)
    lowered = re.sub(r"[^a-z0-9]+", "-", lowered)
    return re.sub(r"-{2,}", "-", lowered).strip("-")


def strip_md(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[*_`]", "", value)).strip()


def normalize_status(value: str) -> str:
    return strip_md(value)


def parse_iso_date(value: str) -> date | None:
    value = strip_md(value)
    if not value or value == "—":
        return None
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def title_key(value: str) -> str:
    return re.sub(r"\s+", " ", strip_md(value)).lower()


def extract_identifier(value: str) -> str:
    patterns = [
        r"(GHSA-[\w-]+)",
        r"(YWH-[A-Z0-9-]+)",
        r"(HRSGROUP-[A-Z0-9]+)",
        r"(PORTOFANTWERP-[A-Z0-9]+)",
        r"(#\d{1,}-\d{2,})",
        r"(#\d{4,})",
        r"\b([a-f0-9]{8})\b",
        r"\b([A-Z]{2,}-\d{2,}[A-Z0-9-]*)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, value, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def identifier_or_title(title: str) -> str:
    return extract_identifier(title) or title


def submission_identity(platform: str, target: str, title: str) -> str:
    ident = extract_identifier(title)
    key_tail = ident.lower() if ident else title_key(title)
    return f"{platform.strip().lower()}|{target.strip().lower()}|{key_tail}"


def split_sections(markdown: str) -> dict[str, str]:
    matches = list(re.finditer(r"^##\s+(.+?)\s*$", markdown, re.MULTILINE))
    sections: dict[str, str] = {}
    for idx, match in enumerate(matches):
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(markdown)
        sections[match.group(1).strip()] = markdown[start:end].strip()
    return sections


def parse_first_table(section_text: str) -> list[dict[str, str]]:
    lines = [line.rstrip() for line in section_text.splitlines()]
    table_lines: list[str] = []
    started = False
    for line in lines:
        if line.strip().startswith("|"):
            started = True
            table_lines.append(line.strip())
            continue
        if started:
            break
    if len(table_lines) < 2:
        return []

    headers = [strip_md(cell) for cell in table_lines[0].strip("|").split("|")]
    rows: list[dict[str, str]] = []
    for line in table_lines[2:]:
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != len(headers):
            continue
        rows.append(dict(zip(headers, cells)))
    return rows


def load_submissions(path: Path) -> list[SubmissionEntry]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = []
    for item in payload.get("submissions", []):
        entries.append(
            SubmissionEntry(
                platform=item.get("platform", "—"),
                target=item.get("target", "—"),
                title=item.get("title", "—"),
                severity=item.get("severity", "—"),
                bounty=item.get("bounty", "—"),
                status=normalize_status(item.get("status", "—")),
                submitted=item.get("submitted", "—"),
                note=item.get("note", ""),
                source_refs=["docs/submissions.json"],
            )
        )
    return entries


def load_tracker_context(path: Path) -> TrackerContext:
    text = path.read_text(encoding="utf-8")
    sections = split_sections(text)
    ctx = TrackerContext(source_last_updated(text))

    for row in parse_first_table(sections.get("Active (Pending / Triage)", "")):
        identity = submission_identity(row.get("Platform", ""), row.get("Target", ""), row.get("Title", ""))
        ctx.active_rows[identity] = row

    for row in parse_first_table(sections.get("Resolved (Accepted / Rejected / Closed)", "")):
        identity = submission_identity(row.get("Platform", ""), row.get("Target", ""), row.get("Title", ""))
        ctx.resolved_rows[identity] = row

    for row in parse_first_table(sections.get("Appeals / Escalations In Flight", "")):
        ctx.appeals.append(
            AppealEntry(
                case=row.get("Case", ""),
                platform=row.get("Platform", ""),
                route=row.get("Route", ""),
                status=row.get("Status", ""),
                next_action=row.get("Next Action", ""),
            )
        )

    platform_notes = []
    for line in sections.get("Platform-level Notes", "").splitlines():
        stripped = line.strip()
        if stripped.startswith("- "):
            platform_notes.append(stripped[2:].strip())
    ctx.platform_notes = platform_notes
    return ctx


def source_last_updated(markdown: str) -> str:
    match = re.search(r"\*\*Last updated\*\*:\s*(.+)", markdown)
    return strip_md(match.group(1)) if match else ""


def load_gmail_state(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def attach_tracker_context(submissions: list[SubmissionEntry], tracker: TrackerContext) -> None:
    for entry in submissions:
        identity = submission_identity(entry.platform, entry.target, entry.title)
        if identity in tracker.active_rows:
            row = tracker.active_rows[identity]
            entry.last_check = row.get("Last Check", "")
            if row.get("Note") and row.get("Note") != entry.note:
                entry.note = f"{entry.note} | {row.get('Note')}".strip(" |")
            entry.source_refs.append("coordination/SUBMISSIONS.md#active")
        elif identity in tracker.resolved_rows:
            row = tracker.resolved_rows[identity]
            entry.resolved = row.get("Resolved", "")
            entry.memory_lesson = row.get("Memory Lesson", "")
            if row.get("Status") and normalize_status(row["Status"]) != entry.status:
                entry.note = f"{entry.note} | tracker_status={row['Status']}".strip(" |")
            entry.source_refs.append("coordination/SUBMISSIONS.md#resolved")


def attach_gmail_context(submissions: list[SubmissionEntry], gmail_state: dict) -> None:
    if not gmail_state:
        return

    reports = gmail_state.get("report_statuses", {})
    drafts = gmail_state.get("response_drafts", [])
    payments = gmail_state.get("bounty_payments", {})

    for entry in submissions:
        key_target = slugify(entry.target)
        key_ident = slugify(extract_identifier(entry.title) or entry.title)
        matches: dict[str, object] = {}

        for key, info in reports.items():
            normalized_key = slugify(key)
            if key_target and key_target in normalized_key:
                if (key_ident and key_ident in normalized_key) or key_ident == slugify(info.get("finding", "")):
                    matches["report_status"] = info
                    break

        draft_matches = []
        for draft in drafts:
            if slugify(draft.get("target", "")) == key_target:
                draft_finding = slugify(draft.get("finding", ""))
                if not key_ident or key_ident == draft_finding:
                    draft_matches.append(draft)
        if draft_matches:
            matches["drafts"] = draft_matches

        for key, info in payments.items():
            normalized_key = slugify(key)
            if key_target and key_target in normalized_key:
                if (key_ident and key_ident in normalized_key) or key_ident == slugify(info.get("finding", "")):
                    matches["payment"] = info
                    break

        entry.gmail_matches = matches


def derive_followups(submissions: list[SubmissionEntry], tracker: TrackerContext, today: date) -> None:
    appeal_targets = " ".join(appeal.case.lower() for appeal in tracker.appeals)
    for entry in submissions:
        status = entry.status.lower()
        age_anchor = parse_iso_date(entry.last_check) or parse_iso_date(entry.submitted)
        age_days = (today - age_anchor).days if age_anchor else None
        note_lower = entry.note.lower()
        title_identifier = extract_identifier(entry.title).lower()

        if status == "accepted" and ("awaiting" in entry.bounty.lower() or "미확정" in note_lower or entry.bounty == "—"):
            entry.followup_priority = "medium"
            entry.followup_reason = "accepted but payout not confirmed"
            entry.followup_action = "Check payout timeline or send a payout follow-up."
        elif status in {"pending", "triage", "under review"}:
            if age_days is not None and age_days >= 10:
                entry.followup_priority = "high"
                entry.followup_reason = f"{entry.status} with no fresh check for {age_days} days"
                entry.followup_action = "Re-check platform state and prepare a polite status nudge if allowed."
            elif age_days is not None and age_days >= 5:
                entry.followup_priority = "medium"
                entry.followup_reason = f"{entry.status} aging for {age_days} days"
                entry.followup_action = "Monitor closely and re-check before sending anything."
        elif status == "hold":
            entry.followup_priority = "blocked"
            entry.followup_reason = "submission blocked by external platform requirement"
            entry.followup_action = "Resolve the platform block before attempting submission."

        if entry.target.lower() in appeal_targets or (title_identifier and title_identifier in appeal_targets):
            entry.followup_priority = "high"
            entry.followup_reason = "appeal or escalation in flight"
            entry.followup_action = "Keep the appeal case synced with the latest evidence and mailbox state."


def render_index(submissions: list[SubmissionEntry], tracker: TrackerContext, out_dir: Path) -> None:
    active = [s for s in submissions if s.status.lower() in ACTIVE_STATUSES]
    resolved = [s for s in submissions if s.status.lower() in RESOLVED_STATUSES]
    platforms = sorted({s.platform for s in submissions}, key=str.lower)

    lines = [
        "# Operations Wiki",
        "",
        f"- Generated: {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"- Tracker last updated: {tracker.last_updated or 'unknown'}",
        "- Canonical sources: `docs/submissions.json`, `coordination/SUBMISSIONS.md`",
        "- Optional enrichment: `.gmail_monitor_state.json`",
        "",
        "## Summary",
        "",
        f"- Active submissions: {len(active)}",
        f"- Resolved submissions: {len(resolved)}",
        f"- Appeals in flight: {len(tracker.appeals)}",
        f"- Platforms tracked: {len(platforms)}",
        "",
        "## Quick Links",
        "",
        "- [Follow-ups](followups.md)",
        "- [Appeals](appeals.md)",
        "",
        "## Platforms",
        "",
    ]
    for platform in platforms:
        slug = slugify(platform)
        count = len([s for s in submissions if s.platform == platform])
        active_count = len([s for s in active if s.platform == platform])
        lines.append(f"- [{platform}](platforms/{slug}.md) — {count} submissions ({active_count} active)")

    write_text(out_dir / "index.md", "\n".join(lines) + "\n")


def render_appeals(tracker: TrackerContext, out_dir: Path) -> None:
    lines = [
        "# Appeals And Escalations",
        "",
        f"- Canonical source: `{DEFAULT_TRACKER_MD.relative_to(PROJECT_ROOT)}`",
        "",
    ]
    if not tracker.appeals:
        lines.append("No active appeals or escalations tracked.")
    else:
        for appeal in tracker.appeals:
            lines.extend(
                [
                    f"## {appeal.case}",
                    "",
                    f"- Platform: {appeal.platform}",
                    f"- Route: {appeal.route}",
                    f"- Status: {appeal.status}",
                    f"- Next Action: {appeal.next_action}",
                    "",
                ]
            )
    write_text(out_dir / "appeals.md", "\n".join(lines) + "\n")


def render_followups(submissions: list[SubmissionEntry], tracker: TrackerContext, out_dir: Path) -> None:
    buckets = {
        "high": [],
        "medium": [],
        "blocked": [],
        "none": [],
    }
    for entry in submissions:
        buckets.setdefault(entry.followup_priority, []).append(entry)

    lines = [
        "# Follow-Up Queue",
        "",
        "Heuristics are deterministic and derived from canonical tracker state.",
        "",
    ]
    section_order = [
        ("high", "Urgent"),
        ("medium", "Monitor Soon"),
        ("blocked", "Blocked / External"),
        ("none", "No Immediate Action"),
    ]
    for key, title in section_order:
        lines.extend([f"## {title}", ""])
        if not buckets.get(key):
            lines.append("- None")
            lines.append("")
            continue
        for entry in sorted(buckets[key], key=lambda item: (item.platform.lower(), item.target.lower(), item.title.lower())):
            lines.append(
                f"- [{entry.title}](submissions/{entry.slug}.md) — "
                f"{entry.platform} / {entry.target} / {entry.status} — "
                f"{entry.followup_reason or 'no action required'}"
            )
        lines.append("")

    if tracker.appeals:
        lines.extend(["## Appeals In Flight", ""])
        for appeal in tracker.appeals:
            lines.append(f"- {appeal.case} — {appeal.status} — {appeal.next_action}")
        lines.append("")

    write_text(out_dir / "followups.md", "\n".join(lines) + "\n")


def render_platform_pages(submissions: list[SubmissionEntry], tracker: TrackerContext, out_dir: Path) -> None:
    platform_dir = out_dir / "platforms"
    platform_dir.mkdir(parents=True, exist_ok=True)
    notes_by_platform = {}
    for note in tracker.platform_notes:
        match = re.match(r"\*\*(.+?)\*\*:\s*(.+)", note)
        if match:
            notes_by_platform.setdefault(match.group(1), []).append(match.group(2))

    for platform in sorted({s.platform for s in submissions}, key=str.lower):
        active = [s for s in submissions if s.platform == platform and s.status.lower() in ACTIVE_STATUSES]
        resolved = [s for s in submissions if s.platform == platform and s.status.lower() in RESOLVED_STATUSES]
        lines = [
            f"# Platform: {platform}",
            "",
            f"- Active: {len(active)}",
            f"- Resolved: {len(resolved)}",
            "",
            "## Active",
            "",
        ]
        if active:
            for entry in active:
                lines.append(
                    f"- [{entry.title}](../submissions/{entry.slug}.md) — "
                    f"{entry.status} — {entry.followup_reason or entry.note}"
                )
        else:
            lines.append("- None")
        lines.extend(["", "## Resolved", ""])
        if resolved:
            for entry in resolved:
                lesson = entry.memory_lesson or entry.note
                lines.append(f"- [{entry.title}](../submissions/{entry.slug}.md) — {entry.status} — {lesson}")
        else:
            lines.append("- None")

        platform_notes = notes_by_platform.get(platform, [])
        if platform_notes:
            lines.extend(["", "## Platform Notes", ""])
            for note in platform_notes:
                lines.append(f"- {note}")
        write_text(platform_dir / f"{slugify(platform)}.md", "\n".join(lines) + "\n")


def render_submission_pages(submissions: list[SubmissionEntry], out_dir: Path) -> None:
    sub_dir = out_dir / "submissions"
    sub_dir.mkdir(parents=True, exist_ok=True)
    for entry in submissions:
        lines = [
            f"# {entry.title}",
            "",
            f"- Platform: {entry.platform}",
            f"- Target: {entry.target}",
            f"- Severity: {entry.severity}",
            f"- Bounty: {entry.bounty}",
            f"- Status: {entry.status}",
            f"- Submitted: {entry.submitted}",
            f"- Last Check: {entry.last_check or '—'}",
            f"- Resolved: {entry.resolved or '—'}",
            "",
            "## Canonical Note",
            "",
            entry.note or "—",
            "",
            "## Derived Operations View",
            "",
            f"- Follow-up Priority: {entry.followup_priority}",
            f"- Follow-up Reason: {entry.followup_reason or '—'}",
            f"- Recommended Action: {entry.followup_action or '—'}",
            "",
            "## Source References",
            "",
        ]
        for source in entry.source_refs:
            lines.append(f"- `{source}`")

        if entry.memory_lesson:
            lines.extend(["", "## Memory Lesson", "", entry.memory_lesson])

        if entry.gmail_matches:
            lines.extend(["", "## Gmail Monitor Enrichment", ""])
            report_status = entry.gmail_matches.get("report_status")
            if report_status:
                lines.append(
                    f"- Email-derived report status: {report_status.get('status', '—')} "
                    f"(updated {report_status.get('updated_at', '—')})"
                )
            for draft in entry.gmail_matches.get("drafts", []):
                lines.append(
                    f"- Draft: {draft.get('subject', '—')} "
                    f"(created {draft.get('created_at', '—')}, sent={draft.get('sent', False)})"
                )
            payment = entry.gmail_matches.get("payment")
            if payment:
                lines.append(
                    f"- Payment tracked: {payment.get('amount', '—')} {payment.get('currency', '')} "
                    f"via {payment.get('platform', '—')}"
                )

        write_text(sub_dir / f"{entry.slug}.md", "\n".join(lines) + "\n")


def render_manifest(submissions: list[SubmissionEntry], tracker: TrackerContext, out_dir: Path) -> None:
    manifest = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "submission_count": len(submissions),
        "appeal_count": len(tracker.appeals),
        "platform_count": len({s.platform for s in submissions}),
        "sources": {
            "submissions_json": str(DEFAULT_SUBMISSIONS_JSON.relative_to(PROJECT_ROOT)),
            "tracker_md": str(DEFAULT_TRACKER_MD.relative_to(PROJECT_ROOT)),
            "gmail_state": str(DEFAULT_GMAIL_STATE.relative_to(PROJECT_ROOT)),
        },
    }
    write_text(out_dir / "manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def build_ops_wiki(
    submissions_json: Path,
    tracker_md: Path,
    gmail_state_path: Path | None,
    out_dir: Path,
    today: date | None = None,
) -> None:
    today = today or date.today()
    submissions = load_submissions(submissions_json)
    tracker = load_tracker_context(tracker_md)
    gmail_state = load_gmail_state(gmail_state_path) if gmail_state_path else {}

    attach_tracker_context(submissions, tracker)
    attach_gmail_context(submissions, gmail_state)
    derive_followups(submissions, tracker, today)

    out_dir.mkdir(parents=True, exist_ok=True)
    render_index(submissions, tracker, out_dir)
    render_appeals(tracker, out_dir)
    render_followups(submissions, tracker, out_dir)
    render_platform_pages(submissions, tracker, out_dir)
    render_submission_pages(submissions, out_dir)
    render_manifest(submissions, tracker, out_dir)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="Build compiled ops wiki pages.")
    build.add_argument("--submissions-json", default=str(DEFAULT_SUBMISSIONS_JSON))
    build.add_argument("--tracker-md", default=str(DEFAULT_TRACKER_MD))
    build.add_argument("--gmail-state", default=str(DEFAULT_GMAIL_STATE))
    build.add_argument("--out", default=str(DEFAULT_OUTPUT_DIR))
    build.add_argument("--today", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "build":
        today = parse_iso_date(args.today) if args.today else None
        build_ops_wiki(
            submissions_json=Path(args.submissions_json),
            tracker_md=Path(args.tracker_md),
            gmail_state_path=Path(args.gmail_state) if args.gmail_state else None,
            out_dir=Path(args.out),
            today=today,
        )
        print(f"Ops wiki built at {args.out}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
