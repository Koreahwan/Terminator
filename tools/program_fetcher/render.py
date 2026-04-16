"""Render a ProgramData into bb_preflight's program_rules_summary.md format.

The template lives at tools/templates/program_rules_summary.md and contains
`<REQUIRED: ...>` placeholders. This renderer replaces ONLY the verbatim
sections — scope, OOS, known issues, submission rules, severity — because
those are the fields the platform page is authoritative for.

Operational sections (Auth Header Format, Mandatory Headers, Verified Curl
Template) are NOT touched. Those require live API traffic verification which
the program fetcher cannot do — scout/web-tester still fill those in from
Frida/mitmproxy/curl.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .base import FetchResult, ProgramData


# Section headings (as they appear in the template) that the fetcher
# auto-fills. These are the VERBATIM sections. Everything else stays as
# <REQUIRED: ...> for the agent to fill from live traffic.
VERBATIM_SECTIONS = {
    "In-Scope Assets": "scope_in",
    "Out-of-Scope / Exclusion List": "scope_out",
    "Known Issues": "known_issues",
    "Submission Rules": "submission_rules",
    "Severity Scope": "severity_table",
    "Asset Scope Constraints": "asset_scope_constraints",
}

# Sections intentionally left alone — operational, need live verification.
OPERATIONAL_SECTIONS = {
    "Auth Header Format",
    "Mandatory Headers",
    "Verified Curl Template",
    "Already Submitted Reports",
    "Platform",
}


def _format_scope_in(pd: ProgramData) -> str:
    if not pd.scope_in:
        return "<REQUIRED: 프로그램 페이지의 in-scope 자산 목록을 한 글자도 빠짐없이 복사>"
    lines: list[str] = []
    for asset in pd.scope_in:
        line = f"- `{asset.identifier}`"
        if asset.type and asset.type != "other":
            line += f" ({asset.type})"
        if asset.qualifier:
            line += f" — {asset.qualifier}"
        lines.append(line)
        for v in asset.in_scope_versions:
            lines.append(f"    - version: `{v}`")
    return "\n".join(lines)


def _format_scope_out(pd: ProgramData) -> str:
    if not pd.scope_out:
        return "<REQUIRED: 프로그램 페이지의 out-of-scope 및 exclusion 전체 목록을 한 글자도 빠짐없이 복사>"
    return "\n".join(f"- {item}" for item in pd.scope_out)


def _format_known_issues(pd: ProgramData) -> str:
    if not pd.known_issues:
        return "- None documented (verify by reading the program's Known Issues section on the live page)"
    return "\n".join(f"- {item}" for item in pd.known_issues)


def _format_submission_rules(pd: ProgramData) -> str:
    if not pd.submission_rules.strip():
        return "<REQUIRED: 제출 규칙 전문을 원본 그대로 복사>"
    return pd.submission_rules.strip()


def _format_severity_table(pd: ProgramData) -> str:
    if pd.severity_table:
        lines = ["| Severity | Asset class | Reward | Notes |",
                 "|---|---|---|---|"]
        for row in pd.severity_table:
            lines.append(
                f"| {row.severity or '-'} | {row.asset_class or '-'} "
                f"| {row.reward or '-'} | {row.notes or '-'} |"
            )
        return "\n".join(lines)
    if pd.bounty_range:
        parts = []
        mn = pd.bounty_range.get("min")
        mx = pd.bounty_range.get("max")
        cur = pd.bounty_range.get("currency", "")
        note = pd.bounty_range.get("note", "")
        if mn or mx:
            parts.append(f"- Range: {mn or '?'} – {mx or '?'} {cur}".strip())
        if note:
            parts.append(f"- Note: {note}")
        return "\n".join(parts) if parts else "<REQUIRED: severity/bounty 테이블 전체를 원문 그대로 복사>"
    return "<REQUIRED: severity/bounty 테이블 전체를 원문 그대로 복사>"


def _format_asset_scope_constraints(pd: ProgramData) -> str:
    """Best-effort: extract branch/tag/version hints from scope_in assets."""
    lines: list[str] = []
    for asset in pd.scope_in:
        if asset.in_scope_versions:
            lines.append(
                f"- `{asset.identifier}`: {', '.join(asset.in_scope_versions)}"
            )
    if not lines:
        return ("<REQUIRED: version/branch/tag/environment 제약사항 원문 그대로 복사>\n"
                "- NOTE: Fetcher did not detect explicit version constraints. "
                "Verify against the live program page.")
    return "\n".join(lines)


_FORMATTERS = {
    "In-Scope Assets": _format_scope_in,
    "Out-of-Scope / Exclusion List": _format_scope_out,
    "Known Issues": _format_known_issues,
    "Submission Rules": _format_submission_rules,
    "Severity Scope": _format_severity_table,
    "Asset Scope Constraints": _format_asset_scope_constraints,
}


def to_rules_summary_md(pd: ProgramData, existing_template: str = "") -> str:
    """Produce a filled-in program_rules_summary.md.

    If `existing_template` is provided (e.g., from `bb_preflight.py init`),
    we REPLACE the body of each VERBATIM section in place and leave the rest
    (including operational sections and their `<REQUIRED: ...>` placeholders)
    untouched. If no template, we build one from the default layout.
    """
    if existing_template:
        return _patch_template(existing_template, pd)
    return _build_fresh(pd)


def _patch_template(template: str, pd: ProgramData) -> str:
    """Replace each VERBATIM section body in `template`."""
    out = template
    for heading, _attr in VERBATIM_SECTIONS.items():
        formatter = _FORMATTERS[heading]
        new_body = formatter(pd)
        # Match: `## <heading>[ verbatim qualifier](...)\n<body until next ##>`
        pattern = re.compile(
            rf"(##\s*{re.escape(heading)}[^\n]*\n)(.*?)(?=\n##|\Z)",
            re.DOTALL,
        )

        def _repl(m: re.Match, body=new_body) -> str:
            return f"{m.group(1)}{body}\n"

        out, n = pattern.subn(_repl, out, count=1)
        if n == 0:
            # Heading missing from template — append it at the end.
            out += f"\n## {heading}\n{new_body}\n"

    # Prepend a provenance header so the operator knows this was auto-filled.
    banner = _banner(pd)
    if "<!-- program_fetcher:" not in out:
        out = banner + "\n" + out
    else:
        out = re.sub(
            r"<!--\s*program_fetcher:.*?-->\n?",
            banner + "\n",
            out,
            count=1,
            flags=re.DOTALL,
        )
    return out


def _build_fresh(pd: ProgramData) -> str:
    """Construct a new rules file when no template is present."""
    parts = [
        _banner(pd),
        f"# Program Rules Summary — {pd.name or pd.handle or 'unknown'}",
        "",
        "## Platform",
        pd.platform or "<REQUIRED: Platform name>",
        "",
        "## Auth Header Format",
        "<REQUIRED: Exact auth header format used in API requests>",
        "",
        "## Mandatory Headers",
        "<REQUIRED: All required headers for valid requests>",
        "",
        "## In-Scope Assets (VERBATIM — program_fetcher auto-filled)",
        _format_scope_in(pd),
        "",
        "## Out-of-Scope / Exclusion List (VERBATIM — program_fetcher auto-filled)",
        _format_scope_out(pd),
        "",
        "## Known Issues (VERBATIM — program_fetcher auto-filled)",
        _format_known_issues(pd),
        "",
        "## Already Submitted Reports (Exclude from Analysis)",
        "<REQUIRED: List of endpoints/vulns from already-submitted reports in this engagement>",
        "",
        "## Submission Rules (VERBATIM — program_fetcher auto-filled)",
        _format_submission_rules(pd),
        "",
        "## Severity Scope (VERBATIM — program_fetcher auto-filled)",
        _format_severity_table(pd),
        "",
        "## Asset Scope Constraints (VERBATIM — program_fetcher auto-filled)",
        _format_asset_scope_constraints(pd),
        "",
        "## Verified Curl Template",
        "<REQUIRED: A WORKING curl command that demonstrates correct auth>",
        "",
    ]
    return "\n".join(parts)


def _banner(pd: ProgramData) -> str:
    return (
        f"<!-- program_fetcher: source={pd.source or 'unknown'} "
        f"confidence={pd.confidence:.2f} fetched_at={pd.fetched_at or 'unknown'} -->"
    )


def render_to_target(pd: ProgramData, target_dir: Path, rules_filename: str = "program_rules_summary.md") -> Path:
    """Write program_rules_summary.md into `target_dir`, patching existing template if present.

    Returns the written path.
    """
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    rules_path = target_dir / rules_filename

    existing = ""
    if rules_path.exists():
        existing = rules_path.read_text(encoding="utf-8")

    content = to_rules_summary_md(pd, existing)
    rules_path.write_text(content, encoding="utf-8")
    return rules_path


def write_artifacts(result: FetchResult, target_dir: Path) -> dict[str, Path]:
    """Write program_data.json, program_page_raw.md, fetch_meta.json into `target_dir`.

    Does NOT write program_rules_summary.md — callers use `render_to_target`
    for that so they can choose whether to patch an existing template.
    """
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    data_path = target_dir / "program_data.json"
    data_path.write_text(
        json.dumps(result.data.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    written["program_data.json"] = data_path

    raw_path = target_dir / "program_page_raw.md"
    raw_path.write_text(result.data.raw_markdown or "", encoding="utf-8")
    written["program_page_raw.md"] = raw_path

    meta_path = target_dir / "fetch_meta.json"
    meta = {
        "verdict": result.verdict,
        "confidence": result.confidence,
        "missing_fields": result.missing_fields,
        "handlers_tried": result.handlers_tried,
        "error": result.error,
        "fetched_at": result.data.fetched_at,
        "source": result.data.source,
    }
    meta_path.write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    written["fetch_meta.json"] = meta_path

    return written
