#!/usr/bin/env python3
"""
Bug Bounty Auto-Fill Payload Generator — reads reporter artifacts and generates
autofill_payload.json for MCP Playwright form filling.

Usage:
  python3 tools/bb_autofill_payload.py <submission_dir> [--platform auto]
  python3 tools/bb_autofill_payload.py targets/paradex/submission/CAND-01/

Output: <submission_dir>/autofill_payload.json
"""

import argparse
import json
import re
import sys
from pathlib import Path


PLATFORM_FORM_FILES = {
    "bugcrowd": ["bugcrowd_form.md"],
    "hackerone": ["hackerone_form.md", "h1_form.md"],
    "immunefi": ["immunefi_form.md"],
    "hackenproof": ["hackenproof_form.md"],
    "intigriti": ["intigriti_form.md"],
    "huntr": ["huntr_form.md"],
    "yeswehack": ["yeswehack_form.md", "ywh_form.md"],
}

# Note: huntr uses a single entry URL (/bounties/disclose) for ALL targets;
# the actual repo is selected on the form page. Do NOT use per-program URL.
PLATFORM_URLS = {
    "bugcrowd": "https://www.bugcrowd.com/{program}/submissions/new",
    "hackerone": "https://www.hackerone.com/{program}/reports/new",
    "immunefi": "https://bugs.immunefi.com/dashboard/submission/create?project={program}",
    "intigriti": "https://app.intigriti.com/programs/{program}/report",
    "hackenproof": "https://hackenproof.com/programs/{program}/report",
    "huntr": "https://huntr.com/bounties/disclose",
    "yeswehack": "https://yeswehack.com/programs/{program}/report",
}


def detect_platform(submission_dir: Path) -> str:
    """Auto-detect platform from available form files or program_rules_summary."""
    for platform, filenames in PLATFORM_FORM_FILES.items():
        for fn in filenames:
            if (submission_dir / fn).exists():
                return platform
            # Check parent target dir too
            target_dir = submission_dir.parent.parent if submission_dir.name != submission_dir.parent.name else submission_dir.parent
            if (target_dir / fn).exists():
                return platform

    # Check program_rules_summary.md for platform hint
    for parent in [submission_dir, submission_dir.parent, submission_dir.parent.parent]:
        rules = parent / "program_rules_summary.md"
        if rules.exists():
            content = rules.read_text().lower()
            for platform in PLATFORM_FORM_FILES:
                if platform in content:
                    return platform

    return "bugcrowd"  # default


def find_file(submission_dir: Path, names: list[str]) -> Path | None:
    """Find first matching file in submission dir or parent target dir."""
    search_dirs = [submission_dir]
    if submission_dir.parent.name == "submission":
        search_dirs.append(submission_dir.parent.parent)  # target dir
    elif submission_dir.name == "submission":
        search_dirs.append(submission_dir.parent)

    for d in search_dirs:
        for name in names:
            for f in d.rglob(name):
                return f
    return None


def parse_markdown_fields(content: str) -> dict[str, str]:
    """Parse markdown with ## headers into field dict."""
    fields = {}
    current_key = None
    current_lines = []

    for line in content.split("\n"):
        header_match = re.match(r"^##\s+(.+)", line)
        if header_match:
            if current_key:
                fields[current_key] = "\n".join(current_lines).strip()
            current_key = header_match.group(1).strip().lower()
            current_key = re.sub(r"[^a-z0-9_]", "_", current_key)
            current_lines = []
        elif current_key:
            current_lines.append(line)

    if current_key:
        fields[current_key] = "\n".join(current_lines).strip()

    return fields


def extract_frontmatter(content: str) -> dict[str, str]:
    """Extract YAML-like frontmatter key: value pairs."""
    fm = {}
    in_fm = False
    for line in content.split("\n"):
        if line.strip() == "---":
            if not in_fm:
                in_fm = True
                continue
            else:
                break
        if in_fm:
            match = re.match(r"^(\w[\w\s]*?):\s*(.+)", line)
            if match:
                key = match.group(1).strip().lower().replace(" ", "_")
                fm[key] = match.group(2).strip()
    return fm


def collect_attachments(submission_dir: Path) -> list[dict]:
    """Collect attachment files from submission directory."""
    attachments = []
    skip_patterns = {"autofill_payload.json", "submission_review.json", ".md"}

    for f in sorted(submission_dir.iterdir()):
        if f.is_file() and f.suffix not in skip_patterns and f.name not in skip_patterns:
            attachments.append({
                "name": f.name,
                "path": str(f.resolve()),
                "size_bytes": f.stat().st_size,
            })

    return attachments


def build_bugcrowd_payload(form_content: str, report_content: str, program: str) -> dict:
    """Build Bugcrowd-specific payload."""
    fields = parse_markdown_fields(form_content)
    fm = extract_frontmatter(form_content)

    return {
        "title": fm.get("title", fields.get("summary_title", fields.get("title", ""))),
        "severity": fm.get("severity", fm.get("vrt", fields.get("technical_severity", ""))),
        "vrt": fm.get("vrt", fields.get("vrt", fields.get("technical_severity", ""))),
        "target": fm.get("target", fields.get("target", "")),
        "url": fm.get("url", fields.get("url___location", fields.get("url", ""))),
        "description": fields.get("description", report_content),
    }


def build_hackerone_payload(form_content: str, report_content: str, program: str) -> dict:
    """Build HackerOne-specific payload."""
    fields = parse_markdown_fields(form_content)
    fm = extract_frontmatter(form_content)

    return {
        "title": fm.get("title", fields.get("title", "")),
        "asset": fm.get("asset", fields.get("asset", "")),
        "weakness": fm.get("weakness", fm.get("cwe", fields.get("weakness", ""))),
        "severity": fm.get("severity", fields.get("severity", "")),
        "cvss_vector": fm.get("cvss_vector", fm.get("cvss", fields.get("cvss", ""))),
        "description": fields.get("description", report_content),
        "impact": fields.get("impact", ""),
    }


def build_immunefi_payload(form_content: str, report_content: str, program: str) -> dict:
    """Build Immunefi-specific payload."""
    fields = parse_markdown_fields(form_content)
    fm = extract_frontmatter(form_content)

    # Immunefi forms often use ## Step N: headers → parse subfields
    # Extract title from ### Title code block, **Title**: value, or inline
    title = fm.get("title", fields.get("title", ""))
    if not title:
        m = re.search(r"###?\s+Title\s*\n+```\s*\n(.+?)\n```", form_content, re.DOTALL)
        if m:
            title = m.group(1).strip()
        else:
            m = re.search(r"\*\*Title\*\*:\s*(.+)", form_content)
            if m:
                title = m.group(1).strip()
            else:
                m = re.search(r"###?\s+Title\s*\n+(.+)", form_content)
                if m:
                    title = m.group(1).strip()
    # Fall back to H1 heading in report_content if form_content had no title
    if not title and report_content:
        m = re.search(r"^#\s+(.+)", report_content, re.MULTILINE)
        if m:
            title = m.group(1).strip()

    # Extract severity from **Selected**: or **Severity**: patterns
    severity = fm.get("severity", fields.get("severity_level", ""))
    if not severity:
        for pat in [r"\*\*Selected\*\*:\s*(\w+)", r"\*\*Severity\*\*:\s*(\w+)"]:
            m = re.search(pat, form_content)
            if m:
                severity = m.group(1).strip()
                break

    # Extract impact from **Impact Selected**: or **Impact Category**: patterns
    impact = fm.get("impact", fields.get("impact", fields.get("impact_details", "")))
    if not impact:
        for pat in [r"\*\*Impact Selected\*\*:\s*(.+)", r"\*\*Impact Category\*\*:\s*(.+)"]:
            m = re.search(pat, form_content)
            if m:
                impact = m.group(1).strip()
                break

    # Extract asset from **Asset**: pattern
    asset = fm.get("asset", fields.get("asset", fields.get("assets_and_impact", "")))
    if not asset:
        m = re.search(r"\*\*Asset\*\*:\s*(.+)", form_content)
        if m:
            asset = m.group(1).strip()

    # Extract description from **Description**: multi-line block
    desc = fields.get("description", fields.get("vulnerability_details", ""))
    if not desc:
        m = re.search(r"\*\*Description\*\*:\s*\n(.+?)(?=\n\*\*|\n---|\Z)", form_content, re.DOTALL)
        if m:
            desc = m.group(1).strip()
        elif not desc:
            m = re.search(r"\*\*Description\*\*:\s*\n(.+)", form_content, re.DOTALL)
            if m:
                desc = m.group(1).strip()

    return {
        "title": title,
        "asset": asset,
        "impact": impact,
        "severity": severity,
        "description": desc or report_content,
        "poc": fields.get("proof_of_concept", fields.get("poc", "")),
        "gist_url": fm.get("gist_url", fm.get("gist", fields.get("secret_gist", ""))),
    }


def build_intigriti_payload(form_content: str, report_content: str, program: str) -> dict:
    """Build Intigriti-specific payload."""
    fields = parse_markdown_fields(form_content)
    fm = extract_frontmatter(form_content)

    # Extract title from ## Title ... ``` block ```
    title = fm.get("title", fields.get("title", ""))
    if not title:
        m = re.search(r"##\s+Title[^\n]*\n+```\s*\n(.+?)\n```", form_content, re.DOTALL)
        if m:
            title = m.group(1).strip()

    # Extract CVSS vector
    cvss = fm.get("cvss", "")
    if not cvss:
        m = re.search(r"\*\*Vector\*\*:\s*`([^`]+)`", form_content)
        if m:
            cvss = m.group(1).strip()

    # Extract summary from ## Summary ... ``` block ```
    summary = fields.get("summary__max_1500_chars_for_initial_field_", "")
    if not summary:
        m = re.search(r"##\s+Summary[^\n]*\n+```\s*\n(.+?)\n```", form_content, re.DOTALL)
        if m:
            summary = m.group(1).strip()

    return {
        "title": title,
        "asset": fm.get("asset", fields.get("asset", "")),
        "weakness": fm.get("weakness", fields.get("weakness", "")),
        "severity": fm.get("severity", ""),
        "cvss_vector": cvss,
        "summary": summary,
        "description": fields.get("full_report_body", fields.get("description", report_content)),
    }


def build_huntr_payload(form_content: str, report_content: str, program: str) -> dict:
    """huntr payload — fields match the Open Source Vulnerability Form."""
    fields = parse_markdown_fields(form_content)
    fm = extract_frontmatter(form_content)

    title = fm.get("title", fields.get("title", ""))
    cvss = fm.get("cvss_vector", fm.get("cvss", fields.get("cvss_vector", "")))
    cwe = fm.get("cwe", fields.get("cwe", ""))
    vuln_type = fm.get("vulnerability_type", fields.get("vulnerability_type", ""))
    version = fm.get("version_affected", fm.get("commit", fields.get("version", "")))
    package_manager = fm.get("package_manager", fields.get("package_manager", "pypi"))

    return {
        "title": title,
        "repository_url": fm.get("asset", fields.get("repository", "")),
        "package_manager": package_manager,
        "version_affected": version,
        "vulnerability_type": vuln_type,
        "cwe": cwe,
        "cvss_vector": cvss,
        "description": fields.get("description", report_content),
        "impact": fields.get("impact", ""),
        "proof_of_concept": fields.get("proof_of_concept", fields.get("poc", "")),
        "occurrences": fields.get("occurrences", ""),
    }


def build_yeswehack_payload(form_content: str, report_content: str, program: str) -> dict:
    """YesWeHack payload — fields match YWH report form."""
    fields = parse_markdown_fields(form_content)
    fm = extract_frontmatter(form_content)

    return {
        "title": fm.get("title", fields.get("title", "")),
        "asset": fm.get("asset", fields.get("asset", "")),
        "category": fm.get("category", fields.get("category", "")),
        "cvss_vector": fm.get("cvss_vector", fields.get("cvss_vector", "")),
        "description": fields.get("description", report_content),
        "impact": fields.get("impact", ""),
        "poc": fields.get("proof_of_concept", fields.get("poc", "")),
    }


PLATFORM_BUILDERS = {
    "bugcrowd": build_bugcrowd_payload,
    "hackerone": build_hackerone_payload,
    "immunefi": build_immunefi_payload,
    "intigriti": build_intigriti_payload,
    "huntr": build_huntr_payload,
    "yeswehack": build_yeswehack_payload,
}


def generate_payload(submission_dir: Path, platform: str = "auto") -> dict:
    """Generate autofill payload from submission artifacts."""
    submission_dir = submission_dir.resolve()

    if platform == "auto":
        platform = detect_platform(submission_dir)

    # Find form file
    form_file = find_file(submission_dir, PLATFORM_FORM_FILES.get(platform, []))
    form_content = form_file.read_text() if form_file else ""

    # Find report
    report_file = find_file(submission_dir, [
        "report_final.md", "report_draft.md", "report.md",
        f"report_{submission_dir.name}.md",
    ])
    report_content = report_file.read_text() if report_file else ""

    # Detect program name
    program = ""
    rules_file = find_file(submission_dir, ["program_rules_summary.md"])
    if rules_file:
        fm = extract_frontmatter(rules_file.read_text())
        program = fm.get("program", fm.get("program_name", submission_dir.parent.parent.name))
    if not program:
        program = submission_dir.parent.parent.name if submission_dir.parent.name == "submission" else submission_dir.parent.name

    # Build platform-specific fields
    builder = PLATFORM_BUILDERS.get(platform, build_bugcrowd_payload)
    fields = builder(form_content, report_content, program)

    # Strip code block markers from field values
    for k, v in fields.items():
        if isinstance(v, str) and v.startswith("```"):
            v = re.sub(r"^```\w*\s*\n?", "", v)
            v = re.sub(r"\n?```\s*$", "", v)
            fields[k] = v.strip()

    # Remove empty fields
    fields = {k: v for k, v in fields.items() if v}

    # Collect attachments
    attachments = collect_attachments(submission_dir)

    payload = {
        "platform": platform,
        "program": program,
        "form_url": PLATFORM_URLS.get(platform, "").format(program=program),
        "fields": fields,
        "attachments": [a["name"] for a in attachments],
        "attachment_paths": [a["path"] for a in attachments],
        "attachment_sizes": {a["name"]: a["size_bytes"] for a in attachments},
        "source_dir": str(submission_dir),
        "auto_submit": False,
    }

    # Validate
    missing = []
    if not fields.get("title"):
        missing.append("title")
    if not fields.get("description") and not report_content:
        missing.append("description")
    if missing:
        payload["warnings"] = [f"Missing field: {f}" for f in missing]

    return payload


def main():
    parser = argparse.ArgumentParser(description="BB Auto-Fill Payload Generator")
    parser.add_argument("submission_dir", type=Path, help="Path to submission directory")
    parser.add_argument("--platform", default="auto", help="Platform (auto|bugcrowd|hackerone|immunefi)")
    args = parser.parse_args()

    if not args.submission_dir.is_dir():
        print(f"ERROR: {args.submission_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    payload = generate_payload(args.submission_dir, args.platform)
    out_path = args.submission_dir / "autofill_payload.json"
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")

    print(f"Platform: {payload['platform']}")
    print(f"Program: {payload['program']}")
    print(f"Fields: {len(payload['fields'])}")
    print(f"Attachments: {len(payload['attachments'])}")
    if payload.get("warnings"):
        for w in payload["warnings"]:
            print(f"WARNING: {w}")
    print(f"Written: {out_path}")


if __name__ == "__main__":
    main()
