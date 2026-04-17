#!/usr/bin/env python3
"""
Bug Bounty Submission Helper — generates platform-specific submission JSON
from standardized finding artifacts.

Usage:
  python3 tools/submit_helper.py prepare <target_dir> --platform immunefi|intigriti|yeswehack|code4rena
  python3 tools/submit_helper.py validate <submission.json>

Output: submission.json ready for Playwright MCP auto-fill.
Human clicks final Submit button.
"""

import argparse
import json
import sys
from pathlib import Path


PLATFORM_FIELDS = {
    "immunefi": {
        "required": ["title", "severity", "impact_category", "asset", "description", "poc", "gist_url"],
        "optional": ["references"],
        "form_url": "https://immunefi.com/bug-bounty/{program}/submit/",
    },
    "intigriti": {
        "required": ["title", "asset", "endpoint", "type", "severity", "cvss_vector",
                      "poc_description", "impact", "recommended_solution"],
        "optional": ["ip_address"],
        "form_url": "https://app.intigriti.com/programs/{program}/report",
    },
    "yeswehack": {
        "required": ["title", "bug_type", "scope", "endpoint", "vulnerable_part",
                      "part_name", "payload", "cvss_vector", "description"],
        "optional": ["technical_environment", "cve", "ip_address", "attachments"],
        "form_url": "https://yeswehack.com/programs/{program}/report",
    },
    "code4rena": {
        "required": ["severity", "title", "lines_of_code", "vulnerability_details", "poc", "assessed_type"],
        "optional": [],
        "form_url": "https://code4rena.com/audits/{program}/submit",
    },
}


def load_finding(target_dir: Path) -> dict:
    """Load finding data from target directory artifacts."""
    finding = {}

    # Try immunefi form
    for pattern in ["submission/*/immunefi_form.md", "submission/immunefi_form.md"]:
        for f in target_dir.glob(pattern):
            finding["immunefi_form"] = f.read_text()
            break

    # Try intigriti form
    for pattern in ["submission/*/intigriti_form.md", "submission/intigriti_form.md"]:
        for f in target_dir.glob(pattern):
            finding["intigriti_form"] = f.read_text()
            break

    # Try report draft
    for pattern in ["submission/*/report_draft.md", "submission/*_report_draft.md",
                     "submission/*/report_final.md"]:
        for f in target_dir.glob(pattern):
            finding["report"] = f.read_text()
            break

    # Try evidence
    for pattern in ["submission/*/evidence.md", "submission/*_evidence.md"]:
        for f in target_dir.glob(pattern):
            finding["evidence"] = f.read_text()
            break

    # Target assessment for program info
    assess = target_dir / "target_assessment.md"
    if assess.exists():
        finding["assessment"] = assess.read_text()

    # Program rules
    rules = target_dir / "program_rules_summary.md"
    if rules.exists():
        finding["rules"] = rules.read_text()

    return finding


def prepare_submission(target_dir: Path, platform: str, program: str = "") -> dict:
    """Prepare a submission JSON for the given platform."""
    finding = load_finding(target_dir)

    submission = {
        "platform": platform,
        "program": program or target_dir.name,
        "target_dir": str(target_dir),
        "form_url": PLATFORM_FIELDS[platform]["form_url"].format(program=program or target_dir.name),
        "fields": {},
        "status": "ready_for_review",
        "auto_submit": False,  # NEVER auto-submit, human clicks button
    }

    # Platform-specific field extraction would go here
    # For now, output the raw finding data for manual mapping
    submission["raw_artifacts"] = {k: v[:200] + "..." if len(v) > 200 else v
                                   for k, v in finding.items()}
    submission["required_fields"] = PLATFORM_FIELDS[platform]["required"]
    submission["optional_fields"] = PLATFORM_FIELDS[platform]["optional"]

    return submission


def validate_submission(submission_path: Path) -> bool:
    """Validate a submission JSON has all required fields."""
    data = json.loads(submission_path.read_text())
    platform = data.get("platform", "")
    if platform not in PLATFORM_FIELDS:
        print(f"ERROR: Unknown platform '{platform}'")
        return False

    required = PLATFORM_FIELDS[platform]["required"]
    fields = data.get("fields", {})
    missing = [f for f in required if f not in fields or not fields[f]]

    if missing:
        print(f"MISSING required fields: {', '.join(missing)}")
        return False

    print(f"VALID: All {len(required)} required fields present for {platform}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Submission Helper")
    sub = parser.add_subparsers(dest="command")

    prep = sub.add_parser("prepare")
    prep.add_argument("target_dir", type=Path)
    prep.add_argument("--platform", required=True, choices=PLATFORM_FIELDS.keys())
    prep.add_argument("--program", default="")

    val = sub.add_parser("validate")
    val.add_argument("submission_json", type=Path)

    args = parser.parse_args()

    if args.command == "prepare":
        result = prepare_submission(args.target_dir, args.platform, args.program)
        out_path = args.target_dir / "submission" / f"submission_{args.platform}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        print(f"Written: {out_path}")
    elif args.command == "validate":
        sys.exit(0 if validate_submission(args.submission_json) else 1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
