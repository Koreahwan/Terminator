#!/usr/bin/env python3
"""
SARIF 2.1.0 Generator for Terminator Security Agent
Generates GitHub Code Scanning compatible SARIF output from findings JSON.

Usage:
    python3 tools/sarif_generator.py --input findings.json --output report.sarif
    python3 tools/sarif_generator.py --input findings.json  # stdout
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Terminator"
TOOL_VERSION = "1.0.0"
TOOL_INFO_URI = "https://github.com/KH/Terminator"

# Map Terminator severity to SARIF level and security-severity
SEVERITY_MAP = {
    "critical": {"level": "error",   "security_severity": "9.0"},
    "high":     {"level": "error",   "security_severity": "7.0"},
    "medium":   {"level": "warning", "security_severity": "5.0"},
    "low":      {"level": "note",    "security_severity": "3.0"},
    "info":     {"level": "none",    "security_severity": "1.0"},
}

# CWE to SARIF tags mapping for common weakness enumerations
CWE_DESCRIPTIONS = {
    "CWE-89":  "Improper Neutralization of Special Elements used in an SQL Command",
    "CWE-79":  "Improper Neutralization of Input During Web Page Generation (XSS)",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-22":  "Improper Limitation of a Pathname to a Restricted Directory",
    "CWE-78":  "Improper Neutralization of Special Elements used in an OS Command",
    "CWE-94":  "Improper Control of Generation of Code",
    "CWE-295": "Improper Certificate Validation",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}


def load_findings(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_severity(severity: str) -> str:
    return severity.lower().strip() if severity else "info"


def build_rule(finding: dict) -> dict:
    rule_id = finding.get("id", "TERM-UNKNOWN")
    title = finding.get("title", "Unnamed Finding")
    severity = normalize_severity(finding.get("severity", "info"))
    cwe = finding.get("cwe", "")
    description = finding.get("description", "")
    remediation = finding.get("remediation", "")
    cvss = finding.get("cvss", "")

    severity_info = SEVERITY_MAP.get(severity, SEVERITY_MAP["info"])

    # Build tags list
    tags = ["security"]
    if cwe:
        tags.append(cwe.lower().replace("-", "/"))
        tags.append(cwe)

    properties: dict[str, Any] = {
        "tags": tags,
        "security-severity": severity_info["security_severity"],
    }
    if cvss:
        properties["cvss"] = cvss

    rule: dict[str, Any] = {
        "id": rule_id,
        "name": title.replace(" ", ""),
        "shortDescription": {
            "text": title
        },
        "fullDescription": {
            "text": description
        },
        "defaultConfiguration": {
            "level": severity_info["level"]
        },
        "properties": properties,
        "help": {
            "text": remediation if remediation else "See description for details.",
            "markdown": f"**Remediation**\n\n{remediation}" if remediation else "See description for details."
        }
    }

    if cwe:
        cwe_desc = CWE_DESCRIPTIONS.get(cwe, cwe)
        rule["relationships"] = [
            {
                "target": {
                    "id": cwe,
                    "guid": None,
                    "toolComponent": {
                        "name": "CWE",
                        "guid": None
                    }
                },
                "kinds": ["relevant"]
            }
        ]
        # Remove None values from relationships
        rule["relationships"][0]["target"].pop("guid")
        rule["relationships"][0]["target"]["toolComponent"].pop("guid")

    return rule


def build_result(finding: dict) -> dict:
    rule_id = finding.get("id", "TERM-UNKNOWN")
    title = finding.get("title", "Unnamed Finding")
    severity = normalize_severity(finding.get("severity", "info"))
    description = finding.get("description", "")
    evidence = finding.get("evidence", "")
    location = finding.get("location", {})

    severity_info = SEVERITY_MAP.get(severity, SEVERITY_MAP["info"])

    message_text = description
    if evidence:
        message_text += f"\n\nEvidence:\n{evidence}"

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": severity_info["level"],
        "message": {
            "text": message_text
        }
    }

    # Add location if file information is available
    if location.get("file"):
        artifact_location: dict[str, Any] = {
            "uri": location["file"],
            "uriBaseId": "%SRCROOT%"
        }

        region: dict[str, Any] = {}
        if location.get("line"):
            region["startLine"] = location["line"]
        if location.get("column"):
            region["startColumn"] = location["column"]

        physical_location: dict[str, Any] = {
            "artifactLocation": artifact_location
        }
        if region:
            physical_location["region"] = region

        result["locations"] = [
            {
                "physicalLocation": physical_location
            }
        ]
    else:
        # SARIF requires at least one location, use a placeholder if none provided
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": "unknown",
                        "uriBaseId": "%SRCROOT%"
                    }
                }
            }
        ]

    # Add properties for GitHub Code Scanning
    result["properties"] = {
        "severity": severity,
    }

    return result


def build_sarif(data: dict) -> dict:
    findings = data.get("findings", [])
    metadata = data.get("metadata", {})

    rules = []
    results = []
    seen_rule_ids: set[str] = set()

    for finding in findings:
        rule_id = finding.get("id", "TERM-UNKNOWN")
        if rule_id not in seen_rule_ids:
            rules.append(build_rule(finding))
            seen_rule_ids.add(rule_id)
        results.append(build_result(finding))

    tool_driver: dict[str, Any] = {
        "name": TOOL_NAME,
        "version": TOOL_VERSION,
        "informationUri": TOOL_INFO_URI,
        "semanticVersion": TOOL_VERSION,
        "rules": rules
    }

    run: dict[str, Any] = {
        "tool": {
            "driver": tool_driver
        },
        "results": results,
        "columnKind": "utf16CodeUnits"
    }

    # Add invocation metadata if available
    target = metadata.get("target", "")
    assessment_date = metadata.get("assessment_date", "")
    if target or assessment_date:
        invocation: dict[str, Any] = {
            "executionSuccessful": True,
            "toolExecutionNotifications": []
        }
        if assessment_date:
            try:
                dt = datetime.strptime(assessment_date, "%Y-%m-%d")
                dt = dt.replace(tzinfo=timezone.utc)
                invocation["startTimeUtc"] = dt.isoformat()
                invocation["endTimeUtc"] = dt.isoformat()
            except ValueError:
                pass
        run["invocations"] = [invocation]

    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run]
    }

    return sarif


def main():
    parser = argparse.ArgumentParser(
        description="Generate SARIF 2.1.0 output from Terminator findings JSON"
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to findings JSON file"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output SARIF file path (default: stdout)"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output (default: true)"
    )
    args = parser.parse_args()

    try:
        data = load_findings(args.input)
    except FileNotFoundError:
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in input file: {e}", file=sys.stderr)
        sys.exit(1)

    sarif_output = build_sarif(data)
    indent = 2 if args.pretty else None
    output_str = json.dumps(sarif_output, indent=indent, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_str)
        finding_count = len(data.get("findings", []))
        print(f"SARIF report written to: {args.output} ({finding_count} findings)", file=sys.stderr)
    else:
        print(output_str)


if __name__ == "__main__":
    main()
