#!/usr/bin/env python3
"""
PDF Security Report Generator for Terminator Security Agent
Generates professional PDF reports from findings JSON using weasyprint.

Usage:
    python3 tools/pdf_generator.py --input findings.json --output report.pdf --title "Security Assessment" --target "example.com"
    python3 tools/pdf_generator.py --input findings.json --output report.pdf --template minimal

Dependencies:
    pip install weasyprint
    sudo apt-get install -y libpango1.0-dev libcairo2-dev  # system deps
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Optional


def load_findings_from_db(assessment_id: int) -> dict:
    """Load findings from assessment DB (AIDA-inspired)."""
    PG_CONFIG = {
        "host": os.environ.get("TERMINATOR_DB_HOST", "localhost"),
        "port": int(os.environ.get("TERMINATOR_DB_PORT", "5433")),
        "dbname": os.environ.get("TERMINATOR_DB_NAME", "terminator"),
        "user": os.environ.get("TERMINATOR_DB_USER", "shadowhunter"),
        "password": os.environ.get("TERMINATOR_DB_PASS", "terminator"),
    }
    try:
        import psycopg2
        conn = psycopg2.connect(**PG_CONFIG)
        cur = conn.cursor()
        cur.execute(
            """SELECT title, severity, cvss_score, cvss_vector, cwe_id, evidence_tier,
                      description, proof, attack_phase, platform
               FROM findings WHERE assessment_id = %s ORDER BY
               CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
               WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END""",
            (assessment_id,),
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        cur.execute("SELECT target, pipeline, template FROM assessments WHERE id = %s", (assessment_id,))
        assess = cur.fetchone()
        conn.close()
        return {
            "assessment_id": assessment_id,
            "target": assess[0] if assess else "",
            "pipeline": assess[1] if assess else "",
            "findings": rows,
        }
    except Exception as e:
        print(f"Warning: Could not load from DB: {e}", file=sys.stderr)
        return {"findings": []}

SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high":     "#fd7e14",
    "medium":   "#ffc107",
    "low":      "#28a745",
    "info":     "#17a2b8",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def load_findings(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_severity(severity: str) -> str:
    s = (severity or "info").lower().strip()
    return s if s in SEVERITY_COLORS else "info"


def count_by_severity(findings: list) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = normalize_severity(f.get("severity", "info"))
        counts[sev] += 1
    return counts


def risk_score(counts: dict) -> int:
    weights = {"critical": 40, "high": 20, "medium": 10, "low": 3, "info": 1}
    total = sum(weights[s] * counts[s] for s in SEVERITY_ORDER)
    return min(100, total)


def get_full_css() -> str:
    return """
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Helvetica Neue', Arial, sans-serif;
            font-size: 11pt;
            color: #212529;
            line-height: 1.5;
        }
        .page-break { page-break-after: always; }

        /* Cover Page */
        .cover {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: flex-start;
            padding: 80px 60px;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: white;
        }
        .cover-logo {
            font-size: 14pt;
            font-weight: 700;
            letter-spacing: 4px;
            text-transform: uppercase;
            color: #e94560;
            margin-bottom: 60px;
        }
        .cover-title {
            font-size: 32pt;
            font-weight: 700;
            line-height: 1.2;
            margin-bottom: 20px;
            max-width: 600px;
        }
        .cover-subtitle {
            font-size: 14pt;
            color: #a8b2c1;
            margin-bottom: 60px;
        }
        .cover-meta {
            border-top: 1px solid #2d3a4a;
            padding-top: 40px;
            width: 100%;
        }
        .cover-meta table { border-collapse: collapse; }
        .cover-meta td {
            padding: 6px 20px 6px 0;
            font-size: 10pt;
            color: #a8b2c1;
        }
        .cover-meta td:first-child {
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #6c8ebf;
            width: 120px;
        }
        .cover-confidential {
            position: fixed;
            bottom: 30px;
            right: 60px;
            font-size: 8pt;
            color: #4a5568;
            text-transform: uppercase;
            letter-spacing: 2px;
        }

        /* Table of Contents */
        .toc {
            padding: 60px;
        }
        .section-header {
            font-size: 20pt;
            font-weight: 700;
            color: #1a1a2e;
            border-bottom: 3px solid #e94560;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }
        .toc-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px dotted #dee2e6;
            font-size: 11pt;
        }
        .toc-item .toc-title { color: #343a40; }
        .toc-item .toc-page { color: #6c757d; }

        /* Executive Summary */
        .exec-summary {
            padding: 60px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin: 30px 0;
        }
        .severity-card {
            text-align: center;
            padding: 20px 10px;
            border-radius: 8px;
            color: white;
        }
        .severity-card .count {
            font-size: 36pt;
            font-weight: 700;
            line-height: 1;
        }
        .severity-card .label {
            font-size: 9pt;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 6px;
            opacity: 0.9;
        }
        .risk-meter {
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #e94560;
        }
        .risk-meter h3 {
            font-size: 12pt;
            color: #495057;
            margin-bottom: 10px;
        }
        .risk-bar-container {
            background: #dee2e6;
            border-radius: 4px;
            height: 20px;
            position: relative;
        }
        .risk-bar {
            height: 100%;
            border-radius: 4px;
            background: linear-gradient(90deg, #28a745, #ffc107, #fd7e14, #dc3545);
        }
        .risk-score-label {
            margin-top: 8px;
            font-size: 10pt;
            color: #495057;
            text-align: right;
        }

        /* Findings Section */
        .findings {
            padding: 60px;
        }
        .finding-card {
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin-bottom: 30px;
            overflow: hidden;
        }
        .finding-header {
            padding: 15px 20px;
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .finding-id {
            font-size: 9pt;
            font-weight: 600;
            letter-spacing: 1px;
            opacity: 0.85;
        }
        .finding-severity-badge {
            font-size: 9pt;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            background: rgba(255,255,255,0.2);
            padding: 3px 10px;
            border-radius: 12px;
        }
        .finding-title {
            font-size: 14pt;
            font-weight: 700;
            margin-top: 4px;
        }
        .finding-body {
            padding: 20px;
        }
        .finding-meta {
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }
        .meta-tag {
            font-size: 9pt;
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 3px 8px;
            color: #495057;
        }
        .meta-tag strong { color: #212529; }
        .finding-section {
            margin-bottom: 15px;
        }
        .finding-section h4 {
            font-size: 10pt;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #6c757d;
            margin-bottom: 6px;
            font-weight: 600;
        }
        .finding-section p {
            font-size: 10.5pt;
            color: #343a40;
        }
        .evidence-box {
            background: #1a1a2e;
            color: #a8f0c8;
            padding: 12px 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 9pt;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .remediation-box {
            background: #f0fff4;
            border-left: 3px solid #28a745;
            padding: 12px 15px;
            border-radius: 0 6px 6px 0;
            font-size: 10.5pt;
            color: #1a4731;
        }

        /* Appendix */
        .appendix {
            padding: 60px;
        }
        .appendix p {
            margin-bottom: 12px;
            font-size: 10.5pt;
            color: #495057;
        }
        .appendix h3 {
            font-size: 13pt;
            color: #343a40;
            margin: 20px 0 10px;
        }
        table.methodology {
            width: 100%;
            border-collapse: collapse;
            font-size: 10pt;
            margin-top: 15px;
        }
        table.methodology th {
            background: #1a1a2e;
            color: white;
            padding: 10px 15px;
            text-align: left;
        }
        table.methodology td {
            padding: 9px 15px;
            border-bottom: 1px solid #dee2e6;
        }
        table.methodology tr:nth-child(even) td {
            background: #f8f9fa;
        }

        /* Footer */
        @page {
            margin: 0;
            @bottom-center {
                content: counter(page);
                font-size: 9pt;
                color: #adb5bd;
            }
        }
    """


def get_minimal_css() -> str:
    return """
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: Arial, sans-serif;
            font-size: 11pt;
            color: #212529;
            line-height: 1.5;
            padding: 40px;
        }
        .page-break { page-break-after: always; }
        .cover { padding: 40px 0 60px; border-bottom: 2px solid #212529; margin-bottom: 40px; }
        .cover-logo { font-size: 10pt; font-weight: 700; letter-spacing: 3px; text-transform: uppercase; color: #dc3545; margin-bottom: 30px; }
        .cover-title { font-size: 24pt; font-weight: 700; margin-bottom: 10px; }
        .cover-subtitle { font-size: 12pt; color: #6c757d; margin-bottom: 30px; }
        .cover-meta table { border-collapse: collapse; font-size: 10pt; }
        .cover-meta td { padding: 4px 20px 4px 0; }
        .cover-meta td:first-child { font-weight: 600; color: #6c757d; width: 120px; }
        .cover-confidential { display: none; }
        .toc, .exec-summary, .findings, .appendix { padding: 20px 0; }
        .section-header { font-size: 16pt; font-weight: 700; border-bottom: 2px solid #212529; padding-bottom: 8px; margin-bottom: 20px; }
        .summary-grid { display: flex; gap: 10px; flex-wrap: wrap; margin: 20px 0; }
        .severity-card { padding: 15px; border-radius: 4px; color: white; min-width: 100px; text-align: center; }
        .severity-card .count { font-size: 24pt; font-weight: 700; }
        .severity-card .label { font-size: 9pt; text-transform: uppercase; }
        .risk-meter { padding: 15px; background: #f8f9fa; margin: 20px 0; }
        .risk-bar-container { background: #dee2e6; border-radius: 4px; height: 12px; }
        .risk-bar { height: 100%; border-radius: 4px; background: #dc3545; }
        .risk-score-label { font-size: 10pt; color: #6c757d; margin-top: 5px; }
        .toc-item { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px dotted #dee2e6; }
        .finding-card { border: 1px solid #dee2e6; margin-bottom: 20px; border-radius: 4px; overflow: hidden; }
        .finding-header { padding: 12px 15px; color: white; }
        .finding-id { font-size: 9pt; opacity: 0.85; }
        .finding-title { font-size: 13pt; font-weight: 700; margin-top: 3px; }
        .finding-severity-badge { float: right; font-size: 9pt; font-weight: 700; text-transform: uppercase; }
        .finding-body { padding: 15px; }
        .finding-meta { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 12px; }
        .meta-tag { font-size: 9pt; background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 3px; padding: 2px 6px; }
        .finding-section { margin-bottom: 12px; }
        .finding-section h4 { font-size: 9pt; text-transform: uppercase; color: #6c757d; margin-bottom: 4px; font-weight: 600; }
        .evidence-box { background: #f8f9fa; border: 1px solid #dee2e6; padding: 10px; font-family: monospace; font-size: 9pt; white-space: pre-wrap; border-radius: 3px; }
        .remediation-box { background: #f0fff4; border-left: 3px solid #28a745; padding: 10px; font-size: 10.5pt; }
        .appendix p { margin-bottom: 10px; color: #495057; }
        table.methodology { width: 100%; border-collapse: collapse; font-size: 10pt; margin-top: 10px; }
        table.methodology th { background: #212529; color: white; padding: 8px 12px; text-align: left; }
        table.methodology td { padding: 7px 12px; border-bottom: 1px solid #dee2e6; }
    """


def build_html(data: dict, title: str, target: str, assessor: str, template: str) -> str:
    findings = data.get("findings", [])
    meta = data.get("metadata", {})

    effective_title = title or meta.get("title", "Security Assessment Report")
    effective_target = target or meta.get("target", "Target System")
    effective_assessor = assessor or meta.get("assessor", "Terminator Security Agent")
    assessment_date = meta.get("assessment_date", datetime.now().strftime("%Y-%m-%d"))
    scope = meta.get("scope", "")

    counts = count_by_severity(findings)
    score = risk_score(counts)
    total = len(findings)

    css = get_full_css() if template == "full" else get_minimal_css()

    # Build severity summary cards
    severity_cards = ""
    for sev in SEVERITY_ORDER:
        color = SEVERITY_COLORS[sev]
        severity_cards += f"""
        <div class="severity-card" style="background-color: {color};">
            <div class="count">{counts[sev]}</div>
            <div class="label">{sev.capitalize()}</div>
        </div>"""

    # Build TOC entries
    toc_entries = ""
    toc_data = [
        ("Executive Summary", "2"),
        ("Detailed Findings", "3"),
        ("Appendix — Methodology", str(3 + max(1, total))),
    ]
    for name, page in toc_data:
        toc_entries += f"""
        <div class="toc-item">
            <span class="toc-title">{name}</span>
            <span class="toc-page">{page}</span>
        </div>"""

    # Build individual findings
    findings_html = ""
    for finding in findings:
        fid = finding.get("id", "TERM-???")
        ftitle = finding.get("title", "Unnamed Finding")
        severity = normalize_severity(finding.get("severity", "info"))
        color = SEVERITY_COLORS[severity]
        cwe = finding.get("cwe", "")
        cvss = finding.get("cvss", "")
        description = finding.get("description", "")
        evidence = finding.get("evidence", "")
        remediation = finding.get("remediation", "")
        loc = finding.get("location", {})

        meta_tags = ""
        if cwe:
            meta_tags += f'<span class="meta-tag"><strong>CWE:</strong> {cwe}</span>'
        if cvss:
            meta_tags += f'<span class="meta-tag"><strong>CVSS:</strong> {cvss}</span>'
        if loc.get("file"):
            loc_str = loc["file"]
            if loc.get("line"):
                loc_str += f":{loc['line']}"
            meta_tags += f'<span class="meta-tag"><strong>Location:</strong> {loc_str}</span>'

        evidence_section = ""
        if evidence:
            evidence_section = f"""
            <div class="finding-section">
                <h4>Evidence</h4>
                <div class="evidence-box">{evidence}</div>
            </div>"""

        remediation_section = ""
        if remediation:
            remediation_section = f"""
            <div class="finding-section">
                <h4>Remediation</h4>
                <div class="remediation-box">{remediation}</div>
            </div>"""

        findings_html += f"""
        <div class="finding-card">
            <div class="finding-header" style="background-color: {color};">
                <div>
                    <div class="finding-id">{fid}</div>
                    <div class="finding-title">{ftitle}</div>
                </div>
                <span class="finding-severity-badge">{severity.upper()}</span>
            </div>
            <div class="finding-body">
                <div class="finding-meta">{meta_tags}</div>
                <div class="finding-section">
                    <h4>Description</h4>
                    <p>{description}</p>
                </div>
                {evidence_section}
                {remediation_section}
            </div>
        </div>"""

    scope_row = f"<tr><td>Scope</td><td>{scope}</td></tr>" if scope else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{effective_title}</title>
<style>{css}</style>
</head>
<body>

<!-- Cover Page -->
<div class="cover page-break">
    <div class="cover-logo">Terminator</div>
    <div class="cover-title">{effective_title}</div>
    <div class="cover-subtitle">Autonomous Security Agent Report</div>
    <div class="cover-meta">
        <table>
            <tr><td>Target</td><td>{effective_target}</td></tr>
            <tr><td>Assessor</td><td>{effective_assessor}</td></tr>
            <tr><td>Date</td><td>{assessment_date}</td></tr>
            <tr><td>Findings</td><td>{total} ({counts['critical']} Critical, {counts['high']} High)</td></tr>
            {scope_row}
        </table>
    </div>
    <div class="cover-confidential">CONFIDENTIAL — For Authorized Recipients Only</div>
</div>

<!-- Table of Contents -->
<div class="toc page-break">
    <div class="section-header">Table of Contents</div>
    {toc_entries}
</div>

<!-- Executive Summary -->
<div class="exec-summary page-break">
    <div class="section-header">Executive Summary</div>
    <p>This report presents the findings of a security assessment conducted against <strong>{effective_target}</strong> on {assessment_date}. The assessment identified <strong>{total} findings</strong> across multiple severity levels.</p>

    <div class="summary-grid">
        {severity_cards}
    </div>

    <div class="risk-meter">
        <h3>Overall Risk Score: {score}/100</h3>
        <div class="risk-bar-container">
            <div class="risk-bar" style="width: {score}%;"></div>
        </div>
        <div class="risk-score-label">{"Critical Risk" if score >= 80 else "High Risk" if score >= 50 else "Medium Risk" if score >= 20 else "Low Risk"}</div>
    </div>

    <p>Immediate remediation is recommended for all Critical and High severity findings. Medium and Low severity findings should be addressed within the standard vulnerability management cycle.</p>
</div>

<!-- Detailed Findings -->
<div class="findings">
    <div class="section-header">Detailed Findings</div>
    {findings_html}
</div>

<!-- Appendix -->
<div class="appendix page-break">
    <div class="section-header">Appendix — Methodology</div>
    <p>This assessment was conducted using the Terminator autonomous security agent framework. The following methodology phases were applied:</p>

    <table class="methodology">
        <tr><th>Phase</th><th>Description</th><th>Tools Used</th></tr>
        <tr><td>Reconnaissance</td><td>Asset enumeration, technology fingerprinting, attack surface mapping</td><td>nmap, ffuf, httpx, katana</td></tr>
        <tr><td>Vulnerability Discovery</td><td>Automated and manual discovery of security weaknesses</td><td>nuclei, Semgrep, CodeQL, custom agents</td></tr>
        <tr><td>Exploitation</td><td>Proof-of-concept development to validate exploitability</td><td>pwntools, Burp Suite, custom PoC</td></tr>
        <tr><td>Reporting</td><td>CVSS scoring, risk rating, and remediation guidance</td><td>Terminator reporter agent</td></tr>
    </table>

    <h3>Severity Rating Scale</h3>
    <table class="methodology">
        <tr><th>Severity</th><th>CVSS Range</th><th>Description</th></tr>
        <tr><td><strong style="color:#dc3545;">Critical</strong></td><td>9.0 – 10.0</td><td>Immediate exploitation possible with severe business impact</td></tr>
        <tr><td><strong style="color:#fd7e14;">High</strong></td><td>7.0 – 8.9</td><td>Significant risk requiring prompt remediation</td></tr>
        <tr><td><strong style="color:#b8860b;">Medium</strong></td><td>4.0 – 6.9</td><td>Moderate risk within standard patch cycle</td></tr>
        <tr><td><strong style="color:#28a745;">Low</strong></td><td>0.1 – 3.9</td><td>Limited impact, low exploitation likelihood</td></tr>
        <tr><td><strong style="color:#17a2b8;">Info</strong></td><td>0.0</td><td>Informational, no direct security impact</td></tr>
    </table>

    <p style="margin-top:20px; font-size:9pt; color:#6c757d;">Generated by Terminator Security Agent v1.0.0 — {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}</p>
</div>

</body>
</html>"""

    return html


def main():
    parser = argparse.ArgumentParser(
        description="Generate PDF security report from Terminator findings JSON"
    )
    parser.add_argument("--input", "-i", required=False, default="", help="Path to findings JSON file")
    parser.add_argument("--assessment-id", type=int, default=None, help="Load findings from assessment DB by ID")
    parser.add_argument("--output", "-o", required=True, help="Output PDF file path")
    parser.add_argument("--title", "-t", default="", help="Report title")
    parser.add_argument("--target", default="", help="Target system name")
    parser.add_argument("--assessor", default="", help="Assessor name")
    parser.add_argument(
        "--template",
        choices=["full", "minimal"],
        default="full",
        help="Report template (default: full)"
    )
    parser.add_argument(
        "--html-only",
        action="store_true",
        help="Generate HTML only (skip PDF conversion, save as .html)"
    )
    args = parser.parse_args()

    if getattr(args, 'assessment_id', None):
        data = load_findings_from_db(args.assessment_id)
        if not args.target and data.get("target"):
            args.target = data["target"]
    else:
        try:
            data = load_findings(args.input)
        except FileNotFoundError:
            print(f"Error: Input file not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in input file: {e}", file=sys.stderr)
            sys.exit(1)

    html_content = build_html(
        data=data,
        title=args.title,
        target=args.target,
        assessor=args.assessor,
        template=args.template,
    )

    if args.html_only:
        html_path = args.output.replace(".pdf", ".html") if args.output.endswith(".pdf") else args.output + ".html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"HTML report written to: {html_path}", file=sys.stderr)
        return

    try:
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(args.output)
        finding_count = len(data.get("findings", []))
        print(f"PDF report written to: {args.output} ({finding_count} findings)", file=sys.stderr)
    except ImportError:
        print(
            "weasyprint not installed. Install with: pip install weasyprint\n"
            "System deps (Ubuntu/Debian): sudo apt-get install -y libpango1.0-dev libcairo2-dev\n"
            "Falling back to HTML output...",
            file=sys.stderr
        )
        html_path = args.output.replace(".pdf", ".html") if args.output.endswith(".pdf") else args.output + ".html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"HTML report written to: {html_path}", file=sys.stderr)
    except Exception as e:
        print(f"PDF generation failed: {e}", file=sys.stderr)
        html_path = args.output.replace(".pdf", ".html") if args.output.endswith(".pdf") else args.output + ".html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"HTML fallback written to: {html_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
