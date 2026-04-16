#!/usr/bin/env python3
"""MCP server for nuclei vulnerability scanner."""
import subprocess
import json
import os
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("nuclei-mcp")

NUCLEI_BIN = os.path.expanduser("~/go/bin/nuclei")
TEMPLATES_DIR = os.path.expanduser("~/nuclei-templates/")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, openWorldHint=True, idempotentHint=True))
def scan(target: str, severity: str = "", templates: str = "", timeout: int = 300) -> str:
    """Run nuclei vulnerability scan on target.

    Args:
        target: URL or IP to scan (e.g., 'https://example.com' or '192.168.1.1')
        severity: Filter by severity: critical,high,medium,low,info (comma-separated)
        templates: Template path or category (e.g., 'cves/', 'exposures/')
        timeout: Scan timeout in seconds (default 300)
    """
    cmd = [NUCLEI_BIN, "-u", target, "-json", "-silent"]

    if severity:
        cmd += ["-severity", severity]

    if templates:
        cmd += ["-t", templates]
    else:
        cmd += ["-t", TEMPLATES_DIR]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout.strip()
        if not output:
            return f"No findings. stderr: {result.stderr[:500]}" if result.stderr else "No findings for target."

        # Parse JSON lines and format
        findings = []
        for line in output.splitlines():
            try:
                finding = json.loads(line)
                findings.append({
                    "template-id": finding.get("template-id", ""),
                    "name": finding.get("info", {}).get("name", ""),
                    "severity": finding.get("info", {}).get("severity", ""),
                    "matched-at": finding.get("matched-at", ""),
                    "description": finding.get("info", {}).get("description", ""),
                })
            except json.JSONDecodeError:
                findings.append({"raw": line})

        return json.dumps(findings, indent=2)
    except subprocess.TimeoutExpired:
        return f"Scan timed out after {timeout}s"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def list_templates(category: str = "", severity: str = "") -> str:
    """List available nuclei templates.

    Args:
        category: Filter by category directory (e.g., 'cves', 'exposures', 'vulnerabilities')
        severity: Filter by severity (critical/high/medium/low/info)
    """
    search_dir = TEMPLATES_DIR
    if category:
        search_dir = os.path.join(TEMPLATES_DIR, category)

    if not os.path.exists(search_dir):
        return f"Category '{category}' not found. Available: " + str(os.listdir(TEMPLATES_DIR)[:20])

    templates = []
    for root, dirs, files in os.walk(search_dir):
        # Skip hidden dirs
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for f in files:
            if f.endswith('.yaml'):
                rel_path = os.path.relpath(os.path.join(root, f), TEMPLATES_DIR)
                templates.append(rel_path)
        if len(templates) > 500:
            templates.append("... (truncated at 500)")
            break

    return json.dumps({
        "count": len(templates),
        "templates": templates[:100]  # Return first 100
    }, indent=2)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def template_info(template_id: str) -> str:
    """Get information about a specific nuclei template.

    Args:
        template_id: Template ID or path (e.g., 'cves/2021/CVE-2021-44228.yaml')
    """
    # Search for template
    template_path = os.path.join(TEMPLATES_DIR, template_id)
    if not template_path.endswith('.yaml'):
        template_path += '.yaml'

    if not os.path.exists(template_path):
        # Try to find by name (portable; avoid external `find`)
        needle = template_id
        if not needle.endswith(".yaml"):
            needle += ".yaml"

        matches: list[str] = []
        for root, _, files in os.walk(TEMPLATES_DIR):
            for name in files:
                if name.endswith(".yaml") and needle in name:
                    matches.append(os.path.join(root, name))
                    if len(matches) >= 5:
                        break
            if len(matches) >= 5:
                break

        if matches:
            template_path = matches[0]
        else:
            return f"Template '{template_id}' not found"

    try:
        with open(template_path) as f:
            content = f.read()
        return content[:3000]  # Limit output
    except Exception as e:
        return f"Error reading template: {str(e)}"


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, openWorldHint=True, idempotentHint=True))
def scan_multiple(targets: str, severity: str = "critical,high", timeout: int = 600) -> str:
    """Run nuclei scan against multiple targets (newline or comma separated).

    Args:
        targets: Newline or comma separated list of targets
        severity: Severity filter (default: critical,high)
        timeout: Timeout in seconds
    """
    import tempfile

    # Parse targets
    target_list = [t.strip() for t in targets.replace(',', '\n').splitlines() if t.strip()]
    if not target_list:
        return "No valid targets provided"

    # Write to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write('\n'.join(target_list))
        target_file = f.name

    try:
        cmd = [NUCLEI_BIN, "-l", target_file, "-json", "-silent",
               "-severity", severity, "-t", TEMPLATES_DIR]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout.strip()

        if not output:
            return "No findings across all targets."

        findings = []
        for line in output.splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass

        return json.dumps(findings, indent=2)
    except subprocess.TimeoutExpired:
        return f"Scan timed out after {timeout}s"
    finally:
        os.unlink(target_file)


if __name__ == "__main__":
    mcp.run()
