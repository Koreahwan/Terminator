#!/usr/bin/env python3
"""MCP server for Semgrep static analysis."""
import subprocess
import json
import os
import tempfile
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("semgrep-mcp")

SEMGREP_BIN = os.path.expanduser("~/.local/bin/semgrep")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def scan(target: str, rules: str = "auto", severity: str = "", timeout: int = 300) -> str:
    """Run Semgrep static analysis scan.

    Args:
        target: File or directory to scan
        rules: Rules to use: 'auto' (default), 'p/security-audit', 'p/owasp-top-ten',
               'p/python', 'p/javascript', path to local rule file, or
               comma-separated registry IDs
        severity: Filter by severity: ERROR, WARNING, INFO (comma-separated)
        timeout: Timeout in seconds (default 300)
    """
    if not os.path.exists(target):
        return f"Target not found: {target}"

    cmd = [SEMGREP_BIN, "--json", "--quiet"]

    # Rules
    for r in rules.split(','):
        r = r.strip()
        if r:
            cmd += ["--config", r]

    # Severity filter
    if severity:
        for sev in severity.upper().split(','):
            sev = sev.strip()
            if sev:
                cmd += ["--severity", sev]

    cmd.append(target)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Output: {result.stdout[:2000]}\nStderr: {result.stderr[:500]}"

        findings = data.get("results", [])
        errors = data.get("errors", [])

        # Format findings
        formatted = []
        for f in findings:
            formatted.append({
                "rule_id": f.get("check_id", ""),
                "message": f.get("extra", {}).get("message", ""),
                "severity": f.get("extra", {}).get("severity", ""),
                "path": f.get("path", ""),
                "line": f.get("start", {}).get("line", 0),
                "end_line": f.get("end", {}).get("line", 0),
                "code": f.get("extra", {}).get("lines", ""),
                "cwe": f.get("extra", {}).get("metadata", {}).get("cwe", []),
                "owasp": f.get("extra", {}).get("metadata", {}).get("owasp", []),
            })

        return json.dumps({
            "total_findings": len(findings),
            "errors": len(errors),
            "findings": formatted[:100]  # Cap at 100
        }, indent=2)

    except subprocess.TimeoutExpired:
        return f"Scan timed out after {timeout}s"
    except FileNotFoundError:
        return f"Semgrep not found at {SEMGREP_BIN}"


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def scan_with_rule(target: str, rule_yaml: str) -> str:
    """Run Semgrep with an inline rule definition.

    Args:
        target: File or directory to scan
        rule_yaml: Complete YAML rule definition as string
    """
    if not os.path.exists(target):
        return f"Target not found: {target}"

    tmp_rule = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(rule_yaml)
            tmp_rule = f.name

        result = subprocess.run(
            [SEMGREP_BIN, "--json", "--quiet", "--config", tmp_rule, target],
            capture_output=True,
            text=True,
            timeout=120
        )

        try:
            data = json.loads(result.stdout)
            findings = data.get("results", [])
            return json.dumps({
                "total_findings": len(findings),
                "findings": findings[:50]
            }, indent=2)
        except json.JSONDecodeError:
            return f"Output: {result.stdout[:2000]}\nStderr: {result.stderr[:500]}"

    except subprocess.TimeoutExpired:
        return "Scan timed out"
    finally:
        if tmp_rule and os.path.exists(tmp_rule):
            os.unlink(tmp_rule)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def list_rules(language: str = "", category: str = "") -> str:
    """List available Semgrep rule packs from the registry.

    Args:
        language: Filter by language (python, javascript, java, go, ruby, etc.)
        category: Filter by category (security, correctness, performance, etc.)
    """
    # Common rule packs
    packs = [
        {"id": "p/security-audit", "desc": "General security audit rules", "lang": "all"},
        {"id": "p/owasp-top-ten", "desc": "OWASP Top 10 vulnerabilities", "lang": "all"},
        {"id": "p/python", "desc": "Python best practices and security", "lang": "python"},
        {"id": "p/javascript", "desc": "JavaScript/TypeScript security", "lang": "javascript"},
        {"id": "p/java", "desc": "Java security rules", "lang": "java"},
        {"id": "p/golang", "desc": "Go security rules", "lang": "go"},
        {"id": "p/ruby", "desc": "Ruby security rules", "lang": "ruby"},
        {"id": "p/php", "desc": "PHP security rules", "lang": "php"},
        {"id": "p/ci", "desc": "CI/CD security misconfiguration", "lang": "all"},
        {"id": "p/docker", "desc": "Dockerfile security rules", "lang": "docker"},
        {"id": "p/kubernetes", "desc": "Kubernetes manifest security", "lang": "yaml"},
        {"id": "p/terraform", "desc": "Terraform IaC security", "lang": "hcl"},
        {"id": "p/xss", "desc": "Cross-site scripting detection", "lang": "javascript"},
        {"id": "p/sql-injection", "desc": "SQL injection patterns", "lang": "all"},
        {"id": "p/command-injection", "desc": "Command injection patterns", "lang": "all"},
        {"id": "p/ssrf", "desc": "Server-side request forgery", "lang": "all"},
        {"id": "p/secrets", "desc": "Hardcoded secrets and credentials", "lang": "all"},
        {"id": "p/supply-chain", "desc": "Supply chain security", "lang": "all"},
        {"id": "p/jwt", "desc": "JWT implementation issues", "lang": "all"},
        {"id": "p/insecure-transport", "desc": "Insecure transport/TLS issues", "lang": "all"},
    ]

    if language:
        packs = [p for p in packs if p["lang"] in (language, "all")]

    if category:
        cat_map = {
            "security": ["security-audit", "owasp", "xss", "sql", "command", "ssrf", "jwt"],
            "secrets": ["secrets"],
            "iac": ["docker", "kubernetes", "terraform", "ci"],
        }
        keywords = cat_map.get(category.lower(), [category.lower()])
        packs = [p for p in packs if any(k in p["id"] for k in keywords)]

    return json.dumps({
        "count": len(packs),
        "rule_packs": packs,
        "usage_hint": "Use 'scan' tool with rules='p/security-audit' or any ID listed above"
    }, indent=2)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def taint_analysis(target: str, language: str = "python") -> str:
    """Run taint-mode analysis to find source-to-sink data flows.

    Args:
        target: File or directory to analyze
        language: Language for taint rules (python, javascript, java)
    """
    lang_rules = {
        "python": "p/python",
        "javascript": "p/javascript",
        "java": "p/java",
        "go": "p/golang",
    }

    rule = lang_rules.get(language, "p/security-audit")

    result = subprocess.run(
        [SEMGREP_BIN, "--json", "--quiet",
         "--config", rule,
         "--config", "p/owasp-top-ten",
         target],
        capture_output=True,
        text=True,
        timeout=300
    )

    try:
        data = json.loads(result.stdout)
        findings = data.get("results", [])

        # Group by CWE
        by_cwe = {}
        for f in findings:
            cwe = f.get("extra", {}).get("metadata", {}).get("cwe", ["Unknown"])
            if isinstance(cwe, list):
                cwe = cwe[0] if cwe else "Unknown"
            if cwe not in by_cwe:
                by_cwe[cwe] = []
            by_cwe[cwe].append({
                "rule": f.get("check_id", ""),
                "path": f.get("path", ""),
                "line": f.get("start", {}).get("line", 0),
                "message": f.get("extra", {}).get("message", "")[:200],
            })

        return json.dumps({
            "total": len(findings),
            "by_cwe": by_cwe
        }, indent=2)
    except json.JSONDecodeError:
        return f"Output: {result.stdout[:2000]}\nStderr: {result.stderr[:500]}"
    except subprocess.TimeoutExpired:
        return "Analysis timed out"


if __name__ == "__main__":
    mcp.run()
