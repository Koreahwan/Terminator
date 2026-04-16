#!/usr/bin/env python3
"""MCP server for CodeQL semantic code analysis and variant analysis."""
import subprocess
import json
import os
import tempfile
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("codeql-mcp")

CODEQL_BIN = os.path.expanduser("~/tools/codeql/codeql")
CODEQL_DIR = os.path.expanduser("~/tools/codeql/")


def run_codeql(args: list, timeout: int = 600) -> tuple[str, str, int]:
    """Run a CodeQL command and return stdout, stderr, returncode."""
    result = subprocess.run(
        [CODEQL_BIN] + args,
        capture_output=True,
        text=True,
        timeout=timeout
    )
    return result.stdout, result.stderr, result.returncode


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False))
def create_database(source_dir: str, db_path: str, language: str = "python") -> str:
    """Create a CodeQL database from source code.

    Args:
        source_dir: Path to source code directory
        db_path: Output database path
        language: Programming language (python, javascript, java, cpp, csharp, go, ruby)
    """
    if not os.path.exists(source_dir):
        return f"Source directory not found: {source_dir}"

    cmd = [
        "database", "create",
        db_path,
        f"--language={language}",
        f"--source-root={source_dir}",
        "--overwrite"
    ]

    try:
        stdout, stderr, rc = run_codeql(cmd, timeout=900)
        if rc == 0:
            return f"Database created at {db_path}\n{stdout[:1000]}"
        else:
            return f"Failed (rc={rc}):\n{stderr[:2000]}"
    except subprocess.TimeoutExpired:
        return "Database creation timed out (>900s)"
    except FileNotFoundError:
        return f"CodeQL not found at {CODEQL_BIN}"


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def run_query(db_path: str, query: str = "", query_file: str = "", output_format: str = "csv") -> str:
    """Run a CodeQL query against a database.

    Args:
        db_path: Path to CodeQL database
        query: Inline CodeQL query string (will be written to temp file)
        query_file: Path to existing .ql query file (overrides query param)
        output_format: Output format: csv, sarif, json (default: csv)
    """
    if not os.path.exists(db_path):
        return f"Database not found: {db_path}"

    tmp_query = None
    try:
        if query_file and os.path.exists(query_file):
            ql_file = query_file
        elif query:
            # Write inline query to temp file
            tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.ql', delete=False)
            tmp.write(query)
            tmp.close()
            tmp_query = tmp.name
            ql_file = tmp_query
        else:
            return "Either query or query_file must be provided"

        output_file = tempfile.mktemp(suffix=f".{output_format}")

        cmd = [
            "query", "run",
            "--database", db_path,
            "--output", output_file,
            "--format", output_format,
            ql_file
        ]

        stdout, stderr, rc = run_codeql(cmd, timeout=300)

        if rc == 0 and os.path.exists(output_file):
            with open(output_file) as f:
                result = f.read()
            os.unlink(output_file)
            return result[:5000]
        else:
            return f"Query failed (rc={rc}):\nstdout: {stdout[:1000]}\nstderr: {stderr[:1000]}"

    except subprocess.TimeoutExpired:
        return "Query timed out (>300s)"
    finally:
        if tmp_query and os.path.exists(tmp_query):
            os.unlink(tmp_query)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def list_queries(language: str = "", category: str = "") -> str:
    """List available CodeQL queries.

    Args:
        language: Filter by language (python, javascript, java, cpp, etc.)
        category: Filter by category (security, correctness, etc.)
    """
    search_root = CODEQL_DIR

    # Find .ql files
    find_cmd = ["find", search_root, "-name", "*.ql", "-type", "f"]
    if language:
        find_cmd += ["-path", f"*/{language}/*"]

    result = subprocess.run(find_cmd, capture_output=True, text=True, timeout=30)
    files = result.stdout.strip().splitlines()

    if category:
        files = [f for f in files if category.lower() in f.lower()]

    # Format output
    query_list = []
    for f in files[:100]:
        rel = os.path.relpath(f, search_root)
        query_list.append(rel)

    return json.dumps({
        "count": len(files),
        "shown": len(query_list),
        "queries": query_list
    }, indent=2)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def analyze(db_path: str, language: str = "python", suite: str = "security") -> str:
    """Run CodeQL analysis with a standard query suite.

    Args:
        db_path: Path to CodeQL database
        language: Language of the database
        suite: Query suite: security, security-extended, security-and-quality
    """
    if not os.path.exists(db_path):
        return f"Database not found: {db_path}"

    output_file = tempfile.mktemp(suffix=".sarif")

    cmd = [
        "database", "analyze",
        db_path,
        f"{language}-{suite}",
        "--format=sarif-latest",
        f"--output={output_file}",
        "--no-print-metrics"
    ]

    try:
        stdout, stderr, rc = run_codeql(cmd, timeout=600)

        if rc == 0 and os.path.exists(output_file):
            with open(output_file) as f:
                sarif = json.load(f)

            # Extract key findings
            findings = []
            for run in sarif.get("runs", []):
                for result in run.get("results", [])[:50]:
                    findings.append({
                        "rule": result.get("ruleId", ""),
                        "message": result.get("message", {}).get("text", ""),
                        "severity": result.get("level", ""),
                        "location": result.get("locations", [{}])[0].get(
                            "physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                    })
            os.unlink(output_file)
            return json.dumps({
                "total_findings": len(findings),
                "findings": findings
            }, indent=2)
        else:
            return f"Analysis failed (rc={rc}):\n{stderr[:2000]}"
    except subprocess.TimeoutExpired:
        return "Analysis timed out (>600s)"
    except FileNotFoundError:
        return f"CodeQL binary not found at {CODEQL_BIN}"


if __name__ == "__main__":
    mcp.run()
