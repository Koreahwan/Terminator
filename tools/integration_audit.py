#!/usr/bin/env python3
"""integration_audit.py — cross-verify tool installation vs code wiring vs docs.

Detects drift between what's installed (pip / npm / docker / binaries / submodules)
and what's referenced in CLAUDE.md / .mcp.json / .claude/agents/*.md / tools/.

Usage:
    python3 tools/integration_audit.py           # print table to stdout
    python3 tools/integration_audit.py --json    # machine-readable
    python3 tools/integration_audit.py --write   # write docs/integration-gaps.md

Exit codes: 0=PASS, 1=medium gaps, 2=high gaps (broken submodule / missing wiring).

Rationale: 2026-04-17 firecrawl + flaresolverr + markitdown-mcp were installed
without CLAUDE.md / agent / transport wiring. This tool catches that class of
drift before it bites the pipeline.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


def sh(cmd: str) -> str:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, check=False, timeout=30
        )
        return r.stdout or ""
    except Exception:
        return ""


def _claude_md() -> str:
    try:
        return (ROOT / "CLAUDE.md").read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def check_submodules() -> list[dict]:
    """Compare .gitmodules mappings vs git index gitlinks + empty dirs."""
    gaps: list[dict] = []
    gm_paths: set[str] = set()
    gm = ROOT / ".gitmodules"
    if gm.exists():
        for m in re.finditer(r"path\s*=\s*([^\n]+)", gm.read_text(encoding="utf-8", errors="replace")):
            gm_paths.add(m.group(1).strip())
    out = sh(f"cd {ROOT} && git ls-files --stage 2>/dev/null")
    for line in out.splitlines():
        if line.startswith("160000"):
            parts = line.split(None, 3)
            if len(parts) >= 4:
                path = parts[3].strip()
                if path not in gm_paths:
                    gaps.append({
                        "category": "submodule",
                        "severity": "high",
                        "path": path,
                        "issue": "gitlink present but missing .gitmodules entry (orphan)",
                    })
    for p in gm_paths:
        full = ROOT / p
        if full.is_dir():
            try:
                if not any(full.iterdir()):
                    gaps.append({
                        "category": "submodule",
                        "severity": "medium",
                        "path": p,
                        "issue": ".gitmodules entry exists but directory is empty (run `git submodule update --init`)",
                    })
            except Exception:
                pass
    return gaps


def _normalize_mcp_name(n: str) -> str:
    """Strip common suffix aliases so `.mcp.json` IDs and CLAUDE.md labels
    compare apples-to-apples. `nuclei-mcp` (server id) vs `nuclei` (prose name)."""
    return re.sub(r"-mcp$", "", n.strip().lower())


def check_mcp() -> list[dict]:
    gaps: list[dict] = []
    mcp_config = ROOT / ".mcp.json"
    registered_raw: set[str] = set()
    if mcp_config.exists():
        try:
            d = json.loads(mcp_config.read_text(encoding="utf-8"))
            registered_raw = set(d.get("mcpServers", {}).keys())
        except Exception as e:
            gaps.append({"category": "mcp", "severity": "high", "name": ".mcp.json", "issue": f"parse error: {e}"})
    registered = {_normalize_mcp_name(n): n for n in registered_raw}
    claude_md = _claude_md()
    claim_raw: set[str] = set()
    m = re.search(r"\*\*MCP[^\n]*?\*\*:\s*([^\n]+)", claude_md)
    if m:
        text = m.group(1)
        for chunk in text.split(","):
            short = re.split(r"[\s(.]", chunk.strip(), 1)[0]
            if short and re.match(r"^[a-zA-Z0-9_-]+$", short):
                claim_raw.add(short)
    claim = {_normalize_mcp_name(n): n for n in claim_raw}
    for key in sorted(set(claim) - set(registered)):
        gaps.append({
            "category": "mcp",
            "severity": "low",
            "name": claim[key],
            "issue": "listed in CLAUDE.md but not in .mcp.json (install-only / plugin-provided / aspirational)",
        })
    for key in sorted(set(registered) - set(claim)):
        gaps.append({
            "category": "mcp",
            "severity": "medium",
            "name": registered[key],
            "issue": ".mcp.json registers but CLAUDE.md doesn't mention",
        })
    return gaps


def check_docker() -> list[dict]:
    gaps: list[dict] = []
    out = sh("docker ps --format '{{.Names}}|{{.Image}}' 2>/dev/null")
    claude_md = _claude_md()
    for line in out.splitlines():
        if "|" not in line:
            continue
        name, image = line.split("|", 1)
        name, image = name.strip(), image.strip()
        mentioned = (
            name in claude_md
            or image.split(":")[0].split("/")[-1] in claude_md.lower()
        )
        if not mentioned:
            ref = sh(
                f"grep -ErlI '{re.escape(name)}' {ROOT}/tools {ROOT}/scripts {ROOT}/.claude 2>/dev/null | head -3"
            )
            if ref.strip():
                mentioned = True
        if not mentioned:
            gaps.append({
                "category": "docker",
                "severity": "medium",
                "name": name,
                "image": image,
                "issue": "running container not mentioned in CLAUDE.md / tools / scripts / .claude",
            })
    return gaps


def check_python_pkgs() -> list[dict]:
    """Python user-site pkgs installed in last 3 days — check wiring + mention."""
    gaps: list[dict] = []
    out = sh(
        "find /home/hw/.local/lib/python3.12/site-packages -maxdepth 1 -type d -mtime -3 -printf '%f\\n' 2>/dev/null"
    )
    claude_md_lower = _claude_md().lower()
    for line in out.splitlines():
        name = line.strip()
        if not name or name.endswith(".dist-info") or name == "site-packages" or name == "tests":
            continue
        mod = name.replace("-", "_")
        rg = sh(
            f"grep -ErlI 'import\\s+{re.escape(mod)}|from\\s+{re.escape(mod)}' "
            f"{ROOT}/tools {ROOT}/.claude {ROOT}/scripts 2>/dev/null | head -3"
        )
        used = bool(rg.strip())
        mentioned = mod in claude_md_lower or name.lower() in claude_md_lower
        if not used and not mentioned:
            gaps.append({
                "category": "python-pkg",
                "severity": "low",
                "name": name,
                "issue": "recent install, no imports in tools/.claude/scripts, no CLAUDE.md mention",
            })
        elif used and not mentioned:
            gaps.append({
                "category": "python-pkg",
                "severity": "info",
                "name": name,
                "issue": "wired in code but missing CLAUDE.md Tools Reference entry",
            })
    return gaps


_BIN_SKIP = {
    # Dev tooling / shell helpers — not in scope for CLAUDE.md Tools Reference.
    "uv", "uvx", "pip", "pipx", "git-filter-repo", "winbrowser",
    "watchmedo",  # watchdog Python CLI, not a security tool
    "ralph",      # OMC harness binary
    "node", "npm", "yarn", "pnpm",
    "python3", "python",
}


def check_bin_tools() -> list[dict]:
    gaps: list[dict] = []
    out = sh(
        "find /home/hw/.local/bin -maxdepth 1 -type f -mtime -3 -printf '%f\\n' 2>/dev/null"
    )
    claude_md = _claude_md()
    for line in out.splitlines():
        b = line.strip()
        if not b or b in _BIN_SKIP:
            continue
        if b in claude_md:
            continue
        ref = sh(f"grep -ErlI '{re.escape(b)}' {ROOT}/.claude/agents 2>/dev/null | head -1")
        if ref.strip():
            continue
        gaps.append({
            "category": "bin",
            "severity": "low",
            "name": b,
            "issue": "recent ~/.local/bin install, not in CLAUDE.md or any agent file",
        })
    return gaps


def check_script_refs() -> list[dict]:
    """Scan terminator.sh + scripts/*.sh for `python3 tools/*.py` /
    `bash scripts/*.sh` references, flag any that don't exist on disk.

    Catches the v13.5.3 class of gap: pyc cache exists but source .py was
    rewritten out of git history by filter-repo, leaving shell scripts
    pointing at non-existent files. 4 days of broken autonomous pipeline
    would have been caught here on day 0."""
    gaps: list[dict] = []
    script_paths: list[Path] = []
    for p in [ROOT / "terminator.sh"]:
        if p.exists():
            script_paths.append(p)
    scripts_dir = ROOT / "scripts"
    if scripts_dir.is_dir():
        script_paths.extend(scripts_dir.glob("*.sh"))

    # Match: python3 [flags] [$SCRIPT_DIR/]tools/xxx.py or bash [$SCRIPT_DIR/]scripts/xxx.sh
    ref_pat = re.compile(
        r"""(?:python3?|bash)\s+                # interpreter
            (?:-\w+\s+)*                         # optional flags like -u
            ["']?                                # optional quote
            (?:\$\{?SCRIPT_DIR\}?/)?             # optional $SCRIPT_DIR prefix
            ((?:tools|scripts)/[\w/.-]+\.(?:py|sh))  # captured path
        """,
        re.VERBOSE,
    )
    seen: set[tuple[str, str]] = set()
    for sh in script_paths:
        try:
            content = sh.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in ref_pat.finditer(content):
            path = m.group(1)
            rel = sh.relative_to(ROOT)
            key = (str(rel), path)
            if key in seen:
                continue
            seen.add(key)
            target = ROOT / path
            if not target.exists():
                gaps.append({
                    "category": "script-ref",
                    "severity": "high",
                    "script": str(rel),
                    "missing_path": path,
                    "issue": "script references a file that does not exist on disk (filter-repo drift? uncommitted dep?)",
                })
    return gaps


def check_recent_commits() -> list[dict]:
    """feat/install commits in last 3 days with 0 keyword overlap in CLAUDE.md."""
    gaps: list[dict] = []
    out = sh(f"cd {ROOT} && git log --oneline --since='3 days ago' 2>/dev/null")
    claude_md_lower = _claude_md().lower()
    for line in out.splitlines():
        m = re.match(r"^(\S+)\s+(.+)$", line.strip())
        if not m:
            continue
        sha, msg = m.groups()
        lower = msg.lower()
        if not (lower.startswith("feat") or "install" in lower):
            continue
        tokens = [t for t in re.findall(r"[a-z][a-z0-9_-]{4,}", lower) if t not in {"feat", "install", "tools", "docs", "update", "commit", "claude"}]
        hits = sum(1 for t in tokens[:8] if t in claude_md_lower)
        if hits == 0 and tokens:
            gaps.append({
                "category": "commit",
                "severity": "info",
                "sha": sha,
                "msg": msg[:80],
                "issue": f"recent feat/install commit keywords ({','.join(tokens[:4])}) absent from CLAUDE.md",
            })
    return gaps


def render_markdown(gaps: list[dict], by_sev: dict[str, list[dict]]) -> str:
    lines = ["# Integration Audit Gaps", ""]
    lines.append("Generated by `tools/integration_audit.py`. Re-run after install / upgrade to verify integration.")
    lines.append("")
    stats = "  ".join(f"**{sev}**={len(by_sev.get(sev, []))}" for sev in ("high", "medium", "low", "info"))
    lines.append(f"Total: {len(gaps)}  |  {stats}")
    lines.append("")
    for sev in ("high", "medium", "low", "info"):
        items = by_sev.get(sev, [])
        if not items:
            continue
        lines.append(f"## {sev.upper()} ({len(items)})")
        lines.append("")
        for g in items:
            body = ", ".join(f"{k}=`{v}`" for k, v in g.items() if k not in ("category", "severity"))
            lines.append(f"- **[{g['category']}]** {body}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--write", action="store_true", help="write docs/integration-gaps.md")
    args = ap.parse_args()

    all_gaps: list[dict] = []
    for fn in (check_submodules, check_mcp, check_docker, check_script_refs, check_python_pkgs, check_bin_tools, check_recent_commits):
        try:
            all_gaps.extend(fn())
        except Exception as e:
            all_gaps.append({"category": "audit-error", "severity": "high", "fn": fn.__name__, "issue": str(e)})

    by_sev: dict[str, list[dict]] = {}
    for g in all_gaps:
        by_sev.setdefault(g.get("severity", "info"), []).append(g)

    if args.json:
        print(json.dumps(all_gaps, indent=2))
    else:
        print(f"# Integration Audit — {len(all_gaps)} gap(s)")
        for sev in ("high", "medium", "low", "info"):
            items = by_sev.get(sev, [])
            if not items:
                continue
            print(f"\n## {sev.upper()} ({len(items)})")
            for g in items:
                body = " | ".join(f"{k}={v}" for k, v in g.items() if k not in ("category", "severity"))
                print(f"- [{g['category']}] {body}")

    if args.write:
        out = ROOT / "docs" / "integration-gaps.md"
        out.write_text(render_markdown(all_gaps, by_sev), encoding="utf-8")
        print(f"\nWritten: {out.relative_to(ROOT)}")

    if by_sev.get("high"):
        return 2
    if by_sev.get("medium"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
