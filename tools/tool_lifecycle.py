#!/usr/bin/env python3
"""Tool lifecycle manager — install, check, update, audit security tools.

Inspired by katoolin (category-based batch install) + AIDA (health checks).
Reads tools/toolspec/tools_full.yaml as the canonical tool registry.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools.toolspec.registry import ToolRegistry, ToolSpec  # noqa: E402

TOOLS_YAML = PROJECT_ROOT / "tools" / "toolspec" / "tools_full.yaml"
KALI_LIST = Path("/etc/apt/sources.list.d/kali.list")
KALI_KEY_URL = "https://archive.kali.org/archive-key.asc"
KALI_REPO_LINE = "deb [signed-by=/etc/apt/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main non-free non-free-firmware"

PIPELINE_CATEGORIES = {
    "bounty": ["recon", "web", "scanning", "password", "sniffing", "exploit",
               "post_exploit", "analysis", "infra"],
    "client-pitch": ["recon", "web", "analysis"],
    "ai_security": ["recon", "web", "scanning", "ai"],
    "ai-security": ["recon", "web", "scanning", "ai"],
}


def _expand_home(p: str) -> str:
    return os.path.expanduser(p) if p else ""


def _resolve_binary(spec: ToolSpec) -> Optional[str]:
    """Find the actual binary path for a tool."""
    if spec.binary_path:
        expanded = _expand_home(spec.binary_path)
        import glob
        matches = glob.glob(expanded)
        if matches:
            return matches[0]
        if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
            return expanded
    return shutil.which(spec.entrypoint) if spec.entrypoint else None


def _run_quiet(cmd: str, timeout: int = 10) -> tuple[int, str]:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode, (r.stdout + r.stderr).strip()[:200]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return -1, ""


class ToolStatus:
    def __init__(self, spec: ToolSpec):
        self.spec = spec
        self.binary_found: Optional[str] = None
        self.version: str = ""
        self.status: str = "UNKNOWN"

    def check(self) -> "ToolStatus":
        self.binary_found = _resolve_binary(self.spec)
        if not self.binary_found:
            self.status = "MISSING"
            return self
        if self.spec.version_cmd:
            code, out = _run_quiet(self.spec.version_cmd)
            if code == 0 or out:
                self.version = out.split("\n")[0][:80]
                self.status = "INSTALLED"
            else:
                self.status = "ERROR"
        else:
            self.status = "INSTALLED"
        return self

    def to_dict(self) -> dict:
        return {
            "tool_id": self.spec.tool_id,
            "name": self.spec.name,
            "category": self.spec.category,
            "status": self.status,
            "version": self.version,
            "binary": self.binary_found or "",
            "install_method": self.spec.install_method,
        }


def _load_registry() -> ToolRegistry:
    if not TOOLS_YAML.exists():
        print(f"ERROR: {TOOLS_YAML} not found", file=sys.stderr)
        sys.exit(1)
    return ToolRegistry(registry_path=TOOLS_YAML)


def _filter_tools(reg: ToolRegistry, category: str = "",
                  pipeline: str = "", tool_ids: list = None) -> List[ToolSpec]:
    if tool_ids:
        return [reg.get(t) for t in tool_ids if reg.get(t)]
    if pipeline:
        if pipeline not in PIPELINE_CATEGORIES:
            return []
        cats = PIPELINE_CATEGORIES.get(pipeline, [])
        result = []
        seen = set()
        for cat in cats:
            for t in reg.find_by_category(cat):
                if t.tool_id not in seen:
                    result.append(t)
                    seen.add(t.tool_id)
        for t in reg.find_by_pipeline(pipeline):
            if t.tool_id not in seen:
                result.append(t)
                seen.add(t.tool_id)
        return result
    if category:
        return reg.find_by_category(category)
    return reg.list_all()


# ── Commands ─────────────────────────────────────────────

def cmd_check(args):
    reg = _load_registry()
    tools = _filter_tools(reg, args.category, args.pipeline, args.tool_ids)
    results = [ToolStatus(t).check() for t in tools]
    installed = sum(1 for r in results if r.status == "INSTALLED")
    missing = sum(1 for r in results if r.status == "MISSING")

    if args.json:
        print(json.dumps({
            "total": len(results),
            "installed": installed,
            "missing": missing,
            "tools": [r.to_dict() for r in results],
        }, indent=2))
    else:
        print(f"\n{'Tool':<25} {'Category':<15} {'Status':<12} {'Version'}")
        print("-" * 80)
        for r in sorted(results, key=lambda x: (x.status != "MISSING", x.spec.category)):
            sym = {"INSTALLED": "+", "MISSING": "!", "ERROR": "?", "UNKNOWN": "~"}.get(r.status, " ")
            print(f"  [{sym}] {r.spec.tool_id:<22} {r.spec.category:<15} {r.status:<12} {r.version[:35]}")
        print(f"\n  Total: {len(results)} | Installed: {installed} | Missing: {missing}")

    sys.exit(1 if missing > 0 else 0)


def cmd_install(args):
    reg = _load_registry()
    if args.all:
        tools = reg.list_all()
    else:
        tools = _filter_tools(reg, args.category, args.pipeline, args.tool_ids)

    to_install = []
    for t in tools:
        s = ToolStatus(t).check()
        if s.status == "MISSING":
            to_install.append(t)

    if not to_install:
        print("All tools already installed.")
        return

    print(f"\n{len(to_install)} tools to install:")
    by_method = {}
    for t in to_install:
        by_method.setdefault(t.install_method, []).append(t)
        print(f"  {t.tool_id:<25} [{t.install_method}] {t.install_cmd}")

    if not args.yes:
        ans = input(f"\nProceed? [y/N] ")
        if ans.lower() != "y":
            print("Aborted.")
            return

    apt_tools = by_method.get("apt", [])
    if apt_tools:
        if not _kali_repo_exists() and any(
            t.category in ("password", "exploit", "sniffing", "post_exploit", "wireless")
            for t in apt_tools
        ):
            print("\nSome tools need Kali repos. Run: tool_lifecycle.py repo add-kali")

        pkgs = [t.install_cmd for t in apt_tools]
        print(f"\n[apt] Installing: {' '.join(pkgs)}")
        subprocess.run(["sudo", "apt-get", "update", "-qq"], check=False)
        subprocess.run(["sudo", "apt-get", "install", "-y", "-qq"] + pkgs, check=False)

    for t in by_method.get("pip", []):
        print(f"\n[pip] Installing: {t.install_cmd}")
        subprocess.run(["pip", "install", "--user", "--quiet", t.install_cmd], check=False)

    for t in by_method.get("go_install", []):
        print(f"\n[go] Installing: {t.install_cmd}")
        subprocess.run(["go", "install", t.install_cmd], check=False)

    for t in by_method.get("cargo", []):
        print(f"\n[cargo] Installing: {t.install_cmd}")
        subprocess.run(["cargo", "install", t.install_cmd], check=False)

    for t in by_method.get("npm", []):
        print(f"\n[npm] Installing: {t.install_cmd}")
        subprocess.run(["npm", "install", "-g", t.install_cmd], check=False)

    for t in by_method.get("gem", []):
        print(f"\n[gem] Installing: {t.install_cmd}")
        subprocess.run(["gem", "install", t.install_cmd], check=False)

    for t in by_method.get("git", []):
        dest = _expand_home(t.binary_path)
        if not os.path.exists(dest):
            print(f"\n[git] Cloning: {t.install_cmd} → {dest}")
            subprocess.run(["git", "clone", "--depth", "1", t.install_cmd, dest], check=False)

    for t in by_method.get("manual", []):
        print(f"\n[manual] {t.tool_id}: {t.install_cmd}")

    print("\nDone. Run 'tool_lifecycle.py check' to verify.")


def cmd_list(args):
    reg = _load_registry()
    tools = _filter_tools(reg, args.category, args.pipeline)

    if args.missing_only:
        tools = [t for t in tools if ToolStatus(t).check().status == "MISSING"]

    if args.json:
        print(json.dumps([{
            "tool_id": t.tool_id, "name": t.name, "category": t.category,
            "install_method": t.install_method, "pipelines": t.pipelines,
        } for t in tools], indent=2))
    else:
        cats = {}
        for t in tools:
            cats.setdefault(t.category, []).append(t)
        for cat in sorted(cats):
            print(f"\n  [{cat}] ({len(cats[cat])} tools)")
            for t in cats[cat]:
                print(f"    {t.tool_id:<25} {t.description[:50]}")
        print(f"\n  Total: {len(tools)} tools")


def cmd_report(args):
    reg = _load_registry()
    results = [ToolStatus(t).check() for t in reg.list_all()]
    lines = [
        "# Installed Tools Reference",
        "",
        f"Auto-generated by `tool_lifecycle.py report` | Total: {len(results)} tools",
        "",
        "| Tool | Category | Status | Version | Install Method |",
        "|------|----------|--------|---------|----------------|",
    ]
    for r in sorted(results, key=lambda x: (x.spec.category, x.spec.tool_id)):
        lines.append(
            f"| {r.spec.tool_id} | {r.spec.category} | {r.status} | "
            f"{r.version[:40]} | {r.spec.install_method} |"
        )

    out = PROJECT_ROOT / "knowledge" / "techniques" / "installed_tools_reference.md"
    if args.stdout:
        print("\n".join(lines))
    else:
        out.write_text("\n".join(lines) + "\n")
        print(f"Written to {out}")


def cmd_audit(args):
    print("Running integration audit + toolspec cross-reference...\n")
    audit_script = PROJECT_ROOT / "tools" / "integration_audit.py"
    if audit_script.exists():
        subprocess.run(f"python3 {audit_script}", shell=True, check=False)
    else:
        print("  integration_audit.py not found, skipping.\n")

    reg = _load_registry()
    results = [ToolStatus(t).check() for t in reg.list_all()]
    missing = [r for r in results if r.status == "MISSING"]
    if missing:
        print(f"\n[toolspec] {len(missing)} tools registered but not installed:")
        for r in missing:
            print(f"  ! {r.spec.tool_id:<25} [{r.spec.install_method}] {r.spec.category}")
    else:
        print(f"\n[toolspec] All {len(results)} registered tools are installed.")


# ── Kali Repo Management (D-1, katoolin pattern) ────────

def _kali_repo_exists() -> bool:
    return KALI_LIST.exists() and KALI_LIST.read_text().strip() != ""


def cmd_repo(args):
    action = args.repo_action
    if action == "status":
        if _kali_repo_exists():
            print(f"Kali repo: ACTIVE ({KALI_LIST})")
            print(f"  Content: {KALI_LIST.read_text().strip()}")
        else:
            print("Kali repo: NOT CONFIGURED")

    elif action == "add-kali":
        if _kali_repo_exists():
            print("Kali repo already configured.")
            return
        print("Adding Kali Linux repository...")
        subprocess.run(["sudo", "mkdir", "-p", "/etc/apt/keyrings"], check=False)
        subprocess.run(f"wget -q -O - {KALI_KEY_URL} | sudo tee /etc/apt/keyrings/kali-archive-keyring.gpg > /dev/null", shell=True, check=False)
        subprocess.run(f'echo "{KALI_REPO_LINE}" | sudo tee {KALI_LIST}', shell=True, check=False)
        subprocess.run("sudo apt-get update -qq", shell=True, check=False)
        print("Kali repo added. WARNING: Remove before system updates (repo remove-kali).")

    elif action == "remove-kali":
        if not _kali_repo_exists():
            print("Kali repo not configured.")
            return
        subprocess.run(f"sudo rm -f {KALI_LIST}", shell=True, check=False)
        subprocess.run("sudo apt-get update -qq", shell=True, check=False)
        print("Kali repo removed. Safe to run system updates.")


# ── Main ─────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        prog="tool_lifecycle.py",
        description="Terminator tool lifecycle manager (katoolin + AIDA inspired)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          %(prog)s check --pipeline bounty
          %(prog)s install --category password --yes
          %(prog)s install --pipeline client-pitch
          %(prog)s list --missing-only
          %(prog)s repo add-kali
          %(prog)s report
          %(prog)s audit
        """),
    )
    sub = p.add_subparsers(dest="command", required=True)

    # check
    s = sub.add_parser("check", help="Check tool health/installation status")
    s.add_argument("--category", default="")
    s.add_argument("--pipeline", default="")
    s.add_argument("--json", action="store_true")
    s.add_argument("tool_ids", nargs="*", default=[])

    # install
    s = sub.add_parser("install", help="Install missing tools")
    s.add_argument("--category", default="")
    s.add_argument("--pipeline", default="")
    s.add_argument("--all", action="store_true")
    s.add_argument("--yes", "-y", action="store_true")
    s.add_argument("tool_ids", nargs="*", default=[])

    # list
    s = sub.add_parser("list", help="List registered tools")
    s.add_argument("--category", default="")
    s.add_argument("--pipeline", default="")
    s.add_argument("--missing-only", action="store_true")
    s.add_argument("--json", action="store_true")

    # report
    s = sub.add_parser("report", help="Generate installed_tools_reference.md")
    s.add_argument("--stdout", action="store_true")

    # audit
    sub.add_parser("audit", help="Run integration audit + toolspec cross-reference")

    # repo
    s = sub.add_parser("repo", help="Manage Kali Linux repository (katoolin)")
    s.add_argument("repo_action", choices=["add-kali", "remove-kali", "status"])

    args = p.parse_args()
    {
        "check": cmd_check,
        "install": cmd_install,
        "list": cmd_list,
        "report": cmd_report,
        "audit": cmd_audit,
        "repo": cmd_repo,
    }[args.command](args)


if __name__ == "__main__":
    main()
