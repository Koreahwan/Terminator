#!/usr/bin/env python3
"""Runtime policy lookup tool for Terminator selective offload.

Commands:
    get-role <role>         Print full policy entry for a role.
    get-policy-summary      Print compact summary for orchestrator injection.
    list-roles              List all roles with backend assignment.
    list-group <group>      List roles in a rollback group (A/B/C).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    # Inline minimal YAML parser for environments without PyYAML.
    yaml = None  # type: ignore[assignment]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = PROJECT_ROOT / "config" / "runtime_policy.yaml"
LEGACY_PROFILE_ALIASES = {
    "hybrid": "scope-first-hybrid",
}


def _load_yaml_fallback(text: str) -> dict:
    """Minimal YAML subset parser for config/runtime_policy.yaml.

    This intentionally supports only the shapes used by the policy file:
    top-level scalars, profile defaults/role overrides, role maps, inline
    lists, and block lists. It exists so the runtime can work in lean
    environments where PyYAML is not installed.
    """

    def parse_scalar(value: str):
        value = value.strip()
        if value in ("true", "false"):
            return value == "true"
        if value == "{}":
            return {}
        if value == "[]":
            return []
        if value.startswith("[") and value.endswith("]"):
            return [
                item.strip().strip('"').strip("'")
                for item in value[1:-1].split(",")
                if item.strip()
            ]
        return value.strip('"').strip("'")

    result: dict = {"profiles": {}, "roles": {}}
    section: str | None = None
    current_profile: str | None = None
    current_profile_section: str | None = None
    current_profile_role: str | None = None
    current_role: str | None = None
    current_key: str | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        if indent == 0 and ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            if key in {"profiles", "roles"} and not val:
                section = key
                current_profile = None
                current_profile_section = None
                current_profile_role = None
                current_role = None
                current_key = None
            else:
                result[key] = parse_scalar(val)
            continue

        if section == "profiles":
            if indent == 2 and stripped.endswith(":"):
                current_profile = stripped[:-1]
                result["profiles"][current_profile] = {}
                current_profile_section = None
                current_profile_role = None
                continue

            if indent == 4 and current_profile and ":" in stripped:
                key, _, val = stripped.partition(":")
                key = key.strip()
                val = val.strip()
                current_profile_section = key
                current_profile_role = None
                result["profiles"][current_profile][key] = parse_scalar(val) if val else {}
                continue

            if indent == 6 and current_profile and current_profile_section == "defaults" and ":" in stripped:
                key, _, val = stripped.partition(":")
                result["profiles"][current_profile].setdefault("defaults", {})[key.strip()] = parse_scalar(val)
                continue

            if indent == 6 and current_profile and current_profile_section == "roles" and stripped.endswith(":"):
                current_profile_role = stripped[:-1]
                result["profiles"][current_profile].setdefault("roles", {})[current_profile_role] = {}
                continue

            if indent == 8 and current_profile and current_profile_role and ":" in stripped:
                key, _, val = stripped.partition(":")
                result["profiles"][current_profile].setdefault("roles", {}).setdefault(current_profile_role, {})[
                    key.strip()
                ] = parse_scalar(val)
                continue

        if section != "roles":
            continue

        if indent == 2 and stripped.endswith(":"):
            current_role = stripped[:-1]
            result["roles"][current_role] = {}
            current_key = None
            continue

        if indent == 4 and current_role and ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            parsed = parse_scalar(val)
            if val == "":
                result["roles"][current_role][key] = []
                current_key = key
            else:
                result["roles"][current_role][key] = parsed
                current_key = None
            continue

        if indent == 6 and stripped.startswith("- ") and current_role and current_key:
            item = stripped[2:].strip().strip('"').strip("'")
            result["roles"][current_role][current_key].append(item)
            continue

    return result


def load_policy(path: Path | None = None) -> dict:
    """Load runtime policy YAML and return parsed dict."""
    policy_path = path or DEFAULT_POLICY_PATH
    if not policy_path.exists():
        print(f"ERROR: Policy file not found: {policy_path}", file=sys.stderr)
        sys.exit(1)

    text = policy_path.read_text(encoding="utf-8")

    if yaml is not None:
        return yaml.safe_load(text)
    return _load_yaml_fallback(text)


def resolve_profile_name(policy: dict, explicit: str | None = None) -> str:
    value = (explicit or "").strip() or ""
    if value:
        return LEGACY_PROFILE_ALIASES.get(value, value)
    import os

    env_value = os.environ.get("TERMINATOR_RUNTIME_PROFILE", "").strip()
    if env_value:
        return LEGACY_PROFILE_ALIASES.get(env_value, env_value)
    default = str(policy.get("default_profile") or "scope-first-hybrid")
    return LEGACY_PROFILE_ALIASES.get(default, default)


def apply_profile(policy: dict, profile_name: str | None = None) -> dict:
    """Return a copy of the policy with profile overrides applied."""
    import copy

    resolved = resolve_profile_name(policy, profile_name)
    merged = copy.deepcopy(policy)
    roles = merged.get("roles", {}) or {}
    profiles = merged.get("profiles", {}) or {}
    if resolved not in profiles:
        raise ValueError(f"Unknown runtime profile: {resolved}")
    profile = profiles.get(resolved, {}) or {}
    defaults = profile.get("defaults", {}) or {}
    role_overrides = profile.get("roles", {}) or {}

    for name, entry in roles.items():
        for key, value in defaults.items():
            entry[key] = value
        for key, value in (role_overrides.get(name, {}) or {}).items():
            entry[key] = value
        entry["runtime_profile"] = resolved

    merged["active_profile"] = resolved
    return merged


def get_role(policy: dict, role_name: str) -> dict | None:
    """Return the policy entry for a specific role, or None."""
    roles = policy.get("roles", {})
    return roles.get(role_name)


def format_role_json(role_name: str, entry: dict) -> str:
    """Format a role entry as JSON."""
    output = {"role": role_name, **entry}
    return json.dumps(output, indent=2, ensure_ascii=False)


def build_policy_summary(policy: dict) -> str:
    """Build a compact policy summary for orchestrator prompt injection.

    Format: one line per role with key flags, grouped by backend.
    Designed to be small enough to fit in the orchestrator's prompt header.
    """
    roles = policy.get("roles", {})
    lines: list[str] = []
    lines.append("# Runtime Policy Summary")
    lines.append(f"# schema_version: {policy.get('schema_version', '?')}")
    lines.append(f"# active_profile: {policy.get('active_profile', policy.get('default_profile', '?'))}")
    lines.append("")

    # Group by backend
    by_backend: dict[str, list[tuple[str, dict]]] = {}
    for name, entry in sorted(roles.items()):
        backend = entry.get("backend", "claude")
        by_backend.setdefault(backend, []).append((name, entry))

    for backend in ["codex", "claude"]:
        entries = by_backend.get(backend, [])
        if not entries:
            continue
        lines.append(f"## {backend.upper()} roles")
        for name, entry in entries:
            model = entry.get("model", "?")
            phase = entry.get("phase_class", "?")
            shadow = entry.get("shadow_mode", "disabled")
            fallback = "fallback-ok" if entry.get("claude_fallback_allowed") else "no-fallback"
            disagree = entry.get("disagreement_policy", "disabled")
            group = entry.get("rollback_group", "none")

            flags = [phase]
            if shadow != "disabled":
                flags.append(f"shadow={shadow}")
            if fallback == "fallback-ok" and backend == "codex":
                flags.append(fallback)
            if disagree != "disabled":
                flags.append(f"disagree={disagree}")
            if group != "none":
                flags.append(f"group={group}")

            parity = entry.get("mcp_parity_required", [])
            if parity:
                flags.append(f"parity-needs=[{','.join(parity)}]")

            lines.append(f"  {name}: model={model} {' '.join(flags)}")
        lines.append("")

    return "\n".join(lines)


def list_group(policy: dict, group: str) -> list[tuple[str, dict]]:
    """List roles in a rollback group."""
    roles = policy.get("roles", {})
    return [
        (name, entry) for name, entry in sorted(roles.items())
        if entry.get("rollback_group") == group
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Runtime policy lookup for Terminator selective offload."
    )
    parser.add_argument("--policy-file", type=Path, default=None,
                        help="Override policy YAML path")
    parser.add_argument("--profile", default=None,
                        help="Runtime profile: claude-only | gpt-only | scope-first-hybrid")
    sub = parser.add_subparsers(dest="command", required=True)

    get = sub.add_parser("get-role", help="Print full policy entry for a role")
    get.add_argument("role", help="Role name (e.g. patch-hunter)")

    sub.add_parser("get-policy-summary",
                    help="Print compact summary for orchestrator injection")

    sub.add_parser("list-roles", help="List all roles with backend assignment")

    lg = sub.add_parser("list-group", help="List roles in a rollback group")
    lg.add_argument("group", help="Group name (A/B/C)")

    args = parser.parse_args()
    policy = apply_profile(load_policy(args.policy_file), args.profile)

    if args.command == "get-role":
        entry = get_role(policy, args.role)
        if entry is None:
            print(f"ERROR: Role '{args.role}' not found in policy.", file=sys.stderr)
            return 1
        print(format_role_json(args.role, entry))
        return 0

    if args.command == "get-policy-summary":
        print(build_policy_summary(policy))
        return 0

    if args.command == "list-roles":
        roles = policy.get("roles", {})
        print(f"{'Role':<22} {'Backend':<8} {'Model':<8} {'Phase Class':<20} {'Group':<6}")
        print("-" * 70)
        for name, entry in sorted(roles.items()):
            print(
                f"{name:<22} {entry.get('backend','?'):<8} "
                f"{entry.get('model','?'):<8} {entry.get('phase_class','?'):<20} "
                f"{entry.get('rollback_group','none'):<6}"
            )
        return 0

    if args.command == "list-group":
        members = list_group(policy, args.group)
        if not members:
            print(f"No roles in group {args.group}.")
            return 0
        for name, entry in members:
            print(f"  {name}: backend={entry.get('backend')}, model={entry.get('model')}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
