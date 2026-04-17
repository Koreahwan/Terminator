#!/usr/bin/env python3
"""Compile compact role contracts from agent definition files.

Reads .claude/agents/<role>.md and produces a compressed contract at
generated/role_contracts/<role>.txt suitable for Codex dispatch prompts.

Compression strategy:
  1. Preserve: IRON RULES, mandatory artifacts, safety rules, output format
  2. Compress: strategy steps → bullet points, verbose prose → structured summaries
  3. Drop: few-shot examples, ReAct loop examples, verbose references, frontmatter

Usage:
    python3 tools/compile_role_contracts.py compile <role>
    python3 tools/compile_role_contracts.py compile-all
    python3 tools/compile_role_contracts.py measure <role>
    python3 tools/compile_role_contracts.py drift-check <role>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AGENTS_DIR = PROJECT_ROOT / ".claude" / "agents"
OUTPUT_DIR = PROJECT_ROOT / "generated" / "role_contracts"
CONTEXT_BUDGET_CHARS = 8000  # revised after patch-hunter prototype (docs/runtime_context_budget.md)


def _parse_sections(text: str) -> list[tuple[str, str, int]]:
    """Parse markdown into (heading, body, heading_level) tuples."""
    sections: list[tuple[str, str, int]] = []
    lines = text.split("\n")
    current_heading = ""
    current_level = 0
    current_body: list[str] = []

    for line in lines:
        m = re.match(r'^(#{1,4})\s+(.*)', line)
        if m:
            if current_heading or current_body:
                sections.append((current_heading, "\n".join(current_body).strip(), current_level))
            current_heading = m.group(2).strip()
            current_level = len(m.group(1))
            current_body = []
        else:
            current_body.append(line)

    if current_heading or current_body:
        sections.append((current_heading, "\n".join(current_body).strip(), current_level))

    return sections


def _strip_frontmatter(text: str) -> str:
    """Remove YAML frontmatter from agent file."""
    if text.startswith("---"):
        end = text.find("---", 3)
        if end != -1:
            return text[end + 3:].strip()
    return text


def _is_droppable_section(heading: str) -> bool:
    """Sections that can be dropped for compaction."""
    drop_patterns = [
        r"few.shot",
        r"example\s*\d",
        r"react\s*loop",
        r"structured\s*reasoning",
        r"recap",             # Redundant with the original rules
        r"verify before",     # Recap sections
    ]
    lower = heading.lower()
    return any(re.search(p, lower) for p in drop_patterns)


def _is_preservable_section(heading: str) -> bool:
    """Sections that must never be trimmed."""
    preserve_patterns = [
        r"iron\s*rule",
        r"checkpoint",
    ]
    lower = heading.lower()
    return any(re.search(p, lower) for p in preserve_patterns)


def _is_output_template_section(heading: str) -> bool:
    """Detect output format / template sections that carry example data."""
    lower = heading.lower()
    return bool(re.search(r"output\s*format|variant\s*candidate|analyzed\s*commit|recommendation", lower))


def _compress_section(heading: str, body: str) -> str:
    """Compress a section body by removing verbose elements."""
    lines = body.split("\n")
    compressed: list[str] = []
    in_code_block = False
    code_block_lines = 0

    for line in lines:
        if line.strip().startswith("```"):
            if in_code_block:
                in_code_block = False
                compressed.append("```")
                code_block_lines = 0
                continue
            else:
                in_code_block = True
                code_block_lines = 0
                compressed.append(line)
                continue

        if in_code_block:
            stripped = line.strip()
            # Skip blank lines and pure comments in code blocks
            if not stripped or (stripped.startswith("#") and not stripped.startswith("#!")):
                continue
            code_block_lines += 1
            if code_block_lines <= 3:
                compressed.append(line)
            # Drop excess code lines silently
            continue

        # Drop empty consecutive lines
        if not line.strip() and compressed and not compressed[-1].strip():
            continue

        # Compress verbose prose: drop lines that are purely
        # contextual explanation (not bullets, not structure)
        stripped = line.strip()
        if (len(stripped) > 80
                and not stripped.startswith(("-", "*", "|", "#", ">", "1", "2", "3"))
                and not stripped.startswith("**")
                and "MANDATORY" not in stripped
                and "IRON" not in stripped):
            # Truncate long prose to first sentence
            first_sentence = re.split(r'(?<=[.!?])\s', stripped, maxsplit=1)[0]
            if len(first_sentence) < len(stripped):
                compressed.append(first_sentence)
                continue

        compressed.append(line)

    return "\n".join(compressed)


def _strip_template_examples(body: str) -> str:
    """Strip example data rows from template sections.

    Keeps table headers and structure markers but removes example data
    lines like '| abc123 | 2024-01-15 | XSS | 1 EXACT |'.
    """
    lines = body.split("\n")
    result: list[str] = []
    saw_table_header = False
    saw_separator = False

    for line in lines:
        stripped = line.strip()

        # Keep table headers and separators, drop data rows
        if stripped.startswith("|"):
            if not saw_table_header:
                result.append(line)
                saw_table_header = True
                continue
            if re.match(r'^\|[\s\-|]+\|$', stripped):
                result.append(line)
                saw_separator = True
                continue
            if saw_separator:
                # This is a data row — skip it
                continue
            result.append(line)
            continue

        # Reset table tracking on non-table lines
        if not stripped.startswith("|"):
            saw_table_header = False
            saw_separator = False

        # Skip lines that look like example placeholders
        if stripped.startswith("[Full candidate") or stripped.startswith("[Full "):
            continue

        # Drop empty consecutive lines
        if not stripped and result and not result[-1].strip():
            continue

        result.append(line)

    return "\n".join(result)


def compile_contract(role: str) -> tuple[str, dict]:
    """Compile a compact contract for a role.

    Returns (contract_text, metadata_dict).
    """
    agent_file = AGENTS_DIR / f"{role}.md"
    if not agent_file.exists():
        raise FileNotFoundError(f"Agent file not found: {agent_file}")

    raw_text = agent_file.read_text(encoding="utf-8")
    source_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()[:16]
    text = _strip_frontmatter(raw_text)
    sections = _parse_sections(text)

    contract_parts: list[str] = []
    contract_parts.append(f"# {role} — Compact Contract")
    contract_parts.append(f"# Source: .claude/agents/{role}.md (hash: {source_hash})")
    contract_parts.append(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    contract_parts.append("")

    preserved_sections: list[str] = []
    dropped_sections: list[str] = []
    compressed_sections: list[str] = []

    for heading, body, level in sections:
        if not heading and not body:
            continue

        if _is_droppable_section(heading):
            dropped_sections.append(heading)
            continue

        prefix = "#" * min(level, 3) if level > 0 else "##"

        if _is_preservable_section(heading):
            preserved_sections.append(heading)
            contract_parts.append(f"{prefix} {heading}")
            contract_parts.append(body)
            contract_parts.append("")
        elif _is_output_template_section(heading):
            # Strip example data rows, keep structure
            compressed_sections.append(heading)
            stripped = _strip_template_examples(body)
            contract_parts.append(f"{prefix} {heading}")
            contract_parts.append(stripped)
            contract_parts.append("")
        else:
            compressed_sections.append(heading)
            compressed_body = _compress_section(heading, body)
            contract_parts.append(f"{prefix} {heading}")
            contract_parts.append(compressed_body)
            contract_parts.append("")

    contract_text = "\n".join(contract_parts).strip() + "\n"

    metadata = {
        "role": role,
        "source_file": str(agent_file.relative_to(PROJECT_ROOT)),
        "source_hash": source_hash,
        "source_size_chars": len(raw_text),
        "contract_size_chars": len(contract_text),
        "budget_chars": CONTEXT_BUDGET_CHARS,
        "within_budget": len(contract_text) <= CONTEXT_BUDGET_CHARS,
        "budget_usage_pct": round(len(contract_text) / CONTEXT_BUDGET_CHARS * 100, 1),
        "preserved_sections": preserved_sections,
        "compressed_sections": compressed_sections,
        "dropped_sections": dropped_sections,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    return contract_text, metadata


def write_contract(role: str) -> tuple[Path, dict]:
    """Compile and write a contract to the output directory."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    contract_text, metadata = compile_contract(role)

    output_path = OUTPUT_DIR / f"{role}.txt"
    output_path.write_text(contract_text, encoding="utf-8")

    meta_path = OUTPUT_DIR / f"{role}.meta.json"
    meta_path.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    return output_path, metadata


def drift_check(role: str) -> dict:
    """Check if the compiled contract is stale relative to the source."""
    agent_file = AGENTS_DIR / f"{role}.md"
    meta_path = OUTPUT_DIR / f"{role}.meta.json"
    contract_path = OUTPUT_DIR / f"{role}.txt"

    result = {"role": role, "drift_detected": False, "reason": ""}

    if not agent_file.exists():
        result["drift_detected"] = True
        result["reason"] = "source agent file missing"
        return result

    if not contract_path.exists() or not meta_path.exists():
        result["drift_detected"] = True
        result["reason"] = "compiled contract missing"
        return result

    raw_text = agent_file.read_text(encoding="utf-8")
    current_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()[:16]

    metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    stored_hash = metadata.get("source_hash", "")

    if current_hash != stored_hash:
        result["drift_detected"] = True
        result["reason"] = f"source hash changed: {stored_hash} → {current_hash}"

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compile compact role contracts from agent definitions."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    comp = sub.add_parser("compile", help="Compile contract for a role")
    comp.add_argument("role", help="Role name (e.g. patch-hunter)")

    sub.add_parser("compile-all", help="Compile contracts for all agent files")

    meas = sub.add_parser("measure", help="Measure contract size for a role")
    meas.add_argument("role")

    dc = sub.add_parser("drift-check", help="Check if contract is stale")
    dc.add_argument("role")

    args = parser.parse_args()

    if args.command == "compile":
        output_path, metadata = write_contract(args.role)
        print(f"Compiled: {output_path}")
        print(f"  Source: {metadata['source_size_chars']} chars")
        print(f"  Contract: {metadata['contract_size_chars']} chars")
        print(f"  Budget: {metadata['budget_usage_pct']}% of {CONTEXT_BUDGET_CHARS}")
        print(f"  Within budget: {metadata['within_budget']}")
        if metadata['dropped_sections']:
            print(f"  Dropped: {', '.join(metadata['dropped_sections'])}")
        return 0

    if args.command == "compile-all":
        if not AGENTS_DIR.exists():
            print("No agents directory found.", file=sys.stderr)
            return 1
        count = 0
        for agent_file in sorted(AGENTS_DIR.glob("*.md")):
            role = agent_file.stem
            if role.startswith("_"):
                continue
            try:
                _, metadata = write_contract(role)
                status = "OK" if metadata["within_budget"] else "OVER BUDGET"
                print(f"  {role}: {metadata['contract_size_chars']} chars ({status})")
                count += 1
            except Exception as e:
                print(f"  {role}: ERROR — {e}", file=sys.stderr)
        print(f"\nCompiled {count} contracts.")
        return 0

    if args.command == "measure":
        try:
            contract_text, metadata = compile_contract(args.role)
        except FileNotFoundError as e:
            print(str(e), file=sys.stderr)
            return 1
        print(json.dumps(metadata, indent=2, ensure_ascii=False))
        return 0

    if args.command == "drift-check":
        result = drift_check(args.role)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if not result["drift_detected"] else 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
