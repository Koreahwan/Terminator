#!/usr/bin/env python3
"""
prepare_data.py - GraphRAG Security Knowledge Graph Data Preparation

Collects knowledge documents into GraphRAG input/ directory with YAML front-matter metadata.

Usage:
    python prepare_data.py --phase 1
    python prepare_data.py --phase 2
    python prepare_data.py --phase 1 --phase 2
"""

import argparse
import os
import re
import shutil
from pathlib import Path

# Project root relative to this script
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
INPUT_DIR = SCRIPT_DIR / "input"


def sanitize_name(name: str) -> str:
    """Convert filename/path to safe output filename."""
    name = re.sub(r"[^\w\-.]", "_", name)
    name = re.sub(r"_+", "_", name)
    return name.strip("_")


def extract_tags(path: Path, doc_type: str) -> list[str]:
    """Auto-extract tags from filename and path components."""
    tags = [doc_type]
    stem = path.stem.lower()

    # Add path components as tags (parent dirs)
    for part in path.parts[:-1]:
        part_clean = re.sub(r"[^\w]", "_", part.lower())
        if part_clean and part_clean not in (".", "..", "knowledge", "targets", "tools"):
            tags.append(part_clean)

    # Keyword tags from filename
    keyword_map = {
        "pwn": ["pwn", "exploit", "binary"],
        "rev": ["reversing", "binary"],
        "crypto": ["crypto", "cryptography"],
        "web": ["web", "http"],
        "rop": ["rop", "exploit", "binary"],
        "heap": ["heap", "exploit", "binary"],
        "stack": ["stack", "exploit", "binary"],
        "format": ["format_string", "exploit"],
        "overflow": ["overflow", "exploit"],
        "uaf": ["use_after_free", "exploit"],
        "xss": ["xss", "web"],
        "sqli": ["sqli", "sql_injection", "web"],
        "rce": ["rce", "remote_code_execution"],
        "ssrf": ["ssrf", "web"],
        "defi": ["defi", "web3", "smart_contract"],
        "solidity": ["solidity", "web3", "smart_contract"],
        "oracle": ["oracle", "web3", "defi"],
        "reentrancy": ["reentrancy", "web3", "smart_contract"],
        "firmware": ["firmware", "iot", "embedded"],
        "router": ["router", "firmware", "iot"],
        "netgear": ["netgear", "firmware", "iot"],
        "qnap": ["qnap", "firmware", "iot"],
        "synology": ["synology", "firmware", "iot"],
        "ctf": ["ctf"],
        "bounty": ["bug_bounty"],
        "immunefi": ["immunefi", "bug_bounty", "web3"],
        "bugcrowd": ["bugcrowd", "bug_bounty"],
    }

    for keyword, tag_list in keyword_map.items():
        if keyword in stem:
            tags.extend(tag_list)

    return list(dict.fromkeys(tags))  # deduplicate while preserving order


def build_frontmatter(source: str, doc_type: str, tags: list[str]) -> str:
    """Build YAML front-matter string."""
    tags_str = "[" + ", ".join(tags) + "]"
    return f"---\nsource: {source}\ntype: {doc_type}\ntags: {tags_str}\n---\n"


def write_doc(output_path: Path, frontmatter: str, content: str) -> None:
    """Write document with front-matter to output path."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(frontmatter)
        f.write("\n")
        f.write(content)


def process_file(src: Path, doc_type: str, stats: dict) -> None:
    """Process a single source file and write to input/."""
    if not src.exists():
        return

    try:
        content = src.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"  [WARN] Cannot read {src}: {e}")
        stats["errors"] += 1
        return

    rel_path = str(src.relative_to(PROJECT_ROOT))
    tags = extract_tags(src, doc_type)
    frontmatter = build_frontmatter(rel_path, doc_type, tags)

    out_name = f"{doc_type}_{sanitize_name(src.stem)}.txt"
    # Avoid collisions: append parent dir name if needed
    out_path = INPUT_DIR / out_name
    if out_path.exists():
        parent_tag = sanitize_name(src.parent.name)
        out_name = f"{doc_type}_{parent_tag}_{sanitize_name(src.stem)}.txt"
        out_path = INPUT_DIR / out_name

    write_doc(out_path, frontmatter, content)
    stats["count"] += 1


def phase1(stats: dict) -> None:
    """Phase 1: ~100 docs from core knowledge and targets."""
    print("\n[Phase 1] Collecting core knowledge documents...")

    # --- knowledge/challenges/*.md ---
    challenges_dir = PROJECT_ROOT / "knowledge" / "challenges"
    if challenges_dir.exists():
        md_files = list(challenges_dir.glob("*.md"))
        for f in md_files:
            process_file(f, "ctf_writeup", stats)
        print(f"  challenges: {len(md_files)} files")
    else:
        print(f"  [WARN] challenges dir not found: {challenges_dir}")

    # --- knowledge/techniques/*.md ---
    techniques_dir = PROJECT_ROOT / "knowledge" / "techniques"
    if techniques_dir.exists():
        md_files = list(techniques_dir.glob("*.md"))
        for f in md_files:
            process_file(f, "technique", stats)
        print(f"  techniques: {len(md_files)} files")
    else:
        print(f"  [WARN] techniques dir not found: {techniques_dir}")

    # --- knowledge/index.md ---
    index_file = PROJECT_ROOT / "knowledge" / "index.md"
    if index_file.exists():
        process_file(index_file, "index", stats)
        print("  index.md: 1 file")
    else:
        print(f"  [WARN] index.md not found: {index_file}")

    # --- targets/*/report.md and targets/*/submission/report.md ---
    targets_dir = PROJECT_ROOT / "targets"
    if targets_dir.exists():
        report_count = 0
        for target_dir in sorted(targets_dir.iterdir()):
            if not target_dir.is_dir():
                continue
            # Direct report
            for report_name in ["report.md", "report_A.md", "report_B.md",
                                  "report_a_bugcrowd_submission.md", "report_b_bugcrowd_submission.md",
                                  "report_A_bugcrowd_submission.md", "report_B_bugcrowd_submission.md",
                                  "report_A_soap_ping_rce.md", "report_B_nvram_injection_chain.md",
                                  "vulnerability_candidates.md", "target_assessment.md"]:
                candidate = target_dir / report_name
                if candidate.exists():
                    process_file(candidate, "bugbounty_report", stats)
                    report_count += 1
            # submission/ subdirectory
            sub_dir = target_dir / "submission"
            if sub_dir.exists():
                for f in sub_dir.glob("*.md"):
                    process_file(f, "bugbounty_report", stats)
                    report_count += 1
        print(f"  targets (reports): {report_count} files")

        # --- retained bounty/client-pitch analysis artifacts ---
        artifact_count = 0
        for target_dir in sorted(targets_dir.iterdir()):
            if not target_dir.is_dir():
                continue
            for artifact_name in ["endpoint_map.md", "high_value_targets.md",
                                    "raw_endpoint_review.md", "critic_review.md"]:
                candidate = target_dir / artifact_name
                if candidate.exists():
                    process_file(candidate, "analysis_artifact", stats)
                    artifact_count += 1
        print(f"  targets (artifacts): {artifact_count} files")
    else:
        print(f"  [WARN] targets dir not found: {targets_dir}")


def phase2(stats: dict) -> None:
    """Phase 2: ~523 docs from protocol-vulns-index."""
    print("\n[Phase 2] Collecting protocol vulnerability index documents...")

    index_dir = PROJECT_ROOT / "knowledge" / "protocol-vulns-index"
    if not index_dir.exists():
        print(f"  [WARN] protocol-vulns-index dir not found: {index_dir}")
        return

    md_files = list(index_dir.rglob("*.md"))
    count = 0
    for f in md_files:
        # Extract category from parent directory name
        try:
            rel = f.relative_to(index_dir)
            parts = rel.parts
            category = parts[0] if len(parts) > 1 else "general"
        except ValueError:
            category = "general"

        category_clean = sanitize_name(category)

        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"  [WARN] Cannot read {f}: {e}")
            stats["errors"] += 1
            continue

        rel_path = str(f.relative_to(PROJECT_ROOT))
        tags = ["protocol_vulnerability_index", category_clean]

        # Add sub-category if deeper nesting
        if len(parts) > 2:
            sub_cat = sanitize_name(parts[1])
            tags.append(sub_cat)

        # Add keywords from filename
        stem_lower = f.stem.lower()
        for kw in ["overflow", "injection", "reentrancy", "oracle", "flash_loan",
                    "access_control", "logic", "dos", "front_run", "sandwich",
                    "manipulation", "bypass", "exposure", "hardcoded"]:
            if kw in stem_lower:
                tags.append(kw)

        tags = list(dict.fromkeys(tags))
        frontmatter = build_frontmatter(rel_path, "protocol_vulnerability_index", tags)

        # Output filename: protocol_vulnerability_index_{category}_{stem}.txt
        out_name = f"protocol_vulnerability_index_{category_clean}_{sanitize_name(f.stem)}.txt"
        out_path = INPUT_DIR / out_name
        if out_path.exists():
            out_name = f"protocol_vulnerability_index_{category_clean}_{sanitize_name(f.parent.name)}_{sanitize_name(f.stem)}.txt"
            out_path = INPUT_DIR / out_name

        write_doc(out_path, frontmatter, content)
        count += 1
        stats["count"] += 1

    print(f"  protocol-vulns-index: {count} files across categories")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare documents for GraphRAG security knowledge graph"
    )
    parser.add_argument(
        "--phase",
        type=int,
        choices=[1, 2],
        action="append",
        dest="phases",
        help="Phase to run (1=core knowledge, 2=protocol-vulns-index). Can specify multiple times.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean input/ directory before processing",
    )
    args = parser.parse_args()

    # Default to phase 1 if none specified
    phases = args.phases if args.phases else [1]
    phases = sorted(set(phases))

    print(f"GraphRAG Data Preparation — Phases: {phases}")
    print(f"Project root: {PROJECT_ROOT}")
    print(f"Output dir:   {INPUT_DIR}")

    # Clean or create input dir
    if args.clean and INPUT_DIR.exists():
        print(f"\n[CLEAN] Removing existing input/ directory...")
        shutil.rmtree(INPUT_DIR)

    INPUT_DIR.mkdir(parents=True, exist_ok=True)

    stats = {"count": 0, "errors": 0}

    if 1 in phases:
        phase1(stats)

    if 2 in phases:
        phase2(stats)

    print(f"\n{'='*50}")
    print(f"Summary:")
    print(f"  Documents written: {stats['count']}")
    print(f"  Errors:            {stats['errors']}")
    print(f"  Output directory:  {INPUT_DIR}")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
