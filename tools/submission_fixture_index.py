#!/usr/bin/env python3
"""Index existing submission packages for runtime quality comparisons."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SUBMISSIONS = PROJECT_ROOT / "coordination" / "SUBMISSIONS.md"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "reports" / "runtime-eval"

BASELINE_TARGETS = {
    "positive": [
        "proconnect-identite",
        "qwant",
        "llama_index",
        "onnx",
        "kubeflow",
        "hrsgroup",
    ],
    "negative": [
        "portofantwerp",
        "magiclabs-mbb-og",
        "paradex",
        "zendesk",
    ],
    "gold": [
        "rhinofi_prove",
    ],
}


SKIP_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "vendor",
}


def has_baseline_packages(source_root: Path) -> bool:
    targets_dir = source_root / "targets"
    for group, names in BASELINE_TARGETS.items():
        for name in names:
            if group == "gold":
                if (source_root / "reports" / name).exists():
                    return True
                continue
            if (targets_dir / name / "submission").exists():
                return True
    return False


def default_source_root() -> Path:
    env_root = os.getenv("TERMINATOR_SUBMISSION_SOURCE_ROOT")
    if env_root:
        return Path(env_root).expanduser()
    if has_baseline_packages(PROJECT_ROOT):
        return PROJECT_ROOT

    # Local worktrees do not contain untracked submission artifacts. In the
    # standard layout, ../Terminator holds the canonical targets/reports data.
    for sibling_name in ("Terminator", "terminator"):
        sibling = PROJECT_ROOT.parent / sibling_name
        if sibling.resolve() == PROJECT_ROOT.resolve():
            continue
        if has_baseline_packages(sibling):
            return sibling
    return PROJECT_ROOT


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def parse_submission_rows(path: Path = SUBMISSIONS) -> list[dict[str, str]]:
    if not path.exists():
        return []
    rows: list[dict[str, str]] = []
    section = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            section = line.strip("# ").strip()
            continue
        if not line.startswith("|") or "---" in line:
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) < 8 or cells[0] == "Platform":
            continue
        rows.append(
            {
                "section": section,
                "platform": cells[0],
                "target": cells[1],
                "title": cells[2],
                "severity": cells[3],
                "bounty": cells[4],
                "status": re.sub(r"\*+", "", cells[5]).strip(),
                "submitted": cells[6],
                "last_or_resolved": cells[7],
                "note": cells[8] if len(cells) > 8 else "",
            }
        )
    return rows


def classify_status(status: str) -> str:
    lowered = status.lower()
    if any(token in lowered for token in ["accepted", "pending", "under review", "triage", "hold"]):
        return "positive"
    if any(token in lowered for token in ["oos", "not applicable", "not reproducible", "n/r", "closed", "won't fix"]):
        return "negative"
    return "unknown"


def package_files(package_dir: Path, source_root: Path) -> dict[str, list[str]]:
    patterns = {
        "reports": ["report*.md", "*submission*.md"],
        "pocs": ["poc*", "*PoC*", "*.t.sol", "*.sh", "*.py", "*.mjs"],
        "evidence": ["*evidence*", "poc_output*", "output_*", "*.png"],
        "reviews": ["submission_review.json", "triager_sim_result.json", "triager_sim_result.md"],
        "autofill": ["autofill_payload.json"],
    }
    result: dict[str, list[str]] = {}
    for key in patterns:
        result[key] = []

    for path in package_dir.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        name = path.name
        for key, globs in patterns.items():
            if any(fnmatch.fnmatch(name, pattern) for pattern in globs):
                result[key].append(relative(path, source_root))

    for key, hits in result.items():
        result[key] = sorted(set(hits))
    return result


def discover_packages(source_root: Path, *, include_other: bool = False) -> dict[str, list[dict[str, object]]]:
    packages: dict[str, list[dict[str, object]]] = {"positive": [], "negative": [], "gold": [], "other": []}
    targets_dir = source_root / "targets"
    for group, names in BASELINE_TARGETS.items():
        for name in names:
            if group == "gold":
                candidate = source_root / "reports" / name
                if candidate.exists():
                    packages[group].append({"name": name, "path": relative(candidate, source_root), "files": package_files(candidate, source_root)})
                continue
            base = targets_dir / name
            submission = base / "submission"
            if submission.exists():
                packages[group].append({"name": name, "path": relative(submission, source_root), "files": package_files(submission, source_root)})

    if not include_other:
        return packages

    known = {item["path"] for values in packages.values() for item in values}
    for submission in sorted(targets_dir.glob("*/submission")):
        rel = relative(submission, source_root)
        if rel in known:
            continue
        files = package_files(submission, source_root)
        if any(files.values()):
            packages["other"].append({"name": submission.parent.name, "path": rel, "files": files})
    return packages


def build_manifest(source_root: Path, *, include_other: bool = False) -> dict[str, object]:
    rows = parse_submission_rows(source_root / "coordination" / "SUBMISSIONS.md")
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_root": str(source_root),
        "source": "coordination/SUBMISSIONS.md",
        "tracker_rows": [{**row, "outcome_class": classify_status(row["status"])} for row in rows],
        "packages": discover_packages(source_root, include_other=include_other),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=default_source_root(),
                        help="Repository root containing targets/reports artifacts")
    parser.add_argument("--include-other", action="store_true",
                        help="Also index every non-baseline targets/*/submission package")
    parser.add_argument("--out", type=Path, help="Output JSON path")
    args = parser.parse_args()

    manifest = build_manifest(args.source_root.resolve(), include_other=args.include_other)
    out = args.out
    if out is None:
        out_dir = DEFAULT_OUTPUT_DIR / time.strftime("%Y%m%d_%H%M%S")
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / "submission_fixtures.json"
    else:
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
