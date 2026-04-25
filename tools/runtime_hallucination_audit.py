#!/usr/bin/env python3
"""Cross-check runtime evaluation reports for unsupported claims."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.submission_quality_compare import score_slop

PIPELINES_DAG = ["ctf_pwn", "ctf_rev", "bounty", "firmware", "ai_security", "robotics", "supplychain"]
PIPELINES_TERMINATOR = ["ctf", "bounty", "firmware", "ai-security", "robotics", "supplychain"]
PROFILES = ["claude-only", "gpt-only", "hybrid"]

OVERCLAIM_PATTERNS = [
    re.compile(r"\bfull\s+live\s+(pipeline|matrix|verification)\b", re.I),
    re.compile(r"\bsubmit-ready\b", re.I),
    re.compile(r"\baccepted\s+by\s+(triage|platform|program)\b", re.I),
    re.compile(r"\b(candidate|gpt|hybrid).*\bmatched\s+or\s+beat\b", re.I),
    re.compile(r"\bno\s+hallucination(s)?\b", re.I),
]


class Audit:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []

    def add(self, name: str, status: str, detail: str, **extra: Any) -> None:
        self.checks.append({"name": name, "status": status, "detail": detail, **extra})

    def require(self, name: str, condition: bool, ok: str, fail: str, **extra: Any) -> None:
        self.add(name, "pass" if condition else "fail", ok if condition else fail, **extra)

    def warn(self, name: str, detail: str, **extra: Any) -> None:
        self.add(name, "warn", detail, **extra)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_dag_matrix(audit: Audit, path: Path, *, expected_mode: str | None = None) -> None:
    name = path.relative_to(path.parents[1]) if len(path.parents) > 1 else path
    audit.require(f"{name}:exists", path.exists(), "matrix JSON exists", "matrix JSON missing")
    if not path.exists():
        return
    try:
        payload = read_json(path)
    except json.JSONDecodeError as exc:
        audit.add(f"{name}:json", "fail", f"invalid JSON: {exc}")
        return
    results = payload.get("results")
    audit.require(f"{name}:results-list", isinstance(results, list), "results list present", "results list missing")
    if not isinstance(results, list):
        return
    expected = {(profile, pipeline) for profile in PROFILES for pipeline in PIPELINES_DAG}
    actual = {(item.get("profile"), item.get("pipeline")) for item in results if isinstance(item, dict)}
    audit.require(f"{name}:coverage", actual == expected, "profile/pipeline coverage is exact", "profile/pipeline coverage mismatch",
                  expected=sorted(map(list, expected)), actual=sorted(map(list, actual)))
    audit.require(f"{name}:status", payload.get("status") == "pass", "matrix status is pass", f"matrix status is {payload.get('status')!r}")
    bad = [item for item in results if item.get("status") != "pass"]
    audit.require(f"{name}:all-pass", not bad, "all matrix rows pass", f"{len(bad)} matrix row(s) failed")
    failures = sum(int(item.get("failure_count", 0) or 0) for item in results)
    audit.require(f"{name}:failure-count", failures == 0, "failure_count total is 0", f"failure_count total is {failures}")
    if expected_mode:
        modes = {item.get("mode") for item in results}
        audit.require(f"{name}:mode", modes == {expected_mode}, f"all rows are {expected_mode}", f"unexpected modes: {sorted(modes)}")


def validate_terminator_dry_run(audit: Audit, path: Path) -> None:
    audit.require("terminator-dry-run:exists", path.exists(), "terminator dry-run matrix exists", "terminator dry-run matrix missing")
    if not path.exists():
        return
    payload = read_json(path)
    results = payload.get("results", [])
    expected = {(profile, pipeline) for profile in PROFILES for pipeline in PIPELINES_TERMINATOR}
    actual = {(item.get("profile"), item.get("pipeline")) for item in results if isinstance(item, dict)}
    audit.require("terminator-dry-run:coverage", actual == expected, "terminator dry-run coverage is exact",
                  "terminator dry-run coverage mismatch", expected=sorted(map(list, expected)), actual=sorted(map(list, actual)))
    audit.require("terminator-dry-run:status", payload.get("status") == "pass", "terminator dry-run status is pass",
                  f"terminator dry-run status is {payload.get('status')!r}")
    bad = [item for item in results if item.get("status") != "pass"]
    audit.require("terminator-dry-run:all-pass", not bad, "all terminator dry-run rows pass", f"{len(bad)} row(s) failed")


def validate_backend_smoke(audit: Audit, path: Path) -> None:
    audit.require("backend-smoke:exists", path.exists(), "backend smoke JSON exists", "backend smoke JSON missing")
    if not path.exists():
        return
    payload = read_json(path)
    result = payload.get("backend_runner_result", {})
    attempts = payload.get("attempts", [])
    audit.require("backend-smoke:status", payload.get("status") == "pass", "backend smoke status is pass",
                  f"backend smoke status is {payload.get('status')!r}")
    audit.require("backend-smoke:runner-completed", isinstance(result, dict) and result.get("status") == "completed",
                  "backend_runner result completed", f"backend_runner result is {result.get('status') if isinstance(result, dict) else 'missing'}")
    audit.require("backend-smoke:expected-observed", bool(payload.get("expected_text_observed")),
                  "expected text observed in model stream", "expected text was not observed in model stream")
    audit.require("backend-smoke:codex", payload.get("backend") == "codex" and payload.get("runtime_profile") == "gpt-only",
                  "codex/gpt-only smoke recorded", "backend smoke is not codex/gpt-only")
    audit.require("backend-smoke:no-failover", payload.get("failover_count") == 0,
                  "no failover used in backend smoke", f"failover_count={payload.get('failover_count')}")
    if isinstance(attempts, list) and attempts:
        audit.require("backend-smoke:attempt", attempts[0].get("failure_kind") == "completed" and attempts[0].get("returncode") == 0,
                      "first attempt completed with returncode 0", f"first attempt was {attempts[0]}")


def manifest_packages(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    packages = manifest.get("packages", {})
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(packages, dict):
        return out
    for group, items in packages.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                out[item["name"]] = {**item, "group": group}
    return out


def validate_submission_fixtures(audit: Audit, path: Path) -> dict[str, Any] | None:
    audit.require("submission-fixtures:exists", path.exists(), "submission fixture manifest exists", "submission fixture manifest missing")
    if not path.exists():
        return None
    manifest = read_json(path)
    source_root = Path(str(manifest.get("source_root", "")))
    audit.require("submission-fixtures:source-root", source_root.exists(), f"source root exists: {source_root}",
                  f"source root missing: {source_root}")
    counts = {group: len(items) for group, items in manifest.get("packages", {}).items()}
    audit.require("submission-fixtures:counts", counts.get("positive") == 6 and counts.get("negative") == 4 and counts.get("gold") == 1,
                  "baseline fixture counts are 6/4/1", f"unexpected counts: {counts}")
    packages = manifest_packages(manifest)
    for package_name, item in packages.items():
        package_path = source_root / str(item.get("path", ""))
        audit.require(f"submission-fixtures:{package_name}:package", package_path.exists(),
                      f"{package_name} package exists", f"{package_name} package missing: {package_path}")
        files = item.get("files", {})
        if not isinstance(files, dict):
            audit.add(f"submission-fixtures:{package_name}:files", "fail", "files map missing")
            continue
        missing: list[str] = []
        for listed in sum((value for value in files.values() if isinstance(value, list)), []):
            if not (source_root / listed).exists():
                missing.append(listed)
        audit.require(f"submission-fixtures:{package_name}:listed-files", not missing,
                      f"{package_name} listed files exist", f"{package_name} missing listed files: {missing}")
    return manifest


def validate_quality_delta(audit: Audit, path: Path, md_path: Path, manifest: dict[str, Any] | None) -> None:
    audit.require("quality-delta:exists", path.exists(), "quality delta JSON exists", "quality delta JSON missing")
    if not path.exists():
        return
    payload = read_json(path)
    baseline = payload.get("baseline", [])
    candidate = payload.get("candidate", [])
    baseline_names = {item.get("name") for item in baseline if isinstance(item, dict)}
    if manifest:
        manifest_names = set(manifest_packages(manifest))
        audit.require("quality-delta:baseline-match", baseline_names == manifest_names,
                      "quality baseline names match fixture manifest", "quality baseline names do not match fixture manifest",
                      manifest=sorted(manifest_names), quality=sorted(baseline_names))
    audit.require("quality-delta:baseline-count", len(baseline) == 11, "quality baseline contains 11 packages",
                  f"quality baseline contains {len(baseline)} packages")
    if not candidate:
        audit.warn("quality-delta:no-candidate", "candidate packages were not scored; comparison is intentionally baseline-only")
        text = md_path.read_text(encoding="utf-8") if md_path.exists() else ""
        audit.require("quality-delta:no-candidate-disclosed", "baseline-only fixture calibration" in text,
                      "baseline-only status is disclosed in markdown", "baseline-only status is not disclosed in markdown")


def validate_markdown_claims(audit: Audit, eval_dir: Path) -> None:
    for path in sorted(eval_dir.rglob("*.md")):
        rel = path.relative_to(eval_dir)
        if rel == Path("hallucination_audit.md"):
            audit.add("markdown:hallucination_audit.md:self-skip", "pass", "skip self-generated audit report")
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        slop = score_slop(text)
        audit.require(f"markdown:{rel}:slop", slop["score"] <= 2,
                      f"slop score {slop['score']} <= 2", f"slop score {slop['score']} > 2", slop=slop)
        hits = [pattern.pattern for pattern in OVERCLAIM_PATTERNS if pattern.search(text)]
        audit.require(f"markdown:{rel}:overclaim", not hits, "no forbidden overclaim pattern found",
                      f"overclaim pattern(s) found: {hits}", patterns=hits)


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    counts = Counter(item["status"] for item in payload["checks"])
    lines = ["# Runtime Hallucination Audit", ""]
    lines.append(f"Generated: {payload['generated_at']}")
    lines.append("")
    lines.append(f"- Status: {payload['status']}")
    lines.append(f"- Pass: {counts.get('pass', 0)}")
    lines.append(f"- Warn: {counts.get('warn', 0)}")
    lines.append(f"- Fail: {counts.get('fail', 0)}")
    lines.append("")
    lines.append("| Status | Check | Detail |")
    lines.append("|---|---|---|")
    for item in payload["checks"]:
        lines.append(f"| {item['status']} | `{item['name']}` | {item['detail']} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval-dir", type=Path, required=True)
    args = parser.parse_args()

    eval_dir = args.eval_dir.resolve()
    audit = Audit()
    audit.require("eval-dir:exists", eval_dir.exists(), f"eval dir exists: {eval_dir}", f"eval dir missing: {eval_dir}")
    if eval_dir.exists():
        validate_dag_matrix(audit, eval_dir / "matrix.json")
        validate_dag_matrix(audit, eval_dir / "live_dry_run" / "matrix.json", expected_mode="live-dry-run")
        validate_terminator_dry_run(audit, eval_dir / "terminator_dry_run_matrix.json")
        validate_backend_smoke(audit, eval_dir / "backend_smoke.json")
        manifest = validate_submission_fixtures(audit, eval_dir / "submission_fixtures.json")
        validate_quality_delta(audit, eval_dir / "quality_delta.json", eval_dir / "quality_delta.md", manifest)
        validate_markdown_claims(audit, eval_dir)

    status = "fail" if any(item["status"] == "fail" for item in audit.checks) else "pass"
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "eval_dir": str(eval_dir),
        "status": status,
        "checks": audit.checks,
    }
    json_path = eval_dir / "hallucination_audit.json"
    md_path = eval_dir / "hallucination_audit.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(md_path, payload)
    print(json_path)
    print(md_path)
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
