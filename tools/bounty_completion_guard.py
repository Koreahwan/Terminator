#!/usr/bin/env python3
"""Normalize and verify bounty session artifacts before marking completion.

This guard runs after a bounty pipeline session finishes. It:
- mirrors canonical root-level artifacts from a submission bundle when safe
- produces a per-phase verification matrix so omissions are explicit
- regenerates report score / evidence manifest artifacts when possible
- exits non-zero if a submission-ready path is missing required artifacts
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


PHASES = [
    "-1 verify-target",
    "0 target-assessment",
    "0.2 rules",
    "1 scout",
    "1 analyst",
    "1 threat-modeler",
    "1 patch-hunter",
    "1.5 workflow-auditor",
    "1.5 web-tester",
    "Gate 1",
    "2 exploiter",
    "Gate 2",
    "3 reporter",
    "4 review",
    "4.5 triager",
    "5 finalize",
    "5.5b platform safety",
    "5.7 live scope",
    "5.8 submission materials",
]


def list_files(root: Path) -> list[str]:
    return [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()]


def find_one(files: list[str], predicate) -> str | None:
    for rel in files:
        if predicate(rel):
            return rel
    return None


def detect_archived_mode(target_dir: Path, report_dir: Path) -> bool:
    for candidate in [target_dir / "final_sweep.md", report_dir / "status.md"]:
        if candidate.exists():
            text = candidate.read_text(encoding="utf-8", errors="ignore").lower()
            if any(token in text for token in ["do not submit", "archive", "archived", "no-go", "no viable finding", "scope excludes", "platform safety is blocked"]):
                return True
    return False


def candidate_score(cand: Path) -> tuple[int, float]:
    score = 0
    for rel in [
        "submission_review.json",
        "submission_review.md",
        "autofill_payload.json",
        "live_scope_check.md",
        "strengthening_report.md",
        "report.md",
        "report_final.md",
        "report_draft.md",
        "bugcrowd_form.md",
        "immunefi_form.md",
        "0din_report.md",
    ]:
        if (cand / rel).exists():
            score += 10
    if any(p.name.startswith("poc") for p in cand.iterdir() if p.is_file()):
        score += 5
    mtime = max((p.stat().st_mtime for p in cand.rglob("*") if p.is_file()), default=0.0)
    return score, mtime


def select_submission_candidate(target_dir: Path) -> Path | None:
    submission_root = target_dir / "submission"
    if not submission_root.is_dir():
        return None
    candidates = [p for p in submission_root.iterdir() if p.is_dir()]
    if not candidates:
        return None
    candidates.sort(key=candidate_score, reverse=True)
    return candidates[0]


def first_existing(base: Path, names: list[str]) -> Path | None:
    for name in names:
        p = base / name
        if p.exists():
            return p
    return None


def mirror_file(src: Path | None, dst: Path) -> bool:
    if src is None or not src.exists() or dst.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def first_glob(base: Path | None, patterns: list[str]) -> Path | None:
    if base is None:
        return None
    for pattern in patterns:
        matches = sorted(base.glob(pattern))
        if matches:
            return matches[0]
    return None


def load_json(path: Path | None) -> dict | None:
    if path is None or not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def collect_status_lines(data: dict | None, prefixes: tuple[str, ...]) -> list[str]:
    if not isinstance(data, dict):
        return []
    lines: list[str] = []
    pipeline_status = data.get("pipeline_status")
    if isinstance(pipeline_status, dict):
        for key, value in pipeline_status.items():
            lowered = str(key).lower()
            if lowered.startswith(prefixes):
                lines.append(f"- `{key}`: {value}")
    verification = data.get("verification")
    if isinstance(verification, dict):
        for key, value in verification.items():
            lowered = str(key).lower()
            if lowered.startswith(prefixes):
                lines.append(f"- `verification.{key}`: {value}")
    return lines


def synthesize_markdown(
    target_dir: Path,
    destination: Path,
    title: str,
    sources: list[Path],
    bullets: list[str],
    note: str,
) -> bool:
    bullets = [bullet for bullet in bullets if bullet]
    if destination.exists() or not sources or not bullets:
        return False
    source_lines = [f"- `{src.relative_to(target_dir)}`" for src in sources]
    body = [f"# {title}", "", "## Source Artifacts", *source_lines, "", "## Extracted Signals", *bullets, "", note, ""]
    destination.write_text("\n".join(body), encoding="utf-8")
    return True


def synthesize_exploit_results(target_dir: Path, candidate: Path | None) -> bool:
    dst = target_dir / "exploit_results.md"
    if dst.exists():
        return False
    lines = ["# Exploit Results", ""]
    evidence_paths: list[Path] = []
    if candidate is not None:
        for pattern in ["exploit_results.md", "evidence.md", "evidence_summary.md", "candidate*_evidence.md"]:
            evidence_paths.extend(candidate.glob(pattern))
        poc_paths = sorted(p for p in candidate.rglob("*") if p.is_file() and ("poc" in p.name.lower() or p.suffix == ".sol"))
    else:
        poc_paths = []
    if not evidence_paths and not poc_paths:
        return False
    if evidence_paths:
        lines.append("## Evidence Sources")
        for p in evidence_paths[:10]:
            lines.append(f"- `{p.relative_to(target_dir)}`")
        lines.append("")
    if poc_paths:
        lines.append("## PoC Files")
        for p in poc_paths[:10]:
            lines.append(f"- `{p.relative_to(target_dir)}`")
        lines.append("")
    lines.append("This root-level summary was synthesized by `bounty_completion_guard.py` from the submission bundle to preserve canonical Phase 2 artifact presence.")
    dst.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True


def materialize_phase_artifacts(target_dir: Path, report_dir: Path, candidate: Path | None) -> list[str]:
    if candidate is None:
        return []
    created: list[str] = []
    review_json_path = first_existing(candidate, ["submission_review.json"])
    review_md_path = first_existing(candidate, ["submission_review.md", "phase45_review.md", "critic_factcheck.md"])
    review_json = load_json(review_json_path)

    live_scope_src = first_existing(candidate, ["live_scope_check.md"])
    if mirror_file(live_scope_src, target_dir / "live_scope_check.md"):
        created.append("live_scope_check.md")
    elif synthesize_markdown(
        target_dir,
        target_dir / "live_scope_check.md",
        "Live Scope Check",
        [p for p in [review_json_path, review_md_path] if p is not None],
        collect_status_lines(review_json, ("phase_57", "live_scope")),
        "This canonical Phase 5.7 summary was synthesized by `bounty_completion_guard.py` from existing review artifacts.",
    ):
        created.append("live_scope_check.md(synthesized)")

    gate1_src = first_glob(candidate, ["gate1*.md", "gate1*.json"])
    gate1_sources = [p for p in [gate1_src, target_dir / "web_test_findings.md", review_json_path, review_md_path] if p is not None and p.exists()]
    gate1_bullets = collect_status_lines(review_json, ("gate_1", "gate1"))
    if not gate1_bullets and (target_dir / "web_test_findings.md").exists():
        gate1_bullets = ["- `web_test_findings.md`: present"]
    if mirror_file(gate1_src, target_dir / "gate1_verdict.md"):
        created.append("gate1_verdict.md")
    elif synthesize_markdown(
        target_dir,
        target_dir / "gate1_verdict.md",
        "Gate 1 Verdict",
        gate1_sources,
        gate1_bullets,
        "This canonical Gate 1 summary was synthesized by `bounty_completion_guard.py` from existing prove-lane and web-test artifacts.",
    ):
        created.append("gate1_verdict.md(synthesized)")

    gate2_src = first_glob(candidate, ["gate2*.md", "gate2*.json", "phase45*.md", "triager*.md", "triager*.json"])
    gate2_sources = [p for p in [gate2_src, review_json_path, review_md_path] if p is not None and p.exists()]
    gate2_bullets = collect_status_lines(review_json, ("gate_2", "gate2", "phase_45", "phase45"))
    if mirror_file(gate2_src, target_dir / "gate2_verdict.md"):
        created.append("gate2_verdict.md")
    elif synthesize_markdown(
        target_dir,
        target_dir / "gate2_verdict.md",
        "Gate 2 Verdict",
        gate2_sources,
        gate2_bullets,
        "This canonical Gate 2 summary was synthesized by `bounty_completion_guard.py` from existing review/triager artifacts.",
    ):
        created.append("gate2_verdict.md(synthesized)")

    finalize_sources = [
        p
        for p in [
            first_existing(candidate, ["report.md", "report_final.md", "report_draft.md"]),
            first_existing(candidate, ["bugcrowd_form.md", "immunefi_form.md", "0din_report.md"]),
            first_existing(candidate, ["autofill_payload.json"]),
            review_json_path,
            review_md_path,
            report_dir / "status.md",
            target_dir / "final_sweep.md",
        ]
        if p is not None and p.exists()
    ]
    finalize_bullets = []
    if review_json_path is not None and review_json is not None:
        for key in ("status", "verdict", "prepared_for_phase", "submission_ready"):
            if key in review_json:
                finalize_bullets.append(f"- `{key}`: {review_json[key]}")
    for artifact in finalize_sources:
        rel = artifact.relative_to(target_dir) if artifact.is_relative_to(target_dir) else artifact.relative_to(report_dir)
        finalize_bullets.append(f"- artifact: `{rel}`")
    if synthesize_markdown(
        target_dir,
        target_dir / "finalize_summary.md",
        "Finalize Summary",
        finalize_sources,
        finalize_bullets,
        "This canonical Phase 5 summary was synthesized by `bounty_completion_guard.py` from existing submission/finalization artifacts.",
    ):
        created.append("finalize_summary.md(synthesized)")

    return created


def run_json(cmd: list[str]) -> dict | None:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def generate_report_score(target_dir: Path, candidate: Path | None) -> tuple[bool, dict | None]:
    if candidate is None:
        return False, None
    report = first_existing(candidate, ["report.md", "report_final.md", "report_draft.md"])
    if report is None:
        return False, None
    proc = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("report_scorer.py")),
            str(report),
            "--poc-dir",
            str(candidate),
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    data = json.loads(proc.stdout)
    (target_dir / "report_score.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return proc.returncode == 0, data


def generate_manifest(target_dir: Path) -> tuple[bool, dict | None]:
    proc = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("evidence_manifest.py")),
            str(target_dir),
            "--validate",
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    data = json.loads(proc.stdout)
    (target_dir / "evidence_manifest.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return proc.returncode == 0, data


def build_phase_matrix(target_dir: Path, report_dir: Path, platform: str, candidate: Path | None) -> dict:
    files = list_files(target_dir)
    archived = detect_archived_mode(target_dir, report_dir)
    gate1_like = find_one(files, lambda f: "gate1" in f.lower() or "web_test_findings" in f.lower() or Path(f).name == "gate1_verdict.md")
    gate2_like = find_one(files, lambda f: "gate2" in f.lower() or "triager" in f.lower() or "phase45_review" in f.lower() or "submission_review" in f.lower() or Path(f).name == "gate2_verdict.md")
    review_like = find_one(files, lambda f: "critic" in f.lower() or "submission_review" in f.lower() or "phase45_review" in f.lower() or "critic_factcheck" in f.lower())
    final_like = find_one(files, lambda f: Path(f).name in {"report_final.md", "bugcrowd_form.md", "immunefi_form.md", "0din_report.md", "finalize_summary.md"} or f in {"report.md", "bugcrowd_form.md"} or "final_sweep.md" in f or "status.md" in f)
    scope_like = find_one(files, lambda f: "live_scope_check" in f.lower() or "submission_review" in f.lower())
    submit_like = find_one(files, lambda f: "autofill_payload" in f.lower() or Path(f).name in {"bugcrowd_form.md", "immunefi_form.md", "0din_report.md"} or ("submission_review.json" in f and not archived))
    checks = [
        ("-1 verify-target", (target_dir / "program_rules_summary.md").exists() or (target_dir / "fetch_meta.json").exists(), "rules/fetch artifact"),
        ("0 target-assessment", any(f.endswith("target_assessment.md") for f in files), "target_assessment.md"),
        ("0.2 rules", any(f.endswith("program_rules_summary.md") for f in files), "program_rules_summary.md"),
        ("1 scout", any(f.endswith("endpoint_map.md") for f in files), "endpoint_map.md"),
        ("1 analyst", any(f.endswith("vulnerability_candidates.md") for f in files), "vulnerability_candidates.md"),
        ("1 threat-modeler", all(any(f.endswith(name) for f in files) for name in ["trust_boundary_map.md", "role_matrix.md", "state_machines.md", "invariants.md"]), "trust-boundary artifacts"),
        ("1 patch-hunter", any(f.endswith("patch_analysis.md") for f in files), "patch_analysis.md"),
        ("1.5 workflow-auditor", any(f.endswith("workflow_map.md") for f in files), "workflow_map.md"),
        ("1.5 web-tester", bool(find_one(files, lambda f: "web_test" in f.lower() or "gate1_" in f.lower() or "web_test_findings" in f.lower())), "web-test-like artifact"),
        ("Gate 1", bool(gate1_like), gate1_like or "missing"),
        ("2 exploiter", bool(find_one(files, lambda f: f.startswith("submission/") and ("poc" in Path(f).name.lower() or "exploit_results" in Path(f).name.lower()) or f == "exploit_results.md")), "exploit/poc artifact"),
        ("Gate 2", bool(gate2_like), gate2_like or "missing"),
        ("3 reporter", bool(find_one(files, lambda f: (f.startswith("submission/") and Path(f).name in {"report.md", "report_final.md", "report_draft.md"}) or f == "report.md")), "report artifact"),
        ("4 review", bool(review_like), review_like or "missing"),
        ("4.5 triager", bool(gate2_like), gate2_like or "missing"),
        ("5 finalize", bool(final_like), final_like or "missing"),
        ("5.5b platform safety", bool(find_one(files, lambda f: "submission_review" in f.lower() or "autofill_payload" in f.lower() or "status.md" in f.lower())), "submission review / autofill / status"),
        ("5.7 live scope", bool(scope_like), scope_like or ("archived terminal verdict" if archived else "missing")),
        ("5.8 submission materials", bool(submit_like) or archived, submit_like or ("archived/no-submit terminal path" if archived else "missing")),
    ]
    rows = []
    for phase, ok, detail in checks:
        rows.append({"phase": phase, "status": "PASS" if ok else "FAIL", "detail": detail})
    matrix = {
        "target": target_dir.name,
        "platform": platform,
        "archived_terminal_mode": archived,
        "phase_pass": sum(1 for row in rows if row["status"] == "PASS"),
        "phase_total": len(rows),
        "phases": rows,
    }
    (target_dir / "phase_matrix.json").write_text(json.dumps(matrix, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = ["# Phase Matrix", "", f"- target: `{target_dir.name}`", f"- platform: `{platform}`", f"- archived_terminal_mode: `{archived}`", ""]
    for row in rows:
        lines.append(f"- [{row['status']}] {row['phase']} — {row['detail']}")
    (target_dir / "phase_matrix.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return matrix


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--target", default="")
    parser.add_argument("--platform", default="unknown")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    report_dir = Path(args.report_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    candidate = select_submission_candidate(target_dir)

    # Normalize root-level artifacts
    mirrored = []
    report_src = first_existing(candidate, ["report.md", "report_final.md", "report_draft.md"]) if candidate else None
    if mirror_file(report_src, target_dir / "report.md"):
        mirrored.append("report.md")
    exploit_src = first_existing(candidate, ["exploit_results.md"]) if candidate else None
    if mirror_file(exploit_src, target_dir / "exploit_results.md"):
        mirrored.append("exploit_results.md")
    elif synthesize_exploit_results(target_dir, candidate):
        mirrored.append("exploit_results.md(synthesized)")

    form_src = first_existing(candidate, ["bugcrowd_form.md", "immunefi_form.md", "0din_report.md"]) if candidate else None
    if form_src is not None:
        form_dst = target_dir / form_src.name
        if mirror_file(form_src, form_dst):
            mirrored.append(form_dst.name)
    mirrored.extend(materialize_phase_artifacts(target_dir, report_dir, candidate))

    report_score_ok, report_score = generate_report_score(target_dir, candidate)
    manifest_ok, manifest = generate_manifest(target_dir)
    phase_matrix = build_phase_matrix(target_dir, report_dir, args.platform, candidate)

    guard_payload = {
        "target": args.target or target_dir.name,
        "platform": args.platform,
        "submission_candidate": str(candidate.relative_to(target_dir)) if candidate else None,
        "mirrored": mirrored,
        "report_score_ok": report_score_ok,
        "report_score_composite": (report_score or {}).get("composite"),
        "manifest_ok": manifest_ok,
        "phase_pass": phase_matrix["phase_pass"],
        "phase_total": phase_matrix["phase_total"],
        "missing_phases": [row["phase"] for row in phase_matrix["phases"] if row["status"] != "PASS"],
    }
    (target_dir / "completion_guard.json").write_text(json.dumps(guard_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(json.dumps(guard_payload, indent=2, ensure_ascii=False))

    if not args.strict:
        return 0

    archived = phase_matrix["archived_terminal_mode"]
    if archived:
        return 0 if phase_matrix["phase_pass"] >= phase_matrix["phase_total"] - 1 else 1
    return 0 if manifest_ok and phase_matrix["phase_pass"] == phase_matrix["phase_total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
