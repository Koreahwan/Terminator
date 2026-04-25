#!/usr/bin/env python3
"""Score existing and generated submission packages with the same rubric."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

TEMPLATE_PATTERNS = re.compile(
    r"It is important to note|comprehensive|robust|Furthermore|In conclusion|"
    r"It should be noted|leveraging|utilizing|In summary|It is worth noting|"
    r"As mentioned|It is crucial|seamlessly|facilitate|Subsequently|Consequently|"
    r"Notably|Specifically|Importantly|holistic|paradigm|synergy|delve into|multifaceted",
    re.I,
)
UNCERTAIN_PATTERNS = re.compile(
    r"should work|probably|most likely|presumably|seems to|appears to|"
    r"it is believed|potentially|theoretically|could potentially|might potentially",
    re.I,
)
SPECIFIC_EVIDENCE = re.compile(
    r"(HTTP/|status_code|tx hash|block\s+\d+|0x[a-f0-9]{16,}|"
    r"[A-Za-z0-9_./-]+:\d+|\d{4}-\d{2}-\d{2}|poc_output|evidence)",
    re.I,
)


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def choose_report(package: Path) -> Path | None:
    candidates = sorted(package.rglob("report*.md"))
    if not candidates:
        candidates = sorted(package.rglob("*submission*.md"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_size)


def choose_pocs(package: Path) -> list[Path]:
    hits: list[Path] = []
    for pattern in ["poc*.py", "poc*.sh", "poc*.md", "poc*.t.sol", "*.t.sol", "PoC*.sol", "poc*.mjs"]:
        hits.extend(p for p in package.rglob(pattern) if p.is_file())
    return sorted(set(hits))


def package_inventory(package: Path) -> dict[str, list[str]]:
    evidence_patterns = ["*evidence*", "*output*", "poc_results*", "*.png"]
    evidence: list[Path] = []
    for pattern in evidence_patterns:
        evidence.extend(p for p in package.rglob(pattern) if p.is_file())
    reviews = [p for p in package.rglob("submission_review.json")] + [p for p in package.rglob("triager_sim_result.json")]
    return {
        "reports": [rel(p) for p in ([choose_report(package)] if choose_report(package) else [])],
        "pocs": [rel(p) for p in choose_pocs(package)],
        "evidence": [rel(p) for p in sorted(set(evidence))],
        "reviews": [rel(p) for p in sorted(set(reviews))],
    }


def score_poc(path: Path) -> dict[str, object]:
    text = read_text(path)
    network_calls = len(re.findall(r"requests\.|fetch\(|curl |remote\(|cast send|cast call|axios\.|http\.|urllib", text))
    response_capture = len(re.findall(r"response\.|status_code|\.json\(\)|recvline|recvuntil|interactive|200 OK|HTTP/|assert", text))
    test_framework = len(re.findall(r"forge test|npm test|pytest|unittest|assert|vm\.expect|console\.log", text))
    incomplete = len(re.findall(r"TODO|FIXME|theoretical|hypothetical|would work|should work|left as exercise|mock|placeholder", text, re.I))
    mock_data = len(re.findall(r"fake_|mock_|dummy_|example\.com|0xdead|placeholder", text, re.I))
    commented_out = len(re.findall(r"^#.*exploit|^#.*send|^#.*remote|^//.*attack", text, re.I | re.M))
    defi_fork = bool(re.search(r"fork-url|createSelectFork|block\s+\d+", text, re.I))
    defi_mock_balance = bool(re.search(r"vm\.deal", text)) and not re.search(r"disclos|honest|setup only|test setup", text, re.I)

    tier = 2.0
    if network_calls == 0:
        tier += 1
    if response_capture > 0:
        tier -= 1
    if test_framework > 0:
        tier -= 0.5
    if incomplete > 0:
        tier += 1
    if mock_data > 2:
        tier += 1
    if commented_out > 0:
        tier += 1
    if defi_fork and test_framework > 0:
        tier -= 0.5
    if defi_mock_balance:
        tier += 1
    tier = max(1, min(4, round(tier)))
    return {
        "path": rel(path),
        "tier": tier,
        "pass": tier <= 2,
        "signals": {
            "network_calls": network_calls,
            "response_capture": response_capture,
            "test_framework": test_framework,
            "incomplete": incomplete,
            "mock_data": mock_data,
            "commented_out": commented_out,
            "defi_fork": defi_fork,
            "defi_mock_balance": defi_mock_balance,
        },
    }


def score_slop(text: str) -> dict[str, object]:
    template = len(TEMPLATE_PATTERNS.findall(text))
    uncertain = len(UNCERTAIN_PATTERNS.findall(text))
    evidence_hits = len(SPECIFIC_EVIDENCE.findall(text))
    score = template * 0.5 + uncertain * 0.5
    if evidence_hits == 0:
        score += 2
    score -= min(evidence_hits, 4) * 1.0
    score = max(0.0, min(10.0, round(score, 1)))
    return {
        "score": score,
        "pass": score <= 2,
        "template_language": template,
        "uncertain_language": uncertain,
        "specific_evidence_hits": evidence_hits,
    }


def score_report(path: Path | None, *, poc_dir: Path | None = None) -> dict[str, object]:
    if path is None:
        return {"path": None, "score": 0, "pass": False, "slop": {"score": 10, "pass": False}}
    text = read_text(path)
    score = 45
    score += min(20, len(text.split()) // 80)
    score += 10 if re.search(r"impact|risk|severity|cvss", text, re.I) else 0
    score += 10 if re.search(r"repro|steps|poc|proof", text, re.I) else 0
    score += 10 if SPECIFIC_EVIDENCE.search(text) else 0
    score += 5 if re.search(r"remediation|fix|mitigation", text, re.I) else 0
    score = max(0, min(100, score))

    external_score = None
    scorer = PROJECT_ROOT / "tools" / "report_scorer.py"
    if scorer.exists():
        cmd = ["python3", str(scorer), str(path), "--json"]
        if poc_dir is not None:
            cmd.extend(["--poc-dir", str(poc_dir)])
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        try:
            payload = json.loads(proc.stdout)
            external_score = payload.get("overall_score") or payload.get("score") or payload.get("composite")
        except json.JSONDecodeError:
            external_score = None

    final_score = int(external_score) if isinstance(external_score, (int, float)) else score
    return {
        "path": rel(path),
        "score": final_score,
        "pass": final_score >= 75,
        "heuristic_score": score,
        "external_score": external_score,
        "slop": score_slop(text),
    }


def load_review_verdict(package: Path) -> dict[str, object] | None:
    for path in list(package.rglob("submission_review.json")) + list(package.rglob("triager_sim_result.json")):
        try:
            return {"path": rel(path), "payload": json.loads(path.read_text(encoding="utf-8"))}
        except (OSError, json.JSONDecodeError):
            continue
    return None


def score_package(package: Path, *, expected_outcome: str = "unknown") -> dict[str, object]:
    report = choose_report(package)
    pocs = choose_pocs(package)
    poc_scores = [score_poc(path) for path in pocs]
    best_tier = min((item["tier"] for item in poc_scores), default=4)
    inventory = package_inventory(package)
    evidence_complete = bool(inventory["reports"]) and bool(inventory["pocs"]) and bool(inventory["evidence"])
    return {
        "package": rel(package),
        "expected_outcome": expected_outcome,
        "inventory": inventory,
        "report": score_report(report, poc_dir=package),
        "pocs": poc_scores,
        "best_poc_tier": best_tier,
        "evidence_complete": evidence_complete,
        "review": load_review_verdict(package),
    }


def iter_manifest_packages(manifest: dict[str, object]) -> list[tuple[str, Path, str]]:
    result: list[tuple[str, Path, str]] = []
    source_root = Path(str(manifest.get("source_root") or PROJECT_ROOT)).expanduser()
    source_root = source_root.resolve()
    packages = manifest.get("packages", {})
    if not isinstance(packages, dict):
        return result
    for group, items in packages.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            if isinstance(path, str):
                package_path = Path(path)
                if not package_path.is_absolute():
                    package_path = source_root / package_path
                result.append((str(item.get("name", path)), package_path, group))
    return result


def compare_scores(baseline: list[dict[str, object]], candidate: list[dict[str, object]]) -> dict[str, object]:
    def package_key(item: dict[str, object]) -> str:
        name = item.get("name")
        if isinstance(name, str) and name:
            return name
        return Path(str(item["package"])).name

    by_name = {package_key(item): item for item in candidate}
    comparable = 0
    matched_or_better = 0
    regressions: list[dict[str, object]] = []
    for base in baseline:
        name = package_key(base)
        cand = by_name.get(name)
        if not cand:
            continue
        comparable += 1
        base_score = base["report"]["score"]
        cand_score = cand["report"]["score"]
        if cand_score >= base_score:
            matched_or_better += 1
        else:
            regressions.append({"package": name, "baseline": base_score, "candidate": cand_score})
    rate = (matched_or_better / comparable) if comparable else None
    return {"comparable": comparable, "matched_or_better": matched_or_better, "match_rate": rate, "regressions": regressions}


def candidate_profile(item: dict[str, object]) -> str:
    package = Path(str(item.get("package") or ""))
    parts = package.parts
    if "candidate_replay" in parts:
        idx = parts.index("candidate_replay")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return "candidate"


def compare_scores_by_profile(baseline: list[dict[str, object]], candidate: list[dict[str, object]]) -> dict[str, object]:
    grouped: dict[str, list[dict[str, object]]] = {}
    for item in candidate:
        grouped.setdefault(candidate_profile(item), []).append(item)
    return {profile: compare_scores(baseline, items) for profile, items in sorted(grouped.items())}


def write_markdown(path: Path, payload: dict[str, object]) -> None:
    lines = ["# Submission Quality Delta", ""]
    lines.append(f"Generated: {payload['generated_at']}")
    comparison = payload.get("comparison") or {}
    if comparison:
        lines.append("")
        lines.append(f"- Comparable packages: {comparison.get('comparable')}")
        lines.append(f"- Matched or better: {comparison.get('matched_or_better')}")
        lines.append(f"- Match rate: {comparison.get('match_rate')}")
    elif not payload.get("candidate"):
        lines.append("")
        lines.append("- Candidate packages: not scored in this run; this report is baseline-only fixture calibration.")
    profile_comparison = payload.get("profile_comparison") or {}
    if profile_comparison:
        lines.append("")
        lines.append("## Profile Comparison")
        lines.append("")
        lines.append("| Profile | Comparable | Matched or Better | Match Rate | Regressions |")
        lines.append("|---|---:|---:|---:|---:|")
        for profile, item in profile_comparison.items():
            lines.append(
                f"| {profile} | {item.get('comparable')} | {item.get('matched_or_better')} | "
                f"{item.get('match_rate')} | {len(item.get('regressions', []))} |"
            )
    lines.append("")
    lines.append("| Set | Profile | Package | Report | Slop | Best PoC | Evidence | Decision |")
    lines.append("|---|---|---|---:|---:|---:|---|---|")
    for set_name in ["baseline", "candidate"]:
        for item in payload.get(set_name, []):
            package_name = item.get("name") or item["package"]
            profile = candidate_profile(item) if set_name == "candidate" else "baseline"
            review = item.get("review") or {}
            review_payload = review.get("payload") if isinstance(review, dict) else {}
            decision = review_payload.get("decision", "") if isinstance(review_payload, dict) else ""
            lines.append(
                f"| {set_name} | {profile} | {package_name} | {item['report']['score']} | "
                f"{item['report']['slop']['score']} | {item['best_poc_tier']} | "
                f"{'yes' if item['evidence_complete'] else 'no'} | {decision} |"
            )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-manifest", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path)
    parser.add_argument("--out-dir", type=Path)
    args = parser.parse_args()

    manifest = json.loads(args.baseline_manifest.read_text(encoding="utf-8"))
    baseline: list[dict[str, object]] = []
    for name, path, group in iter_manifest_packages(manifest):
        if group not in {"positive", "negative", "gold"} or not path.exists():
            continue
        item = score_package(path, expected_outcome=group)
        item["name"] = name
        item["source_group"] = group
        baseline.append(item)

    candidate: list[dict[str, object]] = []
    if args.candidate_root and args.candidate_root.exists():
        roots = [p for p in args.candidate_root.glob("**/submission") if p.is_dir()]
        if not roots:
            roots = [args.candidate_root]
        for path in roots:
            item = score_package(path, expected_outcome="candidate")
            item["name"] = path.parent.name if path.name == "submission" else path.name
            candidate.append(item)

    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "baseline_manifest": rel(args.baseline_manifest),
        "candidate_root": rel(args.candidate_root) if args.candidate_root else None,
        "baseline": baseline,
        "candidate": candidate,
        "comparison": compare_scores(baseline, candidate) if candidate else {},
        "profile_comparison": compare_scores_by_profile(baseline, candidate) if candidate else {},
    }

    out_dir = args.out_dir or (PROJECT_ROOT / "reports" / "runtime-eval" / time.strftime("%Y%m%d_%H%M%S"))
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "quality_delta.json"
    md_path = out_dir / "quality_delta.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(md_path, payload)
    print(json_path)
    print(md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
