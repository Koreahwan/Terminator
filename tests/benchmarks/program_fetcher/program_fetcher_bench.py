#!/usr/bin/env python3
"""program_fetcher benchmark harness — main (jina+regex) vs dev (program_fetcher).

Measures:
    * success rate: was a ProgramData produced with the required fields?
    * verbatim accuracy: longest-common-substring ratio vs hand-frozen ground truth
    * latency: wall-time per URL per path
    * token proxy: len(returned_text) — lossy paths are shorter

Usage:
    # Capture baseline (run on `main` branch before merging dev).
    python3 tests/benchmarks/program_fetcher/program_fetcher_bench.py \\
        --path main --out tests/benchmarks/program_fetcher/results/main_baseline.json

    # Capture dev result.
    python3 tests/benchmarks/program_fetcher/program_fetcher_bench.py \\
        --path both --out tests/benchmarks/program_fetcher/results/dev_run.json

    # Diff and write markdown report.
    python3 tests/benchmarks/program_fetcher/program_fetcher_bench.py --report \\
        --baseline tests/benchmarks/program_fetcher/results/main_baseline.json \\
        --candidate tests/benchmarks/program_fetcher/results/dev_run.json \\
        > tests/benchmarks/program_fetcher/program_fetcher_bench_report.md

Network required. Each URL is hit by the main path (jina via
tools.knowledge_fetcher import path) and/or the dev path
(tools.program_fetcher.fetch). On the `main` branch the dev path is guarded by
an ImportError catch so the script still runs without the new package present.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

HERE = Path(__file__).resolve().parent
BENCH_URLS = HERE / "bench_urls.json"
GROUND_TRUTH = HERE / "ground_truth"


REQUIRED_FIELDS = ("name", "scope_in", "scope_out", "severity_table", "submission_rules")
PLATFORM_ACCURACY_MINIMUMS = {
    "immunefi": 0.95,
    "hackerone": 0.95,
    "yeswehack": 0.95,
    "bugcrowd": 0.95,
}
GLOBAL_ACCURACY_IMPROVEMENT_MIN = 0.20  # dev must beat main by >= 0.20 overall
LATENCY_CEILING_MULTIPLIER = 2.0  # dev median <= 2x main median per URL


# ---------------------------------------------------------------------------
# Main path (control): jina + thin regex extractor
# ---------------------------------------------------------------------------


def _main_path_fetch(url: str) -> dict[str, Any]:
    """Control: WebFetch(r.jina.ai/<url>) → markdown → regex section grab.

    Mirrors what target-evaluator does today with WebFetch. No LLM in the
    loop — we only measure the fetch+parse step.
    """
    t0 = time.monotonic()
    jina_url = f"https://r.jina.ai/{url}"
    req = urllib.request.Request(
        jina_url,
        headers={
            "Accept": "text/markdown",
            "User-Agent": "Terminator-ProgramFetcher-Bench/1.0",
        },
    )
    body = ""
    status = 0
    err = ""
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
        err = f"HTTPError {e.code}"
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    elapsed = time.monotonic() - t0

    fields = _regex_extract(body)
    return {
        "path": "main",
        "status": status,
        "error": err,
        "elapsed_seconds": round(elapsed, 3),
        "body_len": len(body),
        "raw": body,
        "extracted": fields,
    }


def _regex_extract(md: str) -> dict[str, Any]:
    """What target-evaluator does today: grep for likely sections."""
    import re
    def grab(heads: list[str]) -> str:
        for h in heads:
            m = re.search(
                rf"(?mi)^#{{1,4}}\s*{re.escape(h)}[^\n]*\n(.*?)(?=^#{{1,4}}\s|\Z)",
                md,
                re.DOTALL,
            )
            if m:
                return m.group(1).strip()
        return ""

    name = ""
    mt = re.search(r"^#\s+(.+)$", md, re.MULTILINE)
    if mt:
        name = mt.group(1).strip()

    return {
        "name": name,
        "scope_in": grab(["In Scope", "Scope", "Assets", "Targets"]),
        "scope_out": grab(["Out of Scope", "Out-of-Scope", "Exclusions", "Not in scope"]),
        "submission_rules": grab(["Rules", "Program Rules", "Disclosure Policy", "Ground Rules"]),
        "severity_table": grab(["Rewards", "Bounty", "Severity", "Payouts"]),
        "known_issues": grab(["Known Issues", "Known issues"]),
    }


# ---------------------------------------------------------------------------
# Dev path (treatment): tools.program_fetcher
# ---------------------------------------------------------------------------


def _dev_path_fetch(url: str) -> dict[str, Any]:
    """Treatment: tools.program_fetcher.fetch(url).

    Guarded by ImportError so this script still runs on the main branch.
    """
    t0 = time.monotonic()
    try:
        from tools.program_fetcher import fetch as pf_fetch  # type: ignore
    except ImportError as e:
        return {
            "path": "dev",
            "status": 0,
            "error": f"import_error: {e}",
            "elapsed_seconds": 0.0,
            "body_len": 0,
            "raw": "",
            "extracted": {},
            "verdict": "FAIL",
            "confidence": 0.0,
        }

    try:
        result = pf_fetch(url, use_cache=False)
        elapsed = time.monotonic() - t0
        data = result.data
        return {
            "path": "dev",
            "status": 200 if data.raw_markdown else 0,
            "error": result.error or "",
            "elapsed_seconds": round(elapsed, 3),
            "body_len": len(data.raw_markdown or ""),
            "raw": data.raw_markdown or "",
            "extracted": {
                "name": data.name,
                "scope_in": "\n".join(a.identifier for a in data.scope_in),
                "scope_out": "\n".join(data.scope_out),
                "submission_rules": data.submission_rules,
                "severity_table": "\n".join(
                    f"{r.severity}: {r.reward}" for r in data.severity_table
                ),
                "known_issues": "\n".join(data.known_issues),
            },
            "verdict": result.verdict,
            "confidence": result.confidence,
            "handlers_tried": [h.get("handler") for h in result.handlers_tried],
        }
    except Exception as e:
        elapsed = time.monotonic() - t0
        return {
            "path": "dev",
            "status": 0,
            "error": f"{type(e).__name__}: {e}",
            "elapsed_seconds": round(elapsed, 3),
            "body_len": 0,
            "raw": "",
            "extracted": {},
            "verdict": "FAIL",
            "confidence": 0.0,
        }


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def _required_field_coverage(extracted: dict[str, str]) -> float:
    present = sum(
        1 for f in REQUIRED_FIELDS
        if (extracted.get(f) or "").strip()
    )
    return round(present / len(REQUIRED_FIELDS), 3)


def _longest_common_substring_ratio(ground_truth: str, candidate: str) -> float:
    """Ratio of the longest common substring length to the ground truth length.

    Cheap O(n*m) DP — fine for fixtures under a few KB.
    """
    if not ground_truth or not candidate:
        return 0.0
    # Use difflib for efficiency; the math is equivalent.
    import difflib
    matcher = difflib.SequenceMatcher(None, ground_truth, candidate, autojunk=False)
    match = matcher.find_longest_match(0, len(ground_truth), 0, len(candidate))
    return round(match.size / len(ground_truth), 3)


def _verbatim_accuracy(ground_truth_md: str, extracted: dict[str, str]) -> float:
    """Average LCS ratio over the present verbatim fields.

    Ground truth is a single markdown file; we extract its sections via the
    same grep-style helper so the comparison is apples-to-apples per section.
    """
    if not ground_truth_md:
        return 0.0
    gt_fields = _regex_extract(ground_truth_md)
    ratios: list[float] = []
    for f in ("scope_in", "scope_out", "submission_rules", "severity_table"):
        gt_val = gt_fields.get(f, "") or ""
        cand_val = extracted.get(f, "") or ""
        if gt_val:
            ratios.append(_longest_common_substring_ratio(gt_val, cand_val))
    return round(statistics.mean(ratios), 3) if ratios else 0.0


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_bench(path_mode: str, out_path: Path) -> int:
    urls = json.loads(BENCH_URLS.read_text())["urls"]
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        git_sha = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            text=True,
        ).strip()
    except Exception:
        git_sha = "unknown"

    records: list[dict[str, Any]] = []
    for entry in urls:
        url_id = entry["id"]
        url = entry["url"]
        platform = entry["platform"]
        gt_file = entry.get("ground_truth")
        gt_md = ""
        if gt_file:
            gt_path = GROUND_TRUTH / gt_file
            if gt_path.exists():
                gt_md = gt_path.read_text(encoding="utf-8", errors="replace")

        print(f"[{url_id}] {url}", file=sys.stderr)

        paths_to_run: list[str] = []
        if path_mode in ("main", "both"):
            paths_to_run.append("main")
        if path_mode in ("dev", "both"):
            paths_to_run.append("dev")

        for p in paths_to_run:
            if p == "main":
                result = _main_path_fetch(url)
            else:
                result = _dev_path_fetch(url)
            result["id"] = url_id
            result["url"] = url
            result["platform"] = platform
            result["field_coverage"] = _required_field_coverage(result["extracted"])
            result["verbatim_accuracy"] = _verbatim_accuracy(gt_md, result["extracted"])
            # Don't dump raw body into the result file — too large; keep a
            # length proxy + trimmed sample for debugging.
            result["raw_sample"] = (result.pop("raw") or "")[:1000]
            records.append(result)
            print(
                f"  {p}: ok={bool(result['status'] == 200)} "
                f"t={result['elapsed_seconds']}s "
                f"cov={result['field_coverage']} "
                f"acc={result['verbatim_accuracy']}",
                file=sys.stderr,
            )

    payload = {
        "git_sha": git_sha,
        "path_mode": path_mode,
        "url_count": len(urls),
        "records": records,
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    print(f"\nwrote {out_path}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------


def _group_by(records: list[dict[str, Any]], key: str) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        out.setdefault(r.get(key, "_unknown"), []).append(r)
    return out


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    return round(statistics.median(values), 3)


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return round(statistics.mean(values), 3)


def run_report(baseline_path: Path, candidate_path: Path) -> int:
    baseline = json.loads(baseline_path.read_text())
    candidate = json.loads(candidate_path.read_text())

    # Baseline = main path only. Candidate = both paths (we re-derive main from it).
    main_records = [r for r in candidate["records"] if r["path"] == "main"]
    dev_records = [r for r in candidate["records"] if r["path"] == "dev"]
    if not main_records:
        main_records = [r for r in baseline["records"] if r["path"] == "main"]

    main_by_platform = _group_by(main_records, "platform")
    dev_by_platform = _group_by(dev_records, "platform")

    print("# program_fetcher benchmark — main vs dev\n")
    print(f"Baseline: `{baseline_path}` (git sha `{baseline.get('git_sha', '?')}`)")
    print(f"Candidate: `{candidate_path}` (git sha `{candidate.get('git_sha', '?')}`)")
    print()

    print("## Platform summary\n")
    print("| Platform | URLs | main success | dev success | main avg accuracy | dev avg accuracy | main median latency | dev median latency |")
    print("|---|---|---|---|---|---|---|---|")
    all_platforms = sorted(set(list(main_by_platform.keys()) + list(dev_by_platform.keys())))
    gate_failures: list[str] = []
    for platform in all_platforms:
        mr = main_by_platform.get(platform, [])
        dr = dev_by_platform.get(platform, [])

        def _success_rate(rs: list[dict[str, Any]]) -> float:
            if not rs:
                return 0.0
            ok = sum(1 for r in rs if r["status"] == 200 and r["field_coverage"] >= 0.6)
            return round(ok / len(rs), 3)

        m_succ = _success_rate(mr)
        d_succ = _success_rate(dr)
        m_acc = _mean([r["verbatim_accuracy"] for r in mr])
        d_acc = _mean([r["verbatim_accuracy"] for r in dr])
        m_lat = _median([r["elapsed_seconds"] for r in mr])
        d_lat = _median([r["elapsed_seconds"] for r in dr])

        print(f"| {platform} | {len(mr) or len(dr)} | {m_succ} | {d_succ} | {m_acc} | {d_acc} | {m_lat}s | {d_lat}s |")

        # Pass criteria
        if dr and mr and d_succ < m_succ:
            gate_failures.append(f"{platform}: success regressed ({m_succ} → {d_succ})")
        min_required = PLATFORM_ACCURACY_MINIMUMS.get(platform, 0.0)
        if dr and min_required and d_acc < min_required:
            gate_failures.append(
                f"{platform}: accuracy {d_acc} < required {min_required}"
            )
        if dr and mr and m_lat > 0 and d_lat > m_lat * LATENCY_CEILING_MULTIPLIER:
            gate_failures.append(
                f"{platform}: latency {d_lat}s > {LATENCY_CEILING_MULTIPLIER}x main ({m_lat}s)"
            )

    print()

    # Overall accuracy gate.
    m_overall = _mean([r["verbatim_accuracy"] for r in main_records])
    d_overall = _mean([r["verbatim_accuracy"] for r in dev_records])
    print(f"**Overall accuracy**: main={m_overall}, dev={d_overall}, delta={round(d_overall - m_overall, 3)}")
    if (d_overall - m_overall) < GLOBAL_ACCURACY_IMPROVEMENT_MIN and dev_records:
        gate_failures.append(
            f"global: accuracy delta {round(d_overall - m_overall, 3)} "
            f"< required {GLOBAL_ACCURACY_IMPROVEMENT_MIN}"
        )
    print()

    # Per-URL regression table
    print("## Per-URL regressions (dev accuracy < main accuracy - 0.05)\n")
    main_by_id = {r["id"]: r for r in main_records}
    regressions = []
    for d in dev_records:
        m = main_by_id.get(d["id"])
        if not m:
            continue
        delta = d["verbatim_accuracy"] - m["verbatim_accuracy"]
        if delta < -0.05:
            regressions.append((d["id"], m["verbatim_accuracy"], d["verbatim_accuracy"], delta))
    if regressions:
        print("| URL | main acc | dev acc | delta |")
        print("|---|---|---|---|")
        for rid, ma, da, delta in regressions:
            print(f"| {rid} | {ma} | {da} | {round(delta, 3)} |")
    else:
        print("_none_")
    print()

    # Exceptions
    print("## Unhandled exceptions on dev path\n")
    exc = [r for r in dev_records if r["error"] and "import_error" not in r["error"]]
    if exc:
        for r in exc:
            print(f"- `{r['id']}`: {r['error']}")
    else:
        print("_none_")
    print()

    # Verdict
    print("## Verdict\n")
    if gate_failures:
        print("**GATE: FAIL**\n")
        for f in gate_failures:
            print(f"- {f}")
        return 1
    print("**GATE: PASS** — dev path meets all benchmark criteria.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", choices=["main", "dev", "both"], default="both")
    parser.add_argument("--out", type=Path, default=HERE / "results" / "dev_run.json")
    parser.add_argument("--report", action="store_true", help="emit markdown report")
    parser.add_argument("--baseline", type=Path, help="baseline JSON for --report")
    parser.add_argument("--candidate", type=Path, help="candidate JSON for --report")
    args = parser.parse_args()

    if args.report:
        if not args.baseline or not args.candidate:
            print("error: --report requires --baseline and --candidate", file=sys.stderr)
            return 2
        return run_report(args.baseline, args.candidate)

    return run_bench(args.path, args.out)


if __name__ == "__main__":
    sys.exit(main())
