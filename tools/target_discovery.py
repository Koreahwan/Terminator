#!/usr/bin/env python3
"""Discover and rank live bug bounty targets using passive public metadata."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = PROJECT_ROOT / "tools"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(1, str(TOOLS_DIR))

from backend_smoke import parse_agent_messages
from submission_candidate_replay import extract_first_json
from tools.program_fetcher.dispatch import fetch as fetch_program


DEFAULT_H1_SEEDS = [
    "https://hackerone.com/discourse",
    "https://hackerone.com/django",
    "https://hackerone.com/zabbix",
    "https://hackerone.com/kubernetes",
    "https://hackerone.com/neon",
    "https://hackerone.com/vercel-open-source",
]

PROFILE_MODEL = {
    "claude-only": "claude-opus-4-6[1m]",
    "gpt-only": "gpt-5.5",
}


def fetch_json(url: str, *, timeout: int = 25) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "terminator-target-discovery/0.1",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def collect_yeswehack(*, pages: int, page_size: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for page in range(1, pages + 1):
        query = urllib.parse.urlencode(
            {
                "filter[type][]": "bug-bounty",
                "page[number]": page,
                "page[size]": page_size,
            }
        )
        payload = fetch_json(f"https://api.yeswehack.com/programs?{query}")
        for item in payload.get("items", []):
            if not item.get("public") or not item.get("bounty") or item.get("archived") or item.get("disabled"):
                continue
            slug = item.get("slug")
            if not slug:
                continue
            candidates.append(
                {
                    "source": "yeswehack-api",
                    "platform": "yeswehack",
                    "name": item.get("title") or slug,
                    "handle": slug,
                    "program_url": f"https://yeswehack.com/programs/{slug}",
                    "api_url": f"https://api.yeswehack.com/programs/{slug}",
                    "bounty_min": item.get("bounty_reward_min") or 0,
                    "bounty_max": item.get("bounty_reward_max") or 0,
                    "reports_count": item.get("reports_count") or 0,
                    "avg_first_response_days": item.get("average_first_response_time"),
                    "scopes_count": item.get("scopes_count") or 0,
                    "last_update_at": item.get("last_update_at") or "",
                    "activity_area": item.get("activity_area") or "",
                    "raw": item,
                }
            )
    return candidates


def parse_money(value: Any) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value or "")
    nums = [int(x.replace(",", "")) for x in re.findall(r"\d[\d,]*", text)]
    return max(nums) if nums else 0


def severity_reward(row: Any) -> Any:
    if isinstance(row, dict):
        return row.get("max") or row.get("reward") or row.get("bounty")
    return getattr(row, "reward", "")


def collect_seed_programs(seed_urls: list[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for url in seed_urls:
        try:
            result = fetch_program(url, use_cache=False)
        except Exception as exc:  # noqa: BLE001 - discovery keeps weak candidates with error evidence.
            candidates.append({"source": "seed-fetch-error", "program_url": url, "error": f"{type(exc).__name__}: {exc}"})
            continue
        data = result.data
        max_bounty = max(
            [parse_money((data.bounty_range or {}).get("max"))]
            + [parse_money(severity_reward(row)) for row in data.severity_table]
        )
        min_bounty = parse_money((data.bounty_range or {}).get("min"))
        candidates.append(
            {
                "source": "seed-program-fetcher",
                "platform": data.platform,
                "name": data.name or data.handle or url,
                "handle": data.handle,
                "program_url": data.program_url or url,
                "bounty_min": min_bounty,
                "bounty_max": max_bounty,
                "reports_count": None,
                "avg_first_response_days": None,
                "scopes_count": len(data.scope_in),
                "last_update_at": data.last_modified or "",
                "fetch_verdict": result.verdict,
                "fetch_confidence": result.confidence,
                "scope_in_count": len(data.scope_in),
                "scope_out_count": len(data.scope_out),
                "severity_rows": len(data.severity_table),
                "warnings": data.warnings,
            }
        )
    return candidates


def heuristic_score(candidate: dict[str, Any]) -> float:
    max_bounty = parse_money(candidate.get("bounty_max"))
    reports = candidate.get("reports_count")
    response = candidate.get("avg_first_response_days")
    scopes = int(candidate.get("scopes_count") or candidate.get("scope_in_count") or 0)
    score = 0.0

    if max_bounty:
        score += min(4.0, math.log10(max_bounty + 1) * 1.2)
    if response is not None:
        try:
            score += max(0.0, 2.0 - min(float(response), 14.0) / 7.0)
        except (TypeError, ValueError):
            pass
    if reports is not None:
        try:
            report_count = int(reports)
            if report_count <= 50:
                score += 2.0
            elif report_count <= 150:
                score += 1.0
            elif report_count >= 500:
                score -= 1.5
        except (TypeError, ValueError):
            pass
    if scopes >= 2:
        score += min(1.5, scopes / 6.0)
    name = f"{candidate.get('name','')} {candidate.get('activity_area','')}".lower()
    if any(token in name for token in ["open source", "oss", "api", "developer", "identity", "bot", "database"]):
        score += 1.0
    if candidate.get("fetch_verdict") == "PASS":
        score += 1.0
    if candidate.get("error"):
        score -= 3.0
    return round(score, 2)


def dedupe(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_url: dict[str, dict[str, Any]] = {}
    for item in candidates:
        url = str(item.get("program_url") or "").rstrip("/")
        if not url:
            continue
        item["heuristic_score"] = heuristic_score(item)
        existing = by_url.get(url)
        if existing is None or item["heuristic_score"] > existing.get("heuristic_score", -999):
            by_url[url] = item
    return sorted(by_url.values(), key=lambda item: item.get("heuristic_score", 0), reverse=True)


def candidate_cards(candidates: list[dict[str, Any]], *, limit: int) -> str:
    lines = []
    for idx, item in enumerate(candidates[:limit], start=1):
        lines.append(
            "\n".join(
                [
                    f"## Candidate {idx}: {item.get('name')}",
                    f"- url: {item.get('program_url')}",
                    f"- platform: {item.get('platform')}",
                    f"- source: {item.get('source')}",
                    f"- heuristic_score: {item.get('heuristic_score')}",
                    f"- bounty_min/max: {item.get('bounty_min')} / {item.get('bounty_max')}",
                    f"- reports_count: {item.get('reports_count')}",
                    f"- avg_first_response_days: {item.get('avg_first_response_days')}",
                    f"- scopes_count: {item.get('scopes_count') or item.get('scope_in_count')}",
                    f"- scope_out_count: {item.get('scope_out_count')}",
                    f"- last_update_at: {item.get('last_update_at')}",
                    f"- warnings: {item.get('warnings', [])[:3]}",
                ]
            )
        )
    return "\n\n".join(lines)


def discovery_prompt(*, strategy: str, candidates: list[dict[str, Any]], proposer_output: dict[str, Any] | None = None) -> str:
    extra = ""
    if proposer_output:
        extra = "\n\nPrior model proposal to review:\n" + json.dumps(proposer_output, indent=2, ensure_ascii=False)
    return f"""
You are the Terminator target-discovery agent.

Task:
Rank live bug bounty programs for a safe, high-signal bounty pipeline. The
benchmark criterion is: find likely real vulnerabilities without violating
scope or promoting OOS/low-evidence targets.

Strategy: {strategy}

Rules:
- Passive public metadata only. Do not scan assets, create accounts, submit, or
  request live exploitation.
- Prefer targets with clear cash bounty, fresh update, manageable report volume,
  good source/API surface, and scope clarity.
- Penalize no-cash, old/picked-clean, OOS-heavy, hardware-only, private-source,
  or ambiguous scope.
- If uncertain, use CONDITIONAL_GO and list exact missing checks.
- Return exactly one JSON object.

JSON schema:
{{
  "strategy": "{strategy}",
  "selected_url": "https://...",
  "selected_name": "name",
  "selected_platform": "platform",
  "decision": "GO|CONDITIONAL_GO|NO_GO",
  "score": 0,
  "scope_risk": "low|medium|high",
  "recommended_pipeline": "bounty|source_review|supplychain|ai_security",
  "top_candidates": [
    {{
      "program_url": "https://...",
      "name": "name",
      "decision": "GO|CONDITIONAL_GO|NO_GO",
      "score": 0,
      "why": "fact-backed reason",
      "safe_first_steps": ["fetch program", "source review"],
      "blocked_actions": ["live submit", "destructive testing"]
    }}
  ],
  "oos_guardrails": ["specific guardrail"],
  "rationale": "concise factual summary"
}}

Candidate metadata:
{candidate_cards(candidates, limit=len(candidates))}
{extra}
""".strip()


def run_model(model: str, prompt: str, *, timeout: int) -> tuple[dict[str, Any], str, float]:
    started = time.monotonic()
    if model.startswith("claude"):
        proc = subprocess.run(
            ["claude", "-p", "-", "--permission-mode", "bypassPermissions", "--model", model],
            cwd=str(PROJECT_ROOT),
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0:
            raise RuntimeError(output.strip() or f"claude failed rc={proc.returncode}")
        source = proc.stdout
    else:
        proc = subprocess.run(
            [
                "omx",
                "exec",
                "--dangerously-bypass-approvals-and-sandbox",
                "-C",
                str(PROJECT_ROOT),
                "-m",
                model,
                "--json",
                "-",
            ],
            cwd=str(PROJECT_ROOT),
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "TERMINATOR_SKIP_POLICY_INJECTION": "1"},
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0:
            raise RuntimeError(output.strip() or f"omx failed rc={proc.returncode}")
        messages = parse_agent_messages(output)
        source = messages[-1] if messages else output
    return extract_first_json(source), output, round(time.monotonic() - started, 2)


def run_profile(profile: str, candidates: list[dict[str, Any]], *, timeout: int) -> dict[str, Any]:
    if profile in PROFILE_MODEL:
        prompt = discovery_prompt(strategy=profile, candidates=candidates)
        payload, raw_output, duration = run_model(PROFILE_MODEL[profile], prompt, timeout=timeout)
        return {"profile": profile, "model": PROFILE_MODEL[profile], "duration_seconds": duration, "payload": payload, "raw_output": raw_output}

    if profile == "hybrid-a":
        first, out1, dur1 = run_model("gpt-5.5", discovery_prompt(strategy="hybrid-a-gpt-proposer", candidates=candidates), timeout=timeout)
        final, out2, dur2 = run_model(
            "claude-opus-4-6[1m]",
            discovery_prompt(strategy="hybrid-a-claude-scope-gate", candidates=candidates, proposer_output=first),
            timeout=timeout,
        )
        return {
            "profile": profile,
            "model": "gpt-5.5 -> claude-opus-4-6[1m]",
            "duration_seconds": round(dur1 + dur2, 2),
            "payload": final,
            "intermediate": first,
            "raw_output": out1 + "\n\n--- CLAUDE GATE ---\n\n" + out2,
        }

    if profile == "hybrid-b":
        first, out1, dur1 = run_model("claude-opus-4-6[1m]", discovery_prompt(strategy="hybrid-b-claude-proposer", candidates=candidates), timeout=timeout)
        final, out2, dur2 = run_model(
            "gpt-5.5",
            discovery_prompt(strategy="hybrid-b-gpt-challenger", candidates=candidates, proposer_output=first),
            timeout=timeout,
        )
        return {
            "profile": profile,
            "model": "claude-opus-4-6[1m] -> gpt-5.5",
            "duration_seconds": round(dur1 + dur2, 2),
            "payload": final,
            "intermediate": first,
            "raw_output": out1 + "\n\n--- GPT CHALLENGER ---\n\n" + out2,
        }

    raise ValueError(f"unknown profile: {profile}")


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    lines = ["# Target Discovery Results", "", f"Generated: {payload['generated_at']}", ""]
    lines.append("## Model Decisions")
    lines.append("")
    lines.append("| Profile | Model | Decision | Selected | Score | Scope Risk | Duration |")
    lines.append("|---|---|---|---|---:|---|---:|")
    for run in payload["model_runs"]:
        data = run["payload"]
        lines.append(
            f"| {run['profile']} | {run['model']} | {data.get('decision')} | "
            f"{data.get('selected_name')} | {data.get('score', 0)} | {data.get('scope_risk')} | {run['duration_seconds']}s |"
        )
    lines.append("")
    lines.append("## Heuristic Shortlist")
    lines.append("")
    lines.append("| Rank | Platform | Program | Bounty Max | Reports | Response | Heuristic | URL |")
    lines.append("|---:|---|---|---:|---:|---:|---:|---|")
    for idx, item in enumerate(payload["shortlist"], start=1):
        lines.append(
            f"| {idx} | {item.get('platform')} | {item.get('name')} | {item.get('bounty_max')} | "
            f"{item.get('reports_count')} | {item.get('avg_first_response_days')} | {item.get('heuristic_score')} | {item.get('program_url')} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--profiles", nargs="+", default=["claude-only", "gpt-only", "hybrid-a", "hybrid-b"])
    parser.add_argument("--yeswehack-pages", type=int, default=2)
    parser.add_argument("--yeswehack-page-size", type=int, default=42)
    parser.add_argument("--seed-url", action="append", default=[])
    parser.add_argument("--shortlist", type=int, default=12)
    parser.add_argument("--model-candidates", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=360)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    candidates = dedupe(
        collect_yeswehack(pages=args.yeswehack_pages, page_size=args.yeswehack_page_size)
        + collect_seed_programs(list(dict.fromkeys(DEFAULT_H1_SEEDS + args.seed_url)))
    )
    shortlist = candidates[: args.shortlist]
    model_candidates = shortlist[: args.model_candidates]

    model_runs: list[dict[str, Any]] = []
    for profile in args.profiles:
        print(f"[target-discovery] profile={profile}", flush=True)
        run = run_profile(profile, model_candidates, timeout=args.timeout)
        run_dir = args.out_dir / profile
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "raw_output.log").write_text(run.pop("raw_output"), encoding="utf-8")
        (run_dir / "result.json").write_text(json.dumps(run, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        model_runs.append(run)

    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": {
            "yeswehack_api": "https://api.yeswehack.com/programs?filter[type][]=bug-bounty",
            "hackerone_seeds": DEFAULT_H1_SEEDS + args.seed_url,
        },
        "candidate_count": len(candidates),
        "shortlist": shortlist,
        "model_candidates": model_candidates,
        "model_runs": model_runs,
        "recommended": model_runs[0]["payload"] if model_runs else {},
    }
    out_json = args.out_dir / "target_candidates.json"
    out_md = args.out_dir / "target_candidates.md"
    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(out_md, payload)
    print(out_json)
    print(out_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
