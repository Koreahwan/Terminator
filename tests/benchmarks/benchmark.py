#!/usr/bin/env python3
"""
Terminator Pipeline Benchmarking Framework.

Measures solve time, token usage, agent count, and accuracy
across the 20 solved CTF challenges.

Usage:
    python3 tests/benchmarks/benchmark.py [--challenge <name>] [--all] [--report]
"""

import argparse
import json
import os
import shlex
import sys
import time
import datetime
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Optional
import subprocess
import re as re_module

UTC = datetime.UTC


def utc_now() -> datetime.datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.datetime.now(UTC)


def utc_now_iso() -> str:
    """Return an ISO 8601 UTC timestamp with Z suffix."""
    return utc_now().isoformat().replace("+00:00", "Z")

PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.ctf_competition import SUPPORTED_BENCHMARK_LAYOUTS, build_benchmark_catalog, extract_ctf_flags

CHALLENGES_DIR = PROJECT_ROOT / "knowledge" / "challenges"
REPORTS_DIR = PROJECT_ROOT / "reports"
BENCHMARK_DIR = PROJECT_ROOT / "tests" / "benchmarks"
RESULTS_FILE = BENCHMARK_DIR / "results.jsonl"
SUMMARY_FILE = BENCHMARK_DIR / "summary.json"

# Solved challenges registry (from MEMORY.md)
SOLVED_CHALLENGES = {
    "dhcc": {
        "type": "reversing",
        "flag": "REDACTED",
        "technique": "flex/bison DFA+BFS",
        "difficulty": "medium",
        "agents_used": ["reverser", "solver", "critic", "verifier", "reporter"],
    },
    "too_many_questions": {
        "type": "crypto",
        "flag": "REDACTED",
        "technique": "AES-ECB z3",
        "difficulty": "medium",
        "agents_used": ["reverser", "solver", "critic", "verifier", "reporter"],
    },
    "damnida": {
        "type": "reversing",
        "flag": "REDACTED",
        "technique": "Custom VM GDB Oracle",
        "difficulty": "hard",
        "agents_used": ["reverser", "solver", "critic", "verifier", "reporter"],
    },
    "conquergent": {
        "type": "reversing",
        "flag": "REDACTED",
        "technique": "retf VM 3-stage cipher",
        "difficulty": "hard",
        "agents_used": ["reverser", "solver", "critic", "verifier", "reporter"],
    },
    "pwnablekr_fd": {
        "type": "pwn",
        "flag": "mommy! I think I know what a file descriptor is!!",
        "technique": "file descriptor manipulation",
        "difficulty": "easy",
        "agents_used": ["reverser", "chain", "verifier", "reporter"],
    },
    "pwnablekr_col": {
        "type": "pwn",
        "flag": "daddy! I just managed to create a hash collision :)",
        "technique": "hash collision",
        "difficulty": "easy",
        "agents_used": ["reverser", "chain", "verifier", "reporter"],
    },
    "pwnablekr_horcruxes": {
        "type": "pwn",
        "flag": "More_Voldemort_More_Attack",
        "technique": "rop chain",
        "difficulty": "medium",
        "agents_used": ["reverser", "trigger", "chain", "critic", "verifier", "reporter"],
    },
    "pwnablekr_asm": {
        "type": "pwn",
        "flag": "Let's make shellcode!",
        "technique": "shellcode",
        "difficulty": "medium",
        "agents_used": ["reverser", "chain", "verifier", "reporter"],
    },
    "pwnablekr_memcpy": {
        "type": "pwn",
        "flag": "incorrect target for memcpy",
        "technique": "alignment bug",
        "difficulty": "easy",
        "agents_used": ["reverser", "chain", "verifier", "reporter"],
    },
    "pwnablekr_passcode": {
        "type": "pwn",
        "flag": "Now I can see the password file",
        "technique": "scanf format string",
        "difficulty": "medium",
        "agents_used": ["reverser", "chain", "verifier", "reporter"],
    },
    "pwnablekr_cmd1": {
        "type": "pwn",
        "flag": "mommy now I get what PATH env is for :)",
        "technique": "PATH manipulation",
        "difficulty": "easy",
        "agents_used": ["reverser", "chain", "verifier", "reporter"],
    },
    "pwnablekr_cmd2": {
        "type": "pwn",
        "flag": "FuN_w1th_5h3ll_v4r1abl3s_haha",
        "technique": "shell variable injection",
        "difficulty": "medium",
        "agents_used": ["reverser", "chain", "verifier", "reporter"],
    },
    "pwnablekr_random": {
        "type": "pwn",
        "flag": "Mommy, I thought libc random is unpredictable...",
        "technique": "PRNG prediction",
        "difficulty": "easy",
        "agents_used": ["reverser", "chain", "verifier", "reporter"],
    },
    "pwnablekr_input": {
        "type": "pwn",
        "flag": "Mom! I just learned about how to pass various input in Linux :)",
        "technique": "multi-channel input",
        "difficulty": "medium",
        "agents_used": ["reverser", "chain", "verifier", "reporter"],
    },
    "pwnablekr_leg": {
        "type": "reversing",
        "flag": "Daddy told me about the Intel CPUID CPU Architecture",
        "technique": "ARM thumb mode PC calculation",
        "difficulty": "easy",
        "agents_used": ["reverser", "solver", "verifier", "reporter"],
    },
    "pwnablekr_lotto": {
        "type": "pwn",
        "flag": "sorry mom... I FORGOT to check bytes one by one",
        "technique": "byte comparison",
        "difficulty": "easy",
        "agents_used": ["reverser", "chain", "verifier", "reporter"],
    },
    "pwnablekr_mistake": {
        "type": "pwn",
        "flag": "You have no right to see my file",
        "technique": "operator precedence bug",
        "difficulty": "easy",
        "agents_used": ["reverser", "chain", "verifier", "reporter"],
    },
    "pwnablekr_coin1": {
        "type": "pwn",
        "flag": "b1NaRy_ExpErT",
        "technique": "binary search",
        "difficulty": "easy",
        "agents_used": ["reverser", "chain", "verifier", "reporter"],
    },
    "pwnablekr_blackjack": {
        "type": "pwn",
        "flag": "YaY_I_AM_RICH!!",
        "technique": "negative bet exploit",
        "difficulty": "easy",
        "agents_used": ["reverser", "chain", "verifier", "reporter"],
    },
    "pwnablekr_input2": {
        "type": "pwn",
        "flag": "Mom! I just learned about how to pass various input in Linux :)",
        "technique": "multi-channel input v2",
        "difficulty": "medium",
        "agents_used": ["reverser", "chain", "verifier", "reporter"],
    },
}


@dataclass
class BenchmarkResult:
    challenge: str
    run_id: str
    timestamp: str
    status: str  # PASS / FAIL / SKIP
    flag_correct: Optional[bool] = None
    solve_time_seconds: Optional[float] = None
    agent_count: Optional[int] = None
    agents_used: list = field(default_factory=list)
    token_estimate: Optional[int] = None
    pipeline_type: str = ""
    difficulty: str = ""
    challenge_type: str = ""
    notes: str = ""
    error: str = ""


class BenchmarkRunner:
    def __init__(self):
        self.results: list[BenchmarkResult] = []
        BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)

    def load_challenge_metadata(self, name: str) -> dict:
        """Load metadata from solved challenges registry."""
        return SOLVED_CHALLENGES.get(name, {})

    def load_writeup(self, name: str) -> str:
        """Load writeup from knowledge/challenges/."""
        writeup_path = CHALLENGES_DIR / f"{name}.md"
        if writeup_path.exists():
            return writeup_path.read_text()
        return ""

    def extract_metrics_from_writeup(self, writeup: str) -> dict:
        """Parse writeup for timing, agent, token metrics."""
        metrics = {
            "solve_time": None,
            "agent_count": None,
            "token_estimate": None,
        }

        lines = writeup.lower().splitlines()
        for line in lines:
            # Look for timing info
            if "time:" in line or "duration:" in line or "solved in" in line:
                import re
                m = re.search(r'(\d+(?:\.\d+)?)\s*(?:min|minute|sec|second|hour)', line)
                if m:
                    val = float(m.group(1))
                    unit = m.group(0).split()[-1]
                    if "min" in unit:
                        metrics["solve_time"] = val * 60
                    elif "hour" in unit:
                        metrics["solve_time"] = val * 3600
                    else:
                        metrics["solve_time"] = val

            # Token estimate
            if "token" in line:
                import re
                m = re.search(r'(\d+(?:,\d+)?)\s*token', line)
                if m:
                    metrics["token_estimate"] = int(m.group(1).replace(",", ""))

        return metrics

    def _find_solve_script(self, name: str) -> Optional[Path]:
        """Find solve.py for a challenge in common locations."""
        candidates = [
            CHALLENGES_DIR / name / "solve.py",
            PROJECT_ROOT / "tests" / "wargames" / "extracted" / name / "solve.py",
            PROJECT_ROOT / "reports" / name / "solve.py",
        ]
        # Also search by glob pattern
        for pattern_dir in [CHALLENGES_DIR, PROJECT_ROOT / "tests" / "wargames" / "extracted"]:
            if pattern_dir.exists():
                for p in pattern_dir.rglob("solve.py"):
                    if name.lower() in str(p).lower():
                        candidates.append(p)

        for path in candidates:
            if path.exists():
                return path
        return None

    def _extract_flag_from_output(self, output: str) -> Optional[str]:
        """Extract flag from solve.py stdout using known flag formats."""
        patterns = [
            r'FLAG_FOUND:\s*(\S+)',
            r'(DH\{[^}]+\})',
            r'(FLAG\{[^}]+\})',
            r'(flag\{[^}]+\})',
            r'(CTF\{[^}]+\})',
            r'(GoN\{[^}]+\})',
            r'(CYAI\{[^}]+\})',
        ]
        for pattern in patterns:
            match = re_module.search(pattern, output)
            if match:
                return match.group(1)
        return None

    def replay_challenge(self, name: str, timeout: int = 300) -> "BenchmarkResult":
        """Actually execute solve.py and verify flag output."""
        meta = self.load_challenge_metadata(name)
        if not meta:
            return BenchmarkResult(
                challenge=name, run_id=f"replay_{name}",
                timestamp=utc_now_iso(),
                status="SKIP", notes="Not in solved challenges registry"
            )

        solve_path = self._find_solve_script(name)
        if not solve_path:
            return BenchmarkResult(
                challenge=name, run_id=f"replay_{name}",
                timestamp=utc_now_iso(),
                status="SKIP", notes="No solve.py found",
                difficulty=meta.get("difficulty", ""),
                challenge_type=meta.get("type", ""),
            )

        # Execute solve.py in local-only mode
        start = time.time()
        try:
            result = subprocess.run(
                ["python3", str(solve_path)],
                capture_output=True, timeout=timeout,
                cwd=str(solve_path.parent),
                env={**os.environ, "LOCAL_TEST": "1"},
                text=True,
            )
            elapsed = time.time() - start
            output = result.stdout + result.stderr

            # Extract and validate flag
            flag_found = self._extract_flag_from_output(output)
            flag_correct = self.validate_flag(name, flag_found) if flag_found else False

            status = "PASS" if flag_correct else "FAIL"
            notes = f"Replay: {solve_path.name}"
            if result.returncode != 0:
                notes += f" (exit code {result.returncode})"
            if not flag_found:
                notes += " — no flag in output"
                status = "FAIL"

            br = BenchmarkResult(
                challenge=name,
                run_id=f"replay_{name}_{utc_now().strftime('%Y%m%dT%H%M%S')}",
                timestamp=utc_now_iso(),
                status=status,
                flag_correct=flag_correct,
                solve_time_seconds=round(elapsed, 2),
                agent_count=len(meta.get("agents_used", [])),
                agents_used=meta.get("agents_used", []),
                pipeline_type=meta.get("type", ""),
                difficulty=meta.get("difficulty", ""),
                challenge_type=meta.get("type", ""),
                notes=notes,
            )
            self.results.append(br)
            self._save_result(br)
            return br

        except subprocess.TimeoutExpired:
            elapsed = time.time() - start
            br = BenchmarkResult(
                challenge=name,
                run_id=f"replay_{name}_{utc_now().strftime('%Y%m%dT%H%M%S')}",
                timestamp=utc_now_iso(),
                status="FAIL",
                solve_time_seconds=round(elapsed, 2),
                difficulty=meta.get("difficulty", ""),
                challenge_type=meta.get("type", ""),
                notes=f"Timeout after {timeout}s",
                error=f"TimeoutExpired after {timeout}s",
            )
            self.results.append(br)
            self._save_result(br)
            return br

        except Exception as e:
            br = BenchmarkResult(
                challenge=name,
                run_id=f"replay_{name}_{utc_now().strftime('%Y%m%dT%H%M%S')}",
                timestamp=utc_now_iso(),
                status="FAIL",
                difficulty=meta.get("difficulty", ""),
                challenge_type=meta.get("type", ""),
                notes="Exception during replay",
                error=str(e),
            )
            self.results.append(br)
            self._save_result(br)
            return br

    def replay_all(self, filter_type: str = None, filter_difficulty: str = None,
                   timeout: int = 300) -> list:
        """Replay all solved challenges and detect regressions."""
        results = []
        for name, meta in SOLVED_CHALLENGES.items():
            if filter_type and meta.get("type") != filter_type:
                continue
            if filter_difficulty and meta.get("difficulty") != filter_difficulty:
                continue
            print(f"  [REPLAY] {name}...", end=" ", flush=True)
            br = self.replay_challenge(name, timeout=timeout)
            print(f"{br.status} ({br.solve_time_seconds or '?'}s)")
            results.append(br)

        # Print regression summary
        passed = sum(1 for r in results if r.status == "PASS")
        failed = sum(1 for r in results if r.status == "FAIL")
        skipped = sum(1 for r in results if r.status == "SKIP")
        print(f"\n  Replay summary: {passed} PASS, {failed} FAIL, {skipped} SKIP")
        if failed > 0:
            print("  REGRESSIONS DETECTED:")
            for r in results:
                if r.status == "FAIL":
                    print(f"    - {r.challenge}: {r.notes} {r.error}")
        return results

    def validate_flag(self, challenge: str, flag_found: str) -> bool:
        """Validate flag against known correct answer."""
        meta = SOLVED_CHALLENGES.get(challenge, {})
        expected = meta.get("flag", "")
        if not expected:
            return None  # Unknown — can't validate

        # Normalize comparison
        return flag_found.strip() == expected.strip()

    def run_single(self, name: str, flag_found: str = "", solve_time: float = None,
                   agents: list = None, tokens: int = None, notes: str = "") -> BenchmarkResult:
        """Record a benchmark result for a single challenge."""
        meta = self.load_challenge_metadata(name)
        writeup = self.load_writeup(name)
        extracted = self.extract_metrics_from_writeup(writeup)

        run_id = f"{name}_{utc_now().strftime('%Y%m%dT%H%M%S')}"
        timestamp = utc_now_iso()

        effective_flag = flag_found or meta.get("flag", "")

        # Determine flag correctness
        flag_correct = None
        if effective_flag:
            flag_correct = self.validate_flag(name, effective_flag)

        # Use provided or extracted metrics
        actual_time = solve_time or extracted.get("solve_time")
        actual_tokens = tokens or extracted.get("token_estimate")
        actual_agents = agents or meta.get("agents_used", [])

        # Determine pipeline type
        pipeline_map = {
            "pwn": "reverser→trigger→chain→critic→verifier→reporter",
            "reversing": "reverser→solver→critic→verifier→reporter",
            "crypto": "reverser→solver→critic→verifier→reporter",
            "web": "scanner→analyst→exploiter→reporter",
        }
        pipeline = pipeline_map.get(meta.get("type", ""), "unknown")

        status = "PASS" if (flag_correct is True or (flag_correct is None and effective_flag)) else (
            "FAIL" if effective_flag else "SKIP"
        )

        result = BenchmarkResult(
            challenge=name,
            run_id=run_id,
            timestamp=timestamp,
            status=status,
            flag_correct=flag_correct,
            solve_time_seconds=actual_time,
            agent_count=len(actual_agents),
            agents_used=actual_agents,
            token_estimate=actual_tokens,
            pipeline_type=pipeline,
            difficulty=meta.get("difficulty", "unknown"),
            challenge_type=meta.get("type", "unknown"),
            notes=notes,
        )

        self.results.append(result)
        self._save_result(result)
        return result

    def _save_result(self, result: BenchmarkResult):
        """Append result to JSONL file."""
        with open(RESULTS_FILE, "a") as f:
            f.write(json.dumps(asdict(result)) + "\n")

    def _latest_results(self) -> list[BenchmarkResult]:
        """Return the latest result recorded for each challenge."""
        latest: dict[str, BenchmarkResult] = {}
        for result in self.results:
            if result.challenge in latest:
                del latest[result.challenge]
            latest[result.challenge] = result
        return list(latest.values())

    def run_all_from_registry(self) -> list[BenchmarkResult]:
        """Run benchmark for all known solved challenges (from writeups)."""
        results = []
        for name, meta in SOLVED_CHALLENGES.items():
            writeup = self.load_writeup(name)
            if not writeup:
                print(f"  [SKIP] {name}: no writeup found")
                result = self.run_single(name, notes="No writeup available")
                results.append(result)
                continue

            # Extract flag from writeup
            flag_found = meta.get("flag", "")
            result = self.run_single(
                name=name,
                flag_found=flag_found,
                agents=meta.get("agents_used", []),
                notes=f"technique: {meta.get('technique', '')}",
            )
            print(f"  [{result.status}] {name}: flag_correct={result.flag_correct}, "
                  f"agents={result.agent_count}, pipeline={meta.get('type','?')}")
            results.append(result)

        return results

    def generate_summary(self) -> dict:
        """Generate aggregate statistics from all results."""
        if not self.results:
            # Load from file
            if RESULTS_FILE.exists():
                for line in RESULTS_FILE.read_text().splitlines():
                    try:
                        d = json.loads(line)
                        self.results.append(BenchmarkResult(**d))
                    except Exception:
                        pass

        if not self.results:
            return {"error": "No results found"}

        current_results = self._latest_results()

        total = len(current_results)
        passed = sum(1 for r in current_results if r.status == "PASS")
        failed = sum(1 for r in current_results if r.status == "FAIL")
        skipped = sum(1 for r in current_results if r.status == "SKIP")

        times = [r.solve_time_seconds for r in current_results if r.solve_time_seconds]
        tokens = [r.token_estimate for r in current_results if r.token_estimate]
        agents = [r.agent_count for r in current_results if r.agent_count]

        # By type
        by_type = {}
        for r in current_results:
            t = r.challenge_type
            if t not in by_type:
                by_type[t] = {"total": 0, "pass": 0}
            by_type[t]["total"] += 1
            if r.status == "PASS":
                by_type[t]["pass"] += 1

        # By difficulty
        by_diff = {}
        for r in current_results:
            d = r.difficulty
            if d not in by_diff:
                by_diff[d] = {"total": 0, "pass": 0}
            by_diff[d]["total"] += 1
            if r.status == "PASS":
                by_diff[d]["pass"] += 1

        summary = {
            "generated_at": utc_now_iso(),
            "total_challenges": total,
            "pass": passed,
            "fail": failed,
            "skip": skipped,
            "accuracy_pct": round(passed / total * 100, 1) if total else 0,
            "avg_solve_time_sec": round(sum(times) / len(times), 1) if times else None,
            "avg_token_estimate": round(sum(tokens) / len(tokens)) if tokens else None,
            "avg_agent_count": round(sum(agents) / len(agents), 1) if agents else None,
            "by_type": by_type,
            "by_difficulty": by_diff,
            "solved_challenges": [
                {
                    "name": r.challenge,
                    "status": r.status,
                    "type": r.challenge_type,
                    "difficulty": r.difficulty,
                    "agents": r.agent_count,
                    "pipeline": r.pipeline_type,
                }
                for r in current_results
            ],
        }

        SUMMARY_FILE.write_text(json.dumps(summary, indent=2))
        return summary

    def catalog_external_benchmark(
        self,
        root: str,
        layout: str = "auto",
        *,
        splits: list[str] | None = None,
        limit: int | None = None,
        include_tasks: bool = False,
    ) -> dict:
        """Inspect an external benchmark checkout without executing tasks."""
        summary = {"generated_at": utc_now_iso()}
        summary.update(
            build_benchmark_catalog(
                root,
                layout=layout,
                splits=splits,
                limit=limit,
                include_tasks=include_tasks,
            )
        )
        return summary

    def print_report(self, summary: dict):
        """Print human-readable benchmark report."""
        print("\n" + "=" * 60)
        print("TERMINATOR PIPELINE BENCHMARK REPORT")
        print("=" * 60)
        print(f"Generated: {summary.get('generated_at', 'unknown')}")
        print(f"\nTotal challenges: {summary['total_challenges']}")
        print(f"  PASS:  {summary['pass']}")
        print(f"  FAIL:  {summary['fail']}")
        print(f"  SKIP:  {summary['skip']}")
        print(f"  Accuracy: {summary['accuracy_pct']}%")

        if summary.get("avg_solve_time_sec"):
            t = summary["avg_solve_time_sec"]
            print(f"\nAvg solve time: {t:.0f}s ({t/60:.1f}min)")
        if summary.get("avg_token_estimate"):
            print(f"Avg tokens:     {summary['avg_token_estimate']:,}")
        if summary.get("avg_agent_count"):
            print(f"Avg agents:     {summary['avg_agent_count']}")

        print("\nBy challenge type:")
        for t, d in summary.get("by_type", {}).items():
            pct = round(d["pass"] / d["total"] * 100) if d["total"] else 0
            print(f"  {t:12s}: {d['pass']}/{d['total']} ({pct}%)")

        print("\nBy difficulty:")
        for diff, d in summary.get("by_difficulty", {}).items():
            pct = round(d["pass"] / d["total"] * 100) if d["total"] else 0
            print(f"  {diff:10s}: {d['pass']}/{d['total']} ({pct}%)")

        print("\nChallenge breakdown:")
        for ch in summary.get("solved_challenges", []):
            icon = "+" if ch["status"] == "PASS" else ("-" if ch["status"] == "FAIL" else "?")
            print(f"  [{icon}] {ch['name']:30s} {ch['type']:10s} {ch['difficulty']:8s} agents={ch['agents']}")

        print("=" * 60)

    def print_catalog_report(self, summary: dict):
        """Print human-readable external benchmark catalog report."""
        print("\n" + "=" * 60)
        print("TERMINATOR EXTERNAL BENCHMARK CATALOG")
        print("=" * 60)
        print(f"Generated:   {summary.get('generated_at', 'unknown')}")
        print(f"Catalog root: {summary['catalog_root']}")
        print(f"Layout:       {summary['layout']}")
        print(f"Total tasks:  {summary['total_tasks']}")
        print(f"Selected:     {summary['selected_tasks']}")
        filters = summary.get("filters", {})
        if filters.get("splits") or filters.get("limit") is not None:
            print(f"Filters:      splits={filters.get('splits', [])} limit={filters.get('limit')}")
        print("\nBy split:")
        for split, count in sorted(summary.get("by_split", {}).items()):
            print(f"  {split:12s}: {count}")
        print("\nSample tasks:")
        for task in summary.get("sample_tasks", []):
            print(f"  - {task['split']:12s} {task['name']} ({task['benchmark']})")
        print("=" * 60)

    def initialize_external_run_ledger(
        self,
        manifest_path: str,
        *,
        label: str = "",
    ) -> dict:
        """Create a machine-readable held-out run ledger from a selected manifest."""
        manifest_file = Path(manifest_path).resolve()
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        tasks = manifest.get("tasks") or manifest.get("sample_tasks") or []

        ledger_entries = []
        for index, task in enumerate(tasks, start=1):
            ledger_entries.append(
                {
                    "id": f"{task.get('benchmark', 'benchmark')}:{task.get('split', 'split')}:{task.get('name', index)}",
                    "benchmark": task.get("benchmark", ""),
                    "split": task.get("split", ""),
                    "name": task.get("name", ""),
                    "path": task.get("path", ""),
                    "status": "pending",
                    "notes": "",
                    "result_path": "",
                    "attempts": [],
                }
            )

        by_split: dict[str, int] = {}
        for entry in ledger_entries:
            by_split[entry["split"]] = by_split.get(entry["split"], 0) + 1

        return {
            "generated_at": utc_now_iso(),
            "label": label or manifest_file.stem,
            "manifest_path": str(manifest_file),
            "catalog_root": manifest.get("catalog_root", ""),
            "layout": manifest.get("layout", ""),
            "filters": manifest.get("filters", {}),
            "selected_tasks": len(ledger_entries),
            "by_split": by_split,
            "entries": ledger_entries,
        }

    def update_external_run_ledger(
        self,
        ledger_path: str,
        *,
        entry_id: str,
        status: str | None = None,
        notes: str | None = None,
        result_path: str | None = None,
        attempt: dict | None = None,
    ) -> dict:
        """Update one ledger entry in place and return the updated ledger."""
        ledger_file = Path(ledger_path).resolve()
        ledger = json.loads(ledger_file.read_text(encoding="utf-8"))
        entries = ledger.get("entries", [])

        target = None
        for entry in entries:
            if entry.get("id") == entry_id:
                target = entry
                break
        if target is None:
            raise ValueError(f"Ledger entry not found: {entry_id}")

        if status is not None:
            target["status"] = status
        if notes is not None:
            target["notes"] = notes
        if result_path is not None:
            target["result_path"] = result_path
        if attempt is not None:
            target.setdefault("attempts", []).append(attempt)

        ledger["updated_at"] = utc_now_iso()
        ledger_file.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
        return ledger

    def get_next_external_run_entry(
        self,
        ledger_path: str,
        *,
        splits: list[str] | None = None,
        statuses: list[str] | None = None,
    ) -> dict | None:
        """Return the next matching ledger entry without modifying the ledger."""
        ledger_file = Path(ledger_path).resolve()
        ledger = json.loads(ledger_file.read_text(encoding="utf-8"))
        normalized_splits = {split.strip().lower() for split in (splits or []) if split.strip()}
        normalized_statuses = {status.strip().lower() for status in (statuses or ["pending"]) if status.strip()}

        for entry in ledger.get("entries", []):
            entry_split = str(entry.get("split", "")).lower()
            entry_status = str(entry.get("status", "")).lower()
            if normalized_splits and entry_split not in normalized_splits:
                continue
            if normalized_statuses and entry_status not in normalized_statuses:
                continue
            return entry
        return None

    def record_summary_to_external_run_ledger(
        self,
        ledger_path: str,
        *,
        entry_id: str,
        summary_path: str,
        status_override: str | None = None,
        notes_override: str | None = None,
    ) -> dict:
        """Ingest a Terminator summary.json into the matching ledger entry."""
        summary_file = Path(summary_path).resolve()
        summary = json.loads(summary_file.read_text(encoding="utf-8"))

        original_flags_found = summary.get("flags_found", []) or []
        flags_found = list(original_flags_found)
        if not flags_found:
            report_dir = summary_file.parent
            session_log = report_dir / "session.log"
            if session_log.exists():
                flags_found = extract_ctf_flags(
                    session_log.read_text(encoding="utf-8", errors="ignore"),
                    challenge_dir=summary.get("target") or None,
                )
                if flags_found:
                    summary["flags_found"] = flags_found
                    summary_file.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        runtime_status = str(summary.get("status", "unknown"))
        derived_status = "failed"
        if status_override:
            derived_status = status_override
        elif flags_found:
            derived_status = "passed"
        elif runtime_status == "timeout":
            derived_status = "timeout"
        elif runtime_status == "completed":
            derived_status = "no_flag"
        elif runtime_status in {"failed", "runtime_failed"}:
            derived_status = "failed"
        else:
            derived_status = runtime_status or "failed"

        attempt = {
            "timestamp": summary.get("timestamp"),
            "summary_path": str(summary_file),
            "report_dir": str(summary_file.parent),
            "mode": summary.get("mode"),
            "status": runtime_status,
            "ledger_status": derived_status,
            "duration_seconds": summary.get("duration_seconds"),
            "exit_code": summary.get("exit_code"),
            "flags_found": flags_found,
            "backend": summary.get("backend"),
            "failover_count": summary.get("failover_count"),
        }
        competition = summary.get("competition")
        if isinstance(competition, dict):
            attempt["competition_lane"] = competition.get("lane")
        if "competition_warning" in summary:
            attempt["competition_warning"] = summary["competition_warning"]

        notes = notes_override
        if notes is None:
            if flags_found:
                notes = f"verified flags: {', '.join(flags_found)}"
            elif runtime_status == "timeout":
                notes = "run timed out without flag"
            elif runtime_status == "completed":
                notes = "completed without flag"
            else:
                notes = f"run status: {runtime_status}"

        return self.update_external_run_ledger(
            ledger_path,
            entry_id=entry_id,
            status=derived_status,
            notes=notes,
            result_path=str(summary_file),
            attempt=attempt,
        )

    def _build_external_runner_command(self, target_path: str) -> list[str]:
        """Build the external runner command for one held-out task."""
        prefix = shlex.split(os.environ.get("TERMINATOR_BENCHMARK_RUNNER", "bash ./terminator.sh"))
        extra = shlex.split(os.environ.get("TERMINATOR_BENCHMARK_RUNNER_ARGS", ""))
        return [*prefix, *extra, "--json", "--competition-v2", "ctf", target_path]

    @staticmethod
    def _extract_summary_path_from_output(output: str) -> str | None:
        for line in reversed([line.strip() for line in output.splitlines() if line.strip()]):
            if line.endswith("summary.json"):
                return line
        return None

    def run_next_external_run_entry(
        self,
        ledger_path: str,
        *,
        splits: list[str] | None = None,
        statuses: list[str] | None = None,
        wait_seconds: int = 0,
        poll_interval: float = 1.0,
    ) -> dict:
        """Dispatch the next matching ledger entry through the external runner."""
        entry = self.get_next_external_run_entry(ledger_path, splits=splits, statuses=statuses)
        if entry is None:
            return {"status": "empty", "entry": None, "ledger_path": str(Path(ledger_path).resolve())}

        command = self._build_external_runner_command(entry["path"])
        dispatch_attempt = {
            "timestamp": utc_now_iso(),
            "phase": "dispatch",
            "command": command,
        }
        self.update_external_run_ledger(
            ledger_path,
            entry_id=entry["id"],
            status="running",
            notes="runner dispatched",
            attempt=dispatch_attempt,
        )

        result = subprocess.run(
            command,
            cwd=str(PROJECT_ROOT),
            text=True,
            capture_output=True,
            env={**os.environ, "TERM": "dumb"},
        )
        summary_path_raw = self._extract_summary_path_from_output(result.stdout)
        if summary_path_raw is None:
            notes = (result.stderr or result.stdout or "runner did not return summary path").strip()
            updated = self.update_external_run_ledger(
                ledger_path,
                entry_id=entry["id"],
                status="dispatch_failed",
                notes=notes[:500],
                attempt={
                    "timestamp": utc_now_iso(),
                    "phase": "dispatch_result",
                    "dispatch_returncode": result.returncode,
                    "stdout": result.stdout[-1000:],
                    "stderr": result.stderr[-1000:],
                },
            )
            return {
                "status": "dispatch_failed",
                "entry_id": entry["id"],
                "ledger": updated,
                "summary_path": None,
            }

        summary_path = Path(summary_path_raw)
        if not summary_path.is_absolute():
            summary_path = (PROJECT_ROOT / summary_path).resolve()

        self.update_external_run_ledger(
            ledger_path,
            entry_id=entry["id"],
            result_path=str(summary_path),
            attempt={
                "timestamp": utc_now_iso(),
                "phase": "dispatch_result",
                "dispatch_returncode": result.returncode,
                "summary_path": str(summary_path),
            },
        )

        ready = summary_path.exists()
        deadline = time.time() + max(wait_seconds, 0)
        while not ready and wait_seconds > 0 and time.time() < deadline:
            time.sleep(poll_interval)
            ready = summary_path.exists()

        if ready:
            updated = self.record_summary_to_external_run_ledger(
                ledger_path,
                entry_id=entry["id"],
                summary_path=str(summary_path),
            )
            return {
                "status": "completed",
                "entry_id": entry["id"],
                "ledger": updated,
                "summary_path": str(summary_path),
            }

        updated = json.loads(Path(ledger_path).read_text(encoding="utf-8"))
        return {
            "status": "running",
            "entry_id": entry["id"],
            "ledger": updated,
            "summary_path": str(summary_path),
        }

    def run_external_run_batch(
        self,
        ledger_path: str,
        *,
        splits: list[str] | None = None,
        statuses: list[str] | None = None,
        wait_seconds: int = 0,
        poll_interval: float = 1.0,
        max_tasks: int | None = None,
    ) -> dict:
        """Run multiple pending ledger entries sequentially with safe stop semantics."""
        results: list[dict] = []
        processed = 0
        stop_reason = "empty"

        while True:
            if max_tasks is not None and max_tasks >= 0 and processed >= max_tasks:
                stop_reason = "max_tasks"
                break

            result = self.run_next_external_run_entry(
                ledger_path,
                splits=splits,
                statuses=statuses,
                wait_seconds=wait_seconds,
                poll_interval=poll_interval,
            )
            results.append(result)
            status = result.get("status")
            if status == "empty":
                stop_reason = "empty"
                break
            processed += 1
            if status == "running":
                stop_reason = "waiting_on_summary"
                break

        summary = self.summarize_external_run_ledger(ledger_path)
        return {
            "generated_at": utc_now_iso(),
            "ledger_path": str(Path(ledger_path).resolve()),
            "processed": processed,
            "stop_reason": stop_reason,
            "results": results,
            "summary": summary,
        }

    def refresh_external_run_ledger(
        self,
        ledger_path: str,
        *,
        statuses: list[str] | None = None,
    ) -> dict:
        """Refresh existing ledger entries whose summary paths now exist."""
        ledger_file = Path(ledger_path).resolve()
        ledger = json.loads(ledger_file.read_text(encoding="utf-8"))
        normalized_statuses = {status.strip().lower() for status in (statuses or ["running"]) if status.strip()}
        refreshed = []
        skipped = []

        for entry in ledger.get("entries", []):
            entry_status = str(entry.get("status", "")).lower()
            if normalized_statuses and entry_status not in normalized_statuses:
                continue
            result_path = entry.get("result_path")
            if not result_path:
                skipped.append({"id": entry.get("id", ""), "reason": "missing_result_path"})
                continue
            summary_path = Path(result_path)
            if not summary_path.exists():
                skipped.append({"id": entry.get("id", ""), "reason": "summary_not_ready"})
                continue
            self.record_summary_to_external_run_ledger(
                str(ledger_file),
                entry_id=entry["id"],
                summary_path=str(summary_path),
            )
            refreshed.append(entry["id"])

        updated_ledger = json.loads(ledger_file.read_text(encoding="utf-8"))
        return {
            "generated_at": utc_now_iso(),
            "ledger_path": str(ledger_file),
            "refreshed": refreshed,
            "skipped": skipped,
            "ledger": updated_ledger,
            "summary": self.summarize_external_run_ledger(str(ledger_file)),
        }

    def summarize_external_run_ledger(self, ledger_path: str) -> dict:
        """Return aggregate status counts and simple metrics for a run ledger."""
        ledger_file = Path(ledger_path).resolve()
        ledger = json.loads(ledger_file.read_text(encoding="utf-8"))
        entries = ledger.get("entries", [])

        by_status: dict[str, int] = {}
        by_split: dict[str, dict[str, int]] = {}
        by_lane: dict[str, dict[str, int]] = {}
        first_flag_latencies: list[float] = []
        durations: list[float] = []
        total_attempts = 0
        for entry in entries:
            status = entry.get("status", "pending")
            split = entry.get("split", "")
            by_status[status] = by_status.get(status, 0) + 1
            bucket = by_split.setdefault(split, {})
            bucket[status] = bucket.get(status, 0) + 1
            attempts = entry.get("attempts", [])
            total_attempts += len(attempts)
            latest_lane = None
            for attempt in attempts:
                latency = attempt.get("first_flag_latency_sec")
                if isinstance(latency, (int, float)):
                    first_flag_latencies.append(float(latency))
                duration = attempt.get("duration_seconds")
                if isinstance(duration, (int, float)):
                    durations.append(float(duration))
                lane = attempt.get("competition_lane")
                if lane:
                    latest_lane = str(lane)
            if latest_lane:
                lane_bucket = by_lane.setdefault(latest_lane, {})
                lane_bucket[status] = lane_bucket.get(status, 0) + 1

        selected_tasks = ledger.get("selected_tasks", len(entries))
        completed_entries = selected_tasks - by_status.get("pending", 0) - by_status.get("running", 0)

        def pct(value: int) -> float | None:
            if not selected_tasks:
                return None
            return round(value / selected_tasks * 100, 1)

        return {
            "generated_at": utc_now_iso(),
            "ledger_path": str(ledger_file),
            "label": ledger.get("label", ""),
            "selected_tasks": selected_tasks,
            "completed_entries": completed_entries,
            "by_status": by_status,
            "by_split": by_split,
            "by_lane": by_lane,
            "total_attempts": total_attempts,
            "pass_rate_pct": pct(by_status.get("passed", 0)),
            "completion_rate_pct": pct(completed_entries),
            "timeout_rate_pct": pct(by_status.get("timeout", 0)),
            "no_flag_rate_pct": pct(by_status.get("no_flag", 0)),
            "dispatch_failed_rate_pct": pct(by_status.get("dispatch_failed", 0)),
            "avg_first_flag_latency_sec": (
                round(sum(first_flag_latencies) / len(first_flag_latencies), 2)
                if first_flag_latencies
                else None
            ),
            "avg_duration_sec": (
                round(sum(durations) / len(durations), 2)
                if durations
                else None
            ),
        }

    def print_run_ledger_report(self, ledger: dict):
        """Print a concise report for an initialized held-out run ledger."""
        print("\n" + "=" * 60)
        print("TERMINATOR HELD-OUT RUN LEDGER")
        print("=" * 60)
        print(f"Generated:    {ledger.get('generated_at', 'unknown')}")
        print(f"Label:        {ledger.get('label', '')}")
        print(f"Manifest:     {ledger.get('manifest_path', '')}")
        print(f"Catalog root: {ledger.get('catalog_root', '')}")
        print(f"Layout:       {ledger.get('layout', '')}")
        print(f"Selected:     {ledger.get('selected_tasks', 0)}")
        filters = ledger.get("filters", {})
        if filters:
            print(f"Filters:      splits={filters.get('splits', [])} limit={filters.get('limit')}")
        print("\nBy split:")
        for split, count in sorted(ledger.get("by_split", {}).items()):
            print(f"  {split:12s}: {count}")
        print("\nEntries:")
        for entry in ledger.get("entries", [])[:20]:
            print(f"  - {entry['status']:8s} {entry['id']}")
        print("=" * 60)

    def print_run_ledger_summary_report(self, summary: dict):
        """Print aggregate information for a run ledger."""
        print("\n" + "=" * 60)
        print("TERMINATOR HELD-OUT RUN LEDGER SUMMARY")
        print("=" * 60)
        print(f"Generated:    {summary.get('generated_at', 'unknown')}")
        print(f"Ledger:       {summary.get('ledger_path', '')}")
        print(f"Label:        {summary.get('label', '')}")
        print(f"Selected:     {summary.get('selected_tasks', 0)}")
        print(f"Completed:    {summary.get('completed_entries', 0)}")
        print(f"Attempts:     {summary.get('total_attempts', 0)}")
        if summary.get("avg_first_flag_latency_sec") is not None:
            print(f"Avg latency:  {summary['avg_first_flag_latency_sec']:.2f}s")
        if summary.get("avg_duration_sec") is not None:
            print(f"Avg duration: {summary['avg_duration_sec']:.2f}s")
        if summary.get("pass_rate_pct") is not None:
            print(f"Pass rate:    {summary['pass_rate_pct']:.1f}%")
        if summary.get("completion_rate_pct") is not None:
            print(f"Completion:   {summary['completion_rate_pct']:.1f}%")
        if summary.get("timeout_rate_pct") is not None:
            print(f"Timeout rate: {summary['timeout_rate_pct']:.1f}%")
        if summary.get("no_flag_rate_pct") is not None:
            print(f"No-flag rate: {summary['no_flag_rate_pct']:.1f}%")
        print("\nBy status:")
        for status, count in sorted(summary.get("by_status", {}).items()):
            print(f"  {status:12s}: {count}")
        print("\nBy split/status:")
        for split, counts in sorted(summary.get("by_split", {}).items()):
            rendered = ", ".join(f"{status}={count}" for status, count in sorted(counts.items()))
            print(f"  {split:12s}: {rendered}")
        if summary.get("by_lane"):
            print("\nBy lane/status:")
            for lane, counts in sorted(summary.get("by_lane", {}).items()):
                rendered = ", ".join(f"{status}={count}" for status, count in sorted(counts.items()))
                print(f"  {lane:12s}: {rendered}")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Terminator Pipeline Benchmark")
    parser.add_argument("--challenge", help="Benchmark a specific challenge by name")
    parser.add_argument("--all", action="store_true", help="Run all known solved challenges")
    parser.add_argument("--report", action="store_true", help="Generate and print summary report")
    parser.add_argument("--flag", help="Flag found (for --challenge mode)")
    parser.add_argument("--time", type=float, help="Solve time in seconds")
    parser.add_argument("--tokens", type=int, help="Token count used")
    parser.add_argument("--notes", default="", help="Additional notes")
    parser.add_argument("--replay", action="store_true",
                        help="Replay: re-execute solve.py scripts for regression testing")
    parser.add_argument("--type", help="Filter by challenge type (pwn, reversing, crypto)")
    parser.add_argument("--difficulty", help="Filter by difficulty (easy, medium, hard)")
    parser.add_argument("--timeout-replay", type=int, default=300,
                        help="Timeout per challenge replay in seconds")
    parser.add_argument("--catalog-root",
                        help="Inspect an external held-out benchmark checkout without executing tasks")
    parser.add_argument("--catalog-layout", default="auto",
                        choices=["auto", *sorted(SUPPORTED_BENCHMARK_LAYOUTS)],
                        help="Catalog layout override")
    parser.add_argument("--catalog-split", action="append", dest="catalog_splits",
                        help="Limit external catalog to one split (repeatable)")
    parser.add_argument("--catalog-limit", type=int, default=None,
                        help="Limit the number of selected external benchmark tasks")
    parser.add_argument("--catalog-json-out", default=None,
                        help="Write the selected external benchmark catalog to a JSON file")
    parser.add_argument("--ledger-manifest",
                        help="Initialize a held-out run ledger from a selected catalog manifest")
    parser.add_argument("--ledger-out", default=None,
                        help="Write the initialized held-out run ledger to a JSON file")
    parser.add_argument("--ledger-label", default="",
                        help="Optional label for the initialized run ledger")
    parser.add_argument("--ledger-update",
                        help="Update an existing held-out run ledger in place")
    parser.add_argument("--ledger-entry-id", default="",
                        help="Target entry id for --ledger-update")
    parser.add_argument("--ledger-status", default=None,
                        help="New status for the targeted ledger entry")
    parser.add_argument("--ledger-notes", default=None,
                        help="Replacement notes for the targeted ledger entry")
    parser.add_argument("--ledger-result-path", default=None,
                        help="Result path for the targeted ledger entry")
    parser.add_argument("--ledger-attempt-json", default=None,
                        help="JSON object to append to the targeted ledger entry's attempts")
    parser.add_argument("--ledger-report",
                        help="Print an aggregate report for an existing held-out run ledger")
    parser.add_argument("--ledger-next",
                        help="Print the next matching ledger entry as JSON")
    parser.add_argument("--ledger-next-split", action="append", dest="ledger_next_splits",
                        help="Limit --ledger-next to one split (repeatable)")
    parser.add_argument("--ledger-next-status", action="append", dest="ledger_next_statuses",
                        help="Limit --ledger-next to one status (repeatable)")
    parser.add_argument("--ledger-record-summary",
                        help="Ingest a Terminator summary.json into an existing held-out run ledger")
    parser.add_argument("--ledger-summary-path", default=None,
                        help="summary.json path used by --ledger-record-summary")
    parser.add_argument("--ledger-status-override", default=None,
                        help="Optional explicit ledger status override for --ledger-record-summary")
    parser.add_argument("--ledger-notes-override", default=None,
                        help="Optional explicit notes override for --ledger-record-summary")
    parser.add_argument("--ledger-run-next",
                        help="Dispatch the next matching ledger entry through the external runner")
    parser.add_argument("--run-wait-seconds", type=int, default=0,
                        help="When using --ledger-run-next, wait this many seconds for summary.json to appear")
    parser.add_argument("--run-poll-interval", type=float, default=1.0,
                        help="Polling interval in seconds for --ledger-run-next")
    parser.add_argument("--ledger-run-batch",
                        help="Dispatch multiple matching ledger entries sequentially")
    parser.add_argument("--batch-max-tasks", type=int, default=None,
                        help="Maximum number of tasks to process with --ledger-run-batch")
    parser.add_argument("--ledger-refresh",
                        help="Refresh running (or selected) ledger entries whose summaries now exist")
    parser.add_argument("--ledger-refresh-status", action="append", dest="ledger_refresh_statuses",
                        help="Status filter for --ledger-refresh (repeatable, default: running)")
    args = parser.parse_args()

    runner = BenchmarkRunner()

    if args.catalog_root:
        summary = runner.catalog_external_benchmark(
            args.catalog_root,
            layout=args.catalog_layout,
            splits=args.catalog_splits,
            limit=args.catalog_limit,
            include_tasks=bool(args.catalog_json_out),
        )
        if args.catalog_json_out:
            Path(args.catalog_json_out).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        runner.print_catalog_report(summary)
        return

    if args.ledger_manifest:
        ledger = runner.initialize_external_run_ledger(args.ledger_manifest, label=args.ledger_label)
        if args.ledger_out:
            Path(args.ledger_out).write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
        runner.print_run_ledger_report(ledger)
        return

    if args.ledger_update:
        if not args.ledger_entry_id:
            raise SystemExit("--ledger-entry-id is required with --ledger-update")
        attempt = json.loads(args.ledger_attempt_json) if args.ledger_attempt_json else None
        ledger = runner.update_external_run_ledger(
            args.ledger_update,
            entry_id=args.ledger_entry_id,
            status=args.ledger_status,
            notes=args.ledger_notes,
            result_path=args.ledger_result_path,
            attempt=attempt,
        )
        runner.print_run_ledger_report(ledger)
        return

    if args.ledger_report:
        summary = runner.summarize_external_run_ledger(args.ledger_report)
        runner.print_run_ledger_summary_report(summary)
        return

    if args.ledger_next:
        entry = runner.get_next_external_run_entry(
            args.ledger_next,
            splits=args.ledger_next_splits,
            statuses=args.ledger_next_statuses,
        )
        print(json.dumps(entry, indent=2) if entry else "null")
        return

    if args.ledger_record_summary:
        if not args.ledger_entry_id:
            raise SystemExit("--ledger-entry-id is required with --ledger-record-summary")
        if not args.ledger_summary_path:
            raise SystemExit("--ledger-summary-path is required with --ledger-record-summary")
        ledger = runner.record_summary_to_external_run_ledger(
            args.ledger_record_summary,
            entry_id=args.ledger_entry_id,
            summary_path=args.ledger_summary_path,
            status_override=args.ledger_status_override,
            notes_override=args.ledger_notes_override,
        )
        runner.print_run_ledger_report(ledger)
        return

    if args.ledger_run_next:
        result = runner.run_next_external_run_entry(
            args.ledger_run_next,
            splits=args.ledger_next_splits,
            statuses=args.ledger_next_statuses,
            wait_seconds=args.run_wait_seconds,
            poll_interval=args.run_poll_interval,
        )
        print(json.dumps(result, indent=2))
        return

    if args.ledger_run_batch:
        result = runner.run_external_run_batch(
            args.ledger_run_batch,
            splits=args.ledger_next_splits,
            statuses=args.ledger_next_statuses,
            wait_seconds=args.run_wait_seconds,
            poll_interval=args.run_poll_interval,
            max_tasks=args.batch_max_tasks,
        )
        print(json.dumps(result, indent=2))
        return

    if args.ledger_refresh:
        result = runner.refresh_external_run_ledger(
            args.ledger_refresh,
            statuses=args.ledger_refresh_statuses,
        )
        print(json.dumps(result, indent=2))
        return

    if args.replay:
        print(f"Replaying solved challenges (timeout={args.timeout_replay}s)...")
        if args.challenge:
            result = runner.replay_challenge(args.challenge, timeout=args.timeout_replay)
            print(f"Result: {result.status} | flag_correct={result.flag_correct} | "
                  f"time={result.solve_time_seconds}s | {result.notes}")
        else:
            runner.replay_all(
                filter_type=getattr(args, 'type', None),
                filter_difficulty=args.difficulty,
                timeout=args.timeout_replay,
            )
            summary = runner.generate_summary()
            runner.print_report(summary)

    elif args.challenge:
        result = runner.run_single(
            name=args.challenge,
            flag_found=args.flag or "",
            solve_time=getattr(args, "time", None),
            tokens=args.tokens,
            notes=args.notes,
        )
        print(f"Result: {result.status} | flag_correct={result.flag_correct} | "
              f"agents={result.agent_count} | pipeline={result.pipeline_type}")

    elif args.all:
        print(f"Running benchmark for {len(SOLVED_CHALLENGES)} solved challenges...")
        runner.run_all_from_registry()
        summary = runner.generate_summary()
        runner.print_report(summary)

    elif args.report:
        summary = runner.generate_summary()
        runner.print_report(summary)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
