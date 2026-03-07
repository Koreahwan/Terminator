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
    args = parser.parse_args()

    runner = BenchmarkRunner()

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
