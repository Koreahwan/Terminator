# Terminator Pipeline Benchmarking Framework

Measures solve quality across the 20 solved CTF challenges.

## Metrics
- **Accuracy**: flag_correct / total (%)
- **Solve time**: seconds from start to FLAG_FOUND
- **Agent count**: number of agents spawned
- **Token estimate**: approximate tokens consumed
- **Pipeline type**: agent chain used (reverser→chain→... etc.)

## Usage

```bash
# Run all 20 solved challenges benchmark
python3 tests/benchmarks/benchmark.py --all

# Benchmark a single challenge
python3 tests/benchmarks/benchmark.py --challenge pwnablekr_fd --flag "mommy! I think I know what a file descriptor is!!" --time 120 --tokens 15000

# Print summary report from existing results
python3 tests/benchmarks/benchmark.py --report

# Inspect an external held-out benchmark checkout
python3 tests/benchmarks/benchmark.py --catalog-root /path/to/NYU_CTF_Bench

# Emit a machine-readable selected task manifest
python3 tests/benchmarks/benchmark.py --catalog-root /path/to/NYU_CTF_Bench \
  --catalog-split development --catalog-limit 25 --catalog-json-out /tmp/nyu-dev-manifest.json

# Initialize a held-out run ledger from that manifest
python3 tests/benchmarks/benchmark.py --ledger-manifest /tmp/nyu-dev-manifest.json \
  --ledger-label nyu-dev-baseline --ledger-out /tmp/nyu-dev-ledger.json

# Update one ledger entry after a run attempt, then print aggregate summary
python3 tests/benchmarks/benchmark.py --ledger-update /tmp/nyu-dev-ledger.json \
  --ledger-entry-id nyu_ctf_bench:development:chal-a --ledger-status passed \
  --ledger-attempt-json '{"first_flag_latency_sec": 12.5, "pass_k": 1}'
python3 tests/benchmarks/benchmark.py --ledger-report /tmp/nyu-dev-ledger.json

# Ask for the next pending task and ingest a real summary.json into the ledger
python3 tests/benchmarks/benchmark.py --ledger-next /tmp/nyu-dev-ledger.json \
  --ledger-next-split development
python3 tests/benchmarks/benchmark.py --ledger-record-summary /tmp/nyu-dev-ledger.json \
  --ledger-entry-id nyu_ctf_bench:development:chal-a --ledger-summary-path /path/to/summary.json

# Or dispatch the next pending task through the configured runner in one step
python3 tests/benchmarks/benchmark.py --ledger-run-next /tmp/nyu-dev-ledger.json \
  --ledger-next-split development --run-wait-seconds 60

# Or process multiple pending tasks sequentially
python3 tests/benchmarks/benchmark.py --ledger-run-batch /tmp/nyu-dev-ledger.json \
  --ledger-next-split development --run-wait-seconds 60 --batch-max-tasks 10

# Refresh running entries once their summary.json files appear
python3 tests/benchmarks/benchmark.py --ledger-refresh /tmp/nyu-dev-ledger.json

# Thin wrapper for the whole held-out experiment flow
TERMINATOR_BENCHMARK_RUNNER="bash ./terminator.sh" \
  ./tests/benchmarks/external_run.sh --root /path/to/NYU_CTF_Bench \
  --split development --limit 25 --label nyu-dev --wait-seconds 60 --batch-max 25

# Recommended for real runs: force the underlying runner to wait and time out per task
TERMINATOR_BENCHMARK_RUNNER="bash ./terminator.sh" \
TERMINATOR_BENCHMARK_RUNNER_ARGS="--wait --timeout 600" \
  ./tests/benchmarks/external_run.sh --root /path/to/NYU_CTF_Bench \
  --split development --limit 5 --label nyu-dev-timed --wait-seconds 0 --batch-max 5

# List external held-out benchmark tasks from a local checkout
python3 tools/ctf_competition.py catalog --root /path/to/NYU_CTF_Bench --json
```

## Files
- `benchmark.py` — main benchmark runner
- `results.jsonl` — all run results (append-only)
- `summary.json` — latest aggregate statistics
- `weekly_run.sh` — cron script for weekly auto-run
- `runs/` — archived per-run summaries

## Competition Scaffold

`tools/ctf_competition.py` provides additive benchmark catalog discovery for
held-out corpora such as NYU_CTF_Bench, Cybench, pwncollege `ctf-archive`,
and CTF-Dojo style layouts. This scaffold is read-only and does not replace
the current replay/writeup-oriented benchmark flow. The benchmark CLI can also
export a filtered machine-readable manifest for later held-out evaluation runs,
then initialize, dispatch, update, and summarize a pending run ledger from that manifest, including sequential batch processing.

## Weekly Auto-Run (cron)
```
# Add to crontab: runs every Monday at 09:00
0 9 * * 1 /path/to/Terminator/tests/benchmarks/weekly_run.sh
```

## Challenge Registry
20 solved challenges tracked:
- dhcc, too_many_questions, damnida, conquergent (reversing/crypto)
- pwnablekr: fd, col, horcruxes, asm, memcpy, passcode, cmd1, cmd2, random, input, input2, leg, lotto, mistake, coin1, blackjack (pwn)
