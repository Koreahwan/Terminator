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
```

## Files
- `benchmark.py` — main benchmark runner
- `results.jsonl` — all run results (append-only)
- `summary.json` — latest aggregate statistics
- `weekly_run.sh` — cron script for weekly auto-run
- `runs/` — archived per-run summaries

## Weekly Auto-Run (cron)
```
# Add to crontab: runs every Monday at 09:00
0 9 * * 1 <project-root>/All_Projects/Terminator/tests/benchmarks/weekly_run.sh
```

## Challenge Registry
20 solved challenges tracked:
- dhcc, too_many_questions, damnida, conquergent (reversing/crypto)
- pwnablekr: fd, col, horcruxes, asm, memcpy, passcode, cmd1, cmd2, random, input, input2, leg, lotto, mistake, coin1, blackjack (pwn)
