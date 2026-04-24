#!/bin/bash
# Held-out benchmark experiment wrapper for competition-v2.
# Usage:
#   ./tests/benchmarks/external_run.sh --root /path/to/NYU_CTF_Bench
#   ./tests/benchmarks/external_run.sh --root /path/to/NYU_CTF_Bench --split development --limit 25

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BENCHMARK_DIR="$PROJECT_ROOT/tests/benchmarks"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

ROOT=""
LAYOUT="auto"
LABEL=""
LIMIT=""
WAIT_SECONDS="${WAIT_SECONDS:-60}"
BATCH_MAX=""
SPLITS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      ROOT="$2"
      shift 2
      ;;
    --layout)
      LAYOUT="$2"
      shift 2
      ;;
    --split)
      SPLITS+=("$2")
      shift 2
      ;;
    --limit)
      LIMIT="$2"
      shift 2
      ;;
    --label)
      LABEL="$2"
      shift 2
      ;;
    --wait-seconds)
      WAIT_SECONDS="$2"
      shift 2
      ;;
    --batch-max)
      BATCH_MAX="$2"
      shift 2
      ;;
    *)
      echo "[!] Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$ROOT" ]]; then
  echo "Usage: $0 --root /path/to/benchmark [--layout auto] [--split development] [--limit 25] [--label name] [--wait-seconds 60] [--batch-max 25]" >&2
  exit 2
fi

if [[ -z "$LABEL" ]]; then
  ROOT_BASE="$(basename "$ROOT")"
  if [[ ${#SPLITS[@]} -gt 0 ]]; then
    LABEL="${ROOT_BASE}-$(IFS=-; echo "${SPLITS[*]}")"
  else
    LABEL="$ROOT_BASE"
  fi
fi

RUN_DIR="$BENCHMARK_DIR/runs/heldout_${TIMESTAMP}_${LABEL// /_}"
mkdir -p "$RUN_DIR"

MANIFEST_PATH="$RUN_DIR/manifest.json"
LEDGER_PATH="$RUN_DIR/ledger.json"
CATALOG_REPORT="$RUN_DIR/catalog.txt"
LEDGER_REPORT="$RUN_DIR/ledger-summary.txt"

CATALOG_ARGS=(
  --catalog-root "$ROOT"
  --catalog-layout "$LAYOUT"
  --catalog-json-out "$MANIFEST_PATH"
)
for split in "${SPLITS[@]}"; do
  CATALOG_ARGS+=(--catalog-split "$split")
done
if [[ -n "$LIMIT" ]]; then
  CATALOG_ARGS+=(--catalog-limit "$LIMIT")
fi

echo "=== Terminator Held-out External Run ==="
echo "Timestamp:   $TIMESTAMP"
echo "Root:        $ROOT"
echo "Layout:      $LAYOUT"
echo "Label:       $LABEL"
echo "Run dir:     $RUN_DIR"
echo ""

python3 "$BENCHMARK_DIR/benchmark.py" "${CATALOG_ARGS[@]}" | tee "$CATALOG_REPORT"

SELECTED_TASKS="$(python3 - <<PY
import json
from pathlib import Path
manifest = json.loads(Path("$MANIFEST_PATH").read_text(encoding="utf-8"))
print(manifest.get("selected_tasks", 0))
PY
)"

if [[ "$SELECTED_TASKS" -eq 0 ]]; then
  echo "[!] No selected tasks in manifest: $MANIFEST_PATH" >&2
  exit 1
fi

python3 "$BENCHMARK_DIR/benchmark.py" \
  --ledger-manifest "$MANIFEST_PATH" \
  --ledger-label "$LABEL" \
  --ledger-out "$LEDGER_PATH" > /dev/null

BATCH_ARGS=(
  --ledger-run-batch "$LEDGER_PATH"
  --run-wait-seconds "$WAIT_SECONDS"
)
for split in "${SPLITS[@]}"; do
  BATCH_ARGS+=(--ledger-next-split "$split")
done
if [[ -n "$BATCH_MAX" ]]; then
  BATCH_ARGS+=(--batch-max-tasks "$BATCH_MAX")
elif [[ -n "$LIMIT" ]]; then
  BATCH_ARGS+=(--batch-max-tasks "$LIMIT")
fi

python3 "$BENCHMARK_DIR/benchmark.py" "${BATCH_ARGS[@]}" > "$RUN_DIR/batch-result.json"
python3 "$BENCHMARK_DIR/benchmark.py" --ledger-report "$LEDGER_PATH" | tee "$LEDGER_REPORT"

echo ""
echo "Artifacts:"
echo "  Manifest:      $MANIFEST_PATH"
echo "  Ledger:        $LEDGER_PATH"
echo "  Catalog report:$CATALOG_REPORT"
echo "  Ledger report: $LEDGER_REPORT"
echo "  Batch result:  $RUN_DIR/batch-result.json"
