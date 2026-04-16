#!/usr/bin/env bash
# awesome_hacking_clone.sh
# Bulk clone all repos from Awesome-Hacking with shallow clones and parallel execution.

set -euo pipefail

URLS_FILE="$(dirname "$0")/awesome_hacking_urls.txt"
TARGET_DIR="${HOME}/awesome-hacking-repos"
LOG_FILE="${TARGET_DIR}/clone.log"
PARALLEL_JOBS=8

mkdir -p "$TARGET_DIR"
> "$LOG_FILE"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting clone of $(wc -l < "$URLS_FILE") repos into $TARGET_DIR" | tee -a "$LOG_FILE"
echo "Parallel jobs: $PARALLEL_JOBS | Depth: 1" | tee -a "$LOG_FILE"
echo "---" | tee -a "$LOG_FILE"

clone_repo() {
    local url="$1"
    local target_dir="$2"
    local log_file="$3"

    # Derive repo name: org_repo (replace / with _)
    local repo_name
    repo_name=$(echo "$url" | sed 's|https://github.com/||' | tr '/' '_')
    local dest="${target_dir}/${repo_name}"

    if [[ -d "$dest/.git" ]]; then
        echo "[SKIP]    $url  →  already exists" | tee -a "$log_file"
        return 0
    fi

    if git clone --depth=1 --quiet "$url" "$dest" 2>/dev/null; then
        echo "[OK]      $url" | tee -a "$log_file"
    else
        echo "[FAIL]    $url" | tee -a "$log_file"
        return 1
    fi
}

export -f clone_repo

# Run parallel clones; capture per-line exit codes via a temp status file
SUCCESS=0
FAIL=0
SKIP=0

# Use xargs -P for parallelism; collect results via log parsing after completion
while IFS= read -r url || [[ -n "$url" ]]; do
    [[ -z "$url" || "$url" == \#* ]] && continue
    echo "$url"
done < "$URLS_FILE" | \
    xargs -P "$PARALLEL_JOBS" -I{} bash -c 'clone_repo "$@"' _ {} "$TARGET_DIR" "$LOG_FILE"

echo "---" | tee -a "$LOG_FILE"

# Summarize from log
SUCCESS=$(grep -c '^\[OK\]' "$LOG_FILE" || true)
FAIL=$(grep -c '^\[FAIL\]' "$LOG_FILE" || true)
SKIP=$(grep -c '^\[SKIP\]' "$LOG_FILE" || true)
TOTAL=$((SUCCESS + FAIL + SKIP))

echo "" | tee -a "$LOG_FILE"
echo "=== SUMMARY ===" | tee -a "$LOG_FILE"
echo "  Total  : $TOTAL" | tee -a "$LOG_FILE"
echo "  OK     : $SUCCESS" | tee -a "$LOG_FILE"
echo "  Skipped: $SKIP" | tee -a "$LOG_FILE"
echo "  Failed : $FAIL" | tee -a "$LOG_FILE"

if [[ "$FAIL" -gt 0 ]]; then
    echo "" | tee -a "$LOG_FILE"
    echo "Failed repos:" | tee -a "$LOG_FILE"
    grep '^\[FAIL\]' "$LOG_FILE" | tee -a /dev/stderr
    exit 1
fi

echo "" | tee -a "$LOG_FILE"
echo "Done. Log: $LOG_FILE"
