#!/usr/bin/env bash
# Weekly sync of nomi-sec/PoC-in-GitHub CVE/PoC catalog + knowledge-fts reindex
#
# Cadence: run weekly (cron-friendly). Full pull+reindex takes ~1-3 min on SSD.
# Exit codes: 0 = updated (pull had new commits + reindex OK)
#             1 = up-to-date (no new commits) — safe, no reindex needed
#             2 = error (pull failed or reindex failed)
#
# Cron install (user chooses):
#   crontab -e
#   0 3 * * 0 /mnt/c/Users/KH/All_Projects/Terminator/scripts/sync_poc_github.sh >> ~/poc_github_sync.log 2>&1
#   (Sundays 03:00 local)
#
# Safety: does not touch network on skip-if-recent heuristic (set POC_FORCE=1 to override)

set -euo pipefail

POC_DIR="${POC_IN_GITHUB_DIR:-$HOME/PoC-in-GitHub}"
TERMINATOR_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="${TERMINATOR_ROOT}/.omc/logs"
mkdir -p "$LOG_DIR"
STAMP=$(date +%Y%m%dT%H%M%S)
LOG="${LOG_DIR}/sync_poc_github_${STAMP}.log"

log() { echo "[sync_poc_github] $(date -Iseconds) $*" | tee -a "$LOG"; }

if [[ ! -d "$POC_DIR/.git" ]]; then
    log "ERROR: $POC_DIR is not a git repo. Clone first:"
    log "  git clone https://github.com/nomi-sec/PoC-in-GitHub.git $POC_DIR"
    exit 2
fi

# skip-if-recent: if pulled within last 6 days, skip unless forced
last_pull_epoch=$(cd "$POC_DIR" && git log -1 --format=%ct 2>/dev/null || echo 0)
now_epoch=$(date +%s)
age_days=$(( (now_epoch - last_pull_epoch) / 86400 ))
if [[ -z "${POC_FORCE:-}" ]] && (( age_days < 6 )); then
    log "skip-if-recent: last commit ${age_days}d ago (< 6d). Set POC_FORCE=1 to override."
    exit 1
fi

log "pulling $POC_DIR (age=${age_days}d)"
cd "$POC_DIR"
before_head=$(git rev-parse HEAD)
if ! git pull --ff-only 2>&1 | tee -a "$LOG"; then
    log "ERROR: git pull failed"
    exit 2
fi
after_head=$(git rev-parse HEAD)

if [[ "$before_head" == "$after_head" ]]; then
    log "no new commits (HEAD unchanged: ${after_head:0:8}). skipping reindex."
    exit 1
fi

log "new commits: ${before_head:0:8}..${after_head:0:8}"
new_files=$(git diff --name-only "$before_head" "$after_head" | wc -l)
log "files changed: $new_files"

# Reindex knowledge-fts (full rebuild — PoC catalog is external, update-internal won't catch it)
log "running knowledge_indexer.py build"
cd "$TERMINATOR_ROOT"
if python3 tools/knowledge_indexer.py build 2>&1 | tee -a "$LOG" | tail -5; then
    log "reindex OK"
else
    log "ERROR: reindex failed — db may be partial. Run 'python3 tools/knowledge_indexer.py build' manually."
    exit 2
fi

# Summary
log "stats after reindex:"
python3 tools/knowledge_indexer.py stats 2>&1 | tee -a "$LOG" | head -10

log "DONE"
exit 0
