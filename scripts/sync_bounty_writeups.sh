#!/usr/bin/env bash
# Weekly sync of public bug bounty disclosures + writeups → knowledge/accepted_reports.db
# Source DB feeds: tools/bb_preflight.py historical-match (Phase 0 / Kill Gate 1)
# Schedule: Sundays 04:00 (1h after sync_poc_github.sh) — registered in crontab.
#
# Sources covered (2026-04-18):
#   - Bugcrowd /crowdstream.json     (200 OK, structured JSON)
#   - HackerOne /hacktivity          (HTML scrape, jina fallback)
#   - YesWeHack /hacktivity          (jina markdown — regex parsed)
#   - Infosec Writeups RSS           (Medium feed)
#   - Pentesterland newsletter archive
#   - huntr /repos/<owner>/<name>    (per-repo, currently active + popular AI/ML repos)
#   - ZDI published advisories RSS

set -euo pipefail

REPO="${REPO:-/mnt/c/Users/KH/All_Projects/Terminator}"
SCRAPER="$REPO/tools/accepted_reports_scraper.py"
LOG_DIR="${LOG_DIR:-$HOME}"
LOG_FILE="$LOG_DIR/bounty_writeups_sync.log"

cd "$REPO"

ts() { date '+%Y-%m-%dT%H:%M:%S%z'; }
log() { echo "[$(ts)] $*" | tee -a "$LOG_FILE"; }

log "=== sync_bounty_writeups START ==="
log "REPO=$REPO"
log "DB=$REPO/knowledge/accepted_reports.db"

# Ensure DB initialised
python3 "$SCRAPER" init 2>&1 | tee -a "$LOG_FILE"

# Per-source ingest — each is independent so failures isolated
ingest() {
    local source="$1" pages="$2"
    log "[ingest] $source pages=$pages"
    if ! timeout 180 python3 "$SCRAPER" ingest "$source" --pages "$pages" 2>&1 | tee -a "$LOG_FILE"; then
        log "[ingest] $source FAILED (continuing other sources)"
    fi
}

ingest bugcrowd 5
ingest iwu 2
ingest pentesterland 2
ingest ywh 3
ingest zdi 4
ingest ghseclab 1
ingest kh4sh3i 1
ingest nomisec 1   # incremental — local nomi-sec/PoC-in-GitHub already synced by sync_poc_github.sh

# huntr per-repo (active submissions + popular AI/ML — extend as new submissions arrive)
log "[ingest] huntr per-repo (RSC-payload parsed for accurate status)"
if ! timeout 300 python3 "$SCRAPER" ingest huntr \
    --repos run-llama/llama_index onnx/onnx kubeflow/kubeflow \
            parisneo/lollms keras-team/keras triton-inference-server/server \
            langchain-ai/langchain mlflow/mlflow ray-project/ray \
            apache/airflow vllm-project/vllm langgenius/dify \
    2>&1 | tee -a "$LOG_FILE"; then
    log "[ingest] huntr FAILED"
fi

# Final stats
log "[stats]"
python3 "$SCRAPER" stats 2>&1 | tee -a "$LOG_FILE"

log "=== sync_bounty_writeups DONE ==="
