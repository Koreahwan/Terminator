#!/usr/bin/env bash
# Codex Cross-Review wrapper for Terminator pipeline
# Usage:
#   codex_cross_review.sh review <path>              # standard review
#   codex_cross_review.sh adversarial <path> [focus]  # adversarial review
#   codex_cross_review.sh rescue <prompt>             # delegate task to Codex
#   codex_cross_review.sh status                      # check running jobs
#
# Called by: orchestrator, SubagentStop hook, pipeline scripts
# Requires: codex CLI authenticated, codex-plugin-cc installed

set -euo pipefail

CODEX_COMPANION="${HOME}/.claude/plugins/cache/openai-codex/codex/1.0.2/scripts/codex-companion.mjs"
LOG_DIR="${HOME}/01_CYAI_Lab/01_Projects/Terminator/.omc/logs"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)

if [[ ! -f "$CODEX_COMPANION" ]]; then
    echo "[CODEX] ERROR: codex-companion.mjs not found. Run /codex:setup first." >&2
    exit 1
fi

log_result() {
    local mode="$1" target="$2" result="$3"
    mkdir -p "$LOG_DIR"
    echo "${TIMESTAMP}|${mode}|${target}|${result}" >> "${LOG_DIR}/codex_cross_review.log"
}

cmd_review() {
    local target="${1:-.}"
    echo "[CODEX] Running standard review on: ${target}"
    node "$CODEX_COMPANION" review --wait --scope working-tree 2>&1
    local rc=$?
    log_result "review" "$target" "exit=$rc"
    return $rc
}

cmd_adversarial() {
    local target="${1:-.}"
    local focus="${2:-}"
    echo "[CODEX] Running adversarial review on: ${target}"
    if [[ -n "$focus" ]]; then
        node "$CODEX_COMPANION" adversarial-review --wait --scope working-tree "$focus" 2>&1
    else
        node "$CODEX_COMPANION" adversarial-review --wait --scope working-tree 2>&1
    fi
    local rc=$?
    log_result "adversarial" "$target" "exit=$rc"
    return $rc
}

cmd_rescue() {
    local prompt="$*"
    echo "[CODEX] Delegating task to Codex: ${prompt:0:80}..."
    node "$CODEX_COMPANION" task --write --background "$prompt" 2>&1
    local rc=$?
    log_result "rescue" "task" "exit=$rc"
    return $rc
}

cmd_status() {
    node "$CODEX_COMPANION" status 2>&1
}

cmd_result() {
    local job_id="${1:-}"
    node "$CODEX_COMPANION" result $job_id 2>&1
}

# --- Main ---
case "${1:-help}" in
    review)      shift; cmd_review "$@" ;;
    adversarial) shift; cmd_adversarial "$@" ;;
    rescue)      shift; cmd_rescue "$@" ;;
    status)      cmd_status ;;
    result)      shift; cmd_result "$@" ;;
    help|*)
        echo "Usage: codex_cross_review.sh {review|adversarial|rescue|status|result} [args]"
        echo ""
        echo "  review <path>              Standard Codex code review"
        echo "  adversarial <path> [focus]  Adversarial design challenge review"
        echo "  rescue <prompt>             Delegate task to GPT-5.4"
        echo "  status                      Show running/completed jobs"
        echo "  result [job-id]             Get job result"
        ;;
esac
