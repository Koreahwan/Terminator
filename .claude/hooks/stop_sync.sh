#!/bin/bash
# stop_sync.sh — Stop hook that syncs Claude state and keeps pending-task warning behavior.

set -euo pipefail

INPUT="$(cat || true)"
PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

printf '%s' "$INPUT" | bash "$PROJECT_DIR/.claude/hooks/sync_shared_memory.sh" >/dev/null 2>&1 || true

TASKS=$(find ${HOME}/.claude/tasks/ -name "*.json" -exec jq -r 'select(.status=="in_progress" or .status=="pending") | .subject' {} \; 2>/dev/null | head -5)
if [ -n "$TASKS" ]; then
    jq -n --arg msg "[WARN] 미완료 태스크 있음: $TASKS" '{additionalContext: $msg}'
else
    echo '{}'
fi
