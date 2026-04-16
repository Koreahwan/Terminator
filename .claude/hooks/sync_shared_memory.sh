#!/bin/bash
# sync_shared_memory.sh — Mirror Claude-accessible persisted state into coordination/

set -euo pipefail

INPUT="$(cat || true)"
PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
COORD_CLI="$PROJECT_DIR/tools/coordination_cli.py"

CWD="$(echo "$INPUT" | jq -r '.cwd // ""' 2>/dev/null || true)"
SESSION_ID="$(echo "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || true)"

if [[ -z "$CWD" ]]; then
    CWD="$PROJECT_DIR"
fi

if [[ -z "$SESSION_ID" ]]; then
    SESSION_ID="$(python3 "$COORD_CLI" derive-session --cwd "$CWD" 2>/dev/null | jq -r '.session_id' 2>/dev/null || basename "$CWD")"
fi

python3 "$COORD_CLI" ensure-session \
    --session "$SESSION_ID" \
    --cwd "$CWD" \
    --leader "claude" \
    --tool "claude_code" \
    --lead-mode "auto" \
    --status "active" >/dev/null 2>&1 || true

python3 "$COORD_CLI" sync-claude-state \
    --session "$SESSION_ID" \
    --cwd "$CWD" >/dev/null 2>&1 || true

echo '{}'
