#!/bin/bash
# teammate_idle_check.sh — TeammateIdle hook
# 팀원이 idle 상태에 빠졌을 때 자동으로 checkpoint 확인
# checkpoint.status != "completed" → FAKE IDLE 경고

set -euo pipefail

INPUT=$(cat)
CWD=$(echo "$INPUT" | jq -r '.cwd // ""')

PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
COORD_CLI="$PROJECT_DIR/tools/coordination_cli.py"
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || true)

if [[ -z "$SESSION_ID" ]]; then
    SESSION_ID="$(python3 "$COORD_CLI" derive-session --cwd "${CWD:-$PROJECT_DIR}" 2>/dev/null | jq -r '.session_id' 2>/dev/null || basename "${CWD:-$PROJECT_DIR}")"
fi

# 최근 수정된 checkpoint 검색 (5분 이내)
ALERT=""

for cp in $(find "$CWD" "$PROJECT_DIR" -maxdepth 4 -name "checkpoint*.json" -mmin -5 2>/dev/null | head -3); do
    STATUS=$(jq -r '.status // "unknown"' "$cp" 2>/dev/null || continue)
    AGENT=$(jq -r '.agent // "unknown"' "$cp" 2>/dev/null || echo "unknown")

    if [[ "$STATUS" == "in_progress" ]]; then
        PHASE=$(jq -r '.phase_name // .phase // "?"' "$cp" 2>/dev/null || echo "?")
        IN_PROG=$(jq -r '.in_progress // "none"' "$cp" 2>/dev/null || echo "none")
        COMPLETED=$(jq -r '.completed // [] | join("; ")' "$cp" 2>/dev/null || echo "")
        CRITICAL=$(jq -r '.critical_facts // {} | to_entries | map("\(.key)=\(.value)") | join(", ")' "$cp" 2>/dev/null || echo "")

        ALERT="${ALERT}
[FAKE IDLE] @${AGENT} — checkpoint says in_progress
  phase: $PHASE
  doing: $IN_PROG
  done: $COMPLETED
  critical_facts: $CRITICAL
  → SendMessage로 \"checkpoint.json 읽고 이어서 작업\" 전송 권장.
  → 응답 없으면 checkpoint 포함하여 새 에이전트 스폰."

    elif [[ "$STATUS" == "error" ]]; then
        ERROR=$(jq -r '.error // "unknown"' "$cp" 2>/dev/null || echo "unknown")
        ALERT="${ALERT}
[ENV BLOCKER] @${AGENT} — checkpoint says error
  error: $ERROR
  → 환경 문제 해결 후 재스폰."
    fi
done

if [[ -n "$ALERT" ]]; then
    python3 "$COORD_CLI" event \
        --session "$SESSION_ID" \
        --type "teammate_idle_alert" \
        --payload-json "$(jq -n --arg alert "$ALERT" '{alert: $alert}')" >/dev/null 2>&1 || true
fi

printf '%s' "$INPUT" | bash "$PROJECT_DIR/.claude/hooks/sync_shared_memory.sh" >/dev/null 2>&1 || true

if [[ -n "$ALERT" ]]; then
    jq -n --arg msg "$ALERT" '{additionalContext: $msg}'
else
    echo '{}'
fi

exit 0
