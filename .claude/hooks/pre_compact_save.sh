#!/bin/bash
# pre_compact_save.sh — PreCompact hook
# Context 압축 직전에 현재 작업 상태를 자동 저장
# 에이전트가 compaction으로 컨텍스트를 잃어도 복구 가능

set -euo pipefail

INPUT=$(cat)
CWD=$(echo "$INPUT" | jq -r '.cwd // ""')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // ""')

# 프로젝트 루트
PROJECT_DIR="/home/rootk1m/01_CYAI_Lab/01_Projects/Terminator"

# 1. 활성 챌린지/타겟 디렉토리 탐색
CHECKPOINT_SUMMARY=""

# CTF 챌린지 checkpoint 수집
for cp in $(find "$PROJECT_DIR" -maxdepth 4 -name "checkpoint.json" -newer "$PROJECT_DIR/CLAUDE.md" 2>/dev/null | head -5); do
    STATUS=$(jq -r '.status // "unknown"' "$cp" 2>/dev/null || echo "unknown")
    AGENT=$(jq -r '.agent // "unknown"' "$cp" 2>/dev/null || echo "unknown")
    PHASE=$(jq -r '.phase_name // .phase // "unknown"' "$cp" 2>/dev/null || echo "unknown")
    IN_PROG=$(jq -r '.in_progress // "none"' "$cp" 2>/dev/null || echo "none")
    DIR=$(dirname "$cp")

    if [[ "$STATUS" == "in_progress" || "$STATUS" == "error" ]]; then
        CHECKPOINT_SUMMARY="${CHECKPOINT_SUMMARY}
[ACTIVE CHECKPOINT] ${DIR##*/}
  agent=$AGENT status=$STATUS phase=$PHASE
  in_progress: $IN_PROG"
    fi
done

# 2. 활성 팀 파일 확인
TEAM_SUMMARY=""
for team_cfg in "$HOME/.claude/teams"/*/config.json; do
    if [[ -f "$team_cfg" ]]; then
        TEAM_NAME=$(jq -r '.team_name // "unknown"' "$team_cfg" 2>/dev/null || echo "unknown")
        MEMBER_COUNT=$(jq -r '.members | length' "$team_cfg" 2>/dev/null || echo "0")
        TEAM_SUMMARY="${TEAM_SUMMARY}
[ACTIVE TEAM] $TEAM_NAME (${MEMBER_COUNT} members)"
    fi
done

# 3. 최근 산출물 파일 목록
RECENT_ARTIFACTS=""
for f in $(find "$CWD" -maxdepth 2 \( -name "reversal_map.md" -o -name "trigger_report.md" -o -name "chain_report.md" -o -name "solve.py" -o -name "critic_review.md" -o -name "vulnerability_candidates.md" -o -name "recon_report.json" \) -newer "$PROJECT_DIR/CLAUDE.md" 2>/dev/null | head -10); do
    RECENT_ARTIFACTS="${RECENT_ARTIFACTS}
  - ${f##*/} ($(dirname "$f" | xargs basename))"
done

# 4. additionalContext 구성
CONTEXT=""
if [[ -n "$CHECKPOINT_SUMMARY" ]]; then
    CONTEXT="${CONTEXT}

=== ACTIVE CHECKPOINTS (compaction 전 상태) ===${CHECKPOINT_SUMMARY}"
fi

if [[ -n "$TEAM_SUMMARY" ]]; then
    CONTEXT="${CONTEXT}

=== ACTIVE TEAMS ===${TEAM_SUMMARY}"
fi

if [[ -n "$RECENT_ARTIFACTS" ]]; then
    CONTEXT="${CONTEXT}

=== RECENT ARTIFACTS ===${RECENT_ARTIFACTS}"
fi

# 5. 디스크에도 상태 저장 (compaction 후 파일에서 복구 가능)
STATE_FILE="$PROJECT_DIR/.omc/compaction_state.json"
mkdir -p "$(dirname "$STATE_FILE")"
jq -n \
    --arg session "$SESSION_ID" \
    --arg cwd "$CWD" \
    --arg checkpoints "$CHECKPOINT_SUMMARY" \
    --arg teams "$TEAM_SUMMARY" \
    --arg artifacts "$RECENT_ARTIFACTS" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{session: $session, cwd: $cwd, checkpoints: $checkpoints, teams: $teams, artifacts: $artifacts, saved_at: $timestamp}' \
    > "$STATE_FILE" 2>/dev/null || true

# 6. 출력
if [[ -n "$CONTEXT" ]]; then
    jq -n --arg ctx "$CONTEXT" '{additionalContext: $ctx}'
else
    echo '{}'
fi

exit 0
