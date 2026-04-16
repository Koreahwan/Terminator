#!/bin/bash
# check_agent_completion.sh — SubagentStop hook
# 에이전트 종료 시 checkpoint.json으로 실제 완료 여부 자동 검증
# FAKE IDLE (compaction/에러로 중단) vs 진짜 완료 판별

set -euo pipefail

INPUT=$(cat)
CWD=$(echo "$INPUT" | jq -r '.cwd // ""')
LAST_MSG=$(echo "$INPUT" | jq -r '.last_assistant_message // ""')
AGENT_TYPE=$(echo "$INPUT" | jq -r '.agent_type // ""')
AGENT_ID=$(echo "$INPUT" | jq -r '.agent_id // ""')

PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
COORD_CLI="$PROJECT_DIR/tools/coordination_cli.py"
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || true)

if [[ -z "$SESSION_ID" ]]; then
    SESSION_ID="$(python3 "$COORD_CLI" derive-session --cwd "${CWD:-$PROJECT_DIR}" 2>/dev/null | jq -r '.session_id' 2>/dev/null || basename "${CWD:-$PROJECT_DIR}")"
fi

# 최근 수정된 checkpoint.json 찾기 (최근 10분 이내)
WARNINGS=""
FOUND_INCOMPLETE=false
CHECKPOINT_FOUND=""
FOUND_FLAGS=""

for cp in $(find "$CWD" "$PROJECT_DIR" -maxdepth 4 -name "checkpoint*.json" -mmin -10 2>/dev/null | head -5); do
    STATUS=$(jq -r '.status // "unknown"' "$cp" 2>/dev/null || continue)
    AGENT=$(jq -r '.agent // "unknown"' "$cp" 2>/dev/null || echo "unknown")
    PHASE=$(jq -r '.phase_name // .phase // "?"' "$cp" 2>/dev/null || echo "?")
    IN_PROG=$(jq -r '.in_progress // "none"' "$cp" 2>/dev/null || echo "none")
    EXPECTED=$(jq -r '.expected_artifacts // [] | join(", ")' "$cp" 2>/dev/null || echo "")
    PRODUCED=$(jq -r '.produced_artifacts // [] | join(", ")' "$cp" 2>/dev/null || echo "")
    ERROR=$(jq -r '.error // ""' "$cp" 2>/dev/null || echo "")
    DIR=$(dirname "$cp")
    CHECKPOINT_FOUND="yes"

    case "$STATUS" in
        completed)
            # 산출물 존재 여부 검증
            MISSING=""
            for artifact in $(jq -r '.expected_artifacts // [] | .[]' "$cp" 2>/dev/null); do
                if [[ ! -f "$DIR/$artifact" ]]; then
                    MISSING="${MISSING} $artifact"
                fi
            done
            if [[ -n "$MISSING" ]]; then
                WARNINGS="${WARNINGS}
[WARN] $AGENT: status=completed but missing artifacts:$MISSING"
                FOUND_INCOMPLETE=true
            fi
            ;;
        in_progress)
            WARNINGS="${WARNINGS}
[ALERT] $AGENT: FAKE IDLE detected — status=in_progress, phase=$PHASE
  in_progress: $IN_PROG
  produced: $PRODUCED
  expected: $EXPECTED
  → 에이전트가 compaction/에러로 중단됨. 재스폰 또는 resume 필요."
            FOUND_INCOMPLETE=true
            ;;
        error)
            WARNINGS="${WARNINGS}
[ERROR] $AGENT: status=error at phase=$PHASE
  error: $ERROR
  → 환경 문제 해결 후 재스폰 필요."
            FOUND_INCOMPLETE=true
            ;;
    esac
done

# --- Flag Detection ---
if [ -n "$LAST_MSG" ]; then
    FLAG_PATTERNS='(DH|FLAG|flag|CTF|GoN|CYAI)\{[^}]{4,}\}'
    FOUND_FLAGS=$(echo "$LAST_MSG" | grep -oP "$FLAG_PATTERNS" 2>/dev/null || true)
    if [ -n "$FOUND_FLAGS" ]; then
        WARNINGS="${WARNINGS}[FLAG DETECTED] Agent $AGENT_TYPE found: $FOUND_FLAGS\n"
        # Log to coordination store if available
        if [ -f "$PROJECT_DIR/tools/coordination_cli.py" ]; then
            python3 "$PROJECT_DIR/tools/coordination_cli.py" event \
                --session "$(python3 "$PROJECT_DIR/tools/coordination_cli.py" derive-session 2>/dev/null || echo 'unknown')" \
                --kind "flag_detected" \
                --payload "{\"agent\":\"$AGENT_TYPE\",\"flags\":\"$FOUND_FLAGS\"}" 2>/dev/null || true
        fi
    fi
fi

# --- Auto-checkpoint for agents that stopped without one ---
WORK_AGENTS="chain|solver|exploiter|analyst|reverser|trigger|verifier|reporter"
if [[ "$AGENT_TYPE" =~ ^($WORK_AGENTS)$ ]] && [ -z "$CHECKPOINT_FOUND" ]; then
    if [ -f "$PROJECT_DIR/tools/coordination_cli.py" ]; then
        python3 "$PROJECT_DIR/tools/coordination_cli.py" checkpoint \
            --session "$(python3 "$PROJECT_DIR/tools/coordination_cli.py" derive-session 2>/dev/null || echo 'unknown')" \
            --actor "$AGENT_TYPE" \
            --stage "agent_stopped" \
            --status "stopped_without_checkpoint" \
            --payload-json "{\"agent_id\":\"$AGENT_ID\",\"had_flags\":\"${FOUND_FLAGS:-none}\"}" 2>/dev/null || true
    fi
fi

# --- Codex Cross-Review Auto-Trigger (critic APPROVED) ---
CODEX_SCRIPT="$PROJECT_DIR/tools/codex_cross_review.sh"
if [[ "$AGENT_TYPE" == "critic" ]] && [[ -f "$CODEX_SCRIPT" ]]; then
    APPROVED=$(echo "$LAST_MSG" | grep -ci "APPROVED" 2>/dev/null || echo "0")
    if [[ "$APPROVED" -gt 0 ]]; then
        # Check if codex CLI is available
        if command -v codex &>/dev/null; then
            WARNINGS="${WARNINGS}[CODEX] critic APPROVED detected — cross-model review recommended.\n"
            WARNINGS="${WARNINGS}[CODEX] Run: /codex:adversarial-review --wait  OR  tools/codex_cross_review.sh adversarial .\n"
            # Log the trigger event
            if [[ -f "$COORD_CLI" ]]; then
                python3 "$COORD_CLI" event \
                    --session "$SESSION_ID" \
                    --kind "codex_cross_review_trigger" \
                    --payload "{\"agent\":\"critic\",\"verdict\":\"APPROVED\",\"action\":\"codex_adversarial_review_recommended\"}" 2>/dev/null || true
            fi
        fi
    fi
fi

# --- Knowledge extraction hint ---
if [ -n "$LAST_MSG" ]; then
    TECHNIQUE_MARKERS=$(echo "$LAST_MSG" | grep -c -iE '(technique|vulnerability|exploit method|attack vector|bypass|primitive):' 2>/dev/null || echo "0")
    if [ "$TECHNIQUE_MARKERS" -gt 0 ]; then
        WARNINGS="${WARNINGS}[KNOWLEDGE] Agent $AGENT_TYPE output contains $TECHNIQUE_MARKERS technique markers — consider extracting to knowledge/techniques/\n"
    fi
fi

if [[ "$FOUND_INCOMPLETE" == true ]]; then
    python3 "$COORD_CLI" event \
        --session "$SESSION_ID" \
        --type "subagent_completion_warning" \
        --payload-json "$(jq -n --arg warnings "$WARNINGS" '{warnings: $warnings}')" >/dev/null 2>&1 || true
fi

printf '%s' "$INPUT" | bash "$PROJECT_DIR/.claude/hooks/sync_shared_memory.sh" >/dev/null 2>&1 || true

# 결과 출력
if [[ "$FOUND_INCOMPLETE" == true ]]; then
    jq -n --arg msg "$WARNINGS" '{additionalContext: $msg}'
else
    echo '{}'
fi

exit 0
