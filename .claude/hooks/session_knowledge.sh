#!/bin/bash
# session_knowledge.sh — SessionStart hook
# Injects global GraphRAG summary at session start and records coordination state.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COORD_CLI="$PROJECT_ROOT/tools/coordination_cli.py"
CONTEXT_DIGEST="$PROJECT_ROOT/tools/context_digest.py"
GRAPHRAG_ROOT="$(cd "$(dirname "$0")/../../tools/graphrag-security" && pwd)"
TIMEOUT=20
INPUT="$(cat || true)"
SESSION_ID="$(echo "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || true)"
CWD="$(echo "$INPUT" | jq -r '.cwd // "."' 2>/dev/null || echo ".")"

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

SKILL_INDEX="$(python3 "$COORD_CLI" discover-skills --session "$SESSION_ID" 2>/dev/null || echo '{}')"
SKILL_COUNT="$(echo "$SKILL_INDEX" | jq -r '.count // 0' 2>/dev/null || echo 0)"
INSTRUCTION_INDEX="$(python3 "$COORD_CLI" discover-instructions --session "$SESSION_ID" 2>/dev/null || echo '{}')"
INSTRUCTION_COUNT="$(echo "$INSTRUCTION_INDEX" | jq -r '.count // 0' 2>/dev/null || echo 0)"

QUERY="Summarize the top 10 most important security techniques, common failure patterns, and key lessons learned from bug bounty and CTF experience"
SUMMARY="GraphRAG unavailable or unindexed; using coordination indexes only."

if command -v graphrag &>/dev/null && [[ -d "$GRAPHRAG_ROOT" ]] && [[ -d "$GRAPHRAG_ROOT/output" ]]; then
    if ls "$GRAPHRAG_ROOT/output/"*.parquet &>/dev/null 2>&1 || \
       find "$GRAPHRAG_ROOT/output" -name "*.parquet" -type f 2>/dev/null | grep -q .; then
        RESULT=$(timeout "$TIMEOUT" graphrag query \
            --root "$GRAPHRAG_ROOT" \
            --method global \
            --query "$QUERY" 2>/dev/null) || true
        if [[ -n "$RESULT" ]]; then
            SUMMARY="$(echo "$RESULT" | head -80)"
        fi
    fi
fi
COMBINED_SUMMARY=$(cat <<EOF
[SESSION KNOWLEDGE SUMMARY]
$SUMMARY

[SKILL INDEX]
Detected skills: $SKILL_COUNT
Detected instruction docs: $INSTRUCTION_COUNT
Use coordination session digests before re-reading large skill or policy documents.
EOF
)

DIGEST_JSON="$(printf '%s' "$COMBINED_SUMMARY" | python3 "$CONTEXT_DIGEST" \
    --session "$SESSION_ID" \
    --cwd "$CWD" \
    --kind "session_knowledge" \
    --title "Session knowledge summary" \
    --generated-by "session_knowledge_hook" \
    --source-ref "graphrag:global" \
    --source-ref "skills:catalog" \
    --stdin 2>/dev/null || echo '{}')"

python3 "$COORD_CLI" event \
    --session "$SESSION_ID" \
    --type "session_knowledge_injected" \
    --payload-json "{\"skill_count\": $SKILL_COUNT, \"instruction_count\": $INSTRUCTION_COUNT}" >/dev/null 2>&1 || true

printf '%s' "$INPUT" | bash "$PROJECT_ROOT/.claude/hooks/sync_shared_memory.sh" >/dev/null 2>&1 || true

MESSAGE=$(echo "$DIGEST_JSON" | jq -r '.payload.summary_1liner // empty' 2>/dev/null || true)
FACTS=$(echo "$DIGEST_JSON" | jq -r '.payload.high_signal_facts // [] | .[:5] | join("\n")' 2>/dev/null || true)
if [[ -z "$MESSAGE" && -z "$FACTS" ]]; then
    jq -n --arg msg "[SESSION KNOWLEDGE SUMMARY]
$SUMMARY" '{systemMessage: $msg}'
else
    jq -n --arg msg "[SESSION KNOWLEDGE DIGEST]
$MESSAGE
$FACTS" '{systemMessage: $msg}'
fi
