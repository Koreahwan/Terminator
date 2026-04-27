#!/bin/bash
# knowledge_inject.sh — PreToolUse: Task/Agent hook
# Injects relevant GraphRAG knowledge into agent context before spawn and persists
# structured digests for cross-tool reuse.

set -euo pipefail

CODE_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE_ROOT="${COORD_PROJECT_ROOT:-$CODE_ROOT}"
export COORD_PROJECT_ROOT="$STATE_ROOT"

COORD_CLI="$CODE_ROOT/tools/coordination_cli.py"
CONTEXT_DIGEST="$CODE_ROOT/tools/context_digest.py"
GRAPHRAG_ROOT="$CODE_ROOT/tools/graphrag-security"
TIMEOUT=15

# Read stdin JSON
INPUT=$(cat)

# Extract tool_name and tool_input.prompt from JSON
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // ""')

# Only process Task/Agent tool calls
if [[ "$TOOL_NAME" != "Task" && "$TOOL_NAME" != "Agent" ]]; then
    echo '{}'
    exit 0
fi

# Extract subagent_type and prompt from tool_input
SUBAGENT_TYPE=$(echo "$INPUT" | jq -r '.tool_input.subagent_type // ""')
PROMPT=$(echo "$INPUT" | jq -r '.tool_input.prompt // .tool_input.description // ""')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // .tool_input.team_name // .tool_input.session_id // empty')
CWD=$(echo "$INPUT" | jq -r '.cwd // "."')

if [[ -z "$SUBAGENT_TYPE" ]]; then
    echo '{}'
    exit 0
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

# Combine subagent_type and prompt for matching
COMBINED="${SUBAGENT_TYPE} ${PROMPT}"

# Map agent type to GraphRAG query
QUERY=""

if echo "$COMBINED" | grep -qiE 'analyst|scout|recon|recon-scanner|mobile-analyst|web-tester|bounty|submission|owasp|cve|sqli|xss|ssrf|injection|web'; then
    QUERY="bug bounty findings, common rejection reasons, OOS patterns, successful submissions, CVE patterns, web vulnerability techniques, OWASP top 10"
elif echo "$COMBINED" | grep -qiE 'exploiter|reporter|critic|target[-_]evaluator|triager[-_]sim|source-auditor|poc|proof.of.concept|exploit.dev'; then
    QUERY="exploit development techniques, PoC patterns, proof of concept quality, successful exploits, exploit chain assembly"
elif echo "$COMBINED" | grep -qiE 'crypto|cipher|hash|aes|rsa|prng|random|z3|sage'; then
    QUERY="cryptographic vulnerabilities, cipher attacks, hash collisions, PRNG weaknesses, authentication token weaknesses"
elif echo "$COMBINED" | grep -qiE 'web3|defi|smart.contract|solidity|evm|slither|foundry|immunefi'; then
    QUERY="DeFi vulnerabilities, smart contract security, EVM exploitation, reentrancy, price manipulation, flash loan attacks, Immunefi submission patterns"
fi

SKILL_JSON="$(python3 "$COORD_CLI" relevant-skills --session "$SESSION_ID" --query "$COMBINED" --limit 5 2>/dev/null || echo '{"skills": []}')"
SKILL_BLOCK="$(echo "$SKILL_JSON" | jq -r '.skills // [] | map("- " + .name + " — " + .description) | join("\n")' 2>/dev/null || true)"
DOC_JSON="$(python3 "$COORD_CLI" relevant-instructions --session "$SESSION_ID" --query "$COMBINED" --limit 4 2>/dev/null || echo '{"documents": []}')"
DOC_BLOCK="$(echo "$DOC_JSON" | jq -r '.documents // [] | map("- " + .type + ": " + .path) | join("\n")' 2>/dev/null || true)"
GRAPH_SECTION="(GraphRAG query skipped)"

if [[ -n "$QUERY" && "${COORD_SKIP_GRAPHRAG:-0}" != "1" ]] && command -v graphrag &>/dev/null && [[ -d "$GRAPHRAG_ROOT" ]]; then
    RESULT=$(timeout "$TIMEOUT" graphrag query \
        --root "$GRAPHRAG_ROOT" \
        --method local \
        --query "$QUERY" 2>/dev/null) || true
    if [[ -n "$RESULT" ]]; then
        GRAPH_SECTION="$(echo "$RESULT" | head -50)"
    else
        GRAPH_SECTION="(GraphRAG returned no local results)"
    fi
fi

if [[ -z "${SKILL_BLOCK// }" && -z "${DOC_BLOCK// }" && "$GRAPH_SECTION" == "(GraphRAG query skipped)" ]]; then
    echo '{}'
    exit 0
fi

COMBINED_RESULT=$(cat <<EOF
[AUTO-INJECTED KNOWLEDGE - $SUBAGENT_TYPE]
$GRAPH_SECTION

[RELEVANT SKILLS]
${SKILL_BLOCK:-"(no relevant skills matched)"}

[RELEVANT INSTRUCTION DOCS]
${DOC_BLOCK:-"(no instruction documents indexed)"}
EOF
)

DIGEST_JSON="$(printf '%s' "$COMBINED_RESULT" | python3 "$CONTEXT_DIGEST" \
    --session "$SESSION_ID" \
    --cwd "$CWD" \
    --kind "task_knowledge" \
    --title "Task knowledge for $SUBAGENT_TYPE" \
    --generated-by "knowledge_inject_hook" \
    --source-ref "graphrag:local" \
    --source-ref "skills:matched" \
    --stdin 2>/dev/null || echo '{}')"

python3 "$COORD_CLI" event \
    --session "$SESSION_ID" \
    --type "task_knowledge_injected" \
    --payload-json "{\"subagent_type\": \"${SUBAGENT_TYPE}\", \"query\": $(printf '%s' "$QUERY" | jq -Rs .)}" >/dev/null 2>&1 || true

MESSAGE=$(echo "$DIGEST_JSON" | jq -r '.payload.summary_1liner // empty' 2>/dev/null || true)
FACTS=$(echo "$DIGEST_JSON" | jq -r '.payload.high_signal_facts // [] | .[:6] | join("\n")' 2>/dev/null || true)
if [[ -z "$MESSAGE" && -z "$FACTS" ]]; then
    jq -n --arg msg "[AUTO-INJECTED KNOWLEDGE - $SUBAGENT_TYPE]
$GRAPH_SECTION" '{systemMessage: $msg}'
else
    jq -n --arg msg "[AUTO-INJECTED KNOWLEDGE DIGEST - $SUBAGENT_TYPE]
$MESSAGE
$FACTS" '{systemMessage: $msg}'
fi
